"""Outgoing Delta Chat messages: one queue, paced below the relay's send limit.

chatmail relays allow each sender 60 messages a minute with a burst of 10 (GCRA). Over it they
answer "450 Too much mail"; the core retries, the retries count too, and a mass outage (an
incident in every chat, live edits, peer cross-checks) delayed alerts by minutes. Every message,
edit and reaction the bot sends therefore goes through this queue:

- Token bucket: RATE_PER_MINUTE (50, headroom for what the core sends itself) with bursts of
  BURST (5), so the relay's bucket never runs dry.
- Priorities: alerts first, then command replies, live incident edits, the peer protocol and
  telemetry. Within a priority, first come first served (keeps the order within a chat).
- Merging: a job with a key replaces a waiting job with the same key - it keeps that job's place
  in the queue, takes the more urgent priority, and both callers get the result. An incident
  message edited five times while the queue is full goes out once, with the latest text.
- Expiry: a job that has waited past its deadline is dropped without using a token (a
  cross-check answer the peer stopped waiting for is only noise).

Sends run in one worker thread (the RPC calls block). Until start() is called - in tests - a
job runs right away in the caller's thread, without pacing.
"""
import concurrent.futures
import heapq
import itertools
import logging
import threading
import time

logger = logging.getLogger("uptime_bot")

RATE_PER_MINUTE = 50
BURST = 5

PRIO_ALERT = 0      # new / resolved incidents, status changes, SSL, stale, DEGRADED, admin alerts
PRIO_REPLY = 1      # command replies and reactions
PRIO_UPDATE = 2     # live incident edits where only the duration changed
PRIO_PEER = 3       # peer cross-checks, handshakes
PRIO_TELEMETRY = 4  # periodic peer telemetry

PRIO_NAMES = {PRIO_ALERT: "alert", PRIO_REPLY: "reply", PRIO_UPDATE: "update",
              PRIO_PEER: "peer", PRIO_TELEMETRY: "telemetry"}


class _Job:
    __slots__ = ("priority", "seq", "fn", "key", "expires_at", "label", "future", "done")

    def __init__(self, priority, seq, fn, key, expires_at, label):
        self.priority, self.seq, self.fn, self.key = priority, seq, fn, key
        self.expires_at, self.label = expires_at, label
        self.future = concurrent.futures.Future()
        self.done = False  # popped (sent, dropped or replaced by a re-queued copy)


class Outbox:
    def __init__(self, rate_per_minute: float = RATE_PER_MINUTE, burst: int = BURST, clock=time.monotonic):
        self.rate = rate_per_minute / 60.0
        self.burst = burst
        self.clock = clock
        self._tokens = float(burst)
        self._tokens_ts = clock()
        self._heap = []  # (priority, seq, job); a merged job is re-pushed, the old entry skipped
        self._by_key = {}
        self._seq = itertools.count()
        self._cond = threading.Condition()
        self._thread = None
        self.stats = {"sent": 0, "merged": 0, "expired": 0, "failed": 0}

    # ---- submitting ----------------------------------------------------------

    def submit(self, fn, priority: int = PRIO_REPLY, key=None, expires_in: float | None = None,
               label: str = "") -> concurrent.futures.Future:
        """Queue fn() (a blocking send returning e.g. a msg_id); returns a Future with its result."""
        now = self.clock()
        expires_at = now + expires_in if expires_in is not None else None
        if self._thread is None:  # not started (tests): send right away
            job = _Job(priority, 0, fn, key, expires_at, label)
            self._run(job)
            return job.future
        with self._cond:
            old = self._by_key.get(key) if key is not None else None
            if old is not None and not old.done:
                # Same message waiting already: newest content, its place in line, the more urgent priority
                old.fn, old.label = fn, label or old.label
                old.expires_at = None if (old.expires_at is None or expires_at is None) else max(old.expires_at, expires_at)
                self.stats["merged"] += 1
                if priority < old.priority:
                    old.done = True  # skip the old heap entry; a copy goes in at the new priority
                    job = _Job(priority, old.seq, fn, key, old.expires_at, old.label)
                    job.future = old.future
                    self._push(job)
                return old.future
            job = _Job(priority, next(self._seq), fn, key, expires_at, label)
            self._push(job)
            return job.future

    def _push(self, job):
        heapq.heappush(self._heap, (job.priority, job.seq, job))
        if job.key is not None:
            self._by_key[job.key] = job
        self._cond.notify()

    # ---- worker --------------------------------------------------------------

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="uptime_outbox", daemon=True)
            self._thread.start()

    def _refill(self):
        now = self.clock()
        self._tokens = min(float(self.burst), self._tokens + (now - self._tokens_ts) * self.rate)
        self._tokens_ts = now

    def _next_job(self):
        """Blocks until a job may be sent now; drops expired jobs on the way. Call with the lock held."""
        while True:
            while self._heap and self._heap[0][2].done:
                heapq.heappop(self._heap)
            if not self._heap:
                self._cond.wait()
                continue
            job = self._heap[0][2]
            if job.expires_at is not None and self.clock() >= job.expires_at:
                heapq.heappop(self._heap)
                self._finish(job)
                self.stats["expired"] += 1
                logger.debug(f"Outbox: dropped expired {job.label or 'job'}")
                job.future.set_result(None)
                continue
            self._refill()
            if self._tokens < 1:
                # Wait for the next token; a more urgent job arriving meanwhile is picked then
                self._cond.wait((1 - self._tokens) / self.rate)
                continue
            heapq.heappop(self._heap)
            self._finish(job)
            self._tokens -= 1
            return job

    def _finish(self, job):
        job.done = True
        if job.key is not None and self._by_key.get(job.key) is job:
            del self._by_key[job.key]

    def _loop(self):
        while True:
            with self._cond:
                job = self._next_job()
            self._run(job)

    def _run(self, job):
        try:
            job.future.set_result(job.fn())
            self.stats["sent"] += 1
        except Exception as e:
            self.stats["failed"] += 1
            logger.error(f"Outbox: sending {job.label or 'message'} failed: {e}")
            job.future.set_exception(e)

    # ---- status --------------------------------------------------------------

    def waiting(self) -> dict:
        """Jobs waiting, by priority name."""
        with self._cond:
            counts = {}
            for _, _, job in self._heap:
                if not job.done:
                    name = PRIO_NAMES.get(job.priority, str(job.priority))
                    counts[name] = counts.get(name, 0) + 1
            return counts


outbox = Outbox()
