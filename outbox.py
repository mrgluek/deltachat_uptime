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

import database

logger = logging.getLogger("uptime_bot")

RATE_PER_MINUTE = 50
BURST = 5
MAX_PENDING = 2000

PRIO_ALERT = 0      # new / resolved incidents, status changes, SSL, stale, DEGRADED, admin alerts
PRIO_REPLY = 1      # command replies and reactions
PRIO_UPDATE = 2     # live incident edits where only the duration changed
PRIO_PEER = 3       # peer cross-checks, handshakes
PRIO_TELEMETRY = 4  # periodic peer telemetry

PRIO_NAMES = {PRIO_ALERT: "alert", PRIO_REPLY: "reply", PRIO_UPDATE: "update",
              PRIO_PEER: "peer", PRIO_TELEMETRY: "telemetry"}

SKIP_SEND = object()


def record_sent_mail(kind: str):
    try:
        database.record_mail_kind(kind)
    except Exception:
        logger.debug("Could not count sent mail of kind %s", kind, exc_info=True)


class _Job:
    __slots__ = ("priority", "seq", "fn", "key", "expires_at", "label", "kind", "future", "done")

    def __init__(self, priority, seq, fn, key, expires_at, label, kind):
        self.priority, self.seq, self.fn, self.key = priority, seq, fn, key
        self.expires_at, self.label, self.kind = expires_at, label, kind
        self.future = concurrent.futures.Future()
        self.done = False  # popped (sent, dropped or replaced by a re-queued copy)


class Outbox:
    def __init__(self, rate_per_minute: float = RATE_PER_MINUTE, burst: int = BURST, clock=time.monotonic, max_pending: int = MAX_PENDING):
        self.max_pending = max(1, max_pending)
        self._last_drop_warning = float("-inf")
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
        self.stats = {"sent": 0, "merged": 0, "expired": 0, "failed": 0, "dropped": 0}

    # ---- submitting ----------------------------------------------------------

    def submit(self, fn, priority: int = PRIO_REPLY, key=None, expires_in: float | None = None,
               label: str = "", *, kind: str | None = "other") -> concurrent.futures.Future:
        """Queue a send. Jobs that conditionally send and count at the RPC use kind=None."""
        now = self.clock()
        expires_at = now + expires_in if expires_in is not None else None
        if self._thread is None:  # not started (tests): send right away
            job = _Job(priority, 0, fn, key, expires_at, label, kind)
            self._run(job)
            return job.future
        with self._cond:
            old = self._by_key.get(key) if key is not None else None
            if old is not None and not old.done:
                # Same message waiting already: newest content, its place in line, the more urgent priority
                old.fn, old.label, old.kind = fn, label or old.label, kind
                old.expires_at = None if (old.expires_at is None or expires_at is None) else max(old.expires_at, expires_at)
                self.stats["merged"] += 1
                if priority < old.priority:
                    old.done = True  # skip the old heap entry; a copy goes in at the new priority
                    job = _Job(priority, old.seq, fn, key, old.expires_at, old.label, kind)
                    job.future = old.future
                    self._push(job)
                return old.future
            job = _Job(priority, next(self._seq), fn, key, expires_at, label, kind)
            # Compact tombstones and expire waiting items before enforcing the hard capacity.
            self._heap = [entry for entry in self._heap if not entry[2].done]
            for _, _, pending in self._heap:
                if pending.expires_at is not None and now >= pending.expires_at:
                    self._finish(pending)
                    pending.future.set_result(None)
                    self.stats["expired"] += 1
            self._heap = [entry for entry in self._heap if not entry[2].done]
            heapq.heapify(self._heap)
            if len(self._heap) >= self.max_pending:
                # Replies go first, then refreshes/telemetry; protect alerts and protocol traffic.
                rank = {PRIO_REPLY: 4, PRIO_TELEMETRY: 3, PRIO_UPDATE: 2, PRIO_PEER: 1, PRIO_ALERT: 0}
                victim = max([entry[2] for entry in self._heap] + [job],
                             key=lambda j: (rank.get(j.priority, 4), -j.seq))
                self._finish(victim)
                victim.future.set_result(None)
                self.stats["dropped"] += 1
                if now - self._last_drop_warning >= 60:
                    self._last_drop_warning = now
                    logger.warning("Outbox capacity reached (%s); dropped %s item(s)", self.max_pending, self.stats["dropped"])
                if victim is job:
                    return job.future
                self._heap = [entry for entry in self._heap if not entry[2].done]
                heapq.heapify(self._heap)
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
            result = job.fn()
            if result is SKIP_SEND:
                job.future.set_result(None)
                return
            if job.kind is not None:
                record_sent_mail(job.kind)
            self.stats["sent"] += 1
            job.future.set_result(result)
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
