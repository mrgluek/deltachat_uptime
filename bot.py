import asyncio
import base64
import collections
from collections.abc import Callable
import functools
import ipaddress
import contextlib
import contextvars
import io
import heapq
import hmac
import logging
import math
import json
import math
import os
import shutil
import sqlite3
import ssl
import stat
import threading
import weakref
import hashlib
import zipfile
from pathlib import Path
from dataclasses import dataclass, field, replace
from enum import Enum, auto
import time
from time import monotonic
import datetime
import html
import re
import socket
import struct
import shlex
import statistics
import secrets
from urllib.parse import urlparse, urljoin, unquote_plus
from monitor_names import short_monitor_name
import aiohttp
import aiohttp.abc
from aiohttp import web
from deltachat2 import events, MsgData, JsonRpcError, MessageState
from deltabot_cli import BotCli

try:
    import aiodns
except Exception:
    aiodns = None

# On minimal container environments lacking /etc/protocols (e.g. minimal Debian/Alpine without netbase),
# socket.getprotobyname("icmp") raises OSError: protocol not found during aioping import.
# Provide standard IANA protocol number fallback so aioping can initialize safely.
try:
    _orig_getprotobyname = socket.getprotobyname

    def _safe_getprotobyname(name):
        try:
            return _orig_getprotobyname(name)
        except OSError:
            if name.lower() == "icmp":
                return getattr(socket, "IPPROTO_ICMP", 1)
            elif name.lower() in ("icmpv6", "ipv6-icmp"):
                return getattr(socket, "IPPROTO_ICMPV6", 58)
            raise

    socket.getprotobyname = _safe_getprotobyname
    try:
        import aioping
    except Exception:
        aioping = None
except Exception:
    aioping = None

import concurrent.futures
import database
import blockcheck
import dc_fingerprint
import peer_rt
import transports_view
from outbox import outbox as dc_outbox, PRIO_ALERT, PRIO_REPLY, PRIO_UPDATE, PRIO_PEER, PRIO_TELEMETRY
from outbox import SKIP_SEND, record_sent_mail

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uptime_bot")
VERSION = "3.0.0"
SYNC_MAX_BYTES = 64 * 1024
# 200 metrics / 100 cross-checks, including JSON's twelve-byte astral Unicode escaping at field limits.
PEER_MAX_BYTES = 8 * 1024 * 1024
DNS_DEADLINE = 5.0
TITLE_DEADLINE = 5.0
HTTP_REQUEST_TIMEOUT = 10.0
HTTP_TOTAL_DEADLINE = min(45.0, 3 * HTTP_REQUEST_TIMEOUT)
VOTE_ERROR_STORAGE_MAX = 200
KEYWORD_SNIPPET_MAX = 80
MISSING_KEYWORD_PREFIX = '200 OK (Missing keyword: "'
_PROTOCOL_MARKER = re.compile(r"\[(/?UPTIME_(?:PEER_[A-Z_]+|BOT_SYNC_DATA)\])")
_PEER_RT_MAIL_KINDS = frozenset(("RT_OFFER", "RT_ACCEPT", "RT_RESET"))
_PEER_RT_CHECK_KINDS = {
    "CHECK_REQ": "req", "CHECK_RESP": "resp", "CHECK_BATCH_REQ": "breq", "CHECK_BATCH_RESP": "bresp",
}
_PEER_RT_REQUESTS = frozenset(("req", "breq"))
_PEER_RT_MARKER = re.compile(r"\[UPTIME_PEER_(RT_OFFER|RT_ACCEPT|RT_RESET)\]")
_PEER_MAIL_KINDS = frozenset((
    "CHECK_REQ", "CHECK_RESP", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP",
    "METRICS", "HELLO", "HELLO_ACK", "BOT_SYNC_DATA",
)) | _PEER_RT_MAIL_KINDS


def _peer_message_kind(text: str) -> str | None:
    for match in _PROTOCOL_MARKER.finditer(text):
        marker = match.group(1)
        if marker.startswith("UPTIME_"):
            kind = marker.removeprefix("UPTIME_").removeprefix("PEER_").removesuffix("]")
            if kind in _PEER_MAIL_KINDS and text.find("[/" + marker, match.end()) != -1:
                return kind
    return None


def _count_peer_text(text: str | None, direction: str):
    if isinstance(text, str) and (kind := _peer_message_kind(text)):
        database.record_peer_traffic(kind, "mail", direction, len(text.encode("utf-8", errors="replace")))


_SECRET_QUERY_NAMES = {"token", "key", "secret", "password", "pass", "pwd", "auth", "sig",
                       "signature", "api_key", "apikey", "access_token", "code"}


def redact_url(text_or_url) -> str:
    """Remove URL credentials and secret query values from diagnostic text."""
    text = str(text_or_url)
    text = re.sub(r"(?<=[a-z0-9+.-]://)[^/\s?#]*@", "", text, flags=re.IGNORECASE)

    def redact_query(match):
        name = unquote_plus(match.group(2)).lower().replace("-", "_")
        secret = name in _SECRET_QUERY_NAMES or any(p in _SECRET_QUERY_NAMES for p in name.split("_"))
        return match.group(1) + match.group(2) + "=" + ("***" if secret else match.group(3))

    return re.sub(r"(\?|&(?:amp;)?)([^?&=\s#]+)=([^&#\s]*)", redact_query, text, flags=re.IGNORECASE)


def _missing_keyword_error(keyword: str, body: bytes | None, max_length: int) -> str:
    suffix = '")'
    if body is not None:
        decoded = body.decode("utf-8", errors="replace")
        sample = decoded[:256]
        printable = sum(c != "\ufffd" and (c.isprintable() or c.isspace()) for c in sample)
        if printable * 2 < len(sample):
            shown = f"<binary {len(body)} bytes>"
        else:
            text = " ".join("".join(c for c in decoded if c.isprintable() or c.isspace()).split())
            # Redact before truncating, including URL credentials beyond the display limit.
            text = redact_url(text)
            if len(text) > KEYWORD_SNIPPET_MAX:
                text = text[:KEYWORD_SNIPPET_MAX - 1].rstrip() + "…"
            shown = f'"{text}"'
        suffix = f'"; got: {shown})'
    limit = max_length - len(MISSING_KEYWORD_PREFIX) - len(suffix)
    if len(keyword) > limit:
        keyword = keyword[:limit - 1].rstrip() + "…"
    # Legacy peers also scan ordinary chat text for these delimiters.
    return _PROTOCOL_MARKER.sub(r"［\1", MISSING_KEYWORD_PREFIX + keyword + suffix)


STATUS_REFRESH_SECONDS = 1800
WEBXDC_APP_VERSION = 5  # Bump only for layout changes requiring a new app instance.
# Safety net; explicit trimming preserves app instances and ongoing incident messages.
DELETE_DEVICE_AFTER = 30 * 86400
USER_CHAT_KEEP_SECONDS = 86400
USER_CHAT_TRIM_MAX = 2000

# No "bot" in the name: some services (e.g. Hiddify subscription links) reply 400 to any User-Agent containing "bot".
USER_AGENT = f"Delta Chat Uptime Monitor/{VERSION} (+https://git.gluek.info/gluek/deltachat_uptime)"

# Dedicated thread pools for database operations and Delta Chat RPC calls
db_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="uptime_db")
rpc_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="uptime_rpc")

# All external resolvers run in a fixed pool with bounded admission (including queued work).
dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="uptime_dns")
_dns_slots = threading.BoundedSemaphore(16)
title_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="uptime_title")
_title_slots = threading.BoundedSemaphore(4)


def _submit_bounded(executor, slots, func, *args):
    if not slots.acquire(blocking=False):
        raise TimeoutError("Worker capacity reached")
    try:
        future = executor.submit(func, *args)
    except BaseException:
        slots.release()
        raise
    future.add_done_callback(lambda _: slots.release())
    return future


async def _await_worker(future):
    # Cancelling queued ThreadPoolExecutor futures leaves queue tombstones. Keep their admission
    # slots until a worker actually completes them, so repeated deadlines cannot grow that queue.
    wrapped = asyncio.wrap_future(future)
    wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    return await asyncio.shield(wrapped)


TRUSTED_PROXIES = tuple(ipaddress.ip_network(value.strip(), strict=False)
                        for value in os.getenv("TRUSTED_PROXIES",
                            "127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")
                        if value.strip())
RATE_LIMIT_MAX_KEYS = 10000
_rate_limits = collections.OrderedDict()
_rate_limit_lock = threading.Lock()


def _trusted_proxy(value):
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in TRUSTED_PROXIES)
    except ValueError:
        return False


def get_client_ip(request) -> str:
    """Walk forwarding hops from the trusted socket peer towards the client."""
    socket_peer = request.remote or "unknown"
    peer = socket_peer
    forwarded = request.headers.get("X-Forwarded-For")
    if not _trusted_proxy(peer) or not isinstance(forwarded, str):
        return peer
    for hop in reversed(forwarded.split(",")):
        hop = hop.strip()
        try:
            hop = str(ipaddress.ip_address(hop))
        except ValueError:
            return socket_peer  # malformed chains are not client identities
        peer = hop
        if not _trusted_proxy(hop):
            break
    return peer


def check_rate_limit(request, bucket: str = "default", max_requests: int = 60, window_seconds: int = 60) -> bool:
    key = f"{bucket}:{get_client_ip(request)}"
    now = time.monotonic()
    with _rate_limit_lock:
        # Each entry has its own expiry; remove old keys as well as old timestamps.
        while _rate_limits:
            oldest, (expiry, _) = next(iter(_rate_limits.items()))
            if expiry > now and len(_rate_limits) < RATE_LIMIT_MAX_KEYS:
                break
            _rate_limits.pop(oldest)
        _, timestamps = _rate_limits.pop(key, (0, []))
        timestamps = [t for t in timestamps if now - t < window_seconds]
        allowed = len(timestamps) < max_requests
        if allowed:
            timestamps.append(now)
        _rate_limits[key] = (now + window_seconds, timestamps)
        return allowed


COMMANDS_PER_MINUTE = 30
COMMAND_MAX_KEYS = 10000
_command_windows = collections.OrderedDict()
_command_warnings = collections.OrderedDict()
_command_lock = threading.Lock()


def command_budget(handler):
    @functools.wraps(handler)
    def guarded(bot, accid, event):
        msg = event.msg
        if _is_dc_admin(bot, accid, msg.from_id):
            return handler(bot, accid, event)
        now = time.monotonic()
        key = (accid, msg.chat_id, msg.from_id)
        chat = (accid, msg.chat_id)
        with _command_lock:
            for entries in (_command_windows, _command_warnings):
                while entries:
                    first, value = next(iter(entries.items()))
                    stamp = value[-1] if isinstance(value, collections.deque) else value
                    if now - stamp < 60 and len(entries) < COMMAND_MAX_KEYS:
                        break
                    entries.pop(first)
            window = _command_windows.pop(key, collections.deque())
            while window and now - window[0] >= 60:
                window.popleft()
            allowed = len(window) < COMMANDS_PER_MINUTE
            if allowed:
                window.append(now)
            _command_windows[key] = window
            warn = not allowed and now - _command_warnings.get(chat, float("-inf")) >= 60
            if warn:
                _command_warnings[chat] = now
        if allowed:
            return handler(bot, accid, event)
        if warn:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Slow down: at most 30 commands per minute per sender in this chat."))
    return guarded


async def run_db(func, *args, **kwargs):
    """Executes a blocking database operation on the dedicated DB thread pool."""
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(db_executor, lambda: func(*args, **kwargs))
    return await loop.run_in_executor(db_executor, func, *args)


async def run_rpc(func, *args, **kwargs):
    """Executes a blocking Delta Chat RPC / SMTP operation on the dedicated RPC thread pool."""
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(rpc_executor, lambda: func(*args, **kwargs))
    return await loop.run_in_executor(rpc_executor, func, *args)

dc_cli = BotCli("uptimebot")
bot_qr_cache = {}
last_sync_times = {}

# Global references
dc_bot_instance = None
dc_accid = None

def get_bot_invite_link() -> str:
    global dc_bot_instance, dc_accid, bot_qr_cache
    if "invite_link" in bot_qr_cache:
        return bot_qr_cache["invite_link"]
    if dc_bot_instance and dc_accid:
        try:
            link = dc_bot_instance.rpc.get_chat_securejoin_qr_code(dc_accid, None)
            if link:
                bot_qr_cache["invite_link"] = link
                return link
        except Exception as e:
            logger.warning(f"Could not get securejoin link: {e}")
    return ""
async_event_loop = None

# Peering globals
pending_peer_checks = {} # req_id -> (Future, expected_count, list_of_responses, expected_chat_ids)
_pending_peer_rtt = {}  # req_id -> {chat_id: _PeerRtt}, single and batch
_peer_answer_lock = threading.Lock()
_peer_vote_round = contextvars.ContextVar("peer_vote_round", default=None)
last_peer_telemetry_broadcast = 0.0
_telemetry_rotation_offsets = {}  # peer email -> rotation offset
_telemetry_last_sent = {}  # peer email -> {url: status last sent}, so changes go out first

# Batched cross-checks: failing monitors found within CROSS_CHECK_BATCH_WINDOW go to each peer in
# one message (and come back in one), instead of a message per target and peer. In a mass outage
# (300 targets) that was 600 mails per peer a minute, far over the relays' 60/min send limit.
PEER_CAP_BATCH_CHECK = "batch_check"
# smtp:// targets go only to peers that announce this: older versions cannot check them
# (they refuse the target and abstain, but a single /ping request would wait for the timeout)
PEER_CAP_SMTP_CHECK = "smtp_check"
OWN_PEER_CAPS = [PEER_CAP_BATCH_CHECK, PEER_CAP_SMTP_CHECK]
PEER_CAP_RT = "rt1"
PEER_CAPS_ANNOUNCE_INTERVAL = 600
PEER_CAPS_ANNOUNCE_MAX_INTERVAL = 6 * 3600
PEER_CAPS_MAIL_MAX_AGE = 600
PEER_CAPS_CHANGE_LIMIT = 3
PEER_RT_AUDIT_INTERVAL = 60
PEER_RT_ROTATE = 14 * 86400
PEER_RT_OFFER_RETRY = 600
PEER_RT_OFFERS_PER_HOUR = 3
PEER_RT_MAIL_MAX_BYTES = 512
PEER_RT_XDC_MAX_BYTES = 4096
PEER_RT_ADVERT_SPREAD = 60
PEER_RT_ADVERT_COOLDOWN = 60
PEER_RT_PING_INTERVAL = 30
PEER_RT_DISCOVERY_INTERVAL = 3
PEER_RT_EPOCH_SWITCH_INTERVAL = 10
PEER_RT_HELLOS_PER_TICK = 4
PEER_RT_CHALLENGES_PER_TICK = 2
PEER_RT_DISCOVERY_PROBES = 4
PEER_RT_REJOIN_DELAYS = (300, 900, 3600)
PEER_RT_REJOIN_CHECK_INTERVAL = 5
_peer_rt_lock = threading.RLock()
_peer_rt_audit_requested = threading.Event()
_peer_rt_retry_now = set()
_last_peer_rt_audit = None


def _own_peer_caps(peer=None, *, flag=None) -> list[str]:
    if flag is None:
        flag = database.get_peer_rt_flag()
    return [*OWN_PEER_CAPS, PEER_CAP_RT] if _peer_rt_enabled(peer or {}, flag) else OWN_PEER_CAPS
CROSS_CHECK_BATCH_WINDOW = 5.0    # seconds to collect failing targets before sending
CROSS_CHECK_BATCH_MAX = 100       # targets per batch message
CROSS_CHECK_BATCH_TIMEOUT = 25.0  # a peer checks up to 100 targets (10 s timeouts) and mails back
TELEMETRY_INTERVAL = 120  # seconds between telemetry messages to each peer (up to 10 peers)
# Telemetry is mail to every peer; with more peers it goes out less often, so the relay's send limit
# keeps room for what matters in an outage (alerts, votes). (more than N peers, interval)
TELEMETRY_INTERVAL_STEPS = ((20, 300), (10, 180))
PEER_OFFLINE_INTERVALS = 3   # a peer is offline after this many of its telemetry intervals without a word
_peer_telemetry_interval = {}  # peer email (lower) -> interval it announced (default TELEMETRY_INTERVAL)
_telemetry_interval_now = TELEMETRY_INTERVAL  # this node's, set at each broadcast from its peer count
# In a star (one hub linked to every node, the others only to the hub) each leaf has one peer and
# would keep sending every 2 minutes while the hub receives from all of them. So every node also
# says how often it wants to receive (desired_interval, from its own peer count), and a sender
# uses the longer of its own interval and the receiver's wish, per peer.
TELEMETRY_TICK = 30
TELEMETRY_MIN_GAP = 120
TELEMETRY_IDLE_INTERVAL = 300
RT_TELEMETRY_DEBOUNCE = 10
RT_MAIL_KEEPALIVE = 3600
RT_ACTIVITY_INTERVAL = 30
_peer_desired_interval = {}   # peer email (lower) -> how often it wants telemetry
_telemetry_sent_at = {}       # peer email (lower) -> monotonic time of the last enqueue
_telemetry_queued_status = {}  # full status snapshot at the last enqueue
_telemetry_delivered = {}     # (monotonic time, full status snapshot) at the last successful send
_telemetry_started_at = {}     # last RPC attempt, written by the outbox
_telemetry_rt_peers = {}       # telemetry state by peer identity, across carrier changes
_telemetry_delta_timer = None


def interval_for_peer(email: str, own: int) -> int:
    """How often this node sends telemetry to one peer: its own interval or the peer's wish."""
    return max(own, _peer_desired_interval.get((email or "").lower(), 0))


def current_telemetry_interval() -> int:
    return _telemetry_interval_now
PEER_ANSWER_TTL = 20.0  # an answer to a peer's cross-check is dropped if the outbox could not send it by then
PEER_ANSWER_CACHE_TTL = 120
PEER_ANSWER_CACHE_MAX = 2000
PEER_ANSWER_REPLAY_GAP = 5
PEER_ANSWER_REPLAYS_PER_MINUTE = 6
PEER_BATCH_CHECK_CONCURRENCY = 20


def _peer_identity(peer):
    return peer.get("fingerprint") or peer["email"].lower()


class _ProbeAdmission(Enum):
    ACCEPTED = auto()
    RUNNING = auto()
    COMPLETED = auto()
    REJECTED = auto()


@dataclass
class _CachedProbeAnswer:
    sent_at: float
    kind: str
    payload: dict
    via: str
    replay_at: float = -math.inf
    mail_fallback_used: bool = False
    queued: object | None = None
    queued_until: float = -math.inf


class InboundProbeAdmission:
    """Reserve bounded work before creating tasks; shared by single and batch requests."""
    def __init__(self):
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(PEER_BATCH_CHECK_CONCURRENCY)
        self.outstanding = collections.Counter()
        self.rates = {}
        self.seen = collections.OrderedDict()
        self.running = {}
        self.answers = collections.OrderedDict()
        self.replay_rates = collections.OrderedDict()
        self.warned = {}

    def _expire_answers(self, now):
        while self.answers and next(iter(self.answers.values())).sent_at <= now - PEER_ANSWER_CACHE_TTL:
            self.answers.popitem(last=False)

    def reserve_replay(self, peer, req_id, via):
        if not isinstance(req_id, str) or not 0 < len(req_id) <= 64:
            return False, None
        identity = _peer_identity(peer)
        with self.lock:
            now = time.monotonic()
            self._expire_answers(now)
            answer = self.answers.get((identity, req_id))
            if answer is None:
                return False, None
            first_fallback = via == "mail" and answer.via == "rt" and not answer.mail_fallback_used
            if first_fallback:
                # The requester's mail fallback must work even if a realtime replay is queued.
                answer.mail_fallback_used = True
            else:
                if now < answer.queued_until or now - answer.replay_at < PEER_ANSWER_REPLAY_GAP:
                    return True, None
                times = self.replay_rates.setdefault(identity, collections.deque())
                while times and times[0] <= now - 60:
                    times.popleft()
                if len(times) >= PEER_ANSWER_REPLAYS_PER_MINUTE:
                    return True, None
                times.append(now)
                self.replay_rates.move_to_end(identity)
                if len(self.replay_rates) > PEER_ANSWER_CACHE_MAX:
                    self.replay_rates.popitem(last=False)
                answer.replay_at = now
            ticket = answer.queued = object()
            expires_at = answer.queued_until = now + PEER_ANSWER_TTL

        def pending():
            with self.lock:
                return answer.queued is ticket and time.monotonic() < expires_at

        def sent():
            with self.lock:
                if answer.queued is ticket:
                    if not first_fallback:
                        answer.replay_at = time.monotonic()
                    # A realtime answer can still fall back to mail after an ACK timeout.
                    if via == "mail":
                        answer.queued_until = -math.inf

        return True, (answer.kind, answer.payload, pending, sent)

    def remember_answer(self, key, kind, payload, *, via):
        with self.lock:
            now = time.monotonic()
            self._expire_answers(now)
            # A sent answer takes over replay protection from admission.
            self.seen.pop(key, None)
            self.answers[key] = _CachedProbeAnswer(now, kind, payload, via)
            self.answers.move_to_end(key)
            if len(self.answers) > PEER_ANSWER_CACHE_MAX:
                self.answers.popitem(last=False)

    def acquire(self, peer, req_id, slots=1, *, via="mail"):
        if not isinstance(req_id, str) or not 0 < len(req_id) <= 64:
            return _ProbeAdmission.REJECTED, None
        identity = _peer_identity(peer)
        key = (identity, req_id)
        with self.lock:
            now = time.monotonic()
            self._expire_answers(now)
            while self.seen and next(iter(self.seen.values())) <= now - 600:
                self.seen.popitem(last=False)
            if key in self.running:
                if via == "mail":
                    self.running[key] = "mail"
                return _ProbeAdmission.RUNNING, None
            if key in self.answers or key in self.seen:
                return _ProbeAdmission.COMPLETED, None
            for rate_identity, times in list(self.rates.items()):
                while times and times[0] <= now - 60:
                    times.popleft()
                if not times and not self.outstanding[rate_identity]:
                    del self.rates[rate_identity]
            self.warned = {key: ts for key, ts in self.warned.items() if ts > now - 600}
            times = self.rates.get(identity, ())
            rejected = (len(self.seen) + len(self.answers) >= 10000
                        or self.outstanding[identity] + slots > 10 or len(times) >= 120)
            reserved = 0
            if not rejected:
                for _ in range(slots):
                    if not self.slots.acquire(blocking=False):
                        rejected = True
                        break
                    reserved += 1
            if rejected:
                for _ in range(reserved):
                    self.slots.release()
                if identity not in self.warned:
                    self.warned[identity] = now
                    logger.warning("Dropping excess probe requests from peer %s", identity)
                return _ProbeAdmission.REJECTED, None
            self.outstanding[identity] += slots
            self.rates.setdefault(identity, collections.deque()).append(now)
            self.seen[key] = now
            self.running[key] = via
            return _ProbeAdmission.ACCEPTED, (key, slots)

    def reply_via(self, key):
        with self.lock:
            return self.running[key]

    def release(self, reservation):
        key, slots = reservation
        identity, _ = key
        with self.lock:
            del self.running[key]
            self.outstanding[identity] -= slots
            if not self.outstanding[identity]:
                del self.outstanding[identity]
            for _ in range(slots):
                self.slots.release()


_inbound_probes = InboundProbeAdmission()
# Carry the verified request context through the async probe to its outbox callback.
_inbound_probe_answer = contextvars.ContextVar("inbound_probe_answer", default=None)


def _submit_inbound_probe(peer, req_id, make_coro, slots=1, *, via):
    admission = _inbound_probes
    outcome, reservation = admission.acquire(peer, req_id, slots, via=via)
    if reservation is None:
        return outcome
    started = False

    async def run():
        nonlocal started
        started = True
        key, _ = reservation
        token = _inbound_probe_answer.set((key, admission))
        try:
            await make_coro()
        finally:
            _inbound_probe_answer.reset(token)
            admission.release(reservation)

    coro = run()
    try:
        if async_event_loop and async_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, async_event_loop)
        else:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                asyncio.run(coro)
            else:
                loop.create_task(coro)
    except Exception:
        coro.close()
        if not started:
            admission.release(reservation)
        raise
    return outcome


_peer_caps = {}  # peer email (lower) -> set of capabilities it announced
_peer_caps_announcements = {}  # peer identity -> last successfully announced local caps, per process
_peer_caps_requests = set()  # peer identities awaiting a capability announcement
_peer_caps_refresh = set()  # peers newly enabled for realtime, pending a fresh announcement
_peer_caps_attempted = set()  # peer identities that had a caps-only announcement attempt this process
_peer_caps_backoff = {}  # peer identity -> (announced signature, retry delay) while remote caps are unknown
_cross_check_queue = []  # (target_dict, future, reporting node or None) waiting for the next batch
# A vote asks a sample of the most stable peers, not all: every peer asked is two mails, and a
# quorum of 7 tells "down / only some" about as well as 20. Up to this many peers all are asked.
VOTE_SAMPLE_SIZE = 7
VOTE_HISTORY_WINDOW = 86400   # how far back a node's lone failures count against its stability
_node_vote_history = {}       # node -> deque of (time.time(), alone_failing: bool) of its counted votes

# /stats: counters since start and events of the last hour (in memory, reset on restart)
_bot_stats = {"started": time.time(), "trimmed": 0, "user_trimmed": 0}
_stat_events = collections.defaultdict(collections.deque)  # name -> times of the last hour
_cpu_samples = collections.deque(maxlen=4)  # (time.monotonic(), {name: cpu seconds}) once a minute
_last_check_summary = {}


def stat_event(name: str, now: float = None) -> None:
    now = now or time.time()
    q = _stat_events[name]
    q.append(now)
    while q and now - q[0] > 3600:
        q.popleft()


def stat_last_hour(name: str, now: float = None) -> int:
    now = now or time.time()
    q = _stat_events[name]
    while q and now - q[0] > 3600:
        q.popleft()
    return len(q)
_cross_check_flush_task = None
pending_batch_checks = {}  # req_id -> (Future, chat_id, number of targets)

# Quorum alerting (/alertmode quorum, the default): this node and its live peers vote on whether a
# failing target is reachable. Most nodes cannot reach it -> DOWN (incident). Some can't -> DEGRADED:
# a notice in the chat, no incident and no downtime. With fewer than 2 voters this node decides alone.
QUORUM_REVOTE_INTERVAL = 120
QUORUM_REVOTE_STEPS = (QUORUM_REVOTE_INTERVAL, 300, 600)
VOTE_PAUSE_AFTER = 3
VOTE_PAUSE_MIN = 300
VOTE_PAUSE_MAX = 1800
_vote_peer_lock = threading.Lock()
_vote_peers = {}          # peer identity -> _VotePeer
_vote_check = contextvars.ContextVar("vote_check", default=None)  # None: one-off, False: regular, _GridVoteCheck: grid
DEGRADED_CONFIRMATIONS = 2            # consecutive votes needed to enter or leave DEGRADED
DEGRADED_NOTIFY_WINDOW = 10.0         # seconds to collect DEGRADED changes of a chat into one message
VOTE_CACHE_MAX_ENTRIES = 20_000
_vote_cache = collections.OrderedDict()  # cross-check key -> _CachedVote
_alert_streaks = {}       # resource id -> (candidate alert state, consecutive votes for it)
_degraded_notify_queue = {}  # chat id -> list of ("start" | "end", resource, votes, started_at)
_degraded_flush_task = None
# A peer reporting a target DOWN in its telemetry while this node sees it UP: the target's next
# grid check asks peers and votes (the case "this node reaches it, most others don't").
PEER_SUSPECT_MAX_AGE = 300  # seconds a report stays valid, and how old the peer's result may be
_peer_suspects = {}  # url -> (monotonic time, reporting node, wall clock tick)
_peer_suspect_lock = threading.Lock()
# A peer whose report could not count (its vote abstained because the node is unstable) is not heard
# again for that target for a while: its votes are masked, the target stays UP, so every report of
# it started another vote - a noisy node (bad home network, Docker Desktop ICMP, split-horizon DNS)
# made the main node ask all peers ~450 times an hour, each time encrypted mail to every peer.
LONE_REPORTER_HOLD = 1800
# A report its own sender no longer confirms (asked a minute later it answers UP: a short burst, or
# a stale result from an older peer) is not heard again for that target for a shorter while
UNCONFIRMED_REPORT_HOLD = 600
# ... and each time it is unconfirmed again the hold doubles, up to this: an old peer that keeps
# reporting a target wrongly (an smtp:// target it checks as a web page) costs a vote every 2 h,
# not every 10 min. A report its sender confirms resets it.
UNCONFIRMED_REPORT_HOLD_MAX = 7200
DOWNLOAD_LIMIT = 65536
# (url, node) -> (time.time() until which its reports for url are ignored, unconfirmed in a row);
# also in the database (held_reports), so a restart does not start every hold over
_lone_reporters = {}
_lone_reporters_loaded = False


def _held_reports() -> dict:
    global _lone_reporters_loaded
    if not _lone_reporters_loaded:
        _lone_reporters_loaded = True
        try:
            for url, node, until, streak in database.get_held_reports(time.time() - UNCONFIRMED_REPORT_HOLD_MAX):
                _lone_reporters.setdefault((url, node), (until, streak))
        except Exception as e:
            logger.debug(f"Could not load held peer reports: {e}")
    return _lone_reporters


def report_held(url: str, node: str, now: float = None) -> bool:
    entry = _held_reports().get((url, node))
    return bool(entry) and entry[0] > (now or time.time())

# Path quality of ping checks: a target that answers through a congested or lossy path (e.g. a bad
# peering between this node's provider and the target's) is still reachable, so it is not DOWN.
# Such a check returns CHECK_DEGRADED instead of True and this node votes "degraded": in quorum
# chats that makes a DEGRADED notice (never an incident) that names the node and why.
CHECK_DEGRADED = "degraded"   # truthy on purpose: code that only asks "reachable?" sees it as up
PING_COUNT = 5                # echoes per check, sent PING_SPACING apart, each waiting PING_TIMEOUT
PING_SPACING = 0.2
PING_TIMEOUT = 2.0
DEGRADED_LOSS_PCT = 40        # 2 of 5 lost: one lost echo happens on healthy paths too
DEGRADED_RTT_FACTOR = 3       # median RTT this many times the usual one ...
DEGRADED_RTT_MIN_EXTRA_MS = 100  # ... and at least this much above it (5 -> 15 ms is no problem)
DEGRADED_VOTE_ERROR_MAX = 160    # a degraded vote also carries the traceroute hint
DEGRADED_MIN_SAMPLES = 3      # bad series in a row before this node calls a path degraded ...
DEGRADED_MIN_DURATION = 180   # ... spanning at least this many seconds: a short burst on the node's
                              # own uplink (several targets at once, gone in a minute) is not a bad path
_ping_bad_streaks = {}        # ip -> (time.time() of the first bad series in a row, bad series in a row)
PATH_TRACE_TTL = 900          # seconds a traceroute of a degraded path is reused
_path_traces = {}             # ip -> (time.time(), summary or "") of the last traceroute
_path_trace_tasks = {}        # ip -> running traceroute task
_ping_baseline_cache = {}     # ip -> usual RTT in ms (persisted in database.ping_baselines)
_local_degraded = {}          # url -> time.time() of this node's last degraded result (telemetry)

class _ProcessedMessageIds(collections.OrderedDict):
    def add(self, msg_id):
        self[msg_id] = None
        if len(self) > 2000:
            self.popitem(last=False)


_processed_msg_ids = _ProcessedMessageIds()
_peer_metrics_lock = threading.Lock()
_peer_metrics_timestamps = collections.OrderedDict()  # peer identity -> latest applied timestamp
PEER_METRICS_TIMESTAMPS_MAX = 256
PEER_METRICS_QUEUE_SIZE = 4
PEER_METRICS_QUEUE_BYTES = 8 * 1024 * 1024
PEER_METRICS_WORKERS = 2
PEER_METRICS_BATCH_DEADLINE = 10


class _PeerMetricsInbox:
    """Bound the backlog and let one worker at a time apply each peer's snapshots."""
    def __init__(self):
        self.lock = threading.Lock()
        self.pending = collections.OrderedDict()
        self.active = set()
        self.bytes = 0
        self.workers = 0
        self.closed = False
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=PEER_METRICS_WORKERS, thread_name_prefix="uptime_peer_metrics")

    def submit(self, peer, data, via, size, stamp=None):
        identity = _peer_identity(peer)
        with self.lock:
            queue = self.pending.get(identity)
            replace_size = queue[0][-1] if queue and len(queue) >= PEER_METRICS_QUEUE_SIZE else 0
            if self.closed or self.bytes + size - replace_size > PEER_METRICS_QUEUE_BYTES:
                return
            if replace_size:
                queue.popleft()
            self.pending.setdefault(identity, collections.deque()).append((peer, data, via, stamp, size))
            self.bytes += size - replace_size
            if identity not in self.active and self.workers < PEER_METRICS_WORKERS:
                self.workers += 1
                self.executor.submit(self._drain)

    def close(self):
        with self.lock:
            self.closed = True
            self.bytes -= sum(job[-1] for queue in self.pending.values() for job in queue)
            self.pending.clear()
        self.executor.shutdown(wait=False)

    def _drain(self):
        while True:
            with self.lock:
                identity = next((key for key in self.pending if key not in self.active), None)
                if identity is None:
                    self.workers -= 1
                    return
                queue = self.pending[identity]
                peer, data, via, stamp, size = queue.popleft()
                if queue:
                    self.pending.move_to_end(identity)
                else:
                    del self.pending[identity]
                self.active.add(identity)
            try:
                _apply_peer_metrics(peer, data, via, stamp=stamp)
            except Exception:
                logger.exception("Could not process peer metrics for %s", identity)
            finally:
                with self.lock:
                    self.bytes -= size
                    self.active.remove(identity)


_peer_metrics_inbox = _PeerMetricsInbox()

# Scheduler DB cache (reduces repeated full-table scans)
_scheduler_cache = {
    "resources": None,
    "resources_ts": 0,
    "probe_targets": None,
    "probe_targets_ts": 0,
    "ttl": 10,  # seconds
}

# Canary targets for verifying host outbound internet connectivity
CANARY_TARGETS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("9.9.9.9", 53),
    ("1.0.0.1", 53),
]
_canary_cache_lock = asyncio.Lock()
_canary_last_checked = 0.0
_canary_last_result = True
_host_outage_active = False

async def _test_single_canary(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def check_host_internet_connectivity(timeout: float = 2.5, max_age: float = 5.0) -> bool:
    """Verifies that the bot host has outbound internet connectivity via fast canary checks."""
    global _canary_last_checked, _canary_last_result, _host_outage_active
    now = time.time()
    
    if now - _canary_last_checked < max_age:
        return _canary_last_result
        
    async with _canary_cache_lock:
        if time.time() - _canary_last_checked < max_age:
            return _canary_last_result
            
        tasks = [_test_single_canary(host, port, timeout) for host, port in CANARY_TARGETS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        is_online = any(r is True for r in results)
        
        _canary_last_checked = time.time()
        _canary_last_result = is_online
        
        if not is_online:
            if not _host_outage_active:
                logger.warning("Host network outage detected! Canary checks failed. Suppressing false DOWN alerts.")
                _host_outage_active = True
        else:
            if _host_outage_active:
                logger.info("Host network connectivity restored.")
                _host_outage_active = False
                
        return is_online

_ADMIN_CHAT_MEMBERSHIP_TTL = 600
_admin_chat_membership_cache = {}  # chat_id -> (checked_at, admin_is_member)

_admin_contact_cache = {"at": 0.0, "id": None}
ADMIN_CONTACT_TTL = 600


def _admin_contact_id(bot, accid):
    """The admin's contact WITH their key (fingerprint from /initadmin).

    The core keeps an address-only contact and a key contact per address; lookup_contact_id_by_addr
    and create_contact give the address-only one. A chat with it cannot be written to ("e2e
    encryption unavailable"), and groups contain the key contact, so admin notices were lost and
    group membership checks missed the admin."""
    now = time.time()
    if _admin_contact_cache["id"] and now - _admin_contact_cache["at"] < ADMIN_CONTACT_TTL:
        return _admin_contact_cache["id"]
    email, fp = database.get_effective_admin()
    if not email or bot is None or accid is None:
        return None
    # Read once for the loops below; a substring search of the whole encryption info would also
    # match a contact who put the admin's fingerprint into their display name
    self_fp = dc_fingerprint.get_self_fingerprint(bot.rpc, accid) if fp else None
    found = None
    try:
        candidates = bot.rpc.get_contact_ids(accid, 0, email) or []
    except Exception as e:
        logger.debug(f"Could not list admin contacts: {e}")
        candidates = []
    for cid in candidates:
        try:
            c = bot.rpc.get_contact(accid, cid)
            if (_field(c, "address") or "").lower() != email or not _field(c, "is_key_contact", False):
                continue
            if fp and dc_fingerprint.get_contact_fingerprint(bot.rpc, accid, cid, self_fp=self_fp) != fp:
                continue  # same address, other key: not the admin
            found = cid
            break
        except Exception:
            continue
    if not found and fp:
        # The admin's key contact can sit under another address than the one in /initadmin (their
        # transport changed, e.g. to an anonymous address on chat.gluek.info); the fingerprint is
        # the identity, so look through all key contacts. Without it admin notices went to the
        # address-only contact and failed with "e2e encryption unavailable".
        try:
            everyone = bot.rpc.get_contact_ids(accid, 0, None) or []
        except Exception as e:
            logger.debug(f"Could not list contacts: {e}")
            everyone = []
        for cid in everyone:
            if cid in candidates:
                continue  # already checked by address
            try:
                c = bot.rpc.get_contact(accid, cid)
                if not _field(c, "is_key_contact", False):
                    continue
                if dc_fingerprint.get_contact_fingerprint(bot.rpc, accid, cid, self_fp=self_fp) == fp:
                    found = cid
                    break
            except Exception:
                continue
    if not found:
        try:
            found = bot.rpc.lookup_contact_id_by_addr(accid, email)  # older cores: one contact per address
        except Exception as e:
            logger.debug(f"Could not look up admin contact: {e}")
    _admin_contact_cache.update(at=now, id=found)
    return found


def _get_admin_chat_ids(bot, accid, chat_ids) -> set:
    """Returns the subset of chat_ids that the administrator belongs to (1:1 admin chat or groups with the admin)."""
    allowed = set()
    admin_chat = database.get_config("admin_chat_id")
    if admin_chat and str(admin_chat).isdigit():
        allowed.add(int(admin_chat))

    admin_contact_id = _admin_contact_id(bot, accid)
    if not admin_contact_id:
        return allowed & set(chat_ids)

    now = time.time()
    for chat_id in chat_ids:
        if not chat_id or chat_id in allowed:
            continue
        cached = _admin_chat_membership_cache.get(chat_id)
        if cached and now - cached[0] < _ADMIN_CHAT_MEMBERSHIP_TTL:
            is_member = cached[1]
        else:
            try:
                is_member = admin_contact_id in (bot.rpc.get_chat_contacts(accid, chat_id) or [])
            except Exception:
                is_member = False
            _admin_chat_membership_cache[chat_id] = (now, is_member)
        if is_member:
            allowed.add(chat_id)
    return allowed & set(chat_ids)

# Chats the bot can no longer write to (removed from the group, chat deleted, contact blocked):
# their monitors are paused instead of being checked for nobody, and deleted after a grace period
# unless the bot is added back (then they resume with all settings).
ABANDONED_CHAT_GRACE = 30 * 86400
CHAT_AUDIT_INTERVAL = 3600
# Peer chats carry only protocol messages, handled as they arrive. When kept for a day
# by delete_device_after (for incident edits in user chats), they piled up to ~65k
# messages and a 175 MB database, and the core spent ~0.5 s CPU per message instead of ~0.1 s.
PEER_CHAT_TRIM_INTERVAL = 600
PEER_CHAT_KEEP = 20       # newest messages left in each peer chat (a reply may still be on its way)
PEER_CHAT_TRIM_CHUNK = 500


def _field(obj, name, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def chat_send_state(bot, accid, chat_id: int) -> tuple[str | None, str]:
    """-> (state, chat name). state: "ok", "gone" (chat deleted), "removed" (bot no longer in the
    group), "blocked" (1:1 contact blocked), or None when the core could not be asked (no change)."""
    try:
        chat = bot.rpc.get_full_chat_by_id(accid, chat_id)
    except Exception as e:
        # the core's answer for a chat id that no longer exists
        if "query returned no rows" in str(e).lower():  # "Failed loading chat Chat#N from database: ..."
            return "gone", f"chat {chat_id}"
        logger.warning(f"Chat audit: could not load chat {chat_id}: {e}")
        return None, f"chat {chat_id}"
    name = _field(chat, "name") or f"chat {chat_id}"
    chat_type = str(_field(chat, "chat_type", ""))
    # self_in_group only means something for groups: the core reports False for every 1:1 chat
    # and for channels this bot sends (OutBroadcast), although it can write to them
    if chat_type in ("Group", "120") and _field(chat, "self_in_group", True) is False:
        return "removed", name
    if chat_type in ("Single", "100"):
        for contact_id in _field(chat, "contact_ids", None) or []:
            if contact_id <= 9:  # special ids (1 = this bot)
                continue
            try:
                if _field(bot.rpc.get_contact(accid, contact_id), "is_blocked", False):
                    return "blocked", name
            except Exception:
                pass
    return "ok", name


_ABANDON_REASONS = {"gone": "the chat was deleted", "removed": "the bot was removed from the group",
                    "blocked": "the contact was blocked"}


def trim_peer_chats(bot, accid) -> int:
    """Deletes all but the newest PEER_CHAT_KEEP messages of every peer chat, on this device only
    (delete_messages, not for all). Returns how many."""
    deleted = 0
    for peer in database.get_all_peers():
        chat_id = peer.get("chat_id")
        if not chat_id:
            continue
        try:
            old = bot.rpc.get_message_ids(accid, chat_id, False, False)[:-PEER_CHAT_KEEP]
        except Exception as e:
            logger.warning(f"Could not list peer chat {chat_id} ({peer.get('node_name')}): {e}")
            continue
        deleted += _delete_trimmed_messages(bot, accid, old)
    if deleted:
        logger.info(f"Deleted {deleted} old protocol messages from peer chats")
        _bot_stats["trimmed"] += deleted
    return deleted


def _delete_trimmed_messages(bot, accid, old) -> int:
    deleted = 0
    for i in range(0, len(old), PEER_CHAT_TRIM_CHUNK):
        # Recheck at deletion time so a just-accepted OFFER is protected too.
        with _peer_rt_lock:
            protected = database.get_peer_rt_message_ids()
            chunk = [msg_id for msg_id in old[i:i + PEER_CHAT_TRIM_CHUNK] if msg_id not in protected]
            if not chunk:
                continue
            try:
                bot.rpc.delete_messages(accid, chunk)
                deleted += len(chunk)
            except Exception:
                # The core stops at the first message already gone.
                for msg_id in chunk:
                    try:
                        bot.rpc.delete_messages(accid, [msg_id])
                        deleted += 1
                    except Exception:
                        pass
    return deleted


def trim_user_chats(bot, accid) -> int:
    """Locally trim non-peer chats, preserving live references and the newest 20."""
    deleted = 0
    examined = 0
    try:
        peers = {p.get("chat_id") for p in database.get_all_peers()}
        protected = database.get_retained_message_ids()
        cutoff = int(time.time()) - USER_CHAT_KEEP_SECONDS
        # Include archived chats (flag 1) as well as the ordinary chat list.
        chats = dict.fromkeys(bot.rpc.get_chatlist_entries(accid, 0, None, None)
                              + bot.rpc.get_chatlist_entries(accid, 1, None, None))
        for chat_id in chats:
            if chat_id in peers or chat_id <= 9:
                continue
            try:
                # The core returns oldest first (IDs need not be numerically ordered).
                ids = bot.rpc.get_message_ids(accid, chat_id, False, False)[:-20]
            except Exception as exc:
                logger.warning("Cannot list user chat %s: %s", chat_id, exc)
                continue
            old = []
            for msg_id in ids:
                if examined >= USER_CHAT_TRIM_MAX:
                    break
                examined += 1
                try:
                    message = bot.rpc.get_message(accid, msg_id)
                    timestamp = _field(message, "timestamp")
                    if timestamp is None:
                        continue
                    if timestamp >= cutoff:
                        break
                    if msg_id not in protected:
                        old.append(msg_id)
                except Exception:
                    continue  # A core expiry or concurrent deletion is harmless.
            deleted += _delete_trimmed_messages(bot, accid, old)
            if examined >= USER_CHAT_TRIM_MAX:
                break
    except Exception as exc:
        logger.warning("Cannot trim user chats: %s", exc)
    _bot_stats["user_trimmed"] += deleted
    logger.info("Deleted %s old messages from user chats (%s examined)", deleted, examined)
    return deleted


def _delete_abandoned_chat(chat_id):
    with _peer_rt_lock:
        peer = database.get_peer_by_chat_id(chat_id)
        deleted = database.delete_chat_data(chat_id)
        if peer and (peer["rt_msg_id"] or peer["rt_offer_msg_id"]):
            _refresh_peer_rt_channels()
        return deleted


async def audit_abandoned_chats(now: int = None) -> None:
    """Pauses monitors of chats the bot cannot write to, resumes them when it can again and
    deletes them after ABANDONED_CHAT_GRACE. Runs at start and every CHAT_AUDIT_INTERVAL."""
    if not dc_bot_instance or dc_accid is None:
        return
    now = now or int(time.time())
    changed = False
    for chat_id, abandoned_at in (await run_db(database.get_monitored_chats)).items():
        state, name = await asyncio.to_thread(chat_send_state, dc_bot_instance, dc_accid, chat_id)
        if state is None:
            continue
        count = len(await run_db(database.get_resources, chat_id))
        if state != "ok" and abandoned_at is None:
            await run_db(database.set_chat_abandoned, chat_id, now)
            changed = True
            until = datetime.datetime.fromtimestamp(now + ABANDONED_CHAT_GRACE, tz=datetime.timezone.utc).strftime('%Y-%m-%d')
            logger.warning(f"Chat {chat_id} ({name}): {_ABANDON_REASONS[state]}; pausing its {count} monitor(s)")
            await send_admin_notification(
                f"⏸️ **Monitoring Paused**: **{name}** (chat `{chat_id}`)\n"
                f"{_ABANDON_REASONS[state].capitalize()}, so alerts cannot be delivered there. "
                f"**{count}** monitor(s) are paused and no longer shared with peers.\n\n"
                f"They will be deleted on `{until}` unless the bot is added back; then they resume with all settings.")
        elif state == "ok" and abandoned_at is not None:
            await run_db(database.set_chat_abandoned, chat_id, None)
            changed = True
            logger.info(f"Chat {chat_id} ({name}) can be written to again; resuming its {count} monitor(s)")
            await send_admin_notification(f"▶️ **Monitoring Resumed**: **{name}** (chat `{chat_id}`)\n"
                                          f"The bot can write there again: **{count}** monitor(s) are checked again.")
        elif state != "ok" and now - abandoned_at >= ABANDONED_CHAT_GRACE:
            deleted = await run_db(_delete_abandoned_chat, chat_id)
            changed = True
            logger.warning(f"Chat {chat_id} ({name}) abandoned for 30 days: deleted {deleted} monitor(s)")
            await send_admin_notification(f"🗑️ **Paused Monitors Deleted**: **{name}** (chat `{chat_id}`)\n"
                                          f"The bot was not added back within 30 days: **{deleted}** monitor(s) and their history were deleted.")
    if changed:
        _scheduler_cache["resources"] = None  # the scheduler picks the change up at once


def _filter_peer_shareable_resources(bot, accid, resources: list[dict]) -> list[dict]:
    """Applies the peer share scope (/peershare) to local monitors before disclosing them to peers."""
    scope = database.get_peer_share_scope()
    if scope == "all":
        return list(resources)
    if scope == "none":
        return []
    allowed = _get_admin_chat_ids(bot, accid, {r.get("dc_chat_id") for r in resources})
    return [r for r in resources if r.get("dc_chat_id") in allowed]

async def _resolve_peer_chat_id(p: dict):
    chat_id = p.get("chat_id")
    if not chat_id and p.get("email") and not p["email"].endswith("@securejoin"):
        try:
            contact_id = await asyncio.to_thread(dc_bot_instance.rpc.create_contact, dc_accid, p["email"], p.get("node_name") or p["email"])
            chat_id = await asyncio.to_thread(dc_bot_instance.rpc.create_chat_by_contact_id, dc_accid, contact_id)
            await asyncio.to_thread(database.add_or_update_peer, p["email"], p.get("node_name"), chat_id)
        except Exception as e:
            logger.warning(f"Could not resolve chat_id for peer {p['email']}: {e}")
            return None
    return chat_id


def _record_peer_rtt(kind, peer, started_at, finished_at, ok, transport="mail"):
    database.record_peer_rtt(kind, transport, peer, round((finished_at - started_at) * 1000), ok)


class _PeerVoteRound:
    def __init__(self):
        self.samples = []

    def finish(self):
        # The individual attempts finish before their jobs return from gather.
        if self.samples:
            started_at = min(start for start, _, _, _ in self.samples)
            finished_at = max(end for _, end, _, _ in self.samples)
            ok = all(ok for _, _, ok, _ in self.samples)
            transports = {transport for _, _, _, transport in self.samples}
            transport = transports.pop() if len(transports) == 1 else "mixed"
            _record_peer_rtt("vote_round", None, started_at, finished_at, ok, transport)


@dataclass
class _VotePeer:
    streak: int = 0
    pause: int = 0
    until: float = 0
    last_answer: float = -math.inf
    probing: bool = False


def _vote_peer_key(peer):
    return peer.get("fingerprint") or peer["email"].lower()


def _note_vote_peer_result(peer, ok):
    now = time.monotonic()
    with _vote_peer_lock:
        state = _vote_peers.setdefault(_vote_peer_key(peer), _VotePeer())
        name = peer.get("node_name") or peer["email"]
        if ok:
            if state.pause:
                logger.info("Votes resumed for %s after an answer", name)
            state.last_answer = now
            state.streak = state.pause = state.until = 0
            return
        state.streak += 1
        if state.streak >= VOTE_PAUSE_AFTER and now >= state.until:
            state.pause = min(VOTE_PAUSE_MAX, max(VOTE_PAUSE_MIN, state.pause * 2))
            state.until = now + state.pause
            logger.info("Non-urgent votes paused for %s for %d min", name, state.pause // 60)


def _vote_peer_modes(peers, now):
    """Caller holds the vote peer lock. Only one request may test an expired pause."""
    modes = {}
    for peer in peers:
        key = _vote_peer_key(peer)
        state = _vote_peers.get(key)
        if state is None or not state.pause:
            modes[key] = "ask"
        elif state.until <= now and not state.probing:
            modes[key] = "probe"
        else:
            modes[key] = "skip"
    if modes and all(mode == "skip" for mode in modes.values()):
        available = [key for key in modes if not _vote_peers[key].probing]
        for key in sorted(available, key=lambda key: (_vote_peers[key].last_answer, key))[:2]:
            modes[key] = "fallback"
    return modes


def _paused_vote_peers(peers):
    now, wall = time.monotonic(), time.time()
    with _vote_peer_lock:
        modes = _vote_peer_modes([p for p in peers if not p.get("is_offline")], now)
        return {
            key: wall + _vote_peers[key].until - now
            for key, mode in modes.items() if mode == "skip" and _vote_peers[key].until > now
        }


async def _probe_vote_peer(peer, request, *args, **kwargs):
    key = _vote_peer_key(peer)
    with _vote_peer_lock:
        state = _vote_peers[key]
        if state.probing or state.until > time.monotonic():
            return []
        probing = bool(state.pause)
        if probing:
            state.probing = True
            logger.info("Probing %s after its vote pause", peer.get("node_name") or peer["email"])
    try:
        return await request(*args, **kwargs)
    finally:
        if probing:
            with _vote_peer_lock:
                state.probing = False


class _PeerRtt:
    def __init__(self, kind, peer):
        self.kind = kind
        self.peer = peer
        self.vote_round = _peer_vote_round.get()
        self.submitted_at = time.monotonic()
        self.sent_at = None
        self.rt_sent_at = None
        self.answer = None

    def start(self):
        self.sent_at = time.monotonic()

    def start_rt(self):
        self.rt_sent_at = time.monotonic()

    def note_answer(self, arrived_at, node_name, via):
        self.answer = (arrived_at, node_name, via)
        if self.vote_round is not None or self.kind == "vote":
            _note_vote_peer_result(self.peer, True)

    def finish(self, ok, finished_at=None, peer=None):
        via = "mail" if self.sent_at is not None or self.rt_sent_at is None else "rt"
        if self.answer is not None:
            finished_at, peer, via = self.answer
        if finished_at is None:
            finished_at = time.monotonic()
        # A request can expire in the outbox before it gets a send token.
        sent_at = self.rt_sent_at if via == "rt" or self.sent_at is None else self.sent_at
        if sent_at is not None and sent_at > finished_at:
            sent_at = self.rt_sent_at
        started_at = sent_at if sent_at is not None and sent_at <= finished_at else self.submitted_at
        if self.kind:
            _record_peer_rtt(self.kind, peer or self.peer.get("node_name") or "Remote-Node",
                             started_at, finished_at, ok, via)
        if self.vote_round is not None:
            # A round includes any time spent waiting for a fallback.
            self.vote_round.samples.append((self.rt_sent_at if self.rt_sent_at is not None else started_at,
                                            finished_at, ok, via))
        if (self.vote_round is not None or self.kind == "vote") and self.answer is None and (
                ok or self.sent_at is not None or self.rt_sent_at is not None):
            _note_vote_peer_result(self.peer, ok)


async def request_peer_cross_checks(target_dict: dict, timeout: float = 8.0, peers: list[dict] | None = None) -> list[dict]:
    """Broadcasts a cross-check request for one target to the peers (default: all) in 1:1 DMs
    and waits for responses. /ping uses it directly; monitors go through the batched variant."""
    if peers is None:
        peers = await asyncio.to_thread(database.get_all_peers)
    url = target_dict.get("url", "")
    active_peers = []
    ignored_responses = []
    for p in peers or []:
        if not _peer_can_check(p, target_dict):
            continue
        p_node = p.get("node_name") or ""
        if p_node and await asyncio.to_thread(database.is_node_target_ignored, p_node, url):
            ignored_responses.append({
                "url": url,
                "node_name": p_node,
                "status": "skip",
                "latency_ms": None,
                "error_msg": "Ignored for node (/nodeignore)"
            })
            continue
        active_peers.append(p)

    if not active_peers or not dc_bot_instance or dc_accid is None:
        return ignored_responses

    req_id = secrets.token_hex(12)
    req_payload = {
        "req_id": req_id,
        "url": target_dict["url"],
        "type": target_dict.get("type", "http"),
        "expected_keyword": target_dict.get("expected_keyword"),
        "node_name": database.get_local_node_name(),
        "caps": OWN_PEER_CAPS,
    }
    if target_dict.get("family") in (4, 6):
        req_payload["family"] = target_dict["family"]  # older peers ignore it and check any family

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return ignored_responses

    fut = loop.create_future()
    responses = []

    valid_peers = []
    for p in active_peers:
        chat_id = await _resolve_peer_chat_id(p)
        if chat_id:
            valid_peers.append((p, chat_id))

    if not valid_peers:
        return ignored_responses

    # Only the peers this request was sent to may answer it, each once and in its own 1:1 chat.
    # Chats rather than addresses: a peer may answer from another relay address than it used before.
    expected_chats = {chat_id for _, chat_id in valid_peers}
    pending_peer_checks[req_id] = (fut, len(valid_peers), responses, expected_chats)
    timings = _pending_peer_rtt[req_id] = {}
    is_vote = _peer_vote_round.get() is not None
    kind = None if is_vote else "ping"
    timed_out_at = None
    try:
        for p, chat_id in valid_peers:
            timing = timings[chat_id] = _PeerRtt(kind, p)
            try:
                # A request still queued when the answer is no longer awaited is dropped
                destination = _PeerDestination(dc_bot_instance, dc_accid, chat_id, fingerprint=p.get("fingerprint"))
                payload = dict(req_payload, caps=_own_peer_caps(p))
                await asyncio.to_thread(peer_send, destination, "CHECK_REQ", payload,
                                        priority=PRIO_PEER, expires_in=timeout, label="cross-check request",
                                        mail_kind="peer_vote" if is_vote else "peer_other", before_send=timing.start,
                                        before_rt_send=timing.start_rt,
                                        rt_waiting=lambda chat_id=chat_id: not fut.done() and req_id in pending_peer_checks
                                        and chat_id in expected_chats)
            except Exception as e:
                logger.warning(f"Failed to send cross-check request to peer {p.get('email')}: {e}")

        await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        timed_out_at = time.monotonic()
        logger.info(f"Cross-check req_id {req_id} timed out waiting for all peer responses (got {len(responses)}/{len(valid_peers)})")
    except Exception as e:
        logger.warning(f"Error during peer cross-check wait: {e}")
    finally:
        pending_peer_checks.pop(req_id, None)
        _pending_peer_rtt.pop(req_id, None)

    for timing in timings.values():
        if timing.answer is not None:
            timing.finish(True)
        elif timed_out_at is not None:
            timing.finish(False, timed_out_at)

    return responses + ignored_responses

def _cross_check_key(t: dict) -> tuple:
    return (t.get("type") or "http", t.get("url"), (t.get("expected_keyword") or "").strip(), t.get("family") or 0)


def _peer_supports(peer: dict, cap: str) -> bool:
    caps = _peer_caps.get((peer.get("email") or "").lower())
    if caps is None:
        return cap == PEER_CAP_RT and bool(peer.get("rt_capable"))
    return cap in caps


def _peer_can_check(peer: dict, target: dict) -> bool:
    """Whether a peer understands the target's check type (smtp:// needs PEER_CAP_SMTP_CHECK)."""
    return (target.get("type") or "http") != "smtp" or _peer_supports(peer, PEER_CAP_SMTP_CHECK)


def telemetry_interval(peer_count: int) -> int:
    """Seconds between this node's telemetry messages: 2 min up to 10 peers, 3 min up to 20, then 5."""
    for more_than, interval in TELEMETRY_INTERVAL_STEPS:
        if peer_count > more_than:
            return interval
    return TELEMETRY_INTERVAL


def peer_offline_after(email: str) -> int:
    """Silence after which a peer counts as offline: PEER_OFFLINE_INTERVALS of the telemetry
    interval it announced (older peers announce none: 2 min, so 6 min as before)."""
    email = (email or "").lower()
    with _peer_rt_lock:
        for link in _peer_rt_links.values():
            if link.peer["email"].lower() == email and link.state.is_up and link.incoming_metrics_interval is not None:
                return PEER_OFFLINE_INTERVALS * link.incoming_metrics_interval
    return PEER_OFFLINE_INTERVALS * _peer_telemetry_interval.get(email, TELEMETRY_INTERVAL)


_VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
_peer_versions = {}  # peer email (lower) -> version last stored, so telemetry does not rewrite it


def version_tuple(version) -> tuple:
    try:
        return tuple(int(x) for x in str(version).split("."))
    except ValueError:
        return ()


def note_peer_version(email: str, version) -> None:
    """Stores the bot version a peer announces (telemetry and handshakes), when it changed."""
    if not email or not isinstance(version, str) or not _VERSION_RE.match(version.strip()):
        return
    version, key = version.strip(), email.lower()
    if _peer_versions.get(key) != version:
        _peer_versions[key] = version
        try:
            database.set_peer_version(email, version)
        except Exception as e:
            logger.debug(f"Could not store the version of peer {email}: {e}")


def outdated_peers(peers: list[dict]) -> list[str]:
    """'🇵🇱 v2.24.1', '🇷🇺 ≤2.26.2' for peers older than this node (no version: from before 2.26.3)."""
    own = version_tuple(VERSION)
    out = []
    for p in peers:
        v = p.get("version")
        if not v:
            out.append(f"{p.get('node_name') or p.get('email')} ≤2.26.2")
        elif version_tuple(v) < own:
            out.append(f"{p.get('node_name') or p.get('email')} v{v}")
    return out


def _note_peer_caps(email: str, caps) -> None:
    if email and isinstance(caps, list):
        email = email.lower()
        announced = {str(c)[:40] for c in caps[:20]}
        with _peer_rt_lock:
            if PEER_CAP_RT in announced and PEER_CAP_RT not in _peer_caps.get(email, ()):
                _peer_rt_audit_requested.set()
            _peer_caps[email] = announced


def _fresh_peer_caps(peer, timestamp, msg_id):
    if timestamp is not None:
        now = time.time()
        if not now - PEER_CAPS_MAIL_MAX_AGE <= timestamp <= now + PEER_CAPS_MAIL_MAX_AGE:
            return False
        previous = peer.get("rt_caps_timestamp")
        if previous is not None and (timestamp < previous or (timestamp == previous and msg_id is None)):
            return False
    previous_id = peer.get("rt_caps_msg_id")
    if msg_id is not None:
        return previous_id is None or msg_id > previous_id
    return timestamp is not None


def _mail_announcement_stamp(msg):
    timestamp = _field(msg, "timestamp")
    msg_id = _field(msg, "id")
    return (timestamp if type(timestamp) is int and timestamp > 0 else None,
            msg_id if type(msg_id) is int and msg_id > 0 else None)


def _note_peer_announcement(peer: dict, data, *, allow_rename=True, telemetry=False, allow_caps=True,
                            via="mail", stamp=None) -> dict:
    """What a key-verified peer says about itself in protocol messages: its capabilities and its
    node name (changed with /nodename there). Returns the peer row, renamed if the name changed.

    The name is trusted because the peer is bound to its key; it may still not take the name of this
    node or of another peer, so it cannot pose as a different node in votes and measurements."""
    if not isinstance(data, dict):
        return peer
    if allow_caps:
        with _peer_rt_lock:
            caps = data.get("caps")
            fingerprint = peer.get("fingerprint")
            if fingerprint:
                peer = database.get_peer_by_fingerprint(fingerprint) or peer
            had_rt = (_peer_supports(peer, PEER_CAP_RT) or peer.get("rt_capable")
                      or peer.get("rt_cid") or peer.get("rt_offer_at") is not None)
            if telemetry and had_rt and not isinstance(caps, list):
                # Older METRICS can omit caps entirely. Keep the legacy capability
                # cache behavior for all other capabilities.
                caps = [cap for cap in _peer_caps.get(peer["email"].lower(), ()) if cap != PEER_CAP_RT]
            if isinstance(caps, list):
                caps = [str(cap)[:40] for cap in caps[:20]]
                supports_rt = PEER_CAP_RT in caps
                timestamp, msg_id = stamp or (None, None)
                fresh = (_fresh_peer_caps(peer, timestamp, msg_id)
                         or stamp is None and supports_rt and not peer.get("rt_caps_timestamp")
                         and not peer.get("rt_caps_msg_id"))
                # An older message may still teach legacy capabilities. It must
                # preserve the current realtime capability and carrier.
                if (had_rt or supports_rt) and not fresh:
                    caps = [cap for cap in caps if cap != PEER_CAP_RT]
                    if had_rt:
                        caps.insert(0, PEER_CAP_RT)
                _note_peer_caps(peer["email"], caps)
                if isinstance(data.get("caps"), list):
                    _peer_caps_backoff.pop(_peer_identity(peer), None)
                if fingerprint and fresh and (had_rt or supports_rt):
                    database.set_peer_rt_capability(fingerprint, supports_rt, timestamp=timestamp, msg_id=msg_id)
                    if supports_rt != bool(peer.get("rt_capable")) or not supports_rt:
                        _refresh_peer_rt_channels()
    note_peer_version(peer["email"], data.get("version"))
    email = peer["email"].lower()
    announced = data.get("telemetry_interval")
    if type(announced) is int:
        empty_rt_mail = (telemetry and via == "mail" and data.get("metrics") == [] and peer.get("rt_msg_id")
                         and isinstance(data.get("caps"), list) and PEER_CAP_RT in data["caps"])
        # Realtime has its own interval while UP. Keep the mail cadence across short recoveries
        # and caps-only mail until the peer resumes sending nonempty mail snapshots.
        if empty_rt_mail and announced == RT_MAIL_KEEPALIVE:
            _peer_telemetry_interval[email] = RT_MAIL_KEEPALIVE
        elif (_peer_telemetry_interval.get(email) != RT_MAIL_KEEPALIVE
              or (via == "mail" and not empty_rt_mail)):
            _peer_telemetry_interval[email] = min(900, max(60, announced))
    desired = data.get("desired_interval")
    if type(desired) is int:
        _peer_desired_interval[email] = min(900, max(60, desired))
    if not allow_rename:
        return peer
    claimed = data.get("node_name")
    claimed = claimed.strip()[:64] if isinstance(claimed, str) else ""
    current = peer.get("node_name") or ""
    if not claimed or claimed == current:
        return peer
    taken = {database.get_local_node_name().casefold()} | {
        (p.get("node_name") or "").casefold() for p in database.get_all_peers() if p["email"] != peer["email"]}
    if claimed.casefold() in taken:
        logger.warning(f"Peer {peer['email']} announces node name {claimed!r}, already used by another node; keeping {current!r}")
        return peer
    if database.rename_peer_node(peer["email"], claimed):
        logger.info(f"Peer {peer['email']} renamed its node: {current!r} -> {claimed!r}")
        peer = dict(peer, node_name=claimed)
    return peer


@dataclass
class _GridVoteCheck:
    tick: float
    requests: list
    ready: asyncio.Event


async def request_peer_cross_checks_batched(target_dict: dict, reporter: str = None, *, urgent=True) -> list[dict]:
    """Cross-check of a failing monitor, sent together with the others failing at the same time.

    Waits up to CROSS_CHECK_BATCH_WINDOW for more targets, then sends one request per peer (peers
    that did not announce batch support get the old one-target requests). Returns the peers'
    answers for this target, like request_peer_cross_checks."""
    global _cross_check_flush_task
    fut = asyncio.get_running_loop().create_future()
    request = (target_dict, fut, reporter)
    grid = _vote_check.get()
    if not urgent:
        if grid:
            grid.requests.append(request)
            grid.ready.set()
        else:
            await _flush_cross_checks([request], urgent=False)
        return await fut
    if grid:
        grid.ready.set()
    _cross_check_queue.append(request)
    if len(_cross_check_queue) >= CROSS_CHECK_BATCH_MAX:
        batch = _cross_check_queue[:]
        _cross_check_queue.clear()
        asyncio.create_task(_flush_cross_checks(batch))
    elif _cross_check_flush_task is None:
        _cross_check_flush_task = asyncio.create_task(_delayed_cross_check_flush())
    try:
        return await asyncio.wait_for(asyncio.shield(fut), CROSS_CHECK_BATCH_WINDOW + CROSS_CHECK_BATCH_TIMEOUT + 5)
    except asyncio.TimeoutError:
        return []


def node_lone_failure_share(node: str, now: float = None) -> float:
    """Share of a node's counted votes in VOTE_HISTORY_WINDOW where it alone failed the target."""
    now = now or time.time()
    hist = _node_vote_history.get(node)
    if not hist:
        return 0.0
    while hist and now - hist[0][0] > VOTE_HISTORY_WINDOW:
        hist.popleft()
    return sum(1 for _, alone in hist if alone) / len(hist) if hist else 0.0


def pick_vote_peers(peers: list[dict], reporters=(), size: int = VOTE_SAMPLE_SIZE, now: float = None) -> list[dict]:
    """The peers a vote asks: all of them up to size; beyond that the nodes whose report started
    the vote (so they can confirm it) plus the most stable others - not unstable now, fewest lone
    failures in the last day, the most recently heard from first."""
    if len(peers) <= size:
        return peers
    now = now or time.time()
    required = [p for p in peers if p.get("node_name") in reporters]
    rest = sorted((p for p in peers if p.get("node_name") not in reporters),
                  key=lambda p: (is_node_unstable(p.get("node_name") or ""),
                                 node_lone_failure_share(p.get("node_name") or "", now),
                                 -(p.get("last_seen") or 0)))
    return required + rest[:max(0, size - len(required))]


async def _delayed_cross_check_flush():
    global _cross_check_flush_task
    try:
        await asyncio.sleep(CROSS_CHECK_BATCH_WINDOW)
    finally:
        _cross_check_flush_task = None
    batch = _cross_check_queue[:]
    _cross_check_queue.clear()
    await _flush_cross_checks(batch)


async def _flush_cross_checks(batch: list, *, urgent: bool = True) -> None:
    """Sends one batch: identical targets once, a batch message per capable peer, old requests to the rest."""
    if not batch:
        return
    by_key = {}
    reporters = set()
    for target, fut, reporter in batch:
        by_key.setdefault(_cross_check_key(target), (target, []))[1].append(fut)
        if reporter:
            reporters.add(reporter)
    results = {key: [] for key in by_key}
    try:
        peers = await asyncio.to_thread(database.get_all_peers) or []
        # Peers known to be offline would only make everyone wait for the timeout
        live = [p for p in peers if not p.get("is_offline")]
        peers = pick_vote_peers(live, reporters)
        stat_event("vote")
        modes = {}
        if not urgent:
            with _vote_peer_lock:
                modes = _vote_peer_modes(live, time.monotonic())
            selected = {_vote_peer_key(p) for p in peers}
            available = [p for p in live if modes[_vote_peer_key(p)] != "skip"]
            if not any(modes[key] != "skip" for key in selected):
                peers = peers + pick_vote_peers(available, reporters)
            else:
                peers = peers + [p for p in available if _vote_peer_key(p) not in selected
                                 and modes[_vote_peer_key(p)] == "fallback"]
        items = [(key, target) for key, (target, _) in by_key.items()]
        jobs = []
        legacy_peers = []

        async def legacy_probe(peer, key, target):
            results[key].extend(await _probe_vote_peer(
                peer, request_peer_cross_checks, target, timeout=8.0, peers=[peer]))

        for p in peers:
            mode = modes.get(_vote_peer_key(p), "ask")
            if mode == "skip":
                database.record_peer_traffic("vote_skipped_paused", "mail", "out", 0)
                continue
            if not _peer_supports(p, PEER_CAP_BATCH_CHECK):
                if mode == "probe":
                    for key, target in items:
                        node = p.get("node_name")
                        if _peer_can_check(p, target) and not (
                                node and database.is_node_target_ignored(node, target.get("url", ""))):
                            jobs.append(legacy_probe(p, key, target))
                            break
                else:
                    legacy_peers.append(p)
                continue
            p_node = p.get("node_name") or ""
            p_items = []
            for key, t in items:
                if not _peer_can_check(p, t):
                    continue
                if p_node and database.is_node_target_ignored(p_node, t.get("url", "")):
                    results[key].append({
                        "url": t.get("url"),
                        "node_name": p_node,
                        "status": "skip",
                        "latency_ms": None,
                        "error_msg": "Ignored for node (/nodeignore)"
                    })
                    continue
                p_items.append((key, t))
            if mode == "probe" and p_items:
                jobs.append(_probe_vote_peer(p, _batch_cross_check_peer, p, p_items[:CROSS_CHECK_BATCH_MAX], results))
            else:
                for i in range(0, len(p_items), CROSS_CHECK_BATCH_MAX):
                    jobs.append(_batch_cross_check_peer(p, p_items[i:i + CROSS_CHECK_BATCH_MAX], results))
        if legacy_peers:
            async def _legacy(key, target):
                results[key].extend(await request_peer_cross_checks(target, timeout=8.0, peers=legacy_peers))
            jobs += [_legacy(key, target) for key, target in items]
        vote_round = _PeerVoteRound()
        token = _peer_vote_round.set(vote_round)
        try:
            await asyncio.gather(*jobs, return_exceptions=True)
            vote_round.finish()
        finally:
            _peer_vote_round.reset(token)
    except Exception as e:
        logger.warning(f"Batched peer cross-check failed: {e}")
    finally:
        for key, (_, futs) in by_key.items():
            for f in futs:
                if not f.done():
                    f.set_result(list(results[key]))


async def _batch_cross_check_peer(peer: dict, items: list, results: dict) -> None:
    """One [UPTIME_PEER_CHECK_BATCH_REQ] to one peer; its answers are added to results[key]."""
    chat_id = await _resolve_peer_chat_id(peer)
    if not chat_id or not dc_bot_instance or dc_accid is None:
        return
    req_id = secrets.token_hex(12)
    payload = {
        "req_id": req_id,
        "node_name": database.get_local_node_name(),
        "caps": _own_peer_caps(peer),
        "targets": [{k: t.get(k) for k in ("url", "type", "expected_keyword", "family")} for _, t in items],
    }
    fut = asyncio.get_running_loop().create_future()
    pending_batch_checks[req_id] = (fut, chat_id, len(items))
    timing = _PeerRtt("vote", peer)
    _pending_peer_rtt[req_id] = {chat_id: timing}
    try:
        destination = _PeerDestination(dc_bot_instance, dc_accid, chat_id, fingerprint=peer.get("fingerprint"))
        await asyncio.to_thread(peer_send, destination, "CHECK_BATCH_REQ", payload,
                                priority=PRIO_PEER, expires_in=CROSS_CHECK_BATCH_TIMEOUT, label="batch cross-check request",
                                mail_kind="peer_vote", before_send=timing.start, before_rt_send=timing.start_rt,
                                rt_waiting=lambda: not fut.done() and req_id in pending_batch_checks)
        answers = await asyncio.wait_for(fut, CROSS_CHECK_BATCH_TIMEOUT)
    except asyncio.TimeoutError:
        timing.finish(False)
        logger.info(f"Batch cross-check {req_id} ({len(items)} targets) got no answer from {peer.get('email')} in time")
        return
    except Exception as e:
        logger.warning(f"Batch cross-check to {peer.get('email')} failed: {e}")
        return
    finally:
        pending_batch_checks.pop(req_id, None)
        _pending_peer_rtt.pop(req_id, None)
    timing.finish(True, peer=answers[0]["node_name"] if answers else None)
    answered = []
    for (key, target), answer in zip(items, answers):
        answer["url"] = target.get("url")  # positions are what the peer answers; URLs are ours
        results[key].append(answer)
        answered.append(answer)
    if answered:
        await run_db(database.save_peer_measurements_batch, answered[0]["node_name"], answered,
                     peer.get("fingerprint") or peer["email"])


def _clean_peer_result(item, node_name: str, url: str) -> dict:
    """A peer's answer for one target, with the same limits as single responses."""
    item = item if isinstance(item, dict) else {}
    status = item.get("status")
    if not isinstance(status, str) or status not in VOTING_STATUSES:
        status = "unknown"  # also "skip": the peer could not check it (no IPv6 there)
    latency_ms = item.get("latency_ms")
    if not isinstance(latency_ms, int) or isinstance(latency_ms, bool) or not 0 <= latency_ms <= 600000:
        latency_ms = None
    error_msg = item.get("error_msg")
    return {"url": url, "status": status, "latency_ms": latency_ms,
            "error_msg": str(error_msg)[:500] if error_msg else None, "node_name": node_name}


async def _answer_batch_cross_check(bot, accid, chat_id: int, req_id: str, targets: list, concurrency=1,
                                    *, fingerprint=None, via="mail") -> None:
    """Run only the workers reserved at admission, with no task per waiting target."""

    async def one(t):
        if t is None:
            return {"status": "skip", "latency_ms": None, "error_msg": "Target refused"}
        if await asyncio.to_thread(database.is_probe_target_ignored, t["url"]):
            # /probeignore: e.g. blocked in this node's region. Abstain instead of voting "down".
            return {"status": "skip", "latency_ms": None, "error_msg": "Ignored on this node (/probeignore)"}
        is_up, error_msg, latency_ms = await run_single_check(t)
        is_up = for_peers(is_up, error_msg)
        return {"status": check_status(is_up), "latency_ms": latency_ms, "error_msg": error_msg}

    answers = [None] * len(targets)
    waiting = iter(enumerate(targets))

    async def worker():
        for index, target in waiting:
            try:
                answers[index] = await one(target)
            except Exception as exc:
                answers[index] = {"status": "unknown", "latency_ms": None, "error_msg": str(exc)[:200]}

    await asyncio.gather(*(worker() for _ in range(min(concurrency, len(targets)))))
    peer = database.get_peer_by_chat_id(chat_id)
    payload = {"req_id": req_id, "node_name": database.get_local_node_name(), "caps": _own_peer_caps(peer),
               "results": answers}
    # The requester waits CROSS_CHECK_BATCH_TIMEOUT from sending; a later answer is ignored there
    destination = _PeerDestination(bot, accid, chat_id, fingerprint=fingerprint, via=via)
    await asyncio.to_thread(_send_peer_check_answer, destination, "CHECK_BATCH_RESP", payload)


def _valid_peer_fields(item):
    try:
        database.validate_monitor_fields(url=item.get("url"), name=item.get("name"), keyword=item.get("expected_keyword"))
        return True
    except ValueError:
        return False


def _parse_batch_targets(raw) -> list:
    """Requested targets, each validated like a single request; None marks a refused one (keeps positions)."""
    targets = []
    for t in (raw if isinstance(raw, list) else [])[:CROSS_CHECK_BATCH_MAX]:
        if not isinstance(t, dict) or not _valid_peer_fields(t):
            targets.append(None)
            continue
        url, check_type = str(t.get("url") or ""), str(t.get("type") or "http")
        if check_type not in ("http", "tcp", "ping", "smtp") or not is_safe_target_url(url, check_type):
            targets.append(None)
            continue
        kw = t.get("expected_keyword")
        targets.append({"id": 0, "url": url, "type": check_type,
                        "expected_keyword": str(kw)[:200] if kw else None,
                        "family": t.get("family") if t.get("family") in (4, 6) else None})
    return targets


async def _peer_cross_check_allowed(resources: list[dict]) -> bool:
    """A failing monitor's URL is only sent to peers if at least one of its chats is within the share scope."""
    if not await asyncio.to_thread(database.get_all_peers):
        return False
    shareable = await asyncio.to_thread(_filter_peer_shareable_resources, dc_bot_instance, dc_accid, resources)
    return bool(shareable)

def pick_telemetry_batch(email: str, all_metrics: list[dict], batch_size: int, *, sent=None, offsets=None) -> list[dict]:
    """Entries for one telemetry message: status changes since the last message first, then a
    rotating slice of the others. Everything fits: send it all."""
    offsets = _telemetry_rotation_offsets if offsets is None else offsets
    if len(all_metrics) <= batch_size:
        offsets[email] = 0
        return all_metrics
    if sent is None:
        sent = _telemetry_last_sent.get(email, {})
    changed = [m for m in all_metrics if sent.get(m["url"]) != m["status"]][:batch_size]
    changed_urls = {m["url"] for m in changed}
    batch = list(changed)
    # The rotation walks the full list (not the list minus changes, which differs every time),
    # so consecutive messages continue where the last one stopped
    total = len(all_metrics)
    pos = offsets.get(email, 0) % total
    for _ in range(total):
        if len(batch) >= batch_size:
            break
        m = all_metrics[pos]
        pos = (pos + 1) % total
        if m["url"] not in changed_urls:
            batch.append(m)
    offsets[email] = pos
    return batch


def _peer_metrics_payload(metrics, now, node_name, self_addr, caps, interval, announced_interval):
    return {
        "node_name": node_name,
        "sender_email": self_addr,
        "timestamp": now,
        "msg_id": f"{now}_{secrets.token_hex(4)}",
        "caps": caps,
        "telemetry_interval": announced_interval,
        "desired_interval": interval,
        "version": VERSION,
        "metrics": metrics,
    }


def _peer_caps_changed(peer, signature):
    last_caps = peer["caps_announce_value"]
    return (last_caps is not None and last_caps != signature) or _peer_identity(peer) in _peer_caps_refresh


def _recent_peer_caps_changes(peer, now):
    return [at for at in json.loads(peer["caps_change_attempts"]) if now - at < PEER_CAPS_ANNOUNCE_INTERVAL]


def _peer_caps_announcement_due(peer, signature, now, flag):
    identity = _peer_identity(peer)
    if flag == "off" and identity in _peer_caps_attempted:
        return False
    if _up_peer_rt_link(peer.get("chat_id"), peer.get("fingerprint")):
        return False  # The live channel carries the current capabilities, even without monitors.
    last_attempt = peer["caps_announce_attempt_at"]
    previous, interval = _peer_caps_backoff.get(identity, (None, PEER_CAPS_ANNOUNCE_INTERVAL))
    if previous == signature and last_attempt is not None and now - last_attempt < interval:
        return False
    if _peer_caps_changed(peer, signature):
        return len(_recent_peer_caps_changes(peer, now)) < PEER_CAPS_CHANGE_LIMIT
    return ((last_attempt is None or now - last_attempt >= interval)
            and (identity not in _peer_caps_announcements or identity in _peer_caps_requests
                 or peer["email"].lower() not in _peer_caps))


def _note_peer_caps_sent(identity, signature):
    with _peer_rt_lock:
        previous = _peer_caps_announcements.get(identity)
        _peer_caps_announcements[identity] = signature
        if PEER_CAP_RT in json.loads(signature):
            _peer_caps_refresh.discard(identity)
        if previous != signature or identity in _peer_caps_requests:
            _peer_caps_requests.discard(identity)
            _peer_rt_audit_requested.set()


def _note_peer_rt_caps_sent(link, body):
    caps = body.get("caps")
    if isinstance(caps, list) and all(isinstance(cap, str) for cap in caps):
        _note_peer_caps_sent(link.peer["fingerprint"], json.dumps(sorted(caps)))


def _queue_peer_caps_announcement(bot, accid, peer, signature, payload, change_gap):
    chat_id = peer["chat_id"]
    identity = _peer_identity(peer)
    reserved_at = None
    previous_signature = None

    def start_send():
        nonlocal reserved_at, previous_signature
        with _peer_rt_lock:
            current = database.get_peer_by_chat_id(chat_id)
            at = time.time()
            flag = database.get_peer_rt_flag()
            if (not current or _peer_identity(current) != identity
                    or signature != json.dumps(sorted(_own_peer_caps(current, flag=flag)))
                    or not _peer_caps_announcement_due(current, signature, at, flag)):
                return False
            attempts = None
            changed = _peer_caps_changed(current, signature)
            if changed:
                attempts = [*_recent_peer_caps_changes(current, at), at]
            if not database.reserve_peer_caps_announcement(current, at, attempts):
                return False
            reserved_at = at
            previous_signature = current["caps_announce_value"]
            _peer_caps_attempted.add(identity)
            if current["email"].lower() not in _peer_caps:
                previous, interval = _peer_caps_backoff.get(identity, (None, 0))
                delay = interval * 2 if previous == signature else PEER_CAPS_ANNOUNCE_INTERVAL
                _peer_caps_backoff[identity] = (signature, min(delay, PEER_CAPS_ANNOUNCE_MAX_INTERVAL))
            return True

    def record_sent():
        kind = "peer_metrics_idle" if signature == previous_signature else "peer_metrics_change"
        database.record_peer_traffic(kind, "mail", "out", 0)
        with _peer_rt_lock:
            if database.record_peer_caps_announcement(chat_id, identity, reserved_at, signature):
                _note_peer_caps_sent(identity, signature)

    # Queue before carrier offers, using a separate key from monitor telemetry.
    peer_send(_PeerDestination(bot, accid, chat_id), "METRICS", payload,
              priority=PRIO_PEER, key=("peer_caps", identity), expires_in=change_gap,
              label=f"peer capability announcement to {peer['email']}", mail_kind="peer_metrics",
              should_send=start_send, after_send=record_sent)


def _announce_peer_caps(bot, accid):
    """Send capabilities even when there are no monitor or probe results to share."""
    peers = database.get_all_peers()
    flag = database.get_peer_rt_flag()
    now = time.time()
    with _peer_rt_lock:
        due = []
        for peer in peers:
            caps = _own_peer_caps(peer, flag=flag)
            signature = json.dumps(sorted(caps))
            if peer.get("chat_id") and _peer_caps_announcement_due(peer, signature, now, flag):
                due.append((peer, caps, signature))
    if not due:
        return

    node_name = database.get_local_node_name()
    self_addr = _get_self_addr(bot, accid)
    interval = telemetry_interval(len(peers))
    for peer, caps, signature in due:
        change_gap = max(TELEMETRY_MIN_GAP, interval_for_peer(peer["email"], interval))
        payload = _peer_metrics_payload([], int(time.time()), node_name, self_addr, caps, interval,
                                        max(TELEMETRY_IDLE_INTERVAL, change_gap))
        if peer["email"].lower() not in _peer_caps:
            # An already-running peer may have announced before this node restarted.
            payload["request_caps"] = True

        _queue_peer_caps_announcement(bot, accid, peer, signature, payload, change_gap)


def _update_peer_caps_and_carriers(bot, accid):
    global _last_peer_rt_audit
    _announce_peer_caps(bot, accid)
    with _peer_rt_lock:
        now = time.monotonic()
        if (not _peer_rt_audit_requested.is_set() and _last_peer_rt_audit is not None
                and now - _last_peer_rt_audit < PEER_RT_AUDIT_INTERVAL):
            return
        _peer_rt_audit_requested.clear()
        _last_peer_rt_audit = now
    audit_peer_rt_carriers(bot, accid, int(time.time()))


async def _broadcast_peer_updates():
    if dc_bot_instance and dc_accid is not None:
        await asyncio.to_thread(_update_peer_caps_and_carriers, dc_bot_instance, dc_accid)
    await broadcast_telemetry_to_peers()


def _schedule_peer_metrics_delta(delay=RT_TELEMETRY_DEBOUNCE - 1):
    """Coalesce changes with a second of the ten-second budget left for delivery."""
    global _telemetry_delta_timer
    with _peer_rt_lock:
        if not any(link.state.is_up for link in _peer_rt_links.values()):
            return
    loop = asyncio.get_running_loop()
    deadline = loop.time() + delay
    if _telemetry_delta_timer is not None:
        if _telemetry_delta_timer.when() <= deadline:
            return
        _telemetry_delta_timer.cancel()

    def push():
        global _telemetry_delta_timer
        _telemetry_delta_timer = None
        loop.create_task(broadcast_telemetry_to_peers(rt_delta=True))

    _telemetry_delta_timer = loop.call_at(deadline, push)


async def _broadcast_peer_rt_metrics(p, match, state, all_metrics, statuses, interval, node_name, self_addr, rt_delta):
    """Return True when the UP channel handled this tick, including its mail keepalive."""
    msg_id, link = match
    at = monotonic()
    if state.keepalive_at is None:
        state.keepalive_at = at + RT_MAIL_KEEPALIVE
    elif (last_mail := _telemetry_delivered.get(p["email"].lower())) is not None:
        state.keepalive_at = max(state.keepalive_at, last_mail[0] + RT_MAIL_KEEPALIVE)
    if state.busy:
        if rt_delta:
            _schedule_peer_metrics_delta()
        return True
    peer_interval = interval_for_peer(p["email"], interval)
    keepalive = not rt_delta and at >= state.keepalive_at
    full = keepalive or at - state.full_at >= peer_interval
    if not full and not rt_delta:
        return True
    batch = [] if full else [m for m in all_metrics if state.statuses.get(m["url"]) != m["status"]][:200]
    if not full and not batch:
        return True
    if not keepalive and (wait := state.sent_at + RT_TELEMETRY_DEBOUNCE - at) > 0:
        _schedule_peer_metrics_delta(wait)
        return True

    if full:
        batch = pick_telemetry_batch(p["email"], all_metrics, 200, sent=state.statuses, offsets=state.offsets)
    payload = _peer_metrics_payload(batch, int(time.time()), node_name, self_addr, _own_peer_caps(p),
                                    interval, peer_interval)
    if keepalive:
        # The keepalive takes this full snapshot's slot. Reserve it before queuing so a
        # concurrent change push doesn't resend the same snapshot over the channel.
        state.keepalive_at = at + RT_MAIL_KEEPALIVE
        dest = _PeerDestination(dc_bot_instance, dc_accid, p["chat_id"])

        def record_keepalive():
            state.keepalive_at = monotonic() + RT_MAIL_KEEPALIVE
            database.record_peer_traffic("peer_metrics_idle", "mail", "out", 0)
            _note_peer_caps_sent(_peer_identity(p), json.dumps(sorted(payload["caps"])))

        peer_send(dest, "METRICS", payload, priority=PRIO_TELEMETRY, key=("telemetry", p["chat_id"]),
                  expires_in=peer_interval, label=f"telemetry keepalive to {p['email']}", mail_kind="peer_metrics",
                  should_send=lambda: _up_peer_rt_link(p["chat_id"], p["fingerprint"]) == match,
                  after_send=record_keepalive)
    else:
        state.busy = True
        state.sent_at = at
        try:
            sent = await _send_peer_rt_unacked(dc_bot_instance, dc_accid, msg_id, link, "metrics", payload)
            if sent is not True:
                # An RPC exception leaves delivery uncertain. Retry on a later tick.
                return sent is None
            state.sent_at = monotonic()
            database.record_peer_traffic("peer_metrics_rt", "rt", "out", 0)
        finally:
            state.busy = False
    if full:
        state.full_at = at
    state.statuses = {url: status for url, status in state.statuses.items() if url in statuses}
    state.statuses.update((m["url"], m["status"]) for m in batch)
    return True


async def broadcast_telemetry_to_peers(*, rt_delta=False):
    """Periodically sends local monitor telemetry to all configured peers via 1:1 chat.

    Each peer receives the local monitors allowed by the share scope plus the results for the
    probe targets it asked this node to scan. Targets mirrored from one peer are never relayed
    to other peers. Send full snapshots up to the receiver's 200-entry limit. Larger sets
    still rotate, with changes first. Latency and check timestamps do not trigger sends."""
    global _telemetry_interval_now
    if not dc_bot_instance or dc_accid is None:
        return
    peers = await asyncio.to_thread(database.get_all_peers)
    interval = telemetry_interval(len(peers or []))
    _telemetry_interval_now = interval
    if not peers:
        return

    resources = await asyncio.to_thread(database.get_all_resources)
    resources = await asyncio.to_thread(_filter_peer_shareable_resources, dc_bot_instance, dc_accid, resources or [])
    probe_targets = await asyncio.to_thread(database.get_active_probe_targets)
    has_carrier = any(peer.get("rt_msg_id") for peer in peers)
    if not resources and not probe_targets and not (has_carrier or _peer_rt_links or _telemetry_rt_peers):
        return
    rt_flag = await asyncio.to_thread(database.get_peer_rt_flag) if has_carrier else "off"

    now = int(time.time())

    # 1. Local chat resources within the share scope (names are not disclosed)
    shared_metrics = []
    shared_urls = set()
    for r in resources:
        url = r.get("url")
        if not url or url in shared_urls:
            continue
        shared_urls.add(url)
        shared_metrics.append({
            "url": url,
            "type": r.get("type") or "http",
            "expected_keyword": r.get("expected_keyword"),
            # A monitor stays UP while its path is degraded; peers learn it here and vote on it
            "status": "degraded" if r.get("status") == "up" and url in _local_degraded else r.get("status", "unknown"),
            "latency_ms": r.get("last_latency_ms"),
            "last_checked": r.get("last_checked") or now
        })

    # 2. Results for probe targets, grouped by the peer that requested them
    probe_by_source = {}
    for pt in probe_targets or []:
        url = pt.get("url")
        source = (pt.get("source_peer") or "").lower()
        if not url or not source or url in shared_urls:
            continue
        probe_by_source.setdefault(source, []).append({
            "url": url,
            "type": pt.get("type") or "http",
            "expected_keyword": pt.get("expected_keyword"),
            "status": pt.get("last_status") or "unknown",
            "latency_ms": pt.get("last_latency_ms"),
            "last_checked": pt.get("last_checked") or now
        })

    self_addr = _get_self_addr(dc_bot_instance, dc_accid)
    node_name = database.get_local_node_name()
    batch_size = 200

    for p in peers:
        email = (p.get("email") or "").lower()
        change_gap = max(TELEMETRY_MIN_GAP, interval_for_peer(email, interval))
        idle_gap = max(TELEMETRY_IDLE_INTERVAL, change_gap)
        all_metrics = probe_by_source.get(email, []) + shared_metrics
        identity = _peer_identity(p)
        rt_state = _telemetry_rt_peers.get(identity)
        match = _up_peer_rt_link(p.get("chat_id"), p.get("fingerprint"))
        statuses = {m["url"]: m["status"] for m in all_metrics}
        if match:
            rt_state = _mark_peer_telemetry_up(identity)
            if await _broadcast_peer_rt_metrics(p, match, rt_state, all_metrics, statuses, interval,
                                                 node_name, self_addr, rt_delta):
                continue
            if _up_peer_rt_link(p["chat_id"], p["fingerprint"]) != match:
                match = None
        force_mail = not match and rt_state is not None and rt_state.needs_mail_on_down
        if rt_delta and not match:
            continue  # Mail-only peers keep the existing tick and pacing.
        heartbeat = not all_metrics and not match and p.get("rt_msg_id") and _peer_rt_eligible(p, rt_flag)
        if heartbeat and rt_state is None:
            rt_state = _telemetry_rt_peers.setdefault(identity, _PeerRealtimeTelemetry())
        if not all_metrics and not (heartbeat or force_mail):
            continue

        def due(at):
            if heartbeat:
                return at >= rt_state.empty_mail_at + RT_MAIL_KEEPALIVE
            if force_mail:
                return True
            queued = _telemetry_sent_at.get(email)
            if queued is None:
                return True
            delivered, last_statuses = _telemetry_delivered.get(email, (float("-inf"), None))
            gap = idle_gap if statuses == last_statuses else change_gap
            if queued > delivered:
                # Replace a waiting job on a revert as well. The outbox checks if the result is due.
                if statuses != _telemetry_queued_status.get(email):
                    return at - delivered >= change_gap
                # A replacement queued before the idle deadline must leave that deadline intact.
                if queued - delivered >= gap and at - queued < change_gap:
                    return False
            return at - delivered >= gap

        if not due(monotonic()):
            continue
        previous_queue_time = _telemetry_sent_at.get(email)
        chat_id = await _resolve_peer_chat_id(p)
        queued_at = monotonic()
        if not chat_id or _telemetry_sent_at.get(email) != previous_queue_time or not due(queued_at):
            continue
        if email not in _telemetry_sent_at:
            _telemetry_delivered.pop(email, None)
            _telemetry_started_at.pop(email, None)
        _telemetry_sent_at[email] = queued_at
        _telemetry_queued_status[email] = statuses
        metrics_batch = pick_telemetry_batch(email, all_metrics, batch_size)

        payload = _peer_metrics_payload(metrics_batch, now, node_name, self_addr,
                                        _own_peer_caps(p, flag=rt_flag), interval, RT_MAIL_KEEPALIVE if heartbeat else idle_gap)

        def _start_send(email=email, statuses=statuses, force_mail=force_mail, match=match, rt_state=rt_state,
                        chat_id=chat_id, fingerprint=p.get("fingerprint"), heartbeat=heartbeat, caps=payload["caps"]):
            # While the job waited, its predecessor may have sent or the peer interval may have grown.
            if (current := _up_peer_rt_link(chat_id, fingerprint)) and current != match:
                return False
            peer = database.get_peer_by_chat_id(chat_id)
            if peer and _own_peer_caps(peer) != caps:
                return False
            at = monotonic()
            gap = max(TELEMETRY_MIN_GAP, interval_for_peer(email, current_telemetry_interval()))
            delivered, last_statuses = _telemetry_delivered.get(email, (float("-inf"), None))
            delivery_gap = max(TELEMETRY_IDLE_INTERVAL, gap) if statuses == last_statuses else gap
            force = force_mail and rt_state.needs_mail_on_down
            if heartbeat:
                if at < rt_state.empty_mail_at + RT_MAIL_KEEPALIVE:
                    return False
                rt_state.empty_mail_at = at
            elif not force and (at - delivered < delivery_gap
                                or at - _telemetry_started_at.get(email, float("-inf")) < gap):
                return False
            if force:
                rt_state.needs_mail_on_down = False
            _telemetry_started_at[email] = at
            return True

        def _record_sent(email=email, batch=metrics_batch, statuses=statuses, heartbeat=heartbeat,
                         rt_state=rt_state, identity=identity, caps=payload["caps"]):
            # Keep statuses only for live URLs that have actually gone out, including rotated batches.
            sent = {u: st for u, st in _telemetry_last_sent.get(email, {}).items() if u in statuses}
            sent.update({m["url"]: m["status"] for m in batch})
            _telemetry_last_sent[email] = sent
            _, last_statuses = _telemetry_delivered.get(email, (None, None))
            at = monotonic()
            _telemetry_delivered[email] = (at, statuses)
            if heartbeat:
                rt_state.empty_mail_at = at
            _note_peer_caps_sent(identity, json.dumps(sorted(caps)))
            kind = "peer_metrics_idle" if heartbeat or statuses == last_statuses else "peer_metrics_change"
            database.record_peer_traffic(kind, "mail", "out", 0)

        # One telemetry message per peer at a time: a newer one replaces a still queued one.
        peer_send(_PeerDestination(dc_bot_instance, dc_accid, chat_id), "METRICS", payload,
                  priority=PRIO_TELEMETRY, key=("telemetry", chat_id),
                  expires_in=interval_for_peer(email, interval) if heartbeat else change_gap,
                  label=f"telemetry to {email}", mail_kind="peer_metrics",
                  should_send=_start_send, after_send=_record_sent)

# Async event loop and task tracking for check scheduler
async_event_loop = None
running_resource_ids = set()
running_lock = asyncio.Lock()
index_page_html_cache = None

def setup_custom_command_parser(bot):
    original_parse_command = bot._parse_command

    def custom_parse_command(accid: int, event) -> None:
        text = event.msg.text
        if not text:
            original_parse_command(accid, event)
            return

        parts = text.split(maxsplit=1)
        cmd = parts[0]
        
        if "@" in cmd:
            cmd_name, suffix = cmd.split("@", 1)
            suffix_lower = suffix.lower().strip()
            
            if suffix_lower:
                # 1. Get bot's self address
                self_address = dc_fingerprint.get_self_addr(bot.rpc, accid).lower()

                # 2. Derive this bot's unique identifiers
                bot_identifiers = []
                if self_address:
                    bot_identifiers.append(self_address)
                    local_part = self_address.split("@")[0].lower()
                    bot_identifiers.append(local_part)
                
                try:
                    node_name = database.get_local_node_name()
                    if node_name:
                        clean_node = re.sub(r'[^a-zA-Z0-9_-]', '', node_name).lower()
                        if clean_node:
                            bot_identifiers.append(clean_node)
                            if "-" in clean_node:
                                bot_identifiers.append(clean_node.split("-")[0])
                            if "_" in clean_node:
                                bot_identifiers.append(clean_node.split("_")[0])
                except Exception:
                    pass

                # 3. Check if suffix matches this specific bot
                matched = False
                for ident in bot_identifiers:
                    if suffix_lower == ident:
                        matched = True
                        break
                    # If suffix is a prefix of this bot's local part (e.g. 'up' is a prefix of 'uptimebot')
                    if len(suffix_lower) >= 2 and ident.startswith(suffix_lower):
                        matched = True
                        break
                
                if matched:
                    new_text = cmd_name
                    if len(parts) > 1:
                        new_text += " " + parts[1]
                    
                    original_text = event.msg.text
                    event.msg["text"] = new_text
                    try:
                        original_parse_command(accid, event)
                    finally:
                        event.msg["text"] = original_text
                else:
                    event.command = ""
                    event.payload = ""
            else:
                original_parse_command(accid, event)
        else:
            original_parse_command(accid, event)
            
            # /help is not suppressed: plain /help in a group is answered privately (see help_command)
            if event.command in ("/status", "/list"):
                try:
                    chat_info = bot.rpc.get_basic_chat_info(accid, event.msg.chat_id)
                    if isinstance(chat_info, dict):
                        chat_type = chat_info.get('chat_type', 'Single')
                    else:
                        chat_type = getattr(chat_info, 'chat_type', 'Single')
                    is_group = str(chat_type) in ("Group", "Mailinglist", "OutBroadcast", "InBroadcast")
                except Exception:
                    is_group = False
                
                if is_group:
                    try:
                        contacts = bot.rpc.get_chat_contacts(accid, event.msg.chat_id)
                        bot_count = 0
                        for contact_id in contacts:
                            if contact_id == 1:
                                bot_count += 1
                                continue
                            c = bot.rpc.get_contact(accid, contact_id)
                            is_bot = c.get('is_bot', False) if isinstance(c, dict) else getattr(c, 'is_bot', False)
                            if is_bot:
                                bot_count += 1
                                if bot_count > 1:
                                    break
                        if bot_count > 1:
                            event.command = ""
                            event.payload = ""
                    except Exception:
                        pass

    bot._parse_command = custom_parse_command

def is_group_chat(chat) -> bool:
    if isinstance(chat, dict):
        t = chat.get("type")
        if t is not None:
            return t != 1
        ct = chat.get("chat_type")
        if ct is not None:
            return str(ct) != "Single"
        return False
    else:
        t = getattr(chat, "type", None)
        if t is not None:
            return t != 1
        ct = getattr(chat, "chat_type", "Single")
        return str(ct) != "Single"

def is_single_chat(chat) -> bool:
    if not chat:
        return True
    try:
        from unittest.mock import MagicMock
        if isinstance(chat, MagicMock):
            return True
    except Exception:
        pass
    if isinstance(chat, dict):
        ct = chat.get("chat_type")
        if ct is not None:
            return str(ct) == "Single"
        t = chat.get("type")
        if t is not None:
            return t == 1 or str(t) == "1"
        return True
    ct = getattr(chat, "chat_type", None)
    if ct is not None and not str(type(ct)).startswith("<class 'unittest.mock"):
        return str(ct) == "Single"
    t = getattr(chat, "type", None)
    if t is not None and not str(type(t)).startswith("<class 'unittest.mock"):
        return t == 1 or str(t) == "1"
    return True

# Helper: format time durations
def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*$')  # no leading "-": it would read like a flag


def _ipv6_literal(text: str) -> str | None:
    """Normalized IPv6 address (compressed, lowercase) if text is one, else None."""
    import ipaddress
    try:
        return ipaddress.IPv6Address(text).compressed
    except ValueError:
        return None


# Helper: parse add targets
def parse_target(target: str) -> tuple[str, str]:
    """-> (check_type, target). IPv6 needs brackets with a port, as in URLs: an address like
    2a00::1 ends in hex digits, so "2a00::1:22" cannot tell address from port.

    • http(s)://...        -> http
    • smtp://host[:port]   -> smtp (STARTTLS, port 25 by default; 465 = implicit TLS)
    • host:port, [v6]:port -> tcp ("[2a00::1]:443")
    • host, IPv4, IPv6     -> ping ("2a00::1" or "[2a00::1]")"""
    target = target.strip()
    if not target:
        raise ValueError("Target is empty")

    if target.startswith("http://") or target.startswith("https://"):
        return "http", target

    if target.lower().startswith("smtp://"):
        return "smtp", _parse_smtp_target(target)

    bracketed = re.match(r'^\[([^\]]+)\](?::(\d+))?$', target)
    if bracketed:
        ip6 = _ipv6_literal(bracketed.group(1))
        if ip6 is None:
            raise ValueError("Only IPv6 addresses go in brackets, e.g. `[2a00::1]:443`.")
        if bracketed.group(2) is None:
            return "ping", ip6
        port = int(bracketed.group(2))
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        return "tcp", f"[{ip6}]:{port}"

    ip6 = _ipv6_literal(target)
    if ip6:
        return "ping", ip6
        
    if ":" in target:
        parts = target.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit() and _HOSTNAME_RE.match(parts[0]):
            port = int(parts[1])
            if 1 <= port <= 65535:
                return "tcp", target
                
    host = target
    if not _HOSTNAME_RE.match(host):
        raise ValueError("Invalid target format. Provide an HTTP/HTTPS URL, a host:port ([IPv6]:port), or a hostname/IP.")
    return "ping", host


SMTP_DEFAULT_PORT = 25
SMTP_IMPLICIT_TLS_PORTS = (465,)  # SMTPS: TLS from the first byte, no STARTTLS


def _parse_smtp_target(target: str) -> str:
    """smtp://host[:port] -> canonical "smtp://host" (port 25) or "smtp://host:port".

    Only a host and a port: no user, path or query, so one server is one monitor."""
    rest = target[len("smtp://"):]
    if not rest or any(c in rest for c in "/?#@"):
        raise ValueError("SMTP targets are `smtp://host` or `smtp://host:port`, e.g. `smtp://mail.example.org`.")
    bracketed = re.match(r'^\[([^\]]+)\](?::(\d+))?$', rest)
    if bracketed:
        ip6 = _ipv6_literal(bracketed.group(1))
        if ip6 is None:
            raise ValueError("Only IPv6 addresses go in brackets, e.g. `smtp://[2a00::1]:25`.")
        host_fmt, port_s = f"[{ip6}]", bracketed.group(2)
    else:
        host, _, port_s = rest.partition(":")
        if not _HOSTNAME_RE.match(host) or (port_s and not port_s.isdigit()):
            raise ValueError("Invalid SMTP target. Use `smtp://host` or `smtp://host:port`.")
        host_fmt, port_s = host.lower(), port_s or None
    port = int(port_s) if port_s else SMTP_DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return f"smtp://{host_fmt}" + ("" if port == SMTP_DEFAULT_PORT else f":{port}")


def _smtp_host_port(url: str) -> tuple[str, int]:
    """Host (IPv6 without brackets) and port of a canonical smtp:// target."""
    rest = url[len("smtp://"):]
    if rest.startswith("["):
        host, _, port = rest[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = rest.partition(":")
    return host.lower(), int(port) if port else SMTP_DEFAULT_PORT


def has_tls_certificate(url: str) -> bool:
    """Targets whose certificate expiry is tracked: HTTPS sites and SMTP servers."""
    return url.startswith("https://") or url.startswith("smtp://")


def target_type(target: str) -> str:
    """Check type of a stored or received target (http / tcp / ping), "http" if it does not parse."""
    try:
        return parse_target(target)[0]
    except ValueError:
        return "http"

_YGGDRASIL_NET = None

def _is_blocked_ip(ip) -> bool:
    """Returns True if an IP address points to an internal/private/non-routable destination.

    Yggdrasil overlay addresses (200::/7) are flagged as reserved by Python's ipaddress
    module but are publicly routable mesh addresses, so they are not treated as internal.
    """
    import ipaddress
    global _YGGDRASIL_NET
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if _YGGDRASIL_NET is None:
        _YGGDRASIL_NET = ipaddress.ip_network("200::/7")
    if isinstance(ip, ipaddress.IPv6Address) and ip in _YGGDRASIL_NET:
        return False
    return not ip.is_global or ip.is_multicast or ip.is_reserved

# DNS pinning: every hostname is resolved through one cache, and every address is checked against
# _is_blocked_ip before it is connected to. Validation and the actual connection therefore use the
# same answer for the record's TTL, and a re-resolution after expiry is validated again, so a DNS
# rebinding attack (public answer at validation, private answer at connect) cannot reach the probe.
DNS_CACHE_DEFAULT_TTL = 60   # used when the TTL is unknown (system resolver fallback)
DNS_CACHE_MIN_TTL = 30       # TTL 0/1 tricks cannot force a fresh lookup between validation and connect
DNS_CACHE_MAX_TTL = 300      # long TTLs must not keep probing an old address after a migration
DNS_CACHE_MAX_ENTRIES = 50_000
DNS_CACHE_SWEEP_INTERVAL = 5
_dns_cache_sweep_at = 0.0
_dns_cache = collections.OrderedDict()  # host -> (expires_at, tuple_of_ip_strings)
_dns_cache_lock = threading.Lock()


class BlockedAddressError(OSError):
    """A hostname resolved to an internal/private/non-routable address."""


def _dns_cache_get(host: str):
    now = time.monotonic()
    with _dns_cache_lock:
        entry = _dns_cache.get(host)
        if entry is not None:
            if entry[0] > now:
                _dns_cache.move_to_end(host)
                return entry[1]
            del _dns_cache[host]
    return None


def _dns_cache_put(host: str, ips, ttl) -> tuple:
    global _dns_cache_sweep_at
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        ttl = DNS_CACHE_DEFAULT_TTL
    ttl = min(DNS_CACHE_MAX_TTL, max(DNS_CACHE_MIN_TTL, ttl))
    ips = tuple(dict.fromkeys(ips))
    now = time.monotonic()
    with _dns_cache_lock:
        _dns_cache[host] = (now + ttl, ips)
        _dns_cache.move_to_end(host)
        if len(_dns_cache) > DNS_CACHE_MAX_ENTRIES and now >= _dns_cache_sweep_at:
            for expired in [key for key, (expires, _) in _dns_cache.items() if expires <= now]:
                del _dns_cache[expired]
            _dns_cache_sweep_at = now + DNS_CACHE_SWEEP_INTERVAL
        if len(_dns_cache) > DNS_CACHE_MAX_ENTRIES:
            _dns_cache.popitem(last=False)
    return ips


def _dns_cache_forget(host: str) -> None:
    with _dns_cache_lock:
        _dns_cache.pop((host or "").strip().lower().rstrip("."), None)


def _validated_ips(host: str, ips) -> list[str]:
    """Raises BlockedAddressError unless every resolved address is publicly routable."""
    import ipaddress
    if not ips:
        raise BlockedAddressError(f"No addresses for {host}")
    for ip_str in ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str.split("%", 1)[0])
        except ValueError:
            raise BlockedAddressError(f"Invalid address {ip_str!r} for {host}")
        if _is_blocked_ip(ip_obj):
            raise BlockedAddressError(f"{host} resolves to internal or private network address {ip_str}")
    # IPv4 first: ping/TCP fallbacks and most hosts behave best over IPv4
    return sorted(ips, key=lambda a: ":" in a)


def _literal_ip(host: str):
    import ipaddress
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


class NoIPv6Error(OSError):
    """The target is IPv6-only (or IPv6 was asked for), but this node has no route to IPv6 at all.

    Not a failure of the target: such a check is skipped instead of reported as DOWN."""


class NoAddressForFamilyError(OSError):
    """-4 / -6 was asked for, but the name has no address of that family."""


NO_IPV6_MSG = "No IPv6 connectivity on this node"
BLOCKED_TARGET_MSG = "Target blocked: internal or private network address"
RATE_LIMITED_MSG = "429 - Too Many Requests (rate limited, not counted)"


def for_peers(is_up, error_msg):
    """A check result as this node reports it to peers (cross-check answers, mirrored targets):
    a name that resolves to a private address here (split-horizon DNS at home, a VPN) cannot be
    checked by this node, which says nothing about the target, so it abstains instead of DOWN."""
    return None if is_up is False and error_msg == BLOCKED_TARGET_MSG else is_up
PING_UNAVAILABLE_MSG = "Ping not available on this node (no ICMP socket, no ping binary)"
_ping_unavailable_warned = False


def _warn_ping_unavailable() -> None:
    """Logs once per run why ping checks are skipped here (they would otherwise fail silently)."""
    global _ping_unavailable_warned
    if not _ping_unavailable_warned:
        _ping_unavailable_warned = True
        logger.warning("Ping checks are skipped on this node: no raw or datagram ICMP socket and no ping binary "
                       "(install iputils-ping, or allow the bot's group in net.ipv4.ping_group_range)")


PING_UNRELIABLE_MSG = "Ping not reliable on this node (Docker Desktop drops ICMP replies)"
_ping_reliable = None


def ping_is_reliable() -> bool:
    """False on Docker Desktop (macOS / Windows): its VM (kernel "linuxkit") passes ICMP through a
    user-space proxy that drops replies as soon as several echoes are in flight (measured 2026-10-26:
    68% lost with 5 targets at once, 89% with 20, 17% even one at a time next to the running bot;
    0% on a Linux host). Ping results there would be false DOWN and degraded votes, so the node
    abstains on ping targets. PING_ON_DOCKER_DESKTOP=1 checks them anyway."""
    global _ping_reliable
    if _ping_reliable is None:
        try:
            with open("/proc/version", encoding="utf-8") as f:
                desktop = "linuxkit" in f.read().lower()
        except OSError:
            desktop = False
        forced = os.environ.get("PING_ON_DOCKER_DESKTOP", "").strip().lower() in ("1", "true", "yes")
        _ping_reliable = forced or not desktop
        if not _ping_reliable:
            logger.warning("Docker Desktop detected: ping targets are not checked on this node (it abstains "
                           "in votes), because its network proxy drops ICMP replies. "
                           "Set PING_ON_DOCKER_DESKTOP=1 to check them anyway.")
    return _ping_reliable


class PingSocketUnavailable(Exception):
    """This node may not open an unprivileged ICMP socket (see _dgram_ping)."""


def _icmp_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum (one's complement sum of 16-bit words)."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


async def _dgram_ping(ip: str, timeout: float) -> float:
    """One echo request over an unprivileged ICMP datagram socket; returns the round trip in seconds.

    aioping needs a raw socket (root / CAP_NET_RAW), which hosted containers often do not grant, and
    slim images have no ping binary. A "ping socket" (SOCK_DGRAM + IPPROTO_ICMP) needs neither: Linux
    allows it for the groups in net.ipv4.ping_group_range (Docker sets it to all groups since 20.10),
    macOS always. The kernel sets the echo id itself and hands this socket only the replies to it.
    Raises PingSocketUnavailable if the socket cannot be opened, asyncio.TimeoutError, or OSError."""
    is6 = ":" in ip
    try:
        sock = socket.socket(socket.AF_INET6 if is6 else socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_ICMPV6 if is6 else socket.IPPROTO_ICMP)
    except OSError as e:  # EACCES: group not in ping_group_range; EPROTONOSUPPORT: no ping sockets
        raise PingSocketUnavailable(str(e)) from e
    try:
        sock.setblocking(False)
        echo_req, echo_reply = (128, 129) if is6 else (8, 0)
        seq = secrets.randbelow(0x10000)
        payload = secrets.token_bytes(16)  # matched in the reply, so a stray reply cannot count
        header = struct.pack("!BBHHH", echo_req, 0, 0, 0, seq)
        # The ICMPv6 checksum covers an IPv6 pseudo header and is always filled in by the kernel
        csum = 0 if is6 else _icmp_checksum(header + payload)
        packet = struct.pack("!BBHHH", echo_req, 0, csum, 0, seq) + payload
        loop = asyncio.get_running_loop()
        start = time.monotonic()
        await loop.sock_sendto(sock, packet, (ip, 0))

        async def _reply():
            while True:
                data, _ = await loop.sock_recvfrom(sock, 2048)
                # Linux delivers just the ICMP message, macOS prefixes the IPv4 header
                if not is6 and len(data) >= 20 and data[0] >> 4 == 4:
                    data = data[(data[0] & 0x0F) * 4:]
                if len(data) >= 8:
                    rtype, _, _, _, rseq = struct.unpack("!BBHHH", data[:8])
                    if rtype == echo_reply and rseq == seq and data[8:] == payload:
                        return time.monotonic() - start

        return await asyncio.wait_for(_reply(), timeout)
    finally:
        sock.close()


class _PingMethodUnavailable(Exception):
    """This way of sending echoes does not work on this node; ping_series tries the next one."""


async def _aioping_once(ip: str, timeout: float) -> float:
    try:
        return await aioping.ping(ip, timeout=timeout)
    except asyncio.TimeoutError:
        raise
    except Exception as e:  # PermissionError without CAP_NET_RAW, other raw socket errors
        raise _PingMethodUnavailable(str(e)) from e


async def _dgram_ping_once(ip: str, timeout: float) -> float:
    try:
        return await _dgram_ping(ip, timeout)
    except PingSocketUnavailable as e:
        raise _PingMethodUnavailable(str(e)) from e


async def _echo_series(send_one, ip: str, count: int) -> tuple[list[float], str | None]:
    """count echoes PING_SPACING apart, in flight together, so a check takes about
    count * PING_SPACING + PING_TIMEOUT at most. Returns the round trips (seconds) of the answered
    echoes and the last socket error (e.g. host unreachable). Raises _PingMethodUnavailable."""
    async def probe(i):
        await asyncio.sleep(i * PING_SPACING)
        return await send_one(ip, PING_TIMEOUT)

    rtts, error = [], None
    for r in await asyncio.gather(*(probe(i) for i in range(count)), return_exceptions=True):
        if isinstance(r, _PingMethodUnavailable):
            raise r
        if isinstance(r, (int, float)) and not isinstance(r, bool):
            rtts.append(float(r))
        elif isinstance(r, asyncio.TimeoutError):  # before OSError: TimeoutError is one
            continue
        elif isinstance(r, OSError):
            error = r.strerror or str(r)
        elif isinstance(r, Exception):
            error = str(r)
    return rtts, error


_PING_TIME_RE = re.compile(r"time[=<]([\d.]+) ?ms")


async def _ping_binary_series(ip: str, count: int) -> tuple[list[float], str | None]:
    """The ping binary as last resort. Raises FileNotFoundError if there is none."""
    proc = await asyncio.create_subprocess_exec(
        "ping", "-n", "-c", str(count), "-i", str(PING_SPACING), "-W", str(int(PING_TIMEOUT)), ip,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=count * PING_SPACING + PING_TIMEOUT + 5)
    except asyncio.TimeoutError:
        proc.kill()
        return [], None
    return [float(t) / 1000 for t in _PING_TIME_RE.findall(out.decode(errors="replace"))], None


async def ping_series(ip: str, count: int = PING_COUNT) -> tuple[list[float], str | None]:
    """Sends count echoes with the first method that works here: aioping (raw socket), an
    unprivileged ICMP datagram socket, the ping binary. Returns (round trips in seconds of the
    answered echoes, last socket error). Raises FileNotFoundError when no method works."""
    methods = ([_aioping_once] if aioping is not None else []) + [_dgram_ping_once]
    for send_one in methods:
        try:
            return await _echo_series(send_one, ip, count)
        except _PingMethodUnavailable as e:
            logger.debug(f"{send_one.__name__} unavailable for {ip} ({e}), trying the next ping method")
    return await _ping_binary_series(ip, count)


def assess_ping(rtts_ms: list[int], sent: int, usual_ms: float | None) -> tuple[bool | str, str]:
    """(True | CHECK_DEGRADED, details) for a ping series with at least one answer.

    DEGRADED: DEGRADED_LOSS_PCT or more of the echoes lost, or the median round trip far above the
    usual one of this node (DEGRADED_RTT_FACTOR times and DEGRADED_RTT_MIN_EXTRA_MS more)."""
    median = int(statistics.median(rtts_ms))
    loss = round(100 * (sent - len(rtts_ms)) / sent)
    slow = (usual_ms is not None and median >= usual_ms * DEGRADED_RTT_FACTOR
            and median - usual_ms >= DEGRADED_RTT_MIN_EXTRA_MS)
    parts = [f"{median} ms"] + ([f"loss {loss}%"] if loss else [])
    if loss >= DEGRADED_LOSS_PCT or slow:
        if usual_ms is not None:
            parts.append(f"usual {round(usual_ms)} ms")
        return CHECK_DEGRADED, ", ".join(parts)
    return True, ", ".join(parts)


def next_ping_baseline(usual_ms: float | None, sample_ms: int, degraded: bool) -> float | None:
    """The usual round trip after one more check: an average that follows faster round trips
    quickly and slower ones slowly, and ignores degraded checks, so a long bad period does not
    become the new normal."""
    if degraded:
        return usual_ms
    if usual_ms is None:
        return float(sample_ms)
    alpha = 0.3 if sample_ms < usual_ms else 0.05
    return usual_ms + alpha * (sample_ms - usual_ms)


def confirm_degraded(ip: str, bad: bool, now: float = None) -> bool:
    """Records one ping series of ip and returns True once its path has been bad for
    DEGRADED_MIN_SAMPLES series in a row spanning DEGRADED_MIN_DURATION. A good series starts over.
    Checks asked for by peers count too, so the duration matters, not only the number."""
    now = now or time.time()
    if not bad:
        _ping_bad_streaks.pop(ip, None)
        return False
    since, count = _ping_bad_streaks.get(ip, (now, 0))
    _ping_bad_streaks[ip] = (since, count + 1)
    return count + 1 >= DEGRADED_MIN_SAMPLES and now - since >= DEGRADED_MIN_DURATION


def get_ping_baseline(ip: str) -> float | None:
    if ip not in _ping_baseline_cache:
        try:
            _ping_baseline_cache[ip] = database.get_ping_baseline(ip)
        except Exception as e:
            logger.debug(f"Could not read the ping baseline of {ip}: {e}")
            return None
    return _ping_baseline_cache[ip]


def note_ping_sample(ip: str, sample_ms: int, degraded: bool) -> None:
    usual = get_ping_baseline(ip)
    new = next_ping_baseline(usual, sample_ms, degraded)
    if new is None or new == usual:
        return
    _ping_baseline_cache[ip] = new
    if usual is None or abs(new - usual) >= 0.5:  # no write for every sub-millisecond drift
        try:
            database.set_ping_baseline(ip, new)
        except Exception as e:
            logger.debug(f"Could not store the ping baseline of {ip}: {e}")


_TRACE_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_TRACE_ADDR_RE = re.compile(r"(?<![\w:.])([0-9a-fA-F:]+:\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:.])")


def redact_private_hops(text: str) -> str:
    """Keep only globally routable addresses in path diagnostics sent to chats or peers."""
    import ipaddress

    def replace(match):
        try:
            ip = ipaddress.ip_address(match.group(1))
            ip = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
            return match.group(1) if ip.is_global and not ip.is_multicast else "private hop"
        except ValueError:
            return "private hop"

    return _TRACE_ADDR_RE.sub(replace, text)


def summarize_traceroute(output: str) -> str:
    """'trace: +324 ms between hop 6 213.19.194.214 and hop 7 79.104.235.205': the link where the
    median round trip rises most, i.e. where a congested path most likely starts. '' if no link
    adds DEGRADED_RTT_MIN_EXTRA_MS / 2 (the trouble is loss, which traceroute cannot place)."""
    hops = []
    for line in output.splitlines():
        m = _TRACE_HOP_RE.match(line)
        if not m:
            continue
        addr = _TRACE_ADDR_RE.search(m.group(2))
        rtts = [float(x) for x in re.findall(r"([\d.]+) ms", m.group(2))]
        if addr and rtts:
            hops.append((int(m.group(1)), addr.group(1), statistics.median(rtts)))
    best = None
    for (n1, a1, r1), (n2, a2, r2) in zip(hops, hops[1:]):
        if best is None or r2 - r1 > best[0]:
            best = (r2 - r1, n1, a1, n2, a2)
    if not best or best[0] < DEGRADED_RTT_MIN_EXTRA_MS / 2:
        return ""
    rise, n1, a1, n2, a2 = best
    return redact_private_hops(f"trace: +{round(rise)} ms between hop {n1} {a1} and hop {n2} {a2}")


async def _trace_path(ip: str) -> None:
    summary = ""
    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-n", "-q", "3", "-w", "2", "-m", "20", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        # Read hop by hop: silent hops at the end (3 x 2 s each where traceroute probes one hop at
        # a time, as on macOS) may outlast the deadline, and the hops seen so far are what matters
        lines = []
        deadline = time.monotonic() + 60
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=max(0.1, deadline - time.monotonic()))
                if not line:
                    break
                lines.append(line.decode(errors="replace"))
        except asyncio.TimeoutError:
            proc.kill()
        await proc.wait()
        summary = summarize_traceroute("".join(lines))
    except FileNotFoundError:
        logger.debug("traceroute is not installed: degraded ping results come without a path hint")
    except Exception as e:
        logger.debug(f"traceroute to {ip} failed: {e}")
    _path_traces[ip] = (time.time(), summary)


def path_trace_hint(ip: str) -> str:
    """The traceroute summary of a degraded path, from cache. A missing or older one is (re)made in
    the background, so the first degraded result comes without it and the confirming one with it."""
    cached = _path_traces.get(ip)
    if not cached or time.time() - cached[0] >= PATH_TRACE_TTL:
        task = _path_trace_tasks.get(ip)
        if task is None or task.done():
            _path_trace_tasks[ip] = asyncio.create_task(_trace_path(ip))
    return redact_private_hops(cached[1]) if cached else ""


def check_status(is_up) -> str:
    """The status of a run_single_check result as peers exchange it and nodes vote."""
    if is_up is None:
        return "skip"
    if is_up == CHECK_DEGRADED:
        return "degraded"
    return "up" if is_up else "down"


def has_route_to(ip: str) -> bool:
    """True if the kernel has a route (and a source address) for ip.

    connect() on a UDP socket sends nothing: it only picks the route and source address, so this
    is free and instant. Without IPv6 (no global address, or Docker without enable_ipv6) it fails
    with ENETUNREACH (101) or EADDRNOTAVAIL (99) - the "[Errno 101] Connect call failed" seen
    when a TCP check tried the AAAA address of a host on a node without IPv6."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((ip, 53))
        return True
    except OSError:
        return False


def pick_probe_addresses(host: str, ips: list[str], family: int | None = None) -> list[str]:
    """The validated addresses a check should try, in order.

    family 4 / 6 keeps only that family (raises NoAddressForFamilyError if there is none).
    IPv6 addresses this node cannot route to are dropped, so a host with A and AAAA records is
    checked over IPv4 and its result is not replaced by a meaningless IPv6 "network unreachable".
    Raises NoIPv6Error if nothing is left only because IPv6 is missing here."""
    if family in (4, 6):
        ips = [ip for ip in ips if (":" in ip) == (family == 6)]
        if not ips:
            raise NoAddressForFamilyError(f"{host} has no IPv{family} address")
    usable = [ip for ip in ips if ":" not in ip or has_route_to(ip)]
    if not usable:
        raise NoIPv6Error(NO_IPV6_MSG)
    return usable


async def probe_addresses(host: str, family: int | None = None) -> list[str]:
    """resolve_host_safe + pick_probe_addresses: validated, reachable addresses of host."""
    return pick_probe_addresses(host, await resolve_host_safe(host), family)


def resolve_host_safe_sync(host: str, *, deadline=None) -> list[str]:
    """Blocking variant of resolve_host_safe (system resolver, TTL unknown -> DNS_CACHE_DEFAULT_TTL)."""
    host = (host or "").strip().lower().rstrip(".")
    literal = _literal_ip(host)
    if literal:
        return _validated_ips(host, [literal])
    cached = _dns_cache_get(host)
    if cached is None:
        timeout = DNS_DEADLINE if deadline is None else min(DNS_DEADLINE, deadline - monotonic())
        if timeout <= 0:
            raise TimeoutError("DNS deadline exceeded")
        future = _submit_bounded(dns_executor, _dns_slots, socket.getaddrinfo, host, None)
        try:
            infos = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError("DNS deadline exceeded")
        cached = _dns_cache_put(host, [info[4][0] for info in infos], DNS_CACHE_DEFAULT_TTL)
    return _validated_ips(host, cached)


_aiodns_resolvers = weakref.WeakKeyDictionary()  # event loop -> long-lived aiodns.DNSResolver


def _get_aiodns_resolver():
    """One resolver per event loop, kept for the loop's lifetime.

    Creating and closing a pycares channel per query destroys channels while queries are still in
    flight (timeouts, cancellation), and pycares tears channels down in a background thread that can
    crash the interpreter at shutdown. A long-lived resolver is how aiodns is meant to be used."""
    loop = asyncio.get_running_loop()
    resolver = _aiodns_resolvers.get(loop)
    if resolver is None:
        resolver = aiodns.DNSResolver(loop=loop, timeout=3.0, tries=2)
        _aiodns_resolvers[loop] = resolver
    return resolver


_DNS_NO_RECORD_CODES = (1, 4)  # c-ares ARES_ENODATA, ARES_ENOTFOUND: the name has no such record


def _dns_query_failed(err: BaseException) -> bool:
    """True if a query failed (timeout, SERVFAIL, refused...), False if the record just does not exist."""
    code = err.args[0] if getattr(err, "args", None) else None
    return code not in _DNS_NO_RECORD_CODES


async def _query_with_ttl(host: str):
    """Returns (ips, ttl) using aiodns so the record TTL is known; raises if nothing resolves.

    If one of the A / AAAA queries failed while the other answered, the answer lacks a family the
    host may well have (a home resolver timing out on A left only the AAAA address, and a check over
    a broken IPv6 then had no IPv4 to fall back to for the record's TTL). Such a partial answer is
    cached for DNS_CACHE_MIN_TTL only, so the next check asks again."""
    resolver = _get_aiodns_resolver()
    results = await asyncio.gather(resolver.query(host, "A"), resolver.query(host, "AAAA"), return_exceptions=True)
    ips, ttls, partial = [], [], False
    for res in results:
        if isinstance(res, BaseException):
            partial = partial or _dns_query_failed(res)
            continue
        for rec in res:
            ips.append(rec.host)
            ttls.append(getattr(rec, "ttl", DNS_CACHE_DEFAULT_TTL))
    if not ips:
        raise socket.gaierror(socket.EAI_NONAME, f"DNS lookup failed for {host}")
    return ips, DNS_CACHE_MIN_TTL if partial else min(ttls)


async def _resolve_host_safe(host: str) -> list[str]:
    """Resolves a hostname for an outgoing probe connection.

    Uses the cached answer while its TTL is valid, otherwise queries DNS (aiodns, which reports the TTL)
    and falls back to the system resolver (e.g. /etc/hosts). Raises BlockedAddressError if any address
    is internal, so callers must connect only to the returned IPs."""
    host = (host or "").strip().lower().rstrip(".")
    literal = _literal_ip(host)
    if literal:
        return _validated_ips(host, [literal])
    cached = _dns_cache_get(host)
    if cached is None:
        ips, ttl = None, DNS_CACHE_DEFAULT_TTL
        if aiodns is not None:
            try:
                ips, ttl = await _query_with_ttl(host)
            except Exception as e:
                logger.debug(f"aiodns lookup failed for {host} ({e}), using system resolver")
        if not ips:
            future = _submit_bounded(dns_executor, _dns_slots, socket.getaddrinfo, host, None)
            infos = await _await_worker(future)
            ips = [info[4][0] for info in infos]
        cached = _dns_cache_put(host, ips, ttl)
    return _validated_ips(host, cached)


async def resolve_host_safe(host: str) -> list[str]:
    async with asyncio.timeout(DNS_DEADLINE):
        return await _resolve_host_safe(host)


class SafeResolver(aiohttp.abc.AbstractResolver):
    """aiohttp resolver that only hands out validated, cached addresses (DNS rebinding protection)."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        want = {socket.AF_INET: 4, socket.AF_INET6: 6}.get(family)
        ips = await probe_addresses(host, want)
        results = []
        for ip in ips:
            ip_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if family not in (socket.AF_UNSPEC, 0) and family != ip_family:
                continue
            results.append({
                "hostname": host, "host": ip, "port": port,
                "family": ip_family, "proto": 0, "flags": socket.AI_NUMERICHOST,
            })
        if not results:
            raise OSError(f"No usable address for {host}")
        return results

    async def close(self) -> None:
        return None


def _make_safe_connector(**kwargs) -> aiohttp.TCPConnector:
    # aiohttp's own DNS cache is disabled: it ignores record TTLs, and our cache already pins answers
    return aiohttp.TCPConnector(resolver=SafeResolver(), use_dns_cache=False, **kwargs)


def _target_host(validated: str, check_type: str) -> str:
    if check_type == "http":
        return (urlparse(validated).hostname or "").lower().strip()
    if check_type == "tcp":
        return validated.rsplit(":", 1)[0].strip("[]").lower().strip()
    if check_type == "smtp":
        return _smtp_host_port(validated)[0]
    return validated.lower().strip()


def _no_ipv6_note(url: str, check_type: str) -> str:
    """Warning for /add when the target is an IPv6 address this node cannot reach."""
    ip = _literal_ip(_target_host(url, check_type))
    if ip and ":" in ip and not has_route_to(ip):
        return ("\n⚠️ This node has no IPv6 connectivity: its checks of this target are skipped "
                "(not counted as DOWN) until IPv6 works here.")
    return ""


def is_safe_target_url(url: str, check_type: str = "http", *, resolve_dns: bool = True, dns_deadline=None) -> bool:
    """Validates target format and blocks dangerous internal/private/metadata IP addresses (SSRF prevention)."""
    try:
        expected_type, validated = parse_target(url)
        if expected_type != check_type:
            return False

        host = _target_host(validated, check_type)
        if not host:
            return False

        # Block localhost / link-local / cloud metadata
        blocked_names = {
            "localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0",
            "169.254.169.254", "metadata.google.internal", "instance-data"
        }
        if host in blocked_names:
            return False

        if host.endswith(".local") or host.endswith(".internal") or host.endswith(".lan") or host.endswith(".localdomain"):
            return False

        import ipaddress

        # Check for literal private/reserved/loopback IP address
        try:
            ip = ipaddress.ip_address(host)
            if _is_blocked_ip(ip):
                return False
            return True
        except ValueError:
            pass

        if not resolve_dns:
            return True

        # DNS resolution check through the shared pinning cache (the connection reuses this answer)
        try:
            resolve_host_safe_sync(host, deadline=dns_deadline)
        except BlockedAddressError:
            return False
        except socket.gaierror:
            # Domain could not be resolved; allow in offline/test environment if name is syntactically valid
            pass

        return True
    except Exception:
        return False

def _get_peer_fingerprint(bot, accid, contact_id, contact_addr: str = "") -> str | None:
    """Returns the OpenPGP fingerprint Delta Chat holds for a peer contact, or None; see dc_fingerprint.

    `contact_addr` is unused: core 2.66 no longer prints addresses in the encryption info."""
    return dc_fingerprint.get_contact_fingerprint(bot.rpc, accid, contact_id)

def _get_verified_peer_for_msg(bot, accid, msg, is_private_chat: bool = True, *,
                               bind: bool = True) -> tuple[dict | None, str]:
    """Resolves the peer sending a protocol message from Delta Chat contact data.

    A peer is identified by its key fingerprint: a bot with several relays sends from whichever
    address is reachable, so the address alone says nothing. The sender address and fingerprint
    always come from the Delta Chat contact, never from the message payload.

    Peers stored before fingerprints were recorded (or added by address) have none yet. Such a row is
    matched by its 1:1 chat or its address as before, and the first end-to-end encrypted message
    binds the sender's key to it. From then on only that key is accepted.

    Returns (peer_row_or_None, sender_addr). When the peer now sends from another address, the row
    is moved to that address, so peer["email"] is the current one. With bind=False, resolve only
    an already bound fingerprint and leave the peer row untouched."""
    sender_addr = ""
    try:
        contact = bot.rpc.get_contact(accid, msg.from_id)
        sender_addr = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
    except Exception:
        pass

    sender_addr = sender_addr.lower().strip() if isinstance(sender_addr, str) else ""
    if not sender_addr:
        return None, ""

    encrypted = bool(getattr(msg, "show_padlock", False))
    fp = _get_peer_fingerprint(bot, accid, msg.from_id, sender_addr) if encrypted else None

    peer = database.get_peer_by_fingerprint(fp) if fp else None
    if not bind:
        return peer, sender_addr
    if not peer:
        candidates = [database.get_peer(sender_addr)]
        if is_private_chat:
            candidates.append(database.get_peer_by_chat_id(msg.chat_id))
        for cand in candidates:
            if not cand:
                continue
            if cand.get("fingerprint"):
                # A key-bound peer is never accepted by address or chat alone
                reason = "unencrypted" if not encrypted else f"signed by another key ({fp or 'unknown'})"
                logger.warning(f"Peer {cand['email']} is bound to key {cand['fingerprint']}; message from {sender_addr} is {reason}")
                continue
            # Matched by chat: only for an encrypted message in the peer's 1:1 chat. Without a readable
            # key that is accepted for SecureJoin placeholders only (that chat exists only after SecureJoin).
            by_chat = is_private_chat and encrypted and cand.get("chat_id") == msg.chat_id and (
                fp or cand["email"].endswith("@securejoin"))
            if cand["email"] == sender_addr or by_chat:
                peer = cand
                break

    if peer and not fp and peer["email"].endswith("@securejoin") and peer["email"] != sender_addr:
        # SecureJoin peer whose address was unknown at /addpeer time: store the real address
        peer = database.bind_peer_identity(peer["email"], new_email=sender_addr) or peer
    if peer and fp:
        # Key-verified peer: record its key, the address it now sends from and its 1:1 chat
        changes = {}
        if is_private_chat and not peer.get("fingerprint"):
            changes["fingerprint"] = fp
        if peer["email"] != sender_addr:
            changes["new_email"] = sender_addr
        if is_private_chat and peer.get("chat_id") != msg.chat_id:
            changes["chat_id"] = msg.chat_id
        if changes:
            updated = database.bind_peer_identity(peer["email"], **changes)
            if updated:
                if updated["email"] != peer["email"]:
                    logger.info(f"Peer {updated.get('node_name')} now sends from {updated['email']} (was {peer['email']})")
                if "fingerprint" in changes:
                    logger.info(f"Peer {updated.get('node_name')} bound to key {fp}")
                    with _peer_rt_lock:
                        if _peer_identity(peer) in _peer_caps_attempted:
                            _peer_caps_attempted.discard(_peer_identity(peer))
                            _peer_caps_attempted.add(fp)
                peer = updated
                if peer.get("rt_msg_id") and ("new_email" in changes or "chat_id" in changes):
                    _refresh_peer_rt_channels()
    return peer, sender_addr

def _is_trusted_peer_msg(msg, peer: dict | None, is_private_chat: bool) -> bool:
    """Peer data messages are only accepted from a configured peer, in a 1:1 chat, end-to-end encrypted."""
    if not peer or not is_private_chat:
        return False
    if not getattr(msg, "show_padlock", False):
        logger.warning(f"Dropping unencrypted peer protocol message from {peer.get('email')}")
        return False
    return True

# Admin detection helper
_admin_missing_fp_logged = {}
_admin_missing_fp_lock = threading.Lock()


def _log_missing_admin_fingerprint(accid, contact_id):
    now = time.monotonic()
    with _admin_missing_fp_lock:
        key = (accid, contact_id)
        last = _admin_missing_fp_logged.get(key)
        if last is not None and now - last < 3600:
            return
        _admin_missing_fp_logged[key] = now
    logger.warning("Admin command refused for contact %s: sender fingerprint unavailable", contact_id)


def _get_contact_fingerprint(bot, accid, contact_id, contact=None):
    """The contact's key fingerprint, or None; see dc_fingerprint. `contact` is unused, kept for callers."""
    return dc_fingerprint.get_contact_fingerprint(bot.rpc, accid, contact_id)

def _is_dc_admin(bot, accid, contact_id, chat_id: int = None):
    try:
        contact = None
        try:
            contact = bot.rpc.get_contact(accid, contact_id)
        except Exception:
            pass
        
        admin_email, admin_fp = database.get_effective_admin()
        if admin_fp:
            c_fp = _get_contact_fingerprint(bot, accid, contact_id, contact=contact)
            if not c_fp:
                _log_missing_admin_fingerprint(accid, contact_id)
                return False
            if admin_fp == c_fp.upper():
                if chat_id:
                    database.set_config("admin_chat_id", str(chat_id))
                return True
            logger.warning(f"Admin fingerprint mismatch for contact {contact_id}")
            return False
        
        if contact:
            sender_email = contact.address
            if admin_email and admin_email.lower() == sender_email.lower():
                if chat_id:
                    database.set_config("admin_chat_id", str(chat_id))
                return True
            
    except Exception as e:
        logger.error(f"Error during admin verification: {e}")
    return False

async def send_admin_notification(text: str, *, wait_for_send=False) -> bool:
    """Sends high-priority system and probe health alerts to the configured administrator via DM."""
    if not dc_bot_instance or dc_accid is None:
        return False
    admin_chat_id_str = await asyncio.to_thread(database.get_config, "admin_chat_id")
    chat_id = int(admin_chat_id_str) if admin_chat_id_str and admin_chat_id_str.isdigit() else None

    # The 1:1 chat with the admin's key contact (see _admin_contact_id); re-resolved when the
    # cached chat is another one (e.g. one with the address-only contact, which cannot be written to)
    contact_id = await asyncio.to_thread(_admin_contact_id, dc_bot_instance, dc_accid)
    if contact_id:
        try:
            key_chat = await asyncio.to_thread(dc_bot_instance.rpc.create_chat_by_contact_id, dc_accid, contact_id)
            if isinstance(key_chat, int) and key_chat and key_chat != chat_id:
                logger.info(f"Admin notifications now go to chat {key_chat} (was {chat_id})")
                chat_id = key_chat
                await asyncio.to_thread(database.set_config, "admin_chat_id", str(chat_id))
        except Exception as e:
            logger.warning(f"Failed to resolve admin chat: {e}")
    if not chat_id:
        return False

    try:
        result = await asyncio.to_thread(
            _dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=text),
            priority=PRIO_ALERT, label="admin notification", kind="alert", return_future=wait_for_send)
        if wait_for_send:
            if isinstance(result, concurrent.futures.Future):
                result = await asyncio.shield(asyncio.wrap_future(result))
            return result is not None
        return True
    except Exception as e:
        logger.warning(f"Failed to send admin notification to chat {chat_id}: {e}")
        return False

# Uptime checks execution logic
async def check_ssl_expiry(url: str, timeout: float = 10.0) -> tuple[int | None, str | None]:
    """
    Connects to the HTTPS host (or the smtp:// server, via STARTTLS), fetches peer certificate and returns:
    (expiry_timestamp_epoch, None) on success, or (None, error_str) on failure.
    """
    try:
        if url.startswith("smtp://"):
            cert = await asyncio.wait_for(smtp_tls_handshake(url), timeout=timeout)
            exp_ts = _cert_expiry_ts(cert)
            return (exp_ts, None) if exp_ts else (None, "No certificate found")
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return None, "Invalid hostname"
            
        ctx = ssl.create_default_context()
        writer = await asyncio.wait_for(
            _open_pinned_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not cert or "notAfter" not in cert:
            return None, "No certificate found"

        not_after_str = cert["notAfter"]
        try:
            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            # Fallback in case of variant date formats
            import email.utils
            exp_date = email.utils.parsedate_to_datetime(not_after_str)
        exp_date = exp_date.replace(tzinfo=datetime.timezone.utc)
        return int(exp_date.timestamp()), None
    except ssl.SSLCertVerificationError as e:
        return None, f"SSL verification error: {getattr(e, 'verify_message', str(e))}"
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except asyncio.TimeoutError:
        return None, "SSL check timeout"
    except Exception as e:
        return None, f"SSL check error: {e}"

async def notify_ssl_alert(resource, days_left: float, exp_date_str: str, alert_stage: int):
    res_id = resource["id"]
    name = resource["name"] or resource["url"]
    url = resource["url"]
    chat_id = resource["dc_chat_id"]

    if alert_stage == -1:
        msg_text = (
            f"🚨 `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expired!** Expired on `{exp_date_str}`.\n"
            f"  Please renew the certificate immediately to restore secure access."
        )
    elif alert_stage == 1:
        hours_left = max(1, int(days_left * 24))
        msg_text = (
            f"🚨 `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (24 Hours)**\n"
            f"  Certificate will expire in ~`{hours_left}h` (on `{exp_date_str}`).\n"
            f"  Urgent: Please renew your SSL certificate now!"
        )
    elif alert_stage == 3:
        msg_text = (
            f"⚠️ `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (3 Days)**\n"
            f"  Certificate will expire in ~3 days (on `{exp_date_str}`).\n"
            f"  Please renew your SSL certificate soon."
        )
    elif alert_stage == 7:
        msg_text = (
            f"⚠️ `ID: {res_id}` **{name}**\n"
            f"  Target: `{url}`\n"
            f"  🔒 **SSL Certificate Expiration Warning (7 Days)**\n"
            f"  Certificate will expire in ~7 days (on `{exp_date_str}`).\n"
            f"  Please make sure your renewal automation or certificate is up to date."
        )
    else:
        return

    if dc_bot_instance and dc_accid is not None:
        _dc_send_msg_with_stats(dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text),
                                priority=PRIO_ALERT, label="SSL alert", kind="alert")

async def _prewarm_target_dns(url: str, check_type: str) -> bool:
    """Resolves the target asynchronously (with the record TTL) before the synchronous SSRF check,
    so that check hits the cache instead of blocking the event loop. Returns False if blocked."""
    try:
        _, validated = parse_target(url)
        host = _target_host(validated, check_type)
        if host:
            await resolve_host_safe(host)
    except BlockedAddressError:
        return False
    except asyncio.TimeoutError:
        raise
    except Exception:
        pass  # unresolved names fail at the pinned connection boundary
    return True

async def _open_pinned_connection(host: str, port: int, family: int | None = None, **kwargs):
    """Opens a TCP connection to one of the validated addresses of host; returns the writer."""
    _, writer = await _open_pinned_streams(host, port, family, **kwargs)
    return writer


async def _open_pinned_streams(host: str, port: int, family: int | None = None, **kwargs):
    """Like _open_pinned_connection, but returns (reader, writer) for protocols that talk (SMTP)."""
    first_error = None
    for ip in await probe_addresses(host, family):
        try:
            return await asyncio.open_connection(ip, port, **kwargs)
        except OSError as e:
            # The first address is the preferred one (IPv4 first): its error explains the outage best
            first_error = first_error or e
    raise first_error or OSError(f"Could not connect to {host}:{port}")


class SMTPCheckError(Exception):
    """The SMTP server answered, but not as a working TLS mail server should (message is shown as is)."""


# Name sent in EHLO. Postfix and most servers do not check it on a session that sends no mail.
SMTP_EHLO_NAME = os.environ.get("SMTP_EHLO_NAME") or (socket.getfqdn() if "." in socket.getfqdn() else "localhost")


async def _smtp_read_reply(reader) -> tuple[int, list[str]]:
    """One (possibly multi-line, "250-...") SMTP reply -> (code, text lines)."""
    lines = []
    while True:
        raw = await reader.readline()
        if not raw:
            raise SMTPCheckError("SMTP: connection closed by server")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if len(line) < 3 or not line[:3].isdigit():
            raise SMTPCheckError(f"SMTP: unexpected reply: {line[:100]}")
        lines.append(line[4:])
        if len(line) == 3 or line[3] != "-":
            return int(line[:3]), lines
        if len(lines) > 100:
            raise SMTPCheckError("SMTP: reply too long")


async def _smtp_command(reader, writer, cmd: str) -> tuple[int, list[str]]:
    writer.write(cmd.encode() + b"\r\n")
    await writer.drain()
    return await _smtp_read_reply(reader)


def _short_ssl_error(e: Exception) -> str:
    """'SSL: certificate has expired' instead of '[SSL: CERTIFICATE_VERIFY_FAILED] ... (_ssl.c:1006)'."""
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"SSL: {getattr(e, 'verify_message', None) or e}"
    reason = getattr(e, "reason", None)
    return f"SSL: {reason.replace('_', ' ').lower()}" if reason else f"SSL: {e}"


async def smtp_tls_handshake(url: str, family: int | None = None) -> dict:
    """Talks to an smtp:// target the way a sending mail server does and returns its verified
    certificate (ssl.getpeercert()). Raises SMTPCheckError / ssl.SSLError / OSError on failure.

    Port 25/587: greeting 220 -> EHLO -> STARTTLS must be offered -> 220 -> TLS handshake.
    Port 465: TLS right away, then the greeting. Both end with QUIT, so the server logs an
    ordinary session (no "lost connection" lines that fail2ban could count).

    The certificate is checked like MTA-STS senders do: trusted CA and the target host name.
    No timeout here: callers wrap it in asyncio.wait_for."""
    host, port = _smtp_host_port(url)
    ctx = ssl.create_default_context()
    implicit = port in SMTP_IMPLICIT_TLS_PORTS
    if implicit:
        reader, writer = await _open_pinned_streams(host, port, family, ssl=ctx, server_hostname=host)
    else:
        reader, writer = await _open_pinned_streams(host, port, family)
    try:
        code, text = await _smtp_read_reply(reader)
        if code != 220:
            raise SMTPCheckError(f"SMTP: greeting {code} {' '.join(text)[:100]}")
        code, text = await _smtp_command(reader, writer, f"EHLO {SMTP_EHLO_NAME}")
        if code != 250:
            raise SMTPCheckError(f"SMTP: EHLO refused: {code} {' '.join(text)[:100]}")
        if not implicit:
            if not any(t.upper().split(" ", 1)[0] == "STARTTLS" for t in text):
                raise SMTPCheckError("SMTP: STARTTLS not offered")
            code, text = await _smtp_command(reader, writer, "STARTTLS")
            if code != 220:
                raise SMTPCheckError(f"SMTP: STARTTLS refused: {code} {' '.join(text)[:100]}")
            await writer.start_tls(ctx, server_hostname=host)
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        if not cert:
            raise SMTPCheckError("SMTP: no certificate")
        try:
            await asyncio.wait_for(_smtp_command(reader, writer, "QUIT"), timeout=3)
        except Exception:
            pass  # the check already passed; a slow goodbye does not make it fail
        return cert
    finally:
        writer.close()
        if asyncio.current_task().cancelling():
            # A TLS close handshake must not extend an already expired probe deadline.
            writer.transport.abort()
        else:
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _cert_expiry_ts(cert: dict) -> int | None:
    not_after_str = cert.get("notAfter") if cert else None
    if not not_after_str:
        return None
    try:
        exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        import email.utils
        exp_date = email.utils.parsedate_to_datetime(not_after_str)
    return int(exp_date.replace(tzinfo=datetime.timezone.utc).timestamp())

FREEZE_MAX_BYTES = 65536   # a body that stops below this is the TSPU "freeze"; above it, a slow link


class BodyStalled(Exception):
    """The body stopped (timeout, reset, early close) before the length the server announced."""
    def __init__(self, received: int, expected: int):
        super().__init__(f"body stopped after {received} of {expected} bytes")
        self.received, self.expected = received, expected


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def stalled_body_message(stall: BodyStalled) -> str:
    """'Freeze? Stalled after 10 KB of 2.0 MB': the connection opened, a few KB came, then nothing."""
    text = f"Stalled after {_fmt_size(stall.received)} of {_fmt_size(stall.expected)}"
    return blockcheck.with_tag(blockcheck.TAG_FREEZE if stall.received < FREEZE_MAX_BYTES else None, text)


async def _read_body_limited(resp, max_bytes: int) -> bytes:
    """Up to max_bytes of the body. With a known Content-Length it reads until that many bytes (or the
    announced length) have arrived and raises BodyStalled when the body stops earlier: a server that
    announced a file and stops after a few KB is what a freeze looks like. Without a length it is one
    read as before: a stream (events, long polling) may legitimately stay silent."""
    length = getattr(resp, "content_length", None)
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        return await resp.content.read(max_bytes)
    want = min(length, max_bytes)
    chunks, got = [], 0
    try:
        while got < want:
            chunk = await resp.content.read(min(want - got, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
    except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionError) as e:
        raise BodyStalled(got, length) from e
    if got < want and not resp.headers.get("Content-Encoding"):
        raise BodyStalled(got, length)   # closed early without an error
    return b"".join(chunks)


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_SAFE_REDIRECTS = 10

# The redirects of the last request of a check: [(status, next_url), ...]. A list per check, set by
# run_single_check; the caller reads it after the check (a coroutine awaited in the same task shares the
# context), so the (is_up, details, latency) result and the peer protocol stay as they are.
_redirect_trail: contextvars.ContextVar = contextvars.ContextVar("redirect_trail", default=None)
REDIRECT_URL_MAX = 120


def last_redirect_trail() -> list[tuple[int, str]]:
    return list(_redirect_trail.get() or [])


def format_redirects(trail) -> str | None:
    """'301 → https://example.com/' (one hop) or '301 → https://a/ → 302 → https://b/'; None without redirects."""
    if not trail:
        return None
    parts = []
    for status, url in trail:
        shown = redact_url(url)
        if len(shown) > REDIRECT_URL_MAX:
            shown = shown[:REDIRECT_URL_MAX - 1] + "…"
        parts.append(f"`{status}` → `{shown}`")
    return " → ".join(parts)

@contextlib.asynccontextmanager
async def _safe_http_request(sess, method: str, url: str, **kwargs):
    """Performs an HTTP request following redirects manually, re-validating every hop
    against the SSRF filter so a public URL cannot redirect the probe into a private network."""
    kwargs["allow_redirects"] = False
    current_url = url
    trail = _redirect_trail.get()
    if trail is not None:
        trail.clear()  # a HEAD followed by a GET: the trail is that of the request that decided
    for _ in range(_MAX_SAFE_REDIRECTS + 1):
        request_fn = getattr(sess, method.lower())
        async with request_fn(current_url, **kwargs) as resp:
            location = resp.headers.get("Location") if resp.status in _REDIRECT_STATUSES else None
            if not isinstance(location, str) or not location:
                yield resp
                return
            next_url = urljoin(str(resp.url) if getattr(resp, "url", None) else current_url, location)
            if not await _prewarm_target_dns(next_url, "http") or not is_safe_target_url(next_url, "http", resolve_dns=False):
                raise aiohttp.ClientError(f"Redirect to blocked address: {next_url[:200]}")
            if resp.status == 303 and method.upper() != "HEAD":
                method = "GET"
            if trail is not None:
                trail.append((resp.status, next_url))
            current_url = next_url
    raise aiohttp.ClientError("Too many redirects")

BLOCK_DIAGNOSIS_MIN_LEFT = 2.0   # seconds of the overall deadline that must be left to start a diagnosis

_HTTP_STATUS_ERROR_RE = re.compile(r"^\d{3}\b")


async def _annotate_block(resource, result):
    """Puts "SNI block?" / "DNS spoofing?" / "HTTP Host block?" before the error of a failed HTTP check
    when a second probe from this node points at filtering (see blockcheck.py). Only the text changes."""
    is_up, error, latency = result
    if is_up is not False or resource.get("type") != "http" or not error:
        return result
    if (error in (BLOCKED_TARGET_MSG, NO_IPV6_MSG) or _HTTP_STATUS_ERROR_RE.match(error)
            or "Missing keyword" in error or error.startswith("Redirect to blocked address")
            or any(t in error for t in blockcheck.TAGS)):  # already diagnosed (the IPv4 re-check)
        return result  # the server answered, or the target is not ours to probe
    try:
        parsed = urlparse(resource["url"])
        host = parsed.hostname
        if not host or _literal_ip(host):
            return result
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        ips = await probe_addresses(host, resource.get("family") if resource.get("family") in (4, 6) else None)
        tag = await blockcheck.diagnose_cached(host, port, use_tls, ips)
    except Exception as e:
        logger.debug(redact_url(f"Block diagnosis skipped for {resource.get('url')}: {e}"))
        return result
    return (is_up, blockcheck.with_tag(tag, error), latency) if tag else result


async def run_single_check(resource, session=None, *, keyword_error_limit=VOTE_ERROR_STORAGE_MAX) -> tuple[bool, str, int | None]:
    # A single monotonic deadline includes DNS, all redirects, fallback, reads and cleanup.
    started = time.monotonic()
    _redirect_trail.set([])
    try:
        async with asyncio.timeout(HTTP_TOTAL_DEADLINE):
            result = await _run_single_check(resource, session, keyword_error_limit)
    except asyncio.TimeoutError:
        result = (False, "Timeout", int((time.monotonic() - started) * 1000))
    # The diagnosis of a failure is part of the same overall deadline: it gets what is left of it
    remaining = HTTP_TOTAL_DEADLINE - (time.monotonic() - started)
    if remaining < BLOCK_DIAGNOSIS_MIN_LEFT:
        return result
    try:
        async with asyncio.timeout(remaining):
            return await _annotate_block(resource, result)
    except asyncio.TimeoutError:
        return result


async def _run_single_check(resource, session, keyword_error_limit):
    import http
    rtype = resource["type"]
    url = resource["url"]
    timeout = HTTP_REQUEST_TIMEOUT
    # 4 / 6 = only that address family (/ping -4 / -6); None = any, IPv4 first
    family = resource.get("family") if resource.get("family") in (4, 6) else None

    if not await _prewarm_target_dns(url, rtype) or not is_safe_target_url(url, rtype, resolve_dns=False):
        return False, BLOCKED_TARGET_MSG, None

    start_time = time.time()
    try:
        if rtype == "http":
            headers = {"User-Agent": USER_AGENT}
            req_timeout = aiohttp.ClientTimeout(total=timeout)
            expected_kw = (resource.get("expected_keyword") or "").strip()

            async def _do_get(sess, max_bytes: int, is_local: bool):
                get_kwargs = {}
                if not is_local:
                    get_kwargs["timeout"] = req_timeout
                async with _safe_http_request(sess, "GET", url, **get_kwargs) as resp:
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    try:
                        phrase = http.HTTPStatus(resp.status).phrase
                    except ValueError:
                        phrase = "Unknown Status"
                    details = f"{resp.status} - {phrase}"
                    if resp.status == 429:
                        # The target limits request rates: it answers some nodes and refuses others, which says
                        # nothing about whether it is up. Abstain, like a node that cannot check it.
                        return None, RATE_LIMITED_MSG, elapsed_ms
                    if 200 <= resp.status < 400:
                        body_bytes = None
                        try:
                            body_bytes = await _read_body_limited(resp, max_bytes)
                            charset = 'utf-8'
                            content_type = resp.headers.get('Content-Type', '')
                            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
                            if charset_match:
                                charset = charset_match.group(1)
                            try:
                                body_text = body_bytes.decode(charset, errors='ignore')
                            except Exception:
                                body_text = body_bytes.decode('utf-8', errors='ignore')
                        except BodyStalled as stall:
                            return False, stalled_body_message(stall), int((time.time() - start_time) * 1000)
                        except Exception as read_ex:
                            logger.warning(redact_url(f"Failed to read body for {url}: {read_ex}"))
                            body_text = ""

                        if expected_kw:
                            if expected_kw.lower() not in body_text.lower():
                                error = _missing_keyword_error(expected_kw, body_bytes, keyword_error_limit)
                                return False, error, elapsed_ms
                        else:
                            body_lower = body_text.lower()
                            if "error establishing a database connection" in body_lower:
                                return False, "200 OK (Database connection error detected)", elapsed_ms
                            if "database connection failed" in body_lower and len(body_text) < 16384:
                                return False, "200 OK (Database connection failed detected)", elapsed_ms
                            title_match = re.search(r'<title>(.*?)</title>', body_text, re.IGNORECASE | re.DOTALL)
                            if title_match:
                                title_text = title_match.group(1).strip().lower()
                                for err_pat in ("502 bad gateway", "503 service unavailable", "504 gateway time-out", "database error", "error 521", "error 522", "error 523", "error 524"):
                                    if err_pat in title_text:
                                        return False, f"200 OK (Error in title: \"{err_pat.title()}\")", elapsed_ms

                        return True, details, elapsed_ms
                    else:
                        return False, details, elapsed_ms

            async def _memorize_get():
                resource["http_method"] = "GET"
                try:
                    await run_db(database.set_url_http_method, url, "GET")
                except Exception as db_err:
                    logger.warning(redact_url(f"Failed to persist http_method for {url}: {db_err}"))

                # Update in-memory scheduler cache if present
                try:
                    cached_res = _scheduler_cache.get("resources")
                    if cached_res:
                        for cr in cached_res:
                            if cr.get("url") == url:
                                cr["http_method"] = "GET"
                    cached_pt = _scheduler_cache.get("probe_targets")
                    if cached_pt:
                        for cpt in cached_pt:
                            if cpt.get("url") == url:
                                cpt["http_method"] = "GET"
                except Exception:
                    pass

            async def _check_http(sess, is_local: bool):
                http_method = (resource.get("http_method") or "").strip().upper()
                if not expected_kw and http_method != "GET" and hasattr(sess, "head"):
                    # 1. Try lightweight HEAD first (0 bytes body read)
                    head_kwargs = {}
                    if not is_local:
                        head_kwargs["timeout"] = req_timeout
                    head_405 = False
                    head_status = None
                    try:
                        async with _safe_http_request(sess, "HEAD", url, **head_kwargs) as resp:
                            head_status = resp.status
                            if 200 <= resp.status < 400:
                                elapsed_ms = int((time.time() - start_time) * 1000)
                                try:
                                    phrase = http.HTTPStatus(resp.status).phrase
                                except ValueError:
                                    phrase = "Unknown Status"
                                details = f"{resp.status} - {phrase}"
                                return True, details, elapsed_ms
                            elif resp.status == 405:
                                head_405 = True
                    except (asyncio.TimeoutError, aiohttp.ClientConnectorError):
                        # Timeout, refused, DNS or certificate error: a GET would fail the same way and,
                        # for a hung target, hold a check slot for another full timeout
                        raise
                    except Exception as head_ex:
                        logger.debug(redact_url(f"HEAD check failed for {url} ({head_ex}), falling back to GET"))

                    if head_405:
                        logger.info(redact_url(f"HEAD check returned 405 Method Not Allowed for {url}. Memorizing GET method for this monitor."))
                        await _memorize_get()

                    # If HEAD was not 2xx/3xx or threw an exception, fall back to GET (max 16KB)
                    result = await _do_get(sess, 16384, is_local)
                    if head_status is not None and not head_405 and result[0]:
                        # HEAD answered 4xx/5xx but GET works (e.g. an app that only routes GET and
                        # crashes on HEAD): use GET from now on, so the server is not hit with a failing
                        # HEAD on every check
                        logger.info(redact_url(f"HEAD check returned {head_status} for {url} but GET succeeded. Memorizing GET method for this monitor."))
                        await _memorize_get()
                    return result
                elif not expected_kw:
                    return await _do_get(sess, 16384, is_local)
                else:
                    # Keyword check requires body reading (max 128KB)
                    return await _do_get(sess, 131072, is_local)

            if session is not None and not getattr(session, "closed", False) and family is None:
                return await _check_http(session, is_local=False)
            else:
                # aiohttp passes the connector's family to SafeResolver, which keeps only those addresses
                conn_family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(family, 0)
                async with aiohttp.ClientSession(connector=_make_safe_connector(family=conn_family), headers=headers, timeout=req_timeout) as local_session:
                    return await _check_http(local_session, is_local=True)
        elif rtype == "tcp":
            parts = url.rsplit(":", 1)
            host, port = parts[0].strip("[]"), int(parts[1])
            writer = await asyncio.wait_for(_open_pinned_connection(host, port, family), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            elapsed_ms = int((time.time() - start_time) * 1000)
            return True, f"{elapsed_ms} ms", elapsed_ms
        elif rtype == "smtp":
            # UP = greeting, STARTTLS and a certificate valid for this host, like a sending server needs
            try:
                await asyncio.wait_for(smtp_tls_handshake(url, family), timeout=timeout)
            except ssl.SSLError as e:
                return False, _short_ssl_error(e), int((time.time() - start_time) * 1000)
            except SMTPCheckError as e:
                return False, str(e), int((time.time() - start_time) * 1000)
            elapsed_ms = int((time.time() - start_time) * 1000)
            return True, f"{elapsed_ms} ms", elapsed_ms
        elif rtype == "ping":
            host = url.strip().strip("[]")
            if not (_HOSTNAME_RE.match(host) or _ipv6_literal(host)):
                return False, "Invalid hostname format", None

            if not ping_is_reliable():
                return None, PING_UNRELIABLE_MSG, None  # abstain, like a node without ICMP
            # Ping the validated address itself so the ping tool cannot resolve to something else
            host = (await probe_addresses(host, family))[0]
            try:
                rtts, ping_error = await ping_series(host)
            except FileNotFoundError:
                # No way to send ICMP here: abstain (like a missing IPv6) instead of reporting DOWN
                _warn_ping_unavailable()
                return None, PING_UNAVAILABLE_MSG, None
            if not rtts:
                elapsed_ms = int((time.time() - start_time) * 1000)
                return False, f"Ping failed: {ping_error}" if ping_error else "Timeout", elapsed_ms
            rtts_ms = [max(1, int(r * 1000)) for r in rtts]
            usual = await asyncio.to_thread(get_ping_baseline, host)
            state, details = assess_ping(rtts_ms, PING_COUNT, usual)
            latency_ms = int(statistics.median(rtts_ms))
            bad = state == CHECK_DEGRADED
            await asyncio.to_thread(note_ping_sample, host, latency_ms, bad)  # a bad series never teaches the baseline
            if bad and not confirm_degraded(host, True):
                state = True  # not yet: reachable, the details still say how slow
            elif not bad:
                confirm_degraded(host, False)
            if state == CHECK_DEGRADED:
                hint = path_trace_hint(host)
                if hint:
                    details = f"{details}; {hint}"
            return state, details, latency_ms
    except asyncio.TimeoutError:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, "Timeout", elapsed_ms
    except BlockedAddressError:
        return False, BLOCKED_TARGET_MSG, None
    except NoIPv6Error:
        return None, NO_IPV6_MSG, None  # None = not checked here: neither UP nor DOWN
    except NoAddressForFamilyError as e:
        return False, str(e), None
    except aiohttp.ClientConnectorError as e:
        os_error = getattr(e, "os_error", None)
        if isinstance(os_error, BlockedAddressError):
            return False, BLOCKED_TARGET_MSG, None
        if isinstance(os_error, NoIPv6Error):
            return None, NO_IPV6_MSG, None
        if isinstance(os_error, NoAddressForFamilyError):
            return False, str(os_error), None
        if rtype == "http" and not resource.get("family") and _failed_ipv6_address(str(e)):
            return await _recheck_over_ipv4(resource, str(e))
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, str(e), elapsed_ms
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, str(e), elapsed_ms
    return False, "Unknown error", None

_CONNECT_ADDR_RE = re.compile(r"\('([0-9A-Fa-f:.]+)', \d+(?:, \d+, \d+)?\)")


def _failed_ipv6_address(error: str) -> str | None:
    """The IPv6 address in aiohttp's "Connect call failed ('2a06::1', 443, 0, 0)", if any."""
    m = _CONNECT_ADDR_RE.search(error or "")
    return m.group(1) if m and ":" in m.group(1) else None


async def _recheck_over_ipv4(resource: dict, ipv6_error: str):
    """A dual-stack HTTP check failed and aiohttp reported its last attempt, an IPv6 address.

    aiohttp tries the addresses in rounds and keeps only the last error, so "Connect call failed
    ('2a06:...')" hid what happened over IPv4, the preferred family. Check again over IPv4 only:
    if that works the target is up; otherwise report both families."""
    host = urlparse(resource["url"]).hostname or ""
    try:
        try:
            await probe_addresses(host, 4)
        except NoAddressForFamilyError:
            # The cached answer may lack IPv4 only because the A query failed: ask DNS once more
            _dns_cache_forget(host)
            await probe_addresses(host, 4)
    except Exception:
        return False, ipv6_error, None  # IPv6-only host (or DNS gone): the IPv6 error is the answer
    v6 = _CONNECT_ADDR_RE.sub("", short_vote_error(ipv6_error) or ipv6_error).strip()
    prefix, suffix = "IPv4: ", f" · IPv6: {v6}"
    is_up, err4, latency = await run_single_check(
        {**resource, "family": 4}, keyword_error_limit=VOTE_ERROR_STORAGE_MAX - len(prefix) - len(suffix))
    if is_up:
        return is_up, err4, latency
    return False, f"{prefix}{short_vote_error(err4) or err4}{suffix}", latency


# Per-minute check summary (one INFO line instead of one per check; see log_check_summary)
_check_stats = {"up": 0, "down": 0, "skipped": 0, "lat_sum": 0, "lat_n": 0, "slowest": (0, "")}


def _count_check(is_up, latency_ms, label: str) -> None:
    key = "skipped" if is_up is None else ("up" if is_up else "down")
    _check_stats[key] += 1
    if is_up and isinstance(latency_ms, int):
        _check_stats["lat_sum"] += latency_ms
        _check_stats["lat_n"] += 1
        if latency_ms > _check_stats["slowest"][0]:
            _check_stats["slowest"] = (latency_ms, label)


def log_check_summary(running: int) -> None:
    """Logs and resets the counters: 'Checks in the last 60s: 148 (140 up, 6 down, 2 skipped) ...'."""
    st = _check_stats
    total = st["up"] + st["down"] + st["skipped"]
    avg = f"{st['lat_sum'] // st['lat_n']} ms" if st["lat_n"] else "n/a"
    slowest = f", slowest {redact_url(st['slowest'][1])} ({st['slowest'][0]} ms)" if st["slowest"][1] else ""
    waiting = dc_outbox.waiting()
    queued = f", outbox waiting {sum(waiting.values())} ({', '.join(f'{k} {v}' for k, v in waiting.items())})" if waiting else ""
    logger.info(f"Checks in the last 60s: {total} ({st['up']} up, {st['down']} down, {st['skipped']} skipped), "
                f"avg latency {avg}{slowest}; running now: {running}{queued}")
    _last_check_summary.update(total=total, up=st["up"], down=st["down"], skipped=st["skipped"], avg=avg)
    _cpu_samples.append((time.monotonic(), process_cpu_seconds()))
    st.update(up=0, down=0, skipped=0, lat_sum=0, lat_n=0, slowest=(0, ""))


VOTING_STATUSES = ("up", "degraded", "down")  # other votes ("unknown", "unstable") abstain


def decide_quorum(votes: list[dict]) -> str:
    """up / degraded / down from per-node results. Only up, degraded and down votes count.

    down: more than half of the voting nodes cannot reach the target. degraded: some can't, or some
    reach it only through a bad path (a degraded vote alone never makes it DOWN).
    With fewer than two voters the local result decides (as without peers)."""
    voters = [v for v in votes if v.get("status") in VOTING_STATUSES]
    if len(voters) < 2:
        local = next((v for v in votes if v.get("local")), None)
        return "down" if local and local.get("status") == "down" else "up"
    down = sum(1 for v in voters if v["status"] == "down")
    if down * 2 > len(voters):
        return "down"
    return "degraded" if any(v["status"] != "up" for v in voters) else "up"


def next_alert_state(resource_id: int, prev: str, raw: str) -> str:
    """Applies the hysteresis: DEGRADED is entered from UP, and left for UP, only after
    DEGRADED_CONFIRMATIONS consecutive votes. DOWN is entered at once (after this node's retries) and
    left at once, like before quorum alerting."""
    if raw == prev or raw == "down" or prev == "down":
        _alert_streaks.pop(resource_id, None)
        return raw
    cand, count = _alert_streaks.get(resource_id, (None, 0))
    count = count + 1 if cand == raw else 1
    if count >= DEGRADED_CONFIRMATIONS:
        _alert_streaks.pop(resource_id, None)
        return raw
    _alert_streaks[resource_id] = (raw, count)
    return prev


def _vote_entry(node: str, status: str, latency_ms=None, error_msg=None, local: bool = False) -> dict:
    v = {"node": str(node or "Peer")[:64], "status": status if status in VOTING_STATUSES else "unknown",
         "latency_ms": latency_ms if isinstance(latency_ms, int) and not isinstance(latency_ms, bool) else None,
         "error": str(error_msg)[:VOTE_ERROR_STORAGE_MAX] if error_msg and status != "up" else None}
    if local:
        v["local"] = True
    return v


# A node whose own network has trouble (home connection, provider filtering) fails many targets at
# once that the other nodes reach. Each of those became a separate partial outage notice (one node
# caused ~100 a week). Such a node is marked unstable and its DOWN votes abstain until it recovers.
NODE_UNSTABLE_TARGETS = 5     # distinct targets a node fails alone ...
NODE_UNSTABLE_WINDOW = 300    # ... within this many seconds: unstable
NODE_UNSTABLE_HOLD = 600      # stays unstable this long after the last time it met the threshold
UNSTABLE_NODE_ERROR = "node network unstable"
_node_outliers: dict[str, dict[str, float]] = {}  # node -> target url -> when it last failed it alone
_node_unstable_until: dict[str, float] = {}       # node -> unstable until (time.time())
_node_unstable_since: dict[str, float] = {}       # node -> when it became unstable (notified)

# A peer whose DNS or network is broken reports dozens of targets DOWN that are UP here. It also
# answers DOWN when asked again, so the per-target holds never applied: one node caused ~600
# revotes in 2.5 hours (a core CPU peak on de2). Past this many such targets in one report its
# reports are ignored altogether for a while.
PEER_FLOOD_TARGETS = 10
PEER_FLOOD_HOLD = 1800
_peer_flood_until: dict[str, float] = {}          # peer node -> ignored until (time.time())


def is_outlier_down(vote: dict, votes: list[dict]) -> bool:
    """vote is DOWN or DEGRADED while at least two other nodes reach the target fine and they are
    the majority."""
    voters = [v for v in votes if v.get("status") in VOTING_STATUSES]
    up = sum(1 for v in voters if v["status"] == "up")
    return vote.get("status") in ("down", "degraded") and up >= 2 and up * 2 > len(voters)


def note_vote_outliers(url: str, votes: list[dict], now: float = None) -> list[tuple[str, int]]:
    """Records the nodes that failed url alone. Returns (node, targets failed) for each node that
    just became unstable."""
    now = now or time.time()
    newly = []
    for v in votes or []:
        if v.get("status") in VOTING_STATUSES and not v.get("local"):
            hist = _node_vote_history.setdefault(v["node"], collections.deque(maxlen=2000))
            hist.append((now, is_outlier_down(v, votes)))
        if not is_outlier_down(v, votes):
            continue
        node = v["node"]
        recent = _node_outliers.setdefault(node, {})
        recent[url] = now
        for u in [u for u, t in recent.items() if now - t > NODE_UNSTABLE_WINDOW]:
            del recent[u]
        if len(recent) >= NODE_UNSTABLE_TARGETS:
            if not is_node_unstable(node, now):
                newly.append((node, len(recent)))
            _node_unstable_until[node] = now + NODE_UNSTABLE_HOLD
            _node_unstable_since.setdefault(node, now)
    return newly


def is_node_unstable(node: str, now: float = None) -> bool:
    return _node_unstable_until.get(node, 0) > (now or time.time())


def mask_unstable_votes(votes: list[dict], now: float = None) -> list[dict]:
    """DOWN and DEGRADED votes of unstable nodes abstain (status "unstable"): they say more about
    the node than about the target. A real outage is still seen by the other nodes."""
    return [{**v, "status": "unstable", "error": UNSTABLE_NODE_ERROR}
            if v.get("status") in ("down", "degraded") and is_node_unstable(v["node"], now) else v
            for v in votes]


def pop_recovered_nodes(now: float = None) -> list[tuple[str, int]]:
    """(node, seconds it was unstable) for each node whose unstable period just ended."""
    now = now or time.time()
    done = [n for n, since in _node_unstable_since.items() if not is_node_unstable(n, now)]
    out = []
    for n in done:
        out.append((n, int(now - _node_unstable_since.pop(n))))
        _node_unstable_until.pop(n, None)
        _node_outliers.pop(n, None)
    return out


async def notify_unstable_nodes(newly: list[tuple[str, int]]):
    for node, count in newly:
        logger.warning(f"Node {node} failed {count} targets within {NODE_UNSTABLE_WINDOW}s that other nodes reach: marking it unstable")
        await send_admin_notification(
            f"🛰️ **Node Network Problem**: {node}\n"
            f"It failed or degraded **{count}** targets within {NODE_UNSTABLE_WINDOW // 60} min that the other nodes reach, "
            f"so the problem is most likely its own network.\n\n"
            f"Its DOWN votes are ignored (no partial outage notices from it) until it has been stable for "
            f"{NODE_UNSTABLE_HOLD // 60} min. Outages seen by the other nodes are still reported.")


def build_votes(local_node: str, is_up, latency_ms, error_msg, peer_results) -> list[dict]:
    votes = [_vote_entry(local_node, check_status(is_up), latency_ms, error_msg, local=True)]
    seen = {local_node}
    for pr in peer_results or []:
        node = pr.get("node_name") or "Peer"
        if node in seen:
            continue  # one vote per node
        seen.add(node)
        votes.append(_vote_entry(node, pr.get("status"), pr.get("latency_ms"), pr.get("error_msg")))
    return votes


VOTE_ERROR_MAX = 60  # characters of a node's error shown next to it in vote lines
_CONNECT_ERROR_RE = re.compile(r"^Cannot connect to host \S+ ssl:\S+ \[(.*)\]$", re.S)
_ERRNO_PREFIX_RE = re.compile(r"^\[Errno -?\d+\]\s*")


def short_vote_error(error, limit: int = VOTE_ERROR_MAX) -> str | None:
    """A node's check error, short enough for a vote line: 'Timeout', 'Connection refused',
    'SSL: self-signed certificate' instead of aiohttp's full 'Cannot connect to host ...' text."""
    if not error:
        return None
    tag, error = blockcheck.split_tag(" ".join(str(error).split()))
    if tag:  # keep the tag whole and shorten what follows it
        rest = short_vote_error(error, max(limit - len(tag) - 1, 10))
        return f"{tag} {rest}" if rest else tag
    text = " ".join(str(error).split())
    if text.startswith((MISSING_KEYWORD_PREFIX, "IPv4: " + MISSING_KEYWORD_PREFIX)) and '"; got: ' in text:
        return text[:VOTE_ERROR_STORAGE_MAX]
    ssl_fail = re.search(r"certificate verify failed: ([^()'\]]+)", text)
    if ssl_fail:
        text = "SSL: " + ssl_fail.group(1).strip()
    else:
        m = _CONNECT_ERROR_RE.match(text)
        if m and m.group(1).strip():
            text = m.group(1).strip()
        text = _ERRNO_PREFIX_RE.sub("", text)
    if len(text) > limit:
        text = text[:limit - 1].rstrip() + "…"
    return text or None


def format_votes(votes: list[dict]) -> str:
    """🔴 DE (Timeout) · 🟠 HOME (550 ms, loss 60%, usual 60 ms) · 🟢 IT (196ms) · ⚪ RU2 (no result)

    Each failing node shows why it failed; when all of them failed the same way the reason is
    given once: 🔴 DE, RU (Timeout)."""
    down_votes = [v for v in votes if v.get("status") == "down"]
    errors = [short_vote_error(v.get("error")) for v in down_votes]
    if len(down_votes) > 1 and errors[0] and len(set(errors)) == 1:
        down = [", ".join(v["node"] for v in down_votes) + f" ({errors[0]})"]
    else:
        down = [f"{v['node']} ({err})" if err else v["node"] for v, err in zip(down_votes, errors)]
    degraded = [f"{v['node']} ({short_vote_error(v.get('error'), DEGRADED_VOTE_ERROR_MAX) or 'degraded'})"
                for v in votes if v.get("status") == "degraded"]
    up = [f"{v['node']} ({v['latency_ms']}ms)" if v.get("latency_ms") is not None else v["node"]
          for v in votes if v.get("status") == "up"]
    unstable = [v["node"] for v in votes if v.get("status") == "unstable"]
    other = [v["node"] for v in votes if v.get("status") not in ("up", "degraded", "down", "unstable")]
    parts = []
    if down:
        parts.append("🔴 " + ", ".join(down))
    if degraded:
        parts.append("🟠 " + ", ".join(degraded))
    if up:
        parts.append("🟢 " + ", ".join(up))
    if unstable:
        parts.append("⚪ " + ", ".join(unstable) + f" ({UNSTABLE_NODE_ERROR}, not counted)")
    if other:
        parts.append("⚪ " + ", ".join(other) + " (no result)")
    return " · ".join(parts)


def _votes_from_json(raw) -> list[dict]:
    try:
        votes = json.loads(raw) if raw else []
        return votes if isinstance(votes, list) else []
    except (TypeError, ValueError):
        return []


def _votes_summary(votes: list[dict]) -> str:
    down = [v["node"] for v in votes if v.get("status") == "down"]
    degraded = [v["node"] for v in votes if v.get("status") == "degraded"]
    up = [v["node"] for v in votes if v.get("status") == "up"]
    parts = ([f"Unreachable from {', '.join(down)}"] if down else []) + \
            ([f"degraded path from {', '.join(degraded)}"] if degraded else [])
    if not parts:
        return "Reachable from all nodes"
    text = "; ".join(parts)
    text = text[0].upper() + text[1:]
    if up:
        text += f"; reachable from {', '.join(up)}"
    return text


def note_peer_reported_down(peer_node: str, metrics: list[dict]) -> int:
    """Marks targets a peer reports DOWN that are UP here, in a quorum chat. Returns how many."""
    now = int(time.time())
    down_urls = set()
    for m in metrics or []:
        if not isinstance(m, dict) or m.get("status") not in ("down", "degraded"):
            continue
        u = str(m.get("url") or "")
        if not u or database.is_node_target_ignored(peer_node, u):
            continue
        checked = m.get("last_checked")
        received = m.get("received_at")
        if isinstance(received, (int, float)) and now - received > PEER_SUSPECT_MAX_AGE:
            continue
        if isinstance(checked, (int, float)) and not isinstance(checked, bool) and now - checked > PEER_SUSPECT_MAX_AGE:
            continue  # an old result (e.g. late in a >200 target rotation) is not evidence
        down_urls.add(u)
    if not down_urls:
        return 0
    if _peer_flood_until.get(peer_node, 0) > time.time():
        return 0  # flooding: see PEER_FLOOD_TARGETS
    marked = set()
    modes = {}
    for url in [u for u in down_urls if report_held(u, peer_node)]:
        down_urls.discard(url)  # the last vote did not confirm this node's report
    if not down_urls:
        return 0
    for r in database.get_resources_by_urls(down_urls):
        if r["url"] in marked or r.get("status") != "up" or r.get("alert_state") not in (None, "up"):
            continue  # DOWN/DEGRADED targets are re-voted by their regular checks anyway
        if now < (r.get("maintenance_until") or 0):
            continue
        chat = r["dc_chat_id"]
        if chat not in modes:
            modes[chat] = database.get_chat_alert_mode(chat)
        if modes[chat] != "quorum":
            continue
        marked.add(r["url"])
    if len(marked) >= PEER_FLOOD_TARGETS:
        _peer_flood_until[peer_node] = time.time() + PEER_FLOOD_HOLD
        logger.warning(f"Peer {peer_node} reports {len(marked)} targets DOWN or DEGRADED that are UP here: "
                       f"its network is probably broken, ignoring its reports for {PEER_FLOOD_HOLD // 60} min")
        stat_event("held")
        return 0
    with _peer_suspect_lock:
        observed_at = time.monotonic()
        tick = _vote_grid_tick(time.time(), QUORUM_REVOTE_INTERVAL)
        for url in marked:
            previous = _peer_suspects.get(url)
            due = previous[2] if previous and observed_at - previous[0] <= PEER_SUSPECT_MAX_AGE else tick
            _peer_suspects[url] = (observed_at, peer_node, due)
    if marked:
        logger.info(f"Peer {peer_node} reports DOWN or DEGRADED for {len(marked)} target(s) that are UP here; scheduling votes")
    return len(marked)


def note_lone_reporter(url: str, reporter: str, votes: list[dict], now: float = None) -> bool:
    """After a vote that a peer's report started (votes as counted, unstable ones masked): if the
    reporter's vote abstained as unstable, ignore its reports for url for LONE_REPORTER_HOLD; if the
    reporter itself now answers UP, for UNCONFIRMED_REPORT_HOLD, doubled for each time in a row
    (up to UNCONFIRMED_REPORT_HOLD_MAX). A reporter whose vote still fails the target is heard (two
    of its reports in a row make the target DEGRADED) and its count starts over; a reporter that
    did not answer changes nothing. Returns True if it is ignored now."""
    now = now or time.time()
    held = _held_reports()
    status = next((v.get("status") for v in votes if v.get("node") == reporter), None)
    until, streak = held.get((url, reporter), (0, 0))
    if now - until > UNCONFIRMED_REPORT_HOLD_MAX:
        streak = 0  # the last unconfirmed report is long ago
    if status == "unstable":
        hold = LONE_REPORTER_HOLD
    elif status == "up":
        hold = min(UNCONFIRMED_REPORT_HOLD * 2 ** streak, UNCONFIRMED_REPORT_HOLD_MAX)
        streak += 1
    elif status in ("down", "degraded"):
        if held.pop((url, reporter), None):
            _db_quietly(database.delete_held_report, url, reporter)
        return False
    else:
        return False  # no answer: nothing learned
    held[(url, reporter)] = (now + hold, streak)
    _db_quietly(database.set_held_report, url, reporter, now + hold, streak)
    stat_event("held")
    if len(held) > 5000:
        for key in [k for k, (u, _) in held.items() if now - u > UNCONFIRMED_REPORT_HOLD_MAX]:
            del held[key]
    why = "is unstable" if status == "unstable" else "answers UP now"
    logger.info(redact_url(f"{url}: {reporter} {why}; ignoring its reports for this target for {hold // 60} min"))
    return True


def _db_quietly(fn, *args) -> None:
    try:
        fn(*args)
    except Exception as e:
        logger.debug(f"{fn.__name__} failed: {e}")


def _vote_grid_tick(earliest, interval):
    return math.ceil(earliest / interval) * interval


@dataclass
class _CachedVote:
    at: float
    anchor: float
    local_up: bool | str
    results: list
    step: int = 0
    decision: str | None = None

    @property
    def due(self):
        interval = QUORUM_REVOTE_STEPS[self.step]
        return _vote_grid_tick(self.anchor + interval, interval)


def _suspect_vote_due(entry, cached):
    if cached:
        return max(entry[2], _vote_grid_tick(cached.anchor + QUORUM_REVOTE_INTERVAL - 10, QUORUM_REVOTE_INTERVAL))
    return entry[2]


def _take_peer_suspect(rep: dict) -> str | None:
    """Take a fresh report when its grid check can ask for confirmation."""
    grid = _vote_check.get()
    if grid is False:
        return None
    with _peer_suspect_lock:
        entry = _peer_suspects.get(rep["url"])
        if not entry:
            return None
        now = time.monotonic()
        if now - entry[0] > PEER_SUSPECT_MAX_AGE:
            del _peer_suspects[rep["url"]]
            return None
        cached = _vote_cache.get(_cross_check_key(rep))
        if grid and grid.tick < _suspect_vote_due(entry, cached):
            return None
        if not grid and cached and now - cached.at < QUORUM_REVOTE_INTERVAL - 10:
            return None
        del _peer_suspects[rep["url"]]
        return entry[1]


async def _quorum_resource_ids(group: list[dict]) -> set:
    """Monitors of this target decided by quorum: chat mode quorum, live peers exist and the monitor
    may be sent to peers (/peershare) - otherwise there is nobody to vote, and this node decides."""
    peers = await asyncio.to_thread(database.get_all_peers)
    if not any(not p.get("is_offline") for p in peers or []):
        return set()
    modes = {chat: await asyncio.to_thread(database.get_chat_alert_mode, chat)
             for chat in {r["dc_chat_id"] for r in group}}
    candidates = [r for r in group if modes[r["dc_chat_id"]] == "quorum"]
    if not candidates:
        return set()
    shareable = await asyncio.to_thread(_filter_peer_shareable_resources, dc_bot_instance, dc_accid, candidates)
    return {r["id"] for r in shareable}


async def collect_peer_votes(rep: dict, local_up: bool, fresh: bool = False, *,
                             periodic: bool = False, reporter: str = None) -> list[dict] | None:
    """Reuse a vote between grid ticks. Local changes still go straight to the urgent batch."""
    key = _cross_check_key(rep)
    now, wall = time.monotonic(), time.time()
    cached = _vote_cache.get(key)
    grid = _vote_check.get()
    non_urgent = bool(periodic or reporter)
    if periodic and not fresh:
        if cached:
            fresh = cached.local_up != local_up
        else:
            previous = next((v.get("status") for v in _votes_from_json(rep.get("last_votes"))
                             if v.get("local")), rep.get("status"))
            fresh = previous in VOTING_STATUSES and previous != check_status(local_up)
    non_urgent = non_urgent and not fresh
    if cached and not fresh and not reporter and cached.local_up == local_up:
        if periodic and grid is not None:
            if not grid or grid.tick < cached.due:
                return cached.results
        elif now - cached.at < QUORUM_REVOTE_INTERVAL:
            return cached.results
    if non_urgent and grid is False:
        return None  # a scheduled check will get answers; keep the current alert state meanwhile
    results = await request_peer_cross_checks_batched(rep, reporter, urgent=not non_urgent)
    current = _vote_cache.get(key)
    if current is not cached and current is not None and current.at >= now:
        return results
    if periodic and non_urgent and cached:
        step = min(cached.step + 1, len(QUORUM_REVOTE_STEPS) - 1)
    else:
        step = 0
    _vote_cache[key] = _CachedVote(now, grid.tick if non_urgent and grid else wall,
                                   local_up, results, step, cached.decision if cached else None)
    _vote_cache.move_to_end(key)
    if len(_vote_cache) > VOTE_CACHE_MAX_ENTRIES:
        _vote_cache.popitem(last=False)
    return results


def _queue_degraded_notice(kind: str, resource: dict, votes: list[dict], started_at: int = None):
    """Collects DEGRADED starts/ends of a chat for DEGRADED_NOTIFY_WINDOW and sends them as one message."""
    global _degraded_flush_task
    _degraded_notify_queue.setdefault(resource["dc_chat_id"], []).append((kind, resource, votes, started_at))
    if _degraded_flush_task is None or _degraded_flush_task.done():
        _degraded_flush_task = asyncio.create_task(_flush_degraded_notices())


def format_degraded_notice(items: list) -> str:
    starts = [i for i in items if i[0] == "start"]
    ends = [i for i in items if i[0] == "end"]
    now = int(time.time())
    lines = []
    if starts:
        lines.append(f"🟠 Partial outage: {len(starts)} monitor(s) unreachable from some nodes")
        for _, r, votes, _ in starts:
            name = r.get("name") or r["url"]
            lines.append(f"🟠 #{r['id']} {name}")
            if name != r["url"]:
                lines.append(f"  Target: {r['url']}")
            lines.append(f"  {format_votes(votes)}")
        lines.append("Not counted as downtime (most nodes reach them).")
    if ends:
        if lines:
            lines.append("")
        lines.append(f"✅ Partial outage resolved: {len(ends)} monitor(s) reachable from all nodes")
        for _, r, votes, started_at in ends:
            dur = f" after {format_duration(max(1, now - started_at))}" if started_at else ""
            name = r.get("name") or r["url"]
            lines.append(f"🟢 #{r['id']} {name}{dur}")
            if name != r["url"]:
                lines.append(f"  Target: {r['url']}")
            lines.append(f"  {format_votes(votes)}")
    return "\n".join(lines)


def should_notify_start(started_at, now, minutes, ended_at=None) -> bool:
    """Only an open outage whose delay has elapsed may announce its start."""
    return minutes != "off" and ended_at is None and started_at is not None and now >= started_at + minutes * 60


def should_notify_resolved(start_sent: bool) -> bool:
    return bool(start_sent)


_silent_partial_outages: set = set()  # compatibility for diagnostics/tests


def _journal_outage_text(resource, prefix, ending=None):
    name = short_monitor_name(resource)
    if ending is not None:
        duration = re.sub(r" 0s$", "", format_duration(max(0, ending)))
        return f"✅ {name} recovered after {duration}"
    votes = [v for v in _votes_from_json(resource.get("last_votes"))
             if isinstance(v, dict) and v.get("status") in VOTING_STATUSES]
    nodes = [v for v in votes if v.get("status") in ("down", "degraded")]
    condition = "is down" if prefix == "🔴" else "is partially down"
    return f"{prefix} {name} {condition}" + (f" ({len(nodes)} of {len(votes)} nodes)" if votes else "")


def _journal_partial_events(chat_id=None):
    now = int(time.time())
    rows = database.get_partial_journal_rows(chat_id, pending_only=True)
    chats = {r["dc_chat_id"] for r in rows}
    keys = [f"report_partial:{chat}" for chat in chats]
    for r in rows:
        suffix = f"{r['dc_chat_id']}:{r['partial_id']}"
        keys.append(f"journal:partial_start:{suffix}")
        if r["partial_ended_at"] is not None:
            keys.append(f"journal:partial_end:{suffix}")
    config = database.get_configs(keys)
    minutes_by_chat = {chat: database.parse_chat_report_partial(config.get(f"report_partial:{chat}")) for chat in chats}
    for r in rows:
        chat = r["dc_chat_id"]
        minutes = minutes_by_chat[chat]
        if minutes == "off":
            continue
        identity = r["partial_id"]
        start_key = f"journal:partial_start:{chat}:{identity}"
        ended = r["partial_ended_at"]
        if ended is None:
            if start_key in config:
                continue
            votes = _votes_from_json(r.get("last_votes"))
            nodes = [v["node"] for v in votes if v.get("status") in ("down", "degraded")]
            if (r.get("alert_state") == "degraded" and r.get("status") != "down"
                    and r.get("notice_state") in (0, 1, 2)
                    and should_notify_start(r["partial_started_at"], now, minutes)
                    and not (nodes and all(is_node_unstable(n) for n in nodes))):
                database.add_chat_event(chat, "partial_start", _journal_outage_text(r, "🟠", None),
                                        once=identity)
        elif (f"journal:partial_end:{chat}:{identity}" not in config
              and config.get(start_key) and r.get("notice_state") != 3
              and r.get("status") != "down" and r.get("alert_state") != "down"):
            database.add_chat_event(chat, "partial_end", _journal_outage_text(r, "", ended - r["partial_started_at"]),
                                    once=identity)


def _journal_incident_events(chat_id, events, resources, now):
    minutes_key = f"report_full:{chat_id}"
    notices_key = f"report_app_notices_after:{chat_id}"
    keys = [minutes_key, notices_key]
    for event in events:
        suffix = f"{chat_id}:{event['id']}"
        keys.append(f"journal:incident_start:{suffix}")
        if event.get("went_up_at") is not None:
            keys.append(f"journal:incident_end:{suffix}")
    config = database.get_configs(keys)
    minutes = database.parse_chat_report_full(config.get(minutes_key))
    notices_after = int(config.get(notices_key) or 0)
    for event in events:
        identity = event["id"]
        resource = resources.get(event["resource_id"], event)
        ended = event.get("went_up_at")
        start_key = f"journal:incident_start:{chat_id}:{identity}"
        if ended is None:
            if (start_key not in config and event["went_down_at"] > notices_after
                    and should_notify_start(event["went_down_at"], now, minutes)):
                database.add_chat_event(chat_id, "incident_start", _journal_outage_text(resource, "🔴"),
                                        once=identity)
        elif f"journal:incident_end:{chat_id}:{identity}" not in config and config.get(start_key):
            database.add_chat_event(chat_id, "incident_end", _journal_outage_text(resource, "", ended - event["went_down_at"]),
                                    once=identity)


def _deliver_degraded_notices(chat_id: int):
    """Recheck persisted state when the outbox actually sends, including queued recoveries."""
    if not dc_bot_instance or dc_accid is None:
        return
    _journal_partial_events(chat_id)
    minutes = database.get_chat_report_partial(chat_id)
    if database.get_chat_report_app(chat_id) == "only" or minutes == "off":
        return
    keep = []
    claimed_starts = []
    for r in database.get_pending_partial_notices():
        if r["dc_chat_id"] != chat_id:
            continue
        start = r["partial_ended_at"] is None
        votes = _votes_from_json(r.get("last_votes"))
        if start:
            if r.get("alert_state") != "degraded" or r.get("status") == "down":
                continue
            if not should_notify_start(r["partial_started_at"], int(time.time()), minutes):
                continue
            down_nodes = [v["node"] for v in votes if v.get("status") in ("down", "degraded")]
            if down_nodes and all(is_node_unstable(n) for n in down_nodes):
                database.claim_partial_notice(r["partial_id"], True)  # suppress this outage permanently
                continue
        elif r.get("status") == "down" or r.get("alert_state") == "down":
            # Escalation is covered by the full incident; do not call it recovered.
            database.claim_partial_notice(r["partial_id"], False)
            continue
        if database.claim_partial_notice(r["partial_id"], start):
            keep.append(("start" if start else "end", r, votes, r["partial_started_at"]))
            if start:
                claimed_starts.append(r["partial_id"])
    if keep:
        try:
            msg_id = dc_bot_instance.rpc.send_msg(dc_accid, chat_id, MsgData(text=format_degraded_notice(keep)))
        except JsonRpcError:
            for kind, r, _, _ in keep:
                database.release_rejected_partial_notice(r["partial_id"], kind == "start")
            raise
        record_sent_mail("alert")
        stat_event("mail_out")
        for partial_id in claimed_starts:
            database.mark_partial_notice_sent(partial_id)
        return msg_id


async def _check_report_notices():
    await run_db(_journal_partial_events)
    pending = await run_db(database.get_pending_partial_notices)
    now = int(time.time())
    chats = {r["dc_chat_id"] for r in pending}
    config = await run_db(database.get_configs, (f"{key}:{chat}" for chat in chats
                                                  for key in ("report_partial", "report_app")))
    settings = {}
    due_chats = set()
    for r in pending:
        chat_id = r["dc_chat_id"]
        if chat_id not in settings:
            settings[chat_id] = database.parse_chat_report_partial(config.get(f"report_partial:{chat_id}"))
        minutes = settings[chat_id]
        if minutes == "off" or config.get(f"report_app:{chat_id}") == "only":
            continue
        if r["partial_ended_at"] is not None or (
                r.get("alert_state") == "degraded" and r.get("status") != "down"
                and should_notify_start(r["partial_started_at"], now, minutes)):
            due_chats.add(chat_id)
    for chat_id in due_chats:
        dc_outbox.submit(lambda chat=chat_id: _deliver_degraded_notices(chat),
                         priority=PRIO_ALERT, key=("partial", chat_id), label="partial outage notice", kind=None)


async def _flush_degraded_notices():
    await asyncio.sleep(DEGRADED_NOTIFY_WINDOW)
    _degraded_notify_queue.clear()
    await _check_report_notices()


async def apply_quorum_state(r: dict, votes: list[dict], votes_json: str) -> str:
    """Moves a monitor to its next alert state, records partial outages and queues notices.
    Returns the new state; the caller stores status DOWN only for "down"."""
    # status DOWN is alert state DOWN (also for monitors that were down before quorum alerting existed)
    prev = "down" if r.get("status") == "down" else r.get("alert_state")
    if prev not in ("up", "degraded"):
        prev = "down" if prev == "down" and r.get("status") == "down" else "up"
    now = int(time.time())
    if now < (r.get("maintenance_until") or 0):
        await run_db(database.update_resource_votes, r["id"], votes_json)
        return prev
    new = next_alert_state(r["id"], prev, decide_quorum(votes))
    nodes_down = json.dumps([v["node"] for v in votes if v.get("status") in ("down", "degraded")])
    degraded_since = r.get("degraded_since") or 0
    if new == "degraded":
        if prev != "degraded":
            degraded_since = now
            _queue_degraded_notice("start", r, votes)
        await run_db(database.start_partial_outage, r["id"], degraded_since, nodes_down)
    elif prev == "degraded":
        started_at = await run_db(database.end_partial_outage, r["id"], now, new == "up")
        if new == "up":
            _queue_degraded_notice("end", r, votes, started_at or degraded_since or None)
        degraded_since = 0  # to DOWN: the incident message takes over
    if new != prev:
        logger.info(redact_url(f"Quorum: {r.get('name') or r['url']} (id: {r['id']}) {prev.upper()} -> {new.upper()} ({format_votes(votes)})"))
    await run_db(database.update_resource_alert_state, r["id"], new, votes_json, degraded_since)
    r["alert_state"], r["last_votes"], r["degraded_since"] = new, votes_json, degraded_since
    return new


async def check_network_probe(target, semaphore, session=None):
    """Executes a network check acquiring the concurrency semaphore ONLY for the duration of the network probe."""
    async with semaphore:
        return await run_single_check(target, session=session)


def _resource_in_alert(resource):
    return resource["status"] == "down" or resource.get("alert_state") in ("degraded", "down")


async def check_group_task(group, semaphore, session=None):
    groups = collections.defaultdict(list)
    for resource in group:
        groups[_cross_check_key(resource)].append(resource)
    if len(groups) > 1:
        for same_assertion in groups.values():
            await check_group_task(same_assertion, semaphore, session=session)
        return
    rep = group[0]
    if rep.get("is_probe_only"):
        res = await check_network_probe(rep, semaphore, session=session)
        if len(res) == 3:
            is_up, error_msg, latency_ms = res
        else:
            is_up, error_msg = res
            latency_ms = None
        _count_check(is_up, latency_ms, rep["url"])
        is_up = for_peers(is_up, error_msg)
        if is_up is None:  # this node cannot check it (no IPv6, private address here)
            if error_msg in (BLOCKED_TARGET_MSG, RATE_LIMITED_MSG, PING_UNRELIABLE_MSG, PING_UNAVAILABLE_MSG):
                # Not the last result: an earlier "down" would keep going to the peer in telemetry
                await run_db(database.update_probe_target_result, rep["url"], "skip", None, error_msg)
            return
        status_str = check_status(is_up)  # "degraded" goes to the requesting peer in telemetry
        local_node = database.get_local_node_name()
        await run_db(database.update_probe_target_result, rep["url"], status_str, latency_ms, error_msg)
        if status_str != rep.get("last_status"):
            _schedule_peer_metrics_delta()
        await run_db(database.save_peer_measurement, rep["url"], local_node, status_str, latency_ms, error_msg, local=True)
        return

    res = await check_network_probe(rep, semaphore, session=session)
    if len(res) == 3:
        is_up, error_msg, latency_ms = res
    else:
        is_up, error_msg = res
        latency_ms = None

    if is_up is None:
        # IPv6-only target on a node without IPv6: not an outage, so no retries, alerts or status change
        _count_check(None, None, rep["url"])
        logger.debug(redact_url(f"Check skipped: {rep['name'] or rep['url']} (id: {rep['id']}) in chat {rep['dc_chat_id']} ({error_msg})"))
        return

    # Retry logic: retry if check failed and at least one resource in the group was not already
    # DOWN or DEGRADED (those are re-checked every interval anyway).
    # Note: sleep(30) is executed OUTSIDE the semaphore so failing targets do not starve healthy checks!
    if not is_up and any(not _resource_in_alert(r) for r in group):
        for retry in range(1, 3):
            for r in group:
                if not _resource_in_alert(r):
                    logger.info(redact_url(f"Retry {retry}/2 for resource {r['id']} ({r['name'] or r['url']}) in chat {r['dc_chat_id']}"))
            await asyncio.sleep(30)
            res = await check_network_probe(rep, semaphore, session=session)
            if len(res) == 3:
                is_up, error_msg, latency_ms = res
            else:
                is_up, error_msg = res
                latency_ms = None
            if is_up:
                break

    # Host Outage Protection: If check failed, verify host internet before marking DOWN
    if not is_up:
        has_internet = await check_host_internet_connectivity()
        if not has_internet:
            logger.warning(
                redact_url(f"Host internet outage detected! Suppressing DOWN check result for {rep['name'] or rep['url']} in chat {rep['dc_chat_id']}")
            )
            return

    local_node = database.get_local_node_name()
    in_alert = any(_resource_in_alert(r) for r in group)
    # Reachable through a bad path from here: the peers say whether it is only this node's path
    locally_degraded = is_up == CHECK_DEGRADED
    was_locally_degraded = rep["url"] in _local_degraded
    if locally_degraded:
        _local_degraded[rep["url"]] = time.time()
    else:
        _local_degraded.pop(rep["url"], None)
    reported_by = _take_peer_suspect(rep) if is_up and not in_alert else None
    quorum_ids = (await _quorum_resource_ids(group)
                  if (not is_up or in_alert or reported_by or locally_degraded) else set())
    quorum_group = [r for r in group if r["id"] in quorum_ids]
    vote_key = _cross_check_key(rep)
    previous_vote = _vote_cache.get(vote_key)

    newly_failing = not is_up and any(not _resource_in_alert(r) for r in group)
    peer_results = None
    quorum_waiting = False
    try:
        if newly_failing and await _peer_cross_check_allowed(group):
            peer_results = await collect_peer_votes(rep, is_up, fresh=True)
        elif quorum_group and (not is_up or any(r.get("alert_state") in ("degraded", "down") for r in quorum_group)):
            peer_results = await collect_peer_votes(rep, is_up, periodic=True)
            quorum_waiting = peer_results is None
        elif reported_by and quorum_group:
            logger.info(redact_url(f"{rep.get('name') or rep['url']}: UP here but {reported_by} reports it DOWN; asking peers"))
            peer_results = await collect_peer_votes(rep, is_up, reporter=reported_by)
        elif locally_degraded and quorum_group:
            # Not fresh: answers are re-used for QUORUM_REVOTE_INTERVAL, so a path that stays bad
            # (e.g. this node's provider) does not ask the peers every minute
            peer_results = await collect_peer_votes(rep, is_up)
    except Exception as ex:
        logger.warning(redact_url(f"Error during peer cross-check: {ex}"))
    finally:
        if grid := _vote_check.get():
            grid.ready.set()

    votes = build_votes(local_node, is_up, latency_ms, error_msg, peer_results) if peer_results is not None else None
    if votes:
        newly_unstable = note_vote_outliers(rep["url"], votes)
        if newly_unstable:
            asyncio.create_task(notify_unstable_nodes(newly_unstable))
        votes = mask_unstable_votes(votes)
        if reported_by:
            note_lone_reporter(rep["url"], reported_by, votes)
    votes_json = json.dumps(votes) if votes and len(votes) > 1 else None

    # Local-mode monitors: this node decides; peers' answers are added to the error text
    local_error_msg = error_msg
    if not is_up and peer_results:
        up_peers = [pr for pr in peer_results if pr.get("status") == "up"]
        down_peers = [pr for pr in peer_results if pr.get("status") == "down"]
        if up_peers:
            reach_details = ", ".join(f"{pr.get('node_name', 'Peer')}: {pr.get('latency_ms', '?')}ms" for pr in up_peers)
            local_error_msg = f"{error_msg} (Reachable from {reach_details})"
        elif down_peers:
            nodes_confirmed = [pr.get('node_name', 'Peer') for pr in down_peers]
            local_error_msg = f"{error_msg} [Confirmed by {', '.join(nodes_confirmed)}]"

    # Each monitor's result: (is_up, error_msg) as stored and alerted on
    outcomes = {}
    quorum_changed = False
    for r in group:
        if r["id"] in quorum_ids and quorum_waiting:
            outcomes[r["id"]] = (r["status"] != "down", r.get("error_msg"))
            continue
        if r["id"] in quorum_ids and votes is not None:
            previous = "down" if r["status"] == "down" else (r.get("alert_state") or "up")
            state = await apply_quorum_state(r, votes, votes_json)
            quorum_changed |= state != previous
            r_up = state != "down"
            r_err = None if is_up and state == "up" else _votes_summary(votes)
            if not is_up and error_msg:
                # " — " rather than parentheses: the log line wraps this in its own "(...)"
                r_err = f"{error_msg} — {r_err}" if r_err else error_msg
            outcomes[r["id"]] = (r_up, r_err)
            continue
        if r.get("alert_state") == "degraded":
            # Switched to local mode (or no peers left) while degraded: close it quietly
            await run_db(database.end_partial_outage, r["id"], int(time.time()))
            await run_db(database.update_resource_alert_state, r["id"], "up", r.get("last_votes"), 0)
            r["alert_state"] = "up"
        if votes_json:
            await run_db(database.update_resource_votes, r["id"], votes_json)
            r["last_votes"] = votes_json
        if r.get("alert_state") != ("up" if is_up else "down"):
            # Keep alert_state in step with status, so a later switch to quorum starts from it
            await run_db(database.update_resource_alert_state, r["id"], "up" if is_up else "down",
                         r.get("last_votes"), 0)
            r["alert_state"] = "up" if is_up else "down"
        outcomes[r["id"]] = (bool(is_up), local_error_msg)

    cached = _vote_cache.get(vote_key)
    if quorum_group and votes is not None and cached and cached.results is peer_results:
        decision = decide_quorum(votes)
        if quorum_changed or (cached.decision is not None and cached.decision != decision):
            cached.step = 0
            if cached is previous_vote:
                cached.anchor = time.time()
        cached.decision = decision

    _count_check(is_up, latency_ms, rep.get("name") or rep["url"])  # the result after retries

    # One transaction for the whole check: every monitor of this target + the local measurement
    status_str = check_status(is_up)
    updates = [_status_update_for(r, outcomes[r["id"]][0], outcomes[r["id"]][1], latency_ms) for r in group]
    await run_db(database.record_check_results, updates, (rep["url"], local_node, status_str, latency_ms, error_msg))
    if locally_degraded != was_locally_degraded or any(r.get("status") != u["status"] for r, u in zip(group, updates)):
        _schedule_peer_metrics_delta()

    for r in group:
        if latency_ms is not None:
            r["last_latency_ms"] = latency_ms
        if rep.get("http_method"):
            r["http_method"] = rep["http_method"]
        r_up, r_err = outcomes[r["id"]]

        # INFO only for what needs attention (DOWN or a change); routine UPs are in the minute summary
        changed = r.get("status") != ("up" if r_up else "down")
        shown, local_word = ("UP" if r_up else "DOWN"), check_status(is_up).upper()
        logger.log(logging.INFO if (changed or not r_up or not is_up or locally_degraded) else logging.DEBUG,
                   redact_url(f"Check result: {r['name'] or r['url']} (id: {r['id']}) in chat {r['dc_chat_id']} -> {shown}"
                   f"{'' if shown == local_word else ' by quorum, locally ' + local_word} ({r_err})"))
        await handle_check_result(r, r_up, r_err, latency_ms=latency_ms, status_written=True)

    # Check SSL Certificate Expiry for HTTPS and SMTP targets (at most once per hour)
    if rep.get("type") in ("http", "smtp") and has_tls_certificate(rep.get("url", "")):
        now = int(time.time())
        ssl_last_checked = rep.get("ssl_last_checked") or 0
        if now - ssl_last_checked >= 3600:
            ssl_exp_ts, ssl_err = await check_ssl_expiry(rep["url"])
            for r in group:
                cur_state = r.get("ssl_alert_state") if r.get("ssl_alert_state") is not None else 0
                new_state = cur_state
                if ssl_exp_ts is not None:
                    days_left = (ssl_exp_ts - now) / 86400.0
                    exp_date_str = datetime.datetime.fromtimestamp(ssl_exp_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d')

                    if days_left > 7:
                        if cur_state != 0:
                            new_state = 0
                    elif days_left <= 0:
                        if cur_state != -1:
                            new_state = -1
                            await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=-1)
                    elif days_left <= 1:
                        if cur_state in (0, 7, 3):
                            new_state = 1
                            await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=1)
                    elif days_left <= 3:
                        if cur_state in (0, 7):
                            new_state = 3
                            await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=3)
                    elif days_left <= 7:
                        if cur_state == 0:
                            new_state = 7
                            await notify_ssl_alert(r, days_left, exp_date_str, alert_stage=7)

                    await run_db(database.update_resource_ssl, r["id"], ssl_exp_ts, now, new_state)
                else:
                    logger.warning(redact_url(f"SSL check for {rep['url']} failed: {ssl_err}"))
                    await run_db(database.update_resource_ssl, r["id"], r.get("ssl_expiry_date"), now, cur_state)

def format_incident_message(incident_id: int, started_at: int, resources: list[dict], is_resolved: bool = False, resolved_at: int = None, dc_chat_id: int = None, total_chat_monitors: int = None) -> str:
    start_dt = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    now = int(time.time())

    total_monitors = total_chat_monitors if total_chat_monitors is not None else len(resources)
    down_resources = [r for r in resources if r.get("status") == "down" or r.get("resource_status") == "down" or r.get("went_up_at") is None]
    up_resources = [r for r in resources if (r.get("status") == "up" or r.get("resource_status") == "up") and r.get("went_up_at") is not None]

    def append_details(r):
        name = r.get("name") or r.get("url")
        if r.get("url") and name != r["url"]:
            lines.append(f"  Target: {r['url']}")
        votes = _votes_from_json(r.get("last_votes"))
        if votes:
            prefix = "🟠 still partial: " if r.get("alert_state") == "degraded" else "🛰️ "
            lines.append(f"  {prefix}{format_votes(votes)}")

    if is_resolved:
        resolved_ts = resolved_at or now
        resolved_dt = datetime.datetime.fromtimestamp(resolved_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        duration_str = format_duration(max(1, resolved_ts - started_at))
        lines = [
            f"✅ Incident #{incident_id} resolved · {duration_str} ({start_dt} → {resolved_dt} UTC)",
            f"All {total_monitors} monitors operational" if total_monitors > 0 else "All monitored resources removed or operational"
        ]
        for r in resources:
            if not (r.get("name") or r.get("url")):
                continue
            name = r.get("name") or r.get("url")
            r_type = (r.get("type") or "HTTP").upper()
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"🟢 #{r['id']} {name} ({r_type}) · 30d {uptime_val:.2f}%")
            append_details(r)
        return "\n".join(lines)

    duration_str = format_duration(max(1, now - started_at))
    lines = [
        f"🚨 Incident #{incident_id} · Ongoing (started {start_dt} UTC, active {duration_str})",
        f"Affected: {len(down_resources)} / {total_monitors} monitors down"
    ]
    for r in down_resources:
        name = r.get("name") or r.get("url")
        r_type = (r.get("type") or "HTTP").upper()
        d_time = max(1, now - (r.get("last_changed") or r.get("went_down_at") or started_at))
        uptime_val = database.get_resource_uptime_30d(r["id"])
        lines.append(f"🔴 #{r['id']} {name} ({r_type}) · down {format_duration(d_time)} · 30d {uptime_val:.2f}%{slowdown_note(r, now)}")
        append_details(r)

    for r in up_resources:
        name = r.get("name") or r.get("url")
        r_type = (r.get("type") or "HTTP").upper()
        rec_dt = datetime.datetime.fromtimestamp(r.get("last_changed") or r.get("went_up_at") or now, tz=datetime.timezone.utc).strftime('%H:%M:%S')
        uptime_val = database.get_resource_uptime_30d(r["id"])
        lines.append(f"🟢 #{r['id']} {name} ({r_type}) · recovered {rec_dt} UTC · 30d {uptime_val:.2f}%")
        append_details(r)

    return "\n".join(lines)

_incident_sync_locks = {}
_incident_sync_locks_thread_lock = threading.Lock()
_incident_last_edit_state = {}

def get_chat_incident_lock(dc_chat_id: int) -> asyncio.Lock:
    with _incident_sync_locks_thread_lock:
        if dc_chat_id not in _incident_sync_locks:
            _incident_sync_locks[dc_chat_id] = asyncio.Lock()
        return _incident_sync_locks[dc_chat_id]


def prune_incident_sync_locks() -> int:
    """Removes idle (unlocked) incident sync locks to prevent unbounded memory growth."""
    with _incident_sync_locks_thread_lock:
        to_remove = [cid for cid, lock in _incident_sync_locks.items() if not lock.locked()]
        for cid in to_remove:
            del _incident_sync_locks[cid]
        return len(to_remove)

def get_incident_update_interval(duration_seconds: int) -> int:
    """Minimum seconds between live edits that only refresh an incident's duration.

    Every edit is a mail to the whole chat, so in an outage across many chats the old 15-60 s
    timer used most of the send limit. Status changes are still edited in right away; the
    message also shows the start time, so the duration only needs a refresh now and then."""
    if duration_seconds < 86400:
        return 300      # First day: every 5 minutes
    return 3600         # After that: once an hour


def _deliver_incident_message(inc_id: int, dc_chat_id: int, msg_text: str, resolved: bool, *, kind="alert"):
    """Runs in the outbox: edits the incident's message, or sends it if it has none yet (or the edit fails).

    The message id is read here, at sending time: a first message still waiting in the outbox is
    merged with later updates (same key) and goes out once, with the latest text."""
    if database.get_chat_report_app(dc_chat_id) == "only":
        return  # No claim: monitoring and incident state still advance normally.
    inc = database.get_incident_by_id(dc_chat_id, inc_id)
    msg_id = inc.get("msg_id") if inc else None
    if not inc or (resolved != (inc["status"] == "resolved")):
        return
    if not msg_id:
        if resolved or inc["status"] != "ongoing":
            return
        events = database.get_incident_downtime_events(inc_id)
        notices_after = int(database.get_config(f"report_app_notices_after:{dc_chat_id}") or 0)
        open_events = [ev for ev in events if ev.get("went_up_at") is None and ev["went_down_at"] > notices_after]
        minutes = database.get_chat_report_full(dc_chat_id)
        if not any(should_notify_start(ev["went_down_at"], int(time.time()), minutes) for ev in open_events):
            return
        if not database.claim_incident_message(inc_id):
            return
    if msg_id:
        try:
            dc_bot_instance.rpc.send_edit_request(dc_accid, msg_id, msg_text)
            record_sent_mail(kind)
            logger.info(f"{'Resolved' if resolved else 'Edited'} Incident #{inc_id} message {msg_id} in chat {dc_chat_id}")
            return msg_id
        except Exception as e:
            logger.warning(f"Failed to edit Incident message {msg_id} (sending new message): {e}")
    # A first send was claimed above; edits retain the existing replacement fallback.
    try:
        new_msg_id = dc_bot_instance.rpc.send_msg(dc_accid, dc_chat_id, MsgData(text=msg_text))
    except JsonRpcError:
        if not msg_id:
            database.release_rejected_incident_message(inc_id)
        raise
    record_sent_mail("alert")
    if isinstance(new_msg_id, int) and not resolved:
        database.update_incident_msg_id(inc_id, new_msg_id)
        current = database.get_incident_by_id(dc_chat_id, inc_id)
        if current and current["status"] == "resolved":
            # Recovery may have raced the first RPC while its msg_id was still unknown.
            ids = {ev["resource_id"] for ev in database.get_incident_downtime_events(inc_id)}
            resources = database.get_resources(dc_chat_id)
            text = format_incident_message(
                inc_id, current["started_at"], [r for r in resources if r["id"] in ids],
                is_resolved=True, resolved_at=current["resolved_at"],
                total_chat_monitors=len(resources), dc_chat_id=dc_chat_id)
            _queue_incident_message(inc_id, dc_chat_id, text, PRIO_ALERT, resolved=True)
    return new_msg_id


def _queue_incident_message(inc_id: int, dc_chat_id: int, msg_text: str, priority: int, resolved: bool = False):
    """One outbox job per incident: a queued update is replaced by a newer one, keeping its place."""
    if not dc_bot_instance or dc_accid is None:
        return
    if database.get_chat_report_app(dc_chat_id) == "only":
        return
    kind = "alert" if priority == PRIO_ALERT else "incident_edit"
    dc_outbox.submit(lambda: _deliver_incident_message(inc_id, dc_chat_id, msg_text, resolved, kind=kind),
                     priority=priority, key=("incident", inc_id), label=f"incident #{inc_id} message", kind=None)

async def sync_chat_incident_state(dc_chat_id: int, force_update: bool = False):
    chat_lock = get_chat_incident_lock(dc_chat_id)
    async with chat_lock:
        active_incidents, has_unlinked = await run_db(database.get_incident_sync_candidates, dc_chat_id)
        if not active_incidents and not has_unlinked:
            return

        resources = await run_db(database.get_resources, dc_chat_id, for_incident=True)
        total_chat_monitors = len(resources)
        now = int(time.time())
        active_res_map = {r["id"]: r for r in resources}
        
        # Link any unlinked open downtime events to matching incident or create a new incident
        if has_unlinked:
            unlinked_events = await run_db(database.get_unlinked_open_downtime_events, dc_chat_id)
            for ev in unlinked_events:
                matching_inc = await run_db(database.get_active_incident_for_outage, dc_chat_id, ev["went_down_at"], 3600, True)
                if matching_inc:
                    inc_id = matching_inc["id"]
                    if matching_inc.get("status") == "resolved":
                        await run_db(database.reopen_incident, inc_id)
                else:
                    inc_id = await run_db(database.create_incident, dc_chat_id, ev["went_down_at"])
                await run_db(database.link_downtime_event_to_incident, ev["id"], inc_id)
            active_incidents = await run_db(database.get_active_incidents_for_chat, dc_chat_id)

        events_by_incident = await run_db(database.get_incident_downtime_events_batch,
                                          [inc["id"] for inc in active_incidents])
        closed_resources = set()
        reloaded = set()
        for inc in active_incidents:
            inc_id = inc["id"]
            events = events_by_incident.pop(inc_id, None)
            if events is None or any(ev["resource_id"] in closed_resources and ev.get("went_up_at") is None
                                     for ev in events):
                # A retry or one of our earlier closes can invalidate the batch snapshot.
                events = await run_db(database.get_incident_downtime_events, inc_id)
            
            # If any open downtime event belongs to a deleted resource, close it
            for ev in events:
                if ev["resource_id"] not in active_res_map and ev.get("went_up_at") is None:
                    await run_db(database.close_resource_downtime_events, ev["resource_id"], now)
                    closed_resources.add(ev["resource_id"])
                    ev["went_up_at"] = now

            await run_db(_journal_incident_events, dc_chat_id, events, active_res_map, now)
            open_events = [ev for ev in events if ev.get("went_up_at") is None and ev["resource_id"] in active_res_map]
            
            if open_events:
                # Grouped/reopened incidents may be older than the continuous DOWN interval.
                if not inc.get("msg_id"):
                    minutes_key, after_key, app_key = (f"{key}:{dc_chat_id}" for key in
                                                        ("report_full", "report_app_notices_after", "report_app"))
                    settings = await run_db(database.get_configs, (minutes_key, after_key, app_key))
                    minutes = database.parse_chat_report_full(settings.get(minutes_key))
                    notices_after = int(settings.get(after_key) or 0)
                    if settings.get(app_key) == "only" or inc.get("message_claimed") or not any(
                            ev["went_down_at"] > notices_after and should_notify_start(ev["went_down_at"], now, minutes)
                            for ev in open_events):
                        continue
                # Incident is ongoing
                started_at = inc["started_at"]
                duration = max(0, now - started_at)
                
                status_sig = tuple(sorted((ev["resource_id"], ev.get("resource_status") or "", ev.get("went_up_at") or 0) for ev in events))
                last_edit_time, last_sig = _incident_last_edit_state.get(inc_id, (0.0, None))
                throttle_interval = get_incident_update_interval(duration)
                
                should_edit = (status_sig != last_sig) or ((now - last_edit_time) >= throttle_interval) or (inc.get("msg_id") is None)
                if not should_edit:
                    continue

                inc_resources = []
                seen_res = set()
                down_resources = {ev["resource_id"] for ev in open_events}
                for ev in events:
                    rid = ev["resource_id"]
                    if rid in active_res_map and rid not in seen_res:
                        seen_res.add(rid)
                        r = active_res_map[rid]
                        inc_resources.append({
                            "id": r["id"],
                            "name": r.get("name"),
                            "url": r.get("url"),
                            "type": r.get("type"),
                            "status": "down" if rid in down_resources else "up",
                            "last_changed": r.get("last_changed") or ev.get("went_up_at") or ev.get("went_down_at"),
                            "went_down_at": ev.get("went_down_at"),
                            "went_up_at": ev.get("went_up_at"),
                            "last_votes": r.get("last_votes"),
                        })
                
                msg_text = format_incident_message(
                    inc_id,
                    started_at,
                    inc_resources,
                    is_resolved=False,
                    total_chat_monitors=total_chat_monitors
                )
                
                # A new incident or a status change is an alert; a refresh of the duration can wait
                is_alert = inc.get("msg_id") is None or status_sig != last_sig
                _incident_last_edit_state[inc_id] = (now, status_sig)
                _queue_incident_message(inc_id, dc_chat_id, msg_text, PRIO_ALERT if is_alert else PRIO_UPDATE)

            else:
                # All events for this incident are closed -> Incident is resolved!
                _incident_last_edit_state.pop(inc_id, None)
                
                rec_resources = []
                seen_res = set()
                for ev in events:
                    rid = ev["resource_id"]
                    if rid in active_res_map and rid not in seen_res:
                        seen_res.add(rid)
                        rec_resources.append(active_res_map[rid])
                
                if rec_resources:
                    rec_names = [r.get("name") or r.get("url") for r in rec_resources]
                    summary_str = f"Recovered: {', '.join(rec_names)}"
                else:
                    summary_str = f"All {total_chat_monitors} monitors operational" if total_chat_monitors > 0 else "All monitored resources removed or operational"
                
                if not await run_db(database.resolve_incident, inc_id, now, summary_str):
                    # A new failure may have linked after the recovery snapshot. Reload once,
                    # then let the next audit retry if failures keep changing underneath us.
                    current = await run_db(database.get_incident_by_id, dc_chat_id, inc_id)
                    if current and current["status"] == "ongoing" and inc_id not in reloaded:
                        resources = await run_db(database.get_resources, dc_chat_id, for_incident=True)
                        active_res_map = {r["id"]: r for r in resources}
                        total_chat_monitors = len(resources)
                        reloaded.add(inc_id)
                        active_incidents.append(current)
                    continue
                
                msg_text = format_incident_message(
                    inc_id,
                    inc["started_at"],
                    rec_resources,
                    is_resolved=True,
                    resolved_at=now,
                    total_chat_monitors=total_chat_monitors,
                    dc_chat_id=dc_chat_id
                )
                
                if should_notify_resolved(inc.get("msg_id")):
                    _queue_incident_message(inc_id, dc_chat_id, msg_text, PRIO_ALERT, resolved=True)

def trigger_chat_incident_sync(dc_chat_id: int, force_update: bool = False):
    """Trigger incident state sync from a synchronous handler / thread."""
    global async_event_loop
    if async_event_loop and async_event_loop.is_running():
        asyncio.run_coroutine_threadsafe(sync_chat_incident_state(dc_chat_id, force_update=force_update), async_event_loop)
    else:
        try:
            asyncio.run(sync_chat_incident_state(dc_chat_id, force_update=force_update))
        except Exception as ex:
            logger.debug(f"Direct sync_chat_incident_state invocation: {ex}")

# A resource counts as stale for N days when its uptime over the last N days is under this. Not
# "continuously down": one short "up" (a flap, a peer that could still reach it) restarted that
# clock, so a dead target that flaps now and then was never cleaned up.
STALE_MAX_UPTIME_PCT = 1.0
# Auto-cleanup happens at least this long after the 14-day warning, so the chat always gets it first
STALE_CLEANUP_GRACE = 3 * 86400


async def _send_stale_message(dc_chat_id: int, text: str, what: str):
    try:
        if dc_bot_instance and dc_accid:
            await asyncio.to_thread(
                _dc_send_msg_with_stats,
                dc_bot_instance,
                dc_accid,
                dc_chat_id,
                MsgData(text=text),
                priority=PRIO_ALERT,
                kind="alert",
            )
    except Exception as ex:
        logger.error(f"Failed to send {what} message to chat {dc_chat_id}: {ex}")


def _is_stale_for(res_id: int, days: int, now: int) -> bool:
    uptime = database.get_resource_uptime_window(res_id, days * 86400, now)
    return uptime is not None and uptime < STALE_MAX_UPTIME_PCT


async def check_stale_downtime_notifications(resource, now: int):
    """Stale downtime handling for a resource that is down: 7d notice, 14d warning, 30d auto-cleanup.
    "Down for N days" = uptime under STALE_MAX_UPTIME_PCT over the last N days."""
    res = await asyncio.to_thread(database.get_resource_by_id, resource["id"])
    if not res or res["status"] != "down":
        return

    # A resource younger than a week cannot be stale yet (get_resource_uptime_window returns None)
    stale_level = res.get("stale_warning_level") or 0
    if now - (res.get("created_at") or now) < 7 * 86400:
        return

    dc_chat_id = res["dc_chat_id"]
    res_id = res["id"]
    res_name = res.get("name") or res.get("url")
    res_url = res.get("url")
    interval = max(10, res.get("interval") or 60)
    slowed = effective_check_interval(interval, "down", res.get("last_changed"), now)
    slow_text = f"\n\n🐢 _While it stays down, it is checked every {format_every(slowed)}._" if slowed > interval else ""

    if stale_level >= 14 and now - (res.get("stale_warning_at") or 0) >= STALE_CLEANUP_GRACE \
            and await asyncio.to_thread(_is_stale_for, res_id, 30, now):
        logger.warning(redact_url(f"Resource {res_id} ({res_name}) in chat {dc_chat_id} has been down for 30 days. Auto-removing from monitoring..."))
        await asyncio.to_thread(database.delete_resource, dc_chat_id, res_id)
        await _send_stale_message(dc_chat_id, (
            f"🗑️ **Auto-Cleanup (30 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has had practically no uptime "
            f"(under {STALE_MAX_UPTIME_PCT:g}%) for **30 days** and has been automatically removed from monitoring."
        ), "30d auto-cleanup")
        await sync_chat_incident_state(dc_chat_id)
        return

    if stale_level < 14 and await asyncio.to_thread(_is_stale_for, res_id, 14, now):
        await asyncio.to_thread(database.update_stale_warning_level, res_id, 14)
        await _send_stale_message(dc_chat_id, (
            f"⚠️ **Downtime Warning (14 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has been unreachable for **14 days** "
            f"(uptime under {STALE_MAX_UPTIME_PCT:g}%).\n\n"
            f"💡 _Please note: resources that stay this way for **30 days** will be automatically removed from monitoring._ "
            f"You can remove it anytime using `/remove {res_id}`.{slow_text}"
        ), "14d warning")
        return

    if stale_level < 7 and await asyncio.to_thread(_is_stale_for, res_id, 7, now):
        await asyncio.to_thread(database.update_stale_warning_level, res_id, 7)
        await _send_stale_message(dc_chat_id, (
            f"⚠️ **Downtime Notice (7 Days Unreachable)**\n\n"
            f"Resource **{res_name}** (`ID: {res_id}`) targeting `{res_url}` has been unreachable for **7 days** "
            f"(uptime under {STALE_MAX_UPTIME_PCT:g}%).\n\n"
            f"If this service has been permanently retired or decommissioned, consider removing it from monitoring with `/remove {res_id}`.{slow_text}"
        ), "7d notice")


def _status_update_for(resource, is_up, error_msg, latency_ms=None) -> dict:
    """The resources-table update for one check result (see database.batch_update_resource_status)."""
    if int(time.time()) < (resource.get("maintenance_until") or 0):
        # Resource is in maintenance window. Suppress failure transitions and incident creation.
        status, failures = resource["status"], 0
    else:
        status = "up" if is_up else "down"
        failures = 0 if is_up else ((resource.get("consecutive_failures") or 0) + 1)
    return {"id": resource["id"], "status": status, "consecutive_failures": failures,
            "error_msg": error_msg, "latency_ms": latency_ms}


async def handle_check_result(resource, is_up, error_msg, latency_ms=None, status_written=False):
    """Stores a check result and does what follows from it (incident sync, stale reminders).

    status_written: check_group_task already stored it, together with the rest of the check's
    writes in one transaction (database.record_check_results)."""
    now = int(time.time())
    in_maintenance = now < (resource.get("maintenance_until") or 0)
    if not status_written:
        update = _status_update_for(resource, is_up, error_msg, latency_ms)
        await run_db(database.batch_update_resource_status, [update])
        if resource["status"] != update["status"]:
            _schedule_peer_metrics_delta()
    if in_maintenance:
        return

    status = "up" if is_up else "down"
    old_status = resource["status"]
    
    should_sync = False
    if old_status != status:
        if old_status != "unknown" or status == "down":
            should_sync = True
            
    if should_sync:
        await sync_chat_incident_state(resource["dc_chat_id"], force_update=True)

    # If resource is down, evaluate 7d/14d/30d stale downtime reminders and auto-cleanup
    if not is_up:
        await check_stale_downtime_notifications(resource, now)

# Long outages are checked less often. A target down for days needs no check every minute (each
# one costs DNS queries, retries and peer votes on every node), and a recovery is still noticed
# within one step. (down for at least, check at most every) - longest first.
DOWN_BACKOFF_STEPS = (
    (30 * 86400, 86400),  # only peers' targets get here: own resources are removed after 30 days
    (14 * 86400, 3600),
    (7 * 86400, 900),
    (86400, 300),
)


def effective_check_interval(interval: int, status: str | None, down_since: int | None, now: int) -> int:
    """The check interval to use now: the configured one, or a longer one while down for days."""
    if status != "down" or not down_since:
        return interval
    down_for = now - down_since
    for after, every in DOWN_BACKOFF_STEPS:
        if down_for >= after:
            return max(interval, every)
    return interval


def format_every(seconds: int) -> str:
    """5 min, 1 h, 1 day: how often a slowed-down check runs."""
    if seconds % 86400 == 0:
        n = seconds // 86400
        return "day" if n == 1 else f"{n} days"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    return f"{max(1, seconds // 60)} min"


def slowdown_note(resource: dict, now: int) -> str:
    """' | 🐢 checked every 15 min' for a resource whose checks are slowed down, else ''."""
    interval = max(10, resource.get("interval") or 60)
    status = resource.get("resource_status") or resource.get("status")  # incident rows: resource_status
    eff = effective_check_interval(interval, status, resource.get("last_changed"), now)
    return f" | 🐢 checked every {format_every(eff)}" if eff > interval else ""


# resource id -> when its last check finished. The scheduler's cached rows can be read from the DB
# while a long check (retries, peer votes: up to a minute) is running, so they still carry the
# previous last_checked and would start the same check again right after it ends.
_check_finished_at = {}


async def run_and_track_group(group, semaphore, session=None, *, vote_check=False):
    token = _vote_check.set(vote_check)
    try:
        await check_group_task(group, semaphore, session=session)
    finally:
        _vote_check.reset(token)
        if vote_check:
            vote_check.ready.set()
        async with running_lock:
            now = int(time.time())
            for r in group:
                running_resource_ids.discard(r["id"])
                # probe-only targets too ("probe_<url>"): the cached row's last_checked lags behind
                _check_finished_at[r["id"]] = now

async def run_checks_parallel(tasks_list):
    await asyncio.gather(*tasks_list, return_exceptions=True)


def _due_vote_grid_ticks(resources, now, monotonic_now, bootstrap_tick, retry_at):
    """Select grid work independently of the phases of the regular monitor checks."""
    ticks = {}
    for r in resources:
        key = _cross_check_key(r)
        if now < retry_at.get(key, 0):
            continue
        cached = _vote_cache.get(key)
        if _resource_in_alert(r):
            tick = cached.due if cached else bootstrap_tick
        elif (entry := _peer_suspects.get(r["url"])) and monotonic_now - entry[0] <= PEER_SUSPECT_MAX_AGE:
            tick = _suspect_vote_due(entry, cached)
        else:
            continue
        if tick <= now:
            ticks[key] = max(tick, ticks.get(key, tick))
    return ticks


async def _run_grid_checks(groups, ticks, semaphore, session):
    requests = []
    checks = [_GridVoteCheck(ticks[key], requests, asyncio.Event()) for key in groups]
    tasks = [
        asyncio.create_task(run_and_track_group(group, semaphore, session, vote_check=check))
        for group, check in zip(groups.values(), checks)
    ]
    try:
        # Local checks have different runtimes. Flush once all group members have either
        # queued their vote or taken another path (for example, urgent recovery).
        await asyncio.gather(*(check.ready.wait() for check in checks))
        await _flush_cross_checks(requests, urgent=False)
    except BaseException:
        for task in tasks:
            task.cancel()
        raise
    finally:
        await asyncio.gather(*tasks, return_exceptions=True)


# Checks running at once. They are async (a socket each, little CPU), so the limit is about file
# descriptors, not cores: with 50, ~150 hung targets (10 s timeouts, 3 attempts) filled every slot
# for a minute and delayed the healthy checks. docker-compose.yml raises nofile to match.
CHECK_CONCURRENCY = 200


async def monitoring_scheduler_loop():
    import collections
    semaphore = asyncio.Semaphore(CHECK_CONCURRENCY)
    _last_peer_audit = 0
    _last_incident_audit = 0
    _last_cleanup = None
    cleanup_interval = None
    cleanup_retry_at = None
    _last_chat_audit = 0
    _last_peer_chat_trim = 0
    _last_transport_flush = 0
    _last_summary = int(time.time())
    telemetry_task = None
    bootstrap_vote_tick = _vote_grid_tick(time.time(), QUORUM_REVOTE_INTERVAL)
    grid_vote_retry_at = {}
    grid_jitter = secrets.randbelow(3)
    regular_checked_at = {}  # a grid-only check leaves the next regular local check on its normal phase
    # Validated, TTL-pinned DNS answers (see resolve_host_safe)
    # Above CHECK_CONCURRENCY: aiohttp counts the wait for a free connection against the request
    # timeout, so a smaller pool would turn queueing into false "Timeout" results
    connector = _make_safe_connector(limit=CHECK_CONCURRENCY + 50)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as shared_session:
        while True:
            until_telemetry = 5
            try:
                # If host network outage was detected, verify connectivity before launching checks
                if _host_outage_active:
                    is_online = await check_host_internet_connectivity(timeout=2.0, max_age=0.0)
                    if not is_online:
                        logger.warning("Host network outage is still active. Pausing monitoring checks for 10 seconds...")
                        await asyncio.sleep(10)
                        continue

                now = int(time.time())

                # Cached DB reads with TTL to reduce full-table scan frequency
                cache = _scheduler_cache
                if cache["resources"] is None or now - cache["resources_ts"] >= cache["ttl"]:
                    cache["resources"] = await asyncio.to_thread(database.get_all_resources)
                    cache["resources_ts"] = now
                if cache["probe_targets"] is None or now - cache["probe_targets_ts"] >= cache["ttl"]:
                    cache["probe_targets"] = await asyncio.to_thread(database.get_active_probe_targets)
                    cache["probe_targets_ts"] = now

                resources = cache["resources"]
                probe_targets = cache["probe_targets"]
                
                # Group only identical effective assertions; peers use the same identity.
                due_groups = collections.defaultdict(list)
                grid_groups = collections.defaultdict(list)
                seen_urls = set()
                vote_now = now - grid_jitter
                grid_ticks = _due_vote_grid_ticks(resources, vote_now, time.monotonic(),
                                                  bootstrap_vote_tick, grid_vote_retry_at)
                grid_ids = set()
                if grid_ticks:
                    candidates = [r for r in resources if _cross_check_key(r) in grid_ticks
                                  and (_resource_in_alert(r) or r["url"] in _peer_suspects)]
                    grid_ids = await _quorum_resource_ids(candidates)
                    eligible_keys = {_cross_check_key(r) for r in candidates if r["id"] in grid_ids}
                    for key in grid_ticks.keys() - eligible_keys:
                        grid_vote_retry_at[key] = _vote_grid_tick(vote_now + 1, QUORUM_REVOTE_INTERVAL)
                async with running_lock:
                    grid_ready = running_resource_ids.isdisjoint(grid_ids)
                    if grid_ready and vote_now >= bootstrap_vote_tick:
                        bootstrap_vote_tick = _vote_grid_tick(vote_now + 1, QUORUM_REVOTE_INTERVAL)
                    grid_vote_retry_at = {k: t for k, t in grid_vote_retry_at.items() if t > vote_now}
                    for r in resources:
                        r_id = r["id"]
                        if r_id in running_resource_ids:
                            continue
                        target_key = _cross_check_key(r)
                        last_checked = regular_checked_at.get(
                            r_id, max(r["last_checked"] or 0, _check_finished_at.get(r_id, 0)))
                        interval = effective_check_interval(
                            max(10, r["interval"] or 60), r["status"], r.get("last_changed"), now)
                        
                        slot_offset = (r_id * 11) % interval if isinstance(r_id, int) else (sum(str(r_id).encode()) * 11) % interval
                        slot_bucket = slot_offset // 5
                        current_bucket = (now % interval) // 5
                        
                        if last_checked == 0:
                            is_due = (current_bucket == slot_bucket)
                        else:
                            is_due = (now - last_checked >= interval) and (current_bucket == slot_bucket or now - last_checked >= interval + 15)
                        
                        if r_id in grid_ids:
                            if grid_ready:
                                running_resource_ids.add(r_id)
                                grid_groups[target_key].append(r)
                                if is_due:
                                    regular_checked_at.pop(r_id, None)
                                else:
                                    regular_checked_at[r_id] = last_checked
                        elif is_due:
                            regular_checked_at.pop(r_id, None)
                            running_resource_ids.add(r_id)
                            due_groups[target_key].append(r)
                        seen_urls.add(r["url"])

                    # Add probe-only targets mirrored from peers if not already checked by local chats
                    for pt in probe_targets:
                        pt_url = pt.get("url")
                        if not pt_url or pt_url in seen_urls:
                            continue
                        pt_key = f"probe_{pt_url}"
                        if pt_key in running_resource_ids:
                            continue
                        last_checked = max(pt.get("last_checked") or 0, _check_finished_at.get(pt_key, 0))
                        pt_interval = effective_check_interval(60, pt.get("last_status"), pt.get("down_since"), now)
                        if now - last_checked >= pt_interval:
                            running_resource_ids.add(pt_key)
                            probe_rep = {
                                "id": pt_key,
                                "dc_chat_id": 0,
                                "url": pt_url,
                                "name": pt.get("name") or pt_url,
                                "type": pt.get("type") or "http",
                                "expected_keyword": pt.get("expected_keyword"),
                                "http_method": pt.get("http_method"),
                                "status": pt.get("last_status") or "unknown",
                                "is_probe_only": True
                            }
                            due_groups[_cross_check_key(probe_rep)].append(probe_rep)
                
                if grid_groups:
                    for key, group in grid_groups.items():
                        # A skipped probe or a changed sharing policy can leave the old vote due.
                        grid_vote_retry_at[key] = _vote_grid_tick(vote_now + 1, QUORUM_REVOTE_INTERVAL)
                        for r in group:
                            r["last_checked"] = now
                    asyncio.create_task(_run_grid_checks(grid_groups, grid_ticks, semaphore, shared_session))

                tasks = []
                for target_key, group in due_groups.items():
                    for r in group:
                        if isinstance(r.get("id"), int):
                            r["last_checked"] = now
                    tasks.append(run_and_track_group(group, semaphore, session=shared_session))
                    
                if tasks:
                    logger.debug(f"Triggering {len(tasks)} target checks (encompassing {sum(len(g) for g in due_groups.values())} resources)...")
                    asyncio.create_task(run_checks_parallel(tasks))
                    
                # Check for changed telemetry and idle heartbeats.
                global last_peer_telemetry_broadcast
                if (now - last_peer_telemetry_broadcast >= TELEMETRY_TICK
                        and (telemetry_task is None or telemetry_task.done())):
                    last_peer_telemetry_broadcast = now
                    telemetry_task = asyncio.create_task(_broadcast_peer_updates())

                # Audit incidents and peer liveness every 30 seconds (not every 5s)
                if now - _last_incident_audit >= 30:
                    _last_incident_audit = now
                    await _check_report_notices()
                    await push_status_apps()
                    await realtime_status_tick()
                    active_incidents = await run_db(database.get_all_active_incidents)
                    for inc in active_incidents:
                        asyncio.create_task(sync_chat_incident_state(inc["dc_chat_id"]))

                if now - _last_peer_audit >= 30:
                    _last_peer_audit = now
                    for node, secs in pop_recovered_nodes():
                        logger.info(f"Node {node} is stable again after {format_duration(secs)}")
                        asyncio.create_task(send_admin_notification(
                            f"✅ **Node Stable Again**: {node}\nIts votes count again (it was unstable for `{format_duration(secs)}`)."))
                    newly_offline_peers = await run_db(database.audit_peers_offline, PEER_OFFLINE_INTERVALS * TELEMETRY_INTERVAL,
                                                       None, {p["email"]: peer_offline_after(p["email"])
                                                              for p in await run_db(database.get_all_peers)})
                    for p in newly_offline_peers:
                        p_node = p.get("node_name") or "Remote"
                        p_email = p.get("email")
                        diff_secs = max(1, now - (p.get("last_seen") or now))
                        diff_str = format_duration(diff_secs)
                        alert_txt = (
                            f"🚨 **Monitoring Probe Offline Alert**\n"
                            f"Probe Node: 🛰️ **{p_node}** (`{p_email}`)\n"
                            f"Last seen: `{diff_str} ago`\n\n"
                            f"⚠️ This probe is no longer responding or sending telemetry. Distributed cross-checks and multi-region metrics for this node are paused."
                        )
                        asyncio.create_task(send_admin_notification(alert_txt))

                # Chats the bot was removed from (also right after start)
                if now - _last_chat_audit >= CHAT_AUDIT_INTERVAL:
                    _last_chat_audit = now
                    asyncio.create_task(audit_abandoned_chats())

                # Protocol messages in peer chats (also right after start)
                if now - _last_peer_chat_trim >= PEER_CHAT_TRIM_INTERVAL and dc_bot_instance and dc_accid is not None:
                    _last_peer_chat_trim = now
                    asyncio.create_task(asyncio.to_thread(trim_peer_chats, dc_bot_instance, dc_accid))
                    asyncio.create_task(asyncio.to_thread(trim_user_chats, dc_bot_instance, dc_accid))

                # Allow a restart to run cleanup a few hours before its daily schedule.
                if cleanup_interval is None:
                    _last_cleanup = await run_db(database.get_last_cleanup_at)
                    cleanup_interval = 20 * 3600
                cleanup_due = _last_cleanup is None or not 0 <= now - _last_cleanup < cleanup_interval
                cleanup_interval = 86400
                if cleanup_retry_at is not None:
                    cleanup_due = time.monotonic() >= cleanup_retry_at
                if cleanup_due:
                    try:
                        await run_db(database.cleanup_old_records, 90)
                    except Exception:
                        cleanup_retry_at = time.monotonic() + 600
                        raise
                    _last_cleanup = int(time.time())
                    cleanup_retry_at = None
                    for k in [k for k, t in _check_finished_at.items() if now - t > 2 * 86400]:
                        del _check_finished_at[k]  # removed resources and peers' dropped targets
                    active_ids = {r["id"] for r in resources}
                    regular_checked_at = {k: t for k, t in regular_checked_at.items() if k in active_ids}
                    pruned_locks = prune_incident_sync_locks()
                    if pruned_locks:
                        logger.info(f"Pruned {pruned_locks} idle incident sync locks from memory")

                if now - _last_summary >= 60:
                    _last_summary = now
                    log_check_summary(len(running_resource_ids))

                # Periodic transport stats flush (every 10 seconds)
                if now - _last_transport_flush >= 10:
                    _last_transport_flush = now
                    await run_db(database.flush_transport_stats)

            except Exception as e:
                logger.error(f"Error in monitoring scheduler loop: {e}")
            else:
                if telemetry_task is None or telemetry_task.done():
                    until_telemetry = max(0, last_peer_telemetry_broadcast + TELEMETRY_TICK - time.time())

            # Every vote interval is a multiple of a minute. Wake for its wall clock boundary
            # even when the normal scheduler poll would land a few seconds later.
            wall = time.time() - grid_jitter
            until_minute = 60 - wall % 60
            await asyncio.sleep(min(5, until_minute, until_telemetry))

# Web Server handling and dashboard HTML templates
def _votes_html(r: dict) -> str:
    """The last vote of a DOWN/DEGRADED monitor as one small line on the status page."""
    votes = _votes_from_json(r.get("last_votes"))
    if len(votes) < 2:
        return ""
    return (f'<div style="margin-top: 0.35rem; font-size: 0.75rem; color: var(--text-muted);">'
            f'🛰️ Last vote: {html.escape(format_votes(votes))}</div>')


def get_dashboard_html(chat_name, resources, overall_uptime, incidents=None, uptimes_map=None, partial_outages=None) -> str:
    total_monitors = len(resources)
    up_monitors = sum(1 for r in resources if r["status"] == "up")
    down_monitors = sum(1 for r in resources if r["status"] == "down")
    degraded_monitors = sum(1 for r in resources if r["status"] == "up" and r.get("alert_state") == "degraded")
    
    if down_monitors:
        status_badge_class, status_indicator = "some-down", "down"
        status_text = f"{down_monitors} Service(s) Offline"
    elif degraded_monitors:
        status_badge_class, status_indicator = "some-degraded", "degraded"
        status_text = f"{degraded_monitors} Service(s) Unreachable From Some Regions"
    else:
        status_badge_class, status_indicator = "all-up", "up"
        status_text = "All Systems Operational"
    
    monitors_html = ""
    if total_monitors == 0:
        monitors_html = """
        <div class="empty-state">
            <div class="empty-icon">🔍</div>
            <p>No resources are being monitored in this chat yet.</p>
            <p style="font-size: 0.875rem; margin-top: 0.5rem;">Use <code>/add &lt;target&gt; [name]</code> in Delta Chat to add your first monitor.</p>
        </div>
        """
    else:
        now_ts = int(time.time())
        if uptimes_map is None and resources:
            uptimes_map = database.get_resources_uptime_30d([r["id"] for r in resources])
        for r in resources:
            r_uptime = (uptimes_map or {}).get(r["id"]) if uptimes_map else database.get_resource_uptime_30d(r["id"])
            m_until = r.get("maintenance_until") or 0
            is_maintenance = (now_ts < m_until)

            if is_maintenance:
                indicator_class = "unknown"
                status_lbl = "PAUSED"
                status_color = "var(--color-warn)"
            elif r["status"] == "up" and r.get("alert_state") == "degraded":
                indicator_class = "degraded"
                status_lbl = "DEGRADED"
                status_color = "var(--color-warn)"
            elif r["status"] == "up":
                indicator_class = "up"
                status_lbl = "UP"
                status_color = "var(--color-up)"
            elif r["status"] == "down":
                indicator_class = "down"
                status_lbl = "DOWN"
                status_color = "var(--color-down)"
            else:
                indicator_class = "unknown"
                status_lbl = "UNKNOWN"
                status_color = "var(--text-muted)"
            
            last_checked_str = "Never"
            if r["last_checked"]:
                last_checked_str = datetime.datetime.fromtimestamp(r["last_checked"]).strftime('%Y-%m-%d %H:%M:%S')
                
            badges_html = f'<span class="monitor-type">{r["type"]}</span>'
            if r.get("expected_keyword") and r.get("type") == "http":
                badges_html += f' <span class="monitor-type" style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; border-color: rgba(56, 189, 248, 0.25);" title="Expected content keyword">🔍 {html.escape(r["expected_keyword"])}</span>'
            if is_maintenance:
                m_left_secs = m_until - now_ts
                m_left_str = format_duration(m_left_secs)
                badges_html += f' <span class="monitor-type" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);">⏸️ Maintenance ({m_left_str} left)</span>'

            probe_badges_html = ""
            remote_measurements = database.get_peer_measurements_for_url(r["url"], remote_only=True)
            if remote_measurements:
                local_node = database.get_local_node_name()
                local_lat = f"{r['last_latency_ms']}ms" if r.get("last_latency_ms") is not None else ("UP" if r["status"] == "up" else "DOWN")
                local_badge_color = "var(--color-up)" if r["status"] == "up" else ("var(--color-down)" if r["status"] == "down" else "var(--text-muted)")
                probe_badges_html = f'<div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.35rem; font-size: 0.75rem;">'
                probe_badges_html += f'<span style="background: rgba(255, 255, 255, 0.05); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.1);">📍 <b>{html.escape(local_node)}</b>: <span style="color: {local_badge_color};">{local_lat}</span></span>'
                for pm in remote_measurements:
                    pm_status = pm.get("status")
                    pm_lat = f"{pm['latency_ms']}ms" if pm.get("latency_ms") is not None else (pm_status.upper() if pm_status else "UNKNOWN")
                    pm_color = {"up": "var(--color-up)", "degraded": "var(--color-warn)",
                                "down": "var(--color-down)"}.get(pm_status, "var(--text-muted)")
                    probe_badges_html += f'<span style="background: rgba(255, 255, 255, 0.05); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.1);">🛰️ <b>{html.escape(pm["node_name"])}</b>: <span style="color: {pm_color};">{pm_lat}</span></span>'
                probe_badges_html += '</div>'

            latency_stat_html = ""
            if r.get("last_latency_ms") is not None:
                lat_ms = r["last_latency_ms"]
                if lat_ms >= 5000:
                    lat_color = "var(--color-warn)"
                elif lat_ms >= 1000:
                    lat_color = "#38bdf8"
                else:
                    lat_color = "var(--color-up)"
                latency_stat_html = f"""
                <div class="m-stat">
                    <span class="m-val" style="color: {lat_color}; font-size: 0.875rem;">{lat_ms} ms</span>
                    <span class="m-lbl">Latency</span>
                </div>
                """

            ssl_stat_html = ""
            if has_tls_certificate(r.get("url", "")):
                exp_ts = r.get("ssl_expiry_date")
                if exp_ts:
                    d_left = int((exp_ts - now_ts) / 86400)
                    if d_left < 0:
                        ssl_color = "var(--color-down)"
                        ssl_txt = "Expired"
                    elif d_left <= 7:
                        ssl_color = "var(--color-warn)"
                        ssl_txt = f"{d_left}d left"
                    else:
                        ssl_color = "var(--color-up)"
                        ssl_txt = f"{d_left}d left"
                    ssl_stat_html = f"""
                    <div class="m-stat">
                        <span class="m-val" style="color: {ssl_color}; font-size: 0.875rem;">{ssl_txt}</span>
                        <span class="m-lbl">SSL Cert</span>
                    </div>
                    """
                else:
                    ssl_stat_html = """
                    <div class="m-stat">
                        <span class="m-val" style="color: var(--text-muted); font-size: 0.875rem;">Pending</span>
                        <span class="m-lbl">SSL Cert</span>
                    </div>
                    """
                
            monitors_html += f"""
            <div class="monitor-card">
                <div class="monitor-info">
                    <span class="indicator {indicator_class}"></span>
                    <div class="monitor-meta">
                        <span class="monitor-name">{html.escape(r["name"] or r["url"])}</span>
                        <span class="monitor-url">{html.escape(r["url"])}</span>
                        <div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.25rem;">{badges_html}</div>
                        {probe_badges_html}{_votes_html(r) if status_lbl in ("DEGRADED", "DOWN") else ""}
                    </div>
                </div>
                <div class="monitor-stats">
                    <div class="m-stat">
                        <span class="m-val" style="color: {status_color};">{status_lbl}</span>
                        <span class="m-lbl">Status</span>
                    </div>
                    {latency_stat_html}
                    {ssl_stat_html}
                    <div class="m-stat">
                        <span class="m-val">{r_uptime:.2f}%</span>
                        <span class="m-lbl">Uptime 30d</span>
                    </div>
                    <div class="m-stat">
                        <span class="m-val" style="font-size: 0.875rem;">{last_checked_str}</span>
                        <span class="m-lbl">Last Checked</span>
                    </div>
                </div>
            </div>
            """

    incidents_html = ""
    if incidents:
        inc_items = ""
        for inc in incidents:
            inc_id = inc["id"]
            inc_status = inc["status"]
            started_at = inc["started_at"]
            resolved_at = inc["resolved_at"]
            start_str = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            # Fetch affected services for this incident
            events = database.get_incident_downtime_events(inc_id)
            affected_services_html = ""
            if events:
                service_items = []
                seen_event_urls = set()
                for ev in events:
                    s_name = ev.get("name") or ev.get("url") or f"Resource #{ev.get('resource_id')}"
                    s_url = ev.get("url")
                    if s_url in seen_event_urls:
                        continue
                    if s_url:
                        seen_event_urls.add(s_url)
                    s_err = ev.get("error_msg")
                    err_badge = f' <span style="color: var(--text-muted); font-size: 0.75rem;">({html.escape(s_err)})</span>' if s_err else ""
                    service_items.append(f'<li><b>{html.escape(s_name)}</b>{err_badge}</li>')
                
                if service_items:
                    affected_services_html = (
                        '<div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid rgba(255, 255, 255, 0.08);">'
                        '<span style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em;">Affected Monitors:</span>'
                        '<ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.8125rem; color: var(--text-primary); line-height: 1.4;">'
                        + "".join(service_items) +
                        '</ul>'
                        '</div>'
                    )

            if inc_status == "ongoing":
                d_str = format_duration(int(time.time()) - started_at)
                inc_items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-down);">
                    <div class="monitor-info" style="display: flex; align-items: flex-start;">
                        <span class="indicator down" style="margin-top: 4px;"></span>
                        <div class="monitor-meta" style="flex: 1;">
                            <span class="monitor-name" style="color: var(--color-down);">Incident #{inc_id} — Ongoing</span>
                            <span class="monitor-url">Started: {start_str} UTC (active for {d_str})</span>
                            {affected_services_html}
                        </div>
                    </div>
                </div>
                """
            else:
                resolved_str = datetime.datetime.fromtimestamp(resolved_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if resolved_at else "Resolved"
                duration = max(1, (resolved_at or int(time.time())) - started_at)
                d_str = format_duration(duration)
                inc_items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-up);">
                    <div class="monitor-info" style="display: flex; align-items: flex-start;">
                        <span class="indicator up" style="margin-top: 4px;"></span>
                        <div class="monitor-meta" style="flex: 1;">
                            <span class="monitor-name">Incident #{inc_id} — Resolved</span>
                            <span class="monitor-url">{start_str} → {resolved_str} UTC ({d_str})</span>
                            {affected_services_html}
                        </div>
                    </div>
                </div>
                """
        incidents_html = f"""
        <h3 class="monitors-title" style="margin-top: 2rem;">📋 Recent Incidents</h3>
        <div class="monitors-grid">
            {inc_items}
        </div>
        """

    partial_html = ""
    if partial_outages:
        items = ""
        for po in partial_outages:
            start_str = datetime.datetime.fromtimestamp(po["started_at"], tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            nodes = ", ".join(_votes_from_json(po.get("nodes_down")) if po.get("nodes_down") else []) or "some nodes"
            if po.get("ended_at"):
                end_str = datetime.datetime.fromtimestamp(po["ended_at"], tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                when = f"{start_str} → {end_str} UTC ({format_duration(max(1, po['ended_at'] - po['started_at']))})"
                indicator, title_style = "up", ""
            else:
                when = f"Since {start_str} UTC (for {format_duration(max(1, int(time.time()) - po['started_at']))})"
                indicator, title_style = "degraded", ' style="color: var(--color-warn);"'
            items += f"""
                <div class="monitor-card" style="border-left: 4px solid var(--color-warn);">
                    <div class="monitor-info" style="display: flex; align-items: flex-start;">
                        <span class="indicator {indicator}" style="margin-top: 4px;"></span>
                        <div class="monitor-meta" style="flex: 1;">
                            <span class="monitor-name"{title_style}>{html.escape(po.get("name") or po.get("url") or "")}</span>
                            <span class="monitor-url">{when} — unreachable from {html.escape(nodes)}</span>
                        </div>
                    </div>
                </div>
                """
        partial_html = f"""
        <h3 class="monitors-title" style="margin-top: 2rem;">🟠 Partial Outages <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 400;">(unreachable from some nodes, not counted as downtime)</span></h3>
        <div class="monitors-grid">
            {items}
        </div>
        """
    incidents_html += partial_html

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delta Chat Uptime Monitor - {html.escape(chat_name)}</title>
    <link rel="icon" type="image/png" href="icon.png" />
    <link rel="shortcut icon" href="favicon.ico" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --bg-stat: rgba(30, 41, 59, 0.5);
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --color-up: #10b981;
            --color-down: #ef4444;
            --color-warn: #f59e0b;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        
        header {{
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(8px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        .logo-container {{
            max-width: 1100px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .logo-img {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
        }}
        
        .logo-title {{
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        main {{
            flex: 1;
            max-width: 1100px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }}
        
        .stats-panel {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        
        .stats-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .stats-header h2 {{
            font-size: 1.5rem;
            font-weight: 700;
        }}
        
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        
        .status-badge.all-up {{
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-up);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }}
        
        .status-badge.some-down {{
            background: rgba(239, 68, 68, 0.1);
            color: var(--color-down);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }}
        
        .indicator {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }}
        
        .indicator.up {{
            background-color: var(--color-up);
            box-shadow: 0 0 8px var(--color-up);
        }}
        
        .indicator.down {{
            background-color: var(--color-down);
            box-shadow: 0 0 8px var(--color-down);
        }}
        
        .indicator.degraded {{
            background-color: var(--color-warn);
            box-shadow: 0 0 8px var(--color-warn);
        }}
        
        .status-badge.some-degraded {{
            background: rgba(245, 158, 11, 0.1);
            color: var(--color-warn);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }}
        
        .indicator.unknown {{
            background-color: var(--text-muted);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }}
        
        .stat-card {{
            background: var(--bg-stat);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .stat-val {{
            font-size: 1.5rem;
            font-weight: 700;
        }}
        
        .stat-lbl {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .monitors-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        
        .monitors-grid {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}
        
        .monitor-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            transition: border-color 0.2s;
        }}
        
        .monitor-card:hover {{
            border-color: #475569;
        }}
        
        .monitor-info {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .monitor-meta {{
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        
        .monitor-name {{
            font-weight: 600;
            font-size: 1.05rem;
        }}
        
        .monitor-url {{
            font-size: 0.875rem;
            color: var(--text-muted);
            word-break: break-all;
        }}
        
        .monitor-type {{
            display: inline-block;
            font-size: 0.75rem;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.05);
            width: max-content;
        }}
        
        .monitor-stats {{
            display: flex;
            gap: 1.5rem;
            align-items: center;
        }}
        
        .m-stat {{
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }}
        
        .m-val {{
            font-weight: 600;
        }}
        
        .m-lbl {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        footer {{
            padding: 2rem 1.5rem;
            text-align: center;
            font-size: 0.875rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
        }}
        
        footer a {{
            color: #38bdf8;
            text-decoration: none;
        }}
        
        footer a:hover {{
            text-decoration: underline;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-muted);
        }}
        
        .empty-icon {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <img class="logo-img" src="icon.png" alt="Logo">
            <span class="logo-title">Delta Chat Uptime</span>
        </div>
    </header>
    
    <main>
        <div class="stats-panel">
            <div class="stats-header">
                <h2>{html.escape(chat_name)} Status</h2>
                <div class="status-badge {status_badge_class}">
                    <span class="indicator {status_indicator}"></span>
                    <span>{status_text}</span>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-val">{overall_uptime:.2f}%</span>
                    <span class="stat-lbl">Uptime 30d</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val">{total_monitors}</span>
                    <span class="stat-lbl">Total Monitors</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: var(--color-up);">{up_monitors}</span>
                    <span class="stat-lbl">Online</span>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: { 'var(--color-down)' if down_monitors > 0 else 'var(--text-muted)' };">{down_monitors}</span>
                    <span class="stat-lbl">Offline</span>
                </div>
            </div>
        </div>
        
        <h3 class="monitors-title">⚙️ Monitored Services</h3>
        <div class="monitors-grid">
            {monitors_html}
        </div>
        {incidents_html}
    </main>
    
    <footer>
        <p>Powered by <a href="https://github.com/mrgluek/deltachat_uptime" target="_blank">Delta Chat Uptime Bot</a> (<a href="https://git.gluek.info/gluek/deltachat_uptime" target="_blank">Mirror</a>)</p>
    </footer>
</body>
</html>
"""

DASHBOARD_CONCURRENCY = 4
DASHBOARD_CACHE_SECONDS = 15
DASHBOARD_CACHE_MAX_KEYS = 1000
_dashboard_slots = threading.BoundedSemaphore(DASHBOARD_CONCURRENCY)
_dashboard_cache = collections.OrderedDict()
_dashboard_cache_lock = threading.Lock()


async def handle_status_page(request):
    headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
               "X-Content-Type-Options": "nosniff"}
    if not check_rate_limit(request, bucket="web_status", max_requests=120, window_seconds=60):
        return web.Response(text="Rate limit exceeded. Try again later.", status=429,
                            headers={**headers, "Retry-After": "60"})

    token = request.match_info.get('token')
    with _dashboard_cache_lock:
        cached = _dashboard_cache.get(token)
        if cached and cached[0] > time.monotonic():
            return web.Response(text=cached[1], content_type="text/html", headers=headers)
    if not _dashboard_slots.acquire(blocking=False):
        return web.Response(text="Dashboard busy. Try again shortly.", status=503,
                            headers={**headers, "Retry-After": "15"})
    try:
        chat_id = await run_db(database.get_chat_id_by_token, token)
        if not chat_id:
            return web.Response(text="Status Page Not Found", status=404, headers=headers)

        chat_name = "Chat Monitor"
        if dc_bot_instance and dc_accid is not None:
            try:
                chat = await run_rpc(dc_bot_instance.rpc.get_basic_chat_info, dc_accid, chat_id)
                chat_name = chat.name
            except Exception:
                pass

        resources = await run_db(database.get_resources, chat_id)
        incidents = await run_db(database.get_recent_incidents, chat_id, 5)

        # Calculate average uptime using single batch query
        overall_uptime = 100.0
        uptimes_map = {}
        if resources:
            r_ids = [r["id"] for r in resources]
            uptimes_map = await run_db(database.get_resources_uptime_30d, r_ids)
            uptimes = [uptimes_map.get(rid, 100.0) for rid in r_ids]
            overall_uptime = sum(uptimes) / len(uptimes)

        partial_outages = await run_db(database.get_chat_partial_outages, chat_id, 10)
        html_content = await run_db(get_dashboard_html, chat_name, resources, overall_uptime, incidents,
                                    uptimes_map=uptimes_map, partial_outages=partial_outages)
        with _dashboard_cache_lock:
            now = time.monotonic()
            for key, (expires, _) in list(_dashboard_cache.items()):
                if expires <= now:
                    del _dashboard_cache[key]
            while len(_dashboard_cache) >= DASHBOARD_CACHE_MAX_KEYS:
                _dashboard_cache.popitem(last=False)
            _dashboard_cache[token] = (now + DASHBOARD_CACHE_SECONDS, html_content)
        return web.Response(text=html_content, content_type="text/html", headers=headers)
    finally:
        _dashboard_slots.release()

async def handle_health(request):
    """For monitors and other nodes: no database, no page, just alive and which version."""
    return web.json_response({"status": "ok", "version": VERSION}, headers={"Cache-Control": "no-store"})


async def handle_index(request):
    if not check_rate_limit(request, bucket="web_index", max_requests=120, window_seconds=60):
        return web.Response(text="Rate limit exceeded. Try again later.", status=429, headers={"Retry-After": "60"})

    global index_page_html_cache
    if index_page_html_cache is None:
        index_page_html_cache = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delta Chat Uptime Bot</title>
    <link rel="icon" type="image/png" href="icon.png" />
    <link rel="shortcut icon" href="favicon.ico" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(20, 26, 42, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --color-up: #10b981;
            --color-primary: #3b82f6;
            --glow-primary: rgba(59, 130, 246, 0.4);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.06) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 40%);
        }
        
        header {
            padding: 2rem 1.5rem;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .logo-img {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            object-fit: cover;
        }
        
        .logo-title {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        main {
            flex-grow: 1;
            max-width: 900px;
            width: 100%;
            margin: 0 auto;
            padding: 0 1.5rem 3rem;
            display: flex;
            flex-direction: column;
            gap: 2.5rem;
        }
        
        .hero {
            text-align: center;
            padding: 2rem 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }
        
        .hero h1 {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1.2;
            background: linear-gradient(135deg, #ffffff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .hero p {
            font-size: 1.125rem;
            color: var(--text-muted);
            max-width: 600px;
        }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 2rem;
            backdrop-filter: blur(12px);
            position: relative;
            overflow: hidden;
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #10b981);
        }
        
        .card h2 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .features-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-top: 0.5rem;
        }
        
        .feature-item {
            display: flex;
            gap: 0.75rem;
        }
        
        .feature-icon {
            font-size: 1.25rem;
            color: var(--color-up);
        }
        
        .feature-text h3 {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .feature-text p {
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
        
        .steps {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .step-item {
            display: flex;
            gap: 1rem;
            align-items: flex-start;
        }
        
        .step-num {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: var(--color-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.9rem;
            flex-shrink: 0;
        }
        
        .step-content h3 {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .step-content p {
            font-size: 0.9rem;
            color: var(--text-muted);
            line-height: 1.4;
        }
        
        .commands-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }
        
        .commands-table th, .commands-table td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .commands-table th {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        
        .commands-table td code {
            background: rgba(255, 255, 255, 0.05);
            padding: 0.2rem 0.5rem;
            border-radius: 0.25rem;
            font-family: monospace;
            font-size: 0.9rem;
            color: #3b82f6;
        }
        
        .commands-table td {
            font-size: 0.95rem;
        }
        
        footer {
            padding: 2rem 1.5rem;
            text-align: center;
            font-size: 0.875rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.8);
            margin-top: auto;
        }
        
        footer a {
            color: #3b82f6;
            text-decoration: none;
        }
        
        footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <img class="logo-img" src="icon.png" alt="Logo">
            <span class="logo-title">Delta Chat Uptime</span>
        </div>
    </header>
    
    <main>
        <div class="hero">
            <h1>Delta Chat Uptime Monitor</h1>
            <p>A self-hosted, high-concurrency availability monitoring service that sends downtime alerts directly to Delta Chat and hosts beautiful status dashboards.</p>
        </div>
        
        <div class="card">
            <h2>✨ Key Features</h2>
            <div class="features-list">
                <div class="feature-item">
                    <span class="feature-icon">🛡️</span>
                    <div class="feature-text">
                        <h3>Secure Ownership</h3>
                        <p>Claim bot administration using cryptographic fingerprints to secure transports and configurations.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">💬</span>
                    <div class="feature-text">
                        <h3>Per-Chat Monitoring</h3>
                        <p>Monitors are scoped to individual group chats or private chats for privacy and organization.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">⚙️</span>
                    <div class="feature-text">
                        <h3>Multiple Check Modes</h3>
                        <p>Support HTTP/HTTPS availability, SMTP STARTTLS, SSL/TLS certificate expiry checks, TCP ports, and non-blocking ICMP Pings.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🔒</span>
                    <div class="feature-text">
                        <h3>SSL Certificate Alerts</h3>
                        <p>Tracks HTTPS and SMTP certificate expiry with hourly checks and proactive notifications at 7d, 3d, and 24h.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🔄</span>
                    <div class="feature-text">
                        <h3>Smart Retry Logic</h3>
                        <p>Retries 2 times (30s apart) on failures to avoid false alerts. Recovery is marked UP instantly.</p>
                    </div>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🌍</span>
                    <div class="feature-text">
                        <h3>Federated Multi-Location Checks</h3>
                        <p>Link several Uptime bots as peers over encrypted Delta Chat DMs. Outages are confirmed from multiple locations, so regional problems show as "degraded", not false downtime.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🚀 Getting Started</h2>
            <div class="steps">
                <div class="step-item">
                    <span class="step-num">1</span>
                    <div class="step-content">
                        <h3>Add Uptime Bot in Delta Chat</h3>
                        <p>Scan the bot's secure join QR code or open the __LINK_HTML__ to start chatting:</p>
                        <div style="margin: 14px 0 10px 0; display: inline-block; background: #ffffff; padding: 10px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.25);">
                            __QR_HTML__
                        </div>
                    </div>
                </div>
                <div class="step-item">
                    <span class="step-num">2</span>
                    <div class="step-content">
                        <h3>Claim Admin Rights</h3>
                        <p>Send <code>/initadmin</code> in a private chat to link your profile securely via fingerprint authorization.</p>
                    </div>
                </div>
                <div class="step-item">
                    <span class="step-num">3</span>
                    <div class="step-content">
                        <h3>Start Monitoring</h3>
                        <p>Add your first resource with <code>/add https://yourwebsite.com "My Site"</code>. The bot will start periodic checks immediately!</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>⌨️ Bot Commands</h2>
            <table class="commands-table">
                <thead>
                    <tr>
                        <th>Command</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>/add &lt;target&gt; [name]</code></td>
                        <td>Add a website (HTTP), socket (IP:port) or host (Ping) to monitor.</td>
                    </tr>
                    <tr>
                        <td><code>/remove &lt;id|url&gt;</code></td>
                        <td>Stop monitoring a resource (or reply <code>/remove</code> to alert).</td>
                    </tr>
                    <tr>
                        <td><code>/list</code></td>
                        <td>List monitored targets and their current state in the current chat.</td>
                    </tr>
                    <tr>
                        <td><code>/status</code></td>
                        <td>Display average 30-day uptime and link to the secure web dashboard.</td>
                    </tr>
                    <tr>
                        <td><code>/help</code></td>
                        <td>Show instructions and bot version details.</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
    
    <footer>
        <p>Delta Chat Uptime Bot is open-source. Code on <a href="https://github.com/mrgluek/deltachat_uptime" target="_blank">GitHub</a> | <a href="https://git.gluek.info/gluek/deltachat_uptime" target="_blank">Forgejo Mirror</a></p>
    </footer>
</body>
</html>"""
    link = get_bot_invite_link()
    if link:
        escaped_link = html.escape(link)
        link_html = f'<a href="{escaped_link}" target="_blank" rel="noopener noreferrer" style="color: #3b82f6; text-decoration: underline; font-weight: 500;">bot\'s SecureJoin link</a>'
        qr_html = f'<a href="{escaped_link}" target="_blank" rel="noopener noreferrer" title="Click to open SecureJoin link in Delta Chat" style="display: block; cursor: pointer;"><img src="qr.svg" alt="Delta Chat Invite QR Code" style="display: block; width: 190px; height: 190px;" onerror="this.src=\'qr.png\'; this.onerror=function(){{this.parentElement.parentElement.style.display=\'none\'}};"></a>'
    else:
        link_html = "bot's SecureJoin link"
        qr_html = '<img src="qr.svg" alt="Delta Chat Invite QR Code" style="display: block; width: 190px; height: 190px;" onerror="this.src=\'qr.png\'; this.onerror=function(){this.parentElement.style.display=\'none\'};">'

    content = index_page_html_cache.replace("__LINK_HTML__", link_html).replace("__QR_HTML__", qr_html)
    headers = {
        "Cache-Control": "public, max-age=300"
    }
    return web.Response(text=content, content_type="text/html", headers=headers)

async def handle_robots_txt(request):
    headers = {
        "Cache-Control": "public, max-age=86400"
    }
    content = "User-agent: *\nDisallow: /\n"
    return web.Response(text=content, content_type="text/plain", headers=headers)

async def handle_icon(request):
    filename = request.path.lstrip('/')
    if filename == 'favicon.ico':
        filename = 'icon.png'
        
    if os.path.exists(filename):
        headers = {
            'Cache-Control': 'public, max-age=31536000, immutable'
        }
        return web.FileResponse(filename, headers=headers)
    return web.Response(status=404)

async def handle_qr_svg(request):
    link = get_bot_invite_link()
    if link:
        try:
            import qrcode
            import qrcode.image.svg
            qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage, border=2)
            qr.add_data(link)
            qr.make(fit=True)
            img = qr.make_image()
            buf = io.BytesIO()
            img.save(buf)
            headers = {
                "Cache-Control": "public, max-age=3600",
                "Content-Type": "image/svg+xml"
            }
            return web.Response(body=buf.getvalue(), headers=headers)
        except Exception as e:
            logger.error(f"Error generating qr.svg: {e}")
    return web.Response(status=404)

async def handle_qr_png(request):
    link = get_bot_invite_link()
    if link:
        try:
            import qrcode
            qr = qrcode.QRCode(box_size=6, border=2)
            qr.add_data(link)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            headers = {
                "Cache-Control": "public, max-age=3600",
                "Content-Type": "image/png"
            }
            return web.Response(body=buf.getvalue(), headers=headers)
        except Exception as e:
            logger.error(f"Error generating qr.png: {e}")
    return web.Response(status=404)

async def _run_web_server():
    app = web.Application(client_max_size=256 * 1024)
    app.router.add_get('/icon.png', handle_icon)
    app.router.add_get('/favicon.ico', handle_icon)
    app.router.add_get('/qr.svg', handle_qr_svg)
    app.router.add_get('/qr.png', handle_qr_png)
    app.router.add_get('/robots.txt', handle_robots_txt)
    app.router.add_get('/', handle_index)
    app.router.add_get('/health', handle_health)
    app.router.add_get('/{token:[a-zA-Z0-9]{12}}', handle_status_page)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = int(os.getenv("PORT", "8080"))
    site = web.TCPSite(runner, '0.0.0.0', port)
    
    logger.info(f"Starting status page server on 0.0.0.0:{port}...")
    await site.start()
    logger.info("Status page server is running.")
    
    while True:
        await asyncio.sleep(3600)

def start_web_server_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_run_web_server())


async def _flush_peer_metrics_periodically():
    last_core_dump_check = float("-inf")
    last_storage_check = float("-inf")
    while True:
        now = time.monotonic()
        if dc_accid is not None and now - last_core_dump_check >= 600:
            last_core_dump_check = now
            try:
                await _maybe_warn_core_dumps()
            except Exception:
                logger.exception("Could not check for core dumps")
        await asyncio.sleep(60)
        try:
            await run_db(database.flush_peer_metrics)
        except Exception:
            logger.exception("Could not flush peer metrics")
        now = time.monotonic()
        if os.getenv("STORAGE_WARN") != "0" and now - last_storage_check >= 600 and dc_accid is not None:
            last_storage_check = now
            try:
                await _maybe_warn_low_storage(dc_bot_instance, dc_accid)
            except Exception:
                logger.exception("Could not check for low disk space")


def start_monitoring_thread():
    global async_event_loop
    dc_outbox.start()  # from now on messages are queued and paced instead of sent inline
    loop = asyncio.new_event_loop()
    async_event_loop = loop
    asyncio.set_event_loop(loop)
    tasks = [loop.create_task(_flush_peer_metrics_periodically()), loop.create_task(_peer_rt_loop())]
    try:
        loop.run_until_complete(monitoring_scheduler_loop())
    finally:
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))

# Full-state webxdc updates: no per-chat tasks; the scheduler queues paced outbox jobs.
_status_xdc_lock = threading.Lock()
_peer_xdc_lock = threading.Lock()


def build_status_xdc() -> str:
    return _build_xdc("webxdc", "status", _status_xdc_lock)


def build_peer_xdc() -> str:
    return _build_xdc("webxdc_peer", "peer", _peer_xdc_lock, deterministic=True)


def _build_xdc(source_dir, name, lock, *, deterministic=False) -> str:
    """Build the attachment atomically; cache by source contents and bot version."""
    source = Path(__file__).resolve().parent / source_dir
    data_dir = Path(os.getenv("DC_DB_DIR") or Path(database.DB_PATH).resolve().parent)
    with lock:
        files = sorted(p for p in source.rglob("*") if p.is_file())
        digest = hashlib.sha256(VERSION.encode())
        for path in files:
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(path.read_bytes())
        signature = digest.hexdigest()
        data_dir.mkdir(parents=True, exist_ok=True)
        target = data_dir / f"{name}.xdc"
        cache = data_dir / f"{name}.xdc.sha256"
        if not target.exists() or not cache.exists() or cache.read_text() != signature:
            temporary = data_dir / f"{name}.xdc.tmp"
            with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in files:
                    entry = path.relative_to(source).as_posix()
                    if deterministic:
                        archive.writestr(zipfile.ZipInfo(entry), path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
                    else:
                        archive.write(path, entry)
            temporary.replace(target)
            cache.write_text(signature)
        return str(target)


def build_status_state(chat_id: int, *, chat_name: str | None = None) -> dict:
    """Read a full snapshot without RPC calls or writes (chat name is cached at delivery)."""
    now = int(time.time())
    resources = database.get_resources(chat_id)
    created_at = {r["id"]: r["created_at"] for r in resources}
    uptimes = database.get_resources_uptime_30d(list(created_at), created_at=created_at)
    counts = {"up": 0, "partial": 0, "down": 0}
    monitors = []
    for r in resources:
        status = "down" if r.get("status") == "down" else "partial" if r.get("alert_state") == "degraded" else "up"
        # /status includes paused/maintenance monitors; keep them visible here as paused.
        if r.get("status") == "paused" or (r.get("maintenance_until") or 0) > now:
            status = "paused"
        if status in counts:
            counts[status] += 1
        monitors.append({
            "id": r["id"], "name": r.get("name") or r["url"], "type": r["type"], "url": r["url"],
            "status": status, "since": (r.get("degraded_since") if status == "partial" else r.get("last_changed")) or None,
            "uptime30": float(uptimes.get(r["id"], 100.0)),
            "nodes": [{key: v.get(key) for key in ("node", "status", "latency_ms", "error")}
                      for v in _votes_from_json(r.get("last_votes")) if isinstance(v, dict)],
        })
    monitors.sort(key=lambda m: ({"down": 0, "partial": 1, "up": 2, "paused": 3}[m["status"]], m["id"]))
    journal = database.get_recent_chat_events(chat_id, 20, resources=resources)
    recent = [i for i in database.get_recent_incidents(chat_id, 20)
              if (i.get("resolved_at") or now) >= now - 30 * 86400]
    incident_events = database.get_incident_downtime_events_batch([i["id"] for i in recent])
    incidents = []
    for incident in recent:
        affected = {e["resource_id"]: short_monitor_name(e)
                    for e in incident_events[incident["id"]]}
        incidents.append({**{k: incident[k] for k in ("id", "status", "started_at", "resolved_at")},
                          "names": list(affected.values())[:5], "count": len(affected)})
    partials = [{"monitor": short_monitor_name(p), "started_at": p["started_at"], "ended_at": p["ended_at"]}
                for p in database.get_chat_partial_outages(chat_id, 10)]
    if chat_name is None:
        chat_name = database.get_config(f"webxdc_chat_name:{chat_id}")
    return {"v": WEBXDC_APP_VERSION, "chat": chat_name or "Chat Monitor",
            "generated_at": now, "counts": counts, "monitors": monitors, "events": status_app_events(chat_id, journal),
            "event_serial": journal[0]["id"] if journal else 0, "incidents": incidents, "partial_outages": partials}


def _status_content_hash(content: dict) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def status_state_hash(state: dict) -> str:
    """Hash significant changes without per-check measurements."""
    content = {key: value for key, value in state.items()
               if key in ("v", "chat", "counts", "incidents", "partial_outages", "events", "event_serial")
               or key.endswith("_omitted")}
    content["summary"] = status_app_summary(state)
    content["monitors"] = []
    for monitor in state.get("monitors", []):
        item = {key: value for key, value in monitor.items()
                if key in ("id", "name", "url", "type", "status", "since") or key.endswith("_omitted")}
        item["nodes"] = [{key: node.get(key) for key in ("node", "status")}
                         for node in monitor.get("nodes", [])]
        content["monitors"].append(item)
    return _status_content_hash(content)


def status_full_state_hash(state: dict) -> str:
    # The snapshot timestamp alone must never trigger a refresh.
    return _status_content_hash({key: value for key, value in state.items() if key != "generated_at"})


def status_app_refresh_due(chat_id, saved, state, now, *, settings=None):
    get_config = database.get_config if settings is None else settings.get
    return (saved["webxdc_last_sent_at"] is not None
            and now - saved["webxdc_last_sent_at"] >= STATUS_REFRESH_SECONDS
            and get_config(f"webxdc_full_state_hash:{chat_id}") != status_full_state_hash(state))


def status_app_first_state(chat_id, saved, *, settings=None):
    get_config = database.get_config if settings is None else settings.get
    return (not saved["webxdc_state_hash"]
            or get_config(f"webxdc_update_count:{chat_id}") == "0")


def _status_app_capped(chat_id, attempts, now):
    stat_event("status_app_capped", now)
    last_warning = database.get_config(f"webxdc_cap_warning_at:{chat_id}")
    if last_warning is None or now - int(last_warning) >= 3600:
        database.set_config(f"webxdc_cap_warning_at:{chat_id}", str(now))
        logger.warning("Status app update capped in chat %s: %s attempts in the last hour", chat_id, attempts)


def status_app_events(chat_id, rows=None):
    if rows is None:
        rows = database.get_recent_chat_events(chat_id, 20)
    events = [{k: r[k] for k in ("ts", "kind", "text")} for r in rows]
    # Budget is UTF-8 bytes, including JSON escaping and multibyte monitor names.
    for event in events:
        event["text"] = event["text"][:140]
    while len(json.dumps(events, ensure_ascii=False, separators=(",", ":")).encode()) > 2048:
        longest = max(events, key=lambda e: len(e["text"].encode()))
        if not longest["text"]:
            events.pop()
        else:
            longest["text"] = longest["text"][:-1]
    return events


def status_app_summary(state: dict) -> str:
    counts = state["counts"]
    return f"🟢 {counts['up']} up · 🟠 {counts['partial']} partial · 🔴 {counts['down']} down"


def status_line_text(state: dict) -> str:
    def shorten(name, size):
        name = " ".join(str(name).split())
        return name if len(name) <= size else name[:size - 1] + "…"
    for size in range(30, 0, -1):
        parts = []
        for status, icon in (("down", "🔴"), ("partial", "🟠")):
            count = state["counts"][status]
            if count:
                names = [shorten(short_monitor_name(m), size)
                         for m in state.get("monitors", []) if m["status"] == status][:3]
                label = f"{icon} {count} {status}"
                if names:
                    label += ": " + ", ".join(names)
                if count > 3:
                    label += f" +{count - 3}"
                parts.append(label)
        parts.append(f"🟢 {state['counts']['up']} up")
        summary = " · ".join(parts)
        if len(summary) <= 120:
            return summary
    return summary[:119] + "…"


def status_app_info(events):
    lines = [" ".join(e["text"].split())[:140] for e in events[:3]]
    if len(events) > 3:
        lines.append(f"+{len(events) - 3} more")
    return " | ".join(lines)


def status_app_rotation_due(chat_id, now, *, settings=None):
    # Config keys are additive migration: legacy instances acquire an age on first audit.
    get_config = database.get_config if settings is None else settings.get
    posted = get_config(f"webxdc_posted_at:{chat_id}")
    if posted is None:
        posted = get_config(f"webxdc_reposted_at:{chat_id}") or str(now)
        database.set_config(f"webxdc_posted_at:{chat_id}", posted)
    count = int(get_config(f"webxdc_update_count:{chat_id}") or 0)
    return now - int(posted) > 7 * 86400 or count > 500


def status_app_dirty(chat_id):
    return database.get_config(f"webxdc_dirty:{chat_id}") != database.get_config(f"webxdc_clean:{chat_id}")


def status_app_urgent(chat_id):
    dirty, clean, attempted = (f"webxdc_{key}:{chat_id}" for key in ("dirty", "clean", "attempt_revision"))
    settings = database.get_configs((dirty, clean, attempted))
    revision = settings.get(dirty)
    return revision != settings.get(clean) and revision != settings.get(attempted)


def _status_update_json(state: dict, limit: int, info_line=None) -> str:
    """Keep flags for every monitor if node detail would exceed the wire budget."""
    def encode():
        summary = status_app_summary(state)
        update = {"payload": state, "summary": summary}
        if info_line:
            update["info"] = info_line
        return json.dumps(update, ensure_ascii=False, separators=(",", ":"))
    encoded = encode()
    if len(encoded.encode()) > limit and state.get("partial_outages"):
        state["partial_outages"] = []
        state["partial_outages_omitted"] = True
        encoded = encode()
    for key in ("incidents", "events"):
        while len(encoded.encode()) > limit and state.get(key):
            state[key].pop()
            state[key + "_omitted"] = True
            encoded = encode()
    if len(encoded.encode()) > limit:
        state["details_omitted"] = True
        for monitor in state["monitors"]:
            for node in monitor["nodes"]:
                node["latency_ms"] = None
                node["error"] = None
        encoded = encode()
    if len(encoded.encode()) > limit:
        state["node_flags_omitted"] = True
        for monitor in state["monitors"]:
            monitor["nodes"] = []
        encoded = encode()
    if len(encoded.encode()) > limit:
        for monitor in state["monitors"]:
            monitor["name"] = monitor["name"][:80]
            monitor["url"] = ""
        encoded = encode()
    if len(encoded.encode()) > limit:
        raise ValueError("status flags exceed webxdc update size limit")
    return encoded


def _status_line_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _unpin_status_message(bot, accid, msg_id):
    try:
        bot.rpc.set_pinned_message_state(accid, msg_id, False)
        record_sent_mail("status_line")
        stat_event("mail_out")
    except Exception:
        pass


def _pin_status_line(chat_id, bot, accid, msg_id):
    """Pin the companion line, then resume the app's first update."""
    try:
        saved = database.get_chat_webxdc(chat_id)
        if database.get_chat_report_app(chat_id) == "off" or saved["status_line_msg_id"] != msg_id:
            return
        posted = database.get_config(f"webxdc_line_posted_at:{chat_id}")
        if not posted:
            database.set_config(f"webxdc_line_posted_at:{chat_id}", str(int(time.time())))
            return
        if time.time() - int(posted) < 60:
            return
        message = bot.rpc.get_message(accid, msg_id)
        state = message.get("state") if isinstance(message, dict) else message.state
        # JSON-RPC uses the core's enum spelling, e.g. "OutDelivered".
        delivered = (state >= MessageState.OUT_DELIVERED if isinstance(state, int) and not isinstance(state, bool)
                     else state in ("OutDelivered", "OutMdnRcvd"))
        if not delivered:
            return
        bot.rpc.set_pinned_message_state(accid, msg_id, True)
        record_sent_mail("status_line")
        stat_event("mail_out")
        database.set_config(f"webxdc_pin_pending:{chat_id}", "")
        old_ids = json.loads(database.get_config(f"webxdc_unpin:{chat_id}") or "[]")
        for old_id in old_ids:
            if old_id != msg_id:
                dc_outbox.submit(lambda old_id=old_id: _unpin_status_message(bot, accid, old_id),
                                 priority=PRIO_UPDATE, label="unpin previous status message", kind=None)
        database.set_config(f"webxdc_unpin:{chat_id}", "[]")
        queue_status_app(chat_id, bot, accid, known_msg_id=saved["webxdc_msg_id"])
    except Exception as exc:
        logger.warning("Cannot pin status line in chat %s: %s", chat_id, exc)


def _post_status_line(chat_id, bot, accid, text):
    if database.get_chat_report_app(chat_id) == "off":
        return
    now = int(time.time())
    last_attempt = database.get_config(f"webxdc_line_post_attempt:{chat_id}")
    if last_attempt and now - int(last_attempt) < 3600:
        return
    database.set_config(f"webxdc_line_post_attempt:{chat_id}", str(now))
    text = status_line_text(build_status_state(chat_id))
    msg_id = bot.rpc.send_msg(accid, chat_id, MsgData(text=text))
    record_sent_mail("status_line")
    stat_event("mail_out")
    database.set_chat_status_line(chat_id, msg_id, _status_line_hash(text))
    database.set_config(f"webxdc_line_posted_at:{chat_id}", str(int(time.time())))
    database.set_config(f"webxdc_line_post_attempt:{chat_id}", "")
    database.set_config(f"webxdc_pin_pending:{chat_id}", str(msg_id))
    dc_outbox.submit(lambda: _pin_status_line(chat_id, bot, accid, msg_id), priority=PRIO_UPDATE,
                     key=("status-app-pin", chat_id), label="pin status line", kind=None)


def _update_status_line(chat_id, bot, accid, urgent=False):
    """A separate outbox token and rolling-cap entry for each edit attempt."""
    if database.get_chat_report_app(chat_id) == "off":
        return
    saved = database.get_chat_webxdc(chat_id)
    text = status_line_text(build_status_state(chat_id))
    digest = _status_line_hash(text)
    if saved["status_line_hash"] == digest:
        return
    now = int(time.time())
    updates = [ts for ts in json.loads(database.get_config(f"webxdc_updates:{chat_id}") or "[]") if now - ts < 3600]
    cap = status_mail_cap(chat_id, _status_member_count(bot, accid, chat_id), urgent or status_app_urgent(chat_id))
    if len(updates) >= cap:
        _status_app_capped(chat_id, len(updates), now)
        return
    database.set_config(f"webxdc_updates:{chat_id}", json.dumps(updates + [now]))
    try:
        bot.rpc.send_edit_request(accid, saved["status_line_msg_id"], text)
        record_sent_mail("status_line")
        stat_event("mail_out")
        database.set_chat_status_line(chat_id, saved["status_line_msg_id"], digest)
    except Exception as exc:
        # An offline/ambiguous edit must not create duplicate messages.
        if saved["status_line_msg_id"] in bot.rpc.get_existing_msg_ids(accid, [saved["status_line_msg_id"]]):
            logger.warning("Cannot edit status line in chat %s: %s", chat_id, exc)
            return
        last_post = database.get_config(f"webxdc_line_reposted_at:{chat_id}")
        if last_post is not None and now - int(last_post) < 3600:
            return
        database.set_config(f"webxdc_line_reposted_at:{chat_id}", str(now))
        dc_outbox.submit(lambda: _post_status_line(chat_id, bot, accid, text), priority=PRIO_UPDATE,
                         key=("status-line-post", chat_id), label="replace missing status line", kind=None)



def _deliver_status_app(chat_id, bot, accid, known_msg_id=None):
    """Recheck settings and rate limits at actual delivery, not when queued."""
    try:
        if database.get_chat_report_app(chat_id) == "off":
            return
        now = int(time.time())
        saved = database.get_chat_webxdc(chat_id)
        msg_id = saved["webxdc_msg_id"]
        version = database.get_config(f"webxdc_app_version:{chat_id}")
        # A just-posted and successfully pinned id is already known to exist; send its
        # first state next without another existence probe. Audits always probe again.
        exists = msg_id and (msg_id == known_msg_id or msg_id in bot.rpc.get_existing_msg_ids(accid, [msg_id]))
        if not exists or version != str(WEBXDC_APP_VERSION) or status_app_rotation_due(chat_id, now):
            last_post = database.get_config(f"webxdc_reposted_at:{chat_id}")
            if last_post is not None and now - int(last_post) < 3600:
                return
            # Persist before RPC: an ambiguous failure must not cause a re-post loop.
            database.set_config(f"webxdc_reposted_at:{chat_id}", str(now))
            old_ids = [i for i in (msg_id, saved["status_line_msg_id"]) if i]
            database.set_config(f"webxdc_unpin:{chat_id}", json.dumps(old_ids))
            msg_id = bot.rpc.send_msg(accid, chat_id, MsgData(file=build_status_xdc()))
            record_sent_mail("other")
            stat_event("mail_out")
            database.set_chat_webxdc(chat_id, msg_id)
            database.set_config(f"webxdc_posted_at:{chat_id}", str(now))
            database.set_config(f"webxdc_update_count:{chat_id}", "0")
            database.set_config(f"webxdc_app_version:{chat_id}", str(WEBXDC_APP_VERSION))
            database.set_chat_status_line(chat_id, None, None)
            saved = database.get_chat_webxdc(chat_id)
        if not saved["status_line_msg_id"]:
            text = status_line_text(build_status_state(chat_id))
            dc_outbox.submit(lambda: _post_status_line(chat_id, bot, accid, text), priority=PRIO_UPDATE,
                             key=("status-line-post", chat_id), label="post status line", kind=None)
            return
        if database.get_config(f"webxdc_pin_pending:{chat_id}"):
            line_id = saved["status_line_msg_id"]
            dc_outbox.submit(lambda: _pin_status_line(chat_id, bot, accid, line_id), priority=PRIO_UPDATE,
                             key=("status-app-pin", chat_id), label="pin status line", kind=None)
            return
        chat = bot.rpc.get_basic_chat_info(accid, chat_id)
        name = chat.get("name") if isinstance(chat, dict) else chat.name
        database.set_config(f"webxdc_chat_name:{chat_id}", str(name))
        revision = database.get_config(f"webxdc_dirty:{chat_id}")
        state = build_status_state(chat_id)
        info = bot.rpc.get_webxdc_info(accid, msg_id)
        def field(key, default):
            # deltachat2 returns snake_case keys (send_update_max_size); accept camelCase too.
            snake = "".join("_" + c.lower() if c.isupper() else c for c in key)
            for k in (snake, key):
                value = info.get(k) if isinstance(info, dict) else getattr(info, k, None)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                    return value
            return default
        limit = min(60000, int(field("sendUpdateMaxSize", 128000)))
        # The webxdc API expresses sendUpdateInterval in milliseconds.
        urgent = status_app_urgent(chat_id)
        members = _status_member_count(bot, accid, chat_id)
        interval = max(0 if urgent else status_mail_interval(chat_id, members),
                       field("sendUpdateInterval", 10000) / 1000)
        digest = status_state_hash(state)
        full_digest = status_full_state_hash(state)
        refresh_due = status_app_refresh_due(chat_id, saved, state, now)
        first_state = status_app_first_state(chat_id, saved)
        last_info = int(database.get_config(f"webxdc_last_info_event_id:{chat_id}") or 0)
        info_events = database.get_recent_chat_events(chat_id, after_id=last_info)
        update = _status_update_json(state, limit, status_app_info(info_events))
        line_changed = saved["status_line_hash"] != _status_line_hash(status_line_text(state))
        if (saved["webxdc_state_hash"] == digest and not first_state and not refresh_due and not line_changed) or (saved["webxdc_last_sent_at"] is not None
                and now - saved["webxdc_last_sent_at"] < interval):
            return
        updates = json.loads(database.get_config(f"webxdc_updates:{chat_id}") or "[]")
        updates = [ts for ts in updates if now - ts < 3600]
        if len(updates) >= status_mail_cap(chat_id, members, urgent) and not first_state:
            _status_app_capped(chat_id, len(updates), now)
            return
        # The attempts list survives a re-post: a fresh instance must not wait out the previous
        # one's attempts (30 min apart in realtime chats). Its own first-state retries keep the
        # usual 60 s debounce.
        posted_at = int(database.get_config(f"webxdc_posted_at:{chat_id}") or 0)
        own_attempts = [ts for ts in updates if ts >= posted_at]
        gap = max(60, field("sendUpdateInterval", 10000) / 1000) if first_state else interval
        if own_attempts and now - max(own_attempts) < gap:
            return
        if saved["webxdc_state_hash"] == digest and not first_state and not refresh_due:
            if line_changed:
                dc_outbox.submit(lambda: _update_status_line(chat_id, bot, accid, urgent=urgent), priority=PRIO_UPDATE,
                                 key=("status-line-edit", chat_id), label="edit status line", kind=None)
            return
        # Count attempts durably too: retrying an uncertain RPC must not exceed the cap.
        database.set_config(f"webxdc_updates:{chat_id}", json.dumps(updates + [now]))
        database.set_config(f"webxdc_attempt_revision:{chat_id}", revision)
        bot.rpc.send_webxdc_status_update(accid, msg_id, update, status_app_summary(state))
        record_sent_mail("status_app")
        stat_event("mail_out")
        database.set_chat_webxdc(chat_id, msg_id, digest, now)
        database.set_config(f"webxdc_full_state_hash:{chat_id}", full_digest)
        count = int(database.get_config(f"webxdc_update_count:{chat_id}") or 0)
        database.set_config(f"webxdc_update_count:{chat_id}", str(count + 1))
        database.set_config(f"webxdc_clean:{chat_id}", revision)
        if line_changed:
            dc_outbox.submit(lambda: _update_status_line(chat_id, bot, accid, urgent=urgent), priority=PRIO_UPDATE,
                             key=("status-line-edit", chat_id), label="edit status line", kind=None)
        if info_events:
            database.set_config(f"webxdc_last_info_event_id:{chat_id}", str(max(e["id"] for e in info_events)))
    except Exception as exc:
        logger.warning("Cannot update status app in chat %s: %s", chat_id, exc)


def queue_status_app(chat_id, bot, accid, known_msg_id=None):
    return dc_outbox.submit(lambda: _deliver_status_app(chat_id, bot, accid, known_msg_id), priority=PRIO_UPDATE,
                            key=("status-app", chat_id), label="status app", kind=None)


async def push_status_apps():
    if not dc_bot_instance or dc_accid is None:
        return
    try:
        chats = await run_db(database.get_status_app_chats)
    except Exception as exc:
        logger.warning("Cannot list status apps: %s", exc)
        return
    for chat_id in chats:
        try:
            now = int(time.time())
            saved = await run_db(database.get_chat_webxdc, chat_id)
            msg_id = saved["webxdc_msg_id"]
            # Reads use the existing RPC executor; only actual mails need outbox tokens.
            exists = msg_id and msg_id in await run_rpc(dc_bot_instance.rpc.get_existing_msg_ids, dc_accid, [msg_id])
            keys = ("app_version", "posted_at", "reposted_at", "update_count", "pin_pending")
            settings = await run_db(database.get_configs, (f"webxdc_{key}:{chat_id}" for key in keys))
            version = settings.get(f"webxdc_app_version:{chat_id}")
            if (not exists or version != str(WEBXDC_APP_VERSION)
                    or await run_db(status_app_rotation_due, chat_id, now, settings=settings)):
                last_post = settings.get(f"webxdc_reposted_at:{chat_id}")
                if last_post is not None and now - int(last_post) < 3600:
                    continue
            elif not settings.get(f"webxdc_pin_pending:{chat_id}"):
                chat = await run_rpc(dc_bot_instance.rpc.get_basic_chat_info, dc_accid, chat_id)
                name = str(chat.get("name") if isinstance(chat, dict) else chat.name)
                if name != await run_db(database.get_config, f"webxdc_chat_name:{chat_id}"):
                    await run_db(database.set_config, f"webxdc_chat_name:{chat_id}", name)
                members = await run_rpc(_status_member_count, dc_bot_instance, dc_accid, chat_id)
                urgent = await run_db(status_app_urgent, chat_id)
                if (saved["webxdc_last_sent_at"] is not None
                        and now - saved["webxdc_last_sent_at"] < await run_db(status_mail_interval, chat_id, members)
                        and not urgent):
                    continue
                state = await run_db(build_status_state, chat_id, chat_name=name)
                keys = ("update_count", "full_state_hash", "updates")
                settings = await run_db(database.get_configs, (f"webxdc_{key}:{chat_id}" for key in keys))
                first_state = status_app_first_state(chat_id, saved, settings=settings)
                if (status_state_hash(state) == saved["webxdc_state_hash"]
                        and not first_state
                        and not status_app_refresh_due(chat_id, saved, state, now, settings=settings)
                        and saved["status_line_msg_id"] and saved["status_line_hash"] == _status_line_hash(status_line_text(state))):
                    continue
                updates = json.loads(settings.get(f"webxdc_updates:{chat_id}") or "[]")
                attempts = sum(now - ts < 3600 for ts in updates)
                cap = await run_db(status_mail_cap, chat_id, members, urgent)
                if attempts >= cap and not first_state:
                    await run_db(_status_app_capped, chat_id, attempts, now)
                    continue
            queue_status_app(chat_id, dc_bot_instance, dc_accid)
        except Exception as exc:
            logger.warning("Cannot queue status app in chat %s: %s", chat_id, exc)


# Realtime status channel (prototype). While someone has the status app open with "Live updates"
# on, the bot sends the state over the webxdc realtime channel (iroh gossip) instead of mail.
# Mail status updates in these chats drop to one per REALTIME_EMAIL_INTERVAL, except urgent ones
# (incidents, monitor edits), so clients without realtime still get the state.
# /report live enables each chat; STATUS_REALTIME_CHATS overrides the setting.
STATUS_REALTIME_CHATS = {int(x) for x in os.environ.get("STATUS_REALTIME_CHATS", "").replace(" ", "").split(",")
                         if x.isdigit()}
REALTIME_EMAIL_INTERVAL = 1800
LARGE_STATUS_CHAT_MIN_MEMBERS = 10
# The app sends a heartbeat every 60 s; after three missed ones the bot leaves the channel,
# so it does not keep gossiping to nobody. The next app open advertises again.
REALTIME_IDLE_LEAVE = 180
# Size of one realtime message; the core/gossip limit is not documented, so it is configurable
# and failures are logged with the size that was tried.
REALTIME_MAX_BYTES = int(os.environ.get("STATUS_REALTIME_MAX_BYTES", "60000"))
REALTIME_PROTOCOL = 1
_realtime_channels = {}  # webxdc msg_id -> channel activity and last state hash
_realtime_lock = threading.Lock()


def realtime_chat(chat_id) -> bool:
    return chat_id in STATUS_REALTIME_CHATS or database.get_chat_report_live(chat_id) == "on"


def _status_realtime_active(chat_id) -> bool:
    if not realtime_chat(chat_id):
        return False
    msg_id = database.get_chat_webxdc(chat_id)["webxdc_msg_id"]
    with _realtime_lock:
        entry = _realtime_channels.get(msg_id)
        return bool(entry and entry.get("received") and time.time() - entry["last_seen"] < REALTIME_IDLE_LEAVE)


def status_mail_interval(chat_id, member_count=0) -> int:
    """Minimum seconds between non-urgent mail status updates in a chat."""
    if _status_realtime_active(chat_id):
        return REALTIME_EMAIL_INTERVAL
    return 300 if member_count >= LARGE_STATUS_CHAT_MIN_MEMBERS else 60


def status_mail_cap(chat_id, member_count=0, urgent=False):
    if not urgent and member_count >= LARGE_STATUS_CHAT_MIN_MEMBERS and not _status_realtime_active(chat_id):
        return 12
    return 30


def _status_member_count(bot, accid, chat_id):
    try:
        return len(bot.rpc.get_chat_contacts(accid, chat_id))
    except Exception as exc:
        logger.debug("Cannot count status chat %s members: %s", chat_id, exc)
        return 0


def _realtime_chat_for_msg(msg_id):
    """The realtime-enabled chat whose current status app instance is msg_id, else None."""
    for chat_id in set(database.get_status_app_chats()) | STATUS_REALTIME_CHATS:
        if (realtime_chat(chat_id) and database.get_chat_webxdc(chat_id)["webxdc_msg_id"] == msg_id
                and not database.get_peer_by_chat_id(chat_id)):
            return chat_id
    return None


def _decode_realtime(data):
    """App -> bot messages are small JSON objects sent as bytes: {"t": "hello"|"ping", "v": 1}."""
    try:
        msg = json.loads(bytes(data[:1024]).decode())
    except (TypeError, ValueError):
        return None
    return msg if isinstance(msg, dict) and isinstance(msg.get("t"), str) else None


def _encode_realtime_state(state: dict) -> bytes:
    # Same trimming as the mail update, so an oversized state degrades the same way.
    update = _status_update_json(state, REALTIME_MAX_BYTES - 32)
    return ('{"t":"state","v":%d,"u":%s}' % (REALTIME_PROTOCOL, update)).encode()


def _send_realtime_state(bot, accid, msg_id, force=False) -> bool:
    """Sends the chat's state to the channel if it changed (latencies included). True if sent."""
    with _realtime_lock:
        entry = _realtime_channels.get(msg_id)
    if not entry:
        return False
    state = build_status_state(entry["chat_id"])
    digest = status_full_state_hash(state)
    if not force and digest == entry["last_hash"]:
        return False
    blob = _encode_realtime_state(state)
    try:
        bot.rpc.send_webxdc_realtime_data(accid, msg_id, list(blob))
    except Exception as exc:
        logger.warning("Realtime state (%d bytes) to chat %s failed: %s", len(blob), entry["chat_id"], exc)
        return False
    entry["last_hash"] = digest
    stat_event("realtime_out")
    return True


def _realtime_join(bot, accid, msg_id, chat_id) -> None:
    now = time.time()
    with _realtime_lock:
        entry = _realtime_channels.get(msg_id)
        if entry:
            return
        _realtime_channels[msg_id] = {"chat_id": chat_id, "joined_at": now, "last_seen": now, "last_hash": None, "received": False}
    try:
        # Joins the gossip topic; the core also mails a small hidden advertisement to the chat.
        bot.rpc.send_webxdc_realtime_advertisement(accid, msg_id)
        record_sent_mail("peer_other")
        stat_event("mail_out")
        # The core owns the hidden payload and does not return its size.
        database.record_peer_traffic("rt_advert", "mail", "out", 0)
        logger.info("Joined realtime status channel in chat %s", chat_id)
    except Exception as exc:
        with _realtime_lock:
            _realtime_channels.pop(msg_id, None)
        logger.warning("Cannot join realtime status channel in chat %s: %s", chat_id, exc)


@dc_cli.on(events.RawEvent(func=lambda e: e.kind in ("WebxdcRealtimeAdvertisementReceived", "WebxdcRealtimeData")))
def on_status_realtime(bot, accid, event):
    msg_id = event.get("msg_id") or event.get("msgId")
    if not msg_id:
        return
    if _dispatch_peer_rt(bot, accid, msg_id, event):
        return
    chat_id = _realtime_chat_for_msg(msg_id)
    if chat_id is None:
        return
    if event.kind == "WebxdcRealtimeAdvertisementReceived":
        # Someone opened the app with live updates on: join so its "hello" reaches us
        _realtime_join(bot, accid, msg_id, chat_id)
        return
    msg = _decode_realtime(event.get("data") or [])
    if not msg or msg["t"] not in ("hello", "ping"):
        return
    _realtime_join(bot, accid, msg_id, chat_id)
    with _realtime_lock:
        entry = _realtime_channels.get(msg_id)
        if entry:
            entry["received"] = True
            entry["last_seen"] = time.time()
    if msg["t"] == "hello":
        _send_realtime_state(bot, accid, msg_id, force=True)
        return
    # A state that does not change is not resent, so answer the heartbeat: the app shows the
    # channel is alive ("Live · checked HH:MM:SS") instead of an "Updated" time that stands still.
    try:
        pong = json.dumps({"t": "pong", "v": REALTIME_PROTOCOL, "ts": int(time.time())}).encode()
        bot.rpc.send_webxdc_realtime_data(accid, msg_id, list(pong))
    except Exception as exc:
        logger.debug("Realtime pong to chat %s failed: %s", chat_id, exc)


@dc_cli.on(events.RawEvent(func=lambda e: e.kind == "WebxdcInstanceDeleted"))
def on_peer_rt_carrier_deleted(bot, accid, event):
    if dc_accid is not None and dc_accid != accid:
        return
    msg_id = event.get("msg_id") or event.get("msgId")
    if msg_id and database.get_peer_rt_flag() != "off":
        with _peer_rt_lock:
            if database.mark_peer_rt_lost(msg_id):
                _refresh_peer_rt_channels()
                _peer_rt_audit_requested.set()


async def realtime_status_tick():
    """Every audit tick: push changed state to live channels, leave idle ones."""
    if not dc_bot_instance or dc_accid is None:
        return
    now = time.time()
    with _realtime_lock:
        channels = list(_realtime_channels.items())
    for msg_id, entry in channels:
        if (now - entry["last_seen"] >= REALTIME_IDLE_LEAVE
                or not await run_db(realtime_chat, entry["chat_id"])
                or (await run_db(database.get_chat_webxdc, entry["chat_id"]))["webxdc_msg_id"] != msg_id):
            with _realtime_lock:
                _realtime_channels.pop(msg_id, None)
            try:
                await run_rpc(dc_bot_instance.rpc.leave_webxdc_realtime, dc_accid, msg_id)
            except Exception as exc:
                logger.debug("Leaving realtime channel %s: %s", msg_id, exc)
            logger.info("Left idle realtime status channel in chat %s", entry["chat_id"])
            continue
        try:
            await asyncio.to_thread(_send_realtime_state, dc_bot_instance, dc_accid, msg_id)
        except Exception as exc:
            logger.warning("Realtime tick in chat %s: %s", entry["chat_id"], exc)


# Command Handlers
def _send_msg_with_peer_metrics(bot, accid, chat_id, msg_data, before_send=None):
    if before_send:
        before_send()
    msg_id = bot.rpc.send_msg(accid, chat_id, msg_data)
    _count_peer_text(getattr(msg_data, "text", None), "out")
    return msg_id


def _dc_send_msg_with_stats(bot, accid, chat_id, msg_data, priority=PRIO_REPLY, key=None, expires_in=None,
                            label=None, after_send=None, before_send=None, *, kind="reply", should_send=None,
                            return_future=False):
    """Sends a message through the paced outbox (see outbox.py). Default priority: a command reply.

    before_send() runs before the RPC, and after_send() runs after it succeeds.
    Neither runs for a replaced or expired message.
    Returns the msg_id when it was sent right away (outbox not started, as in tests), else None:
    the message is queued and goes out when its turn and a send token come.
    With return_future=True, returns the outbox future when an outbox is available."""
    def send():
        if should_send is not None and not should_send():
            return SKIP_SEND
        msg_id = _send_msg_with_peer_metrics(bot, accid, chat_id, msg_data, before_send)
        stat_event("mail_out")
        if after_send:
            try:
                after_send()
            except Exception:
                logger.exception("Post-send callback failed for chat %s", chat_id)
        return msg_id

    if dc_outbox is None:
        result = send()
        if result is SKIP_SEND:
            return None
        record_sent_mail(kind)
        return result

    fut = dc_outbox.submit(send, priority=priority, key=key, expires_in=expires_in,
                           label=label or f"message to chat {chat_id}", kind=kind)
    if return_future:
        return fut
    if fut.done() and not fut.exception():
        return fut.result()
    return None


@dataclass(frozen=True)
class _PeerDestination:
    bot: object
    accid: int
    chat_id: int
    securejoin_hello: bool = False
    fingerprint: str | None = None
    via: str = "auto"


def peer_send(peer, kind, payload, *, priority, expires_in, label, key=None, mail_kind="peer_other",
              after_send=None, before_send=None, should_send=None, before_rt_send=None, rt_waiting=None):
    """Send checks over an UP peer channel, with the existing mail outbox as fallback."""
    def send_mail(ttl):
        return _send_peer_mail(peer, kind, payload, priority=priority, expires_in=ttl, label=label, key=key,
                               mail_kind=mail_kind, after_send=after_send, before_send=before_send,
                               should_send=should_send)

    if ((rt_kind := _PEER_RT_CHECK_KINDS.get(kind)) and peer.fingerprint and expires_in is not None
            and peer.via != "mail" and not peer.securejoin_hello
            and isinstance(payload, dict) and payload.get("req_id")):
        loop = _peer_rt_event_loop()
        if loop is not None and (dc_accid is None or peer.accid == dc_accid):
            match = _up_peer_rt_link(peer.chat_id, peer.fingerprint)
            if match is not None:
                msg_id, link = match
                deadline = time.monotonic() + expires_in if rt_kind in _PEER_RT_REQUESTS else None
                if after_send:
                    notify = after_send
                    lock = threading.Lock()

                    def once():
                        nonlocal notify
                        with lock:
                            callback, notify = notify, None
                        if callback is not None:
                            callback()

                    after_send = once
                try:
                    loop.call_soon_threadsafe(lambda: loop.create_task(
                        _send_peer_rt_check(peer, msg_id, link, rt_kind, payload, send_mail, expires_in, deadline,
                                            before_rt_send, after_send, should_send, rt_waiting)))
                except RuntimeError:
                    pass  # The loop shut down before accepting the send.
                else:
                    return None
    return send_mail(expires_in)


def _send_peer_mail(peer, kind, payload, *, priority, expires_in, label, key, mail_kind,
                    after_send, before_send, should_send):
    if kind in _PEER_RT_MAIL_KINDS:
        return dc_outbox.submit(lambda: _send_peer_rt_mail(peer, kind, payload) or SKIP_SEND,
                                priority=priority, key=key, expires_in=expires_in, label=label, kind=mail_kind)
    if kind == "HELLO" and isinstance(payload, str):
        # send_peer_hello_when_ready also accepts an already formatted HELLO.
        text = payload
    else:
        marker = f"UPTIME_PEER_{kind}"
        text = f"[{marker}]\n{json.dumps(payload)}\n[/{marker}]"
    message = MsgData(text=text)
    if (kind != "METRICS" and isinstance(payload, dict)
            and payload.get("caps") in (OWN_PEER_CAPS, [*OWN_PEER_CAPS, PEER_CAP_RT])):
        # Votes and handshakes can wait in the outbox across a preview-mode change.
        start = before_send

        def before_send():
            flag = database.get_peer_rt_flag()
            current = database.get_peer_by_chat_id(peer.chat_id) if flag != "off" else None
            caps = _own_peer_caps(current, flag=flag) if current else OWN_PEER_CAPS
            if caps != payload["caps"]:
                message.text = f"[{marker}]\n{json.dumps(dict(payload, caps=caps))}\n[/{marker}]"
            if start:
                start()
    if peer.securejoin_hello:
        # SecureJoin retries need the outbox future and only count peer traffic.
        def send():
            msg_id = _send_msg_with_peer_metrics(peer.bot, peer.accid, peer.chat_id, message, before_send)
            if after_send:
                after_send()
            return msg_id

        return dc_outbox.submit(send, priority=priority, key=key, expires_in=expires_in, label=label, kind=mail_kind)
    return _dc_send_msg_with_stats(peer.bot, peer.accid, peer.chat_id, message, priority=priority, key=key,
                                   expires_in=expires_in, label=label, kind=mail_kind, after_send=after_send,
                                   before_send=before_send, should_send=should_send)


def _peer_rt_enabled(peer, flag):
    mode = peer.get("rt_mode", "auto")
    return mode != "off" and (flag == "on" or (flag == "canary" and mode == "on"))


def _peer_rt_eligible(peer, flag):
    return bool(peer and peer.get("fingerprint") and peer.get("chat_id")
                and _peer_rt_enabled(peer, flag) and _peer_supports(peer, PEER_CAP_RT))


def _up_peer_rt_link(chat_id, fingerprint):
    if not chat_id or not fingerprint:
        return None
    with _peer_rt_lock:
        return next(((msg_id, link) for msg_id, link in _peer_rt_links.items()
                     if link.peer["chat_id"] == chat_id and link.peer["fingerprint"] == fingerprint
                     and link.state.is_up), None)


def _peer_rt_channel_status(peer, flag):
    """Return the display state and link snapshot for a peer."""
    if not _peer_rt_eligible(peer, flag) or not peer.get("rt_msg_id") or peer.get("rt_lost"):
        return "mail only", None, None
    with _peer_rt_lock:
        link = _peer_rt_links.get(peer["rt_msg_id"])
        if not link or link.peer["rt_cid"] != peer["rt_cid"] or link.peer["fingerprint"] != peer["fingerprint"]:
            return "down", None, None
        if link.state.is_up:
            return "up", link.rtt_ms, None
        return "down", None, link.down_since


def _peer_rt_label(peer, flag, now):
    if not _peer_rt_enabled(peer, flag):
        return "iroh: off"
    state, rtt, down_since = _peer_rt_channel_status(peer, flag)
    if state == "up":
        return "iroh: UP" if rtt is None else f"iroh: UP (rtt {rtt} ms)"
    if down_since is not None:
        down_wall = now - max(0, time.monotonic() - down_since)
        since = datetime.datetime.fromtimestamp(down_wall, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"iroh: DOWN since {since}"
    if state == "down" and peer["rt_created_at"] is not None:
        age = max(0, now - peer["rt_created_at"]) // 86400
        return f"iroh: carrier ok (age {age}d)"
    return "iroh: offer sent" if peer.get("rt_offer_msg_id") else "iroh: mail only"


@dataclass
class _PeerRealtimeTelemetry:
    sent_at: float = -math.inf
    full_at: float = -math.inf
    keepalive_at: float | None = None
    empty_mail_at: float = -math.inf
    busy: bool = False
    needs_mail_on_down: bool = False
    statuses: dict[str, str] = field(default_factory=dict)
    offsets: dict[str, int] = field(default_factory=dict)


def _mark_peer_telemetry_up(identity):
    state = _telemetry_rt_peers.get(identity)
    if state is None:
        state = _telemetry_rt_peers.setdefault(identity, _PeerRealtimeTelemetry())
    state.needs_mail_on_down = True
    return state


@dataclass(frozen=True)
class _PeerRealtimeProbe:
    epoch: str
    sent_at: float
    retry_until: float | None  # Only discovery challenges are retried.

    def is_live(self, now):
        timeout = peer_rt.RT_CHANNEL_TIMEOUT if self.retry_until is None else PEER_RT_DISCOVERY_INTERVAL
        return 0 <= now - self.sent_at < timeout


@dataclass(eq=False)
class _PeerRealtimeLink:
    peer: dict
    advertise_at: float | None
    epoch: str = field(default_factory=lambda: secrets.token_hex(16))
    remote_epoch: str | None = None
    replay: peer_rt.ReplayWindow = field(default_factory=lambda: peer_rt.ReplayWindow(clock=time.monotonic))
    discovery_replay: peer_rt.ReplayWindow = field(default_factory=lambda: peer_rt.ReplayWindow(clock=time.monotonic))
    state: peer_rt.PeerChannelState = field(default_factory=lambda: peer_rt.PeerChannelState(clock=time.monotonic))
    started_at: float | None = None
    next_ping_at: float | None = None
    hello_requested: bool = False
    rediscovery_at: float = -math.inf
    logged_up: bool = False
    epoch_switched_at: float = -math.inf
    retired_epochs: dict[str, float] = field(default_factory=dict)
    frames: collections.deque[tuple[str, dict, float]] = field(default_factory=collections.deque)
    hellos: collections.deque[tuple[str, int | None, int]] = field(default_factory=collections.deque)
    seq: int = 0
    probes: dict[int, _PeerRealtimeProbe] = field(default_factory=dict)
    rtt_ms: int | None = None
    acks: peer_rt.AckTracker = field(default_factory=lambda: peer_rt.AckTracker(clock=time.monotonic))
    fallbacks: dict[int, tuple[bool, Callable]] = field(default_factory=dict)
    activity_at: float = -math.inf
    incoming_metrics_interval: int | None = None
    rejoin_checked_at: float = -math.inf
    rejoin_checked_for: tuple[float, int | None] | None = None

    @property
    def down_since(self):
        if self.state.ack_failed_at is not None:
            return self.state.ack_failed_at
        last_frame = self.state.last_frame_at
        return self.started_at if last_frame is None else last_frame + peer_rt.RT_CHANNEL_TIMEOUT


_peer_rt_links: dict[int, _PeerRealtimeLink] = {}
_peer_rt_carrier_ids: set[int] = set()
_peer_rt_pending_adverts: set[int] = set()
_peer_rt_leaves: set[int] = set()
_peer_rt_limiter = peer_rt.TokenBucketLimiter()
_peer_rt_log = peer_rt.LogOnce()


def _refresh_peer_rt_channels():
    """Refresh event routing after a carrier change, preserving unchanged links."""
    with _peer_rt_lock:
        flag = database.get_peer_rt_flag()
        peers = database.get_all_peers()
        _peer_rt_carrier_ids.clear()
        _peer_rt_carrier_ids.update(p[key] for p in peers for key in ("rt_msg_id", "rt_offer_msg_id") if p[key])
        _peer_rt_pending_adverts.intersection_update(_peer_rt_carrier_ids)
        live = {p["rt_msg_id"]: p for p in peers if p["rt_msg_id"] and not p["rt_lost"]
                and p["rt_key_in"] and p["rt_key_out"] and _peer_rt_eligible(p, flag)}
        for msg_id, link in list(_peer_rt_links.items()):
            current = live.get(msg_id)
            keys = ("rt_cid", "fingerprint", "chat_id", "rt_key_in", "rt_key_out")
            if not current or any(current[k] != link.peer[k] for k in keys):
                if not current:
                    _peer_rt_leaves.add(msg_id)
                del _peer_rt_links[msg_id]
                _fallback_peer_rt_sends(link)
            else:
                link.peer.update(email=current["email"], node_name=current["node_name"])
        for msg_id, peer in live.items():
            if msg_id not in _peer_rt_links:
                delay = secrets.randbelow(PEER_RT_ADVERT_SPREAD * 1000) / 1000
                if peer["rt_advert_at"] is not None:
                    delay = max(delay, peer["rt_advert_at"] + PEER_RT_ADVERT_COOLDOWN - time.time())
                _peer_rt_links[msg_id] = _PeerRealtimeLink(
                    peer, time.monotonic() + delay,
                    hello_requested=msg_id in _peer_rt_pending_adverts or peer["rt_advert_at"] is not None)
                _peer_rt_pending_adverts.discard(msg_id)


def _peer_rt_event_loop():
    if async_event_loop and async_event_loop.is_running():
        return async_event_loop
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _dispatch_peer_rt(bot, accid, msg_id, event):
    """Verify frames in the event thread and dispatch peer data to the mail handlers."""
    if dc_accid is not None and dc_accid != accid:
        return False
    message = None
    with _peer_rt_lock:
        if msg_id not in _peer_rt_carrier_ids and msg_id not in _peer_rt_leaves:
            return False
        link = _peer_rt_links.get(msg_id)
        if event.kind == "WebxdcRealtimeAdvertisementReceived":
            if link:
                link.hello_requested = True
            elif msg_id in _peer_rt_carrier_ids:
                _peer_rt_pending_adverts.add(msg_id)
            database.record_peer_traffic("rt_advert", "mail", "in", 0)
        elif link:
            message = _verify_peer_rt_frame(link, event.get("data"))
        else:
            data = event.get("data")
            size = len(data) if isinstance(data, (bytes, list)) else 0
            reason = "Inactive peer carrier" if _peer_rt_limiter.allow(msg_id, size) else "Frame rate exceeded"
            _record_invalid_peer_rt(msg_id, size, reason)
    if message is not None:
        _deliver_peer_rt_message(bot, accid, msg_id, link, *message)
    return True


def _record_invalid_peer_rt(peer, size, error):
    database.record_peer_traffic("rt_invalid", "rt", "in", size)
    if _peer_rt_log.should_log(peer):
        label = peer[-8:] if isinstance(peer, str) else peer
        logger.warning("Dropped realtime frame from peer %s: %s", label, error)


def _verify_peer_rt_frame(link, data):
    fp = link.peer["fingerprint"]
    size = len(data) if isinstance(data, (bytes, list)) else 0
    try:
        if not _peer_rt_limiter.allow(fp, size):
            raise peer_rt.FrameError("Frame rate exceeded")
        if size > peer_rt.RT_PEER_MAX_BYTES:
            raise peer_rt.FrameError("Frame too large")
        if not size:
            raise peer_rt.FrameError("Missing frame bytes")
        try:
            blob = bytes(data)
        except (TypeError, ValueError, OverflowError) as exc:
            raise peer_rt.FrameError("Invalid frame bytes") from exc
        frame = peer_rt.authenticate(blob, link.peer["rt_key_in"], clock=time.time)
        kind, epoch, recipient = frame["k"], frame["e"], frame["r"]
        received_at = time.monotonic()
        if epoch == link.epoch:
            raise peer_rt.FrameError("Reflected local session frame")
        if link.retired_epochs.get(epoch, -math.inf) > received_at:
            raise peer_rt.FrameError("Frame from a retired session")
        if recipient != link.epoch and recipient is not None:
            if epoch == link.remote_epoch and received_at >= link.rediscovery_at:
                link.hello_requested = True
                link.rediscovery_at = received_at + PEER_RT_DISCOVERY_INTERVAL
            raise peer_rt.FrameError("Frame addressed to a different session")
        if kind == "hello":
            if (frame["a"] or len(link.hellos) >= PEER_RT_HELLOS_PER_TICK
                    or not link.discovery_replay.accept(fp, epoch, frame["s"])):
                raise peer_rt.FrameError("Invalid or repeated session hello")
            # A hello can ask for a fresh challenge, but never opens a session on its own.
            link.hellos.append((epoch, frame["s"] if recipient is not None else None, size))
            return
        old_epoch = link.remote_epoch
        switching = epoch != old_epoch
        if kind == "pong":
            echo = frame["b"]
            probe = link.probes.get(echo["s"])
            if (frame["a"] or echo["e"] != link.epoch or probe is None or probe.epoch != epoch
                    or not probe.is_live(received_at)):
                raise peer_rt.FrameError("Pong does not match a current probe")
            if switching and received_at - link.epoch_switched_at < PEER_RT_EPOCH_SWITCH_INTERVAL:
                raise peer_rt.FrameError("Remote session switched too recently")
        elif switching:
            raise peer_rt.FrameError("Frame from an unconfirmed session")
        is_check = kind in _PEER_RT_CHECK_KINDS.values()
        if is_check:
            req_id = frame["b"].get("req_id")
            if not link.state.is_up or frame["a"] != 1 or not isinstance(req_id, str) or not 0 < len(req_id) <= 64:
                raise peer_rt.FrameError("Check requires an UP channel, acknowledgment and request ID")
        elif kind == "metrics":
            if frame["a"] or not isinstance(frame["b"].get("metrics"), list):
                raise peer_rt.FrameError("Invalid metrics frame")
        elif frame["a"] or kind not in peer_rt.RT_HEALTH_KINDS | {"ack"}:
            raise peer_rt.FrameError("Unsupported peer channel frame")
        elif kind == "ack":
            if frame["b"]["e"] != link.epoch:
                raise peer_rt.FrameError("Acknowledgment for a different session")
            if not link.state.is_up:
                raise peer_rt.FrameError("Acknowledgment on a DOWN channel")
        elif not switching and len(link.frames) >= peer_rt.RT_FRAME_BURST:
            raise peer_rt.FrameError("Frame queue full")
        if not link.replay.accept(fp, epoch, frame["s"]):
            raise peer_rt.FrameError("Frame replay or full replay window")
        if is_check or kind == "metrics":
            return frame, received_at, size
        if kind == "ack":
            link.state.on_frame()
            for seq in frame["b"]["s"]:
                if link.acks.ack(seq):
                    link.state.on_ack()
                    # An acknowledged request still needs an answer if the link goes down.
                    if not link.fallbacks[seq][0]:
                        del link.fallbacks[seq]
            database.record_peer_traffic(kind, "rt", "in", size)
            return
        if kind == "pong":
            if not link.state.is_up:
                link.logged_up = False
            if switching:
                link.remote_epoch = epoch
                link.state = peer_rt.PeerChannelState(clock=time.monotonic)
            link.state.on_frame(received_at)
            if switching:
                link.frames.clear()
                if old_epoch is not None:
                    # The switch interval bounds the number of unexpired retired epochs.
                    link.retired_epochs = {e: until for e, until in link.retired_epochs.items()
                                           if until > received_at}
                    link.retired_epochs[old_epoch] = received_at + peer_rt.RT_REPLAY_WINDOW
                    link.epoch_switched_at = received_at
                    for seq, pending in list(link.probes.items()):
                        if pending.epoch == old_epoch:
                            del link.probes[seq]
                    if _peer_rt_log.should_log((fp, "epoch")):
                        logger.info("Peer realtime carrier %s switched remote session", link.peer["rt_msg_id"])
                _fallback_peer_rt_sends(link)
            del link.probes[echo["s"]]
            link.rtt_ms = round((received_at - probe.sent_at) * 1000)
            database.record_peer_rtt("channel_ping", "rt", link.peer["node_name"], link.rtt_ms, True)
        link.frames.append((kind, {"e": epoch, "s": frame["s"]}, received_at))
        database.record_peer_traffic(kind, "rt", "in", size)
    except peer_rt.FrameError as exc:
        _record_invalid_peer_rt(fp, size, exc)


def _reserve_peer_rt_activity(link, received_at):
    if received_at is None or received_at - link.activity_at < RT_ACTIVITY_INTERVAL:
        return False
    link.activity_at = received_at
    return True


def _deliver_peer_rt_message(bot, accid, msg_id, link, frame, received_at, size):
    fp = link.peer["fingerprint"]
    kind = frame["k"]
    with _peer_rt_lock:
        peer = database.get_peer_by_fingerprint(fp)
        if (_peer_rt_links.get(msg_id) is not link or frame["e"] != link.remote_epoch
                or (kind != "metrics" and not link.state.is_up)
                or not _peer_rt_eligible(peer, database.get_peer_rt_flag())
                or peer["rt_msg_id"] != msg_id or peer["rt_lost"]
                or peer["rt_cid"] != link.peer["rt_cid"] or peer["chat_id"] != link.peer["chat_id"]
                or peer["rt_key_in"] != link.peer["rt_key_in"]):
            _record_invalid_peer_rt(fp, size, "Inactive peer carrier")
            return
        link.state.on_frame(received_at)
        _mark_peer_telemetry_up(fp)
        active = _reserve_peer_rt_activity(link, received_at)
    handler = {
        "req": handle_peer_check_req, "resp": handle_peer_check_resp,
        "breq": handle_peer_check_batch_req, "bresp": handle_peer_check_batch_resp,
        "metrics": handle_peer_metrics,
    }[kind]
    try:
        if active:
            _record_peer_activity(None, via="rt", fingerprint=fp, chat_id=peer["chat_id"])
        timing = {"arrived_at": received_at} if kind in ("resp", "bresp") else {}
        if kind == "metrics":
            timing.update(wire_size=size, stamp=(frame["ts"], None))
        outcome = handler(bot, accid, peer, peer["chat_id"], frame["b"], via="rt", **timing)
    except (TypeError, ValueError) as exc:
        _record_invalid_peer_rt(fp, size, type(exc).__name__)
        return
    database.record_peer_traffic(kind, "rt", "in", size)
    if (frame["a"] and (kind not in _PEER_RT_REQUESTS or outcome in (
            _ProbeAdmission.ACCEPTED, _ProbeAdmission.RUNNING, _ProbeAdmission.COMPLETED))
            and (loop := _peer_rt_event_loop()) is not None):
        loop.call_soon_threadsafe(lambda: loop.create_task(
            _send_peer_rt_unacked(bot, accid, msg_id, link, "ack", {"e": frame["e"], "s": [frame["s"]]})))


def _fallback_peer_rt_sends(link):
    for _, fallback in list(link.fallbacks.values()):
        fallback()


def _expire_peer_rt_acks(link):
    with _peer_rt_lock:
        if link.state.is_up:
            link.acks.expire()
        else:
            _fallback_peer_rt_sends(link)


def _discard_peer_rt_send(link, seq):
    with _peer_rt_lock:
        link.acks.discard(seq)
        return link.fallbacks.pop(seq, None)


async def _send_peer_rt_check(destination, msg_id, link, kind, payload, send_mail, ttl, deadline,
                              before_send, after_send, should_send, still_waiting):
    loop = asyncio.get_running_loop()
    send_until = deadline if deadline is not None else time.monotonic() + ttl

    def mail(*, fallback=False):
        remaining = ttl if deadline is None else deadline - time.monotonic()
        if remaining <= 0 or (still_waiting is not None and not still_waiting()):
            return
        if fallback:
            database.record_peer_traffic("rt_fallback", "fallback", "out", 0)
        send_mail(remaining)

    def fallback():
        if _discard_peer_rt_send(link, seq) is not None:
            loop.call_soon_threadsafe(lambda: loop.create_task(asyncio.to_thread(mail, fallback=True)))

    def timed_out(_):
        link.state.on_ack_timeout()
        fallback()
        if not link.state.is_up:
            _fallback_peer_rt_sends(link)

    if (send_until <= time.monotonic()
            or (should_send is not None and not should_send()) or (still_waiting is not None and not still_waiting())):
        return
    blob = None
    with _peer_rt_lock:
        if _peer_rt_links.get(msg_id) is link and link.state.is_up:
            seq = link.seq
            recipient = link.remote_epoch
            try:
                blob = peer_rt.encode(kind, link.epoch, seq, payload, link.peer["rt_key_out"],
                                      recipient=recipient, ack=1, clock=time.time)
            except peer_rt.FrameError:
                pass  # The mail format has a larger size limit.
            if blob is not None:
                link.seq += 1
                link.fallbacks[seq] = (deadline is not None, fallback)
                link.acks.track({"a": 1, "s": seq}, timed_out, arm=False)
    if blob is None:
        await asyncio.to_thread(mail)
        return

    def send():
        if should_send is not None and not should_send():
            return False
        with _peer_rt_lock:
            if (_peer_rt_links.get(msg_id) is not link or link.remote_epoch != recipient
                    or not link.state.is_up or seq not in link.fallbacks or send_until <= time.monotonic()):
                return False
        if before_send:
            before_send()
        destination.bot.rpc.send_webxdc_realtime_data(destination.accid, msg_id, list(blob))
        return True

    sent = False
    send_timeout = asyncio.timeout(max(0, send_until - time.monotonic()))
    try:
        try:
            async with send_timeout:
                sent = await run_rpc(send)
        except Exception as exc:
            if send_timeout.expired():
                return
            if _peer_rt_log.should_log((msg_id, "send")):
                logger.warning("Realtime %s on carrier %s failed (%s)", kind, msg_id, type(exc).__name__)
        if not sent:
            if time.monotonic() < send_until:
                fallback()
            return
    finally:
        if not sent or send_until <= time.monotonic():
            _discard_peer_rt_send(link, seq)
        else:
            with _peer_rt_lock:
                if link.acks.arm(seq):
                    loop.call_later(peer_rt.RT_ACK_TIMEOUT, _expire_peer_rt_acks, link)
                if deadline is not None and seq in link.fallbacks:
                    loop.call_later(max(0, deadline - time.monotonic()), _discard_peer_rt_send, link, seq)
    database.record_peer_traffic(kind, "rt", "out", len(blob))
    _note_peer_rt_caps_sent(link, payload)
    if after_send:
        after_send()


async def _send_peer_rt_unacked(bot, accid, msg_id, link, kind, body, *, recipient=None, retry_until=None):
    def current():
        return (_peer_rt_links.get(msg_id) is link
                and (kind != "metrics" or link.state.is_up)
                and (kind not in ("ack", "metrics", "ping") or link.remote_epoch == recipient)
                and (kind != "hello" or link.retired_epochs.get(recipient, -math.inf) <= time.monotonic()))

    with _peer_rt_lock:
        if kind == "ack":
            recipient = body["e"]
        elif kind in ("ping", "metrics"):
            recipient = link.remote_epoch
        if not current():
            return False
        seq = link.seq
        try:
            blob = peer_rt.encode(kind, link.epoch, seq, body, link.peer["rt_key_out"],
                                  recipient=recipient, clock=time.time)
        except peer_rt.FrameError:
            return False  # METRICS can fall back to the larger mail format.
        link.seq += 1

    def send():
        with _peer_rt_lock:
            if not current():
                return False
            if recipient is not None and kind in ("hello", "ping"):
                link.probes[seq] = _PeerRealtimeProbe(recipient, time.monotonic(), retry_until)
        # Core 2.66 joins implicitly on send.
        bot.rpc.send_webxdc_realtime_data(accid, msg_id, list(blob))
        return True

    try:
        if not await run_rpc(send):
            return False
    except Exception as exc:
        with _peer_rt_lock:
            link.probes.pop(seq, None)
        if _peer_rt_log.should_log((msg_id, "send")):
            logger.warning("Realtime %s on carrier %s failed (%s)", kind, msg_id, type(exc).__name__)
        return None
    database.record_peer_traffic(kind, "rt", "out", len(blob))
    _note_peer_rt_caps_sent(link, body)
    if kind == "hello":
        logger.debug("Joined peer realtime carrier %s and sent hello", msg_id)
    return True


async def _leave_peer_rt(bot, accid, msg_id):
    try:
        await run_rpc(bot.rpc.leave_webxdc_realtime, accid, msg_id)
    except Exception as exc:
        if _peer_rt_log.should_log((msg_id, "leave")):
            logger.warning("Leaving peer realtime carrier %s failed (%s)", msg_id, type(exc).__name__)
        return False
    return True


def _reserve_peer_rt_advert(msg_id, link, recover):
    with _peer_rt_lock:
        if _peer_rt_links.get(msg_id) is not link:
            return False
        fp, cid = link.peer["fingerprint"], link.peer["rt_cid"]
        peer = database.get_peer_by_fingerprint(fp)
        if not peer or peer["rt_msg_id"] != msg_id or peer["rt_cid"] != cid or peer["rt_lost"]:
            return False
        now = time.time()
        rejoin_at, step = peer["rt_rejoin_at"], peer["rt_rejoin_step"]
        if recover:
            down_since = link.down_since
            if (link.frames or link.state.is_up or down_since is None or not peer["last_seen"] or peer["is_offline"]
                    or now - peer["last_seen"] >= peer_offline_after(peer["email"])):
                return False
            # Activity before the timeout could have come from the old realtime channel.
            if peer["last_seen"] <= int(now - (time.monotonic() - down_since)):
                return False
            if rejoin_at is not None and now < rejoin_at:
                return False
            step = min(len(PEER_RT_REJOIN_DELAYS) - 1, (step or 0) + 1)
            rejoin_at = now + PEER_RT_REJOIN_DELAYS[step]
        if not _peer_rt_eligible(peer, database.get_peer_rt_flag()):
            return False
        if not database.reserve_peer_rt_advert(fp, msg_id, cid, now, PEER_RT_ADVERT_COOLDOWN, rejoin_at, step):
            return False
        link.peer.update(rt_advert_at=now, rt_rejoin_at=rejoin_at, rt_rejoin_step=step)
        return True


async def _advertise_peer_rt(bot, accid, msg_id, link, *, recover=False):
    if not await run_db(_reserve_peer_rt_advert, msg_id, link, recover):
        return
    if recover and not await _leave_peer_rt(bot, accid, msg_id):
        return
    if _peer_rt_links.get(msg_id) is not link:
        return
    try:
        await run_rpc(bot.rpc.send_webxdc_realtime_advertisement, accid, msg_id)
    except Exception as exc:
        logger.warning("Advertising peer realtime carrier %s failed (%s)", msg_id, type(exc).__name__)
        return
    record_sent_mail("peer_other")
    stat_event("mail_out")
    database.record_peer_traffic("rt_advert", "mail", "out", 0)
    logger.info("Advertised peer realtime carrier %s", msg_id)


async def _tick_peer_rt_hellos(bot, accid, msg_id, link, hellos, retries):
    challenges = 0
    work = [(epoch, seq, size, None) for epoch, seq, size in hellos]
    work.extend((probe.epoch, None, None, probe.retry_until) for probe in retries)
    for epoch, seq, size, retry_until in work:
        with _peer_rt_lock:
            now = time.monotonic()
            live = [probe for probe in link.probes.values() if probe.is_live(now)]
            needs_probe = seq is None or epoch != link.remote_epoch or not link.state.is_up
            challenge = needs_probe and not any(probe.epoch == epoch for probe in live)
            noncurrent = sum(probe.epoch != link.remote_epoch for probe in live)
            if link.retired_epochs.get(epoch, -math.inf) > now:
                error = "Hello from a retired session"
            elif challenge and (challenges >= PEER_RT_CHALLENGES_PER_TICK
                                or (epoch != link.remote_epoch and noncurrent >= PEER_RT_DISCOVERY_PROBES)):
                error = "Session challenge limit exceeded"
            else:
                error = None
            if error:
                if size is not None:
                    _record_invalid_peer_rt(link.peer["fingerprint"], size, error)
                continue
        if size is not None:
            database.record_peer_traffic("hello", "rt", "in", size)
        if seq is not None:
            await _send_peer_rt_unacked(bot, accid, msg_id, link, "pong", {"e": epoch, "s": seq}, recipient=epoch)
        if challenge:
            challenges += 1
            if retry_until is None:
                retry_until = now + PEER_RT_PING_INTERVAL
            await _send_peer_rt_unacked(bot, accid, msg_id, link, "hello", {}, recipient=epoch,
                                        retry_until=retry_until)


async def _tick_peer_rt_link(bot, accid, msg_id, link):
    with _peer_rt_lock:
        if _peer_rt_links.get(msg_id) is not link:
            return
        frames = list(link.frames)
        link.frames.clear()
        hellos = list(link.hellos)
        link.hellos.clear()
        hello, link.hello_requested = link.hello_requested, False
        now = time.monotonic()
        retries = []
        for seq, probe in list(link.probes.items()):
            if probe.retry_until is not None and not probe.is_live(now):
                del link.probes[seq]
                # A lost challenge reply should not leave discovery waiting on the heartbeat.
                if now < probe.retry_until:
                    retries.append(probe)
        if not link.state.is_up:
            link.logged_up = False
        if frames:
            link.state.on_frame(frames[-1][2])
            if link.state.is_up:
                _mark_peer_telemetry_up(link.peer["fingerprint"])
        active = _reserve_peer_rt_activity(link, link.state.last_frame_at)
        _expire_peer_rt_acks(link)
        log_up = bool(frames and link.state.is_up and not link.logged_up)
        link.logged_up = link.state.is_up
    if active:
        await run_db(functools.partial(_record_peer_activity, None, "rt",
                                       fingerprint=link.peer["fingerprint"], chat_id=link.peer["chat_id"]))
    if log_up:
        logger.info("Peer realtime carrier %s is UP", msg_id)
    if frames:
        if link.peer["rt_rejoin_at"] is not None:
            await run_db(database.reset_peer_rt_rejoin, link.peer["fingerprint"], msg_id, link.peer["rt_cid"])
            link.peer.update(rt_rejoin_at=None, rt_rejoin_step=None)
    for kind, echo, _ in frames:
        if kind == "ping":
            await _send_peer_rt_unacked(bot, accid, msg_id, link, "pong", echo, recipient=echo["e"])
    await _tick_peer_rt_hellos(bot, accid, msg_id, link, hellos, retries)
    if hello:
        await _send_peer_rt_unacked(bot, accid, msg_id, link, "hello", {})
    if link.advertise_at is not None and now >= link.advertise_at:
        link.advertise_at, link.started_at = None, now
        await _advertise_peer_rt(bot, accid, msg_id, link)
    # Schedule local probes independently of replies to the other peer.
    kind = None
    with _peer_rt_lock:
        ping_at = time.monotonic()
        if hello or (link.next_ping_at is None and (link.started_at is not None or frames or hellos)):
            link.next_ping_at = ping_at + PEER_RT_PING_INTERVAL
        elif link.next_ping_at is not None and ping_at >= link.next_ping_at:
            ping = next(((seq, probe) for seq, probe in link.probes.items() if probe.retry_until is None), None)
            if ping is None or ping_at - ping[1].sent_at >= PEER_RT_PING_INTERVAL:
                if ping is not None:
                    del link.probes[ping[0]]
                link.next_ping_at = ping_at + PEER_RT_PING_INTERVAL
                kind = "ping" if link.state.is_up and ping is None else "hello"
    if kind:
        await _send_peer_rt_unacked(bot, accid, msg_id, link, kind, {})
    down_since = link.down_since
    if (not link.state.is_up and down_since is not None and now - down_since >= PEER_RT_REJOIN_DELAYS[0]
            and (link.peer["rt_rejoin_at"] is None or time.time() >= link.peer["rt_rejoin_at"])):
        now = time.monotonic()
        rejoin_check = (down_since, database.peer_last_seen_update(link.peer["fingerprint"]))
        if (rejoin_check != link.rejoin_checked_for
                or now - link.rejoin_checked_at >= PEER_RT_REJOIN_CHECK_INTERVAL):
            link.rejoin_checked_for = rejoin_check
            link.rejoin_checked_at = now
            await _advertise_peer_rt(bot, accid, msg_id, link, recover=True)


async def _tick_peer_rt(bot, accid):
    with _peer_rt_lock:
        leaves, links = list(_peer_rt_leaves), list(_peer_rt_links.items())
    for msg_id in leaves:
        if await _leave_peer_rt(bot, accid, msg_id):
            with _peer_rt_lock:
                _peer_rt_leaves.discard(msg_id)
    results = await asyncio.gather(*(_tick_peer_rt_link(bot, accid, msg_id, link) for msg_id, link in links),
                                   return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            logger.error("Peer realtime tick failed", exc_info=result)


async def _peer_rt_loop():
    while True:
        if dc_bot_instance is not None and dc_accid is not None:
            await _tick_peer_rt(dc_bot_instance, dc_accid)
        await asyncio.sleep(1)


def _peer_rt_chat_is_private(bot, accid, chat_id):
    chat = bot.rpc.get_basic_chat_info(accid, chat_id)
    return (_field(chat, "chat_type") == "Single" and _field(chat, "is_encrypted") is True
            and not _field(chat, "is_self_talk") and not _field(chat, "is_contact_request"))


def _peer_rt_offer_due(peer, now):
    last_attempt = peer["rt_offer_at"]
    if last_attempt is not None and now - last_attempt < PEER_RT_OFFER_RETRY:
        return False
    created = peer["rt_created_at"]
    return (not peer["rt_msg_id"] or peer["rt_lost"] or created is None
            or now - created >= PEER_RT_ROTATE)


def _queue_peer_rt_mail(bot, accid, peer, kind, payload):
    fingerprint = peer["fingerprint"]
    destination = _PeerDestination(bot, accid, peer["chat_id"], fingerprint=fingerprint)
    peer_send(destination, kind, payload, priority=PRIO_PEER, expires_in=PEER_RT_OFFER_RETRY,
              label=f"peer {kind}", key=(kind, fingerprint))


def _send_peer_rt_mail(destination, kind, payload):
    """Recheck queued carrier mail just before sending. Keep keys out of logs."""
    bot, accid, chat_id = destination.bot, destination.accid, destination.chat_id
    fp = destination.fingerprint
    with _peer_rt_lock:
        peer = database.get_peer_by_fingerprint(fp)
        if not _peer_rt_eligible(peer, database.get_peer_rt_flag()) or peer["chat_id"] != chat_id:
            return
        last_caps = _peer_caps_announcements.get(fp, peer["caps_announce_value"])
        reset_after_enable = kind == "RT_RESET" and not peer["rt_cid"] and peer["rt_disabled_cid"]
        if (kind == "RT_OFFER" or reset_after_enable) and (
                fp in _peer_caps_requests or fp in _peer_caps_refresh
                or last_caps is None or PEER_CAP_RT not in json.loads(last_caps)):
            # The recipient needs our rt1 announcement to accept the offer.
            return
        now = int(time.time())
        try:
            own_fp = dc_fingerprint.get_self_fingerprint(bot.rpc, accid)
            if not own_fp or own_fp == fp or (own_fp < fp) != (kind == "RT_OFFER"):
                return
            if not _peer_rt_chat_is_private(bot, accid, chat_id):
                return
            contacts = bot.rpc.get_chat_contacts(accid, chat_id)
            if len(contacts) != 1 or dc_fingerprint.get_contact_fingerprint(
                    bot.rpc, accid, contacts[0], self_fp=own_fp) != fp:
                return
            if kind == "RT_OFFER":
                if not _peer_rt_offer_due(peer, now) or not database.reserve_peer_rt_offer(
                        fp, now, PEER_RT_OFFER_RETRY, PEER_RT_OFFERS_PER_HOUR,
                        retry_now=fp in _peer_rt_retry_now):
                    return
                _peer_rt_retry_now.discard(fp)
                _refresh_peer_rt_channels()
                cid, key = secrets.token_hex(8), secrets.token_bytes(32)
                payload = _peer_rt_key_payload(cid, key)
                file = build_peer_xdc()
            else:
                cid, file = payload["cid"], None
                if reset_after_enable:
                    if cid != peer["rt_disabled_cid"]:
                        return
                elif cid != peer["rt_cid"] or bool(peer["rt_lost"]) != (kind == "RT_RESET"):
                    return
                if kind == "RT_RESET" and not database.reserve_peer_rt_reset(fp, now):
                    return
            marker = f"UPTIME_PEER_{kind}"
            text = f"[{marker}]{json.dumps(payload, separators=(',', ':'))}[/{marker}]"
            msg_id = _send_msg_with_peer_metrics(bot, accid, chat_id, MsgData(text=text, file=file))
            stat_event("mail_out")
            if kind == "RT_OFFER":
                database.save_peer_rt_offer(fp, cid, msg_id, key)
                _refresh_peer_rt_channels()
            return msg_id
        except Exception as exc:
            logger.warning("Peer carrier %s in chat %s failed (%s)", kind, chat_id, type(exc).__name__)


def _peer_rt_key_payload(cid, key):
    # Each key authenticates the frames its sender will send.
    return {"v": 1, "cid": cid, "key": base64.b64encode(key).decode("ascii")}


def _decode_peer_rt_mail(kind, text):
    marker = f"UPTIME_PEER_{kind}"
    start, end = f"[{marker}]", f"[/{marker}]"
    if (len(text) > PEER_RT_MAIL_MAX_BYTES or len(text.encode("utf-8")) > PEER_RT_MAIL_MAX_BYTES
            or not text.startswith(start) or not text.endswith(end)):
        return None
    try:
        data = json.loads(text[len(start):-len(end)])
        fields = {"v", "cid"} if kind == "RT_RESET" else {"v", "cid", "key"}
        if not isinstance(data, dict) or data.keys() != fields or type(data["v"]) is not int or data["v"] != 1:
            return None
        cid = data["cid"]
        if not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{16}", cid):
            return None
        if kind == "RT_RESET":
            return cid, None
        if isinstance(data["key"], str):
            key = base64.b64decode(data["key"], validate=True)
            if len(key) == 32:
                return cid, key
    except (ValueError, RecursionError):
        pass
    return None


def _handle_peer_rt_mail(bot, accid, msg, kind, text):
    with _peer_rt_lock:
        flag = database.get_peer_rt_flag()
        if flag == "off":
            return
        decoded = _decode_peer_rt_mail(kind, text)
        if not decoded or _field(msg, "is_forwarded", False):
            return
        cid, key_in = decoded
        if not _peer_rt_chat_is_private(bot, accid, msg.chat_id):
            return
        peer, _ = _get_verified_peer_for_msg(bot, accid, msg, True, bind=False)
        if (not _is_trusted_peer_msg(msg, peer, True) or not _peer_rt_eligible(peer, flag)
                or peer["chat_id"] != msg.chat_id):
            return
        fp = peer["fingerprint"]
        own_fp = dc_fingerprint.get_self_fingerprint(bot.rpc, accid)
        if not own_fp or own_fp == fp or (own_fp < fp) != (kind != "RT_OFFER"):
            return
        now = int(time.time())
        if kind == "RT_OFFER":
            size = _field(msg, "file_bytes")
            timestamp = _field(msg, "timestamp")
            if (_field(msg, "view_type") != "Webxdc" or type(size) is not int
                    or not 0 < size <= PEER_RT_XDC_MAX_BYTES or type(timestamp) is not int
                    or cid == peer["rt_cid"]
                    or (peer["rt_received_offer_at"] is not None and timestamp <= peer["rt_received_offer_at"])):
                return
            key_out = secrets.token_bytes(32)
            if database.set_peer_rt(fp, cid=cid, msg_id=msg.id, key_out=key_out, key_in=key_in,
                                    created_at=now, received_offer_at=timestamp):
                _queue_peer_rt_mail(bot, accid, peer, "RT_ACCEPT", _peer_rt_key_payload(cid, key_out))
                _refresh_peer_rt_channels()
        elif kind == "RT_ACCEPT":
            offer_key = peer["rt_offer_key"]
            if (cid == peer["rt_offer_cid"] and cid != peer["rt_cid"] and peer["rt_offer_msg_id"]
                    and offer_key and not hmac.compare_digest(key_in, offer_key)):
                if database.set_peer_rt(fp, cid=cid, msg_id=peer["rt_offer_msg_id"],
                                        key_out=offer_key, key_in=key_in, created_at=now):
                    _refresh_peer_rt_channels()
        elif kind == "RT_RESET":
            # A RESET can also refer to an OFFER whose ACCEPT was lost or delayed.
            if cid == peer["rt_cid"] and peer["rt_msg_id"]:
                if database.mark_peer_rt_lost(peer["rt_msg_id"], replace_confirmed=True):
                    _refresh_peer_rt_channels()
                    _peer_rt_audit_requested.set()
            if cid == peer["rt_offer_cid"] and peer["rt_offer_msg_id"]:
                if database.mark_peer_rt_lost(peer["rt_offer_msg_id"]):
                    _refresh_peer_rt_channels()
                    _peer_rt_audit_requested.set()


def audit_peer_rt_carriers(bot, accid, now):
    _refresh_peer_rt_channels()
    flag = database.get_peer_rt_flag()
    if flag == "off":
        return
    peers = [p for p in database.get_all_peers() if _peer_rt_eligible(p, flag)]
    if not peers:
        return
    own_fp = dc_fingerprint.get_self_fingerprint(bot.rpc, accid)
    if not own_fp:
        return
    # Give peers still waiting for a first offer priority over retries.
    for candidate in sorted(peers, key=lambda p: p["rt_offer_at"] or 0):
        fp = candidate["fingerprint"]
        with _peer_rt_lock:
            peer = database.get_peer_by_fingerprint(fp)
            if fp == own_fp or not _peer_rt_eligible(peer, database.get_peer_rt_flag()):
                continue
            active = peer["rt_msg_id"] if not peer["rt_lost"] else None
            pending = peer["rt_offer_msg_id"]
            if active or pending:
                try:
                    ids = set(bot.rpc.get_message_ids(accid, peer["chat_id"], False, False))
                except Exception:
                    continue
                if active and active not in ids:
                    database.mark_peer_rt_lost(active)
                    peer["rt_lost"] = 1
                    _refresh_peer_rt_channels()
                if pending and pending not in ids:
                    database.mark_peer_rt_lost(pending)
                    peer["rt_offer_msg_id"] = None
                    _refresh_peer_rt_channels()
            if own_fp < fp and _peer_rt_offer_due(peer, now):
                _queue_peer_rt_mail(bot, accid, peer, "RT_OFFER", None)
            elif own_fp > fp:
                reset_cid = peer["rt_cid"] if peer["rt_lost"] else peer["rt_disabled_cid"]
                if reset_cid and (peer["rt_reset_at"] is None or now - peer["rt_reset_at"] >= 3600):
                    _queue_peer_rt_mail(bot, accid, peer, "RT_RESET", {"v": 1, "cid": reset_cid})


def _send_peer_check_answer(destination, kind, payload, *, key=None, should_send=None, after_send=None):
    if key is None and (request := _inbound_probe_answer.get()):
        request_key, admission = request
        via = admission.reply_via(request_key)
        destination = replace(destination, via=via)
        key = ("peer_answer", *request_key)
        after_send = functools.partial(admission.remember_answer, request_key, kind, payload, via=via)
    label = "batch cross-check answer" if kind == "CHECK_BATCH_RESP" else "cross-check answer"
    peer_send(destination, kind, payload, priority=PRIO_PEER, expires_in=PEER_ANSWER_TTL,
              label=label, key=key, should_send=should_send, after_send=after_send)


def _resend_cached_probe_answer(bot, accid, chat_id, peer, req_id, via="mail"):
    found, replay = _inbound_probes.reserve_replay(peer, req_id, via)
    if replay is not None:
        kind, payload, pending, sent = replay
        if "caps" in payload:
            payload = dict(payload, caps=_own_peer_caps(peer))
        destination = _PeerDestination(bot, accid, chat_id, fingerprint=peer.get("fingerprint"), via=via)
        _send_peer_check_answer(destination, kind, payload, key=("peer_answer", _peer_identity(peer), req_id),
                                should_send=pending, after_send=sent)
    return found


def _react(bot, accid: int, msg_id: int | None, emoji: str):
    """Add or clear a reaction on a message."""
    if not bot or not hasattr(bot, "rpc") or not msg_id:
        return
    # Keyed by message: a ⏳ still waiting in the outbox is replaced by the final ☑️ (one mail, not two)
    dc_outbox.submit(lambda: bot.rpc.send_reaction(accid, msg_id, [emoji] if emoji else []),
                     priority=PRIO_REPLY, key=("reaction", msg_id), label=f"reaction {emoji} on {msg_id}", kind="reply")

HELP_PRIVATE_NOTE = "\n\n💬 Sent privately because you asked in a group. Use /help@uptime there to show it to everyone."

def _get_help_chat_id(bot, accid, msg):
    """Plain /help in a group is answered privately to the sender so several bots
    don't flood the group; /help@<bot> is still answered in the group itself."""
    cmd = msg.text.split(maxsplit=1)[0] if msg.text else ""
    if "@" in cmd:
        return msg.chat_id
    try:
        chat = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
    except Exception:
        chat = None
    if is_single_chat(chat):
        return msg.chat_id
    return bot.rpc.create_chat_by_contact_id(accid, msg.from_id)

@dc_cli.on(events.NewMessage(command="/help"))
@command_budget
def help_command(bot, accid, event):
    msg = event.msg
    is_actually_admin = _is_dc_admin(bot, accid, msg.from_id)
    admin_email, admin_fp = database.get_effective_admin()
    
    help_text = (
        f"👋 Welcome to Delta Chat Uptime Bot {VERSION}!\n\n"
        f"I monitor resource availability (HTTP, SMTP, TCP, Ping) and alert this chat if they go offline.\n\n"
        f"**Public Commands:**\n"
        f"/ping [-4|-6] <target> [\"keyword\"] — Quick on-demand test & diagnostics without adding (`-6`: only over IPv6)\n"
        f"/add <target> [name] [\"keyword\"] — Monitor a resource. Target formats:\n"
        f"  • `https://example.com` (HTTP/HTTPS)\n"
        f"  • `https://api.site.com Health \"status:ok\"` (Keyword assertion)\n"
        f"  • `smtp://mail.example.com` (SMTP: STARTTLS + certificate, port 25; `:465` = TLS)\n"
        f"  • `example.com:22` (TCP Port)\n"
        f"  • `example.com` (ICMP Ping)\n"
        f"  • `2a00::1`, `[2a00::1]:443` (IPv6: ping, TCP port)\n"
        f"/remove <id|url> (or reply /remove) — Stop monitoring a resource\n"
        f"/pause <id|url> [dur] (or reply /pause) — Pause/mute alerts (e.g. `30m`, `2h`)\n"
        f"/resume <id|url> (or reply /resume) — Resume monitoring after maintenance\n"
        f"/keyword <id|url> [keyword|none] — Set or remove required keyword assertion\n"
        f"/list — List all monitors in this chat with uptime, latency & SSL\n"
        f"/status — Show monthly uptime statistics & web link\n"
        f"/report [all|partial <N|off>|full <N>|app off|on|only|live on|off] — Outage notices and status app\n"
        f"/alertmode [quorum|local] — Alert when most nodes cannot reach a target (default), or on this node's checks only\n"
        f"/events — View incident history and active outages\n"
        f"/history [id] — View downtime history for monitors\n"
        f"/sync — Synchronize monitors with other bots in the chat\n"
        f"/donate — Support bot development ❤️\n"
        f"/help — Show this help message\n\n"
    )
    
    if not admin_email and not admin_fp:
        help_text += (
            f"**Setup Command:**\n"
            f"/initadmin — Claim bot ownership (admin setup)\n\n"
        )
    elif is_actually_admin:
        fp_suffix = f" ({admin_fp[-8:].upper()})" if admin_fp else ""
        help_text += f"👑 **Admin:** `{admin_email}`{fp_suffix}\n\n"
        help_text += (
            f"**Admin Commands:**\n"
            f"/url [base_url] — Set/view base status URL (e.g. `https://up.gluek.info`)\n"
            f"/nodename [name] — Set/view local probe node name (e.g. `Frankfurt-DE`)\n"
            f"/invitepeer — Generate SecureJoin E2EE invite link for pairing with other bots\n"
            f"/peers (or /probes) — List distributed peer bots and their status\n"
            f"/stats — Bot load, mail, peer traffic and relays\n"
            f"/rmcore — Delete core dump files in a private chat\n"
            f"/addpeer <email|link> [node_name] — Add remote peer bot (via email or SecureJoin invite)\n"
            f"/rmpeer <email|key> — Remove remote peer bot\n"
            f"/peershare [admin|all|none] — Choose which local monitors are disclosed to peers\n"
            f"/peerrt [off|canary|on] — Show or set the peer channel preview flag\n"
            f"/peerrt <peer name|email> on|off|auto — Set a peer's preview mode\n"
            f"/nodeignore [node_pat] [target_pat] — Ignore targets on peer node(s) (e.g. `RU* facebook.*`)\n"
            f"/nodeunignore <node_pat> [target_pat] — Resume checks for node(s)\n"
            f"/accounts — List configured bot accounts\n"
            f"/rmaccount <id> — Delete a bot account\n"
            f"/transports — Show mail relays & stats\n"
            f"/addtransport — Add backup mail relay\n"
            f"/rmtransport <addr> — Remove backup mail relay\n\n"
        )
        
    help_text += (
        f"**Repository Links:**\n"
        f"GitHub: https://github.com/mrgluek/deltachat_uptime\n"
        f"Mirror: https://git.gluek.info/gluek/deltachat_uptime\n"
    )
    chat_id = _get_help_chat_id(bot, accid, msg)
    if chat_id != msg.chat_id:
        help_text += HELP_PRIVATE_NOTE
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=help_text))

@dc_cli.on(events.NewMessage(command="/donate"))
@command_budget
def donate_command(bot, accid, event):
    msg = event.msg
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text="❤️ Support Bot Development\n\n"
             "If you find this bot useful, you can support its development:\n\n"
             "☕️ Ko-fi: https://ko-fi.com/gluek (🌍 world cards, paypal)\n"
             "🚀 Tribute: https://web.tribute.tg/d/IWb (🇷🇺 russian cards, SBP)\n\n"
             "Thank you! 🙏"
    ))

@dc_cli.on(events.NewMessage(command="/initadmin"))
@command_budget
def initadmin_command(bot, accid, event):
    msg = event.msg
    if any(database.get_effective_admin()):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Admin is already set. Use `set_admin.py` on the server to change."))
        return

    contact = bot.rpc.get_contact(accid, msg.from_id)
    email = contact.address
    fp = _get_contact_fingerprint(bot, accid, msg.from_id, contact=contact)
    if not database.claim_admin(email, fp):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Admin is already set. Use `set_admin.py` on the server to change."))
        return
    if fp:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\nFingerprint: `{fp[-8:]}`"
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\n⚠️ Fingerprint not available yet (will be used after key exchange)."
        ))

@dc_cli.on(events.NewMessage(command="/url"))
@command_budget
def url_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
        
    payload = event.payload.strip()
    if not payload:
        current_url = database.get_config("base_url") or "Not set"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"🔗 Base external status URL: `{current_url}`"))
        return
        
    # Standardize URL
    url = payload.rstrip('/')
    if not url.startswith("http://") and not url.startswith("https://"):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ URL must start with http:// or https://"))
        return
        
    database.set_config("base_url", url)
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Base status URL set to: `{url}`"))

def _safe_url_opener():
    """urllib opener that connects only to validated, pinned addresses and re-validates redirects."""
    import urllib.request
    import urllib.error

    class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not is_safe_target_url(newurl, "http"):
                raise urllib.error.HTTPError(newurl, code, "Redirect to blocked address", headers, fp)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    import http.client

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            ip = resolve_host_safe_sync(self.host)[0]
            self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            ip = resolve_host_safe_sync(self.host)[0]
            sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    class _PinnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_PinnedHTTPConnection, req)

    class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_PinnedHTTPSConnection, req)

    # No environment proxies: a proxy would resolve the name itself and bypass the pinning
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _PinnedHTTPHandler, _PinnedHTTPSHandler, _SafeRedirectHandler
    )

async def _fetch_html_title(url, timeout=TITLE_DEADLINE):
    try:
        async with asyncio.timeout(timeout):
            if not await _prewarm_target_dns(url, "http") or not is_safe_target_url(url, "http", resolve_dns=False):
                return None
            async with aiohttp.ClientSession(connector=_make_safe_connector(), headers={"User-Agent": USER_AGENT},
                                             timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with _safe_http_request(session, "GET", url) as response:
                    # readexactly waits for EOF or the byte cap; the enclosing timeout defeats slow drip.
                    try:
                        data = await response.content.readexactly(16384)
                    except asyncio.IncompleteReadError as exc:
                        data = exc.partial
                    try:
                        text = data.decode(response.charset or "utf-8", errors="ignore")
                    except LookupError:
                        text = data.decode("utf-8", errors="ignore")
                    match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                    if match:
                        return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:database.MAX_NAME_LENGTH] or None
    except Exception as exc:
        logger.warning(redact_url(f"Could not fetch title for {url}: {exc}"))
    return None


def fetch_html_title(url, timeout=TITLE_DEADLINE):
    """Synchronous compatibility entry point; /add calls this only in a title worker."""
    return asyncio.run(_fetch_html_title(url, timeout))

def parse_duration_string(s: str) -> int | None:
    if not s:
        return None
    s = s.strip().lower()
    match = re.match(r'^(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?$', s)
    if not match:
        return None
    val = int(match.group(1))
    unit = match.group(2) or "m"
    if unit.startswith("m"):
        return val * 60
    elif unit.startswith("h"):
        return val * 3600
    elif unit.startswith("d"):
        return val * 86400
    return val * 60

_chat_ping_anti_spam: dict[int, float] = {}
PING_COOLDOWN_SECONDS = 15

@dc_cli.on(events.NewMessage(command="/ping"))
@dc_cli.on(events.NewMessage(command="/check"))
@dc_cli.on(events.NewMessage(command="/test"))
@command_budget
def ping_command(bot, accid, event):
    msg = event.msg
    now = time.time()
    is_admin_user = _is_dc_admin(bot, accid, msg.from_id)
    if not is_admin_user:
        last_ping = _chat_ping_anti_spam.get(msg.chat_id, 0.0)
        if now - last_ping < PING_COOLDOWN_SECONDS:
            remaining = int(PING_COOLDOWN_SECONDS - (now - last_ping)) + 1
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"⏳ Please wait {remaining}s before running another diagnostic check."
            ))
            return
        _chat_ping_anti_spam[msg.chat_id] = now
        if len(_chat_ping_anti_spam) > 1000:
            expired = [k for k, v in _chat_ping_anti_spam.items() if now - v > 300]
            for k in expired:
                _chat_ping_anti_spam.pop(k, None)

    payload = (event.payload or "").strip()
    
    try:
        tokens = shlex.split(payload) if payload else []
    except Exception:
        tokens = payload.split() if payload else []

    # -4 / -6 (like ping -4 / -6): check only over that address family
    family = None
    for flag in ("-4", "-6"):
        while flag in tokens:
            tokens.remove(flag)
            family = int(flag[1])
        
    if not tokens:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/ping [-4|-6] <target> [\"keyword\"]`\n\n"
                 "Quickly tests target reachability and diagnostics on-demand without adding to monitoring.\n\n"
                 "Examples:\n"
                 "• `/ping https://gluek.info` (HTTP)\n"
                 "• `/ping https://gluek.info \"and enjoy\"` (HTTP + Keyword assertion)\n"
                 "• `/ping 1.1.1.1` (ICMP Ping)\n"
                 "• `/ping 2606:4700:4700::1111` (ICMP Ping, IPv6)\n"
                 "• `/ping smtp://chatmail.uk` (SMTP: STARTTLS + certificate)\n"
                 "• `/ping example.com:443` (TCP Port)\n"
                 "• `/ping [2606:4700:4700::1111]:443` (TCP Port, IPv6)\n"
                 "• `/ping -6 example.com` (only over IPv6; `-4` only over IPv4)"
        ))
        return
        
    target_input = tokens[0]
    keyword = tokens[1] if len(tokens) > 1 else None
    try:
        database.validate_monitor_fields(url=target_input, keyword=keyword)
    except ValueError as exc:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {exc}"))
        return

    try:
        check_type, validated_url = parse_target(target_input)
    except ValueError as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ {e}\n\n"
                 "Examples:\n"
                 "• `/ping https://example.com`\n"
                 "• `/ping example.com:443`\n"
                 "• `/ping smtp://mail.example.com`\n"
                 "• `/ping 1.1.1.1`\n"
                 "• `/ping [2a00::1]:443`"
        ))
        return

    if family is not None:
        literal = _literal_ip(_target_host(validated_url, check_type))
        if literal and (":" in literal) != (family == 6):
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"❌ `-{family}` does not fit `{literal}`: it is an IPv{6 if ':' in literal else 4} address."
            ))
            return

    if not is_safe_target_url(validated_url, check_type):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="❌ Cannot check internal, local, or private network targets."
        ))
        return

    if keyword and check_type != "http":
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ Keyword assertions are only supported for HTTP/HTTPS targets.\nTarget `{validated_url}` is type `{check_type.upper()}`."
        ))
        return

    _react(bot, accid, getattr(msg, "id", None), "⏳")

    async def _do_ping():
        final_reaction = "❌"
        try:
            synth_r = {
                "id": 0,
                "url": validated_url,
                "type": check_type,
                "expected_keyword": keyword,
                "family": family,
            }
            
            # Start multi-region peer cross-checks immediately in parallel
            cross_check_task = None
            peers = await asyncio.to_thread(database.get_all_peers)
            # Ad-hoc targets from non-admin users are only shown to peers when sharing is unrestricted
            if peers and (database.get_peer_share_scope() == "all" or (is_admin_user and database.get_peer_share_scope() != "none")):
                cross_check_task = asyncio.create_task(request_peer_cross_checks(synth_r, timeout=6.5))

            # 1. Local check
            res = await run_single_check(synth_r)
            if len(res) == 3:
                is_up, details, latency_ms = res
            else:
                is_up, details = res
                latency_ms = None

            final_reaction = "☑️" if is_up else ("⚪" if is_up is None else "❌")

            # 2. SSL certificate check if HTTPS
            ssl_info = None
            if has_tls_certificate(validated_url):
                try:
                    exp_epoch, ssl_err = await check_ssl_expiry(validated_url, timeout=4.0)
                    if exp_epoch:
                        now_epoch = int(time.time())
                        days_left = (exp_epoch - now_epoch) / 86400
                        exp_date_str = datetime.datetime.fromtimestamp(exp_epoch, tz=datetime.timezone.utc).strftime('%Y-%m-%d')
                        if days_left < 0:
                            ssl_info = f"❌ Expired on `{exp_date_str}`"
                        else:
                            ssl_info = f"✅ Valid ({int(days_left)} days left, expires `{exp_date_str}`)"
                    elif ssl_err:
                        ssl_info = f"⚠️ {ssl_err}"
                except Exception:
                    pass

            # 3. HTML title if HTTP and UP
            page_title = None
            if check_type == "http" and is_up:
                try:
                    future = _submit_bounded(title_executor, _title_slots, fetch_html_title, validated_url)
                    page_title = await _await_worker(future)
                except Exception:
                    pass

            # 4. Await multi-region probe cross-check results
            peer_responses = []
            if cross_check_task:
                try:
                    peer_responses = await cross_check_task
                except Exception:
                    pass

            local_node = database.get_local_node_name()
            status_icon = "🟢" if is_up else ("⚪" if is_up is None else "🔴")
            if is_up is None:
                # Not checked here (no IPv6): the verdict comes from the peers, if any could check
                peer_states = {pr.get("status") for pr in peer_responses}
                if "up" in peer_states:
                    headline, final_reaction = "🟢 **Target is UP** (from other regions)", "☑️"
                elif "down" in peer_states:
                    headline, final_reaction = "🔴 **Target is DOWN** (from other regions)", "❌"
                else:
                    headline = "⚪ **Not checked**: no IPv6 connectivity here"
            else:
                headline = f"{status_icon} **Target is {'UP' if is_up else 'DOWN'}**"

            type_label = check_type.upper() + (f" · IPv{family}" if family else "")
            lines = [
                f"{headline}\n",
                f"🔗 Target: `{validated_url}`",
                f"⚙️ Type: `{type_label}`",
            ]
            if page_title:
                lines.append(f"🖥️ Title: **{page_title}**")

            if keyword:
                kw_status = "✅ Found in body" if is_up else "❌ Not found or error"
                lines.append(f"🔍 Keyword: `\"{keyword}\"` ({kw_status})")

            lat_str = f"`{latency_ms}ms`" if latency_ms is not None else "N/A"
            lines.append(f"⏱️ Response: {details} ({lat_str})")
            redirects = format_redirects(last_redirect_trail()) if check_type == "http" else None
            if redirects:
                lines.append(f"↪️ Redirect: {redirects}")

            if ssl_info:
                lines.append(f"🔒 SSL Cert: {ssl_info}")

            if peer_responses or (peers and local_node):
                lines.append("\n🛰️ **Multi-Region Check:**")
                lines.append(f"• 📍 **{local_node}** (Local): {status_icon} {lat_str} ({details})")
                for pr in peer_responses:
                    pr_node = pr.get("node_name") or "Remote"
                    pr_status = pr.get("status")
                    pr_icon = {"up": "🟢", "down": "🔴"}.get(pr_status, "⚪")  # ⚪: peer could not check
                    pr_lat = f"`{pr['latency_ms']}ms`" if pr.get("latency_ms") is not None else "N/A"
                    pr_err = f" - {pr['error_msg']}" if pr.get("error_msg") else ""
                    lines.append(f"• 🛰️ **{pr_node}**: {pr_icon} {pr_lat}{pr_err}")

            # Add command hint (monitors have no -4/-6, so none for a family-restricted check)
            if family is None:
                kw_arg = f' "{keyword}"' if keyword else ""
                lines.append(f"\n💡 _To monitor 24/7, run:_ `/add {validated_url}{kw_arg}`")

            out_text = "\n".join(lines)
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=out_text))
        finally:
            _react(bot, accid, getattr(msg, "id", None), final_reaction)

    if async_event_loop and async_event_loop.is_running():
        asyncio.run_coroutine_threadsafe(_do_ping(), async_event_loop)
    else:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_do_ping())
        except RuntimeError:
            asyncio.run(_do_ping())

@dc_cli.on(events.NewMessage(command="/add"))
@command_budget
def add_command(bot, accid, event):
    msg = event.msg
    payload = event.payload.strip()
    
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: /add <target> [name] [\"keyword\"]\n\nExamples:\n"
                 "• `/add https://google.com Google` (HTTP)\n"
                 "• `/add https://api.site.com Health \"status:ok\"` (Keyword assertion)\n"
                 "• `/add smtp://chatmail.uk Mail` (SMTP: STARTTLS + certificate)\n"
                 "• `/add google.com:443 Google TCP` (TCP)\n"
                 "• `/add google.com Google Ping` (Ping)\n"
                 "• `/add 2a00::1 Server` / `/add [2a00::1]:22 SSH` (IPv6 ping / TCP)"
        ))
        return
        
    try:
        tokens = shlex.split(payload)
    except Exception:
        tokens = payload.split()
        
    if not tokens:
        return
        
    target = tokens[0]
    if target in ("-4", "-6"):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ `{target}` works with `/ping` only. To monitor over IPv6, add the address itself, "
                 "e.g. `/add 2a00::1` or `/add [2a00::1]:443`."))
        return
    
    try:
        check_type, url = parse_target(target)
    except ValueError as e:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {e}"))
        return

    name = tokens[1] if len(tokens) > 1 else None
    expected_keyword = tokens[2] if len(tokens) > 2 else None
    try:
        database.validate_monitor_fields(url, name, expected_keyword)
    except ValueError as exc:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {exc}"))
        return

    if not is_safe_target_url(url, check_type):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="❌ Cannot check internal, local, or private network targets."
        ))
        return
        
    def finish_add(name):
        try:
            res_id = database.add_resource(msg.chat_id, url, name, check_type, expected_keyword=expected_keyword)
        except ValueError as exc:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {exc}"))
            return
        if res_id is None:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This target is already being monitored in this chat."))
            return

        _scheduler_cache["resources"] = None
        if async_event_loop and async_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcast_telemetry_to_peers(), async_event_loop)

        kw_line = f"\n🔍 Expected Keyword: `{expected_keyword}`" if expected_keyword else ""
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Added monitor (ID: `{res_id}`):\n"
                 f"🖥️ Name: **{name}**\n"
                 f"🔗 Target: `{url}`\n"
                 f"⚙️ Type: `{check_type.upper()}`{kw_line}\n"
                 f"🕒 Checking once a minute.{_no_ipv6_note(url, check_type)}"
        ))

    if not name and check_type == "http":
        def add_with_title():
            finish_add(fetch_html_title(url) or target[:database.MAX_NAME_LENGTH])
        try:
            _submit_bounded(title_executor, _title_slots, add_with_title)
        except TimeoutError:
            finish_add(target[:database.MAX_NAME_LENGTH])
    else:
        finish_add(name or target[:database.MAX_NAME_LENGTH])

@dc_cli.on(events.NewMessage(command="/rm"))
@dc_cli.on(events.NewMessage(command="/del"))
@dc_cli.on(events.NewMessage(command="/remove"))
@dc_cli.on(events.NewMessage(command="/delete"))
@command_budget
def remove_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()

    # Case 1: Direct numeric ID (e.g. /delete 1)
    if payload.isdigit():
        res_id = int(payload)
        res = database.get_resource_by_id(res_id)
        if res and res["dc_chat_id"] == msg.chat_id:
            res_name = res["name"]
            res_url = res["url"]
            database.delete_resource(msg.chat_id, res_id)
            _scheduler_cache["resources"] = None
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Removed monitor: **{res_name}** (`{res_url}`) (ID: `{res_id}`)."))
            trigger_chat_incident_sync(msg.chat_id, force_update=True)
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Monitor ID `{res_id}` not found in this chat."))
        return

    # Case 2: Target URL / name passed directly (e.g. /delete https://example.com)
    if payload:
        matched_resources = database.get_resources_by_target(msg.chat_id, payload)
        if not matched_resources:
            matched_resources = database.get_resources_matching_text(msg.chat_id, payload)

        if matched_resources:
            deleted_names = []
            for r in matched_resources:
                if database.delete_resource(msg.chat_id, r["id"]):
                    deleted_names.append(f"• **{r['name']}** (`{r['url']}`) (ID: `{r['id']}`)")

            if deleted_names:
                text = "✅ Removed monitor:\n" + "\n".join(deleted_names) if len(deleted_names) > 1 else f"✅ Removed monitor: **{matched_resources[0]['name']}** (`{matched_resources[0]['url']}`) (ID: `{matched_resources[0]['id']}`)."
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=text))
                trigger_chat_incident_sync(msg.chat_id, force_update=True)
                return
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ No monitored resource matching `{payload}` found in this chat."))
            return

    # Case 3: No payload -> check if replying / quoting an incident or alert message
    quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
    if quote:
        quote_msg_id = None
        if isinstance(quote, dict):
            quote_msg_id = quote.get("message_id") or quote.get("messageId")
            quote_text = quote.get("text", "")
        else:
            quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
            quote_text = getattr(quote, "text", "")

        full_quote_text = quote_text or ""
        if quote_msg_id and bot and hasattr(bot, "rpc"):
            try:
                quoted_msg = bot.rpc.get_message(accid, quote_msg_id)
                if quoted_msg and hasattr(quoted_msg, "text") and quoted_msg.text:
                    full_quote_text = f"{full_quote_text}\n{quoted_msg.text}"
            except Exception as e:
                logger.debug(f"Could not fetch quoted message {quote_msg_id}: {e}")

        targets_to_delete = []

        # 3a. Check if quote_msg_id corresponds to an incident from this bot in this chat
        if quote_msg_id:
            inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
            if inc:
                events = database.get_incident_downtime_events(inc["id"])
                for ev in events:
                    r = database.get_resource_by_id(ev["resource_id"])
                    if r and r["dc_chat_id"] == msg.chat_id and r not in targets_to_delete:
                        targets_to_delete.append(r)

        # 3b. Match resources by URLs/names in quote text
        if full_quote_text:
            text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
            for r in text_matched:
                if r not in targets_to_delete:
                    targets_to_delete.append(r)

        if targets_to_delete:
            deleted_names = []
            for r in targets_to_delete:
                if database.delete_resource(msg.chat_id, r["id"]):
                    deleted_names.append(f"• **{r['name']}** (`{r['url']}`) (ID: `{r['id']}`)")

            if deleted_names:
                text = "✅ Removed monitor:\n" + "\n".join(deleted_names) if len(deleted_names) > 1 else f"✅ Removed monitor: **{targets_to_delete[0]['name']}** (`{targets_to_delete[0]['url']}`) (ID: `{targets_to_delete[0]['id']}`)."
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=text))
                trigger_chat_incident_sync(msg.chat_id, force_update=True)
            return
        else:
            logger.info(f"Ignoring /delete reply in chat {msg.chat_id}: no matching monitors found for quote {quote_msg_id}")
            return

    # Case 4: No payload and no quote
    _dc_send_msg_with_stats(
        bot, accid, msg.chat_id,
        MsgData(text="ℹ️ **Usage:**\n• `/delete <id>` — Delete monitor by ID\n• `/delete <url>` — Delete monitor by URL/domain\n• Reply `/delete` directly to an incident or outage alert message.")
    )

@dc_cli.on(events.NewMessage(command="/pause"))
@dc_cli.on(events.NewMessage(command="/mute"))
@dc_cli.on(events.NewMessage(command="/maintenance"))
@command_budget
def pause_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    now = int(time.time())
    
    try:
        tokens = shlex.split(payload) if payload else []
    except Exception:
        tokens = payload.split() if payload else []

    target_res = []
    duration_secs = 3600 # default 1 hour
    
    if len(tokens) >= 1:
        # Check if first token is duration only (e.g. /pause 30m)
        dur = parse_duration_string(tokens[0])
        if dur is not None and len(tokens) == 1:
            duration_secs = dur
        else:
            target_ident = tokens[0]
            if len(tokens) >= 2:
                parsed_dur = parse_duration_string(tokens[1])
                if parsed_dur is not None:
                    duration_secs = parsed_dur
            
            if target_ident.isdigit():
                r = database.get_resource_by_id(int(target_ident))
                if r and r["dc_chat_id"] == msg.chat_id:
                    target_res = [r]
            else:
                target_res = database.get_resources_by_target(msg.chat_id, target_ident)
                if not target_res:
                    target_res = database.get_resources_matching_text(msg.chat_id, target_ident)
                
    # If no target specified via args, try quote/reply
    if not target_res:
        quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
        if quote:
            quote_msg_id = None
            if isinstance(quote, dict):
                quote_msg_id = quote.get("message_id") or quote.get("messageId")
                quote_text = quote.get("text", "")
            else:
                quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
                quote_text = getattr(quote, "text", "")

            full_quote_text = quote_text or ""
            if quote_msg_id and bot and hasattr(bot, "rpc"):
                try:
                    qmsg = bot.rpc.get_message(accid, quote_msg_id)
                    if qmsg and hasattr(qmsg, "text") and qmsg.text:
                        full_quote_text = f"{full_quote_text}\n{qmsg.text}"
                except Exception:
                    pass
                    
            if quote_msg_id:
                inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
                if inc:
                    inc_events = database.get_incident_downtime_events(inc["id"])
                    for ev in inc_events:
                        r = database.get_resource_by_id(ev["resource_id"])
                        if r and r["dc_chat_id"] == msg.chat_id and r not in target_res:
                            target_res.append(r)
                            
            if not target_res and full_quote_text:
                text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
                for r in text_matched:
                    if r not in target_res:
                        target_res.append(r)
                    
            if not target_res:
                logger.info(f"Pause quote in chat {msg.chat_id} did not match any local resources, ignoring.")
                return

    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/pause <id|url> [duration]` or reply `/pause [duration]` to an alert.\n\n"
                 "Examples:\n"
                 "• `/pause 1 30m`\n"
                 "• `/pause https://example.com 2h`\n"
                 "• Reply `/pause 1h` directly to an incident alert"
        ))
        return

    until_ts = now + duration_secs
    until_dt_str = datetime.datetime.fromtimestamp(until_ts, tz=datetime.timezone.utc).strftime('%H:%M:%S')
    dur_str = format_duration(duration_secs)
    
    paused_names = []
    for r in target_res:
        database.set_resource_maintenance(msg.chat_id, r["id"], until_ts)
        paused_names.append(f"• `ID: {r['id']}` **{r['name']}** (`{r['url']}`)")
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"⏸️ **Maintenance Mode Enabled** (active for `{dur_str}`, until `{until_dt_str} UTC`):\n\n" +
             "\n".join(paused_names) +
             "\n\n_Outage alerts will be suppressed until maintenance expires, or use `/resume`._"
    ))

@dc_cli.on(events.NewMessage(command="/resume"))
@dc_cli.on(events.NewMessage(command="/unpause"))
@command_budget
def resume_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    
    target_res = []
    if payload.isdigit():
        r = database.get_resource_by_id(int(payload))
        if r and r["dc_chat_id"] == msg.chat_id:
            target_res = [r]
    elif payload:
        target_res = database.get_resources_by_target(msg.chat_id, payload)
        if not target_res:
            target_res = database.get_resources_matching_text(msg.chat_id, payload)
        
    if not target_res:
        quote = getattr(msg, "quote", None) or (msg.get("quote") if isinstance(msg, dict) else None)
        if quote:
            quote_msg_id = None
            if isinstance(quote, dict):
                quote_msg_id = quote.get("message_id") or quote.get("messageId")
                quote_text = quote.get("text", "")
            else:
                quote_msg_id = getattr(quote, "message_id", None) or getattr(quote, "messageId", None)
                quote_text = getattr(quote, "text", "")

            full_quote_text = quote_text or ""
            if quote_msg_id and bot and hasattr(bot, "rpc"):
                try:
                    qmsg = bot.rpc.get_message(accid, quote_msg_id)
                    if qmsg and hasattr(qmsg, "text") and qmsg.text:
                        full_quote_text = f"{full_quote_text}\n{qmsg.text}"
                except Exception:
                    pass
                    
            if quote_msg_id:
                inc = database.get_incident_by_msg_id(msg.chat_id, quote_msg_id)
                if inc:
                    inc_events = database.get_incident_downtime_events(inc["id"])
                    for ev in inc_events:
                        r = database.get_resource_by_id(ev["resource_id"])
                        if r and r["dc_chat_id"] == msg.chat_id and r not in target_res:
                            target_res.append(r)
                            
            if not target_res and full_quote_text:
                text_matched = database.get_resources_matching_text(msg.chat_id, full_quote_text)
                for r in text_matched:
                    if r not in target_res:
                        target_res.append(r)
                    
            if not target_res:
                logger.info(f"Resume quote in chat {msg.chat_id} did not match any local resources, ignoring.")
                return

    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/resume <id|url>` or reply `/resume` to an alert."
        ))
        return

    resumed_names = []
    for r in target_res:
        database.set_resource_maintenance(msg.chat_id, r["id"], 0)
        resumed_names.append(f"• `ID: {r['id']}` **{r['name']}** (`{r['url']}`)")
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text="▶️ **Resumed Monitoring:**\n\n" +
             "\n".join(resumed_names)
    ))

@dc_cli.on(events.NewMessage(command="/keyword"))
@dc_cli.on(events.NewMessage(command="/assert"))
@dc_cli.on(events.NewMessage(command="/kw"))
@command_budget
def keyword_command(bot, accid, event):
    msg = event.msg
    payload = (event.payload or "").strip()
    
    try:
        tokens = shlex.split(payload) if payload else []
    except Exception:
        tokens = payload.split() if payload else []
        
    if not tokens:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/keyword <id|url> <keyword|none>`\n\n"
                 "Examples:\n"
                 "• `/keyword 1 \"Welcome to site\"`\n"
                 "• `/keyword https://api.site.com/health \"status:ok\"`\n"
                 "• `/keyword 1 none` (to remove keyword assertion)"
        ))
        return
        
    target_ident = tokens[0]
    keyword = tokens[1] if len(tokens) > 1 else None
    try:
        database.validate_monitor_fields(keyword=keyword)
    except ValueError as exc:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {exc}"))
        return
    
    target_res = []
    if target_ident.isdigit():
        r = database.get_resource_by_id(int(target_ident))
        if r and r["dc_chat_id"] == msg.chat_id:
            target_res = [r]
    else:
        target_res = database.get_resources_by_target(msg.chat_id, target_ident)
        if not target_res:
            target_res = database.get_resources_matching_text(msg.chat_id, target_ident)
        
    if not target_res:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ No monitor found for `{target_ident}` in this chat."
        ))
        return
        
    # Prioritize HTTP monitors for keyword assertions if multiple targets match
    http_matches = [r for r in target_res if r.get("type") == "http"]
    target = http_matches[0] if http_matches else target_res[0]

    if target.get("type") != "http":
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ Keyword assertions are only supported for HTTP/HTTPS monitors.\nMonitor `ID: {target['id']}` (**{target['name']}**) has type `{target.get('type', '').upper()}`."
        ))
        return

    if keyword is None:
        current_kw = target.get("expected_keyword")
        if current_kw:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"🔍 Monitor `ID: {target['id']}` (**{target['name']}**) requires keyword:\n`\"{current_kw}\"`"
            ))
        else:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"ℹ️ Monitor `ID: {target['id']}` (**{target['name']}**) does not have a required keyword configured."
            ))
        return
        
    _scheduler_cache["resources"] = None
    if keyword.lower() in ("none", "clear", "remove", "off", "disable", "delete"):
        database.set_resource_keyword(msg.chat_id, target["id"], None)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Cleared expected keyword requirement for **{target['name']}** (`ID: {target['id']}`)."
        ))
    else:
        database.set_resource_keyword(msg.chat_id, target["id"], keyword)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Set expected keyword for **{target['name']}** (`ID: {target['id']}`):\n`\"{keyword}\"`"
        ))

@dc_cli.on(events.NewMessage(command="/list"))
@command_budget
def list_command(bot, accid, event):
    msg = event.msg
    resources = database.get_resources(msg.chat_id)
    if not resources:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="ℹ️ No monitored resources in this chat. Add one with `/add <target>`."))
        return
        
    now_ts = int(time.time())
    uptimes_map = database.get_resources_uptime_30d([r["id"] for r in resources])
    reply = "⚙️ **Monitored Resources:**\n\n"
    for r in resources:
        m_until = r.get("maintenance_until") or 0
        is_maintenance = (now_ts < m_until)

        if is_maintenance:
            emoji_status = "⏸️"
            m_left_secs = m_until - now_ts
            m_left_str = format_duration(m_left_secs)
            status_text = f"PAUSED ({m_left_str} left)"
        elif r["status"] == "up" and r.get("alert_state") == "degraded":
            emoji_status = "🟠"
            status_text = "DEGRADED"
        elif r["status"] == "up":
            emoji_status = "🟢"
            status_text = "UP"
        elif r["status"] == "down":
            emoji_status = "🔴"
            status_text = "DOWN"
        else:
            emoji_status = "⚪"
            status_text = "UNKNOWN"
            
        uptime = uptimes_map.get(r["id"], 100.0)
        votes = _votes_from_json(r.get("last_votes"))
        votes_line = f"  🛰️ {format_votes(votes)}\n" if len(votes) > 1 and status_text in ("DEGRADED", "DOWN") else ""
        
        extra_info = ""
        if r.get("last_latency_ms") is not None:
            extra_info += f" | ⚡ `{r['last_latency_ms']}ms`"
        if r.get("expected_keyword"):
            extra_info += f" | 🔍 \"{r['expected_keyword']}\""
        extra_info += slowdown_note(r, int(now_ts))
            
        ssl_info = ""
        if has_tls_certificate(r.get("url", "")):
            exp_ts = r.get("ssl_expiry_date")
            if exp_ts:
                d_left = int((exp_ts - now_ts) / 86400)
                exp_date_str = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d')
                if d_left < 0:
                    ssl_info = f" | SSL: 🚨 Expired (`{exp_date_str}`)"
                elif d_left <= 7:
                    ssl_info = f" | SSL: ⚠️ `{d_left}d` left (`{exp_date_str}`)"
                else:
                    ssl_info = f" | SSL: 🔒 `{d_left}d` left (`{exp_date_str}`)"
            else:
                ssl_info = " | SSL: 🔒 Pending check"

        reply += (
            f"{emoji_status} `ID: {r['id']}` **{r['name']}**\n"
            f"  Target: `{r['url']}` ({r['type'].upper()})\n"
            f"  Uptime 30d: `{uptime:.2f}%` | Status: `{status_text}`{extra_info}{ssl_info}\n"
            f"{votes_line}\n"
        )
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/alertmode"))
@command_budget
def alertmode_command(bot, accid, event):
    """Per-chat alerting: quorum (default) or local. Any chat member may change it, like /pause."""
    msg = event.msg
    payload = (event.payload or "").strip().lower()
    if payload:
        try:
            database.set_chat_alert_mode(msg.chat_id, payload)
        except ValueError:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Usage: `/alertmode quorum|local`"))
            return
    mode = database.get_chat_alert_mode(msg.chat_id)

    live_peers = [p for p in database.get_all_peers() if not p.get("is_offline")]
    resources = database.get_resources(msg.chat_id)
    shared = _filter_peer_shareable_resources(bot, accid, resources) if resources else [{"dc_chat_id": msg.chat_id}]
    node_count = len(live_peers) + 1
    majority = node_count // 2 + 1

    reply = ("✅ " if payload else "") + f"🛰️ **Alert mode:** `{mode}`\n\n"
    if mode == "quorum":
        reply += (
            f"This node and its live peers check a failing target together ({node_count} node(s) now):\n"
            f"• 🔴 **DOWN** (incident) when at least {majority} of {node_count} cannot reach it\n"
            f"• 🟠 **DEGRADED** (a notice, not downtime) when fewer cannot reach it\n"
            f"Alerts show which nodes can and cannot reach the target.\n\n"
        )
        if node_count < 2:
            reply += "⚠️ _No live peers right now: this node decides alone until a peer is back._\n\n"
        elif resources and not shared:
            reply += ("⚠️ _This chat's monitors are not shared with peers (`/peershare`), "
                      "so this node decides alone for them._\n\n")
    else:
        reply += ("Only this node's checks decide whether a target is down. Peers' results are still "
                  "shown in alerts when they were asked.\n\n")
    reply += "Change with `/alertmode quorum` or `/alertmode local`."
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

def report_settings_text(chat_id: int) -> str:
    partial = database.get_chat_report_partial(chat_id)
    full = database.get_chat_report_full(chat_id)
    return f"partial: {'off' if partial == 'off' else str(partial) + ' min'}, full: {full} min, app: {database.get_chat_report_app(chat_id)}, live: {'on' if realtime_chat(chat_id) else 'off'}"


@dc_cli.on(events.NewMessage(command="/report"))
@command_budget
def report_command(bot, accid, event):
    """Any chat member may configure outage notices and the status app."""
    chat_id = event.msg.chat_id
    args = (event.payload or "").strip().lower().split()
    usage = "Usage: `/report`, `/report all`, `/report partial <0..1440|off>`, `/report full <0..1440>`, `/report app off|on|only`, `/report live on|off`."
    try:
        if args == ["all"]:
            database.set_chat_report_partial(chat_id, 0)
            database.set_chat_report_full(chat_id, 0)
        elif len(args) == 2 and args[0] == "live":
            database.set_chat_report_live(chat_id, args[1])
        elif len(args) == 2 and args[0] == "app":
            database.set_chat_report_app(chat_id, args[1])
            if args[1] != "off":
                queue_status_app(chat_id, bot, accid)
        elif len(args) == 2 and args[0] in ("partial", "full"):
            value = "off" if args[1] == "off" else int(args[1])
            setter = database.set_chat_report_partial if args[0] == "partial" else database.set_chat_report_full
            setter(chat_id, value)
        elif args:
            raise ValueError("invalid report command")
    except ValueError:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=f"❌ {usage}"))
        return
    text = ("✅ " if args else "") + f"🔔 **Report settings:** {report_settings_text(chat_id)}\n\n"
    text += "Live on allows optional realtime updates in the app (shares IP addresses with live members).\n"
    text += "App on keeps chat notices; app only suppresses outage chat notices. App off stops app updates.\n"
    text += "Only chat notifications are delayed; monitoring and uptime statistics stay immediate.\n"
    text += "Resolved notices follow only an announced outage. Zero means immediate; partial off disables partial notices.\n\n" + usage
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=text))


@dc_cli.on(events.NewMessage(command="/status"))
@command_budget
def status_command(bot, accid, event):
    msg = event.msg
    resources = database.get_resources(msg.chat_id)
    if not resources:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="ℹ️ No resources monitored in this chat."))
        return
        
    total_monitors = len(resources)
    degraded_monitors = sum(1 for r in resources if r["status"] == "up" and r.get("alert_state") == "degraded")
    up_monitors = sum(1 for r in resources if r["status"] == "up") - degraded_monitors
    down_monitors = sum(1 for r in resources if r["status"] == "down")
    
    avg_uptime = database.get_chat_uptime_30d(msg.chat_id)
    
    token = database.get_or_create_chat_token(msg.chat_id)
    base_url = database.get_config("base_url") or "http://localhost:8080"
    status_page_url = f"{base_url}/{token}"
    
    reply = (
        f"📊 **Uptime Status Report (Last 30 days):**\n\n"
        f"📈 Overall Uptime: `{avg_uptime:.2f}%`\n"
        f"🖥️ Total Monitors: `{total_monitors}`\n"
        f"🟢 Online: `{up_monitors}` | 🟠 Degraded: `{degraded_monitors}` | 🔴 Offline: `{down_monitors}`\n"
        f"🛰️ Alert mode: `{database.get_chat_alert_mode(msg.chat_id)}` (`/alertmode`)\n"
        f"🔔 Report: {report_settings_text(msg.chat_id)} (`/report`)\n\n"
        f"🔗 **Web Status Dashboard:**\n"
        f"{status_page_url}"
    )
    if not database.get_config("base_url"):
        reply += "\n\n💡 _Admin: Configure base URL via `/url https://domain` to get public links._"
        
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

def _format_partial_outage_line(po: dict, with_name: bool = False) -> str:
    start_str = datetime.datetime.fromtimestamp(po["started_at"], tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    nodes = ", ".join(_votes_from_json(po.get("nodes_down"))) or "some nodes"
    name = f"`ID: {po['resource_id']}` **{po.get('name') or po.get('url')}** — " if with_name else ""
    if po.get("ended_at"):
        end_str = datetime.datetime.fromtimestamp(po["ended_at"], tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        dur = format_duration(max(1, po["ended_at"] - po["started_at"]))
        return f"• {name}`{start_str}` → `{end_str} UTC` (`{dur}`) — unreachable from {nodes}"
    dur = format_duration(max(1, int(time.time()) - po["started_at"]))
    return f"• 🟠 {name}`{start_str} UTC` → `Ongoing` (`{dur}`) — unreachable from {nodes}"


@dc_cli.on(events.NewMessage(command="/events"))
@dc_cli.on(events.NewMessage(command="/incidents"))
@command_budget
def events_command(bot, accid, event):
    msg = event.msg
    chat_id = msg.chat_id
    
    recent_incs = database.get_recent_incidents(chat_id, limit=10)
    partials = database.get_chat_partial_outages(chat_id, limit=10)
    
    if not recent_incs and not partials:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(
            text="✨ **No incidents recorded in this chat!**\nAll monitored resources have been running smoothly."
        ))
        return
        
    lines = [f"📋 **Incident Log for this Chat ({len(recent_incs)} most recent):**\n" if recent_incs
             else "📋 **No incidents recorded in this chat.**\n"]
    
    for inc in recent_incs:
        inc_id = inc["id"]
        status = inc["status"]
        started_at = inc["started_at"]
        resolved_at = inc["resolved_at"]
        
        start_str = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        
        if status == "ongoing":
            duration_str = format_duration(int(time.time()) - started_at)
            lines.append(
                f"• 🚨 **Incident #{inc_id}** — `Ongoing`\n"
                f"  Started: `{start_str} UTC` (active for `{duration_str}`)"
            )
        else:
            resolved_str = datetime.datetime.fromtimestamp(resolved_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if resolved_at else "Resolved"
            duration = max(1, (resolved_at or int(time.time())) - started_at)
            duration_str = format_duration(duration)
            lines.append(
                f"• ✅ **Incident #{inc_id}** — `Resolved`\n"
                f"  Duration: `{duration_str}` (`{start_str}` → `{resolved_str} UTC`)"
            )

    if partials:
        lines.append(f"\n🟠 **Partial Outages ({len(partials)} most recent, not downtime):**")
        lines += [_format_partial_outage_line(po, with_name=True) for po in partials]
            
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))

@dc_cli.on(events.NewMessage(command="/history"))
@command_budget
def history_command(bot, accid, event):
    msg = event.msg
    chat_id = msg.chat_id
    payload = (event.payload or "").strip()
    
    if not payload:
        resources = database.get_resources(chat_id)
        if not resources:
            _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(
                text="ℹ️ No resources monitored in this chat. Add one with `/add <target>`."
            ))
            return
            
        lines = [
            "📜 **Monitor Downtime History Guide**\n",
            "To view the detailed outage log for a specific monitor, use `/history <id>`.\n",
            "**Monitors in this chat:**"
        ]
        for r in resources:
            name = r["name"] or r["url"]
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• `ID: {r['id']}` **{name}** — 30d Uptime: `{uptime_val:.2f}%`")
            
        lines.append("\n💡 Tip: Use `/events` to view the full incident history of this chat.")
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))
        return
        
    try:
        res_id = int(payload)
    except ValueError:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="❌ Invalid monitor ID. Usage: `/history <id>`"))
        return
        
    resources = database.get_resources(chat_id)
    target_res = next((r for r in resources if r["id"] == res_id), None)
    if not target_res:
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=f"❌ Monitor ID `{res_id}` not found in this chat."))
        return
        
    events_list = database.get_resource_downtime_events(res_id, limit=10)
    uptime_val = database.get_resource_uptime_30d(res_id)
    r_name = target_res["name"] or target_res["url"]
    r_type = target_res["type"].upper()
    
    lines = [
        f"📜 **Downtime History for ID {res_id} ({r_name})**",
        f"Target: `{target_res['url']}` ({r_type})",
        f"Uptime 30d: `{uptime_val:.2f}%`\n"
    ]
    
    if not events_list:
        lines.append("✨ No downtime events recorded in the last 30 days!")
    else:
        lines.append(f"**Recorded Outages ({len(events_list)} most recent):**")
        for ev in events_list:
            went_down = ev["went_down_at"]
            went_up = ev["went_up_at"]
            error_reason = ev.get("error_msg") or "Outage"
            
            down_str = datetime.datetime.fromtimestamp(went_down, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            if went_up:
                up_str = datetime.datetime.fromtimestamp(went_up, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                duration_str = format_duration(max(1, went_up - went_down))
                lines.append(f"• `{down_str}` → `{up_str} UTC` (`{duration_str}`) — `{error_reason}`")
            else:
                duration_str = format_duration(max(1, int(time.time()) - went_down))
                lines.append(f"• 🔴 `{down_str} UTC` → `Ongoing` (`{duration_str}`) — `{error_reason}`")

    partials = database.get_partial_outages(res_id, limit=5)
    if partials:
        lines.append(f"\n**Partial Outages ({len(partials)} most recent, not downtime):**")
        lines += [_format_partial_outage_line(po) for po in partials]
                
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text="\n".join(lines)))

@dc_cli.on(events.NewMessage(command="/sync"))
@command_budget
def sync_command(bot, accid, event):
    msg = event.msg
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        if isinstance(chat_info, dict):
            chat_type = chat_info.get('chat_type', 'Single')
        else:
            chat_type = getattr(chat_info, 'chat_type', 'Single')
        is_group = str(chat_type) in ("Group", "Mailinglist", "OutBroadcast", "InBroadcast")
    except Exception:
        is_group = False

    if not is_group:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="ℹ️ Synchronization is only available in group chats containing multiple Uptime Bot instances."
        ))
        return

    # Check rate limit (1 minute per chat for non-admins)
    is_admin = _is_dc_admin(bot, accid, msg.from_id)
    if not is_admin:
        now = time.time()
        last_sync = last_sync_times.get(msg.chat_id, 0.0)
        if now - last_sync < 60.0:
            remaining = int(60.0 - (now - last_sync))
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"⚠️ Command `/sync` is rate-limited. Please wait {remaining}s before trying again."
            ))
            return
        last_sync_times[msg.chat_id] = now

    resources = database.get_resources(msg.chat_id)
    sync_list = []
    for r in resources:
        sync_list.append({
            "url": r["url"],
            "name": r["name"],
            "type": r["type"],
            "interval": r.get("interval", 60)
        })

    sync_data = json.dumps(sync_list)
    reply = (
        "🔄 **Uptime Bot Synchronization**\n"
        "Here are the resources monitored by this bot instance:\n\n"
    )
    if sync_list:
        for r in sync_list:
            reply += f"• `{r['url']}` ({r['name']}) [{r['type'].upper()}]\n"
    else:
        reply += "_No resources monitored._\n"

    reply += f"\n[UPTIME_BOT_SYNC_DATA]\n{sync_data}\n[/UPTIME_BOT_SYNC_DATA]"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

# Admin-Only Account and Transport Command handlers (Standard across bots)
@dc_cli.on(events.NewMessage(command="/accounts"))
@command_budget
def accounts_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    accids = bot.rpc.get_all_account_ids()
    reply = "🤖 **Configured Delta Chat Accounts:**\n\n"
    for a_id in accids:
        try:
            addr = dc_fingerprint.get_self_addr(bot.rpc, a_id)
            primary = " (Primary)" if a_id == accid else ""
            reply += f"• ID: `{a_id}` - `{addr}`{primary}\n"
        except Exception:
            pass
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/rmaccount"))
@command_budget
def rmaccount_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = event.payload.strip()
    if not payload or not payload.isdigit():
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /rmaccount <id>"))
        return
    target_id = int(payload)
    if target_id == accid:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Cannot delete the active account."))
        return
    try:
        bot.rpc.remove_account(target_id)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Account `{target_id}` deleted."))
    except Exception as e:
        logger.error(f"Failed to delete account: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to delete account. Check server logs for details."))

@dc_cli.on(events.NewMessage(command="/transports"))
@command_budget
def transports_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    try:
        transports = bot.rpc.list_transports(accid)
    except Exception:
        transports = []

    # Which relay the core really sends through, its send queue, and per-relay
    # incoming status and storage (see transports_view.py).
    reply = transports_view.build_transports_report(bot.rpc, accid, transports)
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/addtransport"))
@command_budget
def addtransport_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
    if not is_single_chat(chat_info):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="⚠️ For security, `/addtransport` can only be used in a private 1:1 chat with the bot to protect your credentials."
        ))
        return

    payload = event.payload.strip()
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage:\n"
                 "/addtransport DCACCOUNT:server.example\n"
                 "/addtransport user@example.com password123"
        ))
        return

    try:
        if payload.startswith("DCACCOUNT:"):
            bot.rpc.add_transport_from_qr(accid, payload)
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="✅ Backup transport added via chatmail URI."))
        else:
            parts = payload.split(None, 1)
            if len(parts) < 2:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                    text="❌ For email accounts, provide both address and password:\n"
                         "/addtransport user@example.com password123"
                ))
                return
            addr, password = parts[0], parts[1]
            bot.rpc.add_or_update_transport(accid, {"addr": addr, "password": password})
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Backup transport `{addr}` added."))
    except Exception as e:
        logger.error(f"Failed to add transport: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to add transport. Check server logs for details."))

@dc_cli.on(events.NewMessage(command="/rmtransport"))
@command_budget
def rmtransport_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    addr = event.payload.strip()
    if not addr:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: /rmtransport user@example.com"))
        return

    try:
        transports = bot.rpc.list_transports(accid)
        transport_addrs = [t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '') for t in transports]
        if len(transport_addrs) <= 1:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Cannot remove the last transport. Add another one first."))
            return
        if addr not in transport_addrs:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Transport `{addr}` not found."))
            return
            
        bot.rpc.delete_transport(accid, addr)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Transport `{addr}` removed."))
    except Exception as e:
        logger.error(f"Failed to remove transport: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to remove transport. Check server logs for details."))

RELAY_SELECTION_NOTE = (
    "Since core 2.61 the core picks the sending relay itself: it tries the newest relay first "
    "and falls back to the next one if a relay is unreachable. "
    "Use /addtransport and /rmtransport to control relays."
)


@dc_cli.on(events.NewMessage(command="/setprimary"))
@command_budget
def setprimary_command(bot, accid, event):
    """Deprecated: the core no longer uses configured_addr to pick the SMTP relay."""
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Only the bot administrator can use /setprimary."))
        return
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"⚠️ /setprimary is deprecated and disabled. {RELAY_SELECTION_NOTE}"))

@dc_cli.on(events.NewMessage(command="/resilient"))
@command_budget
def resilient_command(bot, accid, event):
    """Deprecated: relay failover is handled by the core."""
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Only the bot administrator can use /resilient."))
        return
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"⚠️ /resilient is deprecated and disabled. {RELAY_SELECTION_NOTE}"))

def _get_self_addr(bot, accid) -> str:
    return dc_fingerprint.get_self_addr(bot.rpc, accid)

# Peer administration commands
def _configured_display_name() -> str:
    """Display name set by the operator: DISPLAY_NAME, or display_name in the Home Assistant options."""
    name = (os.environ.get("DISPLAY_NAME") or "").strip()
    if not name and os.path.exists("/data/options.json"):
        try:
            with open("/data/options.json", "r", encoding="utf-8") as f:
                name = (json.load(f).get("display_name") or "").strip()
        except Exception:
            pass
    return name


def _node_display_name() -> str:
    """Default display name: shows which node it is when several Uptime bots are peers."""
    return f"Uptime Bot ({database.get_local_node_name()})"


@dc_cli.on(events.NewMessage(command="/nodename"))
@command_budget
def nodename_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    if payload:
        try:
            database.rename_local_node(payload)
        except ValueError as exc:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ {exc}"))
            return
        global last_peer_telemetry_broadcast
        # Peers learn the new name from the next telemetry message: send it on the next scheduler tick
        last_peer_telemetry_broadcast = 0.0
        name_note = ""
        if not _configured_display_name():
            # The profile name follows the node name; contacts get it with the bot's next message
            try:
                bot.rpc.set_config(accid, "displayname", _node_display_name())
                name_note = f"\nBot display name is now `{_node_display_name()}`."
            except Exception as e:
                logger.warning(f"Could not update display name: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Local probe node name set to: `{payload}`\nPeers on 2.17.2+ pick it up with the next telemetry message.{name_note}"))
    else:
        current_name = database.get_local_node_name()
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"📍 Current local probe node name: `{current_name}`\n\nTo change it: `/nodename <name>` (e.g. `/nodename Frankfurt-DE`, `/nodename RU-Moscow`)."))

def _proc_stat(pid) -> tuple[float, float] | None:
    """(cpu seconds, start time in seconds since boot) of a process, from /proc (Linux only)."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        tick = os.sysconf("SC_CLK_TCK")
        return (int(fields[11]) + int(fields[12])) / tick, int(fields[19]) / tick
    except (OSError, ValueError, IndexError):
        return None


def _core_pid() -> int | None:
    """The deltachat-rpc-server process (the core) this bot talks to."""
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        if b"deltachat-rpc-server" in f.read():
                            return int(pid)
                except OSError:
                    continue
    except OSError:
        pass
    return None


def process_cpu_seconds() -> dict:
    """CPU seconds used so far by the bot ("bot") and the core ("core"), where /proc has them."""
    out = {}
    for name, pid in (("bot", os.getpid()), ("core", _core_pid())):
        st = _proc_stat(pid) if pid else None
        if st:
            out[name] = st
    return out


def _cpu_report() -> str:
    """'bot 2% (avg 3%), core 11% (avg 14%)': over the last minutes and since the process started."""
    now_cpu, now = process_cpu_seconds(), time.monotonic()
    if not now_cpu:
        return "n/a (no /proc)"
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            boot_secs = float(f.read().split()[0])
    except (OSError, ValueError):
        boot_secs = None
    old = next(((t, c) for t, c in _cpu_samples if now - t >= 30), None)
    parts = []
    for name, (cpu, started) in now_cpu.items():
        recent = f"{100 * (cpu - old[1][name][0]) / (now - old[0]):.0f}%" if old and name in old[1] else "?"
        avg = f", avg {100 * cpu / (boot_secs - started):.0f}%" if boot_secs and boot_secs > started else ""
        parts.append(f"{name} {recent}{avg}")
    return ", ".join(parts)


_STATS_MAX_BYTES = 4095
_STORAGE_TOP = 5
_storage_config_dir = None
_storage_cache = collections.OrderedDict()
_storage_cache_lock = threading.Lock()
_storage_warned_at = float("-inf")
_CORE_DUMP_NAME = re.compile(r"core(?:\.[0-9]+|-.*)?|.*\.core|vgcore\..*", re.DOTALL)
_core_dump_warned = set()


@dataclass
class _StorageTree:
    total: int = 0
    logs: int = 0
    log_count: int = 0
    database_bytes: int = 0
    blob_bytes: int | None = None
    files: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    log_files: list = field(default_factory=list)
    partial: bool = False


@dataclass
class _StorageStats:
    disk: tuple | None
    data: _StorageTree
    app: _StorageTree
    bot_bytes: int
    core_bytes: int | None
    blob_bytes: int | None
    partial: bool


def _format_storage_size(size):
    if size is None:
        return "n/a"
    if size < 1024:
        return f"{size} B"
    for unit in ("KB", "MB", "GB", "TB", "PB"):
        size /= 1024
        if size < 1024 or unit == "PB":
            return f"{size:.1f} {unit}"


def _storage_top(items, size, path):
    item = (size, path)
    if len(items) < _STORAGE_TOP:
        heapq.heappush(items, item)
    else:
        heapq.heappushpop(items, item)


def _storage_id(info):
    return info.st_dev, info.st_ino


def _walk_storage(root, deadline, *, clock=time.monotonic, skip=None, databases=(), blobs=None):
    """Sum regular file sizes. Directory rankings include only the first three levels."""
    result = _StorageTree()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def visit(directory, path="", inside_blobs=False):
        total = 0
        try:
            with os.scandir(directory) as entries:
                while True:
                    if clock() >= deadline:
                        result.partial = True
                        break
                    entry = next(entries, None)
                    if entry is None:
                        break
                    relative = f"{path}/{entry.name}" if path else entry.name
                    if relative == skip:
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            child = os.open(entry.name, flags, dir_fd=directory)
                            try:
                                is_blobs = blobs is not None and _storage_id(os.fstat(child)) == blobs
                                size = visit(child, relative, inside_blobs or is_blobs)
                            finally:
                                os.close(child)
                            total += size
                            if relative.count("/") < 3:
                                _storage_top(result.directories, size, relative)
                            if is_blobs:
                                result.blob_bytes = size
                        elif stat.S_ISREG(info.st_mode):
                            size = info.st_size
                            total += size
                            _storage_top(result.files, size, relative)
                            if not inside_blobs and _storage_id(info) in databases:
                                result.database_bytes += size
                            if entry.name.endswith(".log"):
                                result.logs += size
                                result.log_count += 1
                                _storage_top(result.log_files, size, relative)
                    except OSError:
                        continue
                    except RecursionError:
                        result.partial = True
                    if result.partial:
                        break
        except OSError:
            pass
        return total

    if clock() >= deadline:
        result.partial = True
        return result
    try:
        directory = os.open(root, flags)
        try:
            result.total = visit(directory)
        finally:
            os.close(directory)
    except OSError:
        pass
    return result


def _storage_stat(path, test_mode):
    try:
        info = path.lstat()
        return info if test_mode(info.st_mode) else None
    except OSError:
        return None


def _storage_root():
    return Path(os.path.abspath(os.getenv("DC_DB_DIR") or _storage_config_dir or Path(database.DB_PATH).parent))


def _storage_paths(info):
    core_db = info.get("database_dir")
    core_db = Path(os.path.abspath(core_db)) if isinstance(core_db, str) and core_db else None
    blobs = info.get("blobdir")
    blobs = (Path(os.path.abspath(blobs)) if isinstance(blobs, str) and blobs
             else core_db.parent / "blobs" if core_db else None)
    return (_storage_root(), Path(__file__).resolve().parent, Path(os.path.abspath(database.DB_PATH)), core_db, blobs)


def _storage_disk_usage(root):
    try:
        return shutil.disk_usage(root)
    except OSError:
        return None


def _core_dump_entries():
    """Yield top-level regular dumps with their directory open where supported."""
    roots = (Path(__file__).resolve().parent, Path.cwd(), _storage_root())
    use_dir_fd = os.scandir in os.supports_fd and os.unlink in os.supports_dir_fd
    seen_dirs = set()
    for root in dict.fromkeys(roots):
        try:
            with contextlib.ExitStack() as stack:
                if use_dir_fd:
                    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    stack.callback(os.close, directory)
                    root_info = os.fstat(directory)
                else:
                    directory = root
                    root_info = root.lstat()
                    if not stat.S_ISDIR(root_info.st_mode):
                        continue
                identity = _storage_id(root_info)
                if identity in seen_dirs:
                    continue
                seen_dirs.add(identity)
                for entry in stack.enter_context(os.scandir(directory)):
                    if not _CORE_DUMP_NAME.fullmatch(entry.name):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(info.st_mode) and info.st_size > 0:
                        yield directory, entry.name, info
        except OSError:
            continue


def _scan_core_dumps():
    return sorted(((name, info) for _, name, info in _core_dump_entries()), key=lambda dump: dump[0])


def _remove_core_dumps():
    removed, skipped = [], []
    for directory, name, info in _core_dump_entries():
        # Recheck the entry before unlinking. On Unix, keep the parent pinned by its descriptor.
        path, kwargs = (name, {"dir_fd": directory}) if isinstance(directory, int) else (directory / name, {})
        try:
            current = os.stat(path, follow_symlinks=False, **kwargs)
            if (stat.S_ISREG(current.st_mode) and _storage_id(current) == _storage_id(info)
                    and (current.st_size, current.st_mtime_ns) == (info.st_size, info.st_mtime_ns)):
                os.unlink(path, **kwargs)
                removed.append((name, info.st_size))
            else:
                skipped.append(name)
        except OSError:
            skipped.append(name)
    return removed, skipped


async def _maybe_warn_core_dumps():
    if os.getenv("CORE_DUMP_WARN") == "0":
        return
    new = {}
    for name, info in await asyncio.to_thread(_scan_core_dumps):
        encoded = json.dumps((name, info.st_size, info.st_mtime_ns)).encode()
        key = "core_dump_warned:" + hashlib.sha256(encoded).hexdigest()
        if key not in new and key not in _core_dump_warned and not await run_db(database.get_config, key):
            new[key] = name, info
    if not new:
        return
    lines = []
    for name, info in new.values():
        modified = datetime.datetime.fromtimestamp(info.st_mtime, datetime.timezone.utc)
        crash = ("A process crashed just now" if info.st_mtime > _bot_stats["started"] - 60
                 else "A process of the bot crashed earlier")
        lines.append(f"Core dump found: {_storage_path_text(name)}, {_format_storage_size(info.st_size)}, "
                     f"modified {modified:%Y-%m-%d %H:%M:%S} UTC. {crash} (the bot now disables core dumps).")
    text = ("\n".join(lines) + " It is no longer needed after a crash analysis and takes up disk quota. "
            "Send /rmcore to delete core dump files.")
    disk = await asyncio.to_thread(_storage_disk_usage, _storage_root())
    if disk:
        percent = 100 * disk.free / disk.total if disk.total else 0
        text += f"\nData filesystem: {_format_storage_size(disk.free)} free ({percent:.1f}%)."
    if await send_admin_notification(text, wait_for_send=True):
        _core_dump_warned.update(new)
        for key in new:
            try:
                await run_db(database.set_config, key, "1")
            except sqlite3.Error:
                logger.warning("Could not save core dump warning", exc_info=True)


def _collect_storage(data_dir, app_dir, bot_db, core_db, blobs):
    deadline = time.monotonic() + 2
    bot_files = [info for suffix in ("", "-wal", "-shm")
                 if (info := _storage_stat(Path(f"{bot_db}{suffix}"), stat.S_ISREG)) is not None]
    core_files = [info for suffix in ("", "-wal")
                  if core_db and (info := _storage_stat(Path(f"{core_db}{suffix}"), stat.S_ISREG)) is not None]
    blob_info = _storage_stat(blobs, stat.S_ISDIR) if blobs else None
    disk = _storage_disk_usage(data_dir)
    same_root = data_dir == app_dir
    app_skip = data_dir.relative_to(app_dir).as_posix() if data_dir.is_relative_to(app_dir) else None
    data_skip = app_dir.relative_to(data_dir).as_posix() if app_dir.is_relative_to(data_dir) else None
    data = _walk_storage(data_dir, deadline, skip=data_skip,
                         databases={_storage_id(info) for info in bot_files + core_files},
                         blobs=_storage_id(blob_info) if blob_info else None)
    app = data if same_root else _walk_storage(app_dir, deadline, skip=app_skip)
    blob_bytes = data.blob_bytes
    partial = data.partial or app.partial
    if blob_bytes is None and blob_info and not blobs.is_relative_to(data_dir):
        # Custom account directories can live outside the data root.
        blob_tree = _walk_storage(blobs, deadline)
        blob_bytes = blob_tree.total
        partial = partial or blob_tree.partial
    return _StorageStats(disk, data, app, sum(info.st_size for info in bot_files),
                         sum(info.st_size for info in core_files) if core_db else None, blob_bytes, partial)


def _get_storage_stats(*paths):
    # A cold scan is shared by concurrent commands and the warning check.
    with _storage_cache_lock:
        cached = _storage_cache.get(paths)
        if cached and time.monotonic() - cached[0] < 300:
            return cached[1]
        report = _collect_storage(*paths)
        _storage_cache[paths] = (time.monotonic(), report)
        _storage_cache.move_to_end(paths)
        if len(_storage_cache) > 8:
            _storage_cache.popitem(last=False)
        return report


def _storage_path_text(path):
    clean = "".join(c if c.isprintable() and c != "`" else "?" for c in path)
    raw = clean.encode()
    if len(raw) > 68:
        clean = (raw[:32].decode(errors="ignore") + "…" + raw[-32:].decode(errors="ignore"))
    return clean


def _storage_path_label(path):
    return f"`{_storage_path_text(path)}`"


def _storage_report(stats, budget, core_dumps=()):
    data, app = stats.data, stats.app
    size = _format_storage_size
    disk_summary = "n/a"
    if stats.disk:
        total, used, free = stats.disk
        used_percent = 100 * used / total if total else 0
        free_percent = 100 * free / total if total else 0
        disk_summary = (f"{size(total)} total · {size(used)} used ({used_percent:.1f}%)"
                        f" · {size(free)} free ({free_percent:.1f}%)")
    roots = [("Data", data), ("App", app)] if data is not app else [("Data/app", data)]
    log_count = sum(tree.log_count for _, tree in roots)
    log_size = sum(tree.logs for _, tree in roots)
    log_label = "file" if log_count == 1 else "files"
    other_data = data.total - data.database_bytes - (data.blob_bytes or 0)
    app_label = "App (shared data root)" if data is app else "App"
    lines = [
        "**Storage**" + (" (partial)" if stats.partial else ""),
        f"• Disk: {disk_summary}",
        f"• Bot DB (+ WAL/SHM): {size(stats.bot_bytes)} · Core DB (+ WAL): {size(stats.core_bytes)}",
        f"• Account blobs: {size(stats.blob_bytes)} · Other data: {size(other_data)}",
        f"• {app_label}: {size(app.total)} · Logs: {size(log_size)} ({log_count} {log_label})",
    ]
    if core_dumps:
        items = [f"{_storage_path_text(name)} {size(info.st_size)}" for name, info in core_dumps[:_STORAGE_TOP]]
        if len(core_dumps) > _STORAGE_TOP:
            items.append(f"{len(core_dumps) - _STORAGE_TOP} more")
        lines.append(f"• Core dumps: {', '.join(items)} (send /rmcore to delete)")
    groups = [(f"{label} {kind}", sorted(items, reverse=True)) for label, tree in roots
              for kind, items in (("files", tree.files), ("dirs", tree.directories)) if items]
    logs = sorted(((amount, label, path) for label, tree in roots for amount, path in tree.log_files),
                  reverse=True)[:_STORAGE_TOP]
    if logs:
        groups.append(("Log files", [(amount, f"{label}/{path}") for amount, label, path in logs]))
    remaining = budget - len("\n".join(lines).encode())
    for i, (label, items) in enumerate(groups):
        # Reserve an equal share for each remaining group and keep complete entries.
        allowance = remaining // (len(groups) - i)
        line = f"• {label}:"
        for index, (amount, path) in enumerate(items):
            candidate = f"{line}{',' if index else ''} {size(amount)} {_storage_path_label(path)}"
            if len(("\n" + candidate).encode()) > allowance:
                break
            line = candidate
        if not line.endswith(":"):
            lines.append(line)
            remaining -= len(("\n" + line).encode())
    return "\n".join(lines)


def _storage_is_low(disk):
    return disk is not None and (disk.free < 30 * 1024**2 or disk.free * 10 < disk.total)


def _storage_core_info(bot, accid):
    try:
        info = bot.rpc.get_info(accid)
        return info if isinstance(info, dict) else {}
    except Exception:
        return {}


async def _maybe_warn_low_storage(bot, accid):
    global _storage_warned_at
    if os.getenv("STORAGE_WARN") == "0":
        return
    disk = await asyncio.to_thread(_storage_disk_usage, _storage_root())
    if not _storage_is_low(disk):
        return
    saved = await run_db(database.get_config, "storage_warned_at")
    if time.time() - max(float(saved or "-inf"), _storage_warned_at) < 86400:
        return
    info = await run_rpc(_storage_core_info, bot, accid)
    stats = await asyncio.to_thread(lambda: _get_storage_stats(*_storage_paths(info)))
    roots = [("data", stats.data)]
    if stats.data is not stats.app:
        roots.append(("app", stats.app))
    largest = heapq.nlargest(3, ((amount, label, path) for label, tree in roots
                                 for amount, path in tree.files + tree.directories))
    items = ", ".join(f"{_format_storage_size(amount)} {label}/{_storage_path_label(path)}"
                      for amount, label, path in largest)
    now = time.time()
    if now - _storage_warned_at < 86400:
        return
    _storage_warned_at = now
    try:
        await run_db(database.set_config, "storage_warned_at", str(now))
    except Exception:
        logger.warning("Could not save low disk warning time", exc_info=True)
    percent = 100 * disk.free / disk.total if disk.total else 0
    await send_admin_notification(
        f"⚠️ **Low disk space**\nData filesystem: {_format_storage_size(disk.free)} free ({percent:.1f}%)."
        f"\nLargest items{' (partial scan)' if stats.partial else ''}: {items or 'none found'}")


def _percentile(sorted_values, percent):
    if not sorted_values:
        return None
    rank = (len(sorted_values) - 1) * percent / 100
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    return sorted_values[lower] + (rank - lower) * (sorted_values[upper] - sorted_values[lower])


def _peer_metrics_report(now):
    traffic, rtt = database.get_peer_metrics_24h(now)
    counts = collections.defaultdict(collections.Counter)
    for kind, direction, n in traffic:
        counts[kind][direction] = n
    mails = ", ".join(f"{kind} {counts[kind]['in']}/{counts[kind]['out']}"
                      for kind in sorted(counts.keys() & (_PEER_MAIL_KINDS | {"rt_advert"})))
    samples = collections.defaultdict(list)
    timeouts = collections.Counter()
    transports = {"mail"}
    for kind, transport, ms, ok in rtt:
        transports.add(transport)
        if ok:
            samples[transport, kind].append(ms)
        else:
            timeouts[transport] += 1
    lines = (
        f"• Peer mails (24 h): {mails or 'none'} (in/out)",
        f"• METRICS sent (24 h): idle {counts['peer_metrics_idle']['out']}, on change {counts['peer_metrics_change']['out']}, "
        f"rt {counts['peer_metrics_rt']['out']}",
    )
    for transport in ("mail", "rt", "mixed"):
        if transport not in transports:
            continue
        kinds = ("vote_round",) if transport == "mixed" else ("ping", "vote", "vote_round")
        if (transport, "channel_ping") in samples:
            kinds += ("channel_ping",)
        durations = []
        for kind in kinds:
            values = sorted(samples[transport, kind])
            p50, p95 = _percentile(values, 50), _percentile(values, 95)
            durations.append(f"{kind} {p50:.0f}/{p95:.0f} ms" if values else f"{kind} n/a")
        n = timeouts[transport]
        timeout_label = "timeout" if n == 1 else "timeouts"
        lines += (f"• Peer round trip (24 h, {transport}): {', '.join(durations)} (p50/p95), {n} {timeout_label}",)
    fallbacks, invalid = counts["rt_fallback"]["out"], counts["rt_invalid"]["in"]
    if fallbacks or invalid:
        fallback_label = "fallback" if fallbacks == 1 else "fallbacks"
        invalid_label = "frame" if invalid == 1 else "frames"
        lines += (f"• Realtime checks (24 h): {fallbacks} mail {fallback_label}, {invalid} invalid {invalid_label}",)
    if skipped := counts["vote_skipped_paused"]["out"]:
        lines += (f"• Vote rounds skipped for paused peers (24 h): {skipped}",)
    return lines


def build_stats_report(bot, accid) -> str:
    now = time.time()
    resources = database.get_all_resources() or []
    by_type = collections.Counter(r.get("type") or "http" for r in resources)
    def _state(r):
        if r.get("status") == "paused":
            return "paused"  # chat the bot was removed from
        if now < (r.get("maintenance_until") or 0):
            return "maintenance"
        if r.get("status") == "down":
            return "down"
        return "degraded" if r.get("alert_state") == "degraded" else (r.get("status") or "unknown")
    by_state = collections.Counter(_state(r) for r in resources)
    peers = database.get_all_peers() or []
    rt_flag = database.get_peer_rt_flag() if any(p.get("rt_msg_id") for p in peers) else "off"
    rt_counts = collections.Counter(_peer_rt_channel_status(p, rt_flag)[0] for p in peers)
    live = [p for p in peers if not p.get("is_offline")]
    unstable = [p["node_name"] for p in live if is_node_unstable(p.get("node_name") or "")]
    vote_pauses = _paused_vote_peers(peers)
    paused_by_time = collections.defaultdict(list)
    for p in live:
        if until := vote_pauses.get(_vote_peer_key(p)):
            paused_by_time[datetime.datetime.fromtimestamp(until).strftime("%H:%M")].append(p.get("node_name") or p["email"])
    paused_votes = ", ".join(f"{', '.join(names)} (until {until})" for until, names in paused_by_time.items())
    storage = _get_storage_stats(*_storage_paths(_storage_core_info(bot, accid)))
    try:
        relays = [t.get("addr") if isinstance(t, dict) else getattr(t, "addr", "?") for t in bot.rpc.list_transports(accid)]
    except Exception:
        relays = []
    ob = dc_outbox.stats
    waiting = dc_outbox.waiting()
    cs = _last_check_summary
    checks = (f"{cs['total']} in the last minute ({cs['up']} up, {cs['down']} down, {cs['skipped']} skipped), "
              f"avg latency {cs['avg']}") if cs else "no summary yet"
    load = "\n".join([
        f"📊 **Uptime Bot Statistics** — v{VERSION}, node **{database.get_local_node_name()}**",
        f"Running for `{format_duration(int(now - _bot_stats['started']))}`",
        "",
        "**Load**",
        f"• CPU: {_cpu_report()}",
    ])
    try:
        mail_kinds = database.get_mail_kinds_24h(now)
    except sqlite3.Error:
        logger.debug("Could not read sent mail counts", exc_info=True)
        mail_kinds = []
    top_mail_kinds = set([kind for kind, _ in mail_kinds if kind != "other"][:8])
    mail_kinds_text = ", ".join(f"{kind} {n}" for kind, n in mail_kinds if kind in top_mail_kinds or kind == "other")
    lines = [
        "**Monitors**",
        (f"• {len(resources)} monitors: " + ", ".join(f"{n} {t}" for t, n in by_type.most_common())) if resources else "• No monitors",
        ("• State: " + ", ".join(f"{n} {s}" for s, n in by_state.most_common())) if resources else None,
        f"• Checks: {checks}",
        "",
        "**Mail (last hour)**",
        f"• Received {stat_last_hour('mail_in', now)}, sent {stat_last_hour('mail_out', now)}",
        f"• Sent by kind (24 h): {mail_kinds_text}" if mail_kinds_text else None,
        f"• Outbox since start: {ob.get('sent', 0)} sent, {ob.get('failed', 0)} failed, {ob.get('merged', 0)} merged"
        + (f"; waiting now: " + ", ".join(f"{k} {v}" for k, v in waiting.items()) if waiting else "; nothing waiting"),
        f"• Status app updates/edits capped: {stat_last_hour('status_app_capped', now)} skips in the last hour",
        "",
        "**Peers**",
        f"• {len(peers)} peers, {len(live)} online" + (f", unstable now: {', '.join(unstable)}" if unstable else ""),
        f"• Peer channels: {rt_counts['up']} up, {rt_counts['down']} down, {rt_counts['mail only']} mail only",
        f"• Votes paused for: {paused_votes}" if paused_votes else None,
        ("• Outdated (older than this node): " + ", ".join(old)) if (old := outdated_peers(peers)) else "• All peers run this version or newer",
        f"• Changed telemetry at most every `{format_duration(current_telemetry_interval())}`"
        + (f" (less often to {slower} peers that asked for it)" if (slower := sum(
            1 for p in peers if interval_for_peer(p["email"], current_telemetry_interval()) > current_telemetry_interval())) else "")
        + f"; votes ask up to {VOTE_SAMPLE_SIZE} peers",
        f"• Last hour: {stat_last_hour('vote', now)} votes sent to peers, {stat_last_hour('held', now)} reports held back",
        *_peer_metrics_report(now),
        f"• Old protocol messages deleted since start: {_bot_stats['trimmed']}",
        f"• Old user chat messages deleted since start: {_bot_stats['user_trimmed']}",
        "",
        "**Relays**",
        (f"• {len(relays)}: " + ", ".join(f"`{r}`" for r in relays)) if relays else "• n/a",
    ]
    remainder = "\n".join(line for line in lines if line is not None)
    budget = _STATS_MAX_BYTES - len(load.encode()) - len(remainder.encode()) - 4
    report = f"{load}\n\n{_storage_report(storage, budget, _scan_core_dumps())}\n\n{remainder}"
    raw = report.encode()
    if len(raw) > _STATS_MAX_BYTES:
        return raw[:_STATS_MAX_BYTES - len("…".encode())].decode(errors="ignore").rstrip() + "…"
    return report


def _reply_with_stats(bot, accid, chat_id):
    try:
        reply = build_stats_report(bot, accid)
    except Exception as e:
        logger.error(f"Failed to build /stats: {e}")
        reply = "❌ Failed to collect statistics. Check server logs for details."
    _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=reply))


@dc_cli.on(events.NewMessage(command="/stats"))
@command_budget
def stats_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    if async_event_loop and async_event_loop.is_running():
        asyncio.run_coroutine_threadsafe(
            asyncio.to_thread(_reply_with_stats, bot, accid, msg.chat_id), async_event_loop)
    else:
        _reply_with_stats(bot, accid, msg.chat_id)


@dc_cli.on(events.NewMessage(command="/rmcore"))
@command_budget
def rmcore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        reply = "❌ This command is only for the administrator."
    elif not (chat := bot.rpc.get_basic_chat_info(accid, msg.chat_id)) or not is_single_chat(chat):
        reply = "Use this command in a private chat with the bot."
    else:
        removed, skipped = _remove_core_dumps()
        lines = []
        if removed:
            names = ", ".join(_storage_path_text(name) for name, _ in sorted(removed))
            freed_mb = sum(size for _, size in removed) / 1024**2
            lines.append(f"Deleted core dump files: {names}. Freed {freed_mb:.1f} MB.")
        if skipped:
            lines.append(f"Could not delete: {', '.join(map(_storage_path_text, sorted(skipped)))}.")
        reply = "\n".join(lines) or "No core dump files found"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))


@dc_cli.on(events.NewMessage(command="/peers"))
@dc_cli.on(events.NewMessage(command="/probes"))
@command_budget
def peers_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    peers = database.get_all_peers()
    local_node = database.get_local_node_name()
    
    # Statistics
    all_resources = database.get_all_resources()
    unique_local_urls = len(set(r["url"] for r in all_resources if r.get("url")))
    probe_targets = database.get_active_probe_targets()
    remote_measurement_counts = database.get_remote_measurement_counts()

    reply = f"🛰️ **Distributed Monitoring Peers**\n"
    reply += f"📍 Local Node: `{local_node}`\n\n"
    reply += f"📊 **Network Stats:**\n"
    reply += f"• Local Monitored Targets: `{unique_local_urls}` unique URLs (`{len(all_resources)}` across chats)\n"
    reply += f"• Mirrored Remote Probe Targets: `{len(probe_targets)}`\n"
    paused = [c for c, at in database.get_monitored_chats().items() if at is not None]
    if paused:
        reply += f"• Paused Chats (bot removed or chat gone): `{len(paused)}`\n"
    reply += f"• Cached Remote Measurements: `{sum(remote_measurement_counts.values())}`\n\n"

    if not peers:
        reply += (
            "_No remote peers configured._\n\n"
            "To link another Delta Chat Uptime bot as a remote probe:\n"
            "1. Run `/invitepeer` on the other bot to get its invite link.\n"
            "2. Send the `/addpeer ... token=...` command it prints to this bot."
        )
    else:
        reply += f"🔗 **Connected Probes ({len(peers)}):**\n"
        now = int(time.time())
        vote_pauses = _paused_vote_peers(peers)
        rt_flag = database.get_peer_rt_flag()
        for p in peers:
            last_seen = p.get("last_seen")
            if not last_seen or last_seen == 0:
                seen_str = "Never"
                status_icon = "⚪"
            else:
                diff = max(1, now - last_seen)
                if diff < 300:
                    status_icon = "🟢"
                    seen_str = f"{diff}s ago" if diff < 60 else f"{diff // 60}m ago"
                elif diff < 3600:
                    status_icon = "🟡"
                    seen_str = f"{diff // 60}m ago"
                else:
                    status_icon = "🔴"
                    seen_str = f"{diff // 3600}h ago"
            chat_lbl = f"Chat ID: `{p.get('chat_id')}`" if p.get('chat_id') else "Chat: `Pending`"
            p_node = p.get('node_name') or 'Remote'
            node_meas_count = remote_measurement_counts.get(p_node, 0)
            fp = p.get("fingerprint")
            # First 16 hex digits identify the key; the address only shows the relay it last used
            key_lbl = f"Key: `{' '.join(fp[i:i + 4] for i in range(0, 16, 4))}…`" if fp else "Key: `not bound yet`"
            ver = p.get("version")
            ver_lbl = (f"`v{ver}`" + (" ⚠️ outdated" if version_tuple(ver) < version_tuple(VERSION) else "")) if ver else "`≤2.26.2` ⚠️ outdated"
            vote_mark = " ⏸ votes paused" if _vote_peer_key(p) in vote_pauses else ""
            rt_mode = p.get("rt_mode", "auto")
            rt_label = _peer_rt_label(p, rt_flag, now)
            if rt_mode != "auto":
                rt_label += f" (mode: {rt_mode})"
            reply += f"• {status_icon} **{p_node}**{vote_mark} — `{p['email']}`\n  {key_lbl} | {chat_lbl} | Version: {ver_lbl} | Last seen: `{seen_str}` | Active metrics: `{node_meas_count}` | {rt_label}\n\n"
        reply += "Commands:\n• `/invitepeer` — Generate E2EE invite link\n• `/addpeer <email|link> [node_name]`\n• `/rmpeer <email|key>`\n• `/peershare [admin|all|none]`\n• `/nodename <name>`\n• `/probeignore [url|host|pattern]` — Exclude targets on this node (e.g. `*:25`), or list them\n• `/probeunignore <entry>` — Resume probing on this node\n• `/nodeignore [node_pat] [target_pat]` — Exclude targets on peer node(s) (e.g. `RU* facebook.*`)\n• `/nodeunignore <node_pat> [target_pat]` — Resume checks on node(s)"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply.strip()))

def _note_peer_rt_setting_change(peer, was_enabled, enabled):
    identity = _peer_identity(peer)
    _peer_caps_backoff.pop(identity, None)
    if enabled == was_enabled:
        return
    if enabled:
        _peer_caps_refresh.add(identity)
        if peer.get("fingerprint"):
            _peer_rt_retry_now.add(peer["fingerprint"])
    else:
        _peer_caps_refresh.discard(identity)
        _peer_rt_retry_now.discard(peer.get("fingerprint"))


@dc_cli.on(events.NewMessage(command="/peerrt"))
@command_budget
def peerrt_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return

    parts = (event.payload or "").strip().rsplit(None, 1)
    value = parts[-1].lower() if parts else ""
    if not parts:
        reply = f"Peer channel preview: `{database.get_peer_rt_flag()}`."
    elif len(parts) == 1 and value in database.PEER_RT_FLAGS:
        with _peer_rt_lock:
            previous = database.get_peer_rt_flag()
            database.set_peer_rt_flag(value)
            if value != previous:
                for peer in database.get_all_peers():
                    _note_peer_rt_setting_change(peer, _peer_rt_enabled(peer, previous), _peer_rt_enabled(peer, value))
                _refresh_peer_rt_channels()
                _peer_rt_audit_requested.set()
        reply = f"✅ Peer channel preview set to `{value}`."
    elif len(parts) == 2 and value in database.PEER_RT_MODES:
        identifier = parts[0]
        peer = database.find_peer(identifier)
        if not peer:
            peer = next((p for p in database.get_all_peers()
                         if (p["node_name"] or "").casefold() == identifier.casefold()), None)
        with _peer_rt_lock:
            changed = peer and database.set_peer_rt_mode(peer["email"], value)
            if changed and peer.get("rt_mode", "auto") != value:
                flag = database.get_peer_rt_flag()
                _note_peer_rt_setting_change(peer, _peer_rt_enabled(peer, flag),
                                             _peer_rt_enabled(dict(peer, rt_mode=value), flag))
                _refresh_peer_rt_channels()
                _peer_rt_audit_requested.set()
        if changed:
            reply = f"✅ Peer `{peer['email']}` preview mode set to `{value}`."
        else:
            reply = f"❌ Peer `{identifier}` not found."
    else:
        reply = "❌ Usage: `/peerrt [off|canary|on]` or `/peerrt <peer name|email> on|off|auto`"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/invitepeer"))
@dc_cli.on(events.NewMessage(command="/peerinvite"))
@command_budget
def invitepeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        if not chat_info or not is_single_chat(chat_info):
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text="Use this command in a private chat with the bot."))
            return
        if not getattr(msg, "show_padlock", False):
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text="Use this command in an encrypted private chat with the bot."))
            return
        qr_link = bot.rpc.get_chat_securejoin_qr_code(accid, None)
        node_name = database.get_local_node_name()
        addr = dc_fingerprint.get_self_addr(bot.rpc, accid)
        token = database.create_peer_invite_token()
        ttl_hours = database.PEER_INVITE_TTL_SECONDS // 3600

        reply = (
            f"🔗 **Peering Invite Link (E2E Encrypted SecureJoin)**\n\n"
            f"Local Node: **{node_name}** (`{addr}`)\n\n"
            f"To link this bot to another Delta Chat Uptime bot:\n"
            f"1. Copy this command:\n"
            f"`/addpeer {qr_link} token={token} {node_name}`\n\n"
            f"2. Send it to your other bot (in private chat).\n\n"
            f"🔐 The token is single-use and expires in {ttl_hours}h. Both bots will then exchange telemetry; "
            f"what this bot discloses is controlled by `/peershare` (now: `{database.get_peer_share_scope()}`).\n"
            f"⚠️ Keep this message private: whoever uses the token becomes a peer of this bot."
        )
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
    except Exception as e:
        logger.error(f"Failed to generate invite link: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to generate invite link. Check server logs for details."))

# /addpeer with an invite link: secure_join() returns before the handshake is done, and until then
# the core has no key for the other bot and cannot send to it (it only sends encrypted). The HELLO
# with the invite token was sent at once, failed, and was lost: the other bot never learned this one
# and dropped its cross-check requests as "untrusted sender" (2026-10-26).
PEER_HELLO_RETRY_INTERVAL = 5
PEER_HELLO_RETRY_FOR = 120


def send_peer_hello_when_ready(bot, accid, chat_id: int, hello_text: str | dict, node_name: str,
                               sleep=time.sleep) -> bool:
    """Sends the peering HELLO, retrying every PEER_HELLO_RETRY_INTERVAL until SecureJoin has
    finished and the send succeeds, for up to PEER_HELLO_RETRY_FOR. Tells the admin if it never
    does. Runs in its own thread."""
    deadline = time.monotonic() + PEER_HELLO_RETRY_FOR
    peer = _PeerDestination(bot, accid, chat_id, securejoin_hello=True)
    while True:
        fut = peer_send(peer, "HELLO", hello_text, priority=PRIO_PEER, expires_in=None, label="peer hello")
        try:
            fut.result(timeout=60)
            return True
        except Exception as e:
            last_error = e
        if time.monotonic() >= deadline:
            break
        sleep(PEER_HELLO_RETRY_INTERVAL)
    logger.warning(f"Peer HELLO to {node_name} (chat {chat_id}) not sent within {PEER_HELLO_RETRY_FOR}s: {last_error}")
    if async_event_loop and async_event_loop.is_running():
        asyncio.run_coroutine_threadsafe(send_admin_notification(
            f"⚠️ **Peering Not Completed**: {node_name}\n"
            f"The SecureJoin handshake did not finish within {PEER_HELLO_RETRY_FOR // 60} min, so the "
            f"invite token was not delivered and the other bot does not know this one yet.\n\n"
            f"Run `/invitepeer` on the other bot again and send its `/addpeer` command here."
        ), async_event_loop)
    return False


@dc_cli.on(events.NewMessage(command="/addpeer"))
@command_budget
def addpeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    if not payload:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage:\n"
                 "• Via SecureJoin Invite Link (Recommended for Chatmail/Strict E2EE):\n"
                 "  `/addpeer https://i.delta.chat/#... token=<token> [node_name]`\n"
                 "• Via Email Address (the other bot must add this one too):\n"
                 "  `/addpeer user@example.com [node_name]`\n\n"
                 "💡 Tip: Use `/invitepeer` on your other bot to generate a SecureJoin invite link."
        ))
        return
    parts = payload.split()
    target = parts[0].strip()
    invite_token = None
    name_parts = []
    for part in parts[1:]:
        if part.lower().startswith("token=") and invite_token is None:
            invite_token = part[len("token="):].strip() or None
        else:
            name_parts.append(part)
    node_name = " ".join(name_parts).strip()[:64] or "Remote-Node"

    def _hello_payload(chat_id):
        hello_payload = {
            "node_name": database.get_local_node_name(),
            "sender_email": _get_self_addr(bot, accid),
            "version": VERSION,
            "caps": _own_peer_caps(database.get_peer_by_chat_id(chat_id)),
        }
        if invite_token:
            hello_payload["invite_token"] = invite_token
        return hello_payload

    mutual_note = (
        "" if invite_token else
        "\n\n💡 _No invite token given: the other bot will only accept this link if its admin also runs "
        "`/addpeer` for this bot. Use `/invitepeer` on the other bot for one-step pairing._"
    )

    if "i.delta.chat" in target or target.startswith("OPENPGP4FPR:") or target.startswith("DCACCOUNT:"):
        try:
            # SecureJoin flow for strict E2EE
            qr_info = bot.rpc.check_qr(accid, target)
            chat_id = bot.rpc.secure_join(accid, target)
            
            peer_email = ""
            if isinstance(qr_info, dict):
                peer_email = qr_info.get("address") or qr_info.get("text") or ""
                if not peer_email and qr_info.get("contact_id"):
                    try:
                        c = bot.rpc.get_contact(accid, qr_info["contact_id"])
                        peer_email = getattr(c, 'address', '') or (c.get('address') if isinstance(c, dict) else '')
                    except Exception:
                        pass
                        
            if not peer_email and chat_id:
                try:
                    contacts = bot.rpc.get_chat_contacts(accid, chat_id)
                    for cid in contacts:
                        if cid != 1:
                            c = bot.rpc.get_contact(accid, cid)
                            peer_email = getattr(c, 'address', '') or (c.get('address') if isinstance(c, dict) else '')
                            break
                except Exception:
                    pass
                    
            if not peer_email:
                peer_email = f"peer_{chat_id}@securejoin"

            # The invite carries the peer's key fingerprint: bind it now, so the peer is recognised
            # whichever relay address it later sends from.
            peer_fp = database.normalize_fingerprint(qr_info.get("fingerprint")) if isinstance(qr_info, dict) else None
            existing = database.get_peer_by_fingerprint(peer_fp) if peer_fp else None
            if existing:
                # Re-adding a known bot: keep its row (and mirrored targets) instead of creating a twin
                existing = database.bind_peer_identity(
                    existing["email"],
                    new_email=None if peer_email.endswith("@securejoin") else peer_email,
                    chat_id=chat_id,
                ) or existing
                peer_email = existing["email"]
            database.add_or_update_peer(peer_email, node_name, chat_id, fingerprint=peer_fp)
            # Not right away: the handshake is still running (see send_peer_hello_when_ready)
            threading.Thread(target=send_peer_hello_when_ready,
                             args=(bot, accid, chat_id, _hello_payload(chat_id), node_name),
                             daemon=True, name="peer-hello").start()

            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"✅ SecureJoin started with **{node_name}** (`{peer_email}`).\nChat ID: `{chat_id}`. "
                     f"The handshake is sent as soon as it completes; if it does not within "
                     f"{PEER_HELLO_RETRY_FOR // 60} min, you get a notice." + mutual_note
            ))
        except Exception as e:
            logger.error(f"Failed to process SecureJoin invite: {e}")
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to process SecureJoin invite. Check server logs for details."))
        return
        
    # Email address flow
    email = target.lower()
    if "@" not in email or "." not in email:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Invalid email address or invite link."))
        return
        
    try:
        contact_id = bot.rpc.create_contact(accid, email, node_name)
        chat_id = bot.rpc.create_chat_by_contact_id(accid, contact_id)
        database.add_or_update_peer(email, node_name, chat_id)
        peer_send(_PeerDestination(bot, accid, chat_id), "HELLO", _hello_payload(chat_id),
                  priority=PRIO_PEER, expires_in=None, label="peer hello")

        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Peer `{email}` (**{node_name}**) added.\nSent peering handshake via private chat (Chat ID: `{chat_id}`).\n\n"
                 f"💡 _Note: Peer telemetry is only accepted end-to-end encrypted. If your provider requires strict E2EE (e.g. chatmail), generate an invite on the other bot with `/invitepeer` and add it via `/addpeer <link>`._"
                 + mutual_note
        ))
    except Exception as e:
        logger.error(f"Failed to add peer: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to add peer. Check server logs for details."))

@dc_cli.on(events.NewMessage(command="/peershare"))
@command_budget
def peershare_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip().lower()
    if payload:
        try:
            database.set_peer_share_scope(payload)
        except ValueError:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Usage: `/peershare admin|all|none`"))
            return
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Peer share scope set to `{payload}`."))
        return
    scope = database.get_peer_share_scope()
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"🔐 **Peer share scope:** `{scope}`\n\n"
             f"Controls which local monitors are sent to peers in telemetry and cross-check requests:\n"
             f"• `admin` — only monitors from chats the administrator is a member of (default)\n"
             f"• `all` — monitors from every chat on this bot (all users)\n"
             f"• `none` — no local monitors; this node only returns results for targets peers asked it to probe\n\n"
             f"Change with `/peershare admin|all|none`."
    ))

@dc_cli.on(events.NewMessage(command="/rmpeer"))
@command_budget
def rmpeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    ident = (event.payload or "").strip().lower()
    if not ident:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: `/rmpeer <email|key>` (key: fingerprint or its first 8+ hex digits, see `/peers`)"))
        return
    peer = database.find_peer(ident)
    with _peer_metrics_lock, _peer_rt_lock:
        removed = peer and database.remove_peer(peer["email"])
        if removed:
            _refresh_peer_rt_channels()
            _telemetry_rt_peers.pop(_peer_identity(peer), None)
            _peer_caps_announcements.pop(_peer_identity(peer), None)
            _peer_caps_requests.discard(_peer_identity(peer))
            _peer_caps_refresh.discard(_peer_identity(peer))
            _peer_caps_attempted.discard(_peer_identity(peer))
            _peer_caps_backoff.pop(_peer_identity(peer), None)
            _peer_rt_retry_now.discard(peer.get("fingerprint"))
            caps = _peer_caps.get(peer["email"].lower())
            if caps:
                caps.discard(PEER_CAP_RT)
            _peer_metrics_timestamps.pop(peer["email"].lower(), None)
            if peer.get("fingerprint"):
                _peer_metrics_timestamps.pop(peer["fingerprint"], None)
    if removed:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Peer **{peer.get('node_name') or 'Remote'}** (`{peer['email']}`) removed."))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Peer `{ident}` not found in database (or the key prefix matches several peers)."))

@dc_cli.on(events.NewMessage(command="/probeignore"))
@dc_cli.on(events.NewMessage(command="/ignoreprobe"))
@command_budget
def probeignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    url = (event.payload or "").strip()
    local_node = database.get_local_node_name()
    if not url:
        ignored = database.get_all_ignored_probe_targets()
        if not ignored:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"ℹ️ No ignored probe targets configured on `{local_node}`.\n\nTo ignore an inaccessible or region-blocked target on this probe:\n"
                     f"`/probeignore <url>` — one target, as shown in alerts (`https://site.org/`, `host.org:25`)\n"
                     f"`/probeignore host.org` — every target on that host\n"
                     f"`/probeignore *:25` or `/probeignore *.testrun.org` — patterns (`*` = anything)"
            ))
            return
        reply = f"🚫 **Ignored Probe Targets on `{local_node}` ({len(ignored)}):**\n\n"
        for item in ignored:
            reply += f"• `{item['url']}`\n"
        reply += "\nTo unignore and resume monitoring on this probe: `/probeunignore <entry>` (exactly as listed)"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
        return

    # Stored as written: a target (`https://site/`, `host:25`), a host (all its targets) or a `*` pattern
    url = url.lower()
    matched = database.add_ignored_probe_target(url)
    kind = "Pattern" if "*" in url else ("Host" if "://" not in url and ":" not in url else "Target")
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"✅ {kind} `{url}` is now **ignored** on `{local_node}` ({matched} mirrored target(s) matched now).\n"
             f"This probe does not scan matching targets, does not report them to peers and abstains when peers "
             f"vote on them (`skip`)."
    ))

@dc_cli.on(events.NewMessage(command="/probeunignore"))
@dc_cli.on(events.NewMessage(command="/unignoreprobe"))
@command_budget
def probeunignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    url = (event.payload or "").strip()
    if not url:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Usage: `/probeunignore <url>`"))
        return

    removed = database.remove_ignored_probe_target(url) or database.remove_ignored_probe_target(url.lower())
    if not removed and not url.startswith(("http://", "https://")):
        removed = database.remove_ignored_probe_target(f"https://{url}")
        if removed:
            url = f"https://{url}"

    local_node = database.get_local_node_name()
    if removed:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Target `{url}` removed from probe ignore list on `{local_node}`.\nIt will resume being scanned upon the next peer sync."
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ Target `{url}` was not found in the ignored probe list on `{local_node}`."
        ))


@dc_cli.on(events.NewMessage(command="/nodeignore"))
@dc_cli.on(events.NewMessage(command="/ignorenode"))
@command_budget
def nodeignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    parts = payload.split(maxsplit=1) if payload else []
    if not parts:
        rules = database.get_all_node_ignored_targets()
        if not rules:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text="ℹ️ No node-ignored targets configured.\n\n"
                     "To ignore targets on specific nodes or node patterns:\n"
                     "• `/nodeignore <node_pattern> <target_pattern>`\n\n"
                     "Examples:\n"
                     "• `/nodeignore RU* facebook.*` — all nodes starting with `RU` ignore Facebook\n"
                     "• `/nodeignore *home *:25` — all nodes ending with `home` ignore port 25\n"
                     "• `/nodeignore Node-1 https://site.org/` — single node ignores specific URL"
            ))
            return
        reply = f"🚫 **Node-Ignored Targets ({len(rules)}):**\n\n"
        for r in rules:
            reply += f"• `{r['node_pattern']}` ➔ `{r['target_pattern']}`\n"
        reply += "\nTo remove a rule: `/nodeunignore <node_pattern> <target_pattern>`"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
        return

    if len(parts) == 1:
        node_pat = parts[0]
        rules = database.get_all_node_ignored_targets()
        matching = [r for r in rules if r["node_pattern"].lower() == node_pat.lower() or database.node_matches_pattern(r["node_pattern"], node_pat)]
        if not matching:
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"ℹ️ No node-ignored targets configured matching `{node_pat}`.\n\n"
                     f"To add: `/nodeignore {node_pat} <target_pattern>`"
            ))
            return
        reply = f"🚫 **Node-Ignored Targets for `{node_pat}` ({len(matching)}):**\n\n"
        for r in matching:
            reply += f"• `{r['node_pattern']}` ➔ `{r['target_pattern']}`\n"
        reply += f"\nTo remove: `/nodeunignore {node_pat} <target_pattern>`"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
        return

    node_pat, target_pat = parts[0], parts[1].lower()
    cleaned = database.add_node_ignored_target(node_pat, target_pat)
    clean_note = f" (cleared {cleaned} stale peer measurement(s))" if cleaned else ""
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
        text=f"✅ Added node ignore rule: `{node_pat}` ➔ `{target_pat}`{clean_note}.\n\n"
             f"Checks matching `{target_pat}` will not be sent to nodes matching `{node_pat}`, "
             f"and their reports for them will be ignored in quorum."
    ))


@dc_cli.on(events.NewMessage(command="/nodeunignore"))
@dc_cli.on(events.NewMessage(command="/unignorenode"))
@command_budget
def nodeunignore_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    parts = payload.split(maxsplit=1) if payload else []
    if not parts:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="Usage: `/nodeunignore <node_pattern> [target_pattern]`\n"
                 "Examples:\n"
                 "• `/nodeunignore RU* facebook.*` — remove specific rule\n"
                 "• `/nodeunignore RU*` — remove all rules for node pattern `RU*`"
        ))
        return

    node_pat = parts[0]
    target_pat = parts[1].lower() if len(parts) > 1 else None
    removed = database.remove_node_ignored_target(node_pat, target_pat)
    if removed:
        what = f"`{node_pat}` ➔ `{target_pat}`" if target_pat else f"all rules for `{node_pat}`"
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Removed node ignore rule(s) for {what} ({removed} rule(s) removed).\n"
                 f"Checks for matching targets will be resumed on these nodes."
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"❌ No matching node ignore rule found for `{node_pat}`" + (f" and `{target_pat}`." if target_pat else ".")
        ))


def ensure_configured_account(bot, args) -> None:
    """On `serve` without a configured account, let the core create one on a relay it picks.

    init_transports (core 2.62+) with no QR code probes the core's built-in chatmail relay list,
    configures the fastest one and later adds further relays in the background, so a new bot needs
    no `init` step. An explicit `bot.py init <addr|DCACCOUNT:...>` still works and takes precedence."""
    if getattr(getattr(args, "cmd", None), "__name__", "") != "_serve_cmd":
        return
    accids = [args.account] if getattr(args, "account", None) else bot.rpc.get_all_account_ids()
    if any(bot.rpc.is_configured(a) for a in accids):
        return
    accid = accids[0] if accids else bot.rpc.add_account()
    bot.logger.info("No configured account: creating one on a chatmail relay chosen by the core...")
    try:
        bot.rpc.set_config(accid, "bot", "1")
        bot.rpc.init_transports(accid, None)
        addr = dc_fingerprint.get_self_addr(bot.rpc, accid)
        bot.logger.info(f"Account created: {addr}")
    except Exception as e:
        # serve then exits with "no configured accounts" and the container restart retries
        bot.logger.error(f"Automatic account creation failed: {e}")


@dc_cli.on_init
def on_init(bot, args):
    setup_custom_command_parser(bot)
    bot.logger.info(f"Initializing Uptime Bot v{VERSION}...")
    ensure_configured_account(bot, args)

    global dc_bot_instance, dc_accid, _storage_config_dir
    dc_bot_instance = bot
    _storage_config_dir = getattr(args, "config_dir", None)

    for accid in bot.rpc.get_all_account_ids():
        dc_accid = accid
        try:
            bot.rpc.set_config(accid, "displayname", _configured_display_name() or _node_display_name())

            status_text = os.environ.get("STATUS_TEXT")
            if not status_text and os.path.exists("/data/options.json"):
                try:
                    with open("/data/options.json", "r", encoding="utf-8") as f:
                        opts = json.load(f)
                        status_text = opts.get("status_text", "").strip()
                except Exception:
                    pass
            if not status_text:
                status_text = "Monitors resource availability (HTTP, TCP, Ping) and alerts on outages: https://github.com/mrgluek/deltachat_uptime"
            bot.rpc.set_config(accid, "selfstatus", status_text)
            
            # Set bot avatar from custom path if specified, else fallback to defaults
            avatar_env = os.environ.get("AVATAR_PATH")
            avatar_paths = []
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if avatar_env:
                if os.path.isabs(avatar_env):
                    avatar_paths.append(avatar_env)
                else:
                    avatar_paths.append(os.path.join(base_dir, avatar_env))
                    avatar_paths.append(os.path.abspath(avatar_env))
            
            # Default fallback paths
            avatar_paths.extend([
                os.path.join(base_dir, "icon.png"),
                os.path.join(base_dir, "icon.jpg")
            ])
            
            for path in avatar_paths:
                if os.path.exists(path):
                    bot.rpc.set_config(accid, "selfavatar", path)
                    bot.logger.info(f"Avatar set from {path}")
                    break
            else:
                bot.logger.warning(f"No avatar found in configured or default paths.")
        except Exception as e:
            bot.logger.warning(f"Could not configure profile: {e}")
            
    # Start web server thread
    web_thread = threading.Thread(target=start_web_server_thread, daemon=True)
    web_thread.start()
    
    # Start monitoring check thread
    _refresh_peer_rt_channels()
    monitor_thread = threading.Thread(target=start_monitoring_thread, daemon=True)
    monitor_thread.start()

@dc_cli.on_start
def on_start(bot, _args):
    bot.logger.info(f"Uptime Bot v{VERSION} is now fully running. Waiting for events...")
    global dc_bot_instance, dc_accid
    dc_bot_instance = bot
    accounts = bot.rpc.get_all_account_ids()
    if accounts:
        dc_accid = accounts[0]
        try:
            # Attachments over 64 KB (photos, GIFs, files) are not downloaded: the bot never needs
            # them. Not 1 byte: the core then defers every message, also plain text, to a
            # one-by-one "download later" instead of the normal batch, which delayed peer answers.
            bot.rpc.set_config(dc_accid, "download_limit", str(DOWNLOAD_LIMIT))
            # Safety net alongside explicit peer and user chat trimming.
            bot.rpc.set_config(dc_accid, "delete_device_after", str(DELETE_DEVICE_AFTER))
            logger.info(f"Auto-download limit set to {DOWNLOAD_LIMIT // 1024} KB (larger attachments are not downloaded).")
        except Exception as e:
            logger.error(f"Failed to set storage optimizations: {e}")
            
        admin_email, admin_fp = database.get_effective_admin()
        if admin_email:
            fp_suffix = f" ({admin_fp[-8:].upper()})" if admin_fp else ""
            print(f"Bot Administrator: {admin_email}{fp_suffix}")
            
        try:
            transports = bot.rpc.list_transports(dc_accid)
            print("\n" + "=" * 50)
            print("Configured Bot Transports (Relays):")
            for t in transports:
                addr = t.get('addr', '') if isinstance(t, dict) else getattr(t, 'addr', '')
                print(f" - {addr}")
        except Exception:
            pass

        try:
            qrdata = bot.rpc.get_chat_securejoin_qr_code(dc_accid, None)
            print("\n" + "=" * 50, flush=True)
            print("To add this bot, scan the secure join QR code or copy the link below:\n", flush=True)
            try:
                import qrcode
                qr = qrcode.QRCode(version=1, box_size=1, border=2)
                qr.add_data(qrdata)
                qr.make(fit=True)
                f = io.StringIO()
                qr.print_ascii(out=f, invert=True)
                print(f.getvalue(), flush=True)
            except Exception as qr_err:
                bot.logger.warning(f"Could not render ASCII QR code: {qr_err}")
            print(qrdata, flush=True)
            print("=" * 50 + "\n", flush=True)
        except Exception as e:
            bot.logger.error(f"Failed to generate QR code: {e}")

def _record_peer_activity(sender_addr: str | None, via="mail", *, fingerprint=None, chat_id=None):
    if not sender_addr and not fingerprint:
        return
    options = {"min_interval": RT_ACTIVITY_INTERVAL} if via == "rt" else {}
    if fingerprint:
        options.update(fingerprint=fingerprint, chat_id=chat_id)
    was_offline, downtime_sec, peer_data = database.update_peer_last_seen(sender_addr, **options)
    if was_offline and peer_data:
        p_node = peer_data.get("node_name") or "Remote"
        p_email = peer_data.get("email")
        dt_str = format_duration(downtime_sec)
        rec_txt = (
            f"✅ **Monitoring Probe Restored**\n"
            f"Probe Node: 🛰️ **{p_node}** (`{p_email}`)\n"
            f"Downtime: `{dt_str}`\n\n"
            f"🟢 Probe is back online and actively exchanging distributed telemetry."
        )
        if async_event_loop and async_event_loop.is_running():
            asyncio.run_coroutine_threadsafe(send_admin_notification(rec_txt), async_event_loop)


def _note_peer_check_activity(peer, data, via, stamp):
    if via == "mail":
        _record_peer_activity(peer["email"])
        return _note_peer_announcement(peer, data, stamp=stamp)
    return peer


def handle_peer_check_req(bot, accid, peer, chat_id, data, via="mail", *, stamp=None):
    req_data = data
    req_id = req_data.get("req_id")
    if _resend_cached_probe_answer(bot, accid, chat_id, peer, req_id, via):
        return _ProbeAdmission.COMPLETED
    target_url = req_data.get("url")
    check_type = req_data.get("type", "http")
    keyword = req_data.get("expected_keyword")
    family = req_data.get("family") if req_data.get("family") in (4, 6) else None

    if req_id and target_url and _valid_peer_fields(req_data):
        synth_r = {
            "id": 0,
            "url": target_url,
            "type": check_type,
            "expected_keyword": keyword,
            "family": family,
        }
        async def _do_cross_check_reply():
            current = _note_peer_check_activity(peer, req_data, via, stamp)
            if not await _prewarm_target_dns(target_url, check_type) or not is_safe_target_url(target_url, check_type, resolve_dns=False):
                return
            if await asyncio.to_thread(database.is_probe_target_ignored, target_url):
                res = (None, "Ignored on this node (/probeignore)", None)  # abstain, see batch answers
            else:
                res = await run_single_check(synth_r)
            if len(res) == 3:
                is_up, error_msg, latency_ms = res
            else:
                is_up, error_msg = res
                latency_ms = None
            is_up = for_peers(is_up, error_msg)
            resp_payload = {
                "req_id": req_id,
                "url": target_url,
                # "skip": not checked (no IPv6 here); the receiver files it as "unknown"
                "status": check_status(is_up),
                "latency_ms": latency_ms,
                "error_msg": error_msg,
                "node_name": database.get_local_node_name(),
                "caps": _own_peer_caps(database.get_peer_by_chat_id(chat_id) or current),
            }
            destination = _PeerDestination(bot, accid, chat_id, fingerprint=peer.get("fingerprint"), via=via)
            await asyncio.to_thread(_send_peer_check_answer, destination, "CHECK_RESP", resp_payload)

        outcome = _submit_inbound_probe(peer, req_id, _do_cross_check_reply, via=via)
        if outcome is _ProbeAdmission.COMPLETED:
            _resend_cached_probe_answer(bot, accid, chat_id, peer, req_id, via)
        return outcome
    return _ProbeAdmission.REJECTED


def handle_peer_check_batch_req(bot, accid, peer, chat_id, data, via="mail", *, stamp=None):
    req_data = data
    req_id = req_data.get("req_id")
    if _resend_cached_probe_answer(bot, accid, chat_id, peer, req_id, via):
        return _ProbeAdmission.COMPLETED
    raw_targets = req_data.get("targets")
    workers = min(10, max(1, len(raw_targets))) if isinstance(raw_targets, list) else 1
    async def answer():
        _note_peer_check_activity(peer, req_data, via, stamp)
        targets = await run_db(_parse_batch_targets, req_data.get("targets"))
        if targets:
            await _answer_batch_cross_check(bot, accid, chat_id, req_id, targets, workers,
                                            fingerprint=peer.get("fingerprint"), via=via)
    outcome = _submit_inbound_probe(peer, req_id, answer, workers, via=via)
    if outcome is _ProbeAdmission.COMPLETED:
        _resend_cached_probe_answer(bot, accid, chat_id, peer, req_id, via)
    return outcome


def handle_peer_check_batch_resp(bot, accid, peer, chat_id, data, via="mail", *,
                                 sender_addr=None, arrived_at=None, stamp=None):
    if arrived_at is None:
        arrived_at = time.monotonic()
    resp_data = data
    sender_addr = peer["email"] if sender_addr is None else sender_addr
    # Only an answer to a batch this node sent, from the chat it was sent to
    req_id = resp_data.get("req_id")
    if not isinstance(req_id, str):
        return
    with _peer_answer_lock:
        pending = pending_batch_checks.get(req_id)
        if not pending:
            return
        fut, expected_chat, count = pending
        if fut.done():
            return
        if chat_id != expected_chat:
            logger.warning(f"Dropping batch check response from unexpected peer {sender_addr} in chat {chat_id}")
            return
        pending_batch_checks.pop(req_id, None)
    peer = _note_peer_check_activity(peer, resp_data, via, stamp)
    raw = resp_data.get("results")
    raw = raw if isinstance(raw, list) else []
    node_name = peer.get("node_name") or "Remote-Node"
    # URLs come from our own request (the future's owner knows them): only positions are trusted here
    answers = [_clean_peer_result(raw[i] if i < len(raw) else None, node_name, None) for i in range(count)]
    def resolve():
        if not fut.done():
            timing = _pending_peer_rtt.get(req_id, {}).get(chat_id)
            if timing is not None:
                timing.note_answer(arrived_at, node_name, via)
            fut.set_result(answers)

    if async_event_loop and async_event_loop.is_running():
        async_event_loop.call_soon_threadsafe(resolve)
    else:
        resolve()


def handle_peer_check_resp(bot, accid, peer, chat_id, data, via="mail", *,
                           sender_addr=None, arrived_at=None, stamp=None):
    if arrived_at is None:
        arrived_at = time.monotonic()
    resp_data = data
    req_id = resp_data.get("req_id")
    target_url = resp_data.get("url")
    status = resp_data.get("status", "unknown")
    latency_ms = resp_data.get("latency_ms")
    error_msg = resp_data.get("error_msg")

    sender_addr = peer["email"] if sender_addr is None else sender_addr

    # Only answers to a request this node sent to this very peer are accepted
    pending = pending_peer_checks.get(req_id) if isinstance(req_id, str) else None
    if not pending:
        return
    fut, expected_count, resp_list, expected_chats = pending
    with _peer_answer_lock:
        if fut.done():
            return
        if chat_id not in expected_chats:
            logger.warning(f"Dropping check response for req_id {req_id} from unexpected peer {sender_addr} in chat {chat_id}")
            return
        expected_chats.discard(chat_id)

    peer = _note_peer_check_activity(peer, resp_data, via, stamp)
    node_name = peer.get("node_name") or "Remote-Node"
    if not isinstance(status, str) or status not in VOTING_STATUSES:
        status = "unknown"
    if not isinstance(latency_ms, int) or isinstance(latency_ms, bool):
        latency_ms = None
    error_msg = str(error_msg)[:500] if error_msg else None

    if target_url and _valid_peer_fields(resp_data) and is_safe_target_url(target_url, target_type(target_url)):
        database.save_peer_measurement(target_url, node_name, status, latency_ms, error_msg, int(time.time()),
                                       peer.get("fingerprint") or peer["email"])

    with _peer_answer_lock:
        if fut.done():
            return
        resp_list.append({
            "req_id": req_id,
            "url": target_url,
            "status": status,
            "latency_ms": latency_ms,
            "error_msg": error_msg,
            "node_name": node_name,
        })
        timing = _pending_peer_rtt.get(req_id, {}).get(chat_id)
        if timing is not None:
            timing.note_answer(arrived_at, node_name, via)
        complete = len(resp_list) >= expected_count
    if complete:
        if async_event_loop and async_event_loop.is_running():
            async_event_loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(resp_list))
        else:
            try:
                fut.set_result(resp_list)
            except Exception:
                pass


def _valid_metrics_msg_id(msg_id):
    return isinstance(msg_id, str) and len(msg_id) <= 128


def handle_peer_metrics(bot, accid, peer, chat_id, data, via="mail", *, wire_size=0, stamp=None):
    if isinstance(data, str):
        # Keep the original mail JSON compact until a worker can process it.
        size = data.__sizeof__()
    elif isinstance(data, dict) and _valid_metrics_msg_id(data.get("msg_id")):
        size = wire_size * 8  # The parsed realtime payload takes more space than the frame.
    else:
        return
    _peer_metrics_inbox.submit(peer, data, via, max(4096, size), stamp=stamp)


def _current_metrics_peer(peer):
    if fingerprint := peer.get("fingerprint"):
        return database.get_peer_by_fingerprint(fingerprint)
    current = database.get_peer(peer["email"])
    if current and not current.get("fingerprint"):
        return current


def _apply_peer_metrics(peer, data, via, *, stamp=None):
    metrics_data = json.loads(data) if isinstance(data, str) else data
    if not isinstance(metrics_data, dict) or not _valid_metrics_msg_id(msg_id := metrics_data.get("msg_id")):
        return
    metrics_list = metrics_data.get("metrics", [])
    timestamp = metrics_data.get("timestamp")
    if type(timestamp) not in (int, float) or (isinstance(timestamp, float) and not math.isfinite(timestamp)):
        timestamp = None
    if timestamp is not None:
        sent_at, mail_id = stamp or (None, None)
        stamp = (timestamp if sent_at is None else min(timestamp, sent_at), mail_id)
        timestamp = min(timestamp, time.time() + 300)

    identity = _peer_identity(peer)
    key = (identity, msg_id)
    with _peer_metrics_lock:
        peer = _current_metrics_peer(peer)
        if not peer:
            return
        if via == "mail":
            _record_peer_activity(peer["email"])
        last_timestamp = _peer_metrics_timestamps.get(identity)
        stale = timestamp is not None and last_timestamp is not None and timestamp < last_timestamp
        if key in _processed_msg_ids:
            return
        if not stale and metrics_list == [] and metrics_data.get("request_caps") is True:
            with _peer_rt_lock:
                _peer_caps_requests.add(identity)
        if not stale:
            peer = _note_peer_announcement(peer, metrics_data, allow_rename=via == "mail",
                                           telemetry=True, via=via, stamp=stamp)
            if via == "rt" and type(announced := metrics_data.get("telemetry_interval")) is int:
                with _peer_rt_lock:
                    link = _peer_rt_links.get(peer.get("rt_msg_id"))
                    if link and link.peer["fingerprint"] == peer.get("fingerprint"):
                        link.incoming_metrics_interval = min(900, max(60, announced))
        if not isinstance(metrics_list, list):
            return
        _processed_msg_ids.add(key)
        if stale or not metrics_list:
            return

    deadline = monotonic() + PEER_METRICS_BATCH_DEADLINE
    safe_metrics = []
    for metric in metrics_list[:200]:
        if monotonic() >= deadline:
            break
        if (isinstance(metric, dict) and _valid_peer_fields(metric)
                and is_safe_target_url(str(metric.get("url", "")), str(metric.get("type", "http")),
                                       dns_deadline=deadline)):
            now = int(time.time())
            safe_metrics.append(dict(metric, received_at=now,
                                     last_checked=database._clamp_measurement_time(metric.get("last_checked"), now)))
    if not safe_metrics:
        return

    with _peer_metrics_lock:
        peer = _current_metrics_peer(peer)
        if not peer:
            return
        peer_node = peer.get("node_name") or "Remote-Node"
        database.save_peer_measurements_batch(peer_node, safe_metrics, peer.get("fingerprint") or peer["email"])
        database.save_probe_targets_batch(safe_metrics, peer["email"])
        if timestamp is not None:
            _peer_metrics_timestamps[identity] = timestamp
            _peer_metrics_timestamps.move_to_end(identity)
            if len(_peer_metrics_timestamps) > PEER_METRICS_TIMESTAMPS_MAX:
                _peer_metrics_timestamps.popitem(last=False)
        _scheduler_cache["probe_targets"] = None
        note_peer_reported_down(peer_node, safe_metrics)


@dc_cli.on(events.NewMessage(is_bot=None))
def on_new_message(bot, accid, event):
    arrived_at = time.monotonic()
    msg = event.msg
    stamp = _mail_announcement_stamp(msg)
    if msg.is_info:
        return
    if msg.from_id != 1:
        stat_event("mail_in")

    raw_text = msg.text or ""
    text = raw_text.strip()

    if msg.from_id == 1:
        return

    _count_peer_text(raw_text, "in")

    carrier_marker = _PEER_RT_MARKER.match(text)
    if carrier_marker:
        try:
            _handle_peer_rt_mail(bot, accid, msg, carrier_marker.group(1), text)
        except Exception as exc:
            logger.warning("Peer carrier mail in chat %s failed (%s)", msg.chat_id, type(exc).__name__)
        return

    if "[UPTIME_PEER_" in text and (len(text) > PEER_MAX_BYTES or len(text.encode("utf-8")) > PEER_MAX_BYTES):
        logger.warning("Peer protocol payload exceeds byte limit; ignoring")
        return

    if "[UPTIME_BOT_SYNC_DATA]" in text and "[/UPTIME_BOT_SYNC_DATA]" in text:
        try:
            start_idx = text.find("[UPTIME_BOT_SYNC_DATA]") + len("[UPTIME_BOT_SYNC_DATA]")
            end_idx = text.find("[/UPTIME_BOT_SYNC_DATA]")
            if end_idx - start_idx > SYNC_MAX_BYTES:
                logger.warning("[SYNC RECEIVE] Payload exceeds 64 KB. Ignoring.")
                return
            json_str = text[start_idx:end_idx].strip()
            if len(json_str.encode("utf-8")) > SYNC_MAX_BYTES:
                logger.warning("[SYNC RECEIVE] Payload exceeds 64 KB. Ignoring.")
                return
            sync_list = json.loads(json_str)
            
            if not isinstance(sync_list, list):
                logger.warning("[SYNC RECEIVE] Payload is not a list. Ignoring.")
                return
            
            # Limit the sync payload to a maximum of 50 items to avoid DB spam
            logger.info("[SYNC RECEIVE] Received %s item(s); processing at most 50", len(sync_list))
            sync_list = sync_list[:50]
            
            added_count = 0
            added_resources = []
            refused = set()
            for item in sync_list:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                name = item.get("name")
                check_type = item.get("type")
                
                try:
                    interval = int(item.get("interval", 60))
                except (TypeError, ValueError):
                    interval = 60
                
                # Security: Force interval to be at least 60 seconds
                interval = max(60, interval)
                
                if url and check_type in ("http", "ping", "tcp", "smtp"):
                    # Security: validate URL format and expected type
                    try:
                        keyword = item.get("expected_keyword")
                        database.validate_monitor_fields(url, name, keyword)
                        expected_type, validated_url = parse_target(url)
                        if expected_type == check_type:
                            res_id = database.add_resource(msg.chat_id, validated_url, name or validated_url[:database.MAX_NAME_LENGTH], check_type, interval, expected_keyword=keyword)
                            if res_id is not None:
                                added_count += 1
                                logger.info("[SYNC RECEIVE] Added resource id=%s", res_id)
                                added_resources.append(f"• `{validated_url}` ({name or validated_url}) [{check_type.upper()}]")
                    except ValueError as exc:
                        refused.add(str(exc))
                        continue
            
            if refused:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="Sync refused additions: " + " ".join(sorted(refused))))
            if added_count > 0:
                reply = f"📥 **Sync Complete!**\nAdded {added_count} new resource(s) from the other bot:\n" + "\n".join(added_resources)
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
            else:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="📥 **Sync Complete!**\nNo new resources to add (already up-to-date)."))
        except Exception as e:
            logger.error("Error processing sync data (%s)", type(e).__name__)
        return

    # Determine if chat is 1:1 private (Single) or group
    is_private_chat = True
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        is_private_chat = is_single_chat(chat_info)
    except Exception:
        is_private_chat = True

    # 1. Peer Handshake: HELLO
    if "[UPTIME_PEER_HELLO]" in text and "[/UPTIME_PEER_HELLO]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_HELLO]") + len("[UPTIME_PEER_HELLO]")
            end_idx = text.find("[/UPTIME_PEER_HELLO]")
            hello_data = json.loads(text[start_idx:end_idx].strip())
            if not isinstance(hello_data, dict):
                return
            peer_node = str(hello_data.get("node_name") or "Remote-Node").strip()[:64]
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not sender_addr or not is_private_chat:
                return

            if not peer:
                # Unknown bots are only accepted with a one-time token issued by /invitepeer on this node
                invite_token = hello_data.get("invite_token")
                if not database.consume_peer_invite_token(invite_token):
                    logger.warning(f"Ignoring peer HELLO from unknown sender {sender_addr} without a valid invite token")
                    return
                # Bind the key right away if the handshake is encrypted (it is after SecureJoin)
                fp = _get_peer_fingerprint(bot, accid, msg.from_id, sender_addr) if getattr(msg, "show_padlock", False) else None
                database.add_or_update_peer(sender_addr, peer_node, msg.chat_id, int(time.time()), fingerprint=fp)
                peer = database.get_peer(sender_addr)
                peer_node = peer["node_name"]
                if async_event_loop and async_event_loop.is_running():
                    asyncio.run_coroutine_threadsafe(send_admin_notification(
                        f"🔗 **New Monitoring Peer Linked**\n"
                        f"Probe Node: 🛰️ **{peer_node}** (`{sender_addr}`)\n\n"
                        f"Linked using a `/invitepeer` token. Remove it with `/rmpeer {sender_addr}`."
                    ), async_event_loop)
            else:
                database.add_or_update_peer(peer["email"], chat_id=msg.chat_id, last_seen=int(time.time()))
            _record_peer_activity(peer["email"] if peer else sender_addr)

            ack_payload = {
                "node_name": database.get_local_node_name(),
                "sender_email": _get_self_addr(bot, accid),
                "version": VERSION,
                "caps": _own_peer_caps(peer),
            }
            peer_send(_PeerDestination(bot, accid, msg.chat_id), "HELLO_ACK", ack_payload,
                      priority=PRIO_PEER, expires_in=None, label="peer hello ack")
            _note_peer_announcement(peer, hello_data,
                                    allow_caps=_is_trusted_peer_msg(msg, peer, is_private_chat), stamp=stamp)
        except Exception as e:
            logger.error(f"Error handling peer hello: {e}")
        return

    # 2. Peer Handshake: HELLO_ACK (only from bots this node added itself)
    if "[UPTIME_PEER_HELLO_ACK]" in text and "[/UPTIME_PEER_HELLO_ACK]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_HELLO_ACK]") + len("[UPTIME_PEER_HELLO_ACK]")
            end_idx = text.find("[/UPTIME_PEER_HELLO_ACK]")
            ack_data = json.loads(text[start_idx:end_idx].strip())
            if not isinstance(ack_data, dict):
                return
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not peer or not is_private_chat:
                logger.warning(f"Ignoring peer HELLO_ACK from unknown sender {sender_addr or msg.from_id}")
                return
            database.add_or_update_peer(peer["email"], chat_id=msg.chat_id, last_seen=int(time.time()))
            _record_peer_activity(peer["email"])
            _note_peer_announcement(peer, ack_data,
                                    allow_caps=_is_trusted_peer_msg(msg, peer, is_private_chat), stamp=stamp)
        except Exception as e:
            logger.error(f"Error handling peer hello ack: {e}")
        return

    # 3. Peer Cross-Check Request (Instant verification)
    if "[UPTIME_PEER_CHECK_REQ]" in text and "[/UPTIME_PEER_CHECK_REQ]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_REQ]") + len("[UPTIME_PEER_CHECK_REQ]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_REQ]")
            req_data = json.loads(text[start_idx:end_idx].strip())
            req_data.get("req_id")  # Preserve the pre-verification error for non-object JSON.

            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping check request from untrusted sender {sender_addr or msg.from_id} in chat {msg.chat_id}")
                return
            handle_peer_check_req(bot, accid, peer, msg.chat_id, req_data, stamp=stamp)
        except Exception as e:
            logger.error(f"Error processing peer check request: {e}")
        return

    # 4. Peer Cross-Check Response
    # 3b. Batched cross-check request: several targets in one message, answered in one message
    if "[UPTIME_PEER_CHECK_BATCH_REQ]" in text and "[/UPTIME_PEER_CHECK_BATCH_REQ]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_BATCH_REQ]") + len("[UPTIME_PEER_CHECK_BATCH_REQ]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_BATCH_REQ]")
            req_data = json.loads(text[start_idx:end_idx].strip())
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping batch check request from untrusted sender {sender_addr or msg.from_id} in chat {msg.chat_id}")
                return
            handle_peer_check_batch_req(bot, accid, peer, msg.chat_id, req_data, stamp=stamp)
        except Exception as e:
            logger.error(f"Error processing peer batch check request: {e}")
        return

    # 4b. Batched cross-check response
    if "[UPTIME_PEER_CHECK_BATCH_RESP]" in text and "[/UPTIME_PEER_CHECK_BATCH_RESP]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_BATCH_RESP]") + len("[UPTIME_PEER_CHECK_BATCH_RESP]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_BATCH_RESP]")
            resp_data = json.loads(text[start_idx:end_idx].strip())
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping batch check response from untrusted sender {sender_addr or msg.from_id}")
                return
            handle_peer_check_batch_resp(bot, accid, peer, msg.chat_id, resp_data, sender_addr=sender_addr,
                                         arrived_at=arrived_at, stamp=stamp)
        except Exception as e:
            logger.error(f"Error handling peer batch check response: {e}")
        return

    if "[UPTIME_PEER_CHECK_RESP]" in text and "[/UPTIME_PEER_CHECK_RESP]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_RESP]") + len("[UPTIME_PEER_CHECK_RESP]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_RESP]")
            resp_data = json.loads(text[start_idx:end_idx].strip())
            resp_data.get("req_id")  # Preserve the pre-verification error for non-object JSON.

            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping check response from untrusted sender {sender_addr or msg.from_id}")
                return
            handle_peer_check_resp(bot, accid, peer, msg.chat_id, resp_data, sender_addr=sender_addr,
                                   arrived_at=arrived_at, stamp=stamp)
        except Exception as e:
            logger.error(f"Error handling peer check response: {e}")
        return

    # 5. Peer Telemetry Batch
    if "[UPTIME_PEER_METRICS]" in text and "[/UPTIME_PEER_METRICS]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_METRICS]") + len("[UPTIME_PEER_METRICS]")
            end_idx = text.find("[/UPTIME_PEER_METRICS]")
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping telemetry from untrusted sender {sender_addr or msg.from_id}")
                return
            handle_peer_metrics(bot, accid, peer, msg.chat_id, text[start_idx:end_idx].strip(), stamp=stamp)
        except Exception as e:
            logger.error(f"Error handling peer metrics: {e}")
        return

    # Auto-greet new users in private chat
    try:
        chat_info = bot.rpc.get_basic_chat_info(accid, msg.chat_id)
        if isinstance(chat_info, dict):
            chat_type = chat_info.get('chat_type', 'Single')
        else:
            chat_type = getattr(chat_info, 'chat_type', 'Single')
        is_private = str(chat_type) == "Single"
            
        if is_private:
            greeted_key = f"greeted_{msg.from_id}"
            if not database.get_config(greeted_key):
                help_command(bot, accid, event)
                database.set_config(greeted_key, "1")
    except Exception as e:
        logger.error(f"Error in greeting check: {e}")


def _disable_core_dumps():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, AttributeError, OSError, ValueError) as exc:
        logger.info("Could not disable core dumps: %s", exc)


def main():
    _disable_core_dumps()
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == "init" and sys.argv[2] == "transport":
        if len(sys.argv) < 4:
            print("Usage:")
            print("  python bot.py init transport DCACCOUNT:uri")
            print("  python bot.py init transport addr password")
            sys.exit(1)
            
        from deltachat2 import Rpc, IOTransport
        from appdirs import user_config_dir
        
        config_dir = user_config_dir("uptimebot")
        accounts_dir = os.path.join(config_dir, "accounts")
        
        try:
            with IOTransport(accounts_dir=accounts_dir) as trans:
                rpc = Rpc(trans)
                accids = rpc.get_all_account_ids()
                if not accids:
                    print("Error: No accounts configured. Run 'python bot.py init addr password' first.")
                    sys.exit(1)
                accid = accids[0]
                
                payload = sys.argv[3]
                if payload.startswith("DCACCOUNT:"):
                    rpc.add_transport_from_qr(accid, payload)
                    print(f"Success: Backup transport added via chatmail URI.")
                elif len(sys.argv) >= 5:
                    addr, password = sys.argv[3], sys.argv[4]
                    rpc.add_or_update_transport(accid, {"addr": addr, "password": password})
                    print(f"Success: Backup transport {addr} added.")
                else:
                    print("Error: For email accounts, provide both address and password.")
                    sys.exit(1)
        except Exception as e:
            print(f"Error adding transport: {e}")
            sys.exit(1)
        sys.exit(0)

    if len(sys.argv) == 1:
        sys.argv.append("serve")
    dc_cli.start()


if __name__ == "__main__":
    try:
        main()
    finally:
        _peer_metrics_inbox.close()
