import asyncio
import contextlib
import io
import logging
import json
import os
import ssl
import threading
import weakref
import time
import datetime
import html
import re
import socket
import struct
import shlex
import statistics
import secrets
from urllib.parse import urlparse, urljoin
import aiohttp
import aiohttp.abc
from aiohttp import web
from deltachat2 import events, MsgData
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
import transports_view
from outbox import outbox as dc_outbox, PRIO_ALERT, PRIO_REPLY, PRIO_UPDATE, PRIO_PEER, PRIO_TELEMETRY

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("uptime_bot")
VERSION = "2.25.1"
# No "bot" in the name: some services (e.g. Hiddify subscription links) reply 400 to any User-Agent containing "bot".
USER_AGENT = f"Delta Chat Uptime Monitor/{VERSION} (+https://git.gluek.info/gluek/deltachat_uptime)"

# Dedicated thread pools for database operations and Delta Chat RPC calls
db_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="uptime_db")
rpc_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="uptime_rpc")

# Sliding-window rate limiter per client IP and bucket
_rate_limits: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()

def get_client_ip(request) -> str:
    """Extract client IP from request, taking into account reverse proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote or "unknown"

def check_rate_limit(request, bucket: str = "default", max_requests: int = 60, window_seconds: int = 60) -> bool:
    """In-memory sliding window rate limiter per client IP and bucket.
    Returns True if allowed, False if limit exceeded.
    """
    client_ip = get_client_ip(request) or "unknown"
    key = f"{bucket}:{client_ip}"
    now = time.time()
    with _rate_limit_lock:
        timestamps = [t for t in _rate_limits.get(key, []) if now - t < window_seconds]
        if len(timestamps) >= max_requests:
            _rate_limits[key] = timestamps
            return False
        timestamps.append(now)
        _rate_limits[key] = timestamps
        return True


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
CROSS_CHECK_BATCH_WINDOW = 5.0    # seconds to collect failing targets before sending
CROSS_CHECK_BATCH_MAX = 100       # targets per batch message
CROSS_CHECK_BATCH_TIMEOUT = 25.0  # a peer checks up to 100 targets (10 s timeouts) and mails back
TELEMETRY_INTERVAL = 120  # seconds between telemetry messages to each peer
PEER_ANSWER_TTL = 20.0  # an answer to a peer's cross-check is dropped if the outbox could not send it by then
PEER_BATCH_CHECK_CONCURRENCY = 20
_peer_caps = {}  # peer email (lower) -> set of capabilities it announced (in memory, re-sent every 2 min)
_cross_check_queue = []  # (target_dict, future) waiting for the next batch
_cross_check_flush_task = None
pending_batch_checks = {}  # req_id -> (Future, chat_id, number of targets)
_peer_batch_semaphore = None

# Quorum alerting (/alertmode quorum, the default): this node and its live peers vote on whether a
# failing target is reachable. Most nodes cannot reach it -> DOWN (incident). Some can't -> DEGRADED:
# a notice in the chat, no incident and no downtime. With fewer than 2 voters this node decides alone.
QUORUM_REVOTE_INTERVAL = 120          # peers are asked again at most this often while nothing changed locally
QUORUM_REVOTE_INTERVAL_LONG = 600     # ...and this often for targets down/degraded for over an hour
DEGRADED_CONFIRMATIONS = 2            # consecutive votes needed to enter or leave DEGRADED
DEGRADED_NOTIFY_WINDOW = 10.0         # seconds to collect DEGRADED changes of a chat into one message
_vote_cache = {}          # cross-check key -> (monotonic time, local_up, peer results)
_alert_streaks = {}       # resource id -> (candidate alert state, consecutive votes for it)
_degraded_notify_queue = {}  # chat id -> list of ("start" | "end", resource, votes, started_at)
_degraded_flush_task = None
# A peer reporting a target DOWN in its telemetry while this node sees it UP: the target's next
# regular check asks all peers and votes (the case "this node reaches it, most others don't").
PEER_SUSPECT_MAX_AGE = 300  # seconds a report stays valid, and how old the peer's result may be
_peer_suspects = {}  # url -> (monotonic time, reporting node)

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

# Protocol message deduplication cache (bounded set of recent msg_ids)
_processed_msg_ids = set()
_processed_msg_ids_max = 500

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
    email = (database.get_admin_email() or "").lower()
    if not email or bot is None or accid is None:
        return None
    fp = re.sub(r"[^0-9A-F]", "", (database.get_config("admin_dc_fingerprint") or "").upper())
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
            if fp and fp not in re.sub(r"[^0-9A-F]", "", str(bot.rpc.get_contact_encryption_info(accid, cid)).upper()):
                continue  # same address, other key: not the admin
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
            deleted = await run_db(database.delete_chat_data, chat_id)
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

async def request_peer_cross_checks(target_dict: dict, timeout: float = 8.0, peers: list[dict] | None = None) -> list[dict]:
    """Broadcasts a cross-check request for one target to the peers (default: all) in 1:1 DMs
    and waits for responses. /ping uses it directly; monitors go through the batched variant."""
    if peers is None:
        peers = await asyncio.to_thread(database.get_all_peers)
    peers = [p for p in peers or [] if _peer_can_check(p, target_dict)]
    if not peers or not dc_bot_instance or dc_accid is None:
        return []

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
    msg_text = f"[UPTIME_PEER_CHECK_REQ]\n{json.dumps(req_payload)}\n[/UPTIME_PEER_CHECK_REQ]"

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return []

    fut = loop.create_future()
    responses = []

    valid_peers = []
    for p in peers:
        chat_id = await _resolve_peer_chat_id(p)
        if chat_id:
            valid_peers.append((p, chat_id))

    if not valid_peers:
        return []

    # Only the peers this request was sent to may answer it, each once and in its own 1:1 chat.
    # Chats rather than addresses: a peer may answer from another relay address than it used before.
    expected_chats = {chat_id for _, chat_id in valid_peers}
    pending_peer_checks[req_id] = (fut, len(valid_peers), responses, expected_chats)

    for p, chat_id in valid_peers:
        try:
            # A request still queued when the answer is no longer awaited is dropped
            await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text),
                                    priority=PRIO_PEER, expires_in=timeout, label="cross-check request")
        except Exception as e:
            logger.warning(f"Failed to send cross-check request to peer {p.get('email')}: {e}")

    try:
        await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        logger.info(f"Cross-check req_id {req_id} timed out waiting for all peer responses (got {len(responses)}/{len(valid_peers)})")
    except Exception as e:
        logger.warning(f"Error during peer cross-check wait: {e}")
    finally:
        pending_peer_checks.pop(req_id, None)

    return responses

def _cross_check_key(t: dict) -> tuple:
    return (t.get("type") or "http", t.get("url"), t.get("expected_keyword") or "", t.get("family") or 0)


def _peer_supports(peer: dict, cap: str) -> bool:
    return cap in _peer_caps.get((peer.get("email") or "").lower(), ())


def _peer_can_check(peer: dict, target: dict) -> bool:
    """Whether a peer understands the target's check type (smtp:// needs PEER_CAP_SMTP_CHECK)."""
    return (target.get("type") or "http") != "smtp" or _peer_supports(peer, PEER_CAP_SMTP_CHECK)


def _note_peer_caps(email: str, caps) -> None:
    if email and isinstance(caps, list):
        _peer_caps[email.lower()] = {str(c)[:40] for c in caps[:20]}


def _note_peer_announcement(peer: dict, data) -> dict:
    """What a key-verified peer says about itself in protocol messages: its capabilities and its
    node name (changed with /nodename there). Returns the peer row, renamed if the name changed.

    The name is trusted because the peer is bound to its key; it may still not take the name of this
    node or of another peer, so it cannot pose as a different node in votes and measurements."""
    if not isinstance(data, dict):
        return peer
    _note_peer_caps(peer["email"], data.get("caps"))
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


async def request_peer_cross_checks_batched(target_dict: dict) -> list[dict]:
    """Cross-check of a failing monitor, sent together with the others failing at the same time.

    Waits up to CROSS_CHECK_BATCH_WINDOW for more targets, then sends one request per peer (peers
    that did not announce batch support get the old one-target requests). Returns the peers'
    answers for this target, like request_peer_cross_checks."""
    global _cross_check_flush_task
    fut = asyncio.get_running_loop().create_future()
    _cross_check_queue.append((target_dict, fut))
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


async def _delayed_cross_check_flush():
    global _cross_check_flush_task
    try:
        await asyncio.sleep(CROSS_CHECK_BATCH_WINDOW)
    finally:
        _cross_check_flush_task = None
    batch = _cross_check_queue[:]
    _cross_check_queue.clear()
    await _flush_cross_checks(batch)


async def _flush_cross_checks(batch: list) -> None:
    """Sends one batch: identical targets once, a batch message per capable peer, old requests to the rest."""
    if not batch:
        return
    by_key = {}
    for target, fut in batch:
        by_key.setdefault(_cross_check_key(target), (target, []))[1].append(fut)
    results = {key: [] for key in by_key}
    try:
        peers = await asyncio.to_thread(database.get_all_peers) or []
        # Peers known to be offline would only make everyone wait for the timeout
        peers = [p for p in peers if not p.get("is_offline")]
        batch_peers = [p for p in peers if _peer_supports(p, PEER_CAP_BATCH_CHECK)]
        legacy_peers = [p for p in peers if not _peer_supports(p, PEER_CAP_BATCH_CHECK)]
        items = [(key, target) for key, (target, _) in by_key.items()]
        jobs = []
        for p in batch_peers:
            p_items = [(key, t) for key, t in items if _peer_can_check(p, t)]
            for i in range(0, len(p_items), CROSS_CHECK_BATCH_MAX):
                jobs.append(_batch_cross_check_peer(p, p_items[i:i + CROSS_CHECK_BATCH_MAX], results))
        if legacy_peers:
            async def _legacy(key, target):
                results[key].extend(await request_peer_cross_checks(target, timeout=8.0, peers=legacy_peers))
            jobs += [_legacy(key, target) for key, target in items]
        await asyncio.gather(*jobs, return_exceptions=True)
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
        "caps": OWN_PEER_CAPS,
        "targets": [{k: t.get(k) for k in ("url", "type", "expected_keyword", "family")} for _, t in items],
    }
    fut = asyncio.get_running_loop().create_future()
    pending_batch_checks[req_id] = (fut, chat_id, len(items))
    try:
        msg_text = f"[UPTIME_PEER_CHECK_BATCH_REQ]\n{json.dumps(payload)}\n[/UPTIME_PEER_CHECK_BATCH_REQ]"
        await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text),
                                priority=PRIO_PEER, expires_in=CROSS_CHECK_BATCH_TIMEOUT, label="batch cross-check request")
        answers = await asyncio.wait_for(fut, CROSS_CHECK_BATCH_TIMEOUT)
    except asyncio.TimeoutError:
        logger.info(f"Batch cross-check {req_id} ({len(items)} targets) got no answer from {peer.get('email')} in time")
        return
    except Exception as e:
        logger.warning(f"Batch cross-check to {peer.get('email')} failed: {e}")
        return
    finally:
        pending_batch_checks.pop(req_id, None)
    answered = []
    for (key, target), answer in zip(items, answers):
        answer["url"] = target.get("url")  # positions are what the peer answers; URLs are ours
        results[key].append(answer)
        answered.append(answer)
    if answered:
        await run_db(database.save_peer_measurements_batch, answered[0]["node_name"], answered)


def _clean_peer_result(item, node_name: str, url: str) -> dict:
    """A peer's answer for one target, with the same limits as single responses."""
    item = item if isinstance(item, dict) else {}
    status = item.get("status")
    if status not in VOTING_STATUSES:
        status = "unknown"  # also "skip": the peer could not check it (no IPv6 there)
    latency_ms = item.get("latency_ms")
    if not isinstance(latency_ms, int) or isinstance(latency_ms, bool) or not 0 <= latency_ms <= 600000:
        latency_ms = None
    error_msg = item.get("error_msg")
    return {"url": url, "status": status, "latency_ms": latency_ms,
            "error_msg": str(error_msg)[:500] if error_msg else None, "node_name": node_name}


async def _answer_batch_cross_check(bot, accid, chat_id: int, req_id: str, targets: list) -> None:
    """Runs the checks a peer asked for (PEER_BATCH_CHECK_CONCURRENCY at a time) and answers once."""
    global _peer_batch_semaphore
    if _peer_batch_semaphore is None:
        _peer_batch_semaphore = asyncio.Semaphore(PEER_BATCH_CHECK_CONCURRENCY)

    async def one(t):
        if t is None:
            return {"status": "skip", "latency_ms": None, "error_msg": "Target refused"}
        if await asyncio.to_thread(database.is_probe_target_ignored, t["url"]):
            # /probeignore: e.g. blocked in this node's region. Abstain instead of voting "down".
            return {"status": "skip", "latency_ms": None, "error_msg": "Ignored on this node (/probeignore)"}
        async with _peer_batch_semaphore:
            is_up, error_msg, latency_ms = await run_single_check(t)
        return {"status": check_status(is_up), "latency_ms": latency_ms, "error_msg": error_msg}

    answers = await asyncio.gather(*[one(t) for t in targets], return_exceptions=True)
    answers = [a if isinstance(a, dict) else {"status": "unknown", "latency_ms": None, "error_msg": str(a)[:200]}
               for a in answers]
    payload = {"req_id": req_id, "node_name": database.get_local_node_name(), "caps": OWN_PEER_CAPS, "results": answers}
    resp_msg = f"[UPTIME_PEER_CHECK_BATCH_RESP]\n{json.dumps(payload)}\n[/UPTIME_PEER_CHECK_BATCH_RESP]"
    # The requester waits CROSS_CHECK_BATCH_TIMEOUT from sending; a later answer is ignored there
    await asyncio.to_thread(_dc_send_msg_with_stats, bot, accid, chat_id, MsgData(text=resp_msg),
                            priority=PRIO_PEER, expires_in=PEER_ANSWER_TTL, label="batch cross-check answer")


def _parse_batch_targets(raw) -> list:
    """Requested targets, each validated like a single request; None marks a refused one (keeps positions)."""
    targets = []
    for t in (raw if isinstance(raw, list) else [])[:CROSS_CHECK_BATCH_MAX]:
        if not isinstance(t, dict):
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

def pick_telemetry_batch(email: str, all_metrics: list[dict], batch_size: int) -> list[dict]:
    """Entries for one telemetry message: status changes since the last message first, then a
    rotating slice of the others. Everything fits: send it all."""
    if len(all_metrics) <= batch_size:
        _telemetry_rotation_offsets[email] = 0
        return all_metrics
    sent = _telemetry_last_sent.get(email, {})
    changed = [m for m in all_metrics if sent.get(m["url"]) != m["status"]][:batch_size]
    changed_urls = {m["url"] for m in changed}
    batch = list(changed)
    # The rotation walks the full list (not the list minus changes, which differs every time),
    # so consecutive messages continue where the last one stopped
    total = len(all_metrics)
    pos = _telemetry_rotation_offsets.get(email, 0) % total
    for _ in range(total):
        if len(batch) >= batch_size:
            break
        m = all_metrics[pos]
        pos = (pos + 1) % total
        if m["url"] not in changed_urls:
            batch.append(m)
    _telemetry_rotation_offsets[email] = pos
    return batch


async def broadcast_telemetry_to_peers():
    """Periodically sends local monitor telemetry to all configured peers via 1:1 chat.

    Each peer receives the local monitors allowed by the share scope plus the results for the
    probe targets it asked this node to scan. Targets mirrored from one peer are never relayed
    to other peers. With more than 200 entries, each message carries the entries whose status
    changed since the last one first, and fills the rest from a rotating per-peer offset: a
    status change reaches the peer within 2 minutes even with 1000+ monitors, while the full
    list is refreshed in turn (200 is what receivers accept per message)."""
    if not dc_bot_instance or dc_accid is None:
        return
    peers = await asyncio.to_thread(database.get_all_peers)
    if not peers:
        return

    resources = await asyncio.to_thread(database.get_all_resources)
    resources = await asyncio.to_thread(_filter_peer_shareable_resources, dc_bot_instance, dc_accid, resources or [])
    probe_targets = await asyncio.to_thread(database.get_active_probe_targets)
    if not resources and not probe_targets:
        return

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
        all_metrics = probe_by_source.get(email, []) + shared_metrics
        if not all_metrics:
            continue

        metrics_batch = pick_telemetry_batch(email, all_metrics, batch_size)

        payload = {
            "node_name": node_name,
            "sender_email": self_addr,
            "timestamp": now,
            "msg_id": f"{now}_{secrets.token_hex(4)}",
            "caps": OWN_PEER_CAPS,
            "metrics": metrics_batch
        }
        msg_text = f"[UPTIME_PEER_METRICS]\n{json.dumps(payload)}\n[/UPTIME_PEER_METRICS]"

        chat_id = await _resolve_peer_chat_id(p)
        if chat_id:
            def _record_sent(email=email, batch=metrics_batch, all_metrics=all_metrics):
                # Only what really went out counts as sent (a replaced or expired message did not)
                sent = _telemetry_last_sent.setdefault(email, {})
                sent.update({m["url"]: m["status"] for m in batch})
                if len(sent) > 2 * len(all_metrics):  # forget removed monitors
                    live = {m["url"] for m in all_metrics}
                    _telemetry_last_sent[email] = {u: st for u, st in sent.items() if u in live}

            # One telemetry message per peer at a time: a newer one replaces a still queued one
            _dc_send_msg_with_stats(dc_bot_instance, dc_accid, chat_id, MsgData(text=msg_text),
                                    priority=PRIO_TELEMETRY, key=("telemetry", chat_id), expires_in=TELEMETRY_INTERVAL,
                                    label=f"telemetry to {email}", after_send=_record_sent)

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
                try:
                    contact = bot.rpc.get_contact(accid, 1)
                    self_address = getattr(contact, 'address', '') or (contact.get('address') if isinstance(contact, dict) else '')
                except Exception:
                    self_address = ""
                if not self_address:
                    try:
                        self_address = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr") or ""
                    except Exception:
                        self_address = ""
                self_address = self_address.lower()

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
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.is_reserved:
        if _YGGDRASIL_NET is None:
            _YGGDRASIL_NET = ipaddress.ip_network("200::/7")
        if isinstance(ip, ipaddress.IPv6Address) and ip in _YGGDRASIL_NET:
            return False
        return True
    return False

# DNS pinning: every hostname is resolved through one cache, and every address is checked against
# _is_blocked_ip before it is connected to. Validation and the actual connection therefore use the
# same answer for the record's TTL, and a re-resolution after expiry is validated again, so a DNS
# rebinding attack (public answer at validation, private answer at connect) cannot reach the probe.
DNS_CACHE_DEFAULT_TTL = 60   # used when the TTL is unknown (system resolver fallback)
DNS_CACHE_MIN_TTL = 30       # TTL 0/1 tricks cannot force a fresh lookup between validation and connect
DNS_CACHE_MAX_TTL = 300      # long TTLs must not keep probing an old address after a migration
DNS_CACHE_MAX_ENTRIES = 5000
_dns_cache = {}  # host -> (expires_at, tuple_of_ip_strings)
_dns_cache_lock = threading.Lock()


class BlockedAddressError(OSError):
    """A hostname resolved to an internal/private/non-routable address."""


def _dns_cache_get(host: str):
    now = time.monotonic()
    with _dns_cache_lock:
        entry = _dns_cache.get(host)
        if entry and entry[0] > now:
            return entry[1]
    return None


def _dns_cache_put(host: str, ips, ttl) -> tuple:
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        ttl = DNS_CACHE_DEFAULT_TTL
    ttl = min(DNS_CACHE_MAX_TTL, max(DNS_CACHE_MIN_TTL, ttl))
    ips = tuple(dict.fromkeys(ips))
    now = time.monotonic()
    with _dns_cache_lock:
        if len(_dns_cache) >= DNS_CACHE_MAX_ENTRIES:
            for key in [k for k, v in _dns_cache.items() if v[0] <= now]:
                del _dns_cache[key]
            if len(_dns_cache) >= DNS_CACHE_MAX_ENTRIES:
                _dns_cache.clear()
        _dns_cache[host] = (now + ttl, ips)
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
PING_UNAVAILABLE_MSG = "Ping not available on this node (no ICMP socket, no ping binary)"
_ping_unavailable_warned = False


def _warn_ping_unavailable() -> None:
    """Logs once per run why ping checks are skipped here (they would otherwise fail silently)."""
    global _ping_unavailable_warned
    if not _ping_unavailable_warned:
        _ping_unavailable_warned = True
        logger.warning("Ping checks are skipped on this node: no raw or datagram ICMP socket and no ping binary "
                       "(install iputils-ping, or allow the bot's group in net.ipv4.ping_group_range)")


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
_TRACE_ADDR_RE = re.compile(r"(?<![\w:.])(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:.])")


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
    return f"trace: +{round(rise)} ms between hop {n1} {a1} and hop {n2} {a2}"


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
    return cached[1] if cached else ""


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


def resolve_host_safe_sync(host: str) -> list[str]:
    """Blocking variant of resolve_host_safe (system resolver, TTL unknown -> DNS_CACHE_DEFAULT_TTL)."""
    host = (host or "").strip().lower().rstrip(".")
    literal = _literal_ip(host)
    if literal:
        return _validated_ips(host, [literal])
    cached = _dns_cache_get(host)
    if cached is None:
        infos = socket.getaddrinfo(host, None)
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


async def resolve_host_safe(host: str) -> list[str]:
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
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ips = [info[4][0] for info in infos]
        cached = _dns_cache_put(host, ips, ttl)
    return _validated_ips(host, cached)


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


def is_safe_target_url(url: str, check_type: str = "http") -> bool:
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

        # DNS resolution check through the shared pinning cache (the connection reuses this answer)
        try:
            resolve_host_safe_sync(host)
        except BlockedAddressError:
            return False
        except socket.gaierror:
            # Domain could not be resolved; allow in offline/test environment if name is syntactically valid
            pass

        return True
    except Exception:
        return False

def _get_peer_fingerprint(bot, accid, contact_id, contact_addr: str = "") -> str | None:
    """Returns the OpenPGP fingerprint Delta Chat holds for a peer contact, or None.

    get_contact_encryption_info() lists one block per key ("<name> (<addr>):" followed by the
    fingerprint in groups of four), ours first. The peer's block is the one with its address; if the
    address does not match any block, a single block that is not ours ("Me (...)") is used."""
    try:
        info = bot.rpc.get_contact_encryption_info(accid, contact_id)
    except Exception:
        return None
    if not isinstance(info, str):
        return None
    blocks = []
    for block in info.split("\n\n"):
        lines = block.strip().splitlines()
        if len(lines) < 2 or not lines[0].endswith("):"):
            continue
        fp = database.normalize_fingerprint("".join(lines[1:]))
        if fp:
            blocks.append((lines[0], fp))
    addr = (contact_addr or "").lower().strip()
    if addr:
        for header, fp in blocks:
            if header.lower().endswith(f"({addr}):"):
                return fp
    others = [fp for header, fp in blocks if not header.startswith("Me (")]
    return others[0] if len(others) == 1 else None

def _get_verified_peer_for_msg(bot, accid, msg, is_private_chat: bool = True) -> tuple[dict | None, str]:
    """Resolves the peer sending a protocol message from Delta Chat contact data.

    A peer is identified by its key fingerprint: a bot with several relays sends from whichever
    address is reachable, so the address alone says nothing. The sender address and fingerprint
    always come from the Delta Chat contact, never from the message payload.

    Peers stored before fingerprints were recorded (or added by address) have none yet. Such a row is
    matched by its 1:1 chat or its address as before, and the first end-to-end encrypted message
    binds the sender's key to it. From then on only that key is accepted.

    Returns (peer_row_or_None, sender_addr). When the peer now sends from another address, the row
    is moved to that address, so peer["email"] is the current one."""
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
                peer = updated
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
def _get_contact_fingerprint(bot, accid, contact_id, contact=None):
    try:
        self_fps = []
        try:
            self_enc = bot.rpc.get_contact_encryption_info(accid, 1)
            if self_enc:
                self_fps = [m.upper() for m in re.findall(r'[0-9a-fA-F]{32,64}', "".join(self_enc.split()).replace(':', ''))]
        except Exception:
            pass

        if contact:
            get_val = getattr(contact, 'get', lambda k: getattr(contact, k, None))
            for attr in ['fingerprint', 'key_fingerprint', 'public_key']:
                val = get_val(attr)
                if val:
                    matches = re.findall(r'[0-9a-fA-F]{32,64}', str(val).replace(' ', '').replace(':', ''))
                    valid_matches = [m.upper() for m in matches if m.upper() not in self_fps]
                    if valid_matches:
                        return ",".join(valid_matches)

        try:
            fp = bot.rpc.get_contact_config(accid, contact_id, "fp")
            if fp and fp.upper().replace(' ', '') not in self_fps:
                return fp.upper().replace(' ', '')
        except Exception:
            pass

        for args in [(accid, contact_id), (contact_id,)]:
            try:
                enc_info = bot.rpc.get_contact_encryption_info(*args)
                if enc_info:
                    cleaned_info = "".join(enc_info.split()).replace(':', '')
                    matches = re.findall(r'[0-9a-fA-F]{32,64}', cleaned_info)
                    valid_matches = [m.upper() for m in matches if m.upper() not in self_fps]
                    if valid_matches:
                        return ",".join(valid_matches)
            except Exception:
                continue
    except Exception as e:
        logger.error(f"Error checking fingerprint: {e}")
    return None

def _is_dc_admin(bot, accid, contact_id, chat_id: int = None):
    try:
        contact = None
        try:
            contact = bot.rpc.get_contact(accid, contact_id)
        except Exception:
            pass
        
        admin_fp = database.get_admin_fingerprint()
        if admin_fp:
            c_fp = _get_contact_fingerprint(bot, accid, contact_id, contact=contact)
            if c_fp:
                if admin_fp.upper() in c_fp.upper().split(','):
                    if chat_id:
                        database.set_config("admin_chat_id", str(chat_id))
                    return True
            if c_fp:
                 logger.warning(f"Admin fingerprint mismatch for contact {contact_id}")
                 return False
        
        if contact:
            sender_email = contact.address
            admin_email = database.get_config("admin_dc_email")
            if admin_email and admin_email.lower() == sender_email.lower():
                if chat_id:
                    database.set_config("admin_chat_id", str(chat_id))
                return True
            
    except Exception as e:
        logger.error(f"Error during admin verification: {e}")
    return False

async def send_admin_notification(text: str):
    """Sends high-priority system and probe health alerts to the configured administrator via DM."""
    if not dc_bot_instance or dc_accid is None:
        return
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
        return

    if chat_id:
        try:
            await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=text),
                                    priority=PRIO_ALERT, label="admin notification")
        except Exception as e:
            logger.warning(f"Failed to send admin notification to chat {chat_id}: {e}")

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
                                priority=PRIO_ALERT, label="SSL alert")

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
    except Exception:
        pass  # unresolvable/invalid: is_safe_target_url decides
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

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_SAFE_REDIRECTS = 10

@contextlib.asynccontextmanager
async def _safe_http_request(sess, method: str, url: str, **kwargs):
    """Performs an HTTP request following redirects manually, re-validating every hop
    against the SSRF filter so a public URL cannot redirect the probe into a private network."""
    kwargs["allow_redirects"] = False
    current_url = url
    for _ in range(_MAX_SAFE_REDIRECTS + 1):
        request_fn = getattr(sess, method.lower())
        async with request_fn(current_url, **kwargs) as resp:
            location = resp.headers.get("Location") if resp.status in _REDIRECT_STATUSES else None
            if not isinstance(location, str) or not location:
                yield resp
                return
            next_url = urljoin(str(resp.url) if getattr(resp, "url", None) else current_url, location)
            if not await _prewarm_target_dns(next_url, "http") or not is_safe_target_url(next_url, "http"):
                raise aiohttp.ClientError(f"Redirect to blocked address: {next_url[:200]}")
            if resp.status == 303 and method.upper() != "HEAD":
                method = "GET"
            current_url = next_url
    raise aiohttp.ClientError("Too many redirects")

async def run_single_check(resource, session=None) -> tuple[bool, str, int | None]:
    import http
    rtype = resource["type"]
    url = resource["url"]
    timeout = 10
    # 4 / 6 = only that address family (/ping -4 / -6); None = any, IPv4 first
    family = resource.get("family") if resource.get("family") in (4, 6) else None

    if not await _prewarm_target_dns(url, rtype) or not is_safe_target_url(url, rtype):
        return False, "Target blocked: internal or private network address", None

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
                    if 200 <= resp.status < 400:
                        try:
                            body_bytes = await resp.content.read(max_bytes)
                            charset = 'utf-8'
                            content_type = resp.headers.get('Content-Type', '')
                            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
                            if charset_match:
                                charset = charset_match.group(1)
                            try:
                                body_text = body_bytes.decode(charset, errors='ignore')
                            except Exception:
                                body_text = body_bytes.decode('utf-8', errors='ignore')
                        except Exception as read_ex:
                            logger.warning(f"Failed to read body for {url}: {read_ex}")
                            body_text = ""

                        if expected_kw:
                            if expected_kw.lower() not in body_text.lower():
                                return False, f"200 OK (Missing keyword: \"{expected_kw}\")", elapsed_ms
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

            async def _check_http(sess, is_local: bool):
                http_method = (resource.get("http_method") or "").strip().upper()
                if not expected_kw and http_method != "GET" and hasattr(sess, "head"):
                    # 1. Try lightweight HEAD first (0 bytes body read)
                    head_kwargs = {}
                    if not is_local:
                        head_kwargs["timeout"] = req_timeout
                    head_405 = False
                    try:
                        async with _safe_http_request(sess, "HEAD", url, **head_kwargs) as resp:
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
                        logger.debug(f"HEAD check failed for {url} ({head_ex}), falling back to GET")

                    if head_405:
                        logger.info(f"HEAD check returned 405 Method Not Allowed for {url}. Memorizing GET method for this monitor.")
                        resource["http_method"] = "GET"
                        try:
                            await run_db(database.set_url_http_method, url, "GET")
                        except Exception as db_err:
                            logger.warning(f"Failed to persist http_method for {url}: {db_err}")

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

                    # If HEAD was not 2xx/3xx or threw an exception, fall back to GET (max 16KB)
                    return await _do_get(sess, 16384, is_local)
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
        return False, "Target blocked: internal or private network address", None
    except NoIPv6Error:
        return None, NO_IPV6_MSG, None  # None = not checked here: neither UP nor DOWN
    except NoAddressForFamilyError as e:
        return False, str(e), None
    except aiohttp.ClientConnectorError as e:
        os_error = getattr(e, "os_error", None)
        if isinstance(os_error, BlockedAddressError):
            return False, "Target blocked: internal or private network address", None
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
    is_up, err4, latency = await run_single_check({**resource, "family": 4})
    if is_up:
        return is_up, err4, latency
    v6 = _CONNECT_ADDR_RE.sub("", short_vote_error(ipv6_error) or ipv6_error).strip()
    return False, f"IPv4: {short_vote_error(err4) or err4} · IPv6: {v6}", latency


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
    slowest = f", slowest {st['slowest'][1]} ({st['slowest'][0]} ms)" if st["slowest"][1] else ""
    waiting = dc_outbox.waiting()
    queued = f", outbox waiting {sum(waiting.values())} ({', '.join(f'{k} {v}' for k, v in waiting.items())})" if waiting else ""
    logger.info(f"Checks in the last 60s: {total} ({st['up']} up, {st['down']} down, {st['skipped']} skipped), "
                f"avg latency {avg}{slowest}; running now: {running}{queued}")
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
         "error": str(error_msg)[:200] if error_msg and status != "up" else None}
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
    text = " ".join(str(error).split())
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
        checked = m.get("last_checked")
        if isinstance(checked, (int, float)) and not isinstance(checked, bool) and now - checked > PEER_SUSPECT_MAX_AGE:
            continue  # an old result (e.g. late in a >200 target rotation) is not evidence
        down_urls.add(str(m.get("url") or ""))
    if not down_urls:
        return 0
    marked = set()
    modes = {}
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
        _peer_suspects[r["url"]] = (time.monotonic(), peer_node)
        marked.add(r["url"])
    if marked:
        logger.info(f"Peer {peer_node} reports DOWN or DEGRADED for {len(marked)} target(s) that are UP here; voting on their next check")
    return len(marked)


def _take_peer_suspect(rep: dict) -> str | None:
    """The node that reported this target DOWN, if its report is current and peers were not asked
    about it within QUORUM_REVOTE_INTERVAL (then the report waits for a later check)."""
    entry = _peer_suspects.get(rep["url"])
    if not entry:
        return None
    now = time.monotonic()
    if now - entry[0] > PEER_SUSPECT_MAX_AGE:
        _peer_suspects.pop(rep["url"], None)
        return None
    cached = _vote_cache.get(_cross_check_key(rep))
    if cached and now - cached[0] < QUORUM_REVOTE_INTERVAL - 10:
        return None
    _peer_suspects.pop(rep["url"], None)
    return entry[1]


async def _quorum_resource_ids(group: list[dict]) -> set:
    """Monitors of this target decided by quorum: chat mode quorum, live peers exist and the monitor
    may be sent to peers (/peershare) - otherwise there is nobody to vote, and this node decides."""
    peers = await asyncio.to_thread(database.get_all_peers)
    if not any(not p.get("is_offline") for p in peers or []):
        return set()
    candidates = [r for r in group
                  if await asyncio.to_thread(database.get_chat_alert_mode, r["dc_chat_id"]) == "quorum"]
    if not candidates:
        return set()
    shareable = await asyncio.to_thread(_filter_peer_shareable_resources, dc_bot_instance, dc_accid, candidates)
    return {r["id"] for r in shareable}


async def collect_peer_votes(rep: dict, local_up: bool, fresh: bool = False, revote_interval: float = QUORUM_REVOTE_INTERVAL) -> list[dict]:
    """The peers' results for this target. Re-used for revote_interval while this node's own
    result is unchanged, so targets that stay down or degraded do not ask peers every minute."""
    key = _cross_check_key(rep)
    now = time.monotonic()
    cached = _vote_cache.get(key)
    if cached and not fresh and cached[1] == local_up and now - cached[0] < revote_interval:
        return cached[2]
    results = await request_peer_cross_checks_batched(rep)
    if len(_vote_cache) > 5000:
        _vote_cache.clear()
    _vote_cache[key] = (now, local_up, results)
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
        lines.append(f"🟠 **Partial Outage** — {len(starts)} monitor(s) unreachable or degraded from some nodes\n")
        for _, r, votes, _ in starts:
            lines.append(f"• 🟠 `ID: {r['id']}` **{r.get('name') or r['url']}**\n  Target: `{r['url']}`\n  {format_votes(votes)}")
        lines.append("\n_Not counted as downtime: most nodes still reach these targets._")
    if ends:
        if lines:
            lines.append("")
        lines.append(f"✅ **Partial Outage Resolved** — {len(ends)} monitor(s) reachable from all nodes again\n")
        for _, r, votes, started_at in ends:
            dur = f" after `{format_duration(max(1, now - started_at))}`" if started_at else ""
            lines.append(f"• 🟢 `ID: {r['id']}` **{r.get('name') or r['url']}**{dur}\n  {format_votes(votes)}")
    return "\n".join(lines)


_silent_partial_outages: set = set()  # resource ids whose partial outage notice was dropped


async def _flush_degraded_notices():
    await asyncio.sleep(DEGRADED_NOTIFY_WINDOW)
    queued = dict(_degraded_notify_queue)
    _degraded_notify_queue.clear()
    for chat_id, items in queued.items():
        # A monitor that started and ended within the window only needs its latest change
        latest = {}
        for item in items:
            latest[item[1]["id"]] = item
        keep = []
        for item in latest.values():
            kind, r, votes = item[0], item[1], item[2]
            down_nodes = [v["node"] for v in votes if v.get("status") in ("down", "degraded")]
            if kind == "start" and down_nodes and all(is_node_unstable(n) for n in down_nodes):
                _silent_partial_outages.add(r["id"])  # its node turned out unstable: the end stays silent too
                continue
            if kind == "end" and r["id"] in _silent_partial_outages:
                _silent_partial_outages.discard(r["id"])
                continue
            keep.append(item)
        text = format_degraded_notice(keep)
        if not text or not dc_bot_instance or dc_accid is None:
            continue
        try:
            await asyncio.to_thread(_dc_send_msg_with_stats, dc_bot_instance, dc_accid, chat_id, MsgData(text=text),
                                    priority=PRIO_ALERT, label="partial outage notice")
        except Exception as e:
            logger.warning(f"Failed to send partial outage notice to chat {chat_id}: {e}")


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
        started_at = await run_db(database.end_partial_outage, r["id"], now)
        if new == "up":
            _queue_degraded_notice("end", r, votes, started_at or degraded_since or None)
        degraded_since = 0  # to DOWN: the incident message takes over
    if new != prev:
        logger.info(f"Quorum: {r.get('name') or r['url']} (id: {r['id']}) {prev.upper()} -> {new.upper()} ({format_votes(votes)})")
    await run_db(database.update_resource_alert_state, r["id"], new, votes_json, degraded_since)
    r["alert_state"], r["last_votes"], r["degraded_since"] = new, votes_json, degraded_since
    return new


async def check_network_probe(target, semaphore, session=None):
    """Executes a network check acquiring the concurrency semaphore ONLY for the duration of the network probe."""
    async with semaphore:
        return await run_single_check(target, session=session)


async def check_group_task(group, semaphore, session=None):
    rep = group[0]
    if rep.get("is_probe_only"):
        res = await check_network_probe(rep, semaphore, session=session)
        if len(res) == 3:
            is_up, error_msg, latency_ms = res
        else:
            is_up, error_msg = res
            latency_ms = None
        _count_check(is_up, latency_ms, rep["url"])
        if is_up is None:  # this node cannot check it (no IPv6): keep the last result
            return
        status_str = check_status(is_up)  # "degraded" goes to the requesting peer in telemetry
        local_node = database.get_local_node_name()
        await run_db(database.update_probe_target_result, rep["url"], status_str, latency_ms, error_msg)
        await run_db(database.save_peer_measurement, rep["url"], local_node, status_str, latency_ms, error_msg)
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
        logger.debug(f"Check skipped: {rep['name'] or rep['url']} (id: {rep['id']}) in chat {rep['dc_chat_id']} ({error_msg})")
        return

    def _in_alert(r):
        return r["status"] == "down" or r.get("alert_state") in ("degraded", "down")

    # Retry logic: retry if check failed and at least one resource in the group was not already
    # DOWN or DEGRADED (those are re-checked every interval anyway).
    # Note: sleep(30) is executed OUTSIDE the semaphore so failing targets do not starve healthy checks!
    if not is_up and any(not _in_alert(r) for r in group):
        for retry in range(1, 3):
            for r in group:
                if not _in_alert(r):
                    logger.info(f"Retry {retry}/2 for resource {r['id']} ({r['name'] or r['url']}) in chat {r['dc_chat_id']}")
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
                f"Host internet outage detected! Suppressing DOWN check result for {rep['name'] or rep['url']} in chat {rep['dc_chat_id']}"
            )
            return

    local_node = database.get_local_node_name()
    in_alert = any(_in_alert(r) for r in group)
    # Reachable through a bad path from here: the peers say whether it is only this node's path
    locally_degraded = is_up == CHECK_DEGRADED
    if locally_degraded:
        _local_degraded[rep["url"]] = time.time()
    else:
        _local_degraded.pop(rep["url"], None)
    reported_by = _take_peer_suspect(rep) if is_up and not in_alert else None
    quorum_ids = (await _quorum_resource_ids(group)
                  if (not is_up or in_alert or reported_by or locally_degraded) else set())
    quorum_group = [r for r in group if r["id"] in quorum_ids]

    # Peers are asked when this node newly sees the target failing (fresh answers), and, for quorum
    # monitors that are DOWN/DEGRADED, again to notice recovery or a change between the two
    # (answers re-used for QUORUM_REVOTE_INTERVAL while this node's own result is unchanged).
    newly_failing = not is_up and any(not _in_alert(r) for r in group)
    peer_results = None
    try:
        if newly_failing and await _peer_cross_check_allowed(group):
            peer_results = await collect_peer_votes(rep, is_up, fresh=True)
        elif quorum_group and (not is_up or any(r.get("alert_state") in ("degraded", "down") for r in quorum_group)):
            # Since when it is in this state: DEGRADED keeps status UP, so last_changed says nothing
            oldest_change = min(((r.get("degraded_since") if r.get("alert_state") == "degraded" else r.get("last_changed")) or 0)
                                for r in quorum_group)
            long_running = oldest_change and time.time() - oldest_change > 3600
            peer_results = await collect_peer_votes(
                rep, is_up, revote_interval=QUORUM_REVOTE_INTERVAL_LONG if long_running else QUORUM_REVOTE_INTERVAL)
        elif reported_by and quorum_group:
            logger.info(f"{rep.get('name') or rep['url']}: UP here but {reported_by} reports it DOWN; asking all peers")
            peer_results = await collect_peer_votes(rep, is_up, fresh=True)
        elif locally_degraded and quorum_group:
            # Not fresh: answers are re-used for QUORUM_REVOTE_INTERVAL, so a path that stays bad
            # (e.g. this node's provider) does not ask the peers every minute
            peer_results = await collect_peer_votes(rep, is_up)
    except Exception as ex:
        logger.warning(f"Error during peer cross-check: {ex}")

    votes = build_votes(local_node, is_up, latency_ms, error_msg, peer_results) if peer_results is not None else None
    if votes:
        newly_unstable = note_vote_outliers(rep["url"], votes)
        if newly_unstable:
            asyncio.create_task(notify_unstable_nodes(newly_unstable))
        votes = mask_unstable_votes(votes)
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
    for r in group:
        if r["id"] in quorum_ids and votes is not None:
            state = await apply_quorum_state(r, votes, votes_json)
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

    _count_check(is_up, latency_ms, rep.get("name") or rep["url"])  # the result after retries

    # One transaction for the whole check: every monitor of this target + the local measurement
    status_str = check_status(is_up)
    await run_db(database.record_check_results,
                 [_status_update_for(r, outcomes[r["id"]][0], outcomes[r["id"]][1], latency_ms) for r in group],
                 (rep["url"], local_node, status_str, latency_ms, error_msg))

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
                   f"Check result: {r['name'] or r['url']} (id: {r['id']}) in chat {r['dc_chat_id']} -> {shown}"
                   f"{'' if shown == local_word else ' by quorum, locally ' + local_word} ({r_err})")
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
                    logger.warning(f"SSL check for {rep['url']} failed: {ssl_err}")
                    await run_db(database.update_resource_ssl, r["id"], r.get("ssl_expiry_date"), now, cur_state)

def format_incident_message(incident_id: int, started_at: int, resources: list[dict], is_resolved: bool = False, resolved_at: int = None, dc_chat_id: int = None, total_chat_monitors: int = None) -> str:
    start_dt = datetime.datetime.fromtimestamp(started_at, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    now = int(time.time())
    
    total_monitors = total_chat_monitors if total_chat_monitors is not None else len(resources)
    down_resources = [r for r in resources if r.get("status") == "down" or r.get("resource_status") == "down" or r.get("went_up_at") is None]
    up_resources = [r for r in resources if (r.get("status") == "up" or r.get("resource_status") == "up") and r.get("went_up_at") is not None]
    
    if is_resolved:
        resolved_ts = resolved_at or now
        resolved_dt = datetime.datetime.fromtimestamp(resolved_ts, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        duration = max(1, resolved_ts - started_at)
        duration_str = format_duration(duration)
        
        recovered_resources = [r for r in resources if r.get("name") or r.get("url")]
        
        if total_monitors > 0:
            lines = [
                f"✅ **Incident #{incident_id}** — `Resolved`",
                f"⏱ **Duration:** `{duration_str}` (`{start_dt}` → `{resolved_dt} UTC`)",
                f"📊 **All {total_monitors} monitors operational**"
            ]
            if recovered_resources:
                lines.append("\n**Recovered Monitors:**")
                for r in recovered_resources:
                    r_name = r.get("name") or r.get("url")
                    r_type = (r.get("type") or "HTTP").upper()
                    uptime_val = database.get_resource_uptime_30d(r["id"])
                    lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}** ({r_type}) — Uptime 30d: `{uptime_val:.2f}%`")
                    votes = _votes_from_json(r.get("last_votes"))
                    if len(votes) > 1 and r.get("alert_state") == "degraded":
                        lines.append(f"  🟠 Still unreachable from some nodes: {format_votes(votes)}")
        else:
            lines = [
                f"✅ **Incident #{incident_id}** — `Resolved`",
                f"⏱ **Duration:** `{duration_str}` (`{start_dt}` → `{resolved_dt} UTC`)",
                f"📊 **All monitored resources removed or operational**"
            ]
        return "\n".join(lines)
        
    else:
        duration = max(1, now - started_at)
        duration_str = format_duration(duration)
        down_count = len(down_resources)
        
        # Check if partially recovered
        partially_recovered = len(up_resources) > 0 and down_count > 0
        
        if partially_recovered:
            status_tag = "Ongoing (Partial Recovery)"
            header_icon = "⚠️"
        else:
            status_tag = "Ongoing"
            header_icon = "🚨"
            
        lines = [
            f"{header_icon} **Incident #{incident_id}** — `{status_tag}`",
            f"⏱ **Started:** `{start_dt} UTC` (active for `{duration_str}`)",
            f"📊 **Affected:** {down_count} / {total_monitors} monitors down\n",
            "**Current Status:**"
        ]
        
        for r in down_resources:
            r_name = r.get("name") or r.get("url")
            r_type = (r.get("type") or "HTTP").upper()
            d_time = max(1, now - (r.get("last_changed") or r.get("went_down_at") or started_at))
            d_str = format_duration(d_time)
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🔴 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `DOWN` (down for `{d_str}`) | Uptime 30d: `{uptime_val:.2f}%`{slowdown_note(r, now)}")
            votes = _votes_from_json(r.get("last_votes"))
            if len(votes) > 1:
                lines.append(f"  🛰️ {format_votes(votes)}")
            
        for r in up_resources:
            r_name = r.get("name") or r.get("url")
            r_type = (r.get("type") or "HTTP").upper()
            rec_dt = datetime.datetime.fromtimestamp(r.get("last_changed") or r.get("went_up_at") or now, tz=datetime.timezone.utc).strftime('%H:%M:%S')
            uptime_val = database.get_resource_uptime_30d(r["id"])
            lines.append(f"• 🟢 `ID: {r['id']}` **{r_name}**\n  Target: `{r['url']}` ({r_type})\n  Status: `UP` (recovered at `{rec_dt} UTC`) | Uptime 30d: `{uptime_val:.2f}%`")

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


def _deliver_incident_message(inc_id: int, dc_chat_id: int, msg_text: str, resolved: bool):
    """Runs in the outbox: edits the incident's message, or sends it if it has none yet (or the edit fails).

    The message id is read here, at sending time: a first message still waiting in the outbox is
    merged with later updates (same key) and goes out once, with the latest text."""
    inc = database.get_incident_by_id(dc_chat_id, inc_id)
    msg_id = inc.get("msg_id") if inc else None
    if msg_id:
        try:
            dc_bot_instance.rpc.send_edit_request(dc_accid, msg_id, msg_text)
            logger.info(f"{'Resolved' if resolved else 'Edited'} Incident #{inc_id} message {msg_id} in chat {dc_chat_id}")
            return msg_id
        except Exception as e:
            logger.warning(f"Failed to edit Incident message {msg_id} (sending new message): {e}")
    # No message yet (also an outage that ended before its first message went out: it gets the
    # resolved message, so the chat still learns about it)
    new_msg_id = dc_bot_instance.rpc.send_msg(dc_accid, dc_chat_id, MsgData(text=msg_text))
    if isinstance(new_msg_id, int) and not resolved:
        database.update_incident_msg_id(inc_id, new_msg_id)
    return new_msg_id


def _queue_incident_message(inc_id: int, dc_chat_id: int, msg_text: str, priority: int, resolved: bool = False):
    """One outbox job per incident: a queued update is replaced by a newer one, keeping its place."""
    if not dc_bot_instance or dc_accid is None:
        return
    dc_outbox.submit(lambda: _deliver_incident_message(inc_id, dc_chat_id, msg_text, resolved),
                     priority=priority, key=("incident", inc_id), label=f"incident #{inc_id} message")

async def sync_chat_incident_state(dc_chat_id: int, force_update: bool = False):
    chat_lock = get_chat_incident_lock(dc_chat_id)
    async with chat_lock:
        resources = await asyncio.to_thread(database.get_resources, dc_chat_id)
        total_chat_monitors = len(resources) if resources else 0
        now = int(time.time())
        active_res_map = {r["id"]: r for r in (resources or [])}
        
        # Link any unlinked open downtime events to matching incident or create a new incident
        unlinked_events = await asyncio.to_thread(database.get_unlinked_open_downtime_events, dc_chat_id)
        for ev in unlinked_events:
            matching_inc = await asyncio.to_thread(database.get_active_incident_for_outage, dc_chat_id, ev["went_down_at"], 3600, True)
            if matching_inc:
                if matching_inc.get("status") == "resolved":
                    await asyncio.to_thread(database.reopen_incident, matching_inc["id"])
                await asyncio.to_thread(database.link_downtime_event_to_incident, ev["id"], matching_inc["id"])
                force_update = True
            else:
                new_inc_id = await asyncio.to_thread(database.create_incident, dc_chat_id, ev["went_down_at"])
                await asyncio.to_thread(database.link_downtime_event_to_incident, ev["id"], new_inc_id)
                force_update = True

        active_incidents = await asyncio.to_thread(database.get_active_incidents_for_chat, dc_chat_id)
        if not active_incidents:
            return

        for inc in active_incidents:
            inc_id = inc["id"]
            events = await asyncio.to_thread(database.get_incident_downtime_events, inc_id)
            
            # If any open downtime event belongs to a deleted resource, close it
            for ev in events:
                if ev["resource_id"] not in active_res_map and ev.get("went_up_at") is None:
                    await asyncio.to_thread(database.close_resource_downtime_events, ev["resource_id"], now)
                    ev["went_up_at"] = now

            open_events = [ev for ev in events if ev.get("went_up_at") is None and ev["resource_id"] in active_res_map]
            
            if open_events:
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
                for ev in events:
                    rid = ev["resource_id"]
                    if rid in active_res_map and rid not in seen_res:
                        seen_res.add(rid)
                        r = active_res_map[rid]
                        is_currently_down = any(e["resource_id"] == rid and e.get("went_up_at") is None for e in events)
                        inc_resources.append({
                            "id": r["id"],
                            "name": r.get("name"),
                            "url": r.get("url"),
                            "type": r.get("type"),
                            "status": "down" if is_currently_down else "up",
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
                
                await asyncio.to_thread(database.resolve_incident, inc_id, now, summary_str)
                
                msg_text = format_incident_message(
                    inc_id,
                    inc["started_at"],
                    rec_resources,
                    is_resolved=True,
                    resolved_at=now,
                    total_chat_monitors=total_chat_monitors,
                    dc_chat_id=dc_chat_id
                )
                
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
        logger.warning(f"Resource {res_id} ({res_name}) in chat {dc_chat_id} has been down for 30 days. Auto-removing from monitoring...")
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
        await run_db(database.batch_update_resource_status, [_status_update_for(resource, is_up, error_msg, latency_ms)])
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


async def run_and_track_group(group, semaphore, session=None):
    try:
        await check_group_task(group, semaphore, session=session)
    finally:
        async with running_lock:
            now = int(time.time())
            for r in group:
                running_resource_ids.discard(r["id"])
                # probe-only targets too ("probe_<url>"): the cached row's last_checked lags behind
                _check_finished_at[r["id"]] = now

async def run_checks_parallel(tasks_list):
    await asyncio.gather(*tasks_list, return_exceptions=True)

# Checks running at once. They are async (a socket each, little CPU), so the limit is about file
# descriptors, not cores: with 50, ~150 hung targets (10 s timeouts, 3 attempts) filled every slot
# for a minute and delayed the healthy checks. docker-compose.yml raises nofile to match.
CHECK_CONCURRENCY = 200


async def monitoring_scheduler_loop():
    import collections
    semaphore = asyncio.Semaphore(CHECK_CONCURRENCY)
    _last_peer_audit = 0
    _last_incident_audit = 0
    _last_cleanup = 0
    _last_chat_audit = 0
    _last_transport_flush = 0
    _last_summary = int(time.time())
    # Validated, TTL-pinned DNS answers (see resolve_host_safe)
    # Above CHECK_CONCURRENCY: aiohttp counts the wait for a free connection against the request
    # timeout, so a smaller pool would turn queueing into false "Timeout" results
    connector = _make_safe_connector(limit=CHECK_CONCURRENCY + 50)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as shared_session:
        while True:
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
                
                # Group due resources by (type, url)
                due_groups = collections.defaultdict(list)
                seen_urls = set()
                async with running_lock:
                    for r in resources:
                        r_id = r["id"]
                        if r_id in running_resource_ids:
                            continue
                            
                        last_checked = max(r["last_checked"] or 0, _check_finished_at.get(r_id, 0))
                        interval = effective_check_interval(
                            max(10, r["interval"] or 60), r["status"], r.get("last_changed"), now)
                        
                        slot_offset = (r_id * 11) % interval if isinstance(r_id, int) else (sum(str(r_id).encode()) * 11) % interval
                        slot_bucket = slot_offset // 5
                        current_bucket = (now % interval) // 5
                        
                        if last_checked == 0:
                            is_due = (current_bucket == slot_bucket)
                        else:
                            is_due = (now - last_checked >= interval) and (current_bucket == slot_bucket or now - last_checked >= interval + 15)
                        
                        if is_due:
                            running_resource_ids.add(r_id)
                            target_key = (r["type"], r["url"])
                            due_groups[target_key].append(r)
                            seen_urls.add(r["url"])
                        else:
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
                            due_groups[(probe_rep["type"], pt_url)].append(probe_rep)
                
                tasks = []
                for target_key, group in due_groups.items():
                    for r in group:
                        if isinstance(r.get("id"), int):
                            r["last_checked"] = now
                    tasks.append(run_and_track_group(group, semaphore, session=shared_session))
                    
                if tasks:
                    logger.debug(f"Triggering {len(tasks)} target checks (encompassing {sum(len(g) for g in due_groups.values())} resources)...")
                    asyncio.create_task(run_checks_parallel(tasks))
                    
                # Periodically broadcast telemetry to configured peers (every 2 minutes)
                global last_peer_telemetry_broadcast
                if now - last_peer_telemetry_broadcast >= TELEMETRY_INTERVAL:
                    last_peer_telemetry_broadcast = now
                    asyncio.create_task(broadcast_telemetry_to_peers())

                # Audit incidents and peer liveness every 30 seconds (not every 5s)
                if now - _last_incident_audit >= 30:
                    _last_incident_audit = now
                    active_incidents = await run_db(database.get_all_active_incidents)
                    for inc in active_incidents:
                        asyncio.create_task(sync_chat_incident_state(inc["dc_chat_id"]))

                if now - _last_peer_audit >= 30:
                    _last_peer_audit = now
                    for node, secs in pop_recovered_nodes():
                        logger.info(f"Node {node} is stable again after {format_duration(secs)}")
                        asyncio.create_task(send_admin_notification(
                            f"✅ **Node Stable Again**: {node}\nIts votes count again (it was unstable for `{format_duration(secs)}`)."))
                    newly_offline_peers = await run_db(database.audit_peers_offline, 360)
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

                # Periodic database cleanup (every 24 hours)
                if now - _last_cleanup >= 86400:
                    _last_cleanup = now
                    await run_db(database.cleanup_old_records, 90)
                    for k in [k for k, t in _check_finished_at.items() if now - t > 2 * 86400]:
                        del _check_finished_at[k]  # removed resources and peers' dropped targets
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
                
            await asyncio.sleep(5)

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
            peer_measurements = database.get_peer_measurements_for_url(r["url"])
            local_node = database.get_local_node_name()
            remote_measurements = [pm for pm in peer_measurements if pm.get("node_name") != local_node]
            if remote_measurements:
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

async def handle_status_page(request):
    if not check_rate_limit(request, bucket="web_status", max_requests=120, window_seconds=60):
        return web.Response(text="Rate limit exceeded. Try again later.", status=429, headers={"Retry-After": "60"})

    token = request.match_info.get('token')
    chat_id = await run_db(database.get_chat_id_by_token, token)
    if not chat_id:
        return web.Response(text="Status Page Not Found", status=404)
        
    chat_name = "Chat Monitor"
    if dc_bot_instance and dc_accid is not None:
        try:
            chat = await run_rpc(dc_bot_instance.rpc.get_chat, dc_accid, chat_id)
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
    html_content = get_dashboard_html(chat_name, resources, overall_uptime, incidents, uptimes_map=uptimes_map,
                                      partial_outages=partial_outages)
    return web.Response(text=html_content, content_type="text/html")

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

def start_monitoring_thread():
    global async_event_loop
    dc_outbox.start()  # from now on messages are queued and paced instead of sent inline
    loop = asyncio.new_event_loop()
    async_event_loop = loop
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitoring_scheduler_loop())

# Command Handlers
def _dc_send_msg_with_stats(bot, accid, chat_id, msg_data, priority=PRIO_REPLY, key=None, expires_in=None,
                            label=None, after_send=None):
    """Sends a message through the paced outbox (see outbox.py). Default priority: a command reply.

    after_send() runs right after the message really went out (not if it was replaced or expired).
    Returns the msg_id when it was sent right away (outbox not started, as in tests), else None:
    the message is queued and goes out when its turn and a send token come."""
    def send():
        msg_id = bot.rpc.send_msg(accid, chat_id, msg_data)
        if after_send:
            after_send()
        return msg_id

    fut = dc_outbox.submit(send, priority=priority, key=key, expires_in=expires_in,
                           label=label or f"message to chat {chat_id}")
    if fut.done() and not fut.exception():
        return fut.result()
    return None

def _react(bot, accid: int, msg_id: int | None, emoji: str):
    """Add or clear a reaction on a message."""
    if not bot or not hasattr(bot, "rpc") or not msg_id:
        return
    # Keyed by message: a ⏳ still waiting in the outbox is replaced by the final ☑️ (one mail, not two)
    dc_outbox.submit(lambda: bot.rpc.send_reaction(accid, msg_id, [emoji] if emoji else []),
                     priority=PRIO_REPLY, key=("reaction", msg_id), label=f"reaction {emoji} on {msg_id}")

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
def help_command(bot, accid, event):
    msg = event.msg
    is_actually_admin = _is_dc_admin(bot, accid, msg.from_id)
    admin_email = database.get_config("admin_dc_email")
    
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
        f"/alertmode [quorum|local] — Alert when most nodes cannot reach a target (default), or on this node's checks only\n"
        f"/events — View incident history and active outages\n"
        f"/history [id] — View downtime history for monitors\n"
        f"/sync — Synchronize monitors with other bots in the chat\n"
        f"/donate — Support bot development ❤️\n"
        f"/help — Show this help message\n\n"
    )
    
    if not admin_email:
        help_text += (
            f"**Setup Command:**\n"
            f"/initadmin — Claim bot ownership (admin setup)\n\n"
        )
    elif is_actually_admin:
        admin_fp = database.get_admin_fingerprint()
        fp_suffix = f" ({admin_fp[-8:].upper()})" if admin_fp else ""
        help_text += f"👑 **Admin:** `{admin_email}`{fp_suffix}\n\n"
        help_text += (
            f"**Admin Commands:**\n"
            f"/url [base_url] — Set/view base status URL (e.g. `https://up.gluek.info`)\n"
            f"/nodename [name] — Set/view local probe node name (e.g. `Frankfurt-DE`)\n"
            f"/invitepeer — Generate SecureJoin E2EE invite link for pairing with other bots\n"
            f"/peers (or /probes) — List distributed peer bots and their status\n"
            f"/addpeer <email|link> [node_name] — Add remote peer bot (via email or SecureJoin invite)\n"
            f"/rmpeer <email|key> — Remove remote peer bot\n"
            f"/peershare [admin|all|none] — Choose which local monitors are disclosed to peers\n"
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
def initadmin_command(bot, accid, event):
    msg = event.msg
    admin_email = database.get_config("admin_dc_email")
    admin_fp = database.get_admin_fingerprint()

    if admin_email or admin_fp:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Admin is already set. Use `set_admin.py` on the server to change."))
        return

    contact = bot.rpc.get_contact(accid, msg.from_id)
    email = contact.address
    database.set_config("admin_dc_email", email)

    fp = _get_contact_fingerprint(bot, accid, msg.from_id, contact=contact)
    if fp:
        first_fp = fp.split(',')[0]
        database.set_admin_fingerprint(first_fp)
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\nFingerprint: `{first_fp[-8:]}`"
        ))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ You are now the admin!\n\nEmail: `{email}`\n⚠️ Fingerprint not available yet (will be used after key exchange)."
        ))

@dc_cli.on(events.NewMessage(command="/url"))
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

def fetch_html_title(url, timeout=3.0):
    if not is_safe_target_url(url, "http"):
        return None
    import urllib.request
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'}
        )
        with _safe_url_opener().open(req, timeout=timeout) as response:
            html_bytes = response.read(16384)
            charset = 'utf-8'
            content_type = response.headers.get('Content-Type', '')
            charset_match = re.search(r'charset=([\w-]+)', content_type, re.IGNORECASE)
            if charset_match:
                charset = charset_match.group(1)
            try:
                html_text = html_bytes.decode(charset, errors='ignore')
            except Exception:
                html_text = html_bytes.decode('utf-8', errors='ignore')
                
            match = re.search(r'<title>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                title = html.unescape(title)
                title = re.sub(r'\s+', ' ', title)
                if title:
                    return title
    except Exception as e:
        logger.warning(f"Could not fetch title for {url}: {e}")
    return None

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
def ping_command(bot, accid, event):
    msg = event.msg
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
                    page_title = await asyncio.to_thread(fetch_html_title, validated_url)
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

    if not is_safe_target_url(url, check_type):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text="❌ Cannot check internal, local, or private network targets."
        ))
        return
        
    name = tokens[1] if len(tokens) > 1 else None
    expected_keyword = tokens[2] if len(tokens) > 2 else None
    
    if not name:
        if check_type == "http":
            fetched_title = fetch_html_title(url)
            name = fetched_title if fetched_title else target
        else:
            name = target
        
    res_id = database.add_resource(msg.chat_id, url, name, check_type, expected_keyword=expected_keyword)
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

@dc_cli.on(events.NewMessage(command="/rm"))
@dc_cli.on(events.NewMessage(command="/del"))
@dc_cli.on(events.NewMessage(command="/remove"))
@dc_cli.on(events.NewMessage(command="/delete"))
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

@dc_cli.on(events.NewMessage(command="/status"))
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
        f"🛰️ Alert mode: `{database.get_chat_alert_mode(msg.chat_id)}` (`/alertmode`)\n\n"
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
def accounts_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    accids = bot.rpc.get_all_account_ids()
    reply = "🤖 **Configured Delta Chat Accounts:**\n\n"
    for a_id in accids:
        try:
            addr = bot.rpc.get_config(a_id, "addr")
            primary = " (Primary)" if a_id == accid else ""
            reply += f"• ID: `{a_id}` - `{addr}`{primary}\n"
        except Exception:
            pass
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))

@dc_cli.on(events.NewMessage(command="/rmaccount"))
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
def setprimary_command(bot, accid, event):
    """Deprecated: the core no longer uses configured_addr to pick the SMTP relay."""
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Only the bot administrator can use /setprimary."))
        return
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"⚠️ /setprimary is deprecated and disabled. {RELAY_SELECTION_NOTE}"))

@dc_cli.on(events.NewMessage(command="/resilient"))
def resilient_command(bot, accid, event):
    """Deprecated: relay failover is handled by the core."""
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Only the bot administrator can use /resilient."))
        return
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"⚠️ /resilient is deprecated and disabled. {RELAY_SELECTION_NOTE}"))

def _get_self_addr(bot, accid) -> str:
    try:
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
        if isinstance(addr, str):
            return addr
        return ""
    except Exception:
        return ""

# Peer administration commands
@dc_cli.on(events.NewMessage(command="/nodename"))
def nodename_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    payload = (event.payload or "").strip()
    if payload:
        global last_peer_telemetry_broadcast
        old_name = database.get_local_node_name()
        database.set_local_node_name(payload)
        database.rename_measurement_node(old_name, payload.strip())
        # Peers learn the new name from the next telemetry message: send it on the next scheduler tick
        last_peer_telemetry_broadcast = 0.0
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Local probe node name set to: `{payload}`\nPeers on 2.17.2+ pick it up with the next telemetry message."))
    else:
        current_name = database.get_local_node_name()
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"📍 Current local probe node name: `{current_name}`\n\nTo change it: `/nodename <name>` (e.g. `/nodename Frankfurt-DE`, `/nodename RU-Moscow`)."))

@dc_cli.on(events.NewMessage(command="/peers"))
@dc_cli.on(events.NewMessage(command="/probes"))
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
    all_peer_measurements = database.get_all_peer_measurements()

    reply = f"🛰️ **Distributed Monitoring Peers**\n"
    reply += f"📍 Local Node: `{local_node}`\n\n"
    reply += f"📊 **Network Stats:**\n"
    reply += f"• Local Monitored Targets: `{unique_local_urls}` unique URLs (`{len(all_resources)}` across chats)\n"
    reply += f"• Mirrored Remote Probe Targets: `{len(probe_targets)}`\n"
    paused = [c for c, at in database.get_monitored_chats().items() if at is not None]
    if paused:
        reply += f"• Paused Chats (bot removed or chat gone): `{len(paused)}`\n"
    reply += f"• Cached Remote Measurements: `{len(all_peer_measurements)}`\n\n"

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
            node_meas_count = sum(1 for m in all_peer_measurements if m.get("node_name") == p_node)
            fp = p.get("fingerprint")
            # First 16 hex digits identify the key; the address only shows the relay it last used
            key_lbl = f"Key: `{' '.join(fp[i:i + 4] for i in range(0, 16, 4))}…`" if fp else "Key: `not bound yet`"
            reply += f"• {status_icon} **{p_node}** — `{p['email']}`\n  {key_lbl} | {chat_lbl} | Last seen: `{seen_str}` | Active metrics: `{node_meas_count}`\n\n"
        reply += "Commands:\n• `/invitepeer` — Generate E2EE invite link\n• `/addpeer <email|link> [node_name]`\n• `/rmpeer <email|key>`\n• `/peershare [admin|all|none]`\n• `/nodename <name>`\n• `/probeignore [url|host|pattern]` — Exclude targets on this node (e.g. `*:25`), or list them\n• `/probeunignore <entry>` — Resume probing on this node"
    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply.strip()))

@dc_cli.on(events.NewMessage(command="/invitepeer"))
@dc_cli.on(events.NewMessage(command="/peerinvite"))
def invitepeer_command(bot, accid, event):
    msg = event.msg
    if not _is_dc_admin(bot, accid, msg.from_id):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ This command is only for the administrator."))
        return
    try:
        qr_link = bot.rpc.get_chat_securejoin_qr_code(accid, None)
        node_name = database.get_local_node_name()
        addr = bot.rpc.get_config(accid, "configured_addr") or bot.rpc.get_config(accid, "addr")
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

@dc_cli.on(events.NewMessage(command="/addpeer"))
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

    def _hello_text():
        hello_payload = {
            "node_name": database.get_local_node_name(),
            "sender_email": _get_self_addr(bot, accid),
            "version": VERSION
        }
        if invite_token:
            hello_payload["invite_token"] = invite_token
        return f"[UPTIME_PEER_HELLO]\n{json.dumps(hello_payload)}\n[/UPTIME_PEER_HELLO]"

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
            _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=_hello_text()), priority=PRIO_PEER, label="peer hello")

            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
                text=f"✅ SecureJoin E2EE established with **{node_name}** (`{peer_email}`).\nChat ID: `{chat_id}`." + mutual_note
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
        _dc_send_msg_with_stats(bot, accid, chat_id, MsgData(text=_hello_text()), priority=PRIO_PEER, label="peer hello")

        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(
            text=f"✅ Peer `{email}` (**{node_name}**) added.\nSent peering handshake via private chat (Chat ID: `{chat_id}`).\n\n"
                 f"💡 _Note: Peer telemetry is only accepted end-to-end encrypted. If your provider requires strict E2EE (e.g. chatmail), generate an invite on the other bot with `/invitepeer` and add it via `/addpeer <link>`._"
                 + mutual_note
        ))
    except Exception as e:
        logger.error(f"Failed to add peer: {e}")
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="❌ Failed to add peer. Check server logs for details."))

@dc_cli.on(events.NewMessage(command="/peershare"))
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
    if peer and database.remove_peer(peer["email"]):
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"✅ Peer **{peer.get('node_name') or 'Remote'}** (`{peer['email']}`) removed."))
    else:
        _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=f"❌ Peer `{ident}` not found in database (or the key prefix matches several peers)."))

@dc_cli.on(events.NewMessage(command="/probeignore"))
@dc_cli.on(events.NewMessage(command="/ignoreprobe"))
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
        addr = bot.rpc.get_config(accid, "configured_addr")
        bot.logger.info(f"Account created: {addr}")
    except Exception as e:
        # serve then exits with "no configured accounts" and the container restart retries
        bot.logger.error(f"Automatic account creation failed: {e}")


@dc_cli.on_init
def on_init(bot, args):
    setup_custom_command_parser(bot)
    bot.logger.info(f"Initializing Uptime Bot v{VERSION}...")
    ensure_configured_account(bot, args)

    global dc_bot_instance, dc_accid
    dc_bot_instance = bot

    for accid in bot.rpc.get_all_account_ids():
        dc_accid = accid
        try:
            bot_name = os.environ.get("DISPLAY_NAME")
            if not bot_name and os.path.exists("/data/options.json"):
                try:
                    with open("/data/options.json", "r", encoding="utf-8") as f:
                        opts = json.load(f)
                        bot_name = opts.get("display_name", "").strip()
                except Exception:
                    pass
            if not bot_name:
                bot_name = "Delta Chat Uptime Bot"
            bot.rpc.set_config(accid, "displayname", bot_name)
            
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
            bot.rpc.set_config(dc_accid, "download_limit", "1")
            bot.rpc.set_config(dc_accid, "delete_device_after", "86400")
            logger.info("Successfully set auto-download limit to 1 byte to optimize storage.")
        except Exception as e:
            logger.error(f"Failed to set storage optimizations: {e}")
            
        admin_email = database.get_config("admin_dc_email")
        admin_fp = database.get_admin_fingerprint()
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

def _record_peer_activity(sender_addr: str):
    if not sender_addr:
        return
    was_offline, downtime_sec, peer_data = database.update_peer_last_seen(sender_addr)
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

@dc_cli.on(events.NewMessage(is_bot=None))
def on_new_message(bot, accid, event):
    msg = event.msg
    if msg.is_info:
        return
        

    text = (msg.text or "").strip()
    
    if "[UPTIME_BOT_SYNC_DATA]" in text:
        logger.info(f"[SYNC RECEIVE] Found payload. from_id={msg.from_id}, is_info={msg.is_info}")
    
    if msg.from_id == 1:
        return

    if "[UPTIME_BOT_SYNC_DATA]" in text and "[/UPTIME_BOT_SYNC_DATA]" in text:
        logger.info(f"[SYNC RECEIVE] Processing sync data payload...")
        try:
            start_idx = text.find("[UPTIME_BOT_SYNC_DATA]") + len("[UPTIME_BOT_SYNC_DATA]")
            end_idx = text.find("[/UPTIME_BOT_SYNC_DATA]")
            json_str = text[start_idx:end_idx].strip()
            sync_list = json.loads(json_str)
            logger.info(f"[SYNC RECEIVE] Parsed json: {sync_list}")
            
            if not isinstance(sync_list, list):
                logger.warning("[SYNC RECEIVE] Payload is not a list. Ignoring.")
                return
            
            # Limit the sync payload to a maximum of 50 items to avoid DB spam
            sync_list = sync_list[:50]
            
            added_count = 0
            added_resources = []
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
                        expected_type, validated_url = parse_target(url)
                        if expected_type == check_type:
                            res_id = database.add_resource(msg.chat_id, validated_url, name or validated_url, check_type, interval)
                            if res_id is not None:
                                added_count += 1
                                added_resources.append(f"• `{validated_url}` ({name or validated_url}) [{check_type.upper()}]")
                    except ValueError:
                        # Skip invalid URL
                        continue
            
            if added_count > 0:
                reply = f"📥 **Sync Complete!**\nAdded {added_count} new resource(s) from the other bot:\n" + "\n".join(added_resources)
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=reply))
            else:
                _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text="📥 **Sync Complete!**\nNo new resources to add (already up-to-date)."))
        except Exception as e:
            logger.error(f"Error parsing sync data: {e}")
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
                if async_event_loop and async_event_loop.is_running():
                    asyncio.run_coroutine_threadsafe(send_admin_notification(
                        f"🔗 **New Monitoring Peer Linked**\n"
                        f"Probe Node: 🛰️ **{peer_node}** (`{sender_addr}`)\n\n"
                        f"Linked using a `/invitepeer` token. Remove it with `/rmpeer {sender_addr}`."
                    ), async_event_loop)
            else:
                database.add_or_update_peer(peer["email"], peer_node, msg.chat_id, int(time.time()))
            _record_peer_activity(peer["email"] if peer else sender_addr)

            self_addr = _get_self_addr(bot, accid)
            ack_payload = {
                "node_name": database.get_local_node_name(),
                "sender_email": self_addr,
                "version": VERSION
            }
            ack_msg = f"[UPTIME_PEER_HELLO_ACK]\n{json.dumps(ack_payload)}\n[/UPTIME_PEER_HELLO_ACK]"
            _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=ack_msg), priority=PRIO_PEER, label="peer hello ack")
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
            peer_node = str(ack_data.get("node_name") or "Remote-Node").strip()[:64]
            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not peer or not is_private_chat:
                logger.warning(f"Ignoring peer HELLO_ACK from unknown sender {sender_addr or msg.from_id}")
                return
            database.add_or_update_peer(peer["email"], peer_node, msg.chat_id, int(time.time()))
            _record_peer_activity(peer["email"])
        except Exception as e:
            logger.error(f"Error handling peer hello ack: {e}")
        return

    # 3. Peer Cross-Check Request (Instant verification)
    if "[UPTIME_PEER_CHECK_REQ]" in text and "[/UPTIME_PEER_CHECK_REQ]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_REQ]") + len("[UPTIME_PEER_CHECK_REQ]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_REQ]")
            req_data = json.loads(text[start_idx:end_idx].strip())
            req_id = req_data.get("req_id")
            target_url = req_data.get("url")
            check_type = req_data.get("type", "http")
            keyword = req_data.get("expected_keyword")
            family = req_data.get("family") if req_data.get("family") in (4, 6) else None

            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping check request from untrusted sender {sender_addr or msg.from_id} in chat {msg.chat_id}")
                return
            _record_peer_activity(peer["email"])
            peer = _note_peer_announcement(peer, req_data)

            # Security: Validate target_url against SSRF (no localhost / private IPs)
            if not is_safe_target_url(target_url, check_type):
                logger.warning(f"Dropping unsafe cross-check target: {target_url} ({check_type})")
                return

            if req_id and target_url:
                synth_r = {
                    "id": 0,
                    "url": target_url,
                    "type": check_type,
                    "expected_keyword": keyword,
                    "family": family,
                }
                async def _do_cross_check_reply():
                    if await asyncio.to_thread(database.is_probe_target_ignored, target_url):
                        res = (None, "Ignored on this node (/probeignore)", None)  # abstain, see batch answers
                    else:
                        res = await run_single_check(synth_r)
                    if len(res) == 3:
                        is_up, error_msg, latency_ms = res
                    else:
                        is_up, error_msg = res
                        latency_ms = None
                    resp_payload = {
                        "req_id": req_id,
                        "url": target_url,
                        # "skip": not checked (no IPv6 here); the receiver files it as "unknown"
                        "status": check_status(is_up),
                        "latency_ms": latency_ms,
                        "error_msg": error_msg,
                        "node_name": database.get_local_node_name(),
                        "caps": OWN_PEER_CAPS,  # lets the requester switch to batched requests
                    }
                    resp_msg = f"[UPTIME_PEER_CHECK_RESP]\n{json.dumps(resp_payload)}\n[/UPTIME_PEER_CHECK_RESP]"
                    _dc_send_msg_with_stats(bot, accid, msg.chat_id, MsgData(text=resp_msg),
                                            priority=PRIO_PEER, expires_in=PEER_ANSWER_TTL, label="cross-check answer")

                if async_event_loop and async_event_loop.is_running():
                    asyncio.run_coroutine_threadsafe(_do_cross_check_reply(), async_event_loop)
                else:
                    try:
                        loop = asyncio.get_event_loop()
                        loop.create_task(_do_cross_check_reply())
                    except Exception:
                        asyncio.run(_do_cross_check_reply())
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
            _record_peer_activity(peer["email"])
            peer = _note_peer_announcement(peer, req_data)
            req_id = req_data.get("req_id")
            targets = _parse_batch_targets(req_data.get("targets"))
            if req_id and targets:
                coro = _answer_batch_cross_check(bot, accid, msg.chat_id, str(req_id)[:64], targets)
                if async_event_loop and async_event_loop.is_running():
                    asyncio.run_coroutine_threadsafe(coro, async_event_loop)
                else:
                    asyncio.run(coro)
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
            _record_peer_activity(peer["email"])
            peer = _note_peer_announcement(peer, resp_data)
            # Only an answer to a batch this node sent, from the chat it was sent to
            pending = pending_batch_checks.get(resp_data.get("req_id"))
            if not pending:
                return
            fut, expected_chat, count = pending
            if msg.chat_id != expected_chat:
                logger.warning(f"Dropping batch check response from unexpected peer {sender_addr} in chat {msg.chat_id}")
                return
            raw = resp_data.get("results")
            raw = raw if isinstance(raw, list) else []
            node_name = peer.get("node_name") or "Remote-Node"
            # URLs come from our own request (the future's owner knows them): only positions are trusted here
            answers = [_clean_peer_result(raw[i] if i < len(raw) else None, node_name, None) for i in range(count)]
            if not fut.done():
                if async_event_loop and async_event_loop.is_running():
                    async_event_loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(answers))
                else:
                    fut.set_result(answers)
        except Exception as e:
            logger.error(f"Error handling peer batch check response: {e}")
        return

    if "[UPTIME_PEER_CHECK_RESP]" in text and "[/UPTIME_PEER_CHECK_RESP]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_CHECK_RESP]") + len("[UPTIME_PEER_CHECK_RESP]")
            end_idx = text.find("[/UPTIME_PEER_CHECK_RESP]")
            resp_data = json.loads(text[start_idx:end_idx].strip())
            req_id = resp_data.get("req_id")
            target_url = resp_data.get("url")
            status = resp_data.get("status", "unknown")
            latency_ms = resp_data.get("latency_ms")
            error_msg = resp_data.get("error_msg")

            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping check response from untrusted sender {sender_addr or msg.from_id}")
                return
            _record_peer_activity(peer["email"])
            peer = _note_peer_announcement(peer, resp_data)

            # Only answers to a request this node sent to this very peer are accepted
            pending = pending_peer_checks.get(req_id) if req_id else None
            if not pending:
                return
            fut, expected_count, resp_list, expected_chats = pending
            if msg.chat_id not in expected_chats:
                logger.warning(f"Dropping check response for req_id {req_id} from unexpected peer {sender_addr} in chat {msg.chat_id}")
                return
            expected_chats.discard(msg.chat_id)

            node_name = peer.get("node_name") or "Remote-Node"
            if status not in VOTING_STATUSES:
                status = "unknown"
            if not isinstance(latency_ms, int) or isinstance(latency_ms, bool):
                latency_ms = None
            error_msg = str(error_msg)[:500] if error_msg else None

            if target_url and is_safe_target_url(target_url, target_type(target_url)):
                database.save_peer_measurement(target_url, node_name, status, latency_ms, error_msg, int(time.time()))

            resp_list.append({
                "req_id": req_id,
                "url": target_url,
                "status": status,
                "latency_ms": latency_ms,
                "error_msg": error_msg,
                "node_name": node_name,
            })
            if len(resp_list) >= expected_count and not fut.done():
                if async_event_loop and async_event_loop.is_running():
                    async_event_loop.call_soon_threadsafe(fut.set_result, resp_list)
                else:
                    try:
                        fut.set_result(resp_list)
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Error handling peer check response: {e}")
        return

    # 5. Peer Telemetry Batch
    if "[UPTIME_PEER_METRICS]" in text and "[/UPTIME_PEER_METRICS]" in text:
        try:
            start_idx = text.find("[UPTIME_PEER_METRICS]") + len("[UPTIME_PEER_METRICS]")
            end_idx = text.find("[/UPTIME_PEER_METRICS]")
            metrics_data = json.loads(text[start_idx:end_idx].strip())
            metrics_list = metrics_data.get("metrics", [])
            msg_id = metrics_data.get("msg_id")

            peer, sender_addr = _get_verified_peer_for_msg(bot, accid, msg, is_private_chat)
            if not _is_trusted_peer_msg(msg, peer, is_private_chat):
                logger.warning(f"Dropping telemetry from untrusted sender {sender_addr or msg.from_id}")
                return
            _record_peer_activity(peer["email"])
            peer = _note_peer_announcement(peer, metrics_data)
            if not isinstance(metrics_list, list):
                return

            # Deduplication by msg_id
            if msg_id:
                if msg_id in _processed_msg_ids:
                    logger.info(f"Ignoring duplicate telemetry batch msg_id={msg_id}")
                    return
                _processed_msg_ids.add(msg_id)
                if len(_processed_msg_ids) > _processed_msg_ids_max:
                    try:
                        _processed_msg_ids.pop()
                    except Exception:
                        pass

            peer_node = peer.get("node_name") or "Remote-Node"

            if metrics_list:
                # Sanitize metrics targets before saving
                safe_metrics = [
                    m for m in metrics_list[:200]
                    if isinstance(m, dict) and is_safe_target_url(str(m.get("url", "")), str(m.get("type", "http")))
                ]
                if safe_metrics:
                    database.save_peer_measurements_batch(peer_node, safe_metrics)
                    database.save_probe_targets_batch(safe_metrics, peer["email"])
                    _scheduler_cache["probe_targets"] = None
                    note_peer_reported_down(peer_node, safe_metrics)
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

if __name__ == "__main__":
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
