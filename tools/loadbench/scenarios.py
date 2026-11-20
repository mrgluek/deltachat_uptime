"""Synthetic workloads that call the bot's normal timer and database functions."""

import asyncio
from collections import Counter
from concurrent.futures import Future
from contextlib import ExitStack
import json
import socket
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import urlparse

import database

from .gen_db import DAY, NODE
from .measure import Proxy, patch


SCENARIOS = (
    "scheduler_tick", "record_checks", "report_notices", "status_apps", "telemetry",
    "peer_metrics_in", "quorum_votes", "cleanup", "stale_downtime", "startup",
    "cache_pressure", "rt_ack_queue",
)
VARIANT = "record_checks_all_up"
BOT_FUNCTIONS = (
    "monitoring_scheduler_loop", "_due_vote_grid_ticks", "run_checks_parallel",
    "run_and_track_group", "_run_grid_checks", "_check_report_notices", "_journal_partial_events",
    "sync_chat_incident_state", "_journal_incident_events", "push_status_apps", "build_status_state",
    "broadcast_telemetry_to_peers", "_broadcast_peer_updates", "_broadcast_peer_rt_metrics",
    "_send_peer_rt_unacked", "_apply_peer_metrics", "_quorum_resource_ids", "_peer_cross_check_allowed",
    "_flush_cross_checks", "_batch_cross_check_peer", "check_stale_downtime_notifications",
    "_send_stale_message", "realtime_status_tick", "audit_abandoned_chats", "trim_peer_chats",
    "trim_user_chats", "audit_peer_rt_carriers",
)
DB_FUNCTIONS = (
    "record_check_results", "update_probe_target_result", "save_peer_measurement",
    "save_peer_measurements_batch", "save_probe_targets_batch", "cleanup_old_records",
    "get_local_node_name", "get_chat_alert_mode", "get_chat_report_partial", "get_chat_report_full",
    "get_chat_report_app", "add_chat_event", "get_chat_webxdc", "get_status_app_chats",
    "get_resource_by_id", "audit_peers_offline", "flush_transport_stats",
)


def import_bot_offline():
    violations = []

    def deny_network(event, args):
        if ((event == "socket.__new__" and args[1] != socket.AF_UNIX)
                or (event.startswith("socket.") and event != "socket.__new__")
                or event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn")):
            violations.append(event)
            raise RuntimeError(f"loadbench forbids {event}")

    sys.addaudithook(deny_network)
    # Mock the same imports as the offline unit tests. Keep message text as a real string.
    modules = {"deltachat2": MagicMock(MsgData=SimpleNamespace), "deltabot_cli": MagicMock(),
               "aiodns": None, "aioping": None}
    sys.modules.update(modules)
    with patch(socket, "getfqdn", lambda *args: "loadbench.example.invalid"):
        import bot
    return bot, violations


class FakeSession:
    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass


class FakeRPC:
    def __init__(self, bench, chats, peers):
        self.bench = bench
        self.chats = chats
        self.peers = {p["chat_id"]: p for p in peers}
        self.methods = Counter()
        self.wire_bytes = Counter()
        self.next_msg_id = 1_000_000
        self.answers = 0
        self.unexpected = set()
        self.lock = threading.Lock()

    def count(self, method, size=0):
        with self.lock:
            self.methods[method] += 1
            self.wire_bytes[method] += size
        self.bench.meter.add("rpc_calls")
        self.bench.meter.add("rpc_bytes", size)

    def get_contact(self, accid, contact_id):
        self.count("get_contact")
        return {"address": "loadbench@example.invalid"}

    def get_chat_securejoin_qr_code(self, accid, chat_id):
        self.count("get_chat_securejoin_qr_code")
        return "OPENPGP4FPR:" + "F" * 40

    def get_existing_msg_ids(self, accid, msg_ids):
        self.count("get_existing_msg_ids")
        return msg_ids

    def get_full_chat_by_id(self, accid, chat_id):
        self.count("get_full_chat_by_id")
        return {"name": f"Chat {chat_id}", "chat_type": "Group", "self_in_group": True}

    def get_basic_chat_info(self, accid, chat_id):
        self.count("get_basic_chat_info")
        return {"name": f"Chat {chat_id}", "chat_type": "Single" if chat_id in self.peers else "Group"}

    def get_chat_contacts(self, accid, chat_id):
        self.count("get_chat_contacts")
        return range(15 if chat_id % 3 == 0 else 3)

    def get_chatlist_entries(self, accid, flags, *args):
        self.count("get_chatlist_entries")
        return self.chats if flags == 0 else []

    def get_message_ids(self, accid, chat_id, *args):
        self.count("get_message_ids")
        carrier = self.peers.get(chat_id, {}).get("rt_msg_id")
        return [carrier] if carrier else []

    def send_msg(self, accid, chat_id, message):
        text = getattr(message, "text", "")
        self.count("send_msg", len(text.encode("utf-8")))
        with self.lock:
            self.next_msg_id += 1
            msg_id = self.next_msg_id
        if text.startswith("[UPTIME_PEER_CHECK_BATCH_REQ]\n"):
            data = json.loads(text.split("\n", 2)[1])
            future = self.bench.bot.pending_batch_checks[data["req_id"]][0]
            answers = [{"node_name": self.peers[chat_id]["node_name"], "status": "up",
                        "latency_ms": 35, "error_msg": None} for _ in data["targets"]]
            with self.lock:
                self.answers += len(answers)
            future.get_loop().call_soon_threadsafe(future.set_result, answers)
        return msg_id

    def send_webxdc_realtime_data(self, accid, msg_id, data):
        self.count("send_webxdc_realtime_data", len(data))

    def __getattr__(self, method):
        self.unexpected.add(method)
        raise AssertionError(f"RPC method {method} needs an offline stub")


class FakeOutbox:
    def __init__(self, bench, *, inline):
        self.bench = bench
        self.inline = inline
        self.priorities = Counter()
        self.lock = threading.Lock()

    def submit(self, fn, priority=1, key=None, expires_in=None, label="", *, kind="other"):
        with self.lock:
            self.priorities[priority] += 1
        self.bench.meter.add("mails_queued")
        future = Future()
        if not self.inline:
            return future
        try:
            result = fn()
            if kind is not None and result is not self.bench.bot.SKIP_SEND:
                self.bench.bot.record_sent_mail(kind)
            future.set_result(result)
        except Exception as exc:
            future.set_exception(exc)
            raise
        return future


class Bench:
    def __init__(self, name, bot, meter, clock, stack):
        self.name = name
        self.bot = bot
        self.meter = meter
        self.clock = clock
        self.stack = stack
        self.resources = database.get_all_resources()
        self.probes = database.get_active_probe_targets()
        self.peers = database.get_all_peers()
        self.chats = sorted({r["dc_chat_id"] for r in self.resources})
        self.rpc = FakeRPC(self, self.chats, self.peers)
        self.outbox = FakeOutbox(self, inline=name in ("telemetry", "quorum_votes", "stale_downtime"))
        self.details = {}
        self.notes = []

        def fake_dns(*args, **kwargs):
            return ["192.0.2.1"]

        async def fake_async_dns(*args, **kwargs):
            return fake_dns(*args, **kwargs)

        def unexpected_network(*args, **kwargs):
            raise AssertionError("A benchmark workload reached the network probe path")

        stack.enter_context(patch(bot, "dc_bot_instance", SimpleNamespace(rpc=self.rpc)))
        stack.enter_context(patch(bot, "dc_accid", 1))
        stack.enter_context(patch(bot, "dc_outbox", self.outbox))
        stack.enter_context(patch(bot, "time", clock))
        stack.enter_context(patch(bot, "monotonic", clock.monotonic))
        stack.enter_context(patch(bot, "aiohttp", Proxy(bot.aiohttp, ClientSession=FakeSession)))
        stack.enter_context(patch(bot, "_make_safe_connector", unexpected_network if name not in
                                  ("scheduler_tick", "startup") else lambda **kwargs: None))
        stack.enter_context(patch(bot, "resolve_host_safe_sync", fake_dns))
        stack.enter_context(patch(bot, "resolve_host_safe", fake_async_dns))
        stack.enter_context(patch(bot, "run_single_check", unexpected_network))
        meter.install_executors(stack, bot)
        for name in BOT_FUNCTIONS:
            stack.enter_context(patch(bot, name, meter.wrap(getattr(bot, name))))
        for name in DB_FUNCTIONS:
            stack.enter_context(patch(database, name, meter.wrap(getattr(database, name))))
        self.priorities = {getattr(bot, f"PRIO_{name.upper()}"): name
                           for name in ("alert", "reply", "update", "peer", "telemetry")}

    def note(self, text):
        self.notes.append(text)

    def communications(self):
        return {"rpc_calls_by_method": dict(self.rpc.methods),
                "rpc_bytes_by_method": {key: value for key, value in self.rpc.wire_bytes.items() if value},
                "mails_queued_by_priority": {self.priorities[key]: value
                                             for key, value in self.outbox.priorities.items()}}


def prepare_status(bench):
    bot = bench.bot
    chats = database.get_status_app_chats()
    config = []
    saved = []
    for chat in chats:
        state = bot.build_status_state(chat)
        status_hash = bot.status_state_hash(state)
        full_hash = bot.status_full_state_hash(state)
        line_hash = bot._status_line_hash(bot.status_line_text(state))
        saved.append((status_hash, line_hash, bench.clock.epoch - 600, chat))
        config.extend(((f"webxdc_clean:{chat}", "0"),
                       (f"webxdc_app_version:{chat}", str(bot.WEBXDC_APP_VERSION)),
                       (f"webxdc_posted_at:{chat}", str(bench.clock.epoch - DAY)),
                       (f"webxdc_update_count:{chat}", "1"),
                       (f"webxdc_full_state_hash:{chat}", full_hash)))
    with database._writer_transaction() as conn:
        conn.executemany("UPDATE chats SET webxdc_state_hash = ?, status_line_hash = ?, "
                         "webxdc_last_sent_at = ? WHERE dc_chat_id = ?", saved)
        conn.executemany("INSERT OR REPLACE INTO config VALUES (?, ?)", config)
    database.invalidate_uptime_cache()
    database.close_db()
    return set(chats)


async def status_apps(bench):
    enabled = bench.app_chats
    bench.note("Real push scans all enabled chats. The harness also builds a snapshot for each disabled chat "
               "per pass to measure the per-chat cost across the whole fixture.")
    bench.note("Outbox submissions are counted before deferred delivery. The changed pass renames one monitor "
               "per enabled chat after the unchanged pass, without expiring the 60 s uptime cache.")
    for offset, name in ((0, "status_unchanged"), (30, "status_changed")):
        bench.clock.offset = offset
        if offset:
            # This fixture mutation lives outside the two per-pass spans.
            with database._writer_transaction() as conn:
                last_event = conn.execute("SELECT COALESCE(MAX(id), 0) FROM chat_events").fetchone()[0]
                conn.executemany(
                    "UPDATE resources SET name = name || ' renamed' WHERE id = "
                    "(SELECT MIN(id) FROM resources WHERE dc_chat_id = ?)", ((chat,) for chat in enabled))
                # SQLite's journal triggers use the real clock, independent of Clock.
                conn.execute("UPDATE chat_events SET ts = ? WHERE id > ?", (int(bench.clock.time()), last_event))
        with bench.meter.span(name):
            await bench.bot.push_status_apps()
            for chat in bench.chats:
                if chat not in enabled:
                    await bench.bot.run_db(bench.bot.build_status_state, chat)
    bench.details["app_chats"] = len(enabled)
    bench.details["passes"] = 2


async def record_checks(bench):
    all_up = bench.name == VARIANT
    bench.note("Serial submissions use the bot's database executor. Outcomes match the starting states "
               "to measure steady-state writes. All UP is measured on a separate fixture copy.")
    with bench.meter.span("local_monitor_checks"):
        for r in bench.resources:
            status = "up" if all_up else r["status"]
            error = "Synthetic timeout" if status == "down" else None
            node = database.get_local_node_name()
            latency = r["last_latency_ms"] if status == "up" else None
            update = {"id": r["id"], "status": status, "consecutive_failures": r["consecutive_failures"],
                      "latency_ms": latency, "error_msg": error}
            await bench.bot.run_db(database.record_check_results, [update], (r["url"], node, status, latency, error))
    with bench.meter.span("probe_only_checks"):
        for probe in bench.probes:
            url, latency = probe["url"], probe["last_latency_ms"]
            node = database.get_local_node_name()
            await bench.bot.run_db(database.update_probe_target_result, url, "up", latency)
            await bench.bot.run_db(database.save_peer_measurement, url, node, "up", latency, local=True)
    bench.details.update(monitors=len(bench.resources), probes=len(bench.probes),
                         down=0 if all_up else sum(r["status"] == "down" for r in bench.resources))
    bench.details["local_measurements"] = sum(
        row["node_name"] == NODE for row in database.get_all_peer_measurements())


async def report_notices(bench):
    bot = bench.bot
    bench.note("Each pass uses the normal partial journal call within report notices and syncs each chat "
               "with an active incident. Outbox deliveries are deferred.")
    for offset in (0, 30):
        bench.clock.offset = offset
        await bot._check_report_notices()
        active = await bot.run_db(database.get_all_active_incidents)
        await asyncio.gather(*(bot.sync_chat_incident_state(chat) for chat in sorted({i["dc_chat_id"] for i in active})))
    bench.details.update(passes=2, active_incidents=len(active))


async def telemetry(bench):
    bot = bench.bot
    for index, peer in enumerate(bench.peers, 1):
        if peer["rt_msg_id"]:
            link = bot._PeerRealtimeLink(peer, None, epoch=f"{index:032x}", remote_epoch=f"{index + 1000:032x}")
            link.state.on_frame()
            bot._peer_rt_links[peer["rt_msg_id"]] = link
    await bot.broadcast_telemetry_to_peers()
    url = next((r["url"] for r in bench.resources if r["status"] == "up"), None)
    for delta in range(1, 7):
        bench.clock.offset = 10 * delta
        # Keep established channels up and alternate a reachable monitor's local path state.
        for link in bot._peer_rt_links.values():
            link.state.on_frame()
        if url and delta % 2:
            bot._local_degraded[url] = bench.clock.time()
        else:
            bot._local_degraded.pop(url, None)
        await bot.broadcast_telemetry_to_peers(rt_delta=True)
    bench.note("RT-capable peers start with established synthetic links. The normal RT encoder and inline "
               "mail submission callbacks run against fake RPC. The initial timer pass is due for every peer.")
    bench.details.update(timer_passes=1, rt_delta_passes=6, rt_peers=len(bot._peer_rt_links))


async def peer_metrics_in(bench):
    bot = bench.bot
    by_email = {}
    for target in bench.probes:
        by_email.setdefault(target["source_peer"], []).append(
            {"url": target["url"], "type": target["type"], "status": "up",
             "latency_ms": target["last_latency_ms"], "last_checked": int(bench.clock.time())})
    applied = 0
    batches = 0
    size = 0
    for index, peer in enumerate(bench.peers):
        targets = by_email.get(peer["email"], [])
        for start in range(0, len(targets), 200):
            batch = targets[start:start + 200]
            caps = list(bot.OWN_PEER_CAPS) + ([bot.PEER_CAP_RT] if peer["rt_capable"] else [])
            payload = {"msg_id": f"loadbench-{index}-{start}", "node_name": peer["node_name"],
                       "timestamp": int(bench.clock.time()), "telemetry_interval": 180,
                       "desired_interval": 180, "version": bot.VERSION, "caps": caps, "metrics": batch}
            encoded = json.dumps(payload)
            size += len(encoded.encode("utf-8"))
            await bot.run_db(bot._apply_peer_metrics, peer, encoded,
                             "rt" if peer["rt_capable"] else "mail")
            applied += len(batch)
            batches += 1
    if bench.meter.functions["save_peer_measurements_batch"]["calls"] != batches:
        raise RuntimeError("peer metrics did not reach the measurement write path")
    bench.note("Inbound payloads are pre-authenticated fixture messages. The production parser and validation "
               "run with fixed synthetic DNS answers. Each request carries at most 200 metrics.")
    bench.details.update(peers=len(bench.peers), incoming_batches=batches, incoming_metrics=applied,
                         incoming_json_bytes=size)


async def quorum_votes(bench):
    bot = bench.bot
    targets = sorted(bench.resources, key=lambda r: (r["alert_state"] == "up", r["id"]))[:500]
    for peer in bench.peers:
        bot._note_peer_caps(peer["email"], bot.OWN_PEER_CAPS)
    loop = asyncio.get_running_loop()
    batch = []
    for target in targets:
        group = [dict(target, status="down", alert_state="down")]
        quorum = await bot._quorum_resource_ids(group)
        allowed = await bot._peer_cross_check_allowed(group)
        if quorum and allowed:
            batch.append((group[0], loop.create_future(), None))
    await bot._flush_cross_checks(batch)
    answers = sum(len(f.result()) for _, f, _ in batch)
    if answers != len(batch) * min(len(bench.peers), bot.VOTE_SAMPLE_SIZE) or answers != bench.rpc.answers:
        raise RuntimeError(f"unexpected quorum reply count: {answers}")
    bench.note("Each failing URL gets the normal per-group quorum and sharing checks. The bot selects up to "
               "seven batch-capable peers and the fake RPC supplies immediate positional votes.")
    bench.details.update(failing_monitors=len(targets), cross_checks=len(batch), votes=answers)


async def cleanup(bench):
    bench.details["deleted_rows"] = await bench.bot.run_db(database.cleanup_old_records, 90)
    bench.note("One daily maintenance invocation at 90-day retention. Lock hold is measured from acquisition "
               "to release of the writer lock, including commit.")


async def cache_pressure(bench):
    bot = bench.bot
    urls = (row["url"] for row in (*bench.resources, *bench.probes))
    hosts = list(dict.fromkeys(urlparse(url if "://" in url else f"//{url}").hostname
                               for url in urls))[:12_000]
    addresses = ("192.0.2.1",)
    dns_lock = bot._dns_cache_lock

    class TimedDnsLock:
        acquires = acquire_ns = hold_ns = 0

        def __enter__(self):
            started = time.perf_counter_ns()
            dns_lock.acquire()
            self.acquired = time.perf_counter_ns()
            self.acquire_ns += self.acquired - started
            self.acquires += 1

        def __exit__(self, *exc):
            finished = time.perf_counter_ns()
            dns_lock.release()
            self.hold_ns += finished - self.acquired

    timed_lock = TimedDnsLock()
    with patch(bot, "_dns_cache_lock", timed_lock), bench.meter.span("dns_cache"):
        dns_hits = 0
        for _ in range(2):
            dns_hits = 0
            for host in hosts:
                if bot._dns_cache_get(host) is None:
                    bot._dns_cache_put(host, addresses, 60)
                else:
                    dns_hits += 1

    requests = 0

    async def request(*args, **kwargs):
        nonlocal requests
        requests += 1
        return [{"node": "Peer", "status": "up"}]

    with patch(bot, "request_peer_cross_checks_batched", request), bench.meter.span("vote_cache"):
        for _ in range(2):
            requests = 0
            for resource in bench.resources:
                await bot.collect_peer_votes(resource, True)
    bench.details.update(dns_hosts=len(hosts), dns_second_pass_hits=dns_hits,
                         dns_lock_acquires=timed_lock.acquires, dns_lock_acquire_ns=timed_lock.acquire_ns,
                         dns_lock_hold_ns=timed_lock.hold_ns,
                         vote_targets=len(bench.resources),
                         vote_second_pass_hits=len(bench.resources) - requests)
    bench.note("Two passes over the fixture's distinct hosts and monitor vote keys. DNS misses and "
               "remote vote requests use in-memory stubs. Hit counts are for the second pass.")


async def rt_ack_queue(bench):
    bot = bench.bot
    rt = bot.peer_rt
    links = {}
    for peer in bench.peers:
        if peer["rt_msg_id"]:
            link = bot._PeerRealtimeLink(peer, None, remote_epoch="a" * 32)
            link.state.on_frame()
            links[peer["rt_msg_id"]] = link
    queued = asyncio.Event()
    release = asyncio.Event()
    queued_count = 0
    execute = bot.run_rpc
    original_send = bench.rpc.send_webxdc_realtime_data

    async def queued_send(fn):
        nonlocal queued_count
        queued_count += 1
        if queued_count == 2 * len(links):
            queued.set()
        await release.wait()
        return await execute(fn)

    def send_and_ack(accid, msg_id, data):
        original_send(accid, msg_id, data)
        link = links[msg_id]
        frame = rt.authenticate(bytes(data), link.peer["rt_key_out"], clock=bot.time.time)
        ack = rt.encode("ack", link.remote_epoch, frame["s"], {"e": link.epoch, "s": [frame["s"]]},
                        link.peer["rt_key_in"], recipient=link.epoch, clock=bot.time.time)
        with bot._peer_rt_lock:
            bot._verify_peer_rt_frame(link, ack)

    with (patch(bot, "_peer_rt_links", links), patch(bot, "run_rpc", queued_send),
          patch(bench.rpc, "send_webxdc_realtime_data", send_and_ack)):
        sends = [asyncio.create_task(bot._send_peer_rt_check(
            SimpleNamespace(bot=bot.dc_bot_instance, accid=1), msg_id, link, "req",
            {"req_id": str(seq)}, lambda ttl: bench.meter.add("mails_queued"),
            30, None, None, None, None, None,
        )) for msg_id, link in links.items() for seq in range(2)]
        if sends:
            await queued.wait()
            bench.clock.offset += 3.5
            for link in links.values():
                bot._expire_peer_rt_acks(link)
            release.set()
            await asyncio.gather(*sends)
            await asyncio.sleep(0)  # Let fallback callbacks schedule their mail jobs.
            await asyncio.gather(*(task for task in asyncio.all_tasks() if task is not asyncio.current_task()))
    bench.details.update(links=len(links), queued_sends=queued_count, simulated_queue_seconds=3.5,
                         links_up=sum(link.state.is_up for link in links.values()))
    bench.note("Two requests per realtime link wait 3.5 simulated seconds for an RPC executor slot. "
               "The stub core acknowledges each frame as soon as it receives it.")


def prepare_stale(bench):
    size = min(500, len(bench.resources))
    targets = sorted(bench.resources, key=lambda r: (r["status"] != "down", r["id"]))[:size]
    now = int(bench.clock.time())
    promotions = [(r["id"], now - (16 * DAY if seq % 10 == 0 else 3600))
                  for seq, r in enumerate(targets) if r["status"] != "down"]
    with database._writer_transaction() as conn:
        conn.executemany("UPDATE resources SET status = 'down', alert_state = 'down', last_changed = ? WHERE id = ?",
                         ((since, rid) for rid, since in promotions))
        conn.executemany("INSERT INTO downtime_events (resource_id, went_down_at, error_msg) VALUES (?, ?, ?)",
                         ((rid, since, "Synthetic timeout") for rid, since in promotions))
    database.close_db()
    return targets


async def stale_downtime(bench):
    for r in bench.stale:
        await bench.bot.check_stale_downtime_notifications(r, int(bench.clock.time()))
    bench.note("The fixture supplements naturally DOWN monitors to reach 500 when possible. Some extra "
               "outages are 16 days old to exercise notices. Mail sends are inline against fake RPC.")
    bench.details["down_monitors"] = len(bench.stale)


class EndTicks(Exception):
    pass


async def scheduler(bench):
    bot = bench.bot
    startup = bench.name == "startup"
    ticks = 1 if startup else 12
    loop = asyncio.get_running_loop()
    scheduler_task = asyncio.current_task()
    tasks = []
    tasks_by_name = Counter()
    groups = Counter()
    first_dispatch = None
    tick = 0

    def task_factory(loop, coro, **kwargs):
        nonlocal first_dispatch
        name = getattr(coro, "__name__", type(coro).__name__)
        # Async measurement wrappers share a code name and carry the wrapped callable.
        if name == "measured" and getattr(coro, "cr_frame", None):
            wrapped = coro.cr_frame.f_locals.get("function")
            if wrapped is not None:
                name = wrapped.__name__
        if first_dispatch is None and name in ("run_checks_parallel", "_run_grid_checks"):
            first_dispatch = time.perf_counter() - start
        task = asyncio.Task(coro, loop=loop, **kwargs)
        tasks_by_name[name] += 1
        tasks.append(task)
        return task

    async def sleep(delay):
        nonlocal tick
        if asyncio.current_task() is not scheduler_task:
            return await asyncio.sleep(delay)
        drained = 0
        while drained < len(tasks):
            pending = tasks[drained:]
            await asyncio.gather(*pending)
            drained += len(pending)
        tasks.clear()
        tick += 1
        if tick >= ticks:
            raise EndTicks
        bench.clock.offset += 5

    async def skip_check(group, semaphore, session=None):
        groups["probes" if group[0].get("is_probe_only") else "monitors"] += 1

    async def noop_async(*args, **kwargs):
        pass

    def noop(*args, **kwargs):
        pass

    with ExitStack() as stack:
        stack.enter_context(patch(bot, "asyncio", Proxy(bot.asyncio, sleep=sleep)))
        stack.enter_context(patch(bot, "secrets", Proxy(bot.secrets, randbelow=lambda limit: 0)))
        stack.enter_context(patch(bot, "check_group_task", skip_check))
        if not startup:
            for name in ("_broadcast_peer_updates", "_check_report_notices", "push_status_apps",
                         "realtime_status_tick", "audit_abandoned_chats"):
                stack.enter_context(patch(bot, name, noop_async))
            for name in ("trim_peer_chats", "trim_user_chats"):
                stack.enter_context(patch(bot, name, noop))
            for name in ("get_all_active_incidents", "audit_peers_offline"):
                stack.enter_context(patch(database, name, lambda *args, **kwargs: []))
            for name in ("cleanup_old_records", "flush_transport_stats"):
                stack.enter_context(patch(database, name, noop))
        old_factory = loop.get_task_factory()
        loop.set_task_factory(task_factory)
        start = time.perf_counter()
        try:
            await bot.monitoring_scheduler_loop()
        except EndTicks:
            pass
        finally:
            loop.set_task_factory(old_factory)
    bench.details.update(ticks=tick, groups_dispatched=dict(groups), tasks_created=sum(tasks_by_name.values()),
                         tasks_by_coroutine=dict(tasks_by_name), first_dispatch_s=first_dispatch)
    bench.note("The real scheduler dispatches tasks and tracks completion. Check bodies return immediately "
               "without sockets or result writes. Virtual ticks are exactly 5 s apart, with zero grid jitter.")
    if startup:
        bench.note("All startup timer work runs with fake RPC and an empty core message history except synthetic "
                   "RT carriers. Mails stay in the outbox stub. Time to first dispatch ends at task creation.")
    else:
        bench.note("Periodic timer work is stubbed here because the other scenarios measure it separately.")


def prepare(bench):
    if bench.name in ("status_apps", "startup"):
        bench.app_chats = prepare_status(bench)
    elif bench.name == "stale_downtime":
        bench.stale = prepare_stale(bench)
    elif bench.name == VARIANT:
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET status = 'up', alert_state = 'up', consecutive_failures = 0")
            conn.execute("UPDATE downtime_events SET went_up_at = ? WHERE went_up_at IS NULL", (bench.clock.epoch - 1,))
        database.close_db()
        for resource in bench.resources:
            resource["consecutive_failures"] = 0


WORKLOADS = {
    "scheduler_tick": scheduler, "startup": scheduler, "record_checks": record_checks,
    VARIANT: record_checks, "report_notices": report_notices, "status_apps": status_apps,
    "telemetry": telemetry, "peer_metrics_in": peer_metrics_in, "quorum_votes": quorum_votes,
    "cleanup": cleanup, "stale_downtime": stale_downtime,
    "cache_pressure": cache_pressure, "rt_ack_queue": rt_ack_queue,
}
