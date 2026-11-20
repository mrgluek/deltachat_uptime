"""Generate an isolated SQLite fixture for the uptime bot load benchmark."""

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import random
import sqlite3
import time

import database


DAY = 86_400
EPOCH = 1_800_000_000
NODE = "Loadbench"
MARKER = "loadbench:fixture"
KINDS = ("http", "http", "http", "ping", "tcp", "smtp")


def target(prefix, number):
    kind = KINDS[number % len(KINDS)]
    host = f"{prefix}-{number}.example.invalid"
    return kind, {"http": f"https://{host}/health", "ping": host,
                  "tcp": f"{host}:443", "smtp": f"smtp://{host}"}[kind]


def insert(conn, table, columns, rows):
    placeholders = ", ".join("?" for _ in columns.split(","))
    with conn:
        conn.executemany(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", rows)


def make_resources(args, rng, chat_ids):
    # Give every chat a monitor, cap large chats, and shuffle the resulting assignment.
    single_chats = max(1, args.chats // 10) if args.chats > 1 else 0
    variable_chats = args.chats - single_chats
    weights = [rank ** -0.82 if rank <= variable_chats else 0 for rank in range(1, args.chats + 1)]
    cap = max(300, math.ceil((args.monitors - single_chats) / variable_chats))
    assignments = list(chat_ids)
    counts = Counter(assignments)
    while len(assignments) < args.monitors:
        choices = rng.choices(chat_ids, weights, k=args.monitors - len(assignments))
        for chat in choices:
            if counts[chat] < cap:
                counts[chat] += 1
                assignments.append(chat)
        for index, chat in enumerate(chat_ids):
            if counts[chat] == cap:
                weights[index] = 0
    rng.shuffle(assignments)
    ids = list(range(1, args.monitors + 1))
    rng.shuffle(ids)
    downs = set(ids[:round(args.monitors * 0.03)])
    degraded = set(ids[len(downs):len(downs) + round(args.monitors * 0.02)])
    created = EPOCH - (max(args.history_days, 45) + 2) * DAY
    resources = []
    for rid, chat in enumerate(assignments, 1):
        kind, url = target("monitor", rid)
        status = "down" if rid in downs else "up"
        alert = "degraded" if rid in degraded else status
        # A small fraction of open outages is already old enough for stale notices.
        age = DAY * (8 if rid % 2 else 16) if rid % 20 == 0 else 600 + rid % 2_400
        if rid in degraded and rid % 4 == 0:
            age = 120 + rid % 400
        changed = EPOCH - age if alert != "up" else EPOCH - DAY
        votes = None
        if alert != "up":
            votes = json.dumps([
                {"node": NODE, "status": "down", "local": True, "error": "Synthetic timeout"},
                {"node": "Peer 1", "status": "up" if rid in degraded else "down", "latency_ms": 60},
                {"node": "Peer 2", "status": "up", "latency_ms": 80},
            ], separators=(",", ":"))
        resources.append((
            rid, chat, f"Monitor {rid}", url, kind, 60, status, EPOCH - (-(rid * 11) % 60 or 60),
            changed, 3 if status == "down" else 0, created, 20 + rid % 81,
            alert, votes, changed if alert == "degraded" else 0,
        ))
    return resources


def make_history(args, rng, resources, by_chat, config):
    incidents, downtime, partials, events = [], [], [], []
    window = args.history_days * DAY

    def journal(kind, chat, identity, ts, rid):
        config.append((f"journal:{kind}:{chat}:{identity}", str(ts)))
        events.append((chat, ts, kind, f"Monitor {rid} {kind.replace('_', ' ')}"))

    def add_incident(chat, members, start, end):
        iid = len(incidents) + 1
        incidents.append((iid, chat, "resolved" if end else "ongoing", start, end, 400_000 + iid, 1))
        for rid, down in members:
            did = len(downtime) + 1
            downtime.append((did, rid, down, end, "Synthetic timeout", iid))
            if end or EPOCH - down > 900:
                journal("incident_start", chat, did, down, rid)
            if end:
                journal("incident_end", chat, did, end, rid)

    incident_count = round(args.chats * args.history_days * args.incidents_per_chat_per_day * args.scale)
    for index in range(incident_count):
        chat = 100 + index % args.chats
        end = EPOCH - rng.randint(1, window) - (91 * DAY if index % 257 == 0 else 0)
        start = end - rng.randint(120, 3_600)
        members = rng.sample(by_chat[chat], min(len(by_chat[chat]), rng.choice((1, 1, 1, 2, 3))))
        add_incident(chat, [(rid, start) for rid in members], start, end)

    for chat, ids in by_chat.items():
        members = [(rid, resources[rid - 1][8]) for rid in ids if resources[rid - 1][6] == "down"]
        if members:
            start = min(start for _, start in members)
            add_incident(chat, members, start - 1_200, None)
            rid = members[0][0]
            did = len(downtime) + 1
            downtime.append((did, rid, start - 1_200, start - 60, "Synthetic timeout", len(incidents)))
            journal("incident_start", chat, did, start - 1_200, rid)

    nodes = '["Loadbench"]'
    partial_count = round(args.monitors * args.history_days * args.partial_per_monitor_per_day * args.scale)
    for index in range(partial_count):
        rid = rng.randint(1, args.monitors)
        chat = resources[rid - 1][1]
        end = EPOCH - rng.randint(1, window) - (91 * DAY if index % 257 == 0 else 0)
        duration = rng.randint(90, 5_400)
        start = end - duration
        pid = index + 1
        delivered = rng.random() < 0.96
        # Legacy rows can have no mail state even when both journal entries exist.
        state = (3 if pid % 4 else -1) if delivered else (2 if end > EPOCH - DAY else -1)
        partials.append((pid, rid, start, end, nodes, state))
        if duration >= 600:
            journal("partial_start", chat, pid, start, rid)
            if delivered:
                journal("partial_end", chat, pid, end, rid)

    for rid, chat, *rest in resources:
        alert, _, start = rest[-3:]
        if alert == "degraded":
            pid = len(partials) + 1
            started = EPOCH - start >= 600
            partials.append((pid, rid, start, None, nodes, 2 if started else 0))
            if started:
                journal("partial_start", chat, pid, start, rid)

    events.sort(key=lambda row: row[1])
    return incidents, downtime, partials, events


def make_peers(args):
    peers, probes, measurements = [], [], []
    for index in range(1, args.peers + 1):
        email = f"peer-{index}@example.invalid"
        name = f"Peer {index}"
        fingerprint = f"{index:040X}"
        rt = index % 2 == 0
        peers.append((email, name, 10_000_000 + index, EPOCH - index, fingerprint,
                      int(rt), f"{index:016x}" if rt else None, 900_000 + index if rt else None,
                      bytes([index % 256]) * 32 if rt else None,
                      bytes([(index + 1) % 256]) * 32 if rt else None, EPOCH - DAY if rt else None, EPOCH - 7 * DAY))
        for number in range(1, args.targets_per_peer + 1):
            kind, url = target(f"mirrored-{index}", number)
            checked = EPOCH - ((index * 11 + number * 7) % 60 or 60)
            latency = 20 + number % 81
            probes.append((url, f"Mirror {index}/{number}", kind, email, EPOCH - index, checked, "up", latency))
            measurements.append((url, name, "up", latency, checked, checked, fingerprint))
    return peers, probes, measurements


def populate(conn, args):
    rng = random.Random(args.seed)
    chat_ids = list(range(100, 100 + args.chats))
    app_chats = set(rng.sample(chat_ids, round(args.chats * 0.6)))
    resources = make_resources(args, rng, chat_ids)
    by_chat = defaultdict(list)
    for row in resources:
        by_chat[row[1]].append(row[0])
    config = [
        (MARKER, json.dumps({"epoch": EPOCH, **{key: value for key, value in vars(args).items() if key != "db"}})),
        ("node_name", NODE), ("peer_share_scope", "all"), ("peer_rt", "on"),
    ]
    for chat in chat_ids:
        config.extend(((f"report_app:{chat}", "on" if chat in app_chats else "off"),
                       (f"report_partial:{chat}", "10"), (f"report_full:{chat}", "5"),
                       (f"alert_mode:{chat}", "quorum"),
                       (f"webxdc_chat_name:{chat}", f"Chat {chat}"),
                       (f"webxdc_dirty:{chat}", "0")))
    incidents, downtime, partials, events = make_history(args, rng, resources, by_chat, config)
    peers, probes, measurements = make_peers(args)
    insert(conn, "chats", "dc_chat_id, token, created_at, webxdc_msg_id, status_line_msg_id", (
        (chat, f"{rng.getrandbits(192):048x}", resources[0][10], 100_000 + chat if chat in app_chats else None,
         200_000 + chat if chat in app_chats else None) for chat in chat_ids))
    insert(conn, "resources", "id, dc_chat_id, name, url, type, interval, status, last_checked, last_changed, "
           "consecutive_failures, created_at, last_latency_ms, alert_state, last_votes, degraded_since", resources)
    insert(conn, "incidents", "id, dc_chat_id, status, started_at, resolved_at, msg_id, message_claimed", incidents)
    insert(conn, "downtime_events", "id, resource_id, went_down_at, went_up_at, error_msg, incident_id", downtime)
    insert(conn, "partial_outages", "id, resource_id, started_at, ended_at, nodes_down, notice_state", partials)
    # Resource inserts fire the bot's journal triggers. Give those entries the synthetic creation time.
    with conn:
        conn.execute("UPDATE chat_events SET ts = ?", (resources[0][10],))
        conn.executemany("INSERT INTO chat_events (dc_chat_id, ts, kind, text) VALUES (?, ?, ?, ?)", events)
    insert(conn, "peers", "email, node_name, chat_id, last_seen, fingerprint, rt_capable, rt_cid, rt_msg_id, "
           "rt_key_out, rt_key_in, rt_created_at, created_at", peers)
    insert(conn, "probe_targets", "url, name, type, source_peer, last_seen, last_checked, last_status, last_latency_ms", probes)
    insert(conn, "peer_measurements", "url, node_name, status, latency_ms, last_checked, received_at, source_peer",
           measurements)
    insert(conn, "peer_rtt", "ts, kind, transport, peer, ms, ok", (
        (EPOCH - (day + 1) * DAY + sample * 3_600, "vote", "mail", peer[4], 200 + sample * 10, 1)
        for day in range(round(args.history_days * args.scale))
        for peer in peers for sample in range(4)))
    insert(conn, "peer_traffic", "day, kind, transport, dir, n, bytes", (
        (datetime.fromtimestamp(EPOCH - day * DAY, timezone.utc).date().isoformat(), kind, transport,
         direction, len(peers) * 20, len(peers) * 80_000)
        for day in range(round(args.history_days * args.scale))
        for kind in ("METRICS", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP")
        for transport in ("rt", "mail") for direction in ("in", "out")))
    # Trigger-created settings are intentionally reset to the settled status-app state.
    with conn:
        conn.executemany("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", config)


TABLES = ("chats", "resources", "downtime_events", "incidents", "partial_outages", "chat_events",
          "peers", "peer_measurements", "probe_targets", "peer_rtt", "peer_traffic", "config")


def describe(conn):
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--monitors", type=int, default=10_000)
    parser.add_argument("--chats", type=int, default=300)
    parser.add_argument("--peers", type=int, default=20)
    parser.add_argument("--targets-per-peer", type=int, default=200)
    parser.add_argument("--history-days", type=int, default=30)
    parser.add_argument("--partial-per-monitor-per-day", type=float, default=0.3)
    parser.add_argument("--incidents-per-chat-per-day", type=float, default=2)
    parser.add_argument("--scale", type=float, default=1.0)
    args = parser.parse_args()
    if not 1 <= args.chats <= args.monitors:
        parser.error("require 1 <= chats <= monitors")
    if min(args.peers, args.targets_per_peer, args.history_days) < 0:
        parser.error("peer, target and history counts must be nonnegative")
    rates = (args.partial_per_monitor_per_day, args.incidents_per_chat_per_day, args.scale)
    if any(not math.isfinite(n) or n < 0 for n in rates):
        parser.error("history rates and scale must be finite and nonnegative")

    start = time.perf_counter()
    path = args.db.absolute()
    try:
        # Reserve a new destination without following a symlink or truncating an existing file.
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = f"{path}{suffix}"
            if os.path.lexists(sidecar):
                raise FileExistsError(sidecar)
        with path.open("xb"):
            pass
    except FileExistsError as exc:
        parser.error(f"choose a new database path ({exc})")
    previous_path = database.DB_PATH
    try:
        database.DB_PATH = str(path)
        database.init_db()
        database.close_db()
        with closing(sqlite3.connect(path)) as conn:
            populate(conn, args)
            print(json.dumps(describe(conn), indent=2))
    finally:
        database.close_db()
        database.DB_PATH = previous_path
    print(f"{path}: {path.stat().st_size:,} bytes in {time.perf_counter() - start:.2f} s")


if __name__ == "__main__":
    main()
