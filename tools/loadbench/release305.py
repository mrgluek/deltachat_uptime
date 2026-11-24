"""Benchmark for the 3.0.5 delta status updates; run it from the repository root.

    python -m tools.loadbench.release305 [--monitors 84] [--nodes 7] [--updates 100]

Fake database of N monitors x M nodes, a stub RPC, and a simulated run of updates that each flip 1-3
monitors, delivered through the real _deliver_status_app. Prints, old (mode off, snapshots only) against
new (delta updates): bytes of one update, total bytes per run, and CPU time per update (the whole
delivery pass, including building the state). No network, no Delta Chat core.
"""
import argparse
import itertools
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def run(mode, monitors, nodes, updates):
    import bot
    import database
    from outbox import Outbox
    with tempfile.TemporaryDirectory() as tmp:
        old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(tmp, "bench.db")
        database.init_db()
        clock = {"now": 1_000_000}
        rpc = MagicMock()
        rpc.get_existing_msg_ids.side_effect = lambda acc, ids: ids
        rpc.get_basic_chat_info.return_value = {"name": "Bench"}
        rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 128000, "sendUpdateInterval": 10000}
        rpc.get_chat_contacts.return_value = [1, 2, 3]
        client = MagicMock(rpc=rpc)
        patches = [patch.object(bot, "dc_outbox", Outbox()), patch.object(bot, "dc_bot_instance", client),
                   patch.object(bot, "dc_accid", 1), patch.dict(os.environ, {"DC_DB_DIR": tmp}),
                   patch("bot.time.time", side_effect=lambda: clock["now"])]
        for p in patches:
            p.start()
        try:
            database.set_chat_report_app(1, "on")
            rids = []
            for i in range(monitors):
                rid = database.add_resource(1, f"https://example{i}.org/health", f"Example monitor {i}", "http")
                votes = json.dumps([{"node": f"node{n}", "status": "up", "latency_ms": 20 + (rid + n) % 50,
                                     "error": None} for n in range(nodes)])
                with database._writer_transaction() as conn:
                    conn.execute("UPDATE resources SET status='up', last_changed=?, last_votes=? WHERE id=?",
                                 (900_000 + i, votes, rid))
                rids.append(rid)
            database.set_config("status_app_delta", mode)
            database.set_chat_webxdc(1, 321)
            database.set_chat_status_line(1, 322, bot._status_line_hash(bot.status_line_text(bot.build_status_state(1))))
            database.set_config("webxdc_app_version:1", "6")
            database.set_config("webxdc_posted_at:1", str(clock["now"]))
            rng = random.Random(7)
            sizes, cpu = [], []
            for i in range(updates):
                if i:
                    clock["now"] += 400
                    for rid in rng.sample(rids, rng.randint(1, 3)):
                        status = next(r["status"] for r in database.get_resources(1) if r["id"] == rid)
                        with database._writer_transaction() as conn:
                            conn.execute("UPDATE resources SET status=?, last_changed=? WHERE id=?",
                                         ("down" if status == "up" else "up", clock["now"], rid))
                before = rpc.send_webxdc_status_update.call_count
                t0 = time.process_time()
                bot._deliver_status_app(1, client, 1, known_msg_id=321)
                cpu.append(time.process_time() - t0)
                database.set_chat_status_line(1, 322, bot._status_line_hash(bot.status_line_text(bot.build_status_state(1))))
                calls = rpc.send_webxdc_status_update.call_args_list
                if len(calls) > before:
                    sizes.append(len(calls[-1][0][2].encode()))
            return sizes, cpu
        finally:
            for p in reversed(patches):
                p.stop()
            database.close_db()
            database.DB_PATH = old_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--monitors", type=int, default=84)
    ap.add_argument("--nodes", type=int, default=7)
    ap.add_argument("--updates", type=int, default=100)
    args = ap.parse_args()
    print(f"{args.monitors} monitors x {args.nodes} nodes, {args.updates} updates of 1-3 flipped monitors")
    for label, mode in (("old (snapshots)", "off"), ("new (deltas)   ", "on")):
        sizes, cpu = run(mode, args.monitors, args.nodes, args.updates)
        ordered = sorted(sizes)
        print(f"{label}: first {sizes[0]} B, median {ordered[len(ordered) // 2]} B, max {ordered[-1]} B, "
              f"total {sum(sizes)} B per {len(sizes)} updates, CPU {1000 * sum(cpu) / len(cpu):.1f} ms per update")


if __name__ == "__main__":
    main()
