"""Micro-benchmark for the 3.0.3 hidden status update trim; run it from the repository root.

    python -m tools.loadbench.release303 [--rows 140000] [--hidden 12920] [--avg-kb 35]

Builds a fake core database (msgs table with the production shape: mostly small messages, a share
of hidden 10-80 KB carriers) and measures one trim pass in mode `on` with a stub RPC that sleeps
4 ms per deleted message, as on de2: DB connections opened, CPU and wall time of the read, delete
calls. A first pass reads the oldest 500 of a full backlog; later passes read from the same place.
No network, no Delta Chat core.
"""
import argparse
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def build(path, rows, hidden, avg_kb, now):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE msgs (id INTEGER PRIMARY KEY, chat_id INTEGER, from_id INTEGER, type INTEGER, "
                 "hidden INTEGER, timestamp INTEGER, param TEXT)")
    every = max(1, rows // hidden)
    old = now - 3 * 86400
    batch = []
    for i in range(1, rows + 1):
        if i % every == 0 and (i // every) <= hidden:
            size = int(avg_kb * 1024 * (0.3 + 1.4 * ((i * 7919) % 100) / 100))
            param = '0=1\nE={"updates":[{"payload":{"chat":"x","pad":"' + "x" * size + '"}}]}'
            batch.append((i, 12, 1, 10, 1, old + i, param))
        else:
            batch.append((i, 12, 2, 10, 0, old + i, "0=1"))
        if len(batch) >= 5000:
            conn.executemany("INSERT INTO msgs VALUES (?,?,?,?,?,?,?)", batch)
            batch = []
    if batch:
        conn.executemany("INSERT INTO msgs VALUES (?,?,?,?,?,?,?)", batch)
    conn.commit()
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=140000)
    ap.add_argument("--hidden", type=int, default=12920)
    ap.add_argument("--avg-kb", type=float, default=35)
    args = ap.parse_args()
    import bot
    now = int(time.time())
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "dc.db")
        build(path, args.rows, args.hidden, args.avg_kb, now)
        size_mb = os.path.getsize(path) / 1e6
        opens = {"n": 0}
        real_connect = sqlite3.connect

        def counting(*a, **k):
            opens["n"] += 1
            return real_connect(*a, **k)

        deletes = {"calls": 0, "ids": 0}

        class Rpc:
            def get_info(self, accid):
                return {"database_dir": path}

            def delete_messages(self, accid, ids):
                deletes["calls"] += 1
                deletes["ids"] += len(ids)
                time.sleep(0.004 * len(ids))
                conn = real_connect(path)
                conn.executemany("DELETE FROM msgs WHERE id = ?", [(i,) for i in ids])
                conn.commit()
                conn.close()

        fake = MagicMock()
        fake.rpc = Rpc()
        with patch.object(bot.database, "get_config", return_value="on"), \
                patch.object(bot.database, "get_retained_message_ids", return_value=set()), \
                patch.object(bot.database, "get_peer_rt_message_ids", return_value=set()), \
                patch.object(bot.sqlite3, "connect", counting):
            # Read only (dry), then a full pass in mode on
            with patch.object(bot.database, "get_config", return_value="dry"):
                opens["n"] = 0
                cpu, wall = time.process_time(), time.monotonic()
                bot.trim_hidden_status_updates(fake, 1, now)
                dry = {"db_opens": opens["n"], "cpu_ms": round((time.process_time() - cpu) * 1000, 1),
                       "wall_ms": round((time.monotonic() - wall) * 1000, 1)}
            with patch.object(bot.database, "get_config", return_value="dry"):
                # Worst case: nothing qualifies (all too young), so the query scans the whole table
                opens["n"] = 0
                cpu, wall = time.process_time(), time.monotonic()
                bot.trim_hidden_status_updates(fake, 1, now - 10 * 86400)
                empty = {"db_opens": opens["n"], "cpu_ms": round((time.process_time() - cpu) * 1000, 1),
                         "wall_ms": round((time.monotonic() - wall) * 1000, 1)}
            opens["n"] = 0
            cpu, wall = time.process_time(), time.monotonic()
            deleted = bot.trim_hidden_status_updates(fake, 1, now)
            on = {"deleted": deleted, "db_opens": opens["n"], "delete_calls": deletes["calls"],
                  "cpu_ms_incl_stub_deletes": round((time.process_time() - cpu) * 1000, 1),
                  "wall_ms_including_stub_4ms_per_delete": round((time.monotonic() - wall) * 1000, 1)}
        print(f"fake core db: {args.rows} rows, {args.hidden} hidden carriers, {size_mb:.0f} MB")
        print("dry pass (read only):", dry)
        print("dry pass, no candidate (full table scan):", empty)
        print("on pass:", on)


if __name__ == "__main__":
    main()
