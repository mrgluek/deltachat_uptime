import asyncio
import contextlib
import datetime
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import bot
import database
from outbox import Outbox


def message(kind, payload="é"):
    tag = "UPTIME_BOT_SYNC_DATA" if kind == "BOT_SYNC_DATA" else f"UPTIME_PEER_{kind}"
    return f"[{tag}]\n{payload}\n[/{tag}]"


def event(text, chat_id=7, sender=42):
    return SimpleNamespace(msg=SimpleNamespace(
        text=text, chat_id=chat_id, from_id=sender, is_info=False,
    ))


class TestPeerMetrics(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.object(database, "DB_PATH", str(Path(directory) / "uptime.db")))
        self.enterContext(patch.object(database, "_peer_traffic_buffer", {}))
        self.enterContext(patch.object(database, "_peer_rtt_buffer", []))
        self.enterContext(patch.object(bot, "dc_outbox", Outbox()))
        self.addCleanup(database.close_db)
        # An existing pre-metrics DB should gain the new tables without losing data.
        with contextlib.closing(sqlite3.connect(database.DB_PATH)) as conn, conn:
            conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO config VALUES ('node_name', 'Local')")
        database.init_db()

    def rows(self, sql):
        with contextlib.closing(sqlite3.connect(database.DB_PATH)) as conn:
            return conn.execute(sql).fetchall()

    def test_kind_detection(self):
        for kind in ("CHECK_REQ", "CHECK_RESP", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP",
                     "METRICS", "HELLO", "HELLO_ACK", "BOT_SYNC_DATA"):
            with self.subTest(kind=kind):
                self.assertEqual(bot._peer_message_kind(message(kind)), kind)
        self.assertEqual(bot._peer_message_kind("Sync instructions\n" + message("BOT_SYNC_DATA")), "BOT_SYNC_DATA")
        for text in ("chat", "[/UPTIME_PEER_HELLO]", "［UPTIME_PEER_HELLO]", "[UPTIME_PEER_HELLO]", message("BOGUS")):
            self.assertIsNone(bot._peer_message_kind(text))

    def test_send_receive_bytes_and_unchanged_texts(self):
        rpc_bot = MagicMock()
        for kind in ("CHECK_REQ", "CHECK_RESP", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP",
                     "METRICS", "HELLO", "HELLO_ACK", "BOT_SYNC_DATA"):
            text = " " + message(kind, '{"name":"É😀"}') + "\n "
            data = bot.MsgData(text=text)
            with self.subTest(kind=kind):
                bot._dc_send_msg_with_stats(rpc_bot, 1, 7, data)
                self.assertIs(rpc_bot.rpc.send_msg.call_args.args[2], data)
                self.assertEqual(rpc_bot.rpc.send_msg.call_args.args[2].text.encode(), text.encode())
        incoming = " \n" + message("CHECK_REQ") + "\n  "
        bot.on_new_message(rpc_bot, 1, event(incoming))
        bot.on_new_message(rpc_bot, 1, event(incoming, sender=1))
        self.assertEqual(self.rows("SELECT * FROM peer_traffic"), [])
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT kind, dir, n, bytes FROM peer_traffic WHERE dir = 'in'"),
                         [("CHECK_REQ", "in", 1, len(incoming.encode()))])
        sent = self.rows("SELECT kind, dir, n, bytes FROM peer_traffic WHERE dir = 'out'")
        self.assertEqual(len(sent), 8)
        for kind, direction, n, size in sent:
            self.assertEqual((direction, n, size),
                             ("out", 1, len((" " + message(kind, '{"name":"É😀"}') + "\n ").encode())))
        self.assertEqual(rpc_bot.rpc.send_msg.call_count, 8)
        self.assertEqual(database.get_local_node_name(), "Local")

    def test_queued_and_failed_sends_are_counted_only_after_success(self):
        rpc_bot = MagicMock()
        data = bot.MsgData(text=message("HELLO", "{}"))
        with patch.object(bot.dc_outbox, "submit") as submit:
            submit.return_value.done.return_value = False
            bot._dc_send_msg_with_stats(rpc_bot, 1, 7, data)
            send = submit.call_args.args[0]
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT n FROM peer_traffic"), [])
        rpc_bot.rpc.send_msg.side_effect = RuntimeError("send failed")
        with self.assertRaises(RuntimeError):
            send()
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT n FROM peer_traffic"), [])
        rpc_bot.rpc.send_msg.side_effect = None
        send()
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT n FROM peer_traffic"), [(1,)])

    def test_hello_retry_path_and_realtime_advertisement(self):
        rpc_bot = MagicMock()
        text = message("HELLO", "{}")
        self.assertTrue(bot.send_peer_hello_when_ready(rpc_bot, 1, 7, text, "Remote"))
        rpc_bot.rpc.send_msg.assert_called_once()
        self.assertEqual(rpc_bot.rpc.send_msg.call_args.args[2].text, text)
        with patch.object(bot, "_realtime_channels", {}):
            bot._realtime_join(rpc_bot, 1, 37, 7)
            bot._realtime_join(rpc_bot, 1, 37, 7)
            rpc_bot.rpc.send_webxdc_realtime_advertisement.assert_called_once_with(1, 37)
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT kind, transport, dir, n, bytes FROM peer_traffic ORDER BY kind"),
                         [("HELLO", "mail", "out", 1, len(text.encode())),
                          ("rt_advert", "mail", "out", 1, 0)])

    def test_rollover_retry_and_pruning(self):
        now = datetime.datetime(2026, 11, 18, tzinfo=datetime.timezone.utc).timestamp()
        for ts in (now - 31 * 86400, now - 29 * 86400, now - 86401, now - 1, now, now):
            with patch("database.time.time", return_value=ts):
                database.record_peer_traffic("METRICS", "mail", "in", 5)
                database.record_peer_rtt("ping", "mail", "Paris", 25, True)
                database.record_peer_rtt("vote", "mail", "Berlin", 900, False)
        with contextlib.closing(sqlite3.connect(database.DB_PATH)) as conn, conn:
            conn.execute("CREATE TRIGGER reject_rtt BEFORE INSERT ON peer_rtt "
                         "BEGIN SELECT RAISE(ABORT, 'test rollback'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT * FROM peer_traffic"), [])
        self.assertEqual(self.rows("SELECT * FROM peer_traffic_recent"), [])
        with contextlib.closing(sqlite3.connect(database.DB_PATH)) as conn, conn:
            conn.execute("DROP TRIGGER reject_rtt")
        database.flush_peer_metrics()
        database.flush_peer_metrics()
        self.assertEqual(self.rows("SELECT day, n, bytes FROM peer_traffic ORDER BY day"),
                         [("2026-10-18", 1, 5), ("2026-10-20", 1, 5), ("2026-11-16", 1, 5),
                          ("2026-11-17", 1, 5), ("2026-11-18", 2, 10)])
        traffic, rtt = database.get_peer_metrics_24h(now)
        self.assertEqual(traffic, [("METRICS", "in", 3)])
        self.assertCountEqual(rtt, [("ping", 25, 1), ("vote", 900, 0)] * 3)
        with patch("database.time.time", return_value=now):
            cleaned = database.cleanup_old_records()
        self.assertEqual((cleaned["peer_traffic"], cleaned["peer_traffic_recent"], cleaned["peer_rtt"]), (1, 3, 4))
        self.assertEqual(self.rows("SELECT COUNT(*) FROM peer_traffic"), [(4,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM peer_rtt"), [(8,)])

    def test_percentiles_and_stats_command(self):
        self.assertIsNone(bot._percentile([], 50))
        self.assertEqual(bot._percentile([100], 95), 100)
        self.assertEqual(bot._percentile([100, 200, 300], 50), 200)
        self.assertEqual(bot._percentile([100, 200, 300], 95), 290)
        database.record_peer_traffic("METRICS", "mail", "in", 35)
        database.record_peer_traffic("METRICS", "mail", "out", 20)
        database.record_peer_traffic("METRICS", "mail", "out", 20)
        database.record_peer_traffic("peer_metrics_idle", "mail", "out", 0)
        database.record_peer_traffic("peer_metrics_change", "mail", "out", 0)
        for kind in ("CHECK_REQ", "CHECK_RESP", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP",
                     "HELLO", "HELLO_ACK", "BOT_SYNC_DATA", "rt_advert"):
            database.record_peer_traffic(kind, "mail", "out", 0)
        for ms in (100, 200, 300):
            database.record_peer_rtt("ping", "mail", "Paris", ms, True)
        database.record_peer_rtt("ping", "mail", "Berlin", 6500, False)
        database.record_peer_rtt("vote", "mail", "Paris", 2010, True)
        database.record_peer_rtt("vote_round", "mail", None, 2150, True)
        database.flush_peer_metrics()
        rpc_bot = MagicMock()
        with patch.object(bot, "_is_dc_admin", return_value=True):
            bot.stats_command(rpc_bot, 1, event("/stats"))
        rpc_bot.rpc.send_msg.assert_called_once()
        report = rpc_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Peer mails (24 h): BOT_SYNC_DATA 0/1, CHECK_BATCH_REQ 0/1, CHECK_BATCH_RESP 0/1, "
                      "CHECK_REQ 0/1, CHECK_RESP 0/1, HELLO 0/1, HELLO_ACK 0/1, METRICS 1/2, "
                      "rt_advert 0/1 (in/out)", report)
        self.assertIn("METRICS sent (24 h): idle 1, on change 1", report.split("**Peers**", 1)[1])
        self.assertIn("Peer round trip (24 h): ping 200/290 ms, vote 2010/2010 ms, "
                      "vote_round 2150/2150 ms (p50/p95), 1 timeout", report)
        self.assertLess(len(report.encode()), 4096)
        self.assertEqual(bot._peer_metrics_report(time.time() + 86401),
                         ("• Peer mails (24 h): none (in/out)",
                          "• METRICS sent (24 h): idle 0, on change 0",
                          "• Peer round trip (24 h): ping n/a, vote n/a, vote_round n/a (p50/p95), 0 timeouts"))

    def test_ping_batch_and_round_rtt(self):
        paris = {"email": "paris@example.org", "node_name": "Paris", "chat_id": 7}
        berlin = {"email": "berlin@example.org", "node_name": "Berlin", "chat_id": 8}
        targets = {"url": "https://example.org", "type": "http"}
        rpc_bot = MagicMock()

        def send(accid, chat_id, data):
            if chat_id == 7:
                request = json.loads(data.text.splitlines()[1])
                kind = bot._peer_message_kind(data.text)
                response = {"req_id": request["req_id"], "status": "up"}
                if kind == "CHECK_BATCH_REQ":
                    response["results"] = [{"status": "up"}]
                bot.on_new_message(rpc_bot, accid, event(message(kind.removesuffix("_REQ") + "_RESP",
                                                                json.dumps(response)), chat_id))
            return 100

        async def run():
            with patch.object(bot, "async_event_loop", asyncio.get_running_loop()):
                ping = await bot.request_peer_cross_checks(targets, timeout=0.02, peers=[paris, berlin])
                self.assertEqual([answer["node_name"] for answer in ping], ["Paris"])
                for peers in ([paris, berlin], [paris]):
                    with patch.object(database, "get_all_peers", return_value=peers):
                        result = asyncio.get_running_loop().create_future()
                        await bot._flush_cross_checks([(targets, result, None)])
                    self.assertEqual([answer["node_name"] for answer in result.result()], ["Paris"])
                with patch.object(bot, "_peer_supports", return_value=False), \
                     patch.object(database, "get_all_peers", return_value=[paris]):
                    result = asyncio.get_running_loop().create_future()
                    await bot._flush_cross_checks([(targets, result, None)])
                self.assertEqual([answer["node_name"] for answer in result.result()], ["Paris"])

        rpc_bot.rpc.send_msg.side_effect = send
        with patch.object(bot, "dc_bot_instance", rpc_bot), patch.object(bot, "dc_accid", 1), \
             patch.object(bot, "_get_verified_peer_for_msg", return_value=(paris, paris["email"])), \
             patch.object(bot, "_is_trusted_peer_msg", return_value=True), \
             patch.object(bot, "_note_peer_announcement", return_value=paris), \
             patch.object(bot, "_record_peer_activity"), \
             patch.object(bot, "_peer_supports", return_value=True), \
             patch.object(bot, "CROSS_CHECK_BATCH_TIMEOUT", 0.02):
            asyncio.run(run())
        database.flush_peer_metrics()
        rtt = self.rows("SELECT kind, transport, peer, ms, ok FROM peer_rtt")
        self.assertCountEqual([(kind, transport, peer, ok) for kind, transport, peer, _, ok in rtt],
                              [("ping", "mail", "Paris", 1), ("ping", "mail", "Berlin", 0),
                               ("vote", "mail", "Paris", 1), ("vote", "mail", "Berlin", 0),
                               ("vote_round", "mail", None, 0),
                               ("vote", "mail", "Paris", 1), ("vote_round", "mail", None, 1),
                               ("vote_round", "mail", None, 1)])
        self.assertTrue(all(ms >= 0 for _, _, _, ms, _ in rtt))
        self.assertTrue(all(ms >= 19 for _, _, _, ms, ok in rtt if not ok))
