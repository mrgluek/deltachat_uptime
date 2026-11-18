import asyncio
import itertools
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox, PRIO_ALERT, PRIO_UPDATE


class TestMailKinds(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.object(database, "DB_PATH", str(Path(directory) / "uptime.db")))
        self.enterContext(patch.multiple(database, _mail_kind_buffer={}, _peer_traffic_buffer={}, _peer_rtt_buffer=[]))
        with closing(sqlite3.connect(database.DB_PATH)) as conn, conn:
            conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO config VALUES ('node_name', 'Local')")
        database.init_db()
        self.addCleanup(database.close_db)
        self.clock = self.enterContext(patch.object(bot.time, "time", return_value=1_800_000_000))
        self.box = Outbox(clock=self.clock)
        self.enterContext(patch.object(bot, "dc_outbox", self.box))
        self.client = MagicMock()
        ids = itertools.count(500)
        self.client.rpc.send_msg.side_effect = lambda *_: next(ids)
        self.client.rpc.get_existing_msg_ids.side_effect = lambda _, ids: ids
        self.client.rpc.get_message.return_value = {"state": "OutDelivered"}
        self.client.rpc.get_basic_chat_info.return_value = {"name": "Test chat", "chat_type": "Single"}
        self.client.rpc.get_info.return_value = {}
        self.enterContext(patch.object(bot, "dc_bot_instance", self.client))
        self.enterContext(patch.object(bot, "dc_accid", 1))

    def counts(self):
        database.flush_peer_metrics()
        return dict(database.get_mail_kinds_24h(self.clock()))

    def drain_one(self):
        with self.box._cond:
            job = self.box._next_job()
        self.box._run(job)

    def test_incident_alerts_duration_and_stale_jobs(self):
        database.set_chat_report_full(11, 0)
        rid = database.add_resource(11, "https://incident.example.org", "Incident", "http")
        database.update_resource_status(rid, "down", 1, "timeout")
        asyncio.run(bot.sync_chat_incident_state(11))
        incident = database.get_active_incident(11)
        self.assertIsNotNone(incident["msg_id"])
        bot._queue_incident_message(incident["id"], 11, "Still down", PRIO_UPDATE)
        database.close_resource_downtime_events(rid)
        self.assertTrue(database.resolve_incident(incident["id"]))
        bot._queue_incident_message(incident["id"], 11, "Recovered", PRIO_ALERT, resolved=True)
        bot._queue_incident_message(incident["id"], 11, "Stale duration", PRIO_UPDATE)
        self.assertEqual(self.counts(), {"alert": 2, "incident_edit": 1})
        self.assertEqual(self.client.rpc.send_edit_request.call_count, 2)

    def test_command_reply_and_merged_reaction(self):
        event = SimpleNamespace(msg=SimpleNamespace(chat_id=10, from_id=42))
        bot.donate_command(self.client, 1, event)
        self.box._thread = object()
        bot._react(self.client, 1, 42, "⏳")
        bot._react(self.client, 1, 42, "☑️")
        self.assertEqual(self.counts(), {"reply": 1})
        self.drain_one()
        self.client.rpc.send_reaction.assert_called_once_with(1, 42, ["☑️"])
        self.assertEqual(self.counts(), {"reply": 2})

    def test_status_lifecycle_counts_rpc_sends(self):
        database.set_chat_report_app(11, "on")
        bot.queue_status_app(11, self.client, 1).result()
        self.assertEqual(self.counts(), {"other": 1, "status_line": 1})
        self.clock.return_value += 60
        bot.queue_status_app(11, self.client, 1).result()
        self.client.rpc.send_webxdc_status_update.assert_called_once()
        self.assertEqual(self.counts(), {"other": 1, "status_line": 2, "status_app": 1})

    def test_peer_vote_metrics_hello_and_realtime_advert(self):
        peer = {"email": "peer@example.org", "chat_id": 12}
        target = {"url": "https://monitor.example.org", "status": "up"}
        async def send():
            await bot._batch_cross_check_peer(peer, [("target", target)], {"target": []})
            await bot.broadcast_telemetry_to_peers()

        with patch.object(bot, "CROSS_CHECK_BATCH_TIMEOUT", 0.01), \
             patch.object(database, "get_all_peers", return_value=[peer]), \
             patch.object(database, "get_all_resources", return_value=[target]), \
             patch.object(bot, "_filter_peer_shareable_resources", return_value=[target]), \
             patch.object(bot, "_resolve_peer_chat_id", AsyncMock(return_value=12)), \
             patch.object(bot, "_get_self_addr", return_value="self@example.org"), \
             patch.object(bot, "_telemetry_sent_at", {}), \
             patch.object(bot, "_telemetry_last_sent", {}), \
             patch.object(bot, "_realtime_channels", {}):
            asyncio.run(send())
            self.assertTrue(bot.send_peer_hello_when_ready(self.client, 1, 12, "[UPTIME_PEER_HELLO]\n{}\n[/UPTIME_PEER_HELLO]", "Peer"))
            bot._realtime_join(self.client, 1, 55, 12)
        self.assertEqual(self.counts(), {"peer_vote": 1, "peer_metrics": 1, "peer_other": 2})

    def test_failed_expired_and_direct_sends(self):
        self.box._thread = object()
        self.box.submit(lambda: self.fail("expired job ran"), expires_in=1)
        self.clock.return_value += 1
        self.box.submit(MagicMock(side_effect=RuntimeError("RPC failed")), kind="alert")
        self.drain_one()
        self.assertEqual(self.counts(), {})
        with patch.object(bot, "dc_outbox", None):
            bot._dc_send_msg_with_stats(self.client, 1, 12, bot.MsgData(text="Direct reply"))
        self.assertEqual(self.counts(), {"reply": 1})

    def test_broken_counter_cannot_break_queued_or_direct_sends(self):
        with patch.object(database, "record_mail_kind", side_effect=sqlite3.OperationalError("busy")):
            self.assertEqual(bot._dc_send_msg_with_stats(self.client, 1, 12, bot.MsgData(text="Reply")), 500)
            with patch.object(bot, "dc_outbox", None):
                self.assertEqual(bot._dc_send_msg_with_stats(self.client, 1, 12, bot.MsgData(text="Direct")), 501)
            bot._unpin_status_message(self.client, 1, 99)
        self.assertEqual(self.box.stats["failed"], 0)
        self.client.rpc.set_pinned_message_state.assert_called_once_with(1, 99, False)

    def test_rolling_stats_and_daily_pruning(self):
        now = self.clock.return_value
        self.assertNotIn("Sent by kind", bot.build_stats_report(self.client, 1))
        for at, kind in ((now - 30 * 86400, "alert"), (now - 86400, "incident_edit"),
                         (now - 86399, "reply"), (now, "other"), (now, "reply")):
            self.clock.return_value = at
            database.record_mail_kind(kind)
            database.flush_peer_metrics()
        self.clock.return_value = now
        self.assertEqual(database.get_local_node_name(), "Local")
        report = bot.build_stats_report(self.client, 1)
        lines = report.splitlines()
        mail = lines.index("**Mail (last hour)**")
        self.assertEqual(lines[mail + 2], "• Sent by kind (24 h): reply 2, other 1")
        database.init_db()
        cleaned = database.cleanup_old_records()
        self.assertEqual((cleaned["mail_kind"], cleaned["mail_kind_recent"]), (1, 2))
        with closing(sqlite3.connect(database.DB_PATH)) as conn:
            self.assertEqual(conn.execute("SELECT SUM(n) FROM mail_kind WHERE kind = 'reply'").fetchone(), (2,))
            self.assertEqual(conn.execute("SELECT day FROM mail_kind WHERE kind = 'other'").fetchone(), ("2027-01-15",))
