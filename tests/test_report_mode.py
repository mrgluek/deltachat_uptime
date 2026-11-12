"""Per-chat report delays, persisted delivery claims and transition handling."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

try:
    import deltachat2
except ImportError:
    module = MagicMock()
    module.MsgData = lambda **kwargs: type("MsgData", (), kwargs)()
    sys.modules["deltachat2"] = module
try:
    import deltabot_cli
except ImportError:
    module = MagicMock()
    module.BotCli.return_value.on.side_effect = lambda *a, **kw: lambda f: f
    sys.modules["deltabot_cli"] = module

import bot
import database
from outbox import Outbox


def drain(ob):
    while True:
        with ob._cond:
            if not any(not job.done for _, _, job in ob._heap):
                return
            job = ob._next_job()
        ob._run(job)


class TestReportMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "report.db")
        database.init_db()
        self.saved = bot.dc_bot_instance, bot.dc_accid
        bot.dc_bot_instance, bot.dc_accid = MagicMock(), 1
        bot.dc_bot_instance.rpc.send_msg.return_value = 123
        bot._alert_streaks.clear()
        bot._incident_last_edit_state.clear()
        self.ob = Outbox(burst=100, clock=lambda: 1000)
        self.ob._thread = object()  # hold messages until the test drains them
        self.patcher = patch.object(bot, "dc_outbox", self.ob)
        self.patcher.start()
        database.get_or_create_chat_token(1)
        self.rid = database.add_resource(1, "https://report.example.org", "Report", "http")
        self.now = 10000
        self.clock = patch("bot.time.time", return_value=self.now)
        self.mock_time = self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.patcher.stop()
        bot.dc_bot_instance, bot.dc_accid = self.saved
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def partial(self, start=9400):
        votes = [{"node": "one", "status": "down"}, {"node": "two", "status": "up"}]
        database.update_resource_alert_state(self.rid, "degraded", json.dumps(votes), start)
        database.start_partial_outage(self.rid, start, '["one"]')

    def sync(self):
        asyncio.run(bot.sync_chat_incident_state(1))

    def test_defaults_roundtrip_validation_and_chat_isolation(self):
        self.assertEqual(database.get_chat_report_partial(1), 10)
        self.assertEqual(database.get_chat_report_full(1), 2)
        for value in (0, 1440, "off", 10):
            database.set_chat_report_partial(1, value)
            self.assertEqual(database.get_chat_report_partial(1), value)
        for value in (0, 1440, 2):
            database.set_chat_report_full(1, value)
            self.assertEqual(database.get_chat_report_full(1), value)
        self.assertEqual(database.get_chat_report_partial(2), 10)
        for value in (-1, 1441, True, 1.5, "10", None):
            with self.subTest(value=value):
                for setter in (database.set_chat_report_partial, database.set_chat_report_full):
                    with self.assertRaises(ValueError):
                        setter(1, value)
        with self.assertRaises(ValueError):
            database.set_chat_report_full(1, "off")
        database.delete_chat_data(1)
        self.assertIsNone(database.get_config("report_partial:1"))
        self.assertIsNone(database.get_config("report_full:1"))

    def test_legacy_partial_delivery_history_is_unknown(self):
        import sqlite3
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "legacy.db")
        with sqlite3.connect(database.DB_PATH) as conn:
            conn.execute("CREATE TABLE partial_outages (id INTEGER PRIMARY KEY, resource_id INTEGER, started_at INTEGER, ended_at INTEGER, nodes_down TEXT)")
            conn.execute("INSERT INTO partial_outages VALUES (1, 1, 100, NULL, '[]')")
            conn.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY, dc_chat_id INTEGER, status TEXT, started_at INTEGER, resolved_at INTEGER, msg_id INTEGER, summary TEXT)")
            conn.execute("INSERT INTO incidents VALUES (1, 1, 'ongoing', 100, NULL, NULL, NULL)")
        database.init_db()
        self.assertFalse(database.claim_incident_message(1))
        self.assertEqual(database.get_partial_outages(1)[0]["notice_state"], -1)
        self.assertFalse(database.claim_partial_notice(1, True))

    def test_pending_delay_and_off_do_not_use_outbox_tokens(self):
        self.partial(9999)
        asyncio.run(bot._check_report_notices())
        self.assertFalse(self.ob.waiting())
        database.set_chat_report_partial(1, "off")
        self.mock_time.return_value = self.now + 10000
        asyncio.run(bot._check_report_notices())
        self.assertFalse(self.ob.waiting())

    def test_decision_boundaries(self):
        self.assertTrue(bot.should_notify_start(100, 100, 0))
        self.assertFalse(bot.should_notify_start(100, 699, 10))
        self.assertTrue(bot.should_notify_start(100, 700, 10))
        self.assertFalse(bot.should_notify_start(100, 800, 10, ended_at=699))
        self.assertFalse(bot.should_notify_start(100, 10000, "off"))
        self.assertFalse(bot.should_notify_resolved(False))
        self.assertTrue(bot.should_notify_resolved(True))

    def test_partial_restart_and_recovery_only_once(self):
        self.partial()
        database.close_db()
        database.init_db()
        bot._deliver_degraded_notices(1)
        bot._deliver_degraded_notices(1)
        self.assertEqual(bot.dc_bot_instance.rpc.send_msg.call_count, 1)
        database.end_partial_outage(self.rid, self.now)
        database.update_resource_alert_state(self.rid, "up", "[]")
        bot._deliver_degraded_notices(1)
        bot._deliver_degraded_notices(1)
        self.assertEqual(bot.dc_bot_instance.rpc.send_msg.call_count, 2)
        self.assertIn("Resolved", bot.dc_bot_instance.rpc.send_msg.call_args.args[2].text)

    def test_zero_partial_is_immediate_and_off_suppresses_its_end(self):
        database.set_chat_report_partial(1, 0)
        self.partial(self.now)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        database.set_chat_report_partial(1, "off")
        database.end_partial_outage(self.rid, self.now)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()

    def test_unstable_partial_stays_silent_after_node_recovers(self):
        self.partial()
        with patch("bot.is_node_unstable", return_value=True):
            bot._deliver_degraded_notices(1)
        with patch("bot.is_node_unstable", return_value=False):
            bot._deliver_degraded_notices(1)
        database.end_partial_outage(self.rid, self.now)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()

    def test_short_partial_and_off_are_silent(self):
        self.partial(9999)
        bot._deliver_degraded_notices(1)
        database.end_partial_outage(self.rid, self.now)
        bot._deliver_degraded_notices(1)
        self.partial(1)
        database.set_chat_report_partial(1, "off")
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()

    def test_claimed_partial_is_dropped_after_uncertain_send(self):
        self.partial()
        po = database.get_partial_outages(self.rid)[0]
        database.claim_partial_notice(po["id"], True)
        database.close_db()
        database.init_db()
        bot._deliver_degraded_notices(1)
        database.end_partial_outage(self.rid, self.now)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()

    def test_queued_partial_that_escalates_is_silent(self):
        self.partial()
        asyncio.run(bot._check_report_notices())
        database.end_partial_outage(self.rid, self.now)
        database.update_resource_alert_state(self.rid, "down", "[]")
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()

    def test_full_delay_restart_and_existing_message_edit(self):
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        inc = database.get_active_incident(1)
        self.assertIsNotNone(inc)
        self.assertFalse(self.ob.waiting())
        self.mock_time.return_value = self.now + 120
        database.close_db()
        database.init_db()
        self.sync()
        drain(self.ob)
        self.assertEqual(database.get_active_incident(1)["msg_id"], 123)
        self.sync()
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        database.update_resource_status(self.rid, "up", 0)
        self.sync()
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()

    def test_full_ends_before_delay_or_queued_delivery_is_silent(self):
        database.set_chat_report_full(1, 0)
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        database.update_resource_status(self.rid, "up", 0)
        self.sync()
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()
        self.assertEqual(database.get_recent_incidents(1)[0]["status"], "resolved")

    def test_claimed_full_does_not_repeat_after_restart(self):
        database.set_chat_report_full(1, 0)
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        inc = database.get_active_incident(1)
        database.claim_incident_message(inc["id"])
        database.close_db()
        database.init_db()
        drain(self.ob)
        self.sync()
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()

    def test_full_short_flaps_do_not_accumulate_delay(self):
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        inc_id = database.get_active_incident(1)["id"]
        self.mock_time.return_value = self.now + 60
        database.update_resource_status(self.rid, "up", 0)
        self.sync()
        self.mock_time.return_value = self.now + 180
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        self.assertEqual(database.get_active_incident(1)["id"], inc_id)
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_not_called()
        self.mock_time.return_value = self.now + 300
        self.sync()
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()

    def test_announced_partial_escalation_does_not_resolve_later(self):
        self.partial()
        bot._deliver_degraded_notices(1)
        r = database.get_resources(1)[0]
        votes = [{"node": "one", "status": "down"}, {"node": "two", "status": "down"}]
        with patch("bot.next_alert_state", return_value="down"):
            asyncio.run(bot.apply_quorum_state(r, votes, json.dumps(votes)))
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        bot._deliver_degraded_notices(1)
        database.update_resource_status(self.rid, "up", 0)
        database.update_resource_alert_state(self.rid, "degraded", "[]", self.now)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()

    def test_down_to_partial_resolves_only_the_existing_full_message(self):
        database.set_chat_report_full(1, 0)
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()
        drain(self.ob)
        votes = [{"node": "one", "status": "down"}, {"node": "two", "status": "up"}]
        r = database.get_resources(1)[0]
        with patch("bot.next_alert_state", return_value="degraded"), patch("bot._queue_degraded_notice"):
            asyncio.run(bot.apply_quorum_state(r, votes, json.dumps(votes)))
        database.update_resource_status(self.rid, "up", 0)
        self.sync()
        asyncio.run(bot._check_report_notices())
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()
        self.assertIn("Still unreachable", bot.dc_bot_instance.rpc.send_edit_request.call_args.args[2])

    def test_escalation_during_partial_rpc_cannot_restore_a_recovery(self):
        self.partial()

        def escalate(*args):
            database.end_partial_outage(self.rid, self.now, notify_end=False)
            database.update_resource_alert_state(self.rid, "up", "[]")
            return 123

        bot.dc_bot_instance.rpc.send_msg.side_effect = escalate
        bot._deliver_degraded_notices(1)
        bot._deliver_degraded_notices(1)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        self.assertEqual(database.get_partial_outages(self.rid)[0]["notice_state"], 3)

    def test_recovery_during_first_full_rpc_edits_the_created_message(self):
        database.set_chat_report_full(1, 0)
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        self.sync()

        def recover(*args):
            database.update_resource_status(self.rid, "up", 0)
            self.sync()
            return 123

        bot.dc_bot_instance.rpc.send_msg.side_effect = recover
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()
        self.assertIn("Resolved", bot.dc_bot_instance.rpc.send_edit_request.call_args.args[2])

    def test_report_command(self):
        for payload, expected in (("", "10 min"), ("all", "full: 0 min"),
                                  ("partial off", "partial: off"), ("full 1440", "1440 min"),
                                  ("full off", "❌ Usage:"), ("partial -1", "❌ Usage:"),
                                  ("partial 1441", "❌ Usage:"), ("all extra", "❌ Usage:")):
            event = MagicMock(payload=payload)
            event.msg.chat_id = 1
            bot.report_command(bot.dc_bot_instance, 1, event)
            drain(self.ob)
            self.assertIn(expected, bot.dc_bot_instance.rpc.send_msg.call_args.args[2].text)
