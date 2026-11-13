"""Status app snapshots, persisted pacing, lifecycle and report mode integration."""
import asyncio
import copy
import json
import itertools
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch

try:
    import deltachat2
except ImportError:
    module = MagicMock()
    module.MsgData = lambda **kw: type("MsgData", (), kw)()
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


class TestWebxdcStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "status.db")
        database.init_db()
        self.rpc = MagicMock()
        self.rpc.send_msg.side_effect = lambda *args: next(self.message_ids)
        self.message_ids = itertools.count(400)
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: ids
        self.rpc.get_basic_chat_info.return_value = {"name": "Test chat"}
        self.rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 128000, "sendUpdateInterval": 10000}
        self.client = MagicMock(rpc=self.rpc)
        self.patches = [patch.object(bot, "dc_outbox", Outbox()),
                        patch.object(bot, "dc_bot_instance", self.client), patch.object(bot, "dc_accid", 1),
                        patch.dict(os.environ, {"DC_DB_DIR": self.tmp.name}),
                        patch("bot.time.time", return_value=10000)]
        for p in self.patches:
            p.start()
        self.rid = database.add_resource(1, "https://example.org", "Example", "http")
        database.set_chat_report_app(1, "on")
        self.set_fields(self.rid, status="up", last_changed=9000)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def set_fields(self, rid, **values):
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET " + ", ".join(k + " = ?" for k in values) + " WHERE id = ?",
                         (*values.values(), rid))

    def push(self):
        asyncio.run(bot.push_status_apps())

    def existing(self):
        database.set_chat_webxdc(1, 321)
        database.set_chat_status_line(1, 322, bot._status_line_hash(bot.status_line_text(bot.build_status_state(1))))
        database.set_config("webxdc_app_version:1", str(bot.WEBXDC_APP_VERSION))

    def test_snapshot_status_nodes_summary_and_timestamp_hash(self):
        partial = database.add_resource(1, "https://partial.example", "Partial", "http")
        down = database.add_resource(1, "https://down.example", "Down", "http")
        paused = database.add_resource(1, "https://paused.example", "Paused", "http")
        votes = [{"node": "🇬🇧 UK", "status": "up", "latency_ms": 42, "error": None},
                 {"node": "🇩🇪 DE", "status": "down", "latency_ms": None, "error": "Timeout"}]
        self.set_fields(partial, status="up", alert_state="degraded", last_votes=json.dumps(votes), degraded_since=9500)
        self.set_fields(down, status="down", alert_state="degraded", last_changed=9400)
        self.set_fields(paused, status="up", maintenance_until=11000)
        database.set_config("webxdc_chat_name:1", "Ops")
        state = bot.build_status_state(1)
        self.assertEqual(state["chat"], "Ops")
        self.assertEqual(state["counts"], {"up": 1, "partial": 1, "down": 1})
        self.assertEqual([m["status"] for m in state["monitors"]], ["down", "partial", "up", "paused"])
        self.assertEqual(state["monitors"][1]["nodes"], votes)
        self.assertEqual(state["monitors"][1]["since"], 9500)
        self.assertIsInstance(state["monitors"][0]["uptime30"], float)
        self.assertEqual(bot.status_app_summary(state), "🟢 1 up · 🟠 1 partial · 🔴 1 down")
        later = copy.deepcopy(state)
        later["generated_at"] += 60
        self.assertEqual(bot.status_state_hash(state), bot.status_state_hash(later))
        later["monitors"][0]["status"] = "up"
        self.assertNotEqual(bot.status_state_hash(state), bot.status_state_hash(later))
        self.rpc.get_basic_chat_info.assert_not_called()  # Snapshot builder is RPC-free.

    def test_posts_pins_then_sends_complete_state_and_does_not_repeat(self):
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.assertTrue(self.rpc.send_msg.call_args_list[0].args[2].file.endswith("status.xdc"))
        self.rpc.set_pinned_message_state.assert_any_call(1, 401, True)
        self.rpc.send_webxdc_status_update.assert_called_once()
        update = json.loads(self.rpc.send_webxdc_status_update.call_args.args[2])
        self.assertEqual(update["payload"]["chat"], "Test chat")
        self.assertEqual(len(update["payload"]["monitors"]), 1)
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)

    def test_unchanged_state_uses_no_outbox_tokens_and_rename_is_updated(self):
        self.existing()
        self.push()
        ob = Outbox()
        ob._thread = object()
        with patch.object(bot, "dc_outbox", ob), patch("bot.time.time", return_value=10060):
            self.push()
            self.assertFalse(ob.waiting())
        self.rpc.get_basic_chat_info.return_value = {"name": "Renamed chat"}
        with patch("bot.time.time", return_value=10060):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        update = json.loads(self.rpc.send_webxdc_status_update.call_args.args[2])
        self.assertEqual(update["payload"]["chat"], "Renamed chat")

    def test_debounce_and_durable_hourly_cap(self):
        self.existing()
        self.push()
        self.set_fields(self.rid, status="down")
        with patch("bot.time.time", return_value=10059):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch("bot.time.time", return_value=10060):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        database.set_config("webxdc_updates:1", json.dumps([10000] * 30))
        self.set_fields(self.rid, status="up")
        database.close_db()
        with patch("bot.time.time", return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        with patch("bot.time.time", return_value=13601):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 3)

    def test_missing_instance_reposts_and_hourly_guard(self):
        self.existing()
        self.rpc.get_existing_msg_ids.return_value = []
        self.rpc.get_existing_msg_ids.side_effect = None
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.rpc.set_pinned_message_state.assert_any_call(1, 401, True)
        self.rpc.send_webxdc_status_update.assert_called_once()
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch("bot.time.time", return_value=13600):
            self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 4)

    def test_existing_instance_is_not_reposted_and_layout_version_is(self):
        self.existing()
        self.push()
        self.rpc.send_msg.assert_not_called()
        with patch.object(bot, "VERSION", "99.0.0"):
            self.push()
        self.rpc.send_msg.assert_not_called()
        with patch.object(bot, "WEBXDC_APP_VERSION", 3):
            self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.rpc.set_pinned_message_state.assert_any_call(1, 401, True)

    def test_off_and_missing_bot_do_nothing(self):
        database.set_chat_report_app(1, "off")
        self.push()
        self.rpc.send_msg.assert_not_called()
        database.set_chat_report_app(1, "on")
        with patch.object(bot, "dc_bot_instance", None):
            self.push()
        self.rpc.send_msg.assert_not_called()

    def test_queued_jobs_recheck_mode_and_use_separate_mail_tokens(self):
        ob = Outbox()
        ob._thread = object()
        with patch.object(bot, "dc_outbox", ob):
            self.push()
            database.set_chat_report_app(1, "off")
            with ob._cond:
                job = ob._next_job()
            ob._run(job)
        self.rpc.send_msg.assert_not_called()
        database.set_chat_report_app(1, "on")
        self.push()
        methods = [call[0] for call in self.rpc.mock_calls]
        self.assertLess(methods.index("send_msg"), methods.index("set_pinned_message_state"))
        self.assertLess(methods.index("set_pinned_message_state"), methods.index("send_webxdc_status_update"))

    def test_rpc_failure_is_contained_and_post_attempt_guarded(self):
        self.rpc.send_msg.side_effect = RuntimeError("offline")
        with self.assertLogs("uptime_bot", level="WARNING"):
            self.push()
        self.push()
        self.rpc.send_msg.assert_called_once()
        with patch.object(database, "get_status_app_chats", side_effect=RuntimeError("DB offline")):
            with self.assertLogs("uptime_bot", level="WARNING"):
                self.push()

    def test_pin_failure_is_retried_without_reposting(self):
        self.rpc.set_pinned_message_state.side_effect = [RuntimeError("offline"), None]
        with self.assertLogs("uptime_bot", level="WARNING"):
            self.push()
        self.rpc.send_webxdc_status_update.assert_not_called()
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.assertEqual(self.rpc.set_pinned_message_state.call_count, 2)
        self.rpc.send_webxdc_status_update.assert_called_once()

    def test_uncertain_update_attempts_are_also_debounced(self):
        self.existing()
        self.rpc.send_webxdc_status_update.side_effect = [RuntimeError("offline"), None]
        with self.assertLogs("uptime_bot", level="WARNING"):
            self.push()
        with patch("bot.time.time", return_value=10030):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch("bot.time.time", return_value=10060):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        self.assertEqual(database.get_chat_webxdc(1)["webxdc_last_sent_at"], 10060)

    def test_size_fallback_preserves_all_monitor_flags(self):
        state = bot.build_status_state(1)
        state["monitors"][0]["nodes"] = [{"node": "🇬🇧 UK", "status": "down", "latency_ms": 42, "error": "x" * 70000}]
        encoded = bot._status_update_json(state, 60000)
        self.assertLessEqual(len(encoded.encode()), 60000)
        payload = json.loads(encoded)["payload"]
        self.assertTrue(payload["details_omitted"])
        self.assertEqual(payload["monitors"][0]["nodes"], [
            {"node": "🇬🇧 UK", "status": "down", "latency_ms": None, "error": None}])
        self.assertEqual(payload["monitors"][0]["status"], "up")
        state["monitors"][0]["nodes"] *= 2000
        encoded = bot._status_update_json(state, 60000)
        payload = json.loads(encoded)["payload"]
        self.assertLessEqual(len(encoded.encode()), 60000)
        self.assertTrue(payload["node_flags_omitted"])
        self.assertEqual(payload["monitors"][0]["nodes"], [])
        self.assertEqual(payload["monitors"][0]["status"], "up")

    def test_core_size_and_interval_are_respected(self):
        self.existing()
        self.rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 1000, "sendUpdateInterval": 120000}
        self.push()
        self.set_fields(self.rid, status="down")
        with patch("bot.time.time", return_value=10060):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch("bot.time.time", return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        self.assertLessEqual(len(self.rpc.send_webxdc_status_update.call_args.args[2].encode()), 1000)

    def test_only_suppresses_claims_delivery_and_queueing_but_tracks_incidents(self):
        database.set_chat_report_app(1, "only")
        database.set_chat_report_partial(1, 0)
        database.set_chat_report_full(1, 0)
        database.update_resource_alert_state(self.rid, "degraded", "[]", 9000)
        database.start_partial_outage(self.rid, 9000, "[]")
        with patch.object(database, "claim_partial_notice") as partial_claim:
            bot._deliver_degraded_notices(1)
            asyncio.run(bot._check_report_notices())
            partial_claim.assert_not_called()
        database.update_resource_status(self.rid, "down", 1, "Timeout")
        asyncio.run(bot.sync_chat_incident_state(1))
        incidents = database.get_active_incidents_for_chat(1)
        self.assertEqual(len(incidents), 1)
        with patch.object(database, "claim_incident_message") as claim:
            bot._deliver_incident_message(incidents[0]["id"], 1, "outage", False)
            bot._queue_incident_message(incidents[0]["id"], 1, "outage", 0)
            claim.assert_not_called()
        self.rpc.send_msg.assert_not_called()
        database.set_chat_report_app(1, "on")
        asyncio.run(bot.sync_chat_incident_state(1))
        bot._deliver_incident_message(incidents[0]["id"], 1, "outage", False)
        bot._deliver_degraded_notices(1)
        self.rpc.send_msg.assert_not_called()  # Old open outages are intentionally dropped.
        self.assertEqual(database.get_pending_partial_notices(), [])

    def test_report_app_command_validation_settings_and_deletion(self):
        event = MagicMock(payload="app only")
        event.msg.chat_id = 1
        with patch.object(bot, "queue_status_app") as queue:
            bot.report_command(self.client, 1, event)
            queue.assert_called_once_with(1, self.client, 1)
        self.assertEqual(database.get_chat_report_app(1), "only")
        self.assertIn("app: only", bot.report_settings_text(1))
        event.payload = "app off"
        bot.report_command(self.client, 1, event)
        self.assertEqual(database.get_chat_report_app(1), "off")
        for payload in ("app invalid", "app", "app on extra"):
            event.payload = payload
            bot.report_command(self.client, 1, event)
            self.assertIn("Usage:", self.rpc.send_msg.call_args.args[2].text)
            self.assertEqual(database.get_chat_report_app(1), "off")
        for invalid in (None, True, 1, "invalid"):
            with self.assertRaises(ValueError):
                database.set_chat_report_app(1, invalid)
        self.assertEqual(database.get_chat_report_app(2), "off")
        self.existing()
        for key in ("webxdc_reposted_at", "webxdc_updates", "webxdc_pin_pending", "webxdc_chat_name"):
            database.set_config(key + ":1", "test")
        database.delete_chat_data(1)
        for key in ("report_app", "report_app_notices_after", "webxdc_app_version", "webxdc_reposted_at",
                    "webxdc_updates", "webxdc_pin_pending", "webxdc_chat_name"):
            self.assertIsNone(database.get_config(key + ":1"))

    def test_archive_root_size_and_cache_version(self):
        path = Path(bot.build_status_xdc())
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.toml", "index.html", "icon.png"})
            self.assertIn('name = "Uptime Status"', archive.read("manifest.toml").decode())
        self.assertLess(path.stat().st_size, 200000)
        modified = path.stat().st_mtime_ns
        self.assertEqual(bot.build_status_xdc(), str(path))
        self.assertEqual(path.stat().st_mtime_ns, modified)
        signature = path.with_suffix(".xdc.sha256").read_text()
        with patch.object(bot, "VERSION", "99.0.0"):
            bot.build_status_xdc()
        self.assertNotEqual(path.with_suffix(".xdc.sha256").read_text(), signature)


if __name__ == "__main__":
    unittest.main()
