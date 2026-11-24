"""3.0.4: deletion of old status app instances for all members."""
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import bot
import database
from test_audit4_fixes import AuditCase

NOW = 2_000_000
DAY = 86400


class FakeRpc:
    def __init__(self, missing=(), fail=False):
        self.deleted = []
        self.delete_calls = []
        self.exist_calls = []
        self.missing = set(missing)
        self.fail = fail
        self.media = []
        self.messages = {}
        self.infos = {}

    def get_existing_msg_ids(self, accid, ids):
        self.exist_calls.append(list(ids))
        return [i for i in ids if i not in self.missing]

    def delete_messages_for_all(self, accid, ids):
        self.delete_calls.append(list(ids))
        if self.fail:
            raise RuntimeError("boom")
        self.deleted.extend(ids)

    def get_chat_media(self, accid, chat_id, t, a, b):
        return list(self.media)

    def get_message(self, accid, msg_id):
        return self.messages[msg_id]

    def get_webxdc_info(self, accid, msg_id):
        return self.infos[msg_id]


class Base(AuditCase):
    def setUp(self):
        super().setUp()
        self.rpc = FakeRpc()
        self.bot = MagicMock()
        self.bot.rpc = self.rpc
        database.set_config("app_retire", "on")

    def chat(self, chat_id, current=None):
        database.set_chat_webxdc(chat_id, current or chat_id * 1000)

    def record(self, chat_id, ids, at=NOW - 2 * DAY):
        database.add_retire_entries(chat_id, [(i, at) for i in ids])


class TestRetirePass(Base):
    def test_scale_300_chats_5000_ids(self):
        for c in range(1, 301):
            self.chat(c)
            self.record(c, [c * 1000 + 1 + k for k in range(17)])
        total = sum(len(v) for v in database.get_retire_lists().values())
        self.assertGreaterEqual(total, 5000)
        saves = []
        real = database.save_retire_lists
        with patch.object(database, "save_retire_lists", side_effect=lambda x: (saves.append(len(x)), real(x))[1]), \
                patch.object(database, "set_config") as set_config:
            deleted = bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(deleted, 100)
        self.assertEqual(len(self.rpc.exist_calls), 1)
        self.assertLessEqual(len(self.rpc.delete_calls), 2)
        self.assertTrue(all(len(c) <= 50 for c in self.rpc.delete_calls))
        self.assertEqual(len(self.rpc.deleted), 100)
        self.assertEqual(len(saves), 1)
        set_config.assert_not_called()
        self.assertEqual(sum(len(v) for v in database.get_retire_lists().values()), total - 100)

    def test_current_instance_is_never_deleted(self):
        self.chat(1, current=555)
        self.record(1, [555, 556])
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(self.rpc.deleted, [556])
        self.assertNotIn(555, [e[0] for e in database.get_retire_lists().get(1, [])])

    def test_status_line_is_never_deleted(self):
        self.chat(1)
        database.set_chat_status_line(1, 777, "h")
        self.record(1, [777, 778])
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(self.rpc.deleted, [778])

    def test_off_and_dry_delete_nothing(self):
        self.chat(1)
        self.record(1, [1, 2, 3])
        before = database.get_retire_lists()
        for mode in ("off", "dry"):
            database.set_config("app_retire", mode)
            self.assertEqual(bot.retire_old_status_apps(self.bot, 1, NOW), 0)
        self.assertEqual(self.rpc.delete_calls, [])
        self.assertEqual(self.rpc.exist_calls, [])
        self.assertEqual(database.get_retire_lists(), before)

    def test_default_mode_is_dry(self):
        database.set_config("app_retire", "")
        self.assertEqual(bot.get_app_retire_mode(), "dry")

    def test_24_hour_grace(self):
        self.chat(1)
        database.add_retire_entries(1, [(10, NOW - DAY + 5), (11, NOW - DAY)])
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(self.rpc.deleted, [11])
        self.assertEqual([e[0] for e in database.get_retire_lists()[1]], [10])

    def test_missing_current_instance_leaves_chat_alone(self):
        self.chat(1, current=555)
        self.record(1, [10])
        self.rpc.missing = {555}
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(self.rpc.delete_calls, [])
        self.assertEqual(len(database.get_retire_lists()[1]), 1)

    def test_missing_id_is_dropped_without_delete(self):
        self.chat(1)
        self.record(1, [10, 11])
        self.rpc.missing = {10}
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertEqual(self.rpc.deleted, [11])
        self.assertNotIn(1, database.get_retire_lists())

    def test_failures_retry_then_drop_after_5(self):
        self.chat(1)
        self.record(1, [10])
        self.rpc.fail = True
        for n in range(1, 5):
            bot.retire_old_status_apps(self.bot, 1, NOW)
            self.assertEqual(database.get_retire_lists()[1], [[10, NOW - 2 * DAY, n]])
        bot.retire_old_status_apps(self.bot, 1, NOW)
        self.assertNotIn(1, database.get_retire_lists())
        self.assertEqual(len(self.rpc.delete_calls), 5)


class TestRotationRecords(Base):
    def test_rotation_records_old_instance(self):
        self.chat(1, current=50)
        self.rpc.send_msg = MagicMock(return_value=60)
        self.bot.rpc = MagicMock()
        self.bot.rpc.get_existing_msg_ids.return_value = [50]
        self.bot.rpc.send_msg.return_value = 60
        database.set_chat_report_app(1, "on")
        database.set_config("webxdc_posted_at:1", str(NOW - 8 * DAY))
        with patch.object(bot, "build_status_xdc", return_value="x.xdc"), \
                patch.object(bot.time, "time", return_value=NOW), \
                patch.object(bot, "record_sent_mail"), patch.object(bot, "stat_event"), \
                patch.object(bot.dc_outbox, "submit"):
            bot._deliver_status_app(1, self.bot, 1)
        self.assertEqual(database.get_retire_lists()[1], [[50, NOW, 0]])
        self.assertEqual(database.get_chat_webxdc(1)["webxdc_msg_id"], 60)

    def test_rotation_off_records_nothing(self):
        database.set_config("app_retire", "off")
        self.chat(1, current=50)
        self.bot.rpc = MagicMock()
        self.bot.rpc.get_existing_msg_ids.return_value = [50]
        self.bot.rpc.send_msg.return_value = 60
        database.set_chat_report_app(1, "on")
        database.set_config("webxdc_posted_at:1", str(NOW - 8 * DAY))
        with patch.object(bot, "build_status_xdc", return_value="x.xdc"), \
                patch.object(bot.time, "time", return_value=NOW), \
                patch.object(bot, "record_sent_mail"), patch.object(bot, "stat_event"), \
                patch.object(bot.dc_outbox, "submit"):
            bot._deliver_status_app(1, self.bot, 1)
        self.assertEqual(database.get_retire_lists(), {})


class TestSweep(Base):
    def setUp(self):
        super().setUp()
        self.chat(1, current=400)
        r = self.rpc
        old = NOW - 5 * DAY
        # 100, 200: own old status apps; 150: peer.xdc of the bot; 160: foreign app; 170: own too young
        # (replaced <24h); 400: current
        spec = {100: (1, old, "Uptime Status"), 150: (1, old + 10, "Uptime peer link"),
                160: (9, old + 20, "Uptime Status"), 200: (1, old + 100, "Uptime Status"),
                400: (1, NOW - 3600, "Uptime Status")}
        r.media = list(spec)
        for mid, (frm, ts, name) in spec.items():
            r.messages[mid] = {"from_id": frm, "timestamp": ts, "view_type": "Webxdc"}
            r.infos[mid] = {"name": name}
        self.stack.enter_context(patch.object(bot.time, "time", return_value=NOW))

    def test_sweep_excludes_peer_foreign_and_current(self):
        found, reason = bot.sweep_old_status_apps(self.bot, 1, 1, NOW)
        self.assertIsNone(reason)
        self.assertEqual([m for m, _ in found], [100, 200])
        self.assertEqual(found[1][1], NOW - 3600)   # replaced when the current one was posted

    def test_sweep_needs_current_instance(self):
        self.rpc.media.remove(400)
        found, reason = bot.sweep_old_status_apps(self.bot, 1, 1, NOW)
        self.assertEqual(found, [])
        self.assertTrue(reason)

    def _run(self, mode):
        database.set_config("app_retire", mode)
        sent = []
        event = MagicMock()
        event.msg.from_id = 7
        event.msg.chat_id = 1
        event.payload = "sweep"
        with patch.object(bot, "_is_dc_admin", return_value=True), \
                patch.object(bot, "_dc_send_msg_with_stats", side_effect=lambda b, a, c, m, **k: sent.append(m.text)), \
                patch.object(bot, "_command_allowed", return_value=True, create=True):
            bot.appretire_command(self.bot, 1, event)
        return sent[0]

    def test_sweep_dry_records_nothing(self):
        self.assertIn("2 old status app", self._run("dry"))
        self.assertEqual(database.get_retire_lists(), {})
        self.assertEqual(self.rpc.delete_calls, [])

    def test_sweep_off_does_nothing(self):
        self._run("off")
        self.assertEqual(database.get_retire_lists(), {})

    def test_sweep_on_records(self):
        self._run("on")
        self.assertEqual([e[0] for e in database.get_retire_lists()[1]], [100, 200])
        self.assertEqual(self.rpc.delete_calls, [])


class TestMisc(unittest.TestCase):
    def test_status_name_matches_manifest(self):
        text = (Path(bot.__file__).parent / "webxdc" / "manifest.toml").read_text()
        self.assertIn(f'name = "{bot.STATUS_XDC_NAME}"', text)
        peer = (Path(bot.__file__).parent / "webxdc_peer" / "manifest.toml").read_text()
        self.assertNotIn(f'name = "{bot.STATUS_XDC_NAME}"', peer)


if __name__ == "__main__":
    unittest.main()
