"""Realtime (iroh) status channel prototype: join, hello/ping, idle leave, mail fallback interval."""
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


class Event(dict):
    """CoreEvent stand-in: attribute access for kind, dict access for the rest."""
    @property
    def kind(self):
        return self["kind"]


def data(obj) -> list:
    return list(json.dumps(obj).encode())


class TestWebxdcRealtime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "rt.db")
        database.init_db()
        self.rpc = MagicMock()
        self.client = MagicMock(rpc=self.rpc)
        self.now = 10000.0
        self.patches = [patch.object(bot, "STATUS_REALTIME_CHATS", {1}),
                        patch.object(bot, "_realtime_channels", {}),
                        patch.object(bot, "dc_bot_instance", self.client), patch.object(bot, "dc_accid", 1),
                        patch("bot.time.time", side_effect=lambda: self.now)]
        for p in self.patches:
            p.start()
        rid = database.add_resource(1, "https://example.org", "Example", "http")
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET status='up', last_changed=9000 WHERE id=?", (rid,))
        database.set_chat_webxdc(1, 500)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def sent_states(self):
        sent = [json.loads(bytes(c.args[2]).decode()) for c in self.rpc.send_webxdc_realtime_data.call_args_list]
        return [m for m in sent if m["t"] == "state"]

    def pongs(self):
        sent = [json.loads(bytes(c.args[2]).decode()) for c in self.rpc.send_webxdc_realtime_data.call_args_list]
        return [m for m in sent if m["t"] == "pong"]

    def test_large_chat_mail_policy_tracks_current_live_session(self):
        database.set_chat_report_live(1, "on")
        self.assertEqual(bot.status_mail_interval(1, 66), 300)
        self.assertEqual(bot.status_mail_cap(1, 66), 12)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=500))
        self.assertEqual(bot.status_mail_interval(1, 66), 300)
        self.assertEqual(bot.status_mail_cap(1, 66), 12)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        self.assertEqual(bot.status_mail_interval(1, 66), 1800)
        self.assertEqual(bot.status_mail_cap(1, 66), 30)
        self.assertEqual(bot.status_mail_interval(2), 60)
        self.now += bot.REALTIME_IDLE_LEAVE
        self.assertEqual(bot.status_mail_interval(1, 66), 300)
        self.assertEqual(bot.status_mail_cap(1, 66), 12)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "ping"})))
        self.assertEqual(bot.status_mail_interval(1, 66), 1800)
        database.set_chat_webxdc(1, 501)
        self.assertEqual(bot.status_mail_interval(1, 66), 300)
        self.assertEqual(bot.status_mail_cap(1, 66), 12)
        asyncio.run(bot.realtime_status_tick())
        self.rpc.leave_webxdc_realtime.assert_called_once_with(1, 500)

    def test_decode_rejects_garbage(self):
        self.assertEqual(bot._decode_realtime(data({"t": "hello", "v": 1}))["t"], "hello")
        self.assertIsNone(bot._decode_realtime(list(b"\xff\xfe")))
        self.assertIsNone(bot._decode_realtime(data([1, 2])))
        self.assertIsNone(bot._decode_realtime(data({"t": 5})))

    def test_state_fits_limit(self):
        blob = bot._encode_realtime_state(bot.build_status_state(1))
        self.assertLessEqual(len(blob), bot.REALTIME_MAX_BYTES)
        msg = json.loads(blob)
        self.assertEqual(msg["t"], "state")
        self.assertEqual(msg["u"]["payload"]["monitors"][0]["name"], "Example")

    def test_advertisement_joins_once_and_hello_sends_state(self):
        ad = Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=500)
        bot.on_status_realtime(self.client, 1, ad)
        bot.on_status_realtime(self.client, 1, ad)
        self.rpc.send_webxdc_realtime_advertisement.assert_called_once_with(1, 500)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        self.assertEqual(len(self.sent_states()), 2)  # hello always answers, even when unchanged
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "ping"})))
        self.assertEqual(len(self.sent_states()), 2)  # ping keeps the channel and gets a pong, no state
        self.assertEqual(self.pongs(), [{"t": "pong", "v": 1, "ts": 10000}])

    def test_other_chats_and_old_instances_are_ignored(self):
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=499))
        with patch.object(bot, "STATUS_REALTIME_CHATS", set()):
            bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=500))
        self.rpc.send_webxdc_realtime_advertisement.assert_not_called()

    def test_tick_sends_changes_only_and_leaves_when_idle(self):
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        asyncio.run(bot.realtime_status_tick())
        self.assertEqual(len(self.sent_states()), 1)  # unchanged since the hello answer
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET name='Renamed'")
        asyncio.run(bot.realtime_status_tick())
        self.assertEqual(len(self.sent_states()), 2)  # a changed state goes live
        self.now += bot.REALTIME_IDLE_LEAVE + 1
        asyncio.run(bot.realtime_status_tick())
        self.rpc.leave_webxdc_realtime.assert_called_once_with(1, 500)
        self.assertNotIn(500, bot._realtime_channels)

    def test_fresh_instance_gets_first_state_despite_previous_attempts(self):
        # Re-posted app in a realtime chat: the old instance sent 100 s ago, the 30 min mail
        # interval must not keep the new one empty.
        now = int(self.now)
        database.set_chat_report_app(1, "on")
        database.set_chat_status_line(1, 501, None)
        for key, value in (("webxdc_app_version:1", str(bot.WEBXDC_APP_VERSION)), ("webxdc_posted_at:1", str(now)),
                           ("webxdc_update_count:1", "0"), ("webxdc_updates:1", json.dumps([now - 100]))):
            database.set_config(key, value)
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: ids
        self.rpc.get_basic_chat_info.return_value = {"name": "Test chat"}
        self.rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 128000, "sendUpdateInterval": 10000}
        with patch.object(bot, "dc_outbox", MagicMock()):
            bot._deliver_status_app(1, self.client, 1, known_msg_id=500)
        self.rpc.send_webxdc_status_update.assert_called_once()
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        # The next, non-urgent change waits for the realtime mail interval
        self.rpc.send_webxdc_status_update.reset_mock()
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET name='Renamed'")
        database.set_config("webxdc_clean:1", database.get_config("webxdc_dirty:1"))  # not urgent
        self.now += 120
        with patch.object(bot, "dc_outbox", MagicMock()):
            bot._deliver_status_app(1, self.client, 1, known_msg_id=500)
        self.rpc.send_webxdc_status_update.assert_not_called()

    def test_chat_setting_enables_channel_without_env_and_off_leaves(self):
        database.set_chat_report_app(1, "on")
        database.set_chat_report_live(1, "on")
        with patch.object(bot, "STATUS_REALTIME_CHATS", set()):
            bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
            self.assertEqual(len(self.sent_states()), 1)
            self.assertEqual(bot.status_mail_interval(1), bot.REALTIME_EMAIL_INTERVAL)
            database.set_chat_report_live(1, "off")
            self.assertEqual(bot.status_mail_interval(1), 60)
            asyncio.run(bot.realtime_status_tick())
            self.rpc.leave_webxdc_realtime.assert_called_once_with(1, 500)

    def test_silent_channel_resumes_snapshot_and_status_line(self):
        database.set_chat_report_app(1, "on")
        database.set_chat_status_line(1, 501, "old-line")
        database.set_chat_webxdc(1, 500, "old-state", int(self.now))
        for key, value in (("webxdc_app_version:1", str(bot.WEBXDC_APP_VERSION)),
                           ("webxdc_posted_at:1", str(int(self.now))),
                           ("webxdc_dirty:1", "same"), ("webxdc_clean:1", "same")):
            database.set_config(key, value)
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: ids
        self.rpc.get_basic_chat_info.return_value = {"name": "Test"}
        self.rpc.get_webxdc_info.return_value = {"sendUpdateInterval": 10000}
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=500, data=data({"t": "hello"})))
        self.now += 120
        with patch.object(bot, "dc_outbox", MagicMock()) as outbox:
            bot._deliver_status_app(1, self.client, 1, known_msg_id=500)
            self.rpc.send_webxdc_status_update.assert_not_called()
            self.now += 60
            bot._deliver_status_app(1, self.client, 1, known_msg_id=500)
            self.rpc.send_webxdc_status_update.assert_called_once()
            self.assertIn(("status-line-edit", 1), [c.kwargs.get("key") for c in outbox.submit.call_args_list])

    def test_failed_join_can_retry(self):
        self.rpc.send_webxdc_realtime_advertisement.side_effect = [RuntimeError("offline"), None]
        ad = Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=500)
        bot.on_status_realtime(self.client, 1, ad)
        self.assertNotIn(500, bot._realtime_channels)
        bot.on_status_realtime(self.client, 1, ad)
        self.assertIn(500, bot._realtime_channels)


if __name__ == "__main__":
    unittest.main()
