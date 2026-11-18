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
        return [json.loads(bytes(c.args[2]).decode()) for c in self.rpc.send_webxdc_realtime_data.call_args_list]

    def test_mail_interval_only_for_realtime_chats(self):
        self.assertEqual(bot.status_mail_interval(1), bot.REALTIME_EMAIL_INTERVAL)
        self.assertEqual(bot.status_mail_interval(2), 60)

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
        self.assertEqual(len(self.sent_states()), 2)  # ping only keeps the channel

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

    def test_failed_join_can_retry(self):
        self.rpc.send_webxdc_realtime_advertisement.side_effect = [RuntimeError("offline"), None]
        ad = Event(kind="WebxdcRealtimeAdvertisementReceived", msg_id=500)
        bot.on_status_realtime(self.client, 1, ad)
        self.assertNotIn(500, bot._realtime_channels)
        bot.on_status_realtime(self.client, 1, ad)
        self.assertIn(500, bot._realtime_channels)


if __name__ == "__main__":
    unittest.main()
