"""Authenticated health traffic over accepted peer carriers."""

import json
import os
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import bot
import database
import peer_rt
from outbox import Outbox


EMAIL = "peer@example.org"
FP = "AB" * 20
CHAT = 42
MSG = 456
CID = "ba" * 8
IN_KEY, OUT_KEY = b"i" * 32, b"o" * 32


class Event(dict):
    @property
    def kind(self):
        return self["kind"]


class TestPeerRTChannel(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(database, "DB_PATH", os.path.join(directory, "test.db")))
        self.enterContext(patch.multiple(database, _peer_traffic_buffer={}, _peer_rtt_buffer=[], _mail_kind_buffer={}))
        self.addCleanup(database.close_db)
        database.init_db()
        self.now, self.mono, self.jitter = 1_800_000_000, 0.0, 0
        self.clock = SimpleNamespace(time=lambda: self.now, monotonic=lambda: self.mono)
        self.enterContext(patch.object(database, "time", self.clock))
        self.enterContext(patch.object(bot, "time", self.clock))
        self.enterContext(patch.object(bot.secrets, "randbelow", side_effect=lambda _n: self.jitter))
        self.enterContext(patch.multiple(bot, dc_accid=1, _peer_caps={}, dc_outbox=Outbox(),
                                         _realtime_channels={}))
        self.enterContext(patch.multiple(bot, **self.channel_globals()))
        self.enterContext(patch.object(bot, "run_db", self.run_sync))
        self.enterContext(patch.object(bot, "run_rpc", self.run_sync))
        self.enterContext(patch.object(bot, "stat_event"))
        self.client = Mock()
        self.rpc = self.client.rpc
        self.rpc.list_transports.return_value = []
        self.send = self.rpc.send_webxdc_realtime_data
        self.advertise = self.rpc.send_webxdc_realtime_advertisement
        self.leave = self.rpc.leave_webxdc_realtime
        self.replay = peer_rt.ReplayWindow()
        self.seq = 0
        database.add_or_update_peer(EMAIL, "Peer", CHAT, fingerprint=FP)
        database.set_peer_rt_flag("on")
        database.set_peer_rt_capability(FP, True)

    def channel_globals(self):
        return dict(_peer_rt_links={}, _peer_rt_carrier_ids=set(), _peer_rt_leaves=set(),
                    _peer_rt_pending_adverts=set(), _peer_rt_epoch="feed1234",
                    _peer_rt_replay=peer_rt.ReplayWindow(clock=self.clock.monotonic),
                    _peer_rt_limiter=peer_rt.TokenBucketLimiter(clock=self.clock.monotonic),
                    _peer_rt_log=peer_rt.LogOnce(clock=self.clock.monotonic))

    async def run_sync(self, func, *args):
        return func(*args)

    def carrier(self, msg_id=MSG):
        database.set_peer_rt(FP, cid=CID, msg_id=msg_id, key_out=OUT_KEY, key_in=IN_KEY,
                             created_at=int(self.now))
        bot._refresh_peer_rt_channels()

    def advance(self, seconds):
        self.now += seconds
        self.mono += seconds

    async def tick(self):
        await bot._tick_peer_rt(self.client, 1)

    def receive(self, data, *, msg_id=MSG, accid=1):
        bot.on_status_realtime(self.client, accid, Event(kind="WebxdcRealtimeData", msg_id=msg_id, data=data))

    def advertisement(self, msg_id=MSG):
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeAdvertisementReceived", msgId=msg_id))

    def inbound(self, kind="ping", body=None, *, offset=0, key=IN_KEY, ack=0):
        self.seq += 1
        return list(peer_rt.encode(kind, "ca1ab1e5", self.seq, {} if body is None else body, key,
                                   ack=ack, clock=lambda: self.now + offset))

    def outbound(self):
        return [peer_rt.decode(bytes(call.args[2]), OUT_KEY, peer=FP, replay=self.replay, clock=self.clock.time)
                for call in self.send.call_args_list]

    def command(self, handler, payload=""):
        with patch.object(bot, "_is_dc_admin", return_value=True), patch.object(bot, "_dc_send_msg_with_stats") as reply:
            handler(self.client, 1, SimpleNamespace(msg=SimpleNamespace(chat_id=90, from_id=77), payload=payload))
        return reply.call_args.args[3].text

    def traffic(self):
        database.flush_peer_metrics()
        with sqlite3.connect(database.DB_PATH) as conn:
            return {(k, t, d): (n, size) for k, t, d, n, size in conn.execute(
                "SELECT kind, transport, dir, SUM(n), SUM(bytes) FROM peer_traffic GROUP BY 1, 2, 3"
            )}

    async def test_startup_spread_once_and_persisted_cooldown(self):
        self.jitter = 22_125
        self.carrier()
        self.advance(22)
        await self.tick()
        self.advertise.assert_not_called()
        self.advance(0.125)
        await self.tick()
        await self.tick()
        self.advertise.assert_called_once_with(1, MSG)
        first = self.now
        self.assertEqual(database.get_peer(EMAIL)["rt_advert_at"], first)
        self.advance(2)
        self.jitter = 0
        with patch.multiple(bot, **self.channel_globals()):
            bot._refresh_peer_rt_channels()
            await self.tick()
            self.advance(57)
            await self.tick()
            self.advertise.assert_called_once()
            self.advance(1)
            await self.tick()
            await self.tick()
        self.assertEqual(self.advertise.call_count, 2)
        self.assertEqual(self.traffic()["rt_advert", "mail", "out"], (2, 0))
        self.assertEqual(dict(database.get_mail_kinds_24h(self.now))["peer_other"], 2)

    async def test_both_accept_paths_schedule_an_advertisement_only_once(self):
        self.jitter = 5_000
        for kind, own_fp, msg_id in (("RT_ACCEPT", "AA" * 20, MSG), ("RT_OFFER", "BB" * 20, MSG + 1)):
            with self.subTest(kind=kind):
                database.clear_peer_rt(FP)
                if kind == "RT_ACCEPT":
                    database.save_peer_rt_offer(FP, CID, msg_id, OUT_KEY)
                marker = f"UPTIME_PEER_{kind}"
                payload = json.dumps(bot._peer_rt_key_payload(CID, IN_KEY))
                text = f"[{marker}]{payload}[/{marker}]"
                msg = SimpleNamespace(chat_id=CHAT, id=msg_id, view_type="Webxdc", file_bytes=500,
                                      timestamp=int(self.now))
                with patch.object(bot.dc_fingerprint, "get_self_fingerprint", return_value=own_fp), \
                        patch.object(bot, "_peer_rt_chat_is_private", return_value=True), \
                        patch.object(bot, "_get_verified_peer_for_msg", side_effect=lambda *_a, **_k: (
                            database.get_peer(EMAIL), FP)), \
                        patch.object(bot, "_is_trusted_peer_msg", return_value=True), \
                        patch.object(bot, "_queue_peer_rt_mail") as queue:
                    bot._handle_peer_rt_mail(self.client, 1, msg, kind, text)
                    bot._handle_peer_rt_mail(self.client, 1, msg, kind, text)
                self.assertEqual(queue.call_count, int(kind == "RT_OFFER"))
                self.advertise.reset_mock()
                await self.tick()
                self.advertise.assert_not_called()
                self.advance(5)
                await self.tick()
                await self.tick()
                self.advertise.assert_called_once_with(1, msg_id)

    async def test_pending_offer_dispatch_and_implicit_join_without_an_advertisement_reply(self):
        self.jitter = 10_000
        database.save_peer_rt_offer(FP, CID, MSG, OUT_KEY)
        bot._refresh_peer_rt_channels()
        with patch.object(bot, "_realtime_chat_for_msg", return_value=CHAT) as status:
            self.advertisement()
            await self.tick()
            self.send.assert_not_called()
            self.carrier()
            await self.tick()
            status.assert_not_called()
        self.assertEqual([frame["k"] for frame in self.outbound()], ["hello"])
        self.advertise.assert_not_called()
        self.assertEqual(self.traffic()["rt_advert", "mail", "in"], (1, 0))

    async def test_routes_peer_and_status_events_separately(self):
        self.jitter = 20_000
        self.carrier()
        self.receive(list(b'{"t":"hello","v":1}'))
        self.receive(self.inbound(), accid=2)
        with patch.object(bot, "_realtime_chat_for_msg", return_value=7) as status, \
                patch.object(bot, "_realtime_join") as join, patch.object(bot, "_send_realtime_state") as state:
            self.advertisement()
            status.assert_not_called()
            await self.tick()
            self.advertisement(789)
            join.assert_called_once_with(self.client, 1, 789, 7)
            self.receive(list(b'{"t":"hello","v":1}'), msg_id=789)
            state.assert_called_once_with(self.client, 1, 789, force=True)
            self.receive(self.inbound(), msg_id=789)
            state.assert_called_once()
        self.assertEqual([f["k"] for f in self.outbound()], ["hello"])

    async def test_ping_pong_visibility_and_timeout(self):
        self.carrier()
        self.assertIn("iroh: carrier ok (age 0d)", self.command(bot.peers_command))
        self.advertisement()
        await self.tick()
        hello, = self.outbound()
        self.advance(0.125)
        self.receive(self.inbound("pong", {k: hello[k] for k in ("e", "s")}))
        await self.tick()
        self.assertIn("iroh: UP (rtt 125 ms)", self.command(bot.peers_command))
        database.add_or_update_peer("old@example.org", "Older", 43)
        self.assertIn("Peer channels: 1 up, 0 down, 1 mail only", bot.build_stats_report(self.client, 1))
        self.advance(29.875)
        self.send.reset_mock()
        await self.tick()
        self.assertEqual([f["k"] for f in self.outbound()], ["ping"])
        self.advance(0.25)
        ping = self.inbound("ping")
        self.receive(ping)
        self.send.reset_mock()
        await self.tick()
        pong, = self.outbound()
        self.assertEqual(pong["k"], "pong")
        original = json.loads(bytes(ping))
        self.assertEqual(pong["b"], {k: original[k] for k in ("e", "s")})
        self.advance(89.999)
        self.assertIn("iroh: UP", self.command(bot.peers_command))
        self.advance(0.002)
        self.assertIn("iroh: DOWN since", self.command(bot.peers_command))
        self.assertIn("Peer channels: 0 up, 1 down, 1 mail only", bot.build_stats_report(self.client, 1))
        self.assertEqual(database.get_peer(EMAIL)["last_seen"], 1_800_000_000)
        counts = self.traffic()
        for kind, direction in (("hello", "out"), ("ping", "out"), ("ping", "in"), ("pong", "in"), ("pong", "out")):
            self.assertEqual(counts[kind, "rt", direction][0], 1)
            self.assertGreater(counts[kind, "rt", direction][1], 0)
        with sqlite3.connect(database.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT kind, transport, peer, ms, ok FROM peer_rtt").fetchall(),
                             [("ping", "rt", "Peer", 125, 1)])

    async def test_rejoin_requires_mail_and_persists_backoff(self):
        self.carrier()
        await self.tick()
        self.receive(self.inbound())
        await self.tick()
        self.advance(389)
        database.update_peer_last_seen(EMAIL)
        await self.tick()
        self.advertise.assert_called_once()
        self.advance(1)
        await self.tick()
        self.leave.assert_called_once_with(1, MSG)
        self.assertEqual(self.advertise.call_count, 2)
        self.assertEqual(database.get_peer(EMAIL)["rt_rejoin_at"], self.now + 900)
        self.advance(60)
        with patch.multiple(bot, **self.channel_globals()):
            bot._refresh_peer_rt_channels()
            await self.tick()  # A new endpoint advertises once, preserving recovery backoff.
            self.assertEqual(self.advertise.call_count, 3)
            self.advance(839)
            database.update_peer_last_seen(EMAIL)
            await self.tick()
            self.leave.assert_called_once()
            self.advance(1)
            await self.tick()
            self.assertEqual(self.leave.call_count, 2)
            self.assertEqual(database.get_peer(EMAIL)["rt_rejoin_at"], self.now + 3600)
            self.advance(3600)
            await self.tick()
            self.assertEqual(self.leave.call_count, 2)  # Mail went quiet.
            database.update_peer_last_seen(EMAIL)
            await self.tick()
            self.assertEqual(self.leave.call_count, 3)
            self.assertEqual(database.get_peer(EMAIL)["rt_rejoin_at"], self.now + 3600)
            self.receive(self.inbound())
            await self.tick()
            self.assertIsNone(database.get_peer(EMAIL)["rt_rejoin_at"])

    async def test_leaves_removed_disabled_and_downgraded_carriers(self):
        for index, action in enumerate(("global", "mode", "downgrade", "remove"), 1):
            with self.subTest(action=action):
                database.set_peer_rt_flag("on")
                database.set_peer_rt_mode(EMAIL, "on")
                bot._peer_caps.clear()
                database.set_peer_rt_capability(FP, True)
                msg_id = MSG + index
                self.carrier(msg_id)
                await self.tick()
                if action == "global":
                    self.command(bot.peerrt_command, "off")
                elif action == "mode":
                    self.command(bot.peerrt_command, EMAIL + " off")
                elif action == "downgrade":
                    bot._note_peer_announcement(database.get_peer(EMAIL), {"caps": ["batch_check"]}, telemetry=True)
                else:
                    self.command(bot.rmpeer_command, EMAIL)
                self.advertisement(msg_id)
                self.send.reset_mock()
                await self.tick()
                self.leave.assert_called_with(1, msg_id)
                self.send.assert_not_called()
                peer = database.get_peer(EMAIL)
                if action == "remove":
                    self.assertIsNone(peer)
                else:
                    self.assertIsNone(peer["rt_msg_id"])
                    self.assertIsNone(peer["rt_advert_at"])
                    self.assertEqual(peer["rt_mode"], "off" if action == "mode" else "on")

    async def test_bad_frames_are_counted_and_never_answered(self):
        self.jitter = 30_000
        self.carrier()
        good = self.inbound("hello")
        self.receive(good)
        await self.tick()
        self.send.reset_mock()
        invalid = [good, self.inbound(offset=-121), self.inbound(offset=121),
                   [0] * (peer_rt.RT_PEER_MAX_BYTES + 1), self.inbound(key=OUT_KEY),
                   [999], self.inbound(ack=1)]
        with self.assertLogs(bot.logger, level="WARNING") as logs:
            for frame in invalid:
                self.receive(frame)
        self.assertEqual(len(logs.records), 1)
        await self.tick()
        self.send.assert_not_called()
        self.advertise.assert_not_called()
        counts = self.traffic()
        self.assertEqual(counts["rt_invalid", "rt", "in"], (len(invalid), sum(map(len, invalid))))
        self.assertEqual(counts["hello", "rt", "in"][0], 1)

    async def test_rate_limit_and_only_health_traffic(self):
        self.jitter = 30_000
        self.carrier()
        with self.assertLogs(bot.logger, level="WARNING"):
            for kind in ("req", "resp", "breq", "bresp", "metrics"):
                self.receive(self.inbound(kind))
            for _ in range(50):
                self.receive(self.inbound("pong", {"e": "ba5eba11", "s": 4}))
        await self.tick()
        self.assertFalse(any(json.loads(bytes(call.args[2]))["k"] not in peer_rt.RT_HEALTH_KINDS
                             for call in self.send.call_args_list))
        self.send.reset_mock()
        dest = bot._PeerDestination(self.client, 1, CHAT)
        for kind in ("CHECK_REQ", "CHECK_RESP", "CHECK_BATCH_REQ", "CHECK_BATCH_RESP", "METRICS"):
            bot.peer_send(dest, kind, {"msg_id": "example"}, priority=bot.PRIO_PEER,
                          expires_in=30, label=kind)
        self.send.assert_not_called()
        self.assertEqual(self.rpc.send_msg.call_count, 5)
        counts = self.traffic()
        self.assertEqual(counts["rt_invalid", "rt", "in"][0], 10)
        self.assertEqual(counts["METRICS", "mail", "out"][0], 1)
