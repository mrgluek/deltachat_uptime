"""Exercise both ends of realtime rejoin over a fake carrier."""

import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import bot
import database
import peer_rt
from test_peer_rt_channel import Event


LEFT, RIGHT = 456, 457
OTHER_END = {LEFT: RIGHT, RIGHT: LEFT}
EMAIL = {LEFT: "right@example.org", RIGHT: "left@example.org"}
FP = {LEFT: "AA" * 20, RIGHT: "BB" * 20}
KEY = {LEFT: b"a" * 32, RIGHT: b"b" * 32}


class PeerRTRejoinFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.multiple(database, DB_PATH=str(Path(directory) / "uptime.db"),
                                         _peer_traffic_buffer={}, _peer_rtt_buffer=[], _mail_kind_buffer={}))
        self.addCleanup(database.close_db)
        database.init_db()
        self.seconds = 0
        self.clock = SimpleNamespace(time=lambda: 1_800_000_000 + self.seconds, monotonic=lambda: self.seconds)
        self.client = Mock()
        self.wire = []
        self.cut = False
        self.hold_responses = False
        self.drop_pong_from = None
        self.client.rpc.send_webxdc_realtime_data.side_effect = self.send
        self.client.rpc.send_webxdc_realtime_advertisement.side_effect = self.advertise
        self.enterContext(patch.object(database, "time", self.clock))
        self.enterContext(patch.object(bot.secrets, "randbelow", return_value=0))
        self.enterContext(patch.multiple(
            bot, time=self.clock, dc_accid=1, async_event_loop=asyncio.get_running_loop(),
            run_db=self.run_sync, run_rpc=self.run_sync, _peer_caps={}, _peer_caps_backoff={},
            _peer_caps_refresh=set(), _peer_rt_retry_now=set(), _telemetry_rt_peers={},
            _peer_rt_audit_requested=threading.Event(), _peer_rt_links={}, _peer_rt_carrier_ids=set(),
            _peer_rt_pending_adverts=set(), _peer_rt_leaves=set(), stat_event=Mock(),
            _peer_rt_limiter=peer_rt.TokenBucketLimiter(clock=self.clock.monotonic),
            _peer_rt_log=peer_rt.LogOnce(clock=self.clock.monotonic),
            _is_dc_admin=Mock(return_value=True), _dc_send_msg_with_stats=Mock()))
        database.set_peer_rt_flag("on")
        for msg_id in OTHER_END:
            database.add_or_update_peer(EMAIL[msg_id], EMAIL[msg_id], msg_id, fingerprint=FP[msg_id])
            database.set_peer_version(EMAIL[msg_id], "3.0.0")
            database.set_peer_rt_capability(FP[msg_id], True)
            bot._peer_caps[EMAIL[msg_id]] = {"rt1", "batch_check"}
        self.install_carrier()
        await self.wait_for_link()

    @staticmethod
    async def run_sync(func, *args):
        return func(*args)

    def install_carrier(self, cid="aa" * 8):
        # The accepted carrier is represented by a different local message ID on each side.
        for msg_id, other in OTHER_END.items():
            database.set_peer_rt(FP[msg_id], cid=cid, msg_id=msg_id, key_out=KEY[msg_id],
                                 key_in=KEY[other], created_at=int(self.clock.time()))
        bot._refresh_peer_rt_channels()

    def link(self, msg_id):
        return bot._peer_rt_links[msg_id]

    def deliver(self, msg_id, wire):
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=msg_id, data=list(wire)))

    def send(self, _accid, msg_id, blob):
        wire = bytes(blob)
        self.wire.append((msg_id, wire))
        kind = json.loads(wire)["k"]
        if (not self.cut and not (kind == "resp" and self.hold_responses)
                and not (kind == "pong" and msg_id == self.drop_pong_from)):
            self.deliver(OTHER_END[msg_id], wire)

    def advertise(self, _accid, msg_id):
        if not self.cut:
            bot.on_status_realtime(self.client, 1, Event(
                kind="WebxdcRealtimeAdvertisementReceived", msg_id=OTHER_END[msg_id]))

    async def tick(self):
        await bot._tick_peer_rt(self.client, 1)
        self.seconds += 1

    async def wait_for_link(self):
        for _ in range(5):
            await self.tick()
            if all(self.link(msg_id).state.is_up and self.link(msg_id).remote_epoch == self.link(other).epoch
                   for msg_id, other in OTHER_END.items()):
                return
        self.fail("The first exchange did not establish both ends")

    def mode(self, mode):
        bot.peerrt_command(self.client, 1, SimpleNamespace(
            msg=SimpleNamespace(chat_id=90, from_id=77), payload=f"{EMAIL[LEFT]} {mode}"))

    async def reenable(self):
        self.mode("off")
        self.assertNotIn(LEFT, bot._peer_rt_links)
        self.assertIsNone(database.get_peer_rt(FP[LEFT])["rt_key_in"])
        self.mode("on")
        self.install_carrier(cid="bb" * 8)
        self.wire.clear()
        await self.wait_for_link()

    async def send_unacked(self, msg_id, kind, body):
        self.assertTrue(await bot._send_peer_rt_unacked(
            self.client, 1, msg_id, self.link(msg_id), kind, body))
        return self.wire[-1][1]


class TestPeerRTRejoin(PeerRTRejoinFixture):
    async def test_off_on_rejoins_on_the_first_exchange(self):
        old_epochs = {msg_id: self.link(msg_id).epoch for msg_id in OTHER_END}
        await self.reenable()
        for msg_id, other in OTHER_END.items():
            link = self.link(msg_id)
            self.assertNotEqual(old_epochs[msg_id], link.epoch)
            self.assertEqual(link.remote_epoch, self.link(other).epoch)
            first = next(json.loads(wire) for origin, wire in self.wire if origin == msg_id)
            self.assertEqual((first["s"], first["e"]), (0, link.epoch))
        with patch.object(bot, "handle_peer_metrics") as handler:
            await self.send_unacked(LEFT, "metrics", {"msg_id": "fresh", "metrics": []})
        handler.assert_called_once()

    async def test_old_session_frame_and_current_duplicate_are_rejected(self):
        with patch.object(bot, "handle_peer_metrics") as handler:
            body = {"msg_id": "snapshot", "metrics": []}
            old_wire = await self.send_unacked(LEFT, "metrics", body)
            handler.assert_called_once()
            await self.reenable()
            self.deliver(RIGHT, old_wire)
            handler.assert_called_once()
            new_wire = await self.send_unacked(LEFT, "metrics", body)
            self.deliver(RIGHT, new_wire)
        self.assertEqual(handler.call_count, 2)

    async def test_late_ack_cannot_cancel_a_reused_sequence(self):
        self.hold_responses = True
        request = {"req_id": "vote"}
        destination = bot._PeerDestination(self.client, 1, LEFT, fingerprint=FP[LEFT])
        send_mail = Mock()

        async def response():
            link = self.link(LEFT)
            await bot._send_peer_rt_check(destination, LEFT, link, "resp", request,
                                          send_mail, 30, None, None, None, None, None)
            return json.loads(self.wire[-1][1])

        old = await response()
        old_ack = {"e": old["e"], "s": [old["s"]]}
        old_wire = await self.send_unacked(RIGHT, "ack", old_ack)
        await self.reenable()
        fresh = await response()
        self.assertEqual(fresh["s"], old["s"])
        self.assertNotEqual(fresh["e"], old["e"])
        link = self.link(LEFT)
        self.deliver(LEFT, old_wire)
        self.assertIn(fresh["s"], link.fallbacks)
        # Also reject the old acknowledgment payload inside a current authenticated frame.
        remote = self.link(RIGHT)
        wrong_ack = peer_rt.encode("ack", remote.epoch, remote.seq, old_ack, KEY[RIGHT],
                                   recipient=link.epoch, clock=self.clock.time)
        remote.seq += 1
        self.deliver(LEFT, wrong_ack)
        self.assertIn(fresh["s"], link.fallbacks)
        await self.send_unacked(RIGHT, "ack", {"e": fresh["e"], "s": [fresh["s"]]})
        self.assertNotIn(fresh["s"], link.fallbacks)
        send_mail.assert_not_called()

    async def test_one_side_restarts_with_the_same_carrier_and_keys(self):
        survivor = self.link(RIGHT)
        prior = self.link(LEFT)
        old_hello = next(wire for origin, wire in self.wire if origin == LEFT and json.loads(wire)["k"] == "hello")
        with patch.object(bot, "handle_peer_metrics") as handler:
            to_survivor = await self.send_unacked(LEFT, "metrics", {"metrics": []})
            to_restart = await self.send_unacked(RIGHT, "metrics", {"metrics": []})
            del bot._peer_rt_links[LEFT]
            bot._refresh_peer_rt_channels()
            self.deliver(LEFT, to_restart)
            self.assertEqual(handler.call_count, 2)
            await self.wait_for_link()
            self.deliver(LEFT, to_restart)
            self.deliver(RIGHT, to_survivor)
            self.deliver(RIGHT, old_hello)
            await self.tick()
            self.assertEqual(handler.call_count, 2)
            await self.send_unacked(LEFT, "metrics", {"metrics": []})
            await self.send_unacked(RIGHT, "metrics", {"metrics": []})
        self.assertEqual(handler.call_count, 4)
        self.assertIs(self.link(RIGHT), survivor)
        self.assertEqual(self.link(LEFT).peer["rt_key_in"], prior.peer["rt_key_in"])
        self.assertNotEqual(self.link(LEFT).epoch, prior.epoch)
        self.assertEqual(survivor.remote_epoch, self.link(LEFT).epoch)

    async def test_cut_recovers_on_advertisement_on_the_same_session(self):
        links = {msg_id: self.link(msg_id) for msg_id in OTHER_END}
        self.cut = True
        self.seconds += peer_rt.RT_CHANNEL_TIMEOUT
        await self.tick()
        self.assertTrue(all(not link.state.is_up for link in links.values()))
        self.cut = False
        self.advertise(1, LEFT)
        await self.wait_for_link()
        for msg_id, link in links.items():
            self.assertIs(self.link(msg_id), link)

    async def test_heartbeat_rediscovers_peer_after_lost_handshake_replies(self):
        old_epoch = self.link(LEFT).epoch
        self.drop_pong_from = LEFT
        del bot._peer_rt_links[LEFT]
        bot._refresh_peer_rt_channels()
        for _ in range(8):
            await self.tick()
        self.assertTrue(self.link(LEFT).state.is_up)
        self.assertEqual(self.link(RIGHT).remote_epoch, old_epoch)

        self.drop_pong_from = None
        await self.wait_for_link()
