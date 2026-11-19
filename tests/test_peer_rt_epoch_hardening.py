"""Regression tests for realtime epoch discovery and validation."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import bot
import database
import peer_rt
from test_peer_rt_rejoin import FP, KEY, LEFT, OTHER_END, RIGHT, PeerRTRejoinFixture


EPOCH_B = "2" * 32
EPOCH_C = "3" * 32


class TestPeerRTEpochHardening(PeerRTRejoinFixture):
    def replace_link(self, msg_id, **kwargs):
        link = bot._PeerRealtimeLink(self.link(msg_id).peer, None, **kwargs)
        bot._peer_rt_links[msg_id] = link
        return link

    def inbound(self, kind, epoch, seq, *, body=None, recipient=None, ack=0):
        if recipient is None and kind != "hello":
            recipient = self.link(LEFT).epoch
        return peer_rt.encode(kind, epoch, seq, body or {}, KEY[RIGHT], recipient=recipient, ack=ack,
                              clock=self.clock.time)

    def outbound(self, msg_id):
        return [json.loads(wire) for origin, wire in self.wire if origin == msg_id]

    def pong(self, epoch, challenge, *, seq=1000):
        return self.inbound("pong", epoch, seq, body={"e": self.link(LEFT).epoch, "s": challenge})

    async def challenge(self, epoch, seq):
        self.deliver(LEFT, self.inbound("hello", epoch, seq))
        await self.tick()
        return next(challenge for challenge, probe in self.link(LEFT).probes.items() if probe.epoch == epoch)

    async def test_wrong_recipient_rediscovery_converges_within_five_ticks(self):
        survivor = self.link(RIGHT)
        restart = self.replace_link(LEFT, remote_epoch=survivor.epoch)
        restart.state.on_frame()
        self.assertTrue(survivor.state.is_up)
        self.assertNotEqual(survivor.remote_epoch, restart.epoch)

        started_at = self.seconds
        self.wire.clear()
        await self.send_unacked(RIGHT, "ping", {})
        self.assertTrue(restart.hello_requested)
        await self.tick()
        self.assertEqual([(frame["k"], frame["r"]) for frame in self.outbound(LEFT)], [("hello", None)])
        await self.send_unacked(RIGHT, "ping", {})
        self.assertFalse(restart.hello_requested)
        await self.wait_for_link()
        self.assertLessEqual(self.seconds - started_at, 5)

    async def test_unanswered_ping_sends_discovery_hello_at_the_next_interval(self):
        self.cut = True
        link = self.link(LEFT)
        link.next_ping_at = self.seconds
        self.wire.clear()
        await self.tick()
        self.assertEqual([frame["k"] for frame in self.outbound(LEFT)], ["ping"])
        self.seconds += bot.PEER_RT_PING_INTERVAL - 1
        await self.tick()
        self.assertTrue(link.state.is_up)
        self.assertEqual([(frame["k"], frame["r"]) for frame in self.outbound(LEFT)],
                         [("ping", link.remote_epoch), ("hello", None)])

    async def test_simultaneous_hellos_use_one_challenge_and_accept_both_pongs(self):
        for msg_id in OTHER_END:
            self.replace_link(msg_id)
        self.wire.clear()
        with patch.object(database, "record_peer_traffic", wraps=database.record_peer_traffic) as traffic:
            for msg_id in OTHER_END:
                await self.send_unacked(msg_id, "hello", {})
            await self.wait_for_link()
            await self.tick()
        for msg_id, other in OTHER_END.items():
            frames = self.outbound(msg_id)
            self.assertEqual([f["r"] for f in frames if f["k"] == "hello"], [None, self.link(other).epoch])
            self.assertEqual(sum(f["k"] == "pong" for f in frames), 1)
            self.assertFalse(self.link(msg_id).probes)
        kinds = [call.args[:3] for call in traffic.call_args_list]
        self.assertEqual(kinds.count(("pong", "rt", "in")), 2)
        self.assertNotIn(("rt_invalid", "rt", "in"), kinds)

    async def test_install_preserves_other_epochs_probes_and_accepts_request_before_tick(self):
        self.cut = True
        link = self.link(LEFT)
        old_epoch = link.remote_epoch
        self.deliver(LEFT, self.inbound("hello", old_epoch, 500))
        first_challenge = await self.challenge(EPOCH_B, 501)
        old_challenge = next(seq for seq, probe in link.probes.items() if probe.epoch == old_epoch)
        next_challenge = await self.challenge(EPOCH_C, 502)

        self.deliver(LEFT, self.pong(EPOCH_B, first_challenge))
        self.assertEqual(link.remote_epoch, EPOCH_B)
        self.assertTrue(link.state.is_up)
        self.assertEqual(link.state.last_frame_at, self.seconds)
        self.assertNotIn(old_challenge, link.probes)
        self.assertIn(next_challenge, link.probes)
        self.assertNotIn(first_challenge, link.probes)
        with patch.object(bot, "handle_peer_check_req") as request:
            self.deliver(LEFT, self.inbound("req", EPOCH_B, 1001, body={"req_id": "vote"}, ack=1))
        request.assert_called_once()

    async def test_down_channel_rejection_does_not_spend_request_or_ack_sequence(self):
        self.cut = True
        epoch = self.link(RIGHT).epoch
        link = self.replace_link(LEFT, remote_epoch=epoch)
        challenge = await self.challenge(epoch, 500)
        req = self.inbound("req", epoch, 1001, body={"req_id": "vote"}, ack=1)
        ack = self.inbound("ack", epoch, 1002, body={"e": link.epoch, "s": [77]})
        with patch.object(bot, "handle_peer_check_req") as request, patch.object(link.acks, "ack") as acked:
            acked.return_value = False
            self.deliver(LEFT, req)
            self.deliver(LEFT, ack)
            request.assert_not_called()
            acked.assert_not_called()
            self.deliver(LEFT, self.pong(epoch, challenge))
            self.deliver(LEFT, req)
            self.deliver(LEFT, ack)
        request.assert_called_once()
        acked.assert_called_once_with(77)
        with self.assertLogs(bot.logger, level="INFO") as logs:
            await self.tick()
        self.assertEqual(sum("is UP" in message for message in logs.output), 1)

    async def test_reflected_hello_is_rejected_even_with_equal_keys(self):
        link = self.link(LEFT)
        link.peer["rt_key_in"] = link.peer["rt_key_out"]
        reflected = peer_rt.encode("hello", link.epoch, link.seq, {}, KEY[LEFT],
                                   recipient=None, clock=self.clock.time)
        with self.assertLogs(bot.logger, level="WARNING") as logs:
            self.deliver(LEFT, reflected)
        self.assertIn("Reflected local session frame", logs.output[0])
        self.assertFalse(link.hellos)
        self.assertFalse(link.hello_requested)

    async def test_reflected_accept_key_cannot_install_carrier(self):
        cid = "bb" * 8
        fp = FP[LEFT]
        database.save_peer_rt_offer(fp, cid, 888, KEY[LEFT])
        msg = SimpleNamespace(chat_id=LEFT, id=789)

        def accept(key):
            payload = json.dumps(bot._peer_rt_key_payload(cid, key))
            text = f"[UPTIME_PEER_RT_ACCEPT]{payload}[/UPTIME_PEER_RT_ACCEPT]"
            bot._handle_peer_rt_mail(self.client, 1, msg, "RT_ACCEPT", text)

        with (patch.object(bot, "_peer_rt_chat_is_private", return_value=True),
              patch.object(bot, "_is_trusted_peer_msg", return_value=True),
              patch.object(bot, "_get_verified_peer_for_msg", side_effect=lambda *a, **kw: (
                  database.get_peer_by_fingerprint(fp), fp)),
              patch.object(bot.dc_fingerprint, "get_self_fingerprint", return_value="00" * 20)):
            accept(KEY[LEFT])
            self.assertNotEqual(database.get_peer_rt(fp)["rt_cid"], cid)
            self.assertEqual(database.get_peer_by_fingerprint(fp)["rt_offer_cid"], cid)
            accept(KEY[RIGHT])
        self.assertEqual(database.get_peer_rt(fp)["rt_cid"], cid)

    async def test_hello_burst_and_live_probe_caps_count_excess_frames(self):
        self.cut = True
        link = self.link(LEFT)
        self.wire.clear()
        with (patch.object(database, "record_peer_traffic", wraps=database.record_peer_traffic) as traffic,
              self.assertLogs(bot.logger, level="WARNING") as logs):
            for tick, expected in enumerate((2, 2, 0)):
                for n in range(6):
                    epoch = f"{tick * 6 + n:032x}"
                    self.deliver(LEFT, self.inbound("hello", epoch, 0, recipient=link.epoch))
                self.assertEqual(len(link.hellos), 4)
                self.wire.clear()
                await self.tick()
                self.assertEqual([f["k"] for f in self.outbound(LEFT)], ["pong", "hello"] * expected)
                self.assertEqual(len(link.probes), min(2 * (tick + 1), 4))
        kinds = [call.args[:3] for call in traffic.call_args_list]
        self.assertEqual(kinds.count(("rt_invalid", "rt", "in")), 14)
        self.assertEqual(kinds.count(("hello", "rt", "in")), 4)
        self.assertEqual(len(logs.output), 1)

    async def test_retired_epoch_cannot_return_and_epoch_switches_are_rate_limited(self):
        self.cut = True
        link = self.link(LEFT)
        old_epoch = link.remote_epoch
        replay = link.replay
        self.assertTrue(replay.accept(FP[LEFT], old_epoch, 1000))
        challenge = await self.challenge(EPOCH_B, 500)
        with self.assertLogs(bot.logger, level="INFO") as logs:
            self.deliver(LEFT, self.pong(EPOCH_B, challenge))
            switched_at = self.seconds
            self.assertEqual(link.retired_epochs[old_epoch], switched_at + peer_rt.RT_REPLAY_WINDOW)
            self.assertIs(link.replay, replay)
            self.assertFalse(link.replay.accept(FP[LEFT], old_epoch, 1000))
            self.deliver(LEFT, self.inbound("hello", old_epoch, 501))
            self.assertFalse(link.hellos)

            # Even a matching challenge must not install a retired epoch.
            link.probes[1000] = bot._PeerRealtimeProbe(old_epoch, self.seconds, None)
            self.deliver(LEFT, self.pong(old_epoch, 1000, seq=1002))
            del link.probes[1000]
            self.assertEqual(link.remote_epoch, EPOCH_B)

            challenge = await self.challenge(EPOCH_C, 502)
            self.deliver(LEFT, self.pong(EPOCH_C, challenge))
            self.assertEqual(link.remote_epoch, EPOCH_B)
            self.seconds = switched_at + bot.PEER_RT_EPOCH_SWITCH_INTERVAL
            challenge = await self.challenge(EPOCH_C, 503)
            self.deliver(LEFT, self.pong(EPOCH_C, challenge))
            self.assertEqual(link.remote_epoch, EPOCH_C)
        self.assertEqual(sum("switched remote session" in message for message in logs.output), 1)

        self.seconds = switched_at + peer_rt.RT_REPLAY_WINDOW
        challenge = await self.challenge(old_epoch, 504)
        self.deliver(LEFT, self.pong(old_epoch, challenge, seq=1003))
        self.assertEqual(link.remote_epoch, old_epoch)
        self.assertNotIn(old_epoch, link.retired_epochs)
