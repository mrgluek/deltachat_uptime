"""Cross-checks through the production peer seam with fake realtime and mail."""
import asyncio
import collections
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import bot
import database
import peer_rt
from outbox import Outbox
import test_peer_metrics
import test_peer_rt_channel as channel


TARGET = {"url": "https://target.example.org", "type": "http"}
LEGACY = {"email": "older@example.org", "node_name": "Older", "chat_id": 43}


class TestRealtimeChecks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.multiple(database, DB_PATH=str(Path(directory) / "uptime.db"),
                                         _peer_traffic_buffer={}, _peer_rtt_buffer=[], _mail_kind_buffer={}))
        self.addCleanup(database.close_db)
        database.init_db()
        self.now = 1_800_000_000
        self.mono = 100.0
        self.seq = 0
        self.wire = []
        self.mails = []
        self.client = Mock()
        self.client.rpc.send_webxdc_realtime_data.side_effect = self.capture_frame
        self.client.rpc.send_msg.side_effect = self.capture_mail
        self.outbox = Outbox()
        self.submits = self.enterContext(patch.object(self.outbox, "submit", wraps=self.outbox.submit))
        self.clock = Mock(time=lambda: self.now, monotonic=lambda: self.mono)
        self.replay = peer_rt.ReplayWindow(clock=self.clock.monotonic)
        self.enterContext(patch.multiple(
            bot, time=self.clock, async_event_loop=asyncio.get_running_loop(), dc_accid=1,
            dc_bot_instance=self.client, dc_outbox=self.outbox, _peer_caps={},
            _peer_rt_links={}, _peer_rt_carrier_ids=set(), _peer_rt_leaves=set(), _peer_rt_pending_adverts=set(),
            _peer_rt_epoch="feed1234", _peer_rt_replay=peer_rt.ReplayWindow(clock=self.clock.monotonic),
            _peer_rt_limiter=peer_rt.TokenBucketLimiter(clock=self.clock.monotonic),
            _peer_rt_log=peer_rt.LogOnce(clock=self.clock.monotonic),
            _inbound_probes=bot.InboundProbeAdmission(), pending_peer_checks={}, pending_batch_checks={},
            _pending_peer_rtt={}, _vote_peers={}, run_rpc=self.run_sync, stat_event=Mock(),
            is_safe_target_url=Mock(return_value=True), _prewarm_target_dns=AsyncMock(return_value=True),
            _get_verified_peer_for_msg=self.mail_identity, _is_trusted_peer_msg=Mock(return_value=True)))
        self.enterContext(patch.object(database, "time", self.clock))
        database.add_or_update_peer(channel.EMAIL, "Peer", channel.CHAT, fingerprint=channel.FP)
        database.add_or_update_peer(LEGACY["email"], LEGACY["node_name"], LEGACY["chat_id"])
        database.set_peer_version(LEGACY["email"], "2.44.2")
        database.set_peer_rt_flag("on")
        database.set_peer_rt_capability(channel.FP, True)
        database.set_peer_rt(channel.FP, cid=channel.CID, msg_id=channel.MSG, key_in=channel.IN_KEY,
                             key_out=channel.OUT_KEY, created_at=self.now)
        bot._refresh_peer_rt_channels()
        self.link = bot._peer_rt_links[channel.MSG]
        self.peer = database.get_peer_by_fingerprint(channel.FP)
        bot._peer_caps.update({channel.EMAIL: {"rt1", "batch_check"}, LEGACY["email"]: {"batch_check"}})
        self.link.state.on_frame()

    async def run_sync(self, func, *args):
        return func(*args)

    def advance(self, seconds):
        self.now += seconds
        self.mono += seconds

    def capture_frame(self, accid, msg_id, blob):
        self.assertEqual((accid, msg_id), (1, channel.MSG))
        self.wire.append(peer_rt.decode(bytes(blob), channel.OUT_KEY, peer=channel.FP, replay=self.replay,
                                        clock=self.clock.time))

    def capture_mail(self, accid, chat, msg):
        self.mails.append((chat, msg.text))
        return 100 + len(self.mails)

    def mail_identity(self, _client, _accid, msg, _private):
        peer = database.get_peer_by_chat_id(msg.chat_id)
        return peer, peer["email"]

    def receive_mail(self, kind, body, chat=channel.CHAT):
        event = test_peer_metrics.event(test_peer_metrics.message(kind, json.dumps(body)), chat)
        bot.on_new_message(self.client, 1, event)

    def incoming(self, kind, body, *, ack=1, key=channel.IN_KEY):
        self.seq += 1
        return list(peer_rt.encode(kind, "face1234", self.seq, body, key, ack=ack, clock=self.clock.time))

    def receive_frame(self, kind, body, *, ack=1):
        self.receive_bytes(self.incoming(kind, body, ack=ack))

    def receive_bytes(self, data, msg_id=channel.MSG):
        event = channel.Event(kind="WebxdcRealtimeData", msg_id=msg_id, data=data)
        bot.on_status_realtime(self.client, 1, event)

    def acknowledge(self, frame):
        self.receive_frame("ack", {"s": [frame["s"]]}, ack=0)

    async def until(self, condition):
        async def wait():
            while not condition():
                await asyncio.sleep(0.001)
        await asyncio.wait_for(wait(), 2)

    def vote(self, *, peers=None):
        async def run():
            if peers is None:
                return await run_batch()
            with patch.object(database, "get_all_peers", return_value=peers):
                return await run_batch()

        async def run_batch():
            future = asyncio.get_running_loop().create_future()
            await bot._flush_cross_checks([(TARGET, future, None)])
            return future.result()

        return asyncio.create_task(run())

    def answer_body(self, request, status="up"):
        return {"req_id": request["req_id"], "results": [{"status": status, "latency_ms": 9}]}

    async def first_request(self):
        await self.until(lambda: self.wire)
        frame = self.wire[0]
        self.assertEqual((frame["k"], frame["a"]), ("breq", 1))
        return frame

    def mail_body(self, index=0):
        return json.loads(self.mails[index][1].splitlines()[1])

    def samples(self):
        return [(kind, via, peer, ms, ok) for _, kind, via, peer, ms, ok in database._peer_rtt_buffer]

    async def test_realtime_first_answer_wins_and_uses_peer_row(self):
        task = self.vote(peers=[self.peer])
        req = await self.first_request()
        self.acknowledge(req)
        self.advance(0.75)
        self.receive_frame("bresp", dict(self.answer_body(req["b"]), node_name="Claimed", caps=[]))
        self.receive_mail("CHECK_BATCH_RESP", self.answer_body(req["b"], "down"))
        answers = await task
        await self.until(lambda: len(self.wire) == 2)
        self.assertEqual(self.wire[1]["b"], {"s": [self.seq]})
        self.assertEqual(self.wire[1]["k"], "ack")
        self.assertEqual([(a["node_name"], a["status"]) for a in answers], [("Peer", "up")])
        self.assertEqual(database.get_peer_by_fingerprint(channel.FP)["node_name"], "Peer")
        self.assertEqual(self.samples(), [("vote", "rt", "Peer", 750, 1), ("vote_round", "rt", None, 750, 1)])
        self.assertEqual(self.mails, [])
        self.assertEqual(database._peer_traffic_buffer[int(self.now), "bresp", "rt", "in"][0], 1)

    async def test_lost_request_falls_back_at_three_seconds_and_keeps_original_wait(self):
        task = self.vote(peers=[self.peer])
        with patch.object(asyncio.get_running_loop(), "call_later",
                          wraps=asyncio.get_running_loop().call_later) as timer:
            req = await self.first_request()
        self.assertIn((3, bot._expire_peer_rt_acks, self.link), [item.args for item in timer.call_args_list])
        self.advance(2.999)
        bot._expire_peer_rt_acks(self.link)
        self.assertEqual(self.mails, [])
        self.advance(0.001)
        bot._expire_peer_rt_acks(self.link)
        await self.until(lambda: self.mails)
        self.assertEqual(self.mail_body(), req["b"])
        expected = {
            "req_id": req["b"]["req_id"], "node_name": database.get_local_node_name(),
            "caps": bot._own_peer_caps(), "targets": [dict(TARGET, expected_keyword=None, family=None)],
        }
        self.assertEqual(self.mails[0][1], test_peer_metrics.message("CHECK_BATCH_REQ", json.dumps(expected)))
        self.assertAlmostEqual(self.submits.call_args.kwargs["expires_in"], bot.CROSS_CHECK_BATCH_TIMEOUT - 3)
        self.assertNotIn(channel.FP, bot._vote_peers)
        self.advance(1)
        self.receive_mail("CHECK_BATCH_RESP", self.answer_body(req["b"]))
        self.receive_frame("bresp", self.answer_body(req["b"], "down"))
        self.assertEqual([a["status"] for a in await task], ["up"])
        await self.until(lambda: len(self.wire) == 2)
        self.assertEqual(self.samples(), [("vote", "mail", "Peer", 1000, 1), ("vote_round", "mail", None, 4000, 1)])
        self.assertEqual(bot._vote_peers[channel.FP].streak, 0)
        self.assertEqual(database._peer_traffic_buffer[int(self.now) - 1, "rt_fallback", "fallback", "out"][0], 1)

    async def test_channel_down_after_request_ack_uses_mail(self):
        task = self.vote(peers=[self.peer])
        req = await self.first_request()
        self.acknowledge(req)
        self.advance(1)
        database.set_peer_rt_flag("off")
        bot._refresh_peer_rt_channels()
        await self.until(lambda: self.mails)
        self.assertEqual(self.mail_body(), req["b"])
        self.assertEqual(self.submits.call_args.kwargs["expires_in"], bot.CROSS_CHECK_BATCH_TIMEOUT - 1)
        self.receive_mail("CHECK_BATCH_RESP", self.answer_body(req["b"]))
        self.assertEqual(len(await task), 1)
        self.advance(3)
        bot._expire_peer_rt_acks(self.link)
        self.assertEqual(len(self.mails), 1)
        self.assertEqual(len(self.wire), 1)

    async def test_two_missed_acks_make_the_channel_down(self):
        destination = bot._PeerDestination(self.client, 1, channel.CHAT, fingerprint=channel.FP)
        for req_id in ("first", "second"):
            bot.peer_send(destination, "CHECK_RESP", {"req_id": req_id}, priority=bot.PRIO_PEER,
                          expires_in=bot.PEER_ANSWER_TTL, label="cross-check answer")
        await self.until(lambda: len(self.wire) == 2)
        self.advance(3)
        bot._expire_peer_rt_acks(self.link)
        self.assertFalse(self.link.state.is_up)
        self.assertEqual(self.link.down_since, self.mono)
        await self.until(lambda: len(self.mails) == 2)
        self.assertCountEqual([self.mail_body(i)["req_id"] for i in range(2)], ["first", "second"])
        self.receive_frame("bresp", {"req_id": "second"})
        self.assertEqual(len(self.wire), 2)

    async def test_loss_of_both_paths_is_one_breaker_miss_and_rt_answer_resets_it(self):
        timeout_ready = asyncio.Event()
        wait_for = asyncio.wait_for

        async def wait(future, timeout):
            if timeout != bot.CROSS_CHECK_BATCH_TIMEOUT:
                return await wait_for(future, timeout)
            await timeout_ready.wait()
            if future.done():
                return future.result()
            future.cancel()
            raise asyncio.TimeoutError

        with patch.object(bot.asyncio, "wait_for", side_effect=wait):
            task = self.vote(peers=[self.peer])
            await self.first_request()
            self.advance(3)
            bot._expire_peer_rt_acks(self.link)
            await self.until(lambda: self.mails)
            self.assertNotIn(channel.FP, bot._vote_peers)
            self.advance(bot.CROSS_CHECK_BATCH_TIMEOUT - 3)
            timeout_ready.set()
            self.assertEqual(await task, [])
        self.assertEqual(bot._vote_peers[channel.FP].streak, 1)
        self.assertEqual([entry[-1] for entry in self.samples()], [0, 0])
        task = self.vote(peers=[self.peer])
        await self.until(lambda: len(self.wire) == 2)
        self.acknowledge(self.wire[1])
        self.receive_frame("bresp", self.answer_body(self.wire[1]["b"]))
        self.assertEqual(len(await task), 1)
        await self.until(lambda: len(self.wire) == 3)
        self.assertEqual(bot._vote_peers[channel.FP].streak, 0)

    async def test_mixed_mesh_keeps_one_vote_per_node_and_legacy_envelope(self):
        task = self.vote(peers=[self.peer, LEGACY])
        req = await self.first_request()
        await self.until(lambda: self.mails)
        legacy = self.mail_body()
        expected = {
            "req_id": legacy["req_id"], "node_name": database.get_local_node_name(),
            "caps": bot._own_peer_caps(), "targets": [dict(TARGET, expected_keyword=None, family=None)],
        }
        self.assertEqual(self.mails, [(LEGACY["chat_id"], test_peer_metrics.message("CHECK_BATCH_REQ", json.dumps(expected)))])
        self.acknowledge(req)
        self.receive_frame("bresp", self.answer_body(req["b"]))
        self.receive_mail("CHECK_BATCH_RESP", self.answer_body(legacy), chat=LEGACY["chat_id"])
        answers = await task
        await self.until(lambda: len(self.wire) == 2)
        self.assertCountEqual([a["node_name"] for a in answers], ["Peer", "Older"])
        self.assertCountEqual([(kind, via, node) for kind, via, node, _, _ in self.samples()],
                              [("vote", "mail", "Older"), ("vote", "rt", "Peer"),
                               ("vote_round", "mixed", None)])

    async def test_oversized_frame_uses_byte_identical_mail(self):
        payload = {"req_id": "huge", "results": [{"error_msg": "é" * peer_rt.RT_PEER_MAX_BYTES}]}
        destination = bot._PeerDestination(self.client, 1, channel.CHAT, fingerprint=channel.FP)
        bot.peer_send(destination, "CHECK_BATCH_RESP", payload,
                      priority=bot.PRIO_PEER, expires_in=bot.PEER_ANSWER_TTL, label="batch cross-check answer")
        await self.until(lambda: self.mails)
        self.assertEqual(self.mails, [(channel.CHAT, test_peer_metrics.message("CHECK_BATCH_RESP", json.dumps(payload)))])
        self.assertEqual(self.wire, [])

    async def test_lost_realtime_answer_can_be_replayed_by_mail_without_a_probe(self):
        req = {"req_id": "lost-answer", "targets": [TARGET], "caps": bot._own_peer_caps()}
        check = AsyncMock(return_value=(False, "HTTP 503", 51))
        with patch.object(bot, "run_single_check", check),              patch.object(bot._inbound_probes, "acquire", wraps=bot._inbound_probes.acquire) as admit:
            self.receive_frame("breq", req)
            await self.until(lambda: len(self.wire) == 2)
            frames = {frame["k"]: frame for frame in self.wire}
            lost = frames["bresp"]
            self.assertEqual((lost["a"], lost["b"]["results"][0]["status"]), (1, "down"))
            self.assertEqual(frames["ack"]["b"], {"s": [1]})
            self.receive_mail("CHECK_BATCH_REQ", req)
            self.assertEqual(self.mail_body(), lost["b"])
            self.receive_frame("breq", req)
            await self.until(lambda: len(self.wire) == 4)
            replay, = [frame for frame in self.wire[2:] if frame["k"] == "bresp"]
            self.assertEqual(replay["b"], lost["b"])
            self.acknowledge(replay)
            check.assert_awaited_once()
            admit.assert_called_once()
            self.advance(3)
            bot._expire_peer_rt_acks(self.link)
            await self.until(lambda: len(self.mails) == 2)
            self.assertEqual(self.mail_body(1), lost["b"])
            self.assertEqual(self.submits.call_args.kwargs["expires_in"], bot.PEER_ANSWER_TTL)

    async def test_mail_repeat_during_realtime_probe_does_not_admit_another_probe(self):
        req = {"req_id": "working", "url": TARGET["url"]}
        started, finish = asyncio.Event(), asyncio.Event()

        async def probe(_):
            started.set()
            await finish.wait()
            return True, None, 5

        with patch.object(bot, "run_single_check", side_effect=probe) as check:
            self.receive_frame("req", req)
            await asyncio.wait_for(started.wait(), 2)
            self.receive_mail("CHECK_REQ", req)
            self.assertEqual(self.mails, [])
            finish.set()
            await self.until(lambda: len(self.wire) == 2)
            ack, answer = self.wire
            self.assertEqual((ack["k"], answer["k"], answer["b"]["req_id"]), ("ack", "resp", req["req_id"]))
            self.acknowledge(answer)
            check.assert_awaited_once()

    async def test_ping_uses_single_request_and_first_response(self):
        task = asyncio.create_task(bot.request_peer_cross_checks(TARGET, peers=[self.peer]))
        await self.until(lambda: self.wire)
        req = self.wire[0]
        self.assertEqual((req["k"], req["a"]), ("req", 1))
        self.acknowledge(req)
        resp = {"req_id": req["b"]["req_id"], "url": TARGET["url"], "node_name": "Spoofed", "status": "up"}
        self.receive_frame("resp", resp)
        self.receive_mail("CHECK_RESP", dict(resp, node_name="Peer", status="down"))
        answer, = await task
        await self.until(lambda: len(self.wire) == 2)
        self.assertEqual((answer["status"], answer["node_name"]), ("up", "Peer"))
        self.assertEqual(self.samples(), [("ping", "rt", "Peer", 0, 1)])

    async def test_bad_mac_down_channel_and_replay_never_reach_the_handler(self):
        body = {"req_id": "checked", "targets": [TARGET]}
        self.advance(peer_rt.RT_CHANNEL_TIMEOUT)
        peer = database.get_peer_by_fingerprint(channel.FP)
        with patch.object(bot, "handle_peer_check_batch_req") as handler:
            self.receive_frame("breq", body)
            self.link.state.on_frame()
            self.receive_bytes(self.incoming("breq", body, key=b"x" * 32))
            self.receive_frame("breq", body, ack=0)
            handler.assert_not_called()
            good = self.incoming("breq", body)
            self.receive_bytes(good)
            self.receive_bytes(good)
            handler.assert_called_once_with(self.client, 1, peer, channel.CHAT, body, via="rt")
        await self.until(lambda: self.wire)
        self.assertEqual([frame["k"] for frame in self.wire], ["ack"])
        counts = collections.Counter()
        for (_, kind, via, _), (n, _) in database._peer_traffic_buffer.items():
            counts[kind, via] += n
        self.assertEqual(counts["rt_invalid", "rt"], 4)
        self.assertEqual(counts["breq", "rt"], 1)
