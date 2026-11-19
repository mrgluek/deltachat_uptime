"""Regression coverage for peer admission, replay budgets and telemetry delivery."""
import asyncio
import collections
import json
import threading
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import bot
import database
import peer_rt
from outbox import Outbox
from test_peer_metrics import event, message
from test_peer_rt_channel import CHAT, CID, EMAIL, FP, IN_KEY, MSG, OUT_KEY, Event
from test_peer_seam import inline_peer_metrics
from test_peer_scaling import _DbCase


TARGET = {"url": "https://target.example.org", "type": "http", "status": "up"}
SECOND_EMAIL = "another@example.org"


class TestPeerRTAuditFixes(_DbCase, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.now, self.mono, self.seq = 1_800_000_000, 100.0, 0
        self.clock = SimpleNamespace(time=lambda: self.now, monotonic=lambda: self.mono)
        self.client = Mock()
        self.client.rpc.send_msg.side_effect = lambda *_: self.client.rpc.send_msg.call_count + MSG
        self.client.rpc.get_message_ids.return_value = [MSG]
        self.client.rpc.get_basic_chat_info.return_value = {"chat_type": "Single", "is_encrypted": True}
        self.client.rpc.get_chat_contacts.return_value = [21]
        self.outbox = Outbox(clock=self.clock.monotonic)
        self.enterContext(patch.multiple(
            bot, time=self.clock, monotonic=self.clock.monotonic, dc_accid=1,
            dc_bot_instance=self.client, dc_outbox=self.outbox, stat_event=Mock(),
            _inbound_probes=bot.InboundProbeAdmission(), _peer_rt_links={},
            _peer_rt_carrier_ids=set(), _peer_rt_pending_adverts=set(), _peer_rt_leaves=set(),
            _peer_rt_replay=peer_rt.ReplayWindow(clock=self.clock.monotonic),
            _peer_rt_limiter=peer_rt.TokenBucketLimiter(clock=self.clock.monotonic),
            _peer_rt_audit_requested=threading.Event(), _peer_caps={}, _peer_caps_announcements={},
            _peer_caps_requests=set(), _peer_telemetry_interval={}, _peer_desired_interval={}, _peer_versions={},
            _processed_msg_ids=bot._ProcessedMessageIds(), _peer_metrics_timestamps=collections.OrderedDict(),
            _telemetry_rt_peers={}, _telemetry_delivered={}, _telemetry_started_at={},
            _telemetry_sent_at={}, _telemetry_last_sent={}, _telemetry_queued_status={},
            _scheduler_cache={}, _get_self_addr=lambda *_: "local@example.org",
            _get_verified_peer_for_msg=lambda _bot, _accid, msg, _private: (
                database.get_peer_by_chat_id(msg.chat_id), EMAIL),
            _is_trusted_peer_msg=Mock(return_value=True), note_peer_reported_down=Mock(),
        ))
        self.enterContext(patch.multiple(database, time=self.clock, _peer_traffic_buffer={}, _mail_kind_buffer={}))
        database.set_peer_rt_flag("on")
        database.add_or_update_peer(EMAIL, "Peer", CHAT, fingerprint=FP)
        database.add_or_update_peer(SECOND_EMAIL, "Other", CHAT + 1)
        database.set_peer_rt_capability(FP, True)
        database.set_peer_rt(FP, cid=CID, msg_id=MSG, key_in=IN_KEY, key_out=OUT_KEY, created_at=self.now)
        bot._refresh_peer_rt_channels()
        self.link = bot._peer_rt_links[MSG]
        self.peer = database.get_peer_by_fingerprint(FP)

    async def asyncSetUp(self):
        self.enterContext(patch.object(bot, "async_event_loop", asyncio.get_running_loop()))

    def advance(self, seconds):
        self.mono += seconds
        self.now += seconds

    def receive_rt(self, kind, body, *, ack=1):
        self.seq += 1
        frame = peer_rt.encode(kind, "feed1234", self.seq, body, IN_KEY, ack=ack, clock=self.clock.time)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=MSG, data=list(frame)))

    def receive_mail(self, kind, body, chat=CHAT):
        bot.on_new_message(self.client, 1, event(message(kind, json.dumps(body)), chat))

    async def until(self, condition):
        async def wait():
            while not condition():
                await asyncio.sleep(0.001)
        await asyncio.wait_for(wait(), 5)

    async def test_capacity_rejection_leaves_rt_requests_unacked_until_mail_retry(self):
        self.link.state.on_frame()
        admission = bot._inbound_probes
        reservations = [admission.acquire({"email": f"busy{i}@example.org"}, "busy", 10)[1] for i in range(2)]
        req = dict(TARGET, req_id="one")
        batch = {"req_id": "many", "targets": [TARGET]}
        with patch.object(bot, "_send_peer_rt_unacked", AsyncMock(return_value=True)) as send_rt, \
             patch.object(bot, "is_safe_target_url", return_value=True), \
             patch.object(bot, "_prewarm_target_dns", AsyncMock(return_value=True)), \
             patch.object(bot, "run_single_check", AsyncMock(return_value=(True, None, 5))) as check:
            self.receive_rt("req", req)
            self.receive_rt("breq", batch)
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            send_rt.assert_not_awaited()
            check.assert_not_awaited()

            for reservation in reservations:
                admission.release(reservation)
            self.advance(peer_rt.RT_ACK_TIMEOUT)
            self.receive_mail("CHECK_REQ", req)
            self.receive_mail("CHECK_BATCH_REQ", batch)
            await self.until(lambda: self.client.rpc.send_msg.call_count == 2)
            self.assertCountEqual(
                [json.loads(call.args[2].text.splitlines()[1])["req_id"]
                 for call in self.client.rpc.send_msg.call_args_list], ["one", "many"])

            self.receive_rt("req", req)
            self.receive_rt("breq", batch)
            await self.until(lambda: send_rt.await_count == 2)
            self.assertEqual([call.args[4:] for call in send_rt.await_args_list],
                             [("ack", {"s": [3]}), ("ack", {"s": [4]})])
            self.assertEqual(check.await_count, 2)

    async def test_replays_coalesce_while_queued_and_respect_peer_budget(self):
        admission = bot._inbound_probes

        def remember(req_id, **kwargs):
            admission.remember_answer((FP, req_id), "CHECK_RESP", {"req_id": req_id}, **kwargs)

        def replay(req_id):
            return bot._resend_cached_probe_answer(self.client, 1, CHAT, self.peer, req_id)

        remember("pending", via="mail")
        with patch.object(self.outbox, "submit", side_effect=lambda *args, **kwargs: Future()) as submit:
            self.assertTrue(replay("pending"))
            self.advance(bot.PEER_ANSWER_REPLAY_GAP + 1)
            for _ in range(3):
                self.assertTrue(replay("pending"))
            submit.assert_called_once()
            self.assertEqual(submit.call_args.kwargs["key"], ("peer_answer", FP, "pending"))
            submit.call_args.args[0]()  # delivery releases the queued reservation
            self.assertTrue(replay("pending"))  # The cooldown starts at actual delivery.
            submit.assert_called_once()

        for i in range(bot.PEER_ANSWER_REPLAYS_PER_MINUTE):
            remember(str(i), via="mail")
            self.assertTrue(replay(str(i)))
        self.assertEqual(self.client.rpc.send_msg.call_count, bot.PEER_ANSWER_REPLAYS_PER_MINUTE)

        remember("fallback", via="rt")
        self.assertTrue(replay("fallback"))
        self.assertTrue(replay("fallback"))
        self.assertEqual(self.client.rpc.send_msg.call_count, bot.PEER_ANSWER_REPLAYS_PER_MINUTE + 1)
        self.advance(60)
        self.assertTrue(replay("pending"))
        replayed = json.loads(self.client.rpc.send_msg.call_args.args[2].text.splitlines()[1])
        self.assertEqual(replayed["req_id"], "pending")

        remember("mail-wins", via="rt")
        found, reserved = admission.reserve_replay(self.peer, "mail-wins", "rt")
        self.assertTrue(found)
        _, _, pending, _ = reserved
        self.assertTrue(pending())
        self.assertTrue(replay("mail-wins"))
        self.assertFalse(pending())
        replayed = json.loads(self.client.rpc.send_msg.call_args.args[2].text.splitlines()[1])
        self.assertEqual(replayed["req_id"], "mail-wins")

    async def test_metrics_ids_are_validated_and_scoped_to_verified_peers(self):
        inline_peer_metrics(self)
        with patch.object(bot, "is_safe_target_url", return_value=True) as validate:
            for invalid in (None, [], {}, 123, "x" * 129):
                self.receive_mail("METRICS", {"msg_id": invalid, "metrics": [TARGET]})
            validate.assert_not_called()
            self.assertEqual(list(bot._processed_msg_ids), [])

            valid = "x" * 128
            for chat in (CHAT, CHAT, CHAT + 1):
                self.receive_mail("METRICS", {"msg_id": valid, "metrics": [TARGET]}, chat=chat)
            self.assertEqual(list(bot._processed_msg_ids), [(FP, valid), (SECOND_EMAIL, valid)])
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(len(database.get_peer_measurements_for_url(TARGET["url"])), 2)

    async def test_successful_rt_caps_clear_request_and_allow_rotation_at_14_days(self):
        inline_peer_metrics(self)
        self.advance(14 * 86400)
        self.link.state.on_frame()
        self.receive_mail("METRICS", {"msg_id": "caps-request", "caps": ["rt1"], "metrics": [],
                                      "request_caps": True})
        self.assertIn(FP, bot._peer_caps_requests)
        self.assertIsNotNone(bot._up_peer_rt_link(CHAT, FP))
        with patch.object(bot.dc_fingerprint, "get_self_fingerprint", return_value="AA" * 20), \
             patch.object(bot.dc_fingerprint, "get_contact_fingerprint", return_value=FP), \
             patch.object(bot, "build_peer_xdc", return_value="peer.xdc"):
            bot.audit_peer_rt_carriers(self.client, 1, self.now)
            self.client.rpc.send_msg.assert_not_called()
            caps = {"metrics": [], "caps": bot._own_peer_caps()}
            self.client.rpc.send_webxdc_realtime_data.side_effect = RuntimeError("send failed")
            self.assertIsNone(await bot._send_peer_rt_unacked(self.client, 1, MSG, self.link, "metrics", caps))
            self.assertIn(FP, bot._peer_caps_requests)

            self.client.rpc.send_webxdc_realtime_data.side_effect = None
            self.assertTrue(await bot._send_peer_rt_unacked(self.client, 1, MSG, self.link, "metrics", caps))
            self.assertNotIn(FP, bot._peer_caps_requests)
            bot.audit_peer_rt_carriers(self.client, 1, self.now)
        self.client.rpc.send_msg.assert_called_once()
        self.assertTrue(self.client.rpc.send_msg.call_args.args[2].text.startswith("[UPTIME_PEER_RT_OFFER]"))
        rotated = database.get_peer_by_fingerprint(FP)
        self.assertEqual(rotated["rt_msg_id"], MSG)
        self.assertIsNotNone(rotated["rt_offer_msg_id"])

    async def test_monitorless_down_peer_sends_hourly_mail_and_stays_online(self):
        inline_peer_metrics(self)
        self.assertFalse(self.link.state.is_up)
        database.set_local_node_name("Peer")
        with patch.object(self.outbox, "submit", wraps=self.outbox.submit) as submit:
            for elapsed in (0, 120, 3599, 3600, 4200):
                self.advance(100 + elapsed - self.mono)
                sent = self.client.rpc.send_msg.call_count
                await bot.broadcast_telemetry_to_peers()
                if self.client.rpc.send_msg.call_count > sent:
                    payload = self.client.rpc.send_msg.call_args.args[2].text
                    self.receive_mail("METRICS", json.loads(payload.splitlines()[1]))
                row = database.get_peer_by_fingerprint(FP)
                expected_seen = self.now - elapsed % bot.RT_MAIL_KEEPALIVE
                self.assertEqual(row["last_seen"], expected_seen)
                self.assertEqual(database.audit_peers_offline(
                    360, self.now, {EMAIL: bot.peer_offline_after(EMAIL), SECOND_EMAIL: 100_000}), [])
            self.assertEqual(submit.call_count, 2)
            self.assertEqual([call.kwargs["priority"] for call in submit.call_args_list], [bot.PRIO_TELEMETRY] * 2)
        for call in self.client.rpc.send_msg.call_args_list:
            self.assertEqual(call.args[:2], (1, CHAT))
            payload = json.loads(call.args[2].text.splitlines()[1])
            self.assertEqual(payload["metrics"], [])
            self.assertEqual(payload["telemetry_interval"], bot.RT_MAIL_KEEPALIVE)
        self.client.rpc.send_webxdc_realtime_data.assert_not_called()

    async def test_telemetry_ingress_queues_and_drops_oldest_per_peer_in_order(self):
        inbox = bot._PeerMetricsInbox()
        self.enterContext(patch.object(bot, "_peer_metrics_inbox", inbox))
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(inbox.executor.shutdown)
        self.addCleanup(release.set)
        event_thread = threading.get_ident()
        applied = []
        def url(number):
            return f"https://target{number}.example.org"

        def validate(target, _type, **_):
            self.assertNotEqual(threading.get_ident(), event_thread)
            if target == url(0):
                entered.set()
                release.wait(5)
            return True

        def save(node, metrics, identity):
            applied.append((identity, metrics[0]["url"]))

        def body(number, timestamp):
            return {"msg_id": str(number), "timestamp": timestamp, "caps": ["rt1"],
                    "metrics": [dict(TARGET, url=url(number))]}

        with patch.object(bot, "is_safe_target_url", side_effect=validate), \
             patch.object(database, "save_peer_measurements_batch", side_effect=save):
            self.receive_mail("METRICS", body(0, 100))
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            try:
                for number in range(1, 5):
                    self.receive_rt("metrics", body(number, 100 + number), ack=0)
                self.receive_mail("METRICS", body(5, 50))  # stale when the earlier queued telemetry applies
                self.receive_mail("METRICS", body(6, 90), chat=CHAT + 1)
                await self.until(lambda: len(applied) == 1)
                self.assertEqual(applied, [(SECOND_EMAIL, url(6))])
            finally:
                release.set()
            await self.until(lambda: inbox.workers == 0)
        self.assertEqual(applied, [(SECOND_EMAIL, url(6)), *[(FP, url(i)) for i in (0, 2, 3, 4)]])
        self.assertEqual(bot._peer_metrics_timestamps[FP], 104)
        self.assertEqual(inbox.bytes, 0)

    async def test_dns_waits_share_ten_second_batch_deadline(self):
        queried = []

        def submit(_executor, _slots, _lookup, host, _port):
            def result(*, timeout):
                queried.append((host, timeout))
                if host == "slow1.example.org":
                    self.advance(4)
                    return [(None, None, None, None, ("8.8.8.8", 0))]
                self.advance(timeout)
                raise TimeoutError

            return Mock(result=result)

        metrics = [dict(TARGET, url=f"https://slow{i}.example.org") for i in range(1, 5)]
        with patch.object(bot, "_submit_bounded", side_effect=submit), patch.object(bot, "_dns_cache", {}):
            bot._apply_peer_metrics(self.peer, {"msg_id": "deadline", "metrics": metrics}, "mail")
        self.assertEqual(queried, [("slow1.example.org", 5), ("slow2.example.org", 5), ("slow3.example.org", 1)])
        self.assertEqual([row["url"] for row in database.get_active_probe_targets()], [metrics[0]["url"]])
