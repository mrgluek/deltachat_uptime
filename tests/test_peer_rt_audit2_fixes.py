import asyncio
from concurrent.futures import Future
import json
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import bot
import database
from test_peer_caps import Clock, PeerNode
from test_peer_metrics import message
from test_peer_seam import inline_peer_metrics
from test_peer_rt_carrier import CID, KEY, envelope


class TestPeerRTAuditFixes(unittest.TestCase):
    def setUp(self):
        inline_peer_metrics(self)
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.clock = Clock()
        self.owner = PeerNode(directory, "Owner", "AA" * 20, 123, self.clock)
        self.recipient = PeerNode(directory, "Recipient", "BB" * 20, 456, self.clock)
        for local, remote in self.pairs():
            local.connect(remote)
            with local.active():
                database.add_or_update_peer(remote.email, remote.name, local.chat, fingerprint=remote.fp)

    def pairs(self):
        return ((self.owner, self.recipient), (self.recipient, self.owner))

    def row(self):
        return database.get_peer_by_fingerprint(self.recipient.fp)

    def receive(self, node, kind, payload, **fields):
        node.receive(message(kind, json.dumps(payload)), **fields)

    def tick(self, node):
        bot._update_peer_caps_and_carriers(node.client, 1)

    def store_carrier(self):
        self.receive(self.owner, "HELLO_ACK", {"caps": bot._own_peer_caps()})
        database.set_peer_rt(self.recipient.fp, cid=CID, msg_id=500, key_in=KEY,
                             key_out=KEY, created_at=self.clock.now)
        bot._refresh_peer_rt_channels()

    def test_only_expected_fresh_check_responses_can_downgrade(self):
        with self.owner.active():
            for kind in ("CHECK_RESP", "CHECK_BATCH_RESP"):
                with self.subTest(kind=kind), patch.multiple(bot, pending_peer_checks={}, pending_batch_checks={}):
                    self.store_carrier()
                    response = {"req_id": "request", "caps": bot.OWN_PEER_CAPS}
                    self.receive(self.owner, kind, response)
                    self.assertEqual(self.row()["rt_cid"], CID)

                    def expect(chat, done=False):
                        future = Future()
                        if done:
                            future.set_result([])
                        if kind == "CHECK_RESP":
                            bot.pending_peer_checks["request"] = (future, 1, [], {chat})
                        else:
                            bot.pending_batch_checks["request"] = (future, chat, 1)
                        return future

                    future = expect(self.owner.chat + 1)
                    self.receive(self.owner, kind, response)
                    self.assertFalse(future.done())
                    self.assertEqual(self.row()["rt_cid"], CID)
                    expect(self.owner.chat, done=True)
                    self.receive(self.owner, kind, response)
                    self.assertEqual(self.row()["rt_cid"], CID)
                    future = expect(self.owner.chat)
                    self.receive(self.owner, kind, response, timestamp=self.clock.now - 601)
                    self.assertTrue(future.done())
                    self.assertEqual(self.row()["rt_cid"], CID)
                    expect(self.owner.chat)
                    self.receive(self.owner, kind, {"req_id": "request"})
                    self.assertEqual(self.row()["rt_cid"], CID)
                    expect(self.owner.chat)
                    self.receive(self.owner, kind, response)
                    self.assertIsNone(self.row()["rt_cid"])
                    self.assertFalse(self.row()["rt_capable"])
                    self.clock.now += 1

    def test_old_handshakes_and_empty_metrics_preserve_carrier_across_restart(self):
        with self.owner.active():
            self.store_carrier()
            current_id = self.owner.next_incoming_id
        # The restart loses the in-memory caches. The peer row retains the last announcement.
        self.owner.state["_peer_caps"] = {}
        self.owner.state["_processed_msg_ids"] = bot._ProcessedMessageIds()
        with self.owner.active():
            for kind in ("HELLO", "HELLO_ACK"):
                with self.subTest(kind=kind):
                    self.receive(self.owner, kind, {"caps": []}, msg_id=current_id, timestamp=None)
                    self.receive(self.owner, kind, {"caps": []}, timestamp=self.clock.now - 601)
                    self.assertEqual(self.row()["rt_cid"], CID)
            for index, caps in enumerate(({}, {"caps": []})):
                self.receive(self.owner, "METRICS", dict(caps, msg_id=f"old-{index}", metrics=[],
                                                        timestamp=self.clock.now - 601))
                self.assertEqual(self.row()["rt_cid"], CID)
            self.receive(self.owner, "HELLO_ACK", {"caps": []}, timestamp=None)
            self.assertIsNone(self.row()["rt_cid"])

    def test_canary_waits_for_both_peers_and_for_successful_announcement(self):
        for local, _ in self.pairs():
            with local.active():
                database.set_peer_rt_flag("canary")
                self.tick(local)
                metrics, = local.sent("METRICS")
                self.assertEqual(json.loads(metrics[1].splitlines()[1])["caps"], bot.OWN_PEER_CAPS)
        with self.owner.active():
            self.owner.receive(self.recipient.sent("METRICS")[0][1])
            self.owner.command(bot.peerrt_command, "Recipient on")
            self.clock.now += 30
            self.tick(self.owner)
            _, owner_caps = self.owner.sent("METRICS")[-1]
            self.assertEqual(self.owner.sent("RT_OFFER"), [])

        with self.recipient.active():
            self.recipient.receive(owner_caps)
            self.recipient.command(bot.peerrt_command, "Owner on")
            self.clock.now += 30
            self.tick(self.recipient)
            _, recipient_caps = self.recipient.sent("METRICS")[-1]

        with self.owner.active():
            self.owner.receive(recipient_caps)
            with patch.dict(bot._peer_caps_announcements, {self.recipient.fp: None}):
                bot.audit_peer_rt_carriers(self.owner.client, 1, self.clock.now)
                self.assertIsNone(self.row()["rt_offer_at"])
            bot.audit_peer_rt_carriers(self.owner.client, 1, self.clock.now)
            _, offer = self.owner.sent("RT_OFFER")[-1]
        with self.recipient.active():
            self.recipient.receive(offer, kind="Webxdc")
            self.assertEqual(len(self.recipient.sent("RT_ACCEPT")), 1)

    def test_queued_check_advertises_current_canary_eligibility(self):
        with self.owner.active():
            database.set_peer_rt_flag("canary")
            database.set_peer_rt_mode(self.recipient.email, "on")
            destination = bot._PeerDestination(self.owner.client, 1, self.owner.chat)
            payload = {"req_id": "check", "caps": bot._own_peer_caps(self.row()), "family": 6}
            with patch.object(bot.dc_outbox, "submit", return_value=Future()) as submit:
                bot.peer_send(destination, "CHECK_REQ", payload, priority=bot.PRIO_PEER,
                              expires_in=8, label="cross-check")
            database.set_peer_rt_mode(self.recipient.email, "off")
            submit.call_args.args[0]()
            _, sent = self.owner.sent("CHECK_REQ")[0]
            self.assertEqual(sent, message("CHECK_REQ", json.dumps(dict(payload, caps=bot.OWN_PEER_CAPS))))

    def test_unaccepted_offer_retries_and_reenable_preserves_hourly_budget(self):
        with self.owner.active():
            self.receive(self.owner, "HELLO_ACK", {"caps": bot._own_peer_caps()})
            self.tick(self.owner)
            first = self.row()
            self.assertIsNotNone(first["rt_offer_msg_id"])
            self.owner.rpc.get_message_ids.return_value = [first["rt_offer_msg_id"]]
            self.clock.now += bot.PEER_RT_OFFER_RETRY - 1
            bot.audit_peer_rt_carriers(self.owner.client, 1, self.clock.now)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 1)
            self.clock.now += 1
            bot.audit_peer_rt_carriers(self.owner.client, 1, self.clock.now)
            second = self.row()
            self.assertNotEqual(second["rt_offer_msg_id"], first["rt_offer_msg_id"])

            self.owner.command(bot.peerrt_command, "Recipient off")
            self.owner.command(bot.peerrt_command, "Recipient on")
            self.clock.now += 30
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 3)
            third = self.row()
            self.assertNotEqual(third["rt_offer_cid"], second["rt_offer_cid"])
            self.owner.receive(envelope("ACCEPT", cid=second["rt_offer_cid"]))
            self.assertIsNone(self.row()["rt_cid"])
            self.owner.receive(envelope("ACCEPT", cid=third["rt_offer_cid"]))
            self.assertEqual(self.row()["rt_cid"], third["rt_offer_cid"])
            self.owner.rpc.get_message_ids.return_value = [third["rt_offer_msg_id"]]
            self.clock.now += bot.PEER_RT_OFFER_RETRY
            bot.audit_peer_rt_carriers(self.owner.client, 1, self.clock.now)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 3)
            self.owner.command(bot.peerrt_command, "Recipient off")
            self.owner.command(bot.peerrt_command, "Recipient on")
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 3)
            self.clock.now = first["rt_offer_at"] + 3600
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 4)

    def test_recipient_reenable_requests_replacement_without_off_announcement(self):
        with self.owner.active():
            self.receive(self.owner, "HELLO_ACK", {"caps": bot._own_peer_caps()})
            self.tick(self.owner)
            first = self.row()
            self.owner.rpc.get_message_ids.return_value = [first["rt_offer_msg_id"]]
            _, caps = self.owner.sent("METRICS")[0]
            _, offer = self.owner.sent("RT_OFFER")[0]
        with self.recipient.active():
            self.recipient.receive(caps)
            self.recipient.receive(offer, kind="Webxdc")
            self.recipient.rpc.get_message_ids.return_value = [self.recipient.next_incoming_id]
            _, accept = self.recipient.sent("RT_ACCEPT")[0]
            self.tick(self.recipient)
        with self.owner.active():
            self.owner.receive(accept)
            self.assertEqual(self.row()["rt_cid"], first["rt_offer_cid"])
        with self.recipient.active():
            sent = len(self.recipient.sent("METRICS"))
            self.recipient.command(bot.peerrt_command, "off")
            self.clock.now += 30
            self.tick(self.recipient)
            self.assertEqual(len(self.recipient.sent("METRICS")), sent)
            self.recipient.command(bot.peerrt_command, "canary")
            self.recipient.command(bot.peerrt_command, "Owner on")
            self.clock.now += 30
            self.tick(self.recipient)
            _, caps = self.recipient.sent("METRICS")[-1]
            _, reset = self.recipient.sent("RT_RESET")[0]
        with self.owner.active():
            self.owner.receive(caps)
            self.owner.receive(reset)
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("RT_OFFER")), 2)

    def test_mail_fallback_switches_one_running_single_and_batch_probe(self):
        async def check(kind, handler, fields):
            started, finish = asyncio.Event(), asyncio.Event()

            async def probe(_):
                started.set()
                await finish.wait()
                return True, None, 12

            request = dict(fields, req_id=kind)
            with patch.object(bot, "run_single_check", side_effect=probe) as run, \
                 patch.object(bot, "peer_send", wraps=bot.peer_send) as send:
                args = (self.owner.client, 1, self.row(), self.owner.chat, request)
                self.assertIs(handler(*args, via="rt"), bot._ProbeAdmission.ACCEPTED)
                task, = asyncio.all_tasks() - {asyncio.current_task()}
                try:
                    await asyncio.wait_for(started.wait(), 2)
                    self.assertIs(handler(*args), bot._ProbeAdmission.RUNNING)
                    send.assert_not_called()
                finally:
                    finish.set()
                    await asyncio.wait_for(task, 2)
                run.assert_awaited_once()
                self.assertEqual(send.call_args.args[0].via, "mail")
                self.assertEqual(send.call_args.args[1], kind)
                self.assertEqual(len(self.owner.sent(kind)), 1)

        target = {"url": "https://target.example.org", "type": "http"}
        with self.owner.active(), patch.multiple(
                bot, _inbound_probes=bot.InboundProbeAdmission(), is_safe_target_url=lambda *a, **kw: True,
                _prewarm_target_dns=AsyncMock(return_value=True)):
            asyncio.run(check("CHECK_RESP", bot.handle_peer_check_req, target))
            asyncio.run(check("CHECK_BATCH_RESP", bot.handle_peer_check_batch_req, {"targets": [target]}))

    def test_realtime_heartbeat_updates_current_row_after_address_rotation(self):
        with self.owner.active():
            self.store_carrier()
            link = bot._peer_rt_links[500]
            link.advertise_at = None
            # A frame and a relay switch can arrive between channel refreshes.
            email = "new-relay@example.org"
            database.bind_peer_identity(self.recipient.email, new_email=email)
            database.add_or_update_peer(self.recipient.email, "Other Node", 789, fingerprint="CC" * 20)
            self.clock.now += 31
            link.state.on_frame(self.clock.monotonic())
            asyncio.run(bot._tick_peer_rt_link(self.owner.client, 1, 500, link))
            self.assertEqual(database.get_peer(email)["last_seen"], self.clock.now)
            self.assertNotEqual(database.get_peer(self.recipient.email)["last_seen"], self.clock.now)
            link.incoming_metrics_interval = 700
            database.rename_peer_node(email, "New Name")
            bot._refresh_peer_rt_channels()
            self.assertIs(bot._peer_rt_links[500], link)
            self.assertEqual((link.peer["email"], link.peer["node_name"]), (email, "New Name"))
            self.assertEqual(bot.peer_offline_after(email), 700 * bot.PEER_OFFLINE_INTERVALS)

    def test_caps_only_backoff_maximum_and_reset(self):
        with self.owner.active():
            self.tick(self.owner)
            for count, interval in enumerate((600, 1200, 2400, 4800, 9600, 19200, 21600, 21600), 1):
                self.clock.now += interval - 1
                self.tick(self.owner)
                self.assertEqual(len(self.owner.sent("METRICS")), count)
                self.clock.now += 1
                self.tick(self.owner)
                self.assertEqual(len(self.owner.sent("METRICS")), count + 1)

            self.owner.command(bot.peerrt_command, "canary")
            self.assertNotIn(self.recipient.fp, bot._peer_caps_backoff)
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("METRICS")), 10)
            self.receive(self.owner, "HELLO_ACK", {"caps": bot.OWN_PEER_CAPS})
            self.assertNotIn(self.recipient.fp, bot._peer_caps_backoff)
            self.clock.now += 21600
            self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("METRICS")), 10)

    def test_off_has_at_most_one_startup_caps_only_attempt(self):
        with self.owner.active():
            database.set_peer_rt_flag("off")
            self.tick(self.owner)
            for _ in range(3):
                self.clock.now += 21600
                self.receive(self.owner, "METRICS", {"msg_id": str(self.clock.now), "request_caps": True})
                self.tick(self.owner)
            self.assertEqual(len(self.owner.sent("METRICS")), 1)

    def test_metrics_ordering_bounds_future_time_in_mail_only_mesh(self):
        with self.owner.active(), patch.object(bot, "is_safe_target_url", return_value=True):
            database.set_peer_rt_flag("off")
            url = "https://target.example.org"
            payload = {"msg_id": "future", "timestamp": self.clock.now + 7200,
                       "metrics": [{"url": url, "status": "up", "type": "http"}]}
            self.receive(self.owner, "METRICS", payload)
            self.assertEqual(bot._peer_metrics_timestamps[self.recipient.fp], self.clock.now + 300)
            self.clock.now += 301
            payload.update(msg_id="corrected", timestamp=self.clock.now)
            payload["metrics"][0]["status"] = "down"
            self.receive(self.owner, "METRICS", payload)
            measurements = database.get_peer_measurements_for_url(url)
            self.assertEqual([row["status"] for row in measurements], ["down"])
