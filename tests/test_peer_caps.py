import asyncio
from collections import OrderedDict
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox


class Clock:
    now = 1_800_000_000

    def time(self):
        return self.now

    def monotonic(self):
        return self.now - 1_800_000_000


class PeerNode:
    def __init__(self, directory, name, fp, chat, clock):
        self.path = Path(directory) / name
        self.path.mkdir()
        self.name, self.fp, self.chat = name, fp, chat
        self.email = f"{name.lower()}@example.org"
        self.clock = clock
        self.client = MagicMock()
        self.rpc = self.client.rpc
        self.rpc.create_chat_by_contact_id.return_value = chat
        self.rpc.get_basic_chat_info.return_value = {"chat_type": "Single", "is_encrypted": True}
        self.rpc.get_chat_securejoin_qr_code.return_value = f"https://i.delta.chat/#{fp}&a=local"
        self.rpc.get_chat_contacts.return_value = [21]
        self.rpc.send_msg.side_effect = lambda *_: self.rpc.send_msg.call_count + 500
        self.rpc.get_message_ids.return_value = []
        self.state = dict(
            time=clock, dc_bot_instance=self.client, dc_accid=1, async_event_loop=None,
            dc_outbox=Outbox(clock=clock.monotonic), _peer_caps={}, _peer_caps_announcements={}, _peer_caps_requests=set(),
            _peer_rt_audit_requested=threading.Event(), _last_peer_rt_audit=None, _peer_telemetry_interval={},
            _peer_desired_interval={}, _peer_versions={}, _scheduler_cache={},
            _processed_msg_ids=bot._ProcessedMessageIds(), _peer_metrics_timestamps=OrderedDict(), stat_event=MagicMock(),
        )
        self.mail_kinds = MagicMock()
        self.peer_traffic = MagicMock()
        with self.active():
            database.init_db()
            database.set_local_node_name(name)
            database.set_peer_rt_flag("on")
            database.set_peer_share_scope("none")

    @contextmanager
    def active(self):
        with patch.multiple(bot, **self.state), patch.multiple(
                database, DB_PATH=str(self.path / "test.db"), time=self.clock,
                record_mail_kind=self.mail_kinds, record_peer_traffic=self.peer_traffic):
            try:
                yield
            finally:
                self.state["_last_peer_rt_audit"] = bot._last_peer_rt_audit
                database.close_db()

    def connect(self, other):
        self.rpc.get_contact.side_effect = lambda _, contact: SimpleNamespace(
            address=self.email if contact == 1 else other.email)
        self.rpc.get_contact_encryption_info.return_value = f"Self:\n{self.fp}\n\nPeer:\n{other.fp}"

    def receive(self, text, *, encrypted=True, kind="Text", msg_id=400):
        message = SimpleNamespace(id=msg_id, from_id=21, chat_id=self.chat, text=text, is_info=False,
                                  show_padlock=encrypted, view_type=kind, file_bytes=500, timestamp=self.clock.now)
        bot.on_new_message(self.client, 1, SimpleNamespace(msg=message))

    def command(self, handler, payload):
        with patch.object(bot, "_is_dc_admin", return_value=True):
            handler(self.client, 1, SimpleNamespace(payload=payload, msg=SimpleNamespace(chat_id=42, from_id=51)))

    def sent(self, kind):
        marker = f"[UPTIME_PEER_{kind}]"
        return [(c.args[1], c.args[2].text) for c in self.rpc.send_msg.call_args_list if c.args[2].text.startswith(marker)]


class TestPeerCapabilities(unittest.TestCase):
    def setUp(self):
        database.close_db()
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.clock = Clock()
        self.left = PeerNode(directory, "Left", "AA" * 20, 123, self.clock)
        self.right = PeerNode(directory, "Right", "BB" * 20, 456, self.clock)
        self.left.connect(self.right)
        self.right.connect(self.left)

    def register_right(self):
        database.add_or_update_peer(self.right.email, self.right.name, self.left.chat, fingerprint=self.right.fp)

    def tick(self):
        asyncio.run(bot._broadcast_peer_updates())

    def test_idle_nodes_learn_caps_from_hello_and_ack_and_offer_on_next_tick(self):
        with self.right.active():
            token = database.create_peer_invite_token()
        with self.left.active():
            self.left.command(bot.addpeer_command, f"{self.right.email} token={token} {self.right.name}")
            (_, hello), = self.left.sent("HELLO")
            self.assertEqual(json.loads(hello.splitlines()[1])["caps"], bot._own_peer_caps())
        with self.right.active():
            self.right.receive(hello)
            self.assertIn("rt1", bot._peer_caps[self.left.email])
            self.assertEqual(database.get_peer(self.left.email)["fingerprint"], self.left.fp)
            (_, ack), = self.right.sent("HELLO_ACK")
            self.assertEqual(json.loads(ack.splitlines()[1])["caps"], bot._own_peer_caps())
        with self.left.active():
            self.left.receive(ack)
            self.assertIn("rt1", bot._peer_caps[self.right.email])
            self.assertEqual(database.get_all_resources(), [])
            self.assertEqual(database.get_active_probe_targets(), [])
            self.assertEqual(self.left.sent("RT_OFFER"), [])
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            (_, offer), = self.left.sent("RT_OFFER")
            self.assertFalse(bot._peer_rt_audit_requested.is_set())
        with self.right.active():
            self.right.receive(offer, kind="Webxdc")
            self.assertEqual(len(self.right.sent("RT_ACCEPT")), 1)

    def test_unknown_old_peer_gets_rate_limited_caps_only_and_no_offer(self):
        with self.left.active():
            self.register_right()
            old_ack = {"node_name": self.right.name, "version": "2.43.0"}
            self.left.receive(f"[UPTIME_PEER_HELLO_ACK]\n{json.dumps(old_ack)}\n[/UPTIME_PEER_HELLO_ACK]")
            self.assertNotIn(self.right.email, bot._peer_caps)
            self.tick()
            (_, first), = self.left.sent("METRICS")
            payload = json.loads(first.splitlines()[1])
            self.assertEqual(payload, {
                "node_name": self.left.name, "sender_email": self.left.email, "timestamp": self.clock.now,
                "msg_id": payload["msg_id"], "caps": bot._own_peer_caps(), "telemetry_interval": 300,
                "desired_interval": 120, "version": bot.VERSION, "metrics": [], "request_caps": True,
            })
            self.clock.now += 599
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 1)
            self.clock.now += 1
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 2)
            self.assertEqual([c.args for c in self.left.mail_kinds.call_args_list], [("peer_metrics",)] * 2)
            reasons = [c.args for c in self.left.peer_traffic.call_args_list if c.args[0].startswith("peer_metrics_")]
            self.assertEqual(reasons, [("peer_metrics_change", "mail", "out", 0),
                                       ("peer_metrics_idle", "mail", "out", 0)])
            bot.audit_peer_rt_carriers(self.left.client, 1, self.clock.now)
            self.assertEqual(self.left.sent("RT_OFFER"), [])

    def test_recent_carrier_deletion_reenable_and_mixed_mesh(self):
        started_at = self.clock.now
        with self.left.active():
            self.register_right()
            bot._note_peer_announcement(database.get_peer(self.right.email), {"caps": ["rt1"]})
            self.tick()
            (_, first_offer), = self.left.sent("RT_OFFER")
            self.left.rpc.get_message_ids.return_value = [database.get_peer(self.right.email)["rt_offer_msg_id"]]
        with self.right.active():
            database.add_or_update_peer(self.left.email, self.left.name, self.right.chat, fingerprint=self.left.fp)
            bot._note_peer_announcement(database.get_peer(self.left.email), {"caps": ["rt1"]})
            self.right.receive(first_offer, kind="Webxdc")
            self.right.rpc.get_message_ids.return_value = [400]
            (_, accept), = self.right.sent("RT_ACCEPT")
            self.tick()
        with self.left.active():
            self.left.receive(accept)
            first = database.get_peer(self.right.email)

        # Restart both nodes, then delete the carrier while startup announcements are still on cooldown.
        for node in (self.left, self.right):
            node.state.update(_peer_caps={}, _peer_caps_announcements={}, _last_peer_rt_audit=None)
        self.clock.now += 115
        with self.right.active():
            self.assertEqual(bot._peer_caps, {})
            self.tick()
            self.assertEqual(len(self.right.sent("METRICS")), 1)
            self.right.rpc.get_message_ids.return_value = []
            bot.on_peer_rt_carrier_deleted(self.right.client, 1, {"msgId": 400})
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            (_, reset), = self.right.sent("RT_RESET")
        with self.left.active():
            self.assertEqual(bot._peer_caps, {})
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 1)
            self.left.receive(reset)
            self.assertTrue(bot._peer_rt_audit_requested.is_set())
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            (_, _), (_, second_offer) = self.left.sent("RT_OFFER")
            self.left.rpc.get_message_ids.return_value = [database.get_peer(self.right.email)["rt_offer_msg_id"]]
        with self.right.active():
            self.right.receive(second_offer, kind="Webxdc", msg_id=401)
            self.right.rpc.get_message_ids.return_value = [401]
            (_, _), (_, accept) = self.right.sent("RT_ACCEPT")
            recipient = database.get_peer(self.left.email)
        with self.left.active():
            self.left.receive(accept)
            replacement = database.get_peer(self.right.email)
            self.assertLess(self.clock.now - started_at - 115, 180)
            self.assertNotEqual(replacement["rt_cid"], first["rt_cid"])
            self.assertEqual(replacement["rt_cid"], recipient["rt_cid"])
            for direction, opposite in (("out", "in"), ("in", "out")):
                key = f"rt_key_{direction}"
                self.assertNotEqual(replacement[key], first[key])
                self.assertEqual(replacement[key], recipient[f"rt_key_{opposite}"])
            self.assertEqual(len(self.left.sent("RT_OFFER")), 2)
            self.assertEqual(len(self.right.sent("RT_ACCEPT")), 2)
            self.assertEqual(len(self.right.sent("RT_RESET")), 1)

            self.left.command(bot.peerrt_command, "off")
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            _, disabled = self.left.sent("METRICS")[-1]
            self.assertIsNone(database.get_peer(self.right.email)["rt_cid"])
        with self.right.active():
            self.right.receive(disabled)
            self.assertIsNone(database.get_peer(self.left.email)["rt_cid"])
            self.assertFalse(database.get_peer(self.left.email)["rt_capable"])

        self.clock.now += 65
        with self.left.active():
            self.tick()
            self.assertEqual(len(self.left.sent("RT_OFFER")), 2)
            self.left.command(bot.peerrt_command, "on")
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            _, enabled = self.left.sent("METRICS")[-1]
            self.assertEqual(len(self.left.sent("RT_OFFER")), 3)
            _, third_offer = self.left.sent("RT_OFFER")[-1]
            self.left.rpc.get_message_ids.return_value = [database.get_peer(self.right.email)["rt_offer_msg_id"]]
        with self.right.active():
            self.right.receive(enabled)
            self.right.receive(third_offer, kind="Webxdc", msg_id=402)
            self.assertEqual(len(self.right.sent("RT_ACCEPT")), 3)
            _, accept = self.right.sent("RT_ACCEPT")[-1]
            self.right.rpc.get_message_ids.return_value = [402]
        with self.left.active():
            self.left.receive(accept)
            old_chat = 789
            database.add_or_update_peer("old@example.org", "Old", old_chat, fingerprint="CC" * 20)
            bot._note_peer_caps("old@example.org", ["batch_check"])
            self.clock.now += bot.PEER_RT_AUDIT_INTERVAL
            self.tick()
            self.assertIn(old_chat, [chat for chat, _ in self.left.sent("METRICS")])
            self.assertEqual([chat for chat, _ in self.left.sent("RT_OFFER")], [self.left.chat] * 3)
            self.assertFalse(database.get_peer(self.right.email)["rt_lost"])
            self.assertEqual(len(self.right.sent("RT_RESET")), 1)

    def test_empty_metrics_refresh_activity_without_touching_peer_target_data(self):
        url = "https://monitored.example.org"
        with self.left.active():
            self.register_right()
            peer = database.get_peer(self.right.email)
            data = {"metrics": [{"url": url, "type": "http", "status": "up"}], "timestamp": self.clock.now}
            with patch.object(bot, "is_safe_target_url", return_value=True):
                bot.handle_peer_metrics(self.left.client, 1, peer, self.left.chat, data)
            measurements = database.get_peer_measurements_for_url(url)
            targets = database.get_active_probe_targets()
            self.assertEqual(len(measurements), 1)
            self.assertEqual(len(targets), 1)
            self.clock.now += 10
            with patch.object(bot, "note_peer_reported_down") as report:
                bot.handle_peer_metrics(self.left.client, 1, peer, self.left.chat,
                                        dict(data, timestamp=self.clock.now, caps=["rt1"], metrics=[]))
            self.assertEqual(database.get_peer_measurements_for_url(url), measurements)
            self.assertEqual(database.get_active_probe_targets(), targets)
            self.assertEqual(database.get_peer(self.right.email)["last_seen"], self.clock.now)
            self.assertEqual(database.get_peer(self.right.email)["is_offline"], 0)
            report.assert_not_called()

    def test_peerrt_capability_change_announces_once_per_peer(self):
        with self.left.active():
            database.set_peer_rt_flag("off")
            self.register_right()
            database.add_or_update_peer("old@example.org", "Old", 789)
            bot._note_peer_caps(self.right.email, ["batch_check"])
            bot._note_peer_caps("old@example.org", [])
            self.tick()
            self.assertCountEqual([chat for chat, _ in self.left.sent("METRICS")], [123, 789])
            self.left.rpc.send_msg.reset_mock()
            self.left.command(bot.peerrt_command, "on")
            self.clock.now += bot.TELEMETRY_TICK
            self.tick()
            self.left.command(bot.peerrt_command, "on")
            self.clock.now += 600
            self.tick()
            sent = self.left.sent("METRICS")
            self.assertCountEqual([chat for chat, _ in sent], [123, 789])
            self.assertTrue(all("rt1" in json.loads(text.splitlines()[1])["caps"] for _, text in sent))

    def test_idle_pair_enabling_preview_after_startup_offers_on_next_tick(self):
        started_at = self.clock.now
        with self.right.active():
            database.set_peer_rt_flag("off")
            token = database.create_peer_invite_token()
        with self.left.active():
            database.set_peer_rt_flag("off")
            self.left.command(bot.addpeer_command, f"{self.right.email} token={token} {self.right.name}")
            (_, hello), = self.left.sent("HELLO")
        with self.right.active():
            self.right.receive(hello)
            (_, ack), = self.right.sent("HELLO_ACK")
            self.tick()
            self.assertEqual(database.get_peer(self.left.email)["caps_announce_attempt_at"], started_at)
            (_, startup_right), = self.right.sent("METRICS")
        with self.left.active():
            self.left.receive(ack)
            self.left.receive(startup_right)
            self.tick()
            self.assertEqual(database.get_peer(self.right.email)["caps_announce_attempt_at"], started_at)
            (_, startup_left), = self.left.sent("METRICS")
        with self.right.active():
            self.right.receive(startup_left)
            self.assertNotIn("rt1", bot._peer_caps[self.left.email])
            self.clock.now = started_at + 6
            self.right.command(bot.peerrt_command, "canary")
            self.right.command(bot.peerrt_command, f"{self.left.name} on")
        with self.left.active():
            self.assertNotIn("rt1", bot._peer_caps[self.right.email])
            self.left.command(bot.peerrt_command, "on")

        self.clock.now = started_at + 2 * bot.TELEMETRY_TICK
        with self.right.active():
            self.tick()
            _, announce_right = self.right.sent("METRICS")[1]
            self.assertEqual(json.loads(announce_right.splitlines()[1])["metrics"], [])
            self.assertEqual(self.right.sent("RT_OFFER"), [])
        with self.left.active():
            bot._peer_rt_audit_requested.clear()  # Isolate the wakeup from the incoming announcement.
            self.left.receive(announce_right)
            self.assertIn("rt1", bot._peer_caps[self.right.email])
            self.assertTrue(bot._peer_rt_audit_requested.is_set())
            bot.audit_peer_rt_carriers(self.left.client, 1, self.clock.now)
            self.assertEqual(self.left.sent("RT_OFFER"), [])
            self.assertIsNone(database.get_peer(self.right.email)["rt_offer_at"])
            self.tick()
            _, announce_left = self.left.sent("METRICS")[1]
            (_, offer), = self.left.sent("RT_OFFER")
            self.assertEqual(self.left.rpc.send_msg.call_args_list[-2].args[2].text, announce_left)
            self.assertEqual(self.left.rpc.send_msg.call_args_list[-1].args[2].text, offer)
            self.assertEqual(database.get_peer(self.right.email)["rt_offer_at"], self.clock.now)
        with self.right.active():
            self.right.receive(announce_left)
            self.assertIn("rt1", bot._peer_caps[self.left.email])
            self.right.receive(offer, kind="Webxdc")
            self.assertEqual(len(self.right.sent("RT_ACCEPT")), 1)

    def test_caps_changes_use_persisted_rolling_budget(self):
        started_at = self.clock.now
        with self.left.active():
            database.set_peer_rt_flag("off")
            self.register_right()
            bot._note_peer_caps(self.right.email, ["batch_check"])
            self.tick()
            for elapsed, flag in ((5, "on"), (10, "off"), (20, "on")):
                self.clock.now = started_at + elapsed
                self.left.command(bot.peerrt_command, flag)
                self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 4)
        self.left.state["_peer_caps_announcements"] = {}
        with self.left.active():
            self.clock.now = started_at + 25
            self.left.command(bot.peerrt_command, "off")
            self.tick()
            self.clock.now = started_at + 604
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 4)
            self.clock.now = started_at + 605
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 5)
            self.assertNotIn("rt1", json.loads(self.left.sent("METRICS")[-1][1].splitlines()[1])["caps"])
            self.clock.now = started_at + 606
            self.left.command(bot.peerrt_command, "on")
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 5)

    def test_minute_boundary_does_not_delay_next_telemetry_tick(self):
        self.clock.now += 56
        started_at = self.clock.now
        ticks = []
        sleep = asyncio.sleep

        async def advance(delay):
            await sleep(0)
            if len(ticks) == 2 or self.clock.now >= started_at + bot.TELEMETRY_TICK + 5:
                raise asyncio.CancelledError
            self.clock.now += delay

        async def broadcast():
            ticks.append(self.clock.now)

        with self.left.active(), patch.multiple(
                bot, dc_bot_instance=None, last_peer_telemetry_broadcast=0, _host_outage_active=False,
                _scheduler_cache={"resources": [], "resources_ts": started_at, "probe_targets": [],
                                  "probe_targets_ts": started_at, "ttl": 10}, pop_recovered_nodes=lambda: [],
                _broadcast_peer_updates=broadcast, _check_report_notices=AsyncMock(),
                push_status_apps=AsyncMock(), realtime_status_tick=AsyncMock(), audit_abandoned_chats=AsyncMock()), \
                patch.object(bot.secrets, "randbelow", return_value=0), \
                patch.object(bot.asyncio, "sleep", side_effect=advance), self.assertRaises(asyncio.CancelledError):
            asyncio.run(bot.monitoring_scheduler_loop())
        self.assertEqual(ticks, [started_at, started_at + bot.TELEMETRY_TICK])

    def test_caps_announcement_cooldown_survives_restart_and_key_binding(self):
        with self.left.active():
            database.add_or_update_peer(self.right.email, self.right.name, self.left.chat)
            self.tick()
            database.bind_peer_identity(self.right.email, fingerprint=self.right.fp)
        self.left.state["_peer_caps_announcements"] = {}
        self.left.rpc.send_msg.reset_mock()
        with self.left.active():
            bot._note_peer_caps(self.right.email, ["batch_check"])
            self.clock.now += 599
            self.tick()
            self.assertEqual(self.left.sent("METRICS"), [])
            self.clock.now += 1
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 1)

    def test_idle_peer_answers_a_capability_request_after_the_other_node_restarts(self):
        with self.left.active():
            self.register_right()
            bot._note_peer_caps(self.right.email, ["batch_check"])
            self.tick()
        with self.right.active():
            database.add_or_update_peer(self.left.email, self.left.name, self.right.chat, fingerprint=self.left.fp)
            self.clock.now += 599
            self.tick()
            (_, request), = self.right.sent("METRICS")
        with self.left.active():
            self.left.receive(request)
            self.tick()
            self.assertEqual(len(self.left.sent("METRICS")), 1)
            self.assertEqual(self.left.sent("RT_OFFER"), [])
            self.clock.now += 1
            self.tick()
            _, reply = self.left.sent("METRICS")[-1]
            self.assertNotIn("request_caps", json.loads(reply.splitlines()[1]))
            (_, offer), = self.left.sent("RT_OFFER")
            self.assertEqual(self.left.rpc.send_msg.call_args_list[-2].args[2].text, reply)
            self.assertEqual(self.left.rpc.send_msg.call_args_list[-1].args[2].text, offer)
        with self.right.active():
            self.right.receive(reply)
            self.assertIn("rt1", bot._peer_caps[self.left.email])
            self.right.receive(offer, kind="Webxdc")
            self.assertEqual(len(self.right.sent("RT_ACCEPT")), 1)

    def test_unencrypted_handshake_cannot_announce_rt_capability(self):
        with self.left.active():
            database.add_or_update_peer(self.right.email, self.right.name, self.left.chat)
            for kind in ("HELLO", "HELLO_ACK"):
                data = json.dumps({"node_name": self.right.name, "caps": ["rt1"]})
                self.left.receive(f"[UPTIME_PEER_{kind}]\n{data}\n[/UPTIME_PEER_{kind}]", encrypted=False)
            self.assertNotIn(self.right.email, bot._peer_caps)
            self.assertFalse(bot._peer_rt_audit_requested.is_set())
