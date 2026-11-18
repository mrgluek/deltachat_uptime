import asyncio
from collections import OrderedDict
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

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
            _peer_rt_audit_requested=threading.Event(), _peer_telemetry_interval={},
            _peer_desired_interval={}, _peer_versions={}, _scheduler_cache={},
            _processed_msg_ids=bot._ProcessedMessageIds(), _peer_metrics_timestamps=OrderedDict(), stat_event=MagicMock(),
        )
        self.mail_kinds = MagicMock()
        with self.active():
            database.init_db()
            database.set_local_node_name(name)
            database.set_peer_rt_flag("on")
            database.set_peer_share_scope("none")

    @contextmanager
    def active(self):
        with patch.multiple(bot, **self.state), patch.multiple(
                database, DB_PATH=str(self.path / "test.db"), time=self.clock,
                record_mail_kind=self.mail_kinds, record_peer_traffic=MagicMock()):
            try:
                yield
            finally:
                database.close_db()

    def connect(self, other):
        self.rpc.get_contact.side_effect = lambda _, contact: SimpleNamespace(
            address=self.email if contact == 1 else other.email)
        self.rpc.get_contact_encryption_info.return_value = f"Self:\n{self.fp}\n\nPeer:\n{other.fp}"

    def receive(self, text, *, encrypted=True, kind="Text"):
        message = SimpleNamespace(id=400, from_id=21, chat_id=self.chat, text=text, is_info=False,
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
            bot.audit_peer_rt_carriers(self.left.client, 1, self.clock.now)
            self.assertEqual(self.left.sent("RT_OFFER"), [])

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

    def test_peerrt_capability_change_announces_once_per_peer_after_cooldown(self):
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
            self.clock.now += 599
            self.tick()
            self.assertEqual(self.left.sent("METRICS"), [])
            self.clock.now += 1
            self.tick()
            self.left.command(bot.peerrt_command, "on")
            self.clock.now += 600
            self.tick()
            sent = self.left.sent("METRICS")
            self.assertCountEqual([chat for chat, _ in sent], [123, 789])
            self.assertTrue(all("rt1" in json.loads(text.splitlines()[1])["caps"] for _, text in sent))

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
