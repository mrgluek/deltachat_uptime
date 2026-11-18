import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox


class TestMetricsIdle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.object(database, "DB_PATH", str(Path(directory) / "uptime.db")))
        self.enterContext(patch.multiple(database, _mail_kind_buffer={}, _peer_traffic_buffer={}, _peer_rtt_buffer=[]))
        database.init_db()
        self.addCleanup(database.close_db)
        self.now = 1_000_000
        self.clock = self.enterContext(patch.object(bot.time, "time", side_effect=lambda: self.now))
        self.client = MagicMock()
        self.sent = []
        self.client.rpc.send_msg.side_effect = self.record
        self.peers = [{"email": "peer@example.org", "node_name": "Peer", "chat_id": 10}]
        self.resources = [
            {"url": "https://one.example.org", "status": "up", "last_latency_ms": 10},
            {"url": "https://two.example.org", "status": "up", "last_latency_ms": 20},
        ]
        self.probes = [{"url": "https://probe.example.org", "source_peer": "peer@example.org", "last_status": "up"}]
        self.box = Outbox(clock=self.clock, burst=100)
        self.enterContext(patch.multiple(
            bot, dc_bot_instance=self.client, dc_accid=1, dc_outbox=self.box,
            _telemetry_sent_at={}, _telemetry_last_sent={}, _telemetry_started_at={}, _telemetry_delivered_at={},
            _telemetry_queued_status={}, _telemetry_rotation_offsets={}, _peer_desired_interval={}, _local_degraded={},
            _peer_telemetry_interval={}, _processed_msg_ids=set(),
            _resolve_peer_chat_id=AsyncMock(side_effect=lambda peer: peer["chat_id"]),
            _filter_peer_shareable_resources=lambda *args: args[-1],
            _get_self_addr=lambda *args: "local@example.org",
        ))

    def record(self, accid, chat, message):
        self.sent.append((self.now, chat, json.loads(message.text.splitlines()[1])))
        return len(self.sent)

    async def tick(self, after=0):
        self.now += after
        with patch.multiple(database, get_all_peers=lambda: self.peers,
                            get_all_resources=lambda: self.resources,
                            get_active_probe_targets=lambda: self.probes):
            await bot.broadcast_telemetry_to_peers()

    def pop_job(self):
        with self.box._cond:
            return self.box._next_job()

    async def test_idle_and_latency_refresh_send_the_full_list(self):
        await self.tick()
        self.resources[0]["last_latency_ms"] = 250
        self.probes[0]["last_latency_ms"] = 310
        await self.tick(20)
        await self.tick(279)
        self.assertEqual(len(self.sent), 1)
        await self.tick(1)
        t0, _, first = self.sent[0]
        t1, _, second = self.sent[1]
        self.assertEqual(first["telemetry_interval"], t1 - t0)
        self.assertEqual(second["telemetry_interval"], 300)
        self.assertEqual(second["desired_interval"], 120)
        expected = {"https://one.example.org", "https://two.example.org", "https://probe.example.org"}
        for _, _, payload in self.sent:
            self.assertEqual({m["url"] for m in payload["metrics"]}, expected)
        self.assertEqual([m["latency_ms"] for m in second["metrics"]], [310, 250, 20])

    async def test_local_and_probe_status_changes_send_promptly_with_a_20_second_limit(self):
        bot._peer_desired_interval["peer@example.org"] = 120
        await self.tick()
        self.resources[0]["status"] = "down"
        await self.tick(19)
        self.assertEqual(len(self.sent), 1)
        await self.tick(1)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[-1][2]["metrics"][1]["status"], "down")
        self.probes[0]["last_status"] = "down"
        await self.tick(29)
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(self.sent[-1][2]["metrics"][0]["status"], "down")
        self.assertEqual(len(self.sent[-1][2]["metrics"]), 3)
        await self.tick(299)
        self.assertEqual(len(self.sent), 3)
        await self.tick(1)
        self.assertEqual(self.sent[-1][0] - self.sent[-2][0], self.sent[-2][2]["telemetry_interval"])

    async def test_queue_replaces_pending_metrics_on_a_revert(self):
        await self.tick()
        self.box._thread = object()
        self.resources[0]["status"] = "down"
        await self.tick(20)
        self.resources[0]["status"] = "up"
        await self.tick(5)
        self.assertEqual(self.box.waiting(), {"telemetry": 1})
        self.assertEqual(self.box.stats["merged"], 1)
        self.box._run(self.pop_job())
        self.assertEqual([m["status"] for m in self.sent[-1][2]["metrics"]], ["up", "up", "up"])

    async def test_delayed_rpc_cannot_send_two_messages_within_20_seconds(self):
        self.box._thread = object()
        await self.tick()
        sending = self.pop_job()
        self.resources[0]["status"] = "down"
        await self.tick(20)
        self.box._run(sending)
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 1)
        await self.tick(20)
        self.box._run(self.pop_job())
        self.assertEqual([payload["metrics"][1]["status"] for _, _, payload in self.sent], ["up", "down"])

    async def test_slower_peer_request_is_preserved(self):
        bot._peer_desired_interval["peer@example.org"] = 360
        await self.tick()
        self.assertEqual(self.sent[0][2]["telemetry_interval"], 360)
        self.probes[0]["last_status"] = "down"
        await self.tick(359)
        self.assertEqual(len(self.sent), 1)
        await self.tick(1)
        self.assertEqual(len(self.sent), 2)

    async def test_old_style_receiver_announcement_and_omitted_urls(self):
        peer = self.peers[0]
        email = peer["email"]
        database.add_or_update_peer(email, "Peer", 10)
        database.save_peer_measurement("https://omitted.example.org", "Peer", "up", source_peer=email)
        self.client.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        payload = {"node_name": "Peer", "telemetry_interval": 300, "metrics": [self.resources[0]]}
        msg = SimpleNamespace(from_id=42, chat_id=10, is_info=False,
                              text=f"[UPTIME_PEER_METRICS]\n{json.dumps(payload)}\n[/UPTIME_PEER_METRICS]")
        with patch.object(bot, "_get_verified_peer_for_msg", return_value=(peer, email)), \
             patch.object(bot, "_is_trusted_peer_msg", return_value=True):
            bot.on_new_message(self.client, 1, SimpleNamespace(msg=msg))

        self.assertEqual(len(database.get_all_peer_measurements()), 2)
        self.assertEqual(bot.peer_offline_after("unannounced@example.org"), 360)
        self.assertEqual(bot.peer_offline_after(email), 900)
        thresholds = {email: bot.peer_offline_after(email)}
        self.assertEqual(database.audit_peers_offline(360, self.now + 900, thresholds), [])
        self.assertEqual([p["email"] for p in database.audit_peers_offline(360, self.now + 901, thresholds)], [email])

    async def test_eight_peer_idle_simulation(self):
        self.peers = [{"email": f"p{i}@example.org", "chat_id": 10 + i} for i in range(8)]
        self.probes = []
        old_last_sent = -120
        old_count = 0
        start = self.now
        for elapsed in range(0, 70 * 60, 5):
            self.now = start + elapsed
            if elapsed % 60 == 0 and elapsed - old_last_sent >= bot.telemetry_interval(8) - 5:
                old_last_sent = elapsed
                old_count += len(self.peers)
            await self.tick()
        print(f"Idle METRICS, 8 peers over 70 minutes: {old_count} old, {len(self.sent)} new")
        self.assertEqual((old_count, len(self.sent)), (280, 112))
