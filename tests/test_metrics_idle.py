import asyncio
import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox
from test_peer_seam import inline_peer_metrics


class TestMetricsIdle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        inline_peer_metrics(self)
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
            monotonic=self.clock,
            _telemetry_sent_at={}, _telemetry_last_sent={}, _telemetry_started_at={}, _telemetry_delivered={},
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

    def counts_by_reason(self):
        database.flush_peer_metrics()
        traffic, _ = database.get_peer_metrics_24h(self.now)
        return {kind: n for kind, direction, n in traffic if direction == "out" and kind.startswith("peer_metrics_")}

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

    async def test_local_and_probe_status_changes_wait_for_the_120_second_interval(self):
        bot._peer_desired_interval["peer@example.org"] = 120
        await self.tick()
        self.resources[0]["status"] = "down"
        await self.tick(119)
        self.assertEqual(len(self.sent), 1)
        await self.tick(1)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[-1][2]["metrics"][1]["status"], "down")
        self.probes[0]["last_status"] = "down"
        await self.tick(119)
        self.assertEqual(len(self.sent), 2)
        await self.tick(1)
        self.assertEqual(len(self.sent), 3)
        self.assertEqual(self.sent[-1][2]["metrics"][0]["status"], "down")
        self.assertEqual(len(self.sent[-1][2]["metrics"]), 3)
        await self.tick(299)
        self.assertEqual(len(self.sent), 3)
        await self.tick(1)
        self.assertEqual(self.sent[-1][0] - self.sent[-2][0], self.sent[-2][2]["telemetry_interval"])
        self.assertEqual(self.counts_by_reason(), {"peer_metrics_idle": 1, "peer_metrics_change": 3})
        with contextlib.closing(database._connect()) as conn:
            self.assertEqual(conn.execute("SELECT transport, dir, n, bytes FROM peer_traffic "
                                          "WHERE kind IN ('peer_metrics_change', 'peer_metrics_idle') "
                                          "ORDER BY kind").fetchall(),
                             [("mail", "out", 3, 0), ("mail", "out", 1, 0)])
        self.assertEqual(database.get_mail_kinds_24h(self.now), [("peer_metrics", 4)])

    async def test_queue_replaces_pending_metrics_on_a_revert(self):
        await self.tick()
        self.box._thread = object()
        self.resources[0]["status"] = "down"
        await self.tick(270)
        self.resources[0]["status"] = "up"
        await self.tick(5)
        self.assertEqual(self.box.waiting(), {"telemetry": 1})
        self.assertEqual(self.box.stats["merged"], 1)
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.counts_by_reason(), {"peer_metrics_change": 1})
        await self.tick(24)
        self.assertEqual(self.box.waiting(), {})
        await self.tick(1)
        self.assertEqual(self.box.waiting(), {"telemetry": 1})
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 2)
        self.assertEqual([m["status"] for m in self.sent[-1][2]["metrics"]], ["up", "up", "up"])
        self.assertEqual(self.counts_by_reason(), {"peer_metrics_idle": 1, "peer_metrics_change": 1})

    async def test_delayed_rpc_cannot_send_two_messages_within_120_seconds(self):
        self.box._thread = object()
        await self.tick()
        sending = self.pop_job()
        self.resources[0]["status"] = "down"
        await self.tick(120)

        def slow_send(*args):
            msg_id = self.record(*args)
            self.now += 10
            return msg_id

        self.client.rpc.send_msg.side_effect = slow_send
        self.box._run(sending)
        self.client.rpc.send_msg.side_effect = self.record
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 1)
        await self.tick(119)
        self.assertEqual(self.box.waiting(), {})
        await self.tick(1)
        self.assertEqual(self.box.waiting(), {"telemetry": 1})
        self.box._run(self.pop_job())
        self.assertEqual([payload["metrics"][1]["status"] for _, _, payload in self.sent], ["up", "down"])
        self.assertEqual(self.sent[1][0] - self.sent[0][0], 130)

    async def test_slower_peer_request_is_preserved(self):
        bot._peer_desired_interval["peer@example.org"] = 360
        await self.tick()
        self.assertEqual(self.sent[0][2]["telemetry_interval"], 360)
        self.probes[0]["last_status"] = "down"
        await self.tick(359)
        self.assertEqual(len(self.sent), 1)
        await self.tick(1)
        self.assertEqual(len(self.sent), 2)

    async def test_peer_count_interval_also_limits_changes(self):
        self.peers = [{"email": f"p{i}@example.org", "chat_id": 10 + i} for i in range(11)]
        await self.tick()
        self.resources[0]["status"] = "down"
        await self.tick(179)
        self.assertEqual(len(self.sent), 11)
        await self.tick(1)
        self.assertEqual(len(self.sent), 22)

    async def test_queued_job_honors_a_new_longer_interval(self):
        await self.tick()
        self.box._thread = object()
        self.resources[0]["status"] = "down"
        await self.tick(120)
        bot._peer_desired_interval["peer@example.org"] = 180
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 1)
        await self.tick(59)
        self.assertEqual(self.box.waiting(), {})
        await self.tick(1)
        self.assertEqual(self.box.waiting(), {"telemetry": 1})
        self.box._run(self.pop_job())
        self.assertEqual(len(self.sent), 2)

    async def test_failed_rpc_does_not_count_toward_either_reason(self):
        self.client.rpc.send_msg.side_effect = RuntimeError("send failed")
        await self.tick()
        self.assertEqual(self.box.stats["failed"], 1)
        self.assertEqual(self.counts_by_reason(), {})
        self.client.rpc.send_msg.side_effect = self.record
        await self.tick(120)
        self.assertEqual(self.counts_by_reason(), {"peer_metrics_change": 1})

    async def test_unchanged_large_snapshots_rotate_at_the_idle_interval(self):
        self.resources = [{"url": f"https://monitor{i}.example.org", "status": "up"} for i in range(201)]
        self.probes = []
        await self.tick()
        await self.tick(120)
        self.assertEqual(len(self.sent), 1)
        await self.tick(180)
        self.assertEqual(len(self.sent), 2)
        for _, _, payload in self.sent:
            self.assertEqual(len(payload["metrics"]), 200)
        self.assertEqual(self.sent[-1][2]["metrics"][0]["url"], self.resources[-1]["url"])
        self.assertEqual(self.counts_by_reason(), {"peer_metrics_idle": 1, "peer_metrics_change": 1})

    async def test_old_style_receiver_announcement_and_omitted_urls(self):
        peer = self.peers[0]
        email = peer["email"]
        database.add_or_update_peer(email, "Peer", 10)
        database.save_peer_measurement("https://omitted.example.org", "Peer", "up", source_peer=email)
        self.client.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        payload = {"msg_id": "interval", "node_name": "Peer", "telemetry_interval": 300, "metrics": [self.resources[0]]}
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
            if elapsed % bot.TELEMETRY_TICK == 0:
                await self.tick()
        print(f"Idle METRICS, 8 peers over 70 minutes: {old_count} old, {len(self.sent)} new")
        self.assertEqual((old_count, len(self.sent)), (280, 112))

    async def test_eight_peer_flapping_monitor_simulation(self):
        self.peers = [{"email": f"p{i}@example.org", "chat_id": 10 + i} for i in range(8)]
        self.resources = [{"url": f"https://monitor{i}.example.org", "status": "up"} for i in range(178)]
        self.probes = []
        # Every step changes status. The five-step cycle keeps both 30 s and 120 s polls from
        # repeatedly sampling the same state, as they would with a two-state 10 s cycle.
        statuses = ("up", "down", "up", "down", "degraded")
        start = self.now
        for elapsed in range(0, 70 * 60, 5):
            self.now = start + elapsed
            self.resources[0]["status"] = statuses[(elapsed // 5) % len(statuses)]
            if elapsed % bot.TELEMETRY_TICK == 0:
                await self.tick()
        old_count = 8 * (70 // 2)
        reasons = self.counts_by_reason()
        print(f"Flapping METRICS, 8 peers and 178 monitors over 70 minutes: {old_count} old, "
              f"{len(self.sent)} new ({reasons.get('peer_metrics_change', 0)} on change, "
              f"{reasons.get('peer_metrics_idle', 0)} idle)")
        self.assertLessEqual(len(self.sent), old_count)
        for peer in self.peers:
            sent_at = [at for at, chat, _ in self.sent if chat == peer["chat_id"]]
            self.assertGreater(len(sent_at), 70 // 5)
            self.assertLessEqual(len(sent_at), 70 // 2)
            self.assertTrue(all(b - a >= 120 for a, b in zip(sent_at, sent_at[1:])))
        self.assertEqual(reasons, {"peer_metrics_change": len(self.sent)})
