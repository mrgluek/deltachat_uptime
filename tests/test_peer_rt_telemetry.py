"""Peer telemetry through the realtime dispatcher and the mail outbox."""
import asyncio
import collections
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import bot
import database
import peer_rt
from outbox import Outbox
from test_peer_seam import inline_peer_metrics
from test_peer_metrics import event, message
from test_peer_rt_channel import CHAT, CID, EMAIL, FP, IN_KEY, MSG, OUT_KEY, Event


class TestRealtimeTelemetry(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        inline_peer_metrics(self)
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.multiple(database, DB_PATH=str(Path(directory) / "uptime.db"),
                                         _peer_traffic_buffer={}, _peer_rtt_buffer=[], _mail_kind_buffer={}))
        self.addCleanup(database.close_db)
        database.init_db()
        self.now = 1_800_000_000
        self.mono = 0.0
        self.seq = 0
        self.clock = SimpleNamespace(time=lambda: self.now, monotonic=lambda: self.mono)
        self.enterContext(patch.object(database, "time", self.clock))
        self.wire = []
        self.mail = []
        self.client = Mock()
        self.client.rpc.send_webxdc_realtime_data.side_effect = self.capture_rt
        self.client.rpc.send_msg.side_effect = self.capture_mail
        self.box = Outbox(clock=self.clock.monotonic, burst=100)
        self.resources = [self.resource(number) for number in range(2)]
        self.enterContext(patch.multiple(
            database, get_all_resources=lambda: self.resources, get_active_probe_targets=lambda: []))
        self.enterContext(patch.multiple(
            bot, time=self.clock, monotonic=self.clock.monotonic, dc_bot_instance=self.client,
            dc_accid=1, dc_outbox=self.box, async_event_loop=None, stat_event=Mock(),
            run_rpc=self.run_sync, run_db=self.run_sync,
            _telemetry_sent_at={}, _telemetry_started_at={}, _telemetry_last_sent={}, _telemetry_delivered={},
            _telemetry_queued_status={}, _telemetry_rotation_offsets={}, _telemetry_rt_peers={},
            _telemetry_delta_timer=None, _peer_desired_interval={}, _peer_telemetry_interval={},
            _peer_caps={}, _peer_caps_announcements={}, _peer_caps_requests=set(), _peer_versions={},
            _processed_msg_ids=bot._ProcessedMessageIds(), _peer_metrics_timestamps=collections.OrderedDict(),
            _local_degraded={}, _scheduler_cache={}, _get_self_addr=lambda *_: "local@example.org",
            _filter_peer_shareable_resources=lambda *args: args[-1],
            _peer_rt_links={}, _peer_rt_carrier_ids=set(), _peer_rt_leaves=set(), _peer_rt_pending_adverts=set(),
            _peer_rt_replay=peer_rt.ReplayWindow(clock=self.clock.monotonic),
            _peer_rt_limiter=peer_rt.TokenBucketLimiter(clock=self.clock.monotonic),
            _peer_rt_log=peer_rt.LogOnce(clock=self.clock.monotonic),
            _get_verified_peer_for_msg=lambda _bot, _accid, msg, _private: (database.get_peer(EMAIL), EMAIL),
            _is_trusted_peer_msg=Mock(return_value=True), is_safe_target_url=Mock(return_value=True),
            note_peer_reported_down=Mock(),
        ))
        database.set_peer_rt_flag("on")
        self.link = self.add_channel(EMAIL, "Peer", CHAT, FP, MSG)
        self.link.state.on_frame()

    async def asyncSetUp(self):
        self.addCleanup(self.cancel_delta)

    def cancel_delta(self):
        if bot._telemetry_delta_timer:
            bot._telemetry_delta_timer.cancel()

    def add_channel(self, email, name, chat, fp, msg_id):
        database.add_or_update_peer(email, name, chat, fingerprint=fp)
        database.set_peer_rt_capability(fp, True)
        database.set_peer_rt(fp, cid=CID, msg_id=msg_id, key_in=IN_KEY, key_out=OUT_KEY,
                             created_at=self.now)
        bot._refresh_peer_rt_channels()
        return bot._peer_rt_links[msg_id]

    def resource(self, number):
        return {"url": f"https://monitor{number}.example.org", "status": "up", "last_latency_ms": 100,
                "last_checked": self.now}

    async def run_sync(self, func, *args):
        return func(*args)

    def advance(self, seconds):
        self.now += seconds
        self.mono += seconds

    def capture_rt(self, accid, msg_id, blob):
        self.assertEqual(accid, 1)
        self.wire.append((self.mono, msg_id, json.loads(bytes(blob))))

    def capture_mail(self, accid, chat, msg):
        self.assertEqual(accid, 1)
        self.mail.append((self.mono, chat, msg.text))
        return len(self.mail)

    def mail_body(self, index=-1):
        return json.loads(self.mail[index][2].splitlines()[1])

    def frames(self):
        return [frame for _, _, frame in self.wire if frame["k"] == "metrics"]

    async def tick(self, after=0, *, live=True, delta=False):
        self.advance(after)
        if live:
            for link in bot._peer_rt_links.values():
                link.state.on_frame()
        await bot.broadcast_telemetry_to_peers(rt_delta=delta)

    def receive(self, kind, body, *, ack=0):
        self.seq += 1
        wire = peer_rt.encode(kind, "face1234", self.seq, body, IN_KEY, ack=ack, clock=self.clock.time)
        bot.on_status_realtime(self.client, 1, Event(kind="WebxdcRealtimeData", msg_id=MSG, data=list(wire)))

    def metrics(self, timestamp, *entries, interval=120, **fields):
        return {"msg_id": f"metrics-{self.seq}-{timestamp}", "timestamp": timestamp,
                "caps": ["rt1", "batch_check"], "telemetry_interval": interval, "desired_interval": 120,
                "metrics": list(entries), **fields}

    def audit(self):
        return database.audit_peers_offline(360, self.now, {EMAIL: bot.peer_offline_after(EMAIL)})

    async def test_up_for_70_minutes_sends_one_keepalive_and_regular_full_snapshots(self):
        bot._peer_desired_interval[EMAIL] = 180
        bot._announce_peer_caps(self.client, 1)  # An UP peer needs no caps-only mail.
        for elapsed in range(0, 4200, 30):
            await self.tick(after=30 if elapsed else 0)
        self.assertEqual([(at, chat) for at, chat, _ in self.mail], [(3600, CHAT)])
        self.assertEqual(self.mail_body()["telemetry_interval"], 180)
        expected = list(range(0, 4200, 180))
        expected.remove(3600)  # The keepalive carries that full snapshot.
        self.assertEqual([at for at, _, _ in self.wire], expected)
        for frame in self.frames():
            self.assertEqual((frame["a"], frame["b"]["telemetry_interval"], frame["b"]["desired_interval"]), (0, 180, 120))
            self.assertEqual(len(frame["b"]["metrics"]), 2)

    async def test_down_forces_the_next_tick_then_preserves_mail_change_and_idle_pacing(self):
        self.advance(90)
        await self.tick(live=False)
        await self.tick(1)  # Channel recovered one second after the first mail.
        await self.tick(89, live=False)
        self.assertEqual(len(self.mail), 1)
        await self.tick(1, live=False)
        self.assertEqual([at for at, _, _ in self.mail], [90, 181])
        self.resources[0]["status"] = "down"
        await self.tick(119, live=False)
        self.assertEqual(len(self.mail), 2)
        await self.tick(1, live=False)
        await self.tick(299, live=False)
        self.assertEqual(len(self.mail), 3)
        await self.tick(1, live=False)
        self.assertEqual([at for at, _, _ in self.mail], [90, 181, 301, 601])
        self.assertEqual([f["k"] for f in self.frames()], ["metrics"])
        self.assertEqual(self.mail_body()["telemetry_interval"], 300)

    async def test_status_write_schedules_one_debounce_and_flapping_is_rate_limited(self):
        await self.tick()
        loop = asyncio.get_running_loop()
        timer = Mock()
        timer.when.return_value = 1010.0
        with patch.object(loop, "time", return_value=1001.0), patch.object(loop, "call_at", return_value=timer) as schedule, \
             patch.object(database, "batch_update_resource_status") as write, \
             patch.object(bot, "sync_chat_incident_state"), patch.object(bot, "check_stale_downtime_notifications"):
            resource = dict(self.resources[0], id=1, dc_chat_id=7)
            await bot.handle_check_result(resource, False, "unavailable")
            await bot.handle_check_result(resource, False, "still unavailable")
            self.assertEqual(write.call_count, 2)
            schedule.assert_called_once()
            deadline, push = schedule.call_args.args
            self.assertEqual(deadline, 1010)
        self.assertEqual(len(self.wire), 1)
        self.advance(10)
        self.resources[0]["status"] = "down"
        tasks = []
        create_task = loop.create_task
        with patch.object(loop, "create_task", side_effect=lambda coro: tasks.append(create_task(coro))):
            push()
            self.assertIsNone(bot._telemetry_delta_timer)
        await tasks[0]
        self.assertEqual([(m["url"], m["status"]) for m in self.frames()[-1]["b"]["metrics"]],
                         [(self.resources[0]["url"], "down")])
        for second in range(12, 72):
            self.resources[0]["status"] = "up" if second % 3 else "down"
            await self.tick(1, delta=True)
        times = [at for at, _, _ in self.wire]
        self.assertGreater(len(times), 2)
        self.assertTrue(all(second - first >= 10 for first, second in zip(times, times[1:])))
        self.assertFalse(self.mail)

    def test_partial_receiver_upserts_and_uses_peer_identity_with_cross_transport_ordering(self):
        first, second = self.resources
        t = self.now
        self.receive("metrics", self.metrics(t, first, second, node_name="Claimed", sender_email="other@example.org"))
        self.advance(20)
        self.receive("metrics", self.metrics(t + 20, dict(first, status="down"), node_name="Different"))
        late_mail = self.metrics(t + 10, first, node_name="Old")
        bot.on_new_message(self.client, 1, event(message("METRICS", json.dumps(late_mail)), CHAT))
        for expected, resource in [("down", first), ("up", second)]:
            measurement, = database.get_peer_measurements_for_url(resource["url"])
            self.assertEqual((measurement["status"], measurement["node_name"]), (expected, "Peer"))
        self.advance(20)
        fresh_mail = self.metrics(t + 40, first)
        bot.on_new_message(self.client, 1, event(message("METRICS", json.dumps(fresh_mail)), CHAT))
        self.receive("metrics", self.metrics(t + 30, dict(first, status="down")))
        self.assertEqual(database.get_peer_measurements_for_url(first["url"])[0]["status"], "up")
        with sqlite3.connect(database.DB_PATH) as conn:
            urls = conn.execute("SELECT url FROM probe_targets").fetchall()
        self.assertCountEqual(urls, [(first["url"],), (second["url"],)])
        self.assertFalse(self.wire)  # METRICS sends no ACK.

    async def test_frames_keep_peer_online_with_hourly_keepalive_and_silence_marks_offline(self):
        t = self.now
        self.receive("metrics", self.metrics(t, *self.resources, interval=120))
        # A larger mail announcement cannot change the live frame threshold.
        bot.on_new_message(self.client, 1, event(message("METRICS", json.dumps(
            self.metrics(t, interval=300))), CHAT))
        self.assertEqual(bot.peer_offline_after(EMAIL), 360)
        self.link.advertise_at = None
        with sqlite3.connect(database.DB_PATH) as conn:
            conn.executescript("""
                CREATE TABLE seen_writes (timestamp INTEGER);
                CREATE TRIGGER log_seen AFTER UPDATE OF last_seen ON peers
                BEGIN INSERT INTO seen_writes VALUES (new.last_seen); END;
            """)
        with patch.object(database, "update_peer_last_seen", wraps=database.update_peer_last_seen) as seen:
            for elapsed in range(5, 4200, 5):
                self.advance(5)
                if elapsed % 30:
                    self.receive("metrics", self.metrics(self.now))
                elif elapsed % 60:
                    self.receive("ping", {})
                else:
                    self.receive("pong", {"e": "face1234", "s": 1})
                if elapsed == 3600:
                    keepalive = self.metrics(self.now, *self.resources)
                    bot.on_new_message(self.client, 1, event(message("METRICS", json.dumps(keepalive)), CHAT))
                await bot._tick_peer_rt_link(self.client, 1, MSG, self.link)
                self.assertEqual(self.audit(), [])
            self.assertEqual(seen.call_count, 140)  # One realtime attempt shares the mail keepalive's timestamp.
        with sqlite3.connect(database.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT timestamp FROM seen_writes ORDER BY rowid").fetchall(),
                             [(t + elapsed,) for elapsed in range(30, 4200, 30)])
        seen_at = database.get_peer(EMAIL)["last_seen"]
        self.advance(seen_at + 360 - self.now)
        self.assertEqual(self.audit(), [])
        self.advance(1)
        self.assertEqual([p["email"] for p in self.audit()], [EMAIL])
        self.receive("metrics", self.metrics(self.now))
        self.assertEqual(database.get_peer(EMAIL)["is_offline"], 0)
        self.assertEqual(database.get_peer(EMAIL)["last_seen"], self.now)

    async def test_mixed_peer_mail_is_byte_identical_and_delta_only_goes_to_rt_peer(self):
        database.add_or_update_peer("older@example.org", "Older", CHAT + 1)
        database.set_peer_version("older@example.org", "2.44.2")
        with patch.object(bot.secrets, "token_hex", return_value="fixed"):
            await self.tick()
        expected = {
            "node_name": database.get_local_node_name(), "sender_email": "local@example.org",
            "timestamp": self.now, "msg_id": f"{self.now}_fixed", "caps": [*bot.OWN_PEER_CAPS, "rt1"],
            "telemetry_interval": 300, "desired_interval": 120, "version": bot.VERSION,
            "metrics": [{"url": r["url"], "type": "http", "expected_keyword": None, "status": "up",
                         "latency_ms": 100, "last_checked": self.now} for r in self.resources],
        }
        self.assertEqual(self.mail, [(0, CHAT + 1,
                                      f"[UPTIME_PEER_METRICS]\n{json.dumps(expected)}\n[/UPTIME_PEER_METRICS]")])
        self.assertEqual([(msg_id, frame["k"]) for _, msg_id, frame in self.wire], [(MSG, "metrics")])
        self.resources[1]["status"] = "down"
        await self.tick(10, delta=True)
        self.assertEqual(len(self.mail), 1)
        self.assertEqual([m["url"] for m in self.frames()[-1]["b"]["metrics"]], [self.resources[1]["url"]])

    async def test_oversize_falls_back_once_and_uses_mail_counters(self):
        self.resources = [dict(self.resource(number), url=self.resource(number)["url"] + "/" + "a" * 640)
                          for number in range(178)]
        await self.tick()
        self.assertFalse(self.wire)
        self.assertEqual(len(self.mail_body()["metrics"]), 178)
        self.assertEqual(self.mail_body()["telemetry_interval"], 300)
        await self.tick(30)
        self.assertEqual(len(self.mail), 1)
        self.resources = [self.resource(0)]
        await self.tick(10, delta=True)
        self.receive("metrics", self.metrics(self.now, self.resources[0]))
        database.flush_peer_metrics()
        with sqlite3.connect(database.DB_PATH) as conn:
            rows = conn.execute("SELECT kind, transport, dir, n, bytes FROM peer_traffic").fetchall()
        counts = {(kind, transport, direction): (n, size) for kind, transport, direction, n, size in rows}
        for direction in ("in", "out"):
            self.assertEqual(counts["metrics", "rt", direction][0], 1)
            self.assertGreater(counts["metrics", "rt", direction][1], 0)
        self.assertEqual(counts["peer_metrics_rt", "rt", "out"], (1, 0))
        self.assertEqual(counts["peer_metrics_change", "mail", "out"], (1, 0))
        self.assertEqual(database.get_mail_kinds_24h(self.now), [("peer_metrics", 1)])
        self.assertIn("• METRICS sent (24 h): idle 0, on change 1, rt 1", bot._peer_metrics_report(self.now))

    async def test_queued_mail_is_skipped_if_the_channel_recovers_before_send(self):
        await self.tick()
        self.box._thread = object()
        await self.tick(90, live=False)
        with self.box._cond:
            job = self.box._next_job()
        await self.tick(30)
        self.box._run(job)
        self.assertFalse(self.mail)
        self.assertEqual(len(self.frames()), 2)
        await self.tick(90, live=False)
        with self.box._cond:
            job = self.box._next_job()
        self.box._run(job)
        self.assertEqual([(at, chat) for at, chat, _ in self.mail], [(210, CHAT)])

    async def test_mode_off_uses_mail_even_with_recent_realtime_activity(self):
        await self.tick()
        database.set_peer_rt_mode(EMAIL, "off")
        bot._refresh_peer_rt_channels()
        await self.tick(30)
        self.assertEqual([(at, chat) for at, chat, _ in self.mail], [(30, CHAT)])
        self.assertEqual(len(self.frames()), 1)

    async def test_ambiguous_realtime_rpc_failure_does_not_redeliver_the_same_snapshot_by_mail(self):
        def send_and_raise(*args):
            self.capture_rt(*args)
            raise OSError("reply was lost")

        self.client.rpc.send_webxdc_realtime_data.side_effect = send_and_raise
        with self.assertLogs(bot.logger, level="WARNING"):
            await self.tick()
        self.assertEqual(len(self.frames()), 1)
        self.assertFalse(self.mail)
        self.client.rpc.send_webxdc_realtime_data.side_effect = self.capture_rt
        await self.tick(30)
        self.assertEqual(len(self.frames()), 2)
        self.assertNotEqual(self.frames()[0]["b"]["msg_id"], self.frames()[1]["b"]["msg_id"])

    async def test_timed_out_rt_activity_alone_cannot_authorize_rejoin_mail(self):
        self.receive("metrics", self.metrics(self.now, interval=600))
        self.link.advertise_at = None
        self.advance(390)
        await bot._tick_peer_rt_link(self.client, 1, MSG, self.link)
        self.client.rpc.send_webxdc_realtime_advertisement.assert_not_called()
        database.update_peer_last_seen(EMAIL)
        await bot._tick_peer_rt_link(self.client, 1, MSG, self.link)
        self.client.rpc.send_webxdc_realtime_advertisement.assert_called_once_with(1, MSG)

    async def test_eight_peers_flapping_178_monitors_for_70_minutes(self):
        for index in range(1, 8):
            self.add_channel(f"node{index}@example.org", f"Node {index}", CHAT + index, f"{index:040X}", MSG + index)
        self.resources = [self.resource(number) for number in range(178)]

        async def simulate(live):
            sent_rt = 0
            for elapsed in range(0, 4200, 10):
                for index, resource in enumerate(self.resources):
                    resource["status"] = "down" if (elapsed // 10 + index) % 13 < 6 else "up"
                await self.tick(10, live=live, delta=elapsed % 30 != 0)
                sent_rt += len(self.wire)
                self.wire.clear()
            return collections.Counter(chat for _, chat, _ in self.mail), sent_rt

        up_mails, up_frames = await simulate(True)
        self.assertEqual(up_mails, {CHAT + index: 1 for index in range(8)})
        self.mail.clear()
        self.advance(peer_rt.RT_CHANNEL_TIMEOUT)
        down_mails, down_frames = await simulate(False)
        self.assertEqual(down_mails, {CHAT + index: 35 for index in range(8)})
        self.assertEqual(down_frames, 0)
        print(f"70-minute telemetry simulation (8 peer links, 178 flapping monitors): "
              f"{up_mails.total()} mail UP ({up_frames} realtime frames), {down_mails.total()} mail DOWN")
