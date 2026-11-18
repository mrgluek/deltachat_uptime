"""Grid scheduling and timeout handling for periodic peer votes."""
import asyncio
import collections
import datetime
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database


class Clock:
    now = 0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now + 10_000


def target(index, state="down"):
    return {"id": index, "name": f"Target {index}", "url": f"http://target{index}.example.org",
            "status": state, "alert_state": state, "dc_chat_id": 1, "type": "http"}


def peer(index):
    return {"email": f"peer{index}@example.org", "node_name": f"Peer {index}", "chat_id": index + 10}


def result(node, status="down"):
    return {"node_name": node, "status": status, "latency_ms": None, "error_msg": None}


class VoteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.clock = Clock()
        self.peers = [peer(i) for i in range(7)]
        self.sent = []
        self.local = {}
        self.peer_status = "down"
        self.install(bot, time=self.clock, _vote_cache={}, _peer_suspects={}, _vote_peers={},
                     _alert_streaks={}, _check_finished_at={}, running_resource_ids=set(),
                     _cross_check_queue=[], _cross_check_flush_task=None,
                     CROSS_CHECK_BATCH_WINDOW=0.001, _stat_events=collections.defaultdict(collections.deque),
                     _peer_supports=MagicMock(return_value=True), run_db=AsyncMock(),
                     _quorum_resource_ids=AsyncMock(side_effect=lambda group: {r["id"] for r in group}),
                     _peer_cross_check_allowed=AsyncMock(return_value=True),
                     handle_check_result=AsyncMock(), check_host_internet_connectivity=AsyncMock(return_value=True),
                     check_network_probe=AsyncMock(side_effect=self.local_check),
                     note_vote_outliers=MagicMock(return_value=[]), mask_unstable_votes=lambda votes: votes,
                     _queue_degraded_notice=MagicMock(), note_lone_reporter=MagicMock())
        self.install(database, get_all_peers=lambda: self.peers, get_local_node_name=lambda: "Local",
                     is_node_target_ignored=lambda node, url: False, record_peer_traffic=MagicMock())

    def install(self, module, **values):
        patcher = patch.multiple(module, **values)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def local_check(self, monitor, semaphore, session=None):
        await asyncio.sleep(0)
        return self.local.get(monitor["id"], (False, "Timeout", None))

    async def batches(self, remote, items, results):
        self.sent.append((self.clock.now, remote["email"], tuple(t["id"] for _, t in items)))
        for key, _ in items:
            results[key].append(result(remote["node_name"], self.peer_status))

    def seed(self, monitor, phase, *, up=False):
        key = bot._cross_check_key(monitor)
        bot._vote_cache[key] = bot._CachedVote(phase + 10_000, phase, up, [result(p["node_name"]) for p in self.peers])

    async def grid(self, resources, now, bootstrap=0):
        self.clock.now = now
        ticks = bot._due_vote_grid_ticks(resources, now, self.clock.monotonic(), bootstrap, {})
        groups = collections.defaultdict(list)
        for monitor in resources:
            key = bot._cross_check_key(monitor)
            if key in ticks:
                groups[key].append(monitor)
        if groups:
            await bot._run_grid_checks(groups, ticks, asyncio.Semaphore(10), None)
        return ticks

    async def flush(self, resources, *, urgent=False):
        requests = [(r, asyncio.get_running_loop().create_future(), None) for r in resources]
        await bot._flush_cross_checks(requests, urgent=urgent)
        return [future.result() for _, future, _ in requests]

    async def test_phased_targets_and_suspects_share_a_grid_batch(self):
        down = [target(i) for i in range(3)]
        for monitor, phase in zip(down, (13, 52, 101)):
            self.seed(monitor, phase)
        suspects = [target(i, "up") for i in range(3, 5)]
        self.local.update({r["id"]: (True, None, 10) for r in suspects})
        self.install(database, get_resources_by_urls=lambda urls: [r for r in suspects if r["url"] in urls],
                     get_chat_alert_mode=lambda chat: "quorum")
        with patch.object(bot, "report_held", return_value=False):
            for now, monitor in ((130, suspects[0]), (175, suspects[1]), (231, suspects[0])):
                self.clock.now = now
                self.assertEqual(bot.note_peer_reported_down("Peer 0", [{"url": monitor["url"], "status": "down"}]), 1)

        async def unequal_duration(remote_target, semaphore, session=None):
            for _ in range(4 - remote_target["id"]):
                await asyncio.sleep(0)
            return await self.local_check(remote_target, semaphore, session)

        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches), \
             patch.object(bot, "check_network_probe", side_effect=unequal_duration):
            self.assertEqual(await self.grid(down + suspects, 239), {})
            for monitor in down + suspects:
                await bot.run_and_track_group([monitor], asyncio.Semaphore(1))
            self.assertEqual(self.sent, [])
            self.assertEqual(set((await self.grid(down + suspects, 240)).values()), {240})
        self.assertEqual(len(self.sent), 7)
        self.assertTrue(all(tick == 240 and set(ids) == set(range(5)) for tick, _, ids in self.sent))

    async def test_vote_schedule_and_reset_on_quorum_change_and_recovery(self):
        monitor = target(0)
        self.seed(monitor, 0)
        key = bot._cross_check_key(monitor)
        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches):
            for due, step, following in ((120, 1, 600), (600, 2, 1200), (1200, 2, 1800)):
                self.assertEqual(bot._vote_cache[key].due, due)
                self.assertFalse(await self.grid([monitor], due - 1))
                await self.grid([monitor], due)
                self.assertEqual((bot._vote_cache[key].step, bot._vote_cache[key].due), (step, following))

            self.peer_status = "up"
            await self.grid([monitor], 1800)
            self.assertEqual(monitor["alert_state"], "degraded")
            self.assertEqual((bot._vote_cache[key].step, bot._vote_cache[key].due), (0, 1920))

            monitor["status"] = "up"
            self.clock.now = 1850
            self.local[0] = (True, None, 10)
            await bot.run_and_track_group([monitor], asyncio.Semaphore(1))
            self.assertEqual((bot._vote_cache[key].step, bot._vote_cache[key].due), (0, 2040))
            self.assertTrue(all(tick == 1850 for tick, _, _ in self.sent[-7:]))

    async def test_monitoring_scheduler_launches_grid_between_regular_slots(self):
        resources = [target(i) | {"last_checked": 230, "interval": 60} for i in range(3)]
        for monitor, phase in zip(resources, (13, 52, 101)):
            self.seed(monitor, phase)
        self.clock.now = 239
        self.install(bot, _scheduler_cache={"resources": resources, "resources_ts": 239,
                                            "probe_targets": [], "probe_targets_ts": 239, "ttl": 10},
                     _host_outage_active=False, last_peer_telemetry_broadcast=239,
                     pop_recovered_nodes=lambda: [], _check_report_notices=AsyncMock(),
                     push_status_apps=AsyncMock(), realtime_status_tick=AsyncMock(),
                     audit_abandoned_chats=AsyncMock())
        sleep = asyncio.sleep

        async def advance(delay):
            if not delay:
                await sleep(0)
            elif self.clock.now == 239:
                self.assertEqual(delay, 1)
                self.assertEqual(self.sent, [])
                self.clock.now = 240
            else:
                for _ in range(100):
                    if not bot.running_resource_ids:
                        break
                    await sleep(0)
                self.assertEqual(len(self.sent), 7)
                raise asyncio.CancelledError

        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches), \
             patch.object(bot.secrets, "randbelow", return_value=0), \
             patch.object(bot.asyncio, "sleep", side_effect=advance), \
             self.assertRaises(asyncio.CancelledError):
            await bot.monitoring_scheduler_loop()
        self.assertTrue(all(tick == 240 and set(ids) == {0, 1, 2} for tick, _, ids in self.sent))

    async def test_new_failure_keeps_urgent_window_and_local_retries(self):
        monitor = target(0, "up")
        self.clock.now = 37
        sleep = asyncio.sleep

        async def immediate_sleep(delay):
            await sleep(0)

        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches), \
             patch.object(bot.asyncio, "sleep", side_effect=immediate_sleep) as calls:
            await bot.run_and_track_group([monitor], asyncio.Semaphore(1))
        self.assertEqual([call.args[0] for call in calls.call_args_list].count(30), 2)
        self.assertIn(bot.CROSS_CHECK_BATCH_WINDOW, [call.args[0] for call in calls.call_args_list])
        self.assertEqual(len(self.sent), 7)
        self.assertTrue(all(tick == 37 for tick, _, _ in self.sent))

    async def test_grid_batches_respect_target_cap(self):
        self.peers = self.peers[:1]
        resources = [target(i) for i in range(bot.CROSS_CHECK_BATCH_MAX + 1)]
        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches):
            answers = await self.flush(resources)
        self.assertEqual([len(ids) for _, _, ids in self.sent], [bot.CROSS_CHECK_BATCH_MAX, 1])
        self.assertTrue(all(len(a) == 1 for a in answers))

    async def test_breaker_backoff_probe_urgent_and_reset(self):
        self.peers = self.peers[:3]
        slow = self.peers[0]
        key = bot._vote_peer_key(slow)
        loop = asyncio.get_running_loop()
        slow_answers = False
        requests = []

        def mail(rpc, accid, chat_id, data, **kwargs):
            kwargs["before_send"]()
            payload = json.loads(data.text.splitlines()[1])
            requests.append((chat_id, len(payload["targets"])))
            if chat_id != slow["chat_id"] or slow_answers:
                remote = next(p for p in self.peers if p["chat_id"] == chat_id)
                fut, _, count = bot.pending_batch_checks[payload["req_id"]]
                loop.call_soon_threadsafe(fut.set_result, [result(remote["node_name"])] * count)

        def sent_to_slow():
            return [length for chat, length in requests if chat == slow["chat_id"]]

        with patch.multiple(bot, dc_bot_instance=MagicMock(), dc_accid=1, CROSS_CHECK_BATCH_MAX=2,
                            CROSS_CHECK_BATCH_TIMEOUT=0.02, _dc_send_msg_with_stats=mail,
                            _record_peer_rtt=MagicMock()):
            with self.assertLogs(bot.logger, level="INFO") as logs:
                for n in range(3):
                    self.clock.now = n
                    requests.clear()
                    await self.flush([target(0)], urgent=n == 0)
                    self.assertEqual(sent_to_slow(), [1])
                self.assertEqual(bot._vote_peers[key].pause, 300)

                requests.clear()
                answers = (await self.flush([target(0)]))[0]
                self.assertEqual(sent_to_slow(), [])
                self.assertCountEqual(answers, [result(p["node_name"]) | {"url": target(0)["url"]}
                                                for p in self.peers[1:]])
                got = bot.build_votes("Local", True, 10, None, answers)
                without_slow = bot.build_votes("Local", True, 10, None,
                                                [result(p["node_name"]) for p in self.peers[1:]])
                self.assertEqual(bot.decide_quorum(got), bot.decide_quorum(without_slow))
                database.record_peer_traffic.assert_called_once_with("vote_skipped_paused", "mail", "out", 0)

                requests.clear()
                await self.flush([target(0)], urgent=True)
                self.assertEqual(sent_to_slow(), [1])
                self.assertEqual(bot._vote_peers[key].until, 10_302)

                for now, pause in ((302, 600), (902, 1200), (2102, 1800), (3902, 1800)):
                    self.clock.now = now
                    requests.clear()
                    await asyncio.gather(self.flush([target(n) for n in range(5)]), self.flush([target(6)]))
                    self.assertEqual(len(sent_to_slow()), 1)
                    self.assertLessEqual(sent_to_slow()[0], 2)
                    self.assertEqual(bot._vote_peers[key].pause, pause)

                slow_answers = True
                self.clock.now = 3903
                await self.flush([target(0)], urgent=True)
                self.assertEqual((bot._vote_peers[key].streak, bot._vote_peers[key].until), (0, 0))
                requests.clear()
                await self.flush([target(0)])
                self.assertEqual(sent_to_slow(), [1])
            self.assertEqual(sum("Probing Peer 0" in entry for entry in logs.output), 4)
            self.assertEqual(sum("Votes resumed for Peer 0" in entry for entry in logs.output), 1)

    async def test_all_paused_keeps_the_two_oldest_answers(self):
        for i in (2, 5, 4, 1, 6, 0, 3):
            self.clock.now += 1
            bot._note_vote_peer_result(self.peers[i], True)
            for _ in range(3):
                bot._note_vote_peer_result(self.peers[i], False)
        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches):
            await self.flush([target(0)])
        self.assertCountEqual([address for _, address, _ in self.sent], [self.peers[i]["email"] for i in (2, 5)])

    async def test_pause_shown_in_stats_and_peers(self):
        self.clock.now = 2000
        for _ in range(3):
            bot._note_vote_peer_result(self.peers[0], False)
        self.install(database, get_all_resources=lambda: [], get_active_probe_targets=lambda: [],
                     get_all_peer_measurements=lambda: [], get_monitored_chats=lambda: {},
                     get_peer_metrics_24h=lambda now: ([("vote_skipped_paused", "out", 7)], []))
        expected = datetime.datetime.fromtimestamp(2300).strftime("%H:%M")
        stats = bot.build_stats_report(MagicMock(), 1)
        self.assertIn(f"Votes paused for: Peer 0 (until {expected})", stats)
        self.assertIn("Vote rounds skipped for paused peers (24 h): 7", stats)
        with patch.object(bot, "_is_dc_admin", return_value=True), patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.peers_command(MagicMock(), 1, MagicMock())
        self.assertIn("**Peer 0** ⏸ votes paused", send.call_args.args[3].text)
        self.assertNotIn("**Peer 1** ⏸ votes paused", send.call_args.args[3].text)

    async def test_seventy_minute_simulation(self):
        resources = [target(i) for i in range(6)]
        phases = (8, 26, 44, 62, 80, 100)
        old_rounds = []
        for monitor, phase in zip(resources, phases):
            self.seed(monitor, phase)
            last = phase
            for check in range(phase + 60, 4200, 60):
                interval = 600 if check - phase > 3600 else 120
                if check - last >= interval:
                    old_rounds.append(check)
                    last = check
        # In v2.42 a five-second window starting at the first due check collected more targets.
        old_batches = 0
        closes = -1
        for due in sorted(old_rounds):
            if due >= closes:
                old_batches += len(self.peers)
                closes = due + 5
        with patch.object(bot, "_batch_cross_check_peer", side_effect=self.batches):
            for now in range(0, 4200, 5):
                await self.grid(resources, now)
        new_batches = len(self.sent)
        print(f"70-minute periodic CHECK_BATCH_REQ simulation: {old_batches} old, {new_batches} new")
        self.assertGreater(new_batches, 0)
        self.assertGreaterEqual(old_batches, new_batches * 3)


if __name__ == "__main__":
    unittest.main()
