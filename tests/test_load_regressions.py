import asyncio
from collections import OrderedDict
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

import bot
import database


NOW = 1_800_000_000
DAY = 86_400


def seed_cleanup(conn):
    """Cover all retention cutoffs, including old starts of open outages."""
    cutoff = NOW - 90 * DAY
    journal = NOW - 30 * DAY
    meas = NOW - 7 * DAY
    conn.execute("INSERT INTO resources(id, dc_chat_id, url) VALUES (1, 42, 'https://local.example')")
    for table, columns in (("downtime_events", "id, resource_id, went_up_at"),
                           ("partial_outages", "id, resource_id, ended_at")):
        conn.executemany(f"INSERT INTO {table}({columns}) VALUES (?, 1, ?)",
                         [(1, None), (2, cutoff - 1), (3, cutoff)])
    conn.executemany("INSERT INTO incidents(id, dc_chat_id, status, started_at, resolved_at) VALUES (?, 42, ?, 1, ?)",
                     [(1, "ongoing", None), (2, "resolved", cutoff - 1), (3, "resolved", cutoff)])
    conn.executemany("INSERT INTO config VALUES (?, ?)", [
        ("journal:partial_start:42:1", str(journal - 1)),
        ("journal:incident_start:42:1", str(journal - 1)),
        ("journal:partial_start:42:2", str(journal - 1)),
        ("journal:incident_start:42:2", str(journal - 1)),
        ("Journal:partial_start:42:1", str(journal - 1)),
        ("journal:incident_end:42:3", str(journal)),
        ("journal:legacy", "invalid"),
        ("journal:null", None),
        ("journal;keep", "1"),
    ])
    conn.execute("DELETE FROM chat_events")
    conn.executemany("INSERT INTO chat_events(dc_chat_id, ts, kind, text) VALUES (42, ?, 'test', '')",
                     [(journal - 1,), (journal,)])
    conn.executemany("INSERT INTO peer_measurements(url, node_name, received_at) VALUES (?, 'Peer', ?)",
                     [("old", meas - 1), ("boundary", meas)])
    conn.executemany("INSERT INTO probe_targets(url, last_seen) VALUES (?, ?)", [("old", meas - 1), ("boundary", meas)])
    conn.executemany("INSERT INTO peer_rtt(ts, kind, transport, peer, ms, ok) VALUES (?, 'req', 'rt', 'Peer', 1, 1)",
                     [(meas - 1,), (meas,)])
    conn.executemany("INSERT INTO mail_kind_recent VALUES (?, 'req', 1)", [(NOW - DAY,), (NOW - DAY + 1,)])
    conn.executemany("INSERT INTO peer_traffic_recent VALUES (?, 'req', 'rt', 'in', 1, 1)",
                     [(NOW - DAY,), (NOW - DAY + 1,)])
    for table, fields in (("peer_traffic", "'req', 'rt', 'in', 1, 1"), ("mail_kind", "'req', 1")):
        conn.executemany(f"INSERT INTO {table} VALUES (date(?, 'unixepoch'), {fields})",
                         [(journal,), (journal + DAY,)])


class DatabaseLoadTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.object(database, "DB_PATH", str(Path(directory) / "uptime.db")))
        self.addCleanup(database.close_db)
        self.clock = self.enterContext(patch.object(database.time, "time", return_value=NOW))
        database.init_db()

    def test_cleanup_preserves_retention_boundaries_and_open_journals(self):
        with database._writer_transaction() as conn:
            seed_cleanup(conn)
        deleted = database.cleanup_old_records()
        self.assertTrue(all(count == 1 for count in deleted.values()), deleted)
        with database._writer_transaction() as conn:
            for table in ("downtime_events", "partial_outages", "incidents"):
                self.assertEqual(conn.execute(f"SELECT id FROM {table} ORDER BY id").fetchall(), [(1,), (3,)])
            self.assertEqual([key for key, in conn.execute(
                "SELECT key FROM config WHERE key LIKE 'journal%' ORDER BY key"
            )], ["journal:incident_end:42:3", "journal:incident_start:42:1",
                 "journal:null", "journal:partial_start:42:1", "journal;keep"])
        database.close_db()
        self.assertEqual(database.get_config("last_cleanup_at"), str(NOW))

    def test_cleanup_releases_writer_with_300000_expired_journal_keys(self):
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO config(key, value) VALUES (?, '1')",
                             ((f"journal:partial_end:42:{i:06d}",) for i in range(300_000)))
        holds = []
        lock = database._write_lock

        class TimedLock:
            def __enter__(self):
                lock.acquire()
                self.start = time.perf_counter()

            def __exit__(self, *exc):
                holds.append(time.perf_counter() - self.start)
                lock.release()

        with patch.object(database, "_write_lock", TimedLock()):
            database.cleanup_old_records()
        self.assertLess(max(holds), 0.100, f"Longest write lock hold: {max(holds):.3f} s")
        self.assertGreaterEqual(len(holds), 300)
        with database._writer_transaction() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM config WHERE key LIKE 'journal:%'").fetchone(), (0,))

    async def run_scheduler(self, ticks, cleanup):
        sleep = asyncio.sleep
        self.clock.return_value, *remaining = ticks

        async def advance(_):
            await sleep(0)
            if not remaining:
                raise asyncio.CancelledError
            self.clock.return_value = remaining.pop(0)

        async def run_db(fn, *args):
            if fn is database.cleanup_old_records:
                return cleanup(*args)
            return fn(*args)

        clock = Mock(time=self.clock, monotonic=lambda: self.clock.return_value - NOW)
        with (patch.multiple(bot, time=clock, run_db=run_db, dc_bot_instance=None, _host_outage_active=False,
                             _scheduler_cache={"resources": [], "resources_ts": NOW, "probe_targets": [],
                                               "probe_targets_ts": NOW, "ttl": 10},
                             _check_report_notices=AsyncMock(), push_status_apps=AsyncMock(),
                             realtime_status_tick=AsyncMock(), _broadcast_peer_updates=AsyncMock(),
                             audit_abandoned_chats=AsyncMock(), last_peer_telemetry_broadcast=NOW),
              patch.object(asyncio, "sleep", advance), self.assertRaises(asyncio.CancelledError)):
            await bot.monitoring_scheduler_loop()
        database.close_db()

    def test_scheduler_skips_recent_cleanup_after_restart(self):
        runs = []

        def cleanup(*args):
            runs.append(self.clock.return_value)
            return database.cleanup_old_records(*args)

        for ticks in ((NOW,), (NOW + 19 * 3600, NOW + 20 * 3600, NOW + DAY), (NOW + 45 * 3600,)):
            asyncio.run(self.run_scheduler(ticks, cleanup))
        self.assertEqual(runs, [NOW, NOW + DAY, NOW + 45 * 3600])

    def test_scheduler_runs_cleanup_after_wall_clock_steps_back(self):
        database.set_config("last_cleanup_at", str(NOW + 3600))
        cleanup = Mock(wraps=database.cleanup_old_records)
        asyncio.run(self.run_scheduler((NOW, NOW + 5), cleanup))
        cleanup.assert_called_once_with(90)
        self.assertEqual(database.get_last_cleanup_at(), NOW)

    def test_scheduler_retries_failed_cleanup_and_only_persists_success(self):
        previous = NOW - 21 * 3600
        database.set_config("last_cleanup_at", str(previous))
        runs = []

        def cleanup(*args):
            runs.append(self.clock.return_value)
            self.assertEqual(database.get_last_cleanup_at(), previous)
            if len(runs) == 1:
                with patch.object(database, "_clear_disabled_peer_rt", side_effect=RuntimeError("cleanup failed")):
                    return database.cleanup_old_records(*args)
            return database.cleanup_old_records(*args)

        with self.assertLogs(bot.logger, level="ERROR"):
            asyncio.run(self.run_scheduler((NOW, NOW + 5, NOW + 599, NOW + 600, NOW + 605), cleanup))
        self.assertEqual(runs, [NOW, NOW + 600])
        self.assertEqual(database.get_last_cleanup_at(), NOW + 600)

    def test_rename_during_probe_only_save_keeps_all_local_rows(self):
        node = database.get_local_node_name()
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO peer_measurements(url, node_name, received_at, source_peer) VALUES (?, ?, ?, ?)",
                             ((f"https://local-{i}.example.org", node, NOW, node) for i in range(1001)))

        async def run_db(fn, *args, **kwargs):
            if fn is database.update_probe_target_result:
                event = Mock(payload="New local")
                with patch.object(bot, "_is_dc_admin", return_value=True), patch.object(bot, "_dc_send_msg_with_stats"):
                    bot.nodename_command(Mock(), 1, event)
            return fn(*args, **kwargs)

        group = [{"url": "https://probe.example.org", "is_probe_only": True, "last_status": "up"}]
        with (patch.object(bot, "run_db", run_db), patch.object(bot, "_count_check"),
              patch.object(bot, "check_network_probe", AsyncMock(return_value=(True, None, 22)))):
            asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
        rows = database.get_all_peer_measurements()
        self.assertEqual(len(rows), 1002)
        self.assertEqual({row["node_name"] for row in rows}, {"New local"})
        self.assertEqual({row["source_peer"] for row in rows}, {None})

    def test_nodename_refuses_a_case_insensitive_peer_name_collision(self):
        database.add_or_update_peer("remote@example.org", "Remote", 42)
        original = database.get_local_node_name()
        event = Mock(payload="remote")
        with (patch.object(bot, "_is_dc_admin", return_value=True),
              patch.object(bot, "_dc_send_msg_with_stats") as reply):
            bot.nodename_command(Mock(), 1, event)
        self.assertEqual(database.get_local_node_name(), original)
        self.assertIn("already used by a peer", reply.call_args.args[3].text)

    def test_legacy_peer_name_collision_cannot_replace_local_measurement(self):
        database.add_or_update_peer("remote@example.org", "Remote", 42)
        database.set_config("node_name", "Remote")
        url = "https://shared.example.org"
        database.record_check_results([], (url, "Remote", "up", 22, None))
        database.save_peer_measurement(url, "Remote", "down", source_peer="remote@example.org")
        self.assertEqual([(row["status"], row["source_peer"]) for row in database.get_peer_measurements_for_url(url)],
                         [("up", None)])

    def test_probe_updates_keep_all_local_measurements(self):
        node = database.get_local_node_name()
        local_urls = [f"https://local-{i}.example.org" for i in range(10_000)]
        for url in local_urls:
            database.record_check_results([], (url, node, "up", 22, None))
        for i in range(4_000):
            database.save_peer_measurement(f"https://probe-{i}.example.org", node, "up", 22)
        urls = {row["url"] for row in database.get_all_peer_measurements() if row["node_name"] == node}
        self.assertEqual(len(urls), 14_000)
        self.assertTrue(set(local_urls).issubset(urls))

    def test_remote_measurements_only_prune_above_quota(self):
        source = "A" * 40
        traces = []
        with database._writer_transaction() as conn:
            conn.set_trace_callback(traces.append)
        try:
            batch = [{"url": f"https://remote-{i}.example.org", "status": "up"} for i in range(200)]
            database.save_peer_measurements_batch("Peer", batch, source)
            for item in batch:
                database.save_peer_measurement(item["url"], "Peer", "up", source_peer=source)
            self.assertFalse(any("DELETE FROM peer_measurements" in sql for sql in traces))
        finally:
            with database._writer_transaction() as conn:
                conn.set_trace_callback(None)
        for batch_number in range(1, 6):
            batch = [{"url": f"https://remote-{batch_number}-{i}.example.org", "status": "up"} for i in range(200)]
            database.save_peer_measurements_batch("Peer", batch, source)
        database.save_peer_measurement("https://latest.example.org", "Peer", "up", source_peer=source)
        rows = database.get_all_peer_measurements()
        self.assertEqual(len(rows), 1_000)
        self.assertTrue(all(row["source_peer"] == source for row in rows))
        self.assertIn("https://latest.example.org", {row["url"] for row in rows})


class CacheLoadTests(unittest.IsolatedAsyncioTestCase):
    def test_dns_storm_keeps_second_pass_hits(self):
        self.enterContext(patch.object(bot, "_dns_cache", OrderedDict()))
        hosts = [f"host-{i}.example.org" for i in range(12_000)]
        addresses = ("192.0.2.1",)
        for host in hosts:
            bot._dns_cache_put(host, addresses, 60)
        self.assertEqual(sum(bot._dns_cache_get(host) == addresses for host in hosts), 12_000)
        for i in range(len(hosts), 50_000):
            bot._dns_cache_put(f"host-{i}.example.org", addresses, 60)
        self.assertEqual(bot._dns_cache_get(hosts[0]), addresses)
        bot._dns_cache_put("extra.example.org", addresses, 60)
        self.assertEqual(len(bot._dns_cache), 50_000)
        self.assertEqual(bot._dns_cache_get(hosts[0]), addresses)
        self.assertIsNone(bot._dns_cache_get(hosts[1]))

    def test_dns_capacity_reclaims_expired_entries_before_evicting_live_ones(self):
        addresses = ("192.0.2.1",)

        class CountingCache(OrderedDict):
            sweeps = 0

            def items(self):
                self.sweeps += 1
                return super().items()

        cache = CountingCache()
        with (patch.object(bot, "_dns_cache", cache), patch.object(bot, "DNS_CACHE_MAX_ENTRIES", 3),
              patch.object(bot, "_dns_cache_sweep_at", 0.0, create=True),
              patch.object(bot.time, "monotonic", return_value=100.0) as clock):
            bot._dns_cache_put("live-oldest", addresses, 300)
            bot._dns_cache_put("expires", addresses, 30)
            bot._dns_cache_put("live-newer", addresses, 300)
            self.assertEqual(bot._dns_cache_get("expires"), addresses)
            clock.return_value = 131.0
            bot._dns_cache_put("new", addresses, 300)
            self.assertEqual(list(bot._dns_cache), ["live-oldest", "live-newer", "new"])
            bot._dns_cache_put("newest", addresses, 300)
            self.assertEqual(list(bot._dns_cache), ["live-newer", "new", "newest"])
            self.assertEqual(cache.sweeps, 1)

    async def test_vote_cache_promotes_on_write_only(self):
        self.enterContext(patch.object(bot, "_vote_cache", OrderedDict()))
        requests = 0

        async def remote(*args, **kwargs):
            nonlocal requests
            requests += 1
            return []

        self.enterContext(patch.object(bot, "request_peer_cross_checks_batched", remote))
        targets = [{"url": f"https://vote-{i}.example.org"} for i in range(20_001)]
        for target in targets[:-1]:
            await bot.collect_peer_votes(target, True)
        await bot.collect_peer_votes(targets[0], True)
        self.assertEqual(requests, 20_000)
        await bot.collect_peer_votes(targets[1], True, fresh=True)
        await bot.collect_peer_votes(targets[-1], True)
        self.assertEqual(len(bot._vote_cache), 20_000)
        self.assertNotIn(bot._cross_check_key(targets[0]), bot._vote_cache.keys())
        self.assertIn(bot._cross_check_key(targets[1]), bot._vote_cache.keys())

    async def test_routine_up_check_does_not_promote_cached_vote(self):
        oldest = {"id": 1, "dc_chat_id": 42, "url": "https://oldest.example.org", "name": "Oldest",
                  "status": "up", "alert_state": "up"}
        newest = {"url": "https://newest.example.org"}
        keys = list(map(bot._cross_check_key, (oldest, newest)))
        cache = OrderedDict((key, object()) for key in keys)
        with (patch.object(bot, "_vote_cache", cache), patch.object(bot, "run_db", AsyncMock()),
              patch.object(bot, "_take_peer_suspect", return_value=None), patch.object(bot, "_count_check"),
              patch.object(bot, "check_network_probe", AsyncMock(return_value=(True, None, 22)))):
            await bot.check_group_task([oldest], asyncio.Semaphore(1))
        self.assertEqual(list(cache), keys)
