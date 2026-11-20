import asyncio
from collections import OrderedDict
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

import bot
import database
import monitor_names


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
        database.invalidate_uptime_cache()
        self.addCleanup(database.invalidate_uptime_cache)
        self.clock = self.enterContext(patch.object(database.time, "time", return_value=NOW))
        database.init_db()

    def test_incident_sync_checks_idle_chats_in_one_read(self):
        with patch.object(database, "_connect", wraps=database._connect) as read:
            asyncio.run(bot.sync_chat_incident_state(1))
        read.assert_called_once()

    def test_incident_sync_batches_active_events(self):
        resource = database.add_resource(1, "https://uptime.example", "Uptime", "http")
        incidents = [database.create_incident(1, NOW - offset) for offset in (600, 300, 100)]
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, incident_id) VALUES (?, ?, ?)",
                             [(resource, NOW - 600, incident) for incident in incidents])
        statements = []
        connect = sqlite3.connect

        def traced_connect(*args, **kwargs):
            conn = connect(*args, **kwargs)
            conn.set_trace_callback(statements.append)
            return conn

        database.close_db()
        with (patch.object(sqlite3, "connect", traced_connect),
              patch.object(database, "get_resources", wraps=database.get_resources) as resources,
              patch.object(bot, "_queue_incident_message") as queue,
              patch.object(bot, "_incident_last_edit_state", {})):
            asyncio.run(bot.sync_chat_incident_state(1))
        resources.assert_called_once_with(1, for_incident=True)
        self.assertEqual([call.args[0] for call in queue.call_args_list], incidents)
        event_queries = [sql for sql in statements if "WHERE de.incident_id" in sql]
        self.assertEqual(len(event_queries), 1)
        with closing(sqlite3.connect(database.DB_PATH)) as reader:
            plan = [row[-1] for row in reader.execute("EXPLAIN QUERY PLAN " + event_queries[0])]
        self.assertTrue(any("idx_downtime_incident_started" in node for node in plan), plan)
        self.assertFalse(any("TEMP B-TREE" in node for node in plan), plan)

    def test_legacy_unlinked_outage_still_creates_an_incident(self):
        resource = database.add_resource(1, "https://legacy.example", "Legacy", "http")
        with database._writer_transaction() as conn:
            conn.execute("INSERT INTO downtime_events(resource_id, went_down_at) VALUES (?, ?)", (resource, NOW - 300))
        with patch.object(bot, "_queue_incident_message") as queue:
            asyncio.run(bot.sync_chat_incident_state(1))
        incident = database.get_active_incident(1)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["started_at"], NOW - 300)
        self.assertEqual(database.get_incident_downtime_events(incident["id"])[0]["resource_id"], resource)
        queue.assert_called_once()

    def test_unlinked_incident_queries_use_sparse_index_on_skewed_history(self):
        monitor = database.add_resource(1, "https://legacy.example", "Legacy", "http")
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, went_up_at) VALUES (?, ?, ?)",
                             [(monitor, NOW - 60, NOW - 1)] * 20_000)
            conn.execute("ANALYZE")
        incident = database.create_incident(1, NOW)

        statements = []
        for read, expected in ((database.get_unlinked_open_downtime_events, []),
                               (database.get_incident_sync_candidates, ([incident], False))):
            with self.subTest(read=read.__name__):
                conn = sqlite3.connect(database.DB_PATH)
                conn.set_trace_callback(statements.append)
                with patch.object(database, "_connect", return_value=conn):
                    result = read(1)
                if read is database.get_incident_sync_candidates:
                    active, pending = result
                    result = ([row["id"] for row in active], pending)
                self.assertEqual(result, expected)
                with closing(database._connect()) as conn:
                    plan = [row[-1] for row in conn.execute("EXPLAIN QUERY PLAN " + statements[-1])]
                self.assertTrue(any("idx_downtime_unlinked_open" in node for node in plan), plan)

        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO resources(dc_chat_id, url) VALUES (1, ?)",
                             [(f"https://monitor-{i}.example",) for i in range(1_000)])
        steps = []
        conn = sqlite3.connect(database.DB_PATH)
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        conn.set_progress_handler(lambda: steps.append(1) or 0, 100)
        with patch.object(database, "_connect", return_value=conn):
            self.assertFalse(database.get_incident_sync_candidates(1)[1])
        self.assertLess(len(steps), 2)

        with database._writer_transaction() as conn:
            conn.execute("INSERT INTO downtime_events(resource_id, went_down_at) VALUES (?, ?)", (monitor, NOW))
        self.assertEqual([row["resource_id"] for row in database.get_unlinked_open_downtime_events(1)], [monitor])
        self.assertTrue(database.get_incident_sync_candidates(1)[1])
        self.assertEqual(database.get_incident_sync_candidates(2), ([], False))

    def test_partial_notice_pass_reads_settings_together(self):
        database.set_chat_report_partial(1, 0)
        database.set_chat_report_app(2, "only")
        rows = [dict(dc_chat_id=chat, partial_ended_at=NOW - 1) for chat in (1, 1, 2)]
        with (patch.object(bot, "_journal_partial_events"),
              patch.object(bot, "dc_outbox") as outbox,
              patch.object(database, "get_pending_partial_notices", return_value=rows),
              patch.object(database, "get_configs", wraps=database.get_configs) as read):
            asyncio.run(bot._check_report_notices())
        read.assert_called_once()
        self.assertEqual([call.kwargs["key"] for call in outbox.submit.call_args_list], [("partial", 1)])

    def test_candidate_search_skips_events_of_expired_resolved_incidents(self):
        monitor = database.add_resource(1, "https://uptime.example", "Uptime", "http")
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO incidents(id, dc_chat_id, status, started_at, resolved_at) "
                             "VALUES (?, 1, 'resolved', ?, ?)",
                             [(i, NOW - 10 * DAY, NOW - 9 * DAY) for i in range(1, 51)])
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, went_up_at, incident_id) "
                             "VALUES (?, ?, ?, ?)",
                             [(monitor, NOW - 10 * DAY, NOW - 9 * DAY, i) for i in range(1, 51)] * 100)
        recent = database.create_incident(1, NOW - 20 * DAY)
        with database._writer_transaction() as conn:
            conn.execute("INSERT INTO downtime_events(resource_id, went_down_at, went_up_at, incident_id) "
                         "VALUES (?, ?, ?, ?)", (monitor, NOW - 60, NOW - 1, recent))

        steps = []
        with closing(sqlite3.connect(database.DB_PATH)) as reader:
            reader.set_progress_handler(lambda: steps.append(1) or 0, 100)
            with patch.object(database, "_connect", return_value=reader):
                self.assertEqual(database.get_active_incident_for_outage(1, NOW)["id"], recent)
        self.assertLess(len(steps), 100)

        steps.clear()
        writer = database._get_writer_conn()
        writer.set_progress_handler(lambda: steps.append(1) or 0, 100)
        try:
            database.update_resource_status(monitor, "down", 1)
        finally:
            writer.set_progress_handler(None, 0)
        self.assertLess(len(steps), 100)
        self.assertEqual(len(database.get_incident_downtime_events(recent)), 2)

    def test_status_reads_resources_once_and_batches_incident_events(self):
        resource = database.add_resource(1, "https://uptime.example", "Uptime", "http")
        incidents = [database.create_incident(1, NOW - offset) for offset in range(21)]
        with database._writer_transaction() as conn:
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, incident_id) VALUES (?, ?, ?)",
                             [(resource, NOW - 600, incident) for incident in incidents])
        with (patch.object(database, "_connect", wraps=database._connect) as read,
              patch.object(database, "get_resources", wraps=database.get_resources) as resources):
            state = bot.build_status_state(1)
        self.assertEqual([i["id"] for i in state["incidents"]], incidents[:0:-1])
        self.assertTrue(all(i["names"] == ["Uptime"] for i in state["incidents"]))
        resources.assert_called_once_with(1)
        self.assertLessEqual(read.call_count, 7)

    def test_journal_compacts_each_monitor_label_once(self):
        name = "A long monitor label that should shrink"
        database.add_resource(1, "https://uptime.example", name, "http")
        for _ in range(5):
            database.add_chat_event(1, "test", f"{name} changed")
        short = monitor_names.short_monitor_name({"name": name})
        with patch.object(monitor_names, "short_monitor_name", wraps=monitor_names.short_monitor_name) as shorten:
            entries = database.get_recent_chat_events(1, limit=5)
        self.assertEqual([e["text"] for e in entries], [f"{short} changed"] * 5)
        shorten.assert_called_once()

    def test_status_push_batches_settings_and_uses_the_chat_name_it_just_read(self):
        database.add_resource(1, "https://uptime.example", "Uptime", "http")
        database.set_chat_report_app(1, "on")
        database.set_chat_webxdc(1, 100, "old-state", NOW - 600)
        database.set_chat_status_line(1, 101, "old-line")
        database.set_config("webxdc_app_version:1", str(bot.WEBXDC_APP_VERSION))
        database.set_config("webxdc_posted_at:1", str(NOW - 3600))
        rpc = Mock()
        rpc.get_existing_msg_ids.return_value = [100]
        rpc.get_basic_chat_info.return_value = {"name": "Renamed chat"}
        rpc.get_chat_contacts.return_value = [1, 2]
        client = Mock(rpc=rpc)
        with (patch.multiple(bot, dc_accid=1, dc_bot_instance=client, STATUS_REALTIME_CHATS=set()),
              patch.object(bot, "queue_status_app") as queue,
              patch.object(database, "get_config", wraps=database.get_config) as read):
            asyncio.run(bot.push_status_apps())
        queue.assert_called_once_with(1, client, 1)
        self.assertEqual(sum(call.args == ("webxdc_chat_name:1",) for call in read.call_args_list), 1)
        self.assertLessEqual(read.call_count, 2)

    def test_uptime_uses_end_range_and_includes_old_open_outages(self):
        monitor = database.add_resource(1, "https://uptime.example", "Uptime", "http")
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET created_at = ? WHERE id = ?", (NOW - 90 * DAY, monitor))
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, went_up_at) VALUES (?, ?, ?)",
                             [(monitor, NOW - 40 * DAY, NOW - 31 * DAY)] * 5000)
            conn.executemany("INSERT INTO downtime_events(resource_id, went_down_at, went_up_at) VALUES (?, ?, ?)", [
                (monitor, NOW - 32 * DAY, NOW - 30 * DAY),
                (monitor, NOW - 31 * DAY, NOW - 29 * DAY),
                (monitor, NOW - DAY, None),
                (monitor, NOW, None),
            ])
        steps = []
        with closing(sqlite3.connect(database.DB_PATH)) as reader:
            reader.set_progress_handler(lambda: steps.append(1) or 0, 100)
            with patch.object(database, "_connect", return_value=reader):
                self.assertEqual(database.get_resources_uptime_30d([monitor])[monitor], 28 / 30 * 100)
        self.assertLess(len(steps), 25)

    def test_partial_outage_limit_sorts_index_entries_and_preserves_ties(self):
        earlier = database.add_resource(1, "https://first.example", "First", "http")
        later = database.add_resource(1, "https://second.example", "Second", "http")
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET status = 'up' WHERE id = ?", (earlier,))
            conn.execute("UPDATE resources SET status = 'down' WHERE id = ?", (later,))
            conn.executemany("INSERT INTO partial_outages(resource_id, started_at) VALUES (?, ?)",
                             [(earlier, NOW), (later, NOW), (later, NOW)])
        statements = []
        with closing(sqlite3.connect(database.DB_PATH)) as reader:
            reader.set_trace_callback(statements.append)
            with patch.object(database, "_connect", return_value=reader):
                self.assertEqual([p["id"] for p in database.get_chat_partial_outages(1, 2)], [3, 2])
        with closing(sqlite3.connect(database.DB_PATH)) as reader:
            plan = [row[-1] for row in reader.execute("EXPLAIN QUERY PLAN " + statements[-1])]
        self.assertTrue(any("COVERING INDEX idx_partial_outages_resource_started" in node for node in plan), plan)

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
