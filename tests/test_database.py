from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import gc
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import Mock, PropertyMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database

TEST_DB = "test_uptime_db.db"


class TestReadConnections(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(TemporaryDirectory())
        self.path = Path(temp) / "readers.db"
        self.enterContext(patch.object(database, "DB_PATH", self.path))
        self.addCleanup(database.close_db)
        self.seed(self.path, "first")

    def seed(self, path, value):
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO config VALUES ('key', ?)", (value,))

    def test_reuses_one_connection_per_thread_and_closes_on_thread_exit(self):
        def read_config():
            for _ in range(1000):
                self.assertEqual(database.get_config("key"), "first")

        with patch.object(sqlite3, "connect", wraps=sqlite3.connect) as connect:
            read_config()
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(read_config).result()
            self.assertEqual(connect.call_count, 2)
            self.assertEqual(len(database._readers), 1)

    def test_file_replacement_and_path_change(self):
        self.assertEqual(database.get_config("key"), "first")
        with closing(database._connect()) as conn:
            original = conn.cursor().connection
        replacement = self.path.with_name("replacement.db")
        self.seed(replacement, "second")
        replacement.replace(self.path)
        self.assertEqual(database.get_config("key"), "second")
        with self.assertRaises(sqlite3.ProgrammingError):
            original.execute("SELECT 1")
        other = self.path.with_name("other.db")
        self.seed(other, "third")
        with patch.object(database, "DB_PATH", other):
            self.assertEqual(database.get_config("key"), "third")
        self.assertEqual(database.get_config("key"), "second")

    def test_replacement_retires_other_threads_and_writer_before_opening(self):
        def raw_reader():
            with closing(database._connect()) as conn:
                return conn.cursor().connection

        database.set_config("key", "old WAL")
        with ThreadPoolExecutor(max_workers=1) as executor:
            idle = executor.submit(raw_reader).result()
            self.assertEqual(idle.execute("SELECT value FROM config").fetchone(), ("old WAL",))
            self.assertEqual(database._get_writer_conn().execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
            replacement = self.path.with_name("replacement.db")
            self.seed(replacement, "second")
            with closing(sqlite3.connect(replacement)) as conn:
                conn.execute("PRAGMA journal_mode = WAL").fetchall()
                self.assertEqual(conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
            replacement.replace(self.path)

            self.assertEqual(database.get_config("key"), "second")
            with self.assertRaises(sqlite3.ProgrammingError):
                idle.execute("SELECT 1")
            self.assertEqual(executor.submit(database.get_config, "key").result(), "second")
            database.set_config("key", "written after replacement")
            self.assertEqual(database.get_config("key"), "written after replacement")

    def test_writer_reopens_after_same_path_replacement_without_a_read(self):
        database.set_config("old", "value")
        self.assertEqual(database._get_writer_conn().execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
        replacement = self.path.with_name("replacement.db")
        self.seed(replacement, "second")
        replacement.replace(self.path)
        database.set_config("new", "value")
        self.assertEqual(database.get_config("key"), "second")
        self.assertEqual(database.get_config("new"), "value")
        self.assertIsNone(database.get_config("old"))

    def test_replacement_defers_reopening_until_active_readers_release(self):
        replacement = self.path.with_name("replacement.db")
        self.seed(replacement, "second")
        with closing(database._connect()) as conn:
            self.assertEqual(conn.execute("SELECT value FROM config").fetchone(), ("first",))
            replacement.replace(self.path)
            with self.assertRaisesRegex(sqlite3.OperationalError, "active readers"):
                database._connect()
            self.assertEqual(conn.execute("SELECT value FROM config").fetchone(), ("first",))
        self.assertEqual(database.get_config("key"), "second")

    def test_replacement_rejects_a_nonempty_wal_left_at_the_path(self):
        database.set_config("key", "old WAL")
        replacement = self.path.with_name("replacement.db")
        self.seed(replacement, "second")
        with closing(sqlite3.connect(replacement)) as conn:
            conn.execute("PRAGMA journal_mode = WAL").fetchall()
        replacement.replace(self.path)
        with self.assertRaisesRegex(sqlite3.OperationalError, "nonempty WAL"):
            database._connect()
        with self.assertRaisesRegex(sqlite3.OperationalError, "nonempty WAL"):
            database.set_config("key", "also blocked")
        with closing(sqlite3.connect(f"file:{self.path}?immutable=1", uri=True)) as conn:
            self.assertEqual(conn.execute("SELECT value FROM config").fetchone(), ("second",))

    def test_nested_checkout_and_write_protection(self):
        with closing(database._connect()) as conn:
            conn.row_factory = sqlite3.Row
            with closing(database._connect()) as nested:
                self.assertEqual(nested.execute("SELECT value FROM config").fetchone(), ("first",))
                self.assertEqual(nested.execute("PRAGMA query_only").fetchone(), (0,))
            self.assertIs(conn.row_factory, sqlite3.Row)
            with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                conn.execute("UPDATE config SET value = 'bad'")
        with closing(database._connect()) as conn:
            self.assertIsNone(conn.row_factory)
            self.assertEqual(conn.execute("PRAGMA query_only").fetchone(), (1,))
            self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone(), (5000,))
            self.assertEqual(conn.execute("PRAGMA cache_size").fetchone(), (-2000,))

    def test_closing_releases_implicit_and_explicit_read_snapshots(self):
        with closing(sqlite3.connect(self.path)) as writer, writer:
            writer.execute("PRAGMA journal_mode = WAL").fetchall()
            writer.execute("INSERT INTO config VALUES ('second', 'extra')")
        for begin in (False, True):
            with self.subTest(begin=begin), closing(sqlite3.connect(self.path)) as writer:
                with closing(database._connect()) as conn:
                    if begin:
                        conn.execute("BEGIN")
                    cursor = conn.execute("SELECT value FROM config ORDER BY key")
                    self.assertEqual(cursor.fetchone(), ("first",))
                with self.assertRaises(sqlite3.ProgrammingError):
                    cursor.fetchone()
                writer.execute("UPDATE config SET value = 'new' WHERE key = 'key'")
                writer.commit()
                writer.execute("PRAGMA busy_timeout = 0")
                self.assertEqual(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
                self.assertEqual(database.get_config("key"), "new")
                writer.execute("UPDATE config SET value = 'first' WHERE key = 'key'")
                writer.commit()

    def test_close_db_closes_connections_in_all_threads(self):
        def raw_reader():
            with closing(database._connect()) as conn:
                return conn.cursor().connection

        with ThreadPoolExecutor(max_workers=1) as executor:
            connections = [raw_reader(), executor.submit(raw_reader).result()]
            self.assertIsNot(*connections)
            database.close_db()
            for conn in connections:
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")
            self.assertEqual(executor.submit(database.get_config, "key").result(), "first")

    def test_close_db_leaves_a_running_query_to_its_owner(self):
        # Isolate the old behavior: closing across threads can crash the interpreter.
        script = """
import resource
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Event
import database

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
database.DB_PATH = sys.argv[1]
entered = Event()
resume = Event()

def wait_for_close():
    entered.set()
    assert resume.wait(5)
    return 42

def read():
    with closing(database._connect()) as conn:
        raw = conn.cursor().connection
        conn.create_function("wait_for_close", 0, wait_for_close)
        assert conn.execute("SELECT wait_for_close() FROM config").fetchall() == [(42,)]
    try:
        raw.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return
    raise AssertionError("retired reader is still open")

with ThreadPoolExecutor(max_workers=2) as executor:
    query = executor.submit(read)
    assert entered.wait(5)
    try:
        executor.submit(database.close_db).result(5)
    finally:
        resume.set()
    query.result(5)
"""
        result = subprocess.run([sys.executable, "-c", script, str(self.path)], capture_output=True, text=True,
                                cwd=Path(database.__file__).parent, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_close_db_continues_after_an_idle_reader_close_fails(self):
        def raw_reader():
            with closing(database._connect()) as conn:
                return conn.cursor().connection

        raw = raw_reader()
        reader = database._thread_reader.reader
        with ThreadPoolExecutor(max_workers=1) as executor:
            other = executor.submit(raw_reader).result()
            with patch.object(reader, "close", side_effect=sqlite3.OperationalError("close failed")):
                database.close_db()
            self.assertEqual(len(database._readers), 0)
            with self.assertRaises(sqlite3.ProgrammingError):
                other.execute("SELECT 1")
        raw.close()

    def test_leaked_checkout_releases_snapshot_and_restores_pool_after_gc(self):
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute("PRAGMA journal_mode = WAL").fetchall()
            writer.execute("INSERT INTO config VALUES ('second', 'extra')")
            writer.commit()

            def fail_before_cleanup():
                conn = database._connect()
                conn.row_factory = sqlite3.Row
                cursors.append(conn.execute("SELECT value FROM config ORDER BY key"))
                self.assertEqual(cursors[-1].fetchone()[0], "first")
                raise RuntimeError("before cleanup")

            cursors = []
            try:
                fail_before_cleanup()
            except RuntimeError as error:
                self.assertEqual(str(error), "before cleanup")
            gc.collect()

            writer.execute("UPDATE config SET value = 'new' WHERE key = 'key'")
            writer.commit()
            writer.execute("PRAGMA busy_timeout = 0")
            self.assertEqual(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
            with closing(database._connect()) as conn:
                self.assertIsNone(conn.row_factory)
                self.assertEqual(conn.execute("PRAGMA query_only").fetchone(), (1,))
                self.assertEqual(conn.execute("SELECT value FROM config WHERE key = 'key'").fetchone(), ("new",))

    def test_failed_row_factory_assignment_closes_checkout(self):
        conn = Mock()
        row_factory = PropertyMock(side_effect=RuntimeError("setting row factory failed"))
        with (patch.object(type(conn), "row_factory", row_factory, create=True),
              patch.object(database, "_connect", return_value=conn),
              self.assertRaisesRegex(RuntimeError, "setting row factory failed")):
            database.get_resources(1)
        conn.close.assert_called_once()

    def test_rollback_failure_discards_reader_and_restores_pool(self):
        conn = database._connect()
        reader = database._thread_reader.reader
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        raw = conn.cursor().connection
        conn.set_authorizer(lambda action, operation, *_:
                            sqlite3.SQLITE_DENY if (action, operation) == (sqlite3.SQLITE_TRANSACTION, "ROLLBACK")
                            else sqlite3.SQLITE_OK)
        conn.close()
        self.assertIsNone(raw.row_factory)
        self.assertFalse(reader.lease.locked())
        with self.assertRaises(sqlite3.ProgrammingError):
            raw.execute("SELECT 1")
        with closing(database._connect()) as next_conn:
            self.assertEqual(next_conn.execute("PRAGMA query_only").fetchone(), (1,))

    def test_slow_reader_open_does_not_stall_other_checkouts_or_closes(self):
        entered = threading.Event()
        resume = threading.Event()
        original_open = database._open_reader
        slow_connections = []

        def slow_open(*args, **kwargs):
            slow = threading.current_thread().name.startswith("slow_reader")
            if slow:
                entered.set()
                self.assertTrue(resume.wait(10))
            conn = original_open(*args, **kwargs)
            if slow:
                slow_connections.append(conn)
            return conn

        with (ThreadPoolExecutor(max_workers=1, thread_name_prefix="slow_reader") as slow,
              ThreadPoolExecutor(max_workers=1) as warm,
              patch.object(database, "_open_reader", slow_open)):
            self.assertEqual(warm.submit(database.get_config, "key").result(3), "first")
            query = slow.submit(database.get_config, "key")
            self.assertTrue(entered.wait(3))
            try:
                self.assertEqual(warm.submit(database.get_config, "key").result(3), "first")
                warm.submit(database.close_db).result(3)
                self.assertEqual(warm.submit(database.get_config, "key").result(3), "first")
            finally:
                resume.set()
            self.assertEqual(query.result(3), "first")
            self.assertEqual(len(slow_connections), 2)
            with self.assertRaises(sqlite3.ProgrammingError):
                slow_connections[0].execute("SELECT 1")

    def test_inflight_open_does_not_recreate_a_removed_database(self):
        other = self.path.with_name("other.db")
        self.seed(other, "second")
        entered = threading.Event()
        resume = threading.Event()
        original_open = database._open_reader

        def slow_open(path, *args, **kwargs):
            if Path(path) == self.path:
                entered.set()
                self.assertTrue(resume.wait(5))
            return original_open(path, *args, **kwargs)

        with (ThreadPoolExecutor(max_workers=1) as executor,
              patch.object(database, "_open_reader", slow_open)):
            query = executor.submit(database.get_config, "key")
            self.assertTrue(entered.wait(3))
            self.path.unlink()
            with patch.object(database, "DB_PATH", other):
                resume.set()
                self.assertEqual(query.result(3), "second")
            self.assertFalse(self.path.exists())


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        database.invalidate_uptime_cache()
        with database._transport_stats_lock:
            database._transport_stats_buffer.clear()

    def tearDown(self):
        database.close_db()
        database.invalidate_uptime_cache()
        with database._transport_stats_lock:
            database._transport_stats_buffer.clear()
        database.DB_PATH = self.orig_db
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except OSError:
                pass
        for suffix in ["-wal", "-shm"]:
            fpath = TEST_DB + suffix
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    def test_database_indexes_created(self):
        """Verify that all performance and scaling indexes are created in init_db."""
        conn = database._connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
            indexes = {row[0] for row in cursor.fetchall()}
        finally:
            conn.close()

        expected_indexes = [
            "idx_downtime_resource",
            "idx_downtime_went_down",
            "idx_downtime_went_up",
            "idx_downtime_resource_range",
            "idx_downtime_incident",
            "idx_incidents_chat",
            "idx_incidents_status",
            "idx_incidents_chat_status",
            "idx_incidents_resolved",
            "idx_resources_chat_status",
            "idx_resources_url",
            "idx_resources_status",
            "idx_peers_chat",
            "idx_peers_last_seen",
            "idx_peer_measurements_url",
            "idx_peer_meas_checked",
        ]
        for idx in expected_indexes:
            self.assertIn(idx, indexes, f"Index {idx} was not found in database")

    def test_config_roundtrip(self):
        self.assertIsNone(database.get_config("nonexistent_key"))
        database.set_config("key1", "val1")
        self.assertEqual(database.get_config("key1"), "val1")
        database.set_config("key1", "val2")
        self.assertEqual(database.get_config("key1"), "val2")

    def test_admin_email_normalization(self):
        self.assertIsNone(database.get_admin_email())
        database.set_admin_email("  ADMIN@Example.COM  ")
        self.assertEqual(database.get_admin_email(), "admin@example.com")

    def test_admin_fingerprint_handling(self):
        self.assertIsNone(database.get_admin_fingerprint())
        database.set_admin_fingerprint("aa:bb:cc:dd:11:22:33:44:55:66:77:88:99:00:11:22")
        self.assertEqual(database.get_admin_fingerprint(), "AABBCCDD112233445566778899001122")

    def test_batch_uptime_calculation_and_cache(self):
        """Test batch 30d uptime calculation and verify TTL caching."""
        chat_id = 999
        r1 = database.add_resource(chat_id, "https://r1.example.com", "R1", "http")
        r2 = database.add_resource(chat_id, "https://r2.example.com", "R2", "http")
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)

        # Brand new resources should both have 100.0% uptime
        results = database.get_resources_uptime_30d([r1, r2])
        self.assertEqual(results[r1], 100.0)
        self.assertEqual(results[r2], 100.0)

        # Cache should now be populated
        with database._uptime_cache_lock:
            self.assertIn(r1, database._uptime_cache)
            self.assertIn(r2, database._uptime_cache)

        # Single getter should use cache
        self.assertEqual(database.get_resource_uptime_30d(r1), 100.0)
        self.assertEqual(database.get_chat_uptime_30d(chat_id), 100.0)

    def test_uptime_cache_invalidation_on_status_change(self):
        """Status change (transition to DOWN) must invalidate cached uptime."""
        chat_id = 998
        r_id = database.add_resource(chat_id, "https://inv.example.com", "Inv", "http")
        
        # Populate cache
        u1 = database.get_resource_uptime_30d(r_id)
        self.assertEqual(u1, 100.0)
        with database._uptime_cache_lock:
            self.assertIn(r_id, database._uptime_cache)

        # Transition to DOWN
        database.update_resource_status(r_id, "down", 1, error_msg="Timeout")

        # Cache must be invalidated for this resource
        with database._uptime_cache_lock:
            self.assertNotIn(r_id, database._uptime_cache)

    def test_batch_update_resource_status(self):
        """Verify batch_update_resource_status correctly updates multiple resources in one transaction."""
        chat_id = 997
        r1 = database.add_resource(chat_id, "https://b1.com", "B1", "http")
        r2 = database.add_resource(chat_id, "https://b2.com", "B2", "http")

        updates = [
            {"id": r1, "status": "up", "consecutive_failures": 0, "error_msg": None, "latency_ms": 42},
            {"id": r2, "status": "down", "consecutive_failures": 1, "error_msg": "Connection refused", "latency_ms": None},
        ]
        database.batch_update_resource_status(updates)

        res1 = database.get_resource_by_id(r1)
        res2 = database.get_resource_by_id(r2)

        self.assertEqual(res1["status"], "up")
        self.assertEqual(res1["last_latency_ms"], 42)
        self.assertEqual(res2["status"], "down")
        self.assertEqual(res2["consecutive_failures"], 1)

    def test_delete_resource_invalidates_cache(self):
        chat_id = 996
        r_id = database.add_resource(chat_id, "https://del.com", "Del", "http")
        database.get_resource_uptime_30d(r_id)

        with database._uptime_cache_lock:
            self.assertIn(r_id, database._uptime_cache)

        database.delete_resource(chat_id, r_id)
        with database._uptime_cache_lock:
            self.assertNotIn(r_id, database._uptime_cache)

    def test_write_lock_backwards_compatibility(self):
        """Verify _write_lock exists and _lock is an alias to _write_lock."""
        self.assertTrue(hasattr(database, "_write_lock"))
        self.assertIs(database._lock, database._write_lock)

    def test_concurrent_read_while_write_lock_held(self):
        """Verify that reader queries execute without blocking even while _write_lock is held by another thread."""
        database.set_config("concurrency_key", "initial_value")
        chat_id = 995
        database.add_resource(chat_id, "https://concur.example.com", "Concur", "http")

        read_results = {}
        read_done = threading.Event()

        # Thread 1 holds _write_lock
        with database._write_lock:
            def reader_thread():
                # Readers should execute freely without acquiring _write_lock
                cfg = database.get_config("concurrency_key")
                res = database.get_resources(chat_id)
                read_results["config"] = cfg
                read_results["resources_count"] = len(res)
                read_done.set()

            t = threading.Thread(target=reader_thread)
            t.start()
            t.join(timeout=2.0)

        self.assertTrue(read_done.is_set(), "Reader thread was blocked by _write_lock")
        self.assertEqual(read_results["config"], "initial_value")
        self.assertEqual(read_results["resources_count"], 1)

    def test_persistent_writer_and_pragmas(self):
        """Verify writer connection is persistent and connections use synchronous=NORMAL and WAL."""
        w_conn1 = database._get_writer_conn()
        w_conn2 = database._get_writer_conn()
        self.assertIs(w_conn1, w_conn2, "Writer connection must be reused and persistent")

        # Check PRAGMAs on writer connection
        sync_mode = w_conn1.execute("PRAGMA synchronous;").fetchone()[0]
        # synchronous: 1 = NORMAL
        self.assertEqual(sync_mode, 1, "Writer connection should have synchronous=NORMAL (1)")

        j_mode = w_conn1.execute("PRAGMA journal_mode;").fetchone()[0]
        self.assertEqual(j_mode.lower(), "wal", "Writer connection should be in WAL mode")

        # Check PRAGMA on reader connection
        r_conn = database._connect()
        try:
            r_sync = r_conn.execute("PRAGMA synchronous;").fetchone()[0]
            self.assertEqual(r_sync, 1, "Reader connection should have synchronous=NORMAL (1)")
        finally:
            r_conn.close()

        # Check close_db resets writer connection
        database.close_db()
        self.assertIsNone(database._writer_conn)

    def test_http_method_database_operations(self):
        """Test setting and inheriting http_method on resources and probe_targets."""
        chat_id = 1234
        url = "https://gotosocial.example.com"
        r_id = database.add_resource(chat_id, url, "GoToSocial", "http")
        self.assertIsNotNone(r_id)

        # Initially http_method is None
        res = database.get_resource_by_id(r_id)
        self.assertIsNone(res.get("http_method"))

        # Set by resource ID
        ok = database.set_resource_http_method(r_id, "GET")
        self.assertTrue(ok)
        res = database.get_resource_by_id(r_id)
        self.assertEqual(res["http_method"], "GET")

        # Also add a probe target with the same URL
        database.save_probe_targets_batch([
            {"url": url, "name": "GTS Remote", "type": "http"}
        ], source_peer="peer@example.com")
        pts = database.get_active_probe_targets()
        pt = next((p for p in pts if p["url"] == url), None)
        self.assertIsNotNone(pt)

        # Set by URL updates both resources and probe_targets
        updated_count = database.set_url_http_method(url, "GET")
        self.assertGreaterEqual(updated_count, 2)

        res = database.get_resource_by_id(r_id)
        self.assertEqual(res["http_method"], "GET")
        pts = database.get_active_probe_targets()
        pt = next((p for p in pts if p["url"] == url), None)
        self.assertEqual(pt["http_method"], "GET")

        # Adding a new resource with the same URL inherits learned http_method
        r2_id = database.add_resource(5678, url, "GoToSocial Chat 2", "http")
        res2 = database.get_resource_by_id(r2_id)
        self.assertEqual(res2["http_method"], "GET")


if __name__ == "__main__":
    unittest.main()
