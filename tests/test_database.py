import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database

TEST_DB = "test_uptime_db.db"


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


if __name__ == "__main__":
    unittest.main()
