import os
import tempfile
import threading
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_journal_connections import CountConnections

import bot
import database


class DatabaseFixture:
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        database.close_db()
        self.enterContext(patch.object(database, "DB_PATH", str(Path(directory) / "uptime.db")))
        self.addCleanup(database.close_db)
        database.init_db()


class TestDownPeerConnections(DatabaseFixture, unittest.IsolatedAsyncioTestCase):
    async def test_seven_down_peers_check_at_most_twelve_times_per_minute(self):
        seconds = 0
        clock = SimpleNamespace(time=lambda: 1_800_000_000 + seconds, monotonic=lambda: seconds)
        self.enterContext(patch.multiple(bot, time=clock, _peer_rt_links={}, _peer_rt_leaves=set(),
                                         _peer_rt_carrier_ids=set(), _peer_rt_pending_adverts=set(), stat_event=Mock()))
        self.enterContext(patch.multiple(database, time=clock, _peer_traffic_buffer={}, _mail_kind_buffer={}))
        self.enterContext(patch.object(bot.secrets, "randbelow", return_value=0))
        client = Mock()

        async def run_rpc(func, *args):
            return func(*args)

        self.enterContext(patch.object(bot, "run_rpc", run_rpc))
        database.set_peer_rt_flag("on")
        for msg_id in range(1, 8):
            fp = f"{msg_id:040X}"
            database.add_or_update_peer(f"peer{msg_id}@example.org", f"Peer {msg_id}", msg_id, fingerprint=fp)
            database.set_peer_rt_capability(fp, True)
            database.set_peer_rt(fingerprint=fp, cid="ab" * 8, msg_id=msg_id, key_out=b"a" * 32,
                                 key_in=b"b" * 32, created_at=int(clock.time()))
        database.audit_peers_offline(threshold_seconds=1, now=int(clock.time()) + 2)
        bot._refresh_peer_rt_channels()
        self.assertEqual(len(bot._peer_rt_links), 7)
        await bot._tick_peer_rt(client, 1)
        client.rpc.send_webxdc_realtime_advertisement.reset_mock()

        seconds = bot.PEER_RT_REJOIN_DELAYS[0]
        with CountConnections() as connections:
            dispatches, reads = Counter(), Counter()

            async def run_db(func, *args):
                msg_id = args[0]
                dispatches[msg_id] += 1
                before = connections.calls
                result = func(*args)
                reads[msg_id] += connections.calls - before
                return result

            with patch.object(bot, "run_db", run_db):
                for _ in range(10):
                    dispatches.clear()
                    reads.clear()
                    minute_start = connections.calls
                    for _ in range(60):
                        await bot._tick_peer_rt(client, 1)
                        seconds += 1
                    for msg_id in bot._peer_rt_links:
                        self.assertLessEqual(dispatches[msg_id], 12, f"dispatches for link {msg_id}")
                        self.assertLessEqual(reads[msg_id], 12, f"connections for link {msg_id}")
                    self.assertLessEqual(connections.calls - minute_start, 7 * 12)
        client.rpc.send_webxdc_realtime_advertisement.assert_not_called()

        await bot._tick_peer_rt(client, 1)  # Check just before the peer returns.
        seconds += 1
        database.update_peer_last_seen("peer1@example.org")
        for _ in range(6):
            await bot._tick_peer_rt(client, 1)
            if client.rpc.send_webxdc_realtime_advertisement.called:
                break
            seconds += 1
        client.rpc.send_webxdc_realtime_advertisement.assert_called_once_with(1, 1)


class TestLocalNodeNameConnections(DatabaseFixture, unittest.TestCase):
    def test_thousand_node_name_calls_use_one_connection_and_see_renames(self):
        with patch.dict(os.environ, {"NODE_NAME": "Fallback"}), CountConnections() as connections:
            for _ in range(1000):
                self.assertEqual(database.get_local_node_name(), "Fallback")
            self.assertLessEqual(connections.calls, 1)
            database.set_local_node_name("X")
            self.assertEqual(database.get_local_node_name(), "X")
            self.assertLessEqual(connections.calls, 2)
            database.set_config("node_name", "Y")
            self.assertEqual(database.get_local_node_name(), "Y")

    def test_empty_node_name_uses_current_environment_fallback(self):
        database.set_local_node_name("X")
        self.assertEqual(database.get_local_node_name(), "X")
        database.set_config("node_name", "")
        for fallback in ("Fallback", "New fallback"):
            with patch.dict(os.environ, {"NODE_NAME": fallback}):
                self.assertEqual(database.get_local_node_name(), fallback)

    def test_close_db_invalidates_node_name_cache(self):
        database.set_local_node_name("X")
        self.assertEqual(database.get_local_node_name(), "X")
        database.close_db()
        with CountConnections() as connections:
            self.assertEqual(database.get_local_node_name(), "X")
            self.assertEqual(connections.calls, 1)

    def test_rename_during_node_name_read_discards_old_value(self):
        database.set_local_node_name("X")
        read_old_name, renamed = threading.Event(), threading.Event()
        get_config = database.get_config

        def pause_after_read(key):
            name = get_config(key)
            if name == "X":
                read_old_name.set()
                self.assertTrue(renamed.wait(timeout=5))
            return name

        with patch.object(database, "get_config", side_effect=pause_after_read), ThreadPoolExecutor(2) as pool:
            reader = pool.submit(database.get_local_node_name)
            try:
                self.assertTrue(read_old_name.wait(timeout=5))
                pool.submit(database.set_local_node_name, "Y").result(timeout=5)
            finally:
                renamed.set()
            self.assertEqual(reader.result(timeout=5), "Y")
        self.assertEqual(database.get_local_node_name(), "Y")

    def test_node_name_cache_follows_database_path_and_reinitialization(self):
        database.set_local_node_name("First")
        other_path = str(Path(database.DB_PATH).with_name("other.db"))
        with patch.object(database, "DB_PATH", other_path):
            database.init_db()
            database.set_local_node_name("Other")
        self.assertEqual(database.get_local_node_name(), "First")
        with patch.object(database, "DB_PATH", other_path):
            self.assertEqual(database.get_local_node_name(), "Other")
            with database._writer_transaction() as conn:
                conn.execute("UPDATE config SET value = 'Reinitialized' WHERE key = 'node_name'")
            database.init_db()
            self.assertEqual(database.get_local_node_name(), "Reinitialized")


class TestPeerLastSeenUpdates(DatabaseFixture, unittest.TestCase):
    email = "peer@example.org"
    fingerprint = "AB" * 20

    def setUp(self):
        super().setUp()
        database.add_or_update_peer(self.email, "Peer", 1, fingerprint=self.fingerprint)

    def test_hint_keeps_latest_timestamp(self):
        database.update_peer_last_seen(self.email, 200)
        database.update_peer_last_seen(self.email, 100)
        self.assertEqual(database.peer_last_seen_update(self.fingerprint), 200)
        database.update_peer_last_seen(None, 300, fingerprint=self.fingerprint, chat_id=1)
        self.assertEqual(database.peer_last_seen_update(self.fingerprint), 300)

    def test_removing_peer_clears_hint_and_late_update_cannot_recreate_it(self):
        database.update_peer_last_seen(self.email, 100)
        self.assertEqual(database.peer_last_seen_update(self.fingerprint), 100)
        self.assertTrue(database.remove_peer(self.fingerprint))
        self.assertIsNone(database.peer_last_seen_update(self.fingerprint))
        database.update_peer_last_seen(self.email, 200)
        self.assertIsNone(database.peer_last_seen_update(self.fingerprint))

    def test_init_and_close_discard_peer_hints(self):
        for reset in (database.init_db, database.close_db):
            with self.subTest(reset=reset.__name__):
                database.update_peer_last_seen(self.email, 100)
                self.assertEqual(database.peer_last_seen_update(self.fingerprint), 100)
                reset()
                self.assertIsNone(database.peer_last_seen_update(self.fingerprint))
