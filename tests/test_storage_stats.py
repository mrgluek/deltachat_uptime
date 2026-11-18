import itertools
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import bot


def disk_usage(total, free):
    return bot.shutil._ntuple_diskusage(total, total - free, free)


def write_file(root, name, size):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.truncate(size)
    return path


class StorageStatsTests(unittest.TestCase):
    def setUp(self):
        folder = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(folder)
        self.data = self.root / "data"
        self.app = self.root / "app"
        self.data.mkdir()
        self.app.mkdir()

    def test_size_format(self):
        for value, expected in ((None, "n/a"), (0, "0 B"), (1023, "1023 B"),
                                (1536, "1.5 KB"), (7 * 1024**2, "7.0 MB"),
                                (3 * 1024**3, "3.0 GB"), (1024**4, "1.0 TB")):
            with self.subTest(value=value):
                self.assertEqual(bot._format_storage_size(value), expected)

    def test_walk_rankings_depth_and_symlinks(self):
        write_file(self.data, "a/b/c/d/large.bin", 1000)
        for i in range(1, 8):
            write_file(self.data, f"folder{i}/file{i}.log", 100 + i)
        outside = write_file(self.root, "outside/secret", 9000)
        (self.data / "outside").symlink_to(outside.parent)
        (self.data / "secret-link").symlink_to(outside)
        (self.data / "loop").symlink_to(self.data)

        tree = bot._walk_storage(self.data, time.monotonic() + 2)
        self.assertEqual(tree.total, 1000 + sum(range(101, 108)))
        self.assertEqual(tree.logs, sum(range(101, 108)))
        self.assertEqual(tree.log_count, 7)
        self.assertEqual(sorted(tree.files, reverse=True), [
            (1000, "a/b/c/d/large.bin"), (107, "folder7/file7.log"), (106, "folder6/file6.log"),
            (105, "folder5/file5.log"), (104, "folder4/file4.log"),
        ])
        self.assertEqual(sorted(tree.directories, reverse=True), [
            (1000, "a/b/c"), (1000, "a/b"), (1000, "a"), (107, "folder7"), (106, "folder6"),
        ])
        self.assertFalse(tree.partial)

    def test_walk_stops_at_deadline(self):
        for i in range(5):
            write_file(self.data, str(i), 123)
        clock = itertools.count()
        tree = bot._walk_storage(self.data, 2, clock=lambda: next(clock))
        self.assertEqual(tree.total, 123)
        self.assertTrue(tree.partial)
        stats = bot._StorageStats(None, tree, bot._StorageTree(), 0, None, None, tree.partial)
        self.assertIn("**Storage** (partial)", bot._storage_report(stats, 1000))

    def test_walk_ignores_unreadable_entries(self):
        write_file(self.data, "denied/file", 1000)
        write_file(self.data, "readable", 200)
        real_open = os.open

        def open_path(path, *args, **kwargs):
            if path == "denied":
                raise PermissionError(path)
            return real_open(path, *args, **kwargs)

        with patch("bot.os.open", side_effect=open_path):
            tree = bot._walk_storage(self.data, time.monotonic() + 2)
        self.assertEqual(tree.total, 200)
        self.assertEqual(tree.files, [(200, "readable")])

    def test_stats_section_and_message_limit(self):
        bot_db = write_file(self.data, "uptime.db", 1024)
        write_file(self.data, "uptime.db-wal", 512)
        write_file(self.data, "uptime.db-shm", 512)
        core_db = write_file(self.data, "account/dc.db", 4096)
        write_file(self.data, "account/dc.db-wal", 1024)
        write_file(self.data, "account/blobs/file", 8192)
        write_file(self.data, "account/notes", 8192)
        write_file(self.app, "venv/library", 1024**2)
        write_file(self.app, "service.log", 8192)
        for i in range(7):
            for root in (self.data, self.app):
                write_file(root, f"{'長' * 70}{i}/large", 10_000 + i)

        rpc_bot, event = MagicMock(), MagicMock()
        rpc_bot.rpc.get_info.return_value = {"database_dir": str(core_db)}
        peers = [{"email": f"{i}@example.org", "node_name": f"Peer{i}" + "語" * 20, "version": "2.42.0"}
                 for i in range(30)]
        with (
            patch.dict(os.environ, {"DC_DB_DIR": str(self.data)}),
            patch.object(bot, "__file__", str(self.app / "bot.py")),
            patch.object(bot.database, "DB_PATH", str(bot_db)),
            patch.object(bot, "_is_dc_admin", return_value=True),
            patch.object(bot, "async_event_loop", None),
            patch.object(bot.database, "get_all_resources", return_value=[]),
            patch.object(bot.database, "get_local_node_name", return_value="Example"),
            patch.object(bot.database, "get_all_peers", return_value=peers),
            patch.object(bot, "interval_for_peer", return_value=bot.TELEMETRY_INTERVAL),
            patch.object(bot, "_peer_metrics_report", return_value=()),
            patch.object(bot, "_storage_disk_usage", return_value=disk_usage(250 * 1024**2, 50 * 1024**2)),
        ):
            bot.stats_command(rpc_bot, 1, event)

        rpc_bot.rpc.send_msg.assert_called_once()
        text = rpc_bot.rpc.send_msg.call_args.args[2].text
        self.assertLess(len(text.encode()), 4096)
        section = text.split("**Load**", 1)[1].split("**Monitors**", 1)[0]
        self.assertIn("**Storage**", section)
        self.assertIn("250.0 MB total · 200.0 MB used (80.0%) · 50.0 MB free (20.0%)", section)
        self.assertIn("Bot DB (+ WAL/SHM): 2.0 KB · Core DB (+ WAL): 5.0 KB", section)
        self.assertIn("Account blobs: 8.0 KB · Other data: 76.4 KB", section)
        self.assertIn("App: 1.1 MB · Logs: 8.0 KB (1 file)", section)
        self.assertIn("`venv/library`", section)
        self.assertNotIn(str(self.root), text)

    def test_app_total_excludes_nested_data(self):
        data = self.app / "data"
        database = write_file(data, "uptime.db", 2048)
        write_file(self.app, "venv/lib/module", 4096)
        stats = bot._collect_storage(data, self.app, database, None, None)
        self.assertEqual(stats.data.total, 2048)
        self.assertEqual(stats.app.total, 4096)
        self.assertEqual(stats.app.files, [(4096, "venv/lib/module")])

    def test_cache_expires_after_five_minutes(self):
        paths = (self.data, self.app, self.data / "uptime.db", None, None)
        with patch.object(bot.time, "monotonic", side_effect=[0, 299, 300, 301]), \
             patch.object(bot, "_collect_storage", side_effect=["first", "second"]) as collect:
            self.assertEqual(bot._get_storage_stats(*paths), "first")
            self.assertEqual(bot._get_storage_stats(*paths), "first")
            self.assertEqual(bot._get_storage_stats(*paths), "second")
        self.assertEqual(collect.call_count, 2)

    def test_warning_thresholds(self):
        mb = 1024**2
        self.assertTrue(bot._storage_is_low(disk_usage(1000 * mb, 99 * mb)))
        self.assertTrue(bot._storage_is_low(disk_usage(100 * mb, 29 * mb)))
        self.assertFalse(bot._storage_is_low(disk_usage(300 * mb, 30 * mb)))
        self.assertFalse(bot._storage_is_low(disk_usage(250 * mb, 40 * mb)))
        self.assertFalse(bot._storage_is_low(None))


class StorageWarningTests(unittest.IsolatedAsyncioTestCase):
    async def test_warning_is_persisted_and_repeated_at_most_daily(self):
        data = bot._StorageTree(files=[(1024, "first"), (512, "second")], directories=[(2048, "largest")])
        app = bot._StorageTree(files=[(128, "fourth")])
        disk = disk_usage(250 * 1024**2, 20 * 1024**2)
        stats = bot._StorageStats(disk, data, app, 0, 0, None, False)
        config = {}
        clock = 100_000
        with (
            patch.dict(os.environ, {"STORAGE_WARN": "1"}),
            patch.object(bot, "_storage_warned_at", float("-inf")),
            patch.object(bot, "_storage_disk_usage", return_value=disk),
            patch.object(bot, "_get_storage_stats", return_value=stats) as scan,
            patch.object(bot.database, "get_config", side_effect=config.get),
            patch.object(bot.database, "set_config", side_effect=config.__setitem__),
            patch.object(bot.time, "time", side_effect=lambda: clock),
            patch.object(bot, "send_admin_notification", new_callable=AsyncMock) as notify,
        ):
            await bot._maybe_warn_low_storage(MagicMock(), 1)
            notify.assert_awaited_once()
            body = notify.call_args.args[0]
            self.assertIn("20.0 MB free (8.0%)", body)
            self.assertIn("2.0 KB data/`largest`, 1.0 KB data/`first`, 512 B data/`second`", body)
            self.assertNotIn("fourth", body)
            # A fresh process still honors the saved timestamp.
            bot._storage_warned_at = float("-inf")
            clock += 86399
            await bot._maybe_warn_low_storage(MagicMock(), 1)
            notify.assert_awaited_once()
            scan.assert_called_once()
            clock += 1
            await bot._maybe_warn_low_storage(MagicMock(), 1)
            self.assertEqual(notify.await_count, 2)

    async def test_disabled_warning_skips_disk_check(self):
        with patch.dict(os.environ, {"STORAGE_WARN": "0"}), patch.object(bot, "_storage_disk_usage") as usage:
            await bot._maybe_warn_low_storage(MagicMock(), 1)
        usage.assert_not_called()
