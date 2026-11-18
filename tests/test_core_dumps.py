import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import bot


MB = 1024**2


class CoreDumpFixture:
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.app = self.root / "app"
        self.cwd = self.root / "cwd"
        self.data = self.root / "data"
        for root in (self.app, self.cwd, self.data):
            root.mkdir()
        self.enterContext(patch.object(bot, "__file__", str(self.app / "bot.py")))
        self.enterContext(patch.object(bot.Path, "cwd", return_value=self.cwd))
        self.enterContext(patch.object(bot, "_storage_config_dir", str(self.data)))
        self.enterContext(patch.dict(os.environ, {"DC_DB_DIR": "", "CORE_DUMP_WARN": "1", "STORAGE_WARN": "0"}))

    def write_file(self, root, name, size=MB):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            handle.truncate(size)
        return path

    def scan_names(self):
        return [name for name, _ in bot._scan_core_dumps()]


class CoreDumpScanTests(CoreDumpFixture, unittest.TestCase):
    def test_name_matching(self):
        for name, expected in (
            ("core", True), ("core.10", True), ("core.000", True), ("core-123", True),
            ("core-", True), ("python.core", True), (".core", True), ("vgcore.42", True),
            ("core.py", False), ("corefile", False), ("score", False), ("core.1.gz", False),
            ("Core", False), ("core.", False), ("core.١", False), ("core.1x", False),
            ("vgcore", False), ("some.core.bak", False),
        ):
            with self.subTest(name=name):
                self.assertEqual(bool(bot._CORE_DUMP_NAME.fullmatch(name)), expected)

    def test_scan_only_three_top_level_dirs(self):
        self.write_file(self.app, "core.10")
        self.write_file(self.cwd, "python.core")
        self.write_file(self.data, "vgcore.9")
        for root in (self.app, self.cwd, self.data):
            self.write_file(root, "nested/core.8")
        self.write_file(self.root, "core.7")
        self.assertEqual(self.scan_names(), ["core.10", "python.core", "vgcore.9"])

    def test_scan_ignores_symlinks_empty_files_and_directories(self):
        outside = self.write_file(self.root, "outside")
        (self.app / "core.10").symlink_to(outside)
        (self.app / "core.11").symlink_to(self.root / "missing")
        self.write_file(self.app, "core.12", 0)
        (self.app / "core.13").mkdir()
        self.assertEqual(self.scan_names(), [])

    def test_scan_does_not_follow_a_symlink_as_data_root(self):
        self.write_file(self.root, "core")
        link = self.cwd / "data-link"
        link.symlink_to(self.root, target_is_directory=True)
        with patch.dict(os.environ, {"DC_DB_DIR": str(link)}):
            self.assertEqual(self.scan_names(), [])


class CoreDumpWarningTests(CoreDumpFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(bot.database, "DB_PATH", str(self.data / "uptime.db")))
        bot.database.init_db()
        self.addCleanup(bot.database.close_db)
        self.enterContext(patch.object(bot, "_core_dump_warned", set()))
        self.enterContext(patch.dict(bot._bot_stats, {"started": 1000}))
        disk = bot.shutil._ntuple_diskusage(250 * MB, 200 * MB, 50 * MB)
        self.enterContext(patch.object(bot, "_storage_disk_usage", return_value=disk))
        self.notify = self.enterContext(patch.object(bot, "send_admin_notification", new=AsyncMock(return_value=True)))

    async def test_once_per_key_and_again_when_mtime_or_size_changes(self):
        dump = self.write_file(self.app, "core.10", int(161.8 * MB))
        os.utime(dump, (900, 900))
        await bot._maybe_warn_core_dumps()
        await bot._maybe_warn_core_dumps()
        self.notify.assert_awaited_once()
        self.assertEqual(
            self.notify.call_args.args[0],
            "Core dump found: core.10, 161.8 MB, modified 1970-01-01 00:15:00 UTC. "
            "A process of the bot crashed earlier (the bot now disables core dumps). "
            "It is no longer needed after a crash analysis and takes up disk quota. "
            "Send /rmcore to delete core dump files.\nData filesystem: 50.0 MB free (20.0%).",
        )

        os.utime(dump, (901, 901))
        await bot._maybe_warn_core_dumps()
        self.assertEqual(self.notify.await_count, 2)
        self.write_file(self.app, "core.10", 2 * MB)
        os.utime(dump, (901, 901))
        await bot._maybe_warn_core_dumps()
        self.assertEqual(self.notify.await_count, 3)

    async def test_notice_survives_restart(self):
        self.write_file(self.cwd, "test.core")
        await bot._maybe_warn_core_dumps()
        bot.database.close_db()
        with patch.object(bot, "_core_dump_warned", set()):
            await bot._maybe_warn_core_dumps()
        self.notify.assert_awaited_once()

    async def test_multiple_new_dumps_send_one_message_with_crash_timing(self):
        for name, modified in (("core.10", 940), ("core.11", 941)):
            dump = self.write_file(self.app, name)
            os.utime(dump, (modified, modified))
        await bot._maybe_warn_core_dumps()
        self.notify.assert_awaited_once()
        text = self.notify.call_args.args[0]
        self.assertIn("Core dump found: core.10, 1.0 MB, modified 1970-01-01 00:15:40 UTC. "
                      "A process of the bot crashed earlier", text)
        self.assertIn("Core dump found: core.11, 1.0 MB, modified 1970-01-01 00:15:41 UTC. "
                      "A process crashed just now", text)

    async def test_warning_disabled_independently_of_low_storage_warning(self):
        self.write_file(self.app, "core")
        with patch.dict(os.environ, {"CORE_DUMP_WARN": "0", "STORAGE_WARN": "1"}):
            await bot._maybe_warn_core_dumps()
        self.notify.assert_not_awaited()

    async def test_unsent_warning_is_retried(self):
        self.write_file(self.app, "core")
        self.notify.side_effect = [False, True]
        await bot._maybe_warn_core_dumps()
        self.assertEqual(bot._core_dump_warned, set())
        await bot._maybe_warn_core_dumps()
        await bot._maybe_warn_core_dumps()
        self.assertEqual(self.notify.await_count, 2)

    async def test_periodic_task_scans_at_start_and_every_ten_minutes(self):
        class EndTest(Exception):
            pass

        elapsed = 0
        scans = []

        async def sleep(seconds):
            nonlocal elapsed
            elapsed += seconds
            if elapsed > 1200:
                raise EndTest

        async def scan():
            scans.append(elapsed)

        with (
            patch.object(bot, "asyncio", MagicMock(sleep=sleep)),
            patch.object(bot, "time", MagicMock(monotonic=lambda: elapsed)),
            patch.object(bot, "dc_accid", 1),
            patch.object(bot, "run_db", new_callable=AsyncMock),
            patch.object(bot, "_maybe_warn_core_dumps", side_effect=scan),
            self.assertRaises(EndTest),
        ):
            await bot._flush_peer_metrics_periodically()
        self.assertEqual(scans, [0, 600, 1200])


class CoreDumpCommandTests(CoreDumpFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.client, self.event = MagicMock(), MagicMock()
        self.event.msg.chat_id = 12
        self.event.msg.from_id = 23
        self.client.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        self.send = self.enterContext(patch.object(bot, "_dc_send_msg_with_stats"))
        self.admin = self.enterContext(patch.object(bot, "_is_dc_admin", return_value=True))

    def reply(self):
        return self.send.call_args.args[3].text

    def test_non_admin_cannot_delete_dumps(self):
        dump = self.write_file(self.app, "core.10")
        self.admin.return_value = False
        bot.rmcore_command(self.client, 1, self.event)
        self.assertTrue(dump.exists())
        self.assertIn("only for the administrator", self.reply())

    def test_command_requires_private_chat(self):
        dump = self.write_file(self.app, "core.10")
        self.client.rpc.get_basic_chat_info.return_value = {"chat_type": "Group"}
        bot.rmcore_command(self.client, 1, self.event)
        self.assertTrue(dump.exists())
        self.assertIn("private chat", self.reply())

    def test_deletes_only_detected_dumps_and_reports_freed_mb(self):
        keep = self.write_file(self.app, "core.py")
        nested = self.write_file(self.data, "nested/core")
        link = self.data / "core.11"
        link.symlink_to(keep)
        empty = self.write_file(self.cwd, "core.12", 0)
        dumps = (self.write_file(self.app, "core.10"), self.write_file(self.cwd, "python.core", 2 * MB))
        self.event.msg.text = f"/rmcore {keep}"
        bot.rmcore_command(self.client, 1, self.event)
        self.assertEqual(self.reply(), "Deleted core dump files: core.10, python.core. Freed 3.0 MB.")
        for path in dumps:
            self.assertFalse(path.exists())
        for path in (keep, nested, empty):
            self.assertTrue(path.exists())
        self.assertTrue(link.is_symlink())

        bot.rmcore_command(self.client, 1, self.event)
        self.assertEqual(self.reply(), "No core dump files found")

    def test_stats_line_is_live_even_when_warnings_are_disabled(self):
        stats = bot._StorageStats(None, bot._StorageTree(), bot._StorageTree(), 0, None, None, False)
        self.client.rpc.get_info.return_value = {}
        with (
            patch.dict(os.environ, {"CORE_DUMP_WARN": "0"}),
            patch.object(bot, "async_event_loop", None),
            patch.object(bot, "_get_storage_stats", return_value=stats),
            patch.object(bot.database, "get_all_resources", return_value=[]),
            patch.object(bot.database, "get_local_node_name", return_value="Example"),
            patch.object(bot.database, "get_all_peers", return_value=[]),
            patch.object(bot.database, "get_mail_kinds_24h", return_value=[]),
            patch.object(bot, "_peer_metrics_report", return_value=()),
        ):
            bot.stats_command(self.client, 1, self.event)
            self.assertNotIn("Core dumps:", self.reply())

            self.write_file(self.app, "core.10", int(161.8 * MB))
            bot.stats_command(self.client, 1, self.event)
            storage = self.reply().split("**Storage**", 1)[1].split("**Monitors**", 1)[0]
            self.assertIn("• Core dumps: core.10 161.8 MB (send /rmcore to delete)", storage)


class CoreDumpLimitTests(unittest.TestCase):
    def test_main_disables_dumps_before_rpc_start(self):
        resource = MagicMock(RLIMIT_CORE=4)

        def start():
            resource.setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

        with patch.dict(sys.modules, {"resource": resource}), patch.object(sys, "argv", ["bot.py"]), \
             patch.object(bot.dc_cli, "start", side_effect=start) as cli_start:
            bot.main()
        cli_start.assert_called_once()

    def test_setrlimit_failure_does_not_prevent_startup(self):
        resource = MagicMock(RLIMIT_CORE=4)
        resource.setrlimit.side_effect = OSError("unsupported")
        with patch.dict(sys.modules, {"resource": resource}), patch.object(sys, "argv", ["bot.py"]), \
             patch.object(bot.dc_cli, "start") as cli_start, self.assertLogs(bot.logger, "INFO") as logs:
            bot.main()
        cli_start.assert_called_once()
        self.assertEqual(len(logs.output), 1)
        self.assertIn("Could not disable core dumps: unsupported", logs.output[0])

    def test_resource_module_is_optional(self):
        with patch.dict(sys.modules, {"resource": None}), self.assertLogs(bot.logger, "INFO") as logs:
            bot._disable_core_dumps()
        self.assertEqual(len(logs.output), 1)
