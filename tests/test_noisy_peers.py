import asyncio
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_noisy_peers.db"


class _DbCase(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)


class TestSmtpProbeTargets(_DbCase):
    def _type(self, url):
        return next(t["type"] for t in database.get_active_probe_targets() if t["url"] == url)

    def test_smtp_type_is_kept(self):
        database.save_probe_targets_batch([{"url": "smtp://chatmail.uk", "type": "smtp"}], "peer@example.org")
        self.assertEqual(self._type("smtp://chatmail.uk"), "smtp")

    def test_mistyped_rows_are_fixed_at_start(self):
        database.save_probe_targets_batch([{"url": "smtp://chatmail.uk", "type": "smtp"}], "peer@example.org")
        conn = database._connect()
        conn.execute("UPDATE probe_targets SET type = 'http', last_status = 'down' WHERE url = 'smtp://chatmail.uk'")
        conn.commit()
        conn.close()
        database.init_db()
        t = next(t for t in database.get_active_probe_targets() if t["url"] == "smtp://chatmail.uk")
        self.assertEqual((t["type"], t["last_status"]), ("smtp", None))


class TestDockerDesktopPing(unittest.TestCase):
    def setUp(self):
        self.saved = bot._ping_reliable
        bot._ping_reliable = None

    def tearDown(self):
        bot._ping_reliable = self.saved

    def _reliable(self, version, env=None):
        env = dict(env or {})
        with patch("builtins.open", mock_open(read_data=version)), patch.dict(os.environ, env):
            if "PING_ON_DOCKER_DESKTOP" not in env:
                os.environ.pop("PING_ON_DOCKER_DESKTOP", None)  # patch.dict restores it afterwards
            return bot.ping_is_reliable()

    def test_linux_host_is_reliable(self):
        self.assertTrue(self._reliable("Linux version 6.8.0-147-generic (buildd@lcy02)"))

    def test_docker_desktop_is_not(self):
        self.assertFalse(self._reliable("Linux version 7.0.12-linuxkit (root@buildkitsandbox)"))

    def test_override(self):
        self.assertTrue(self._reliable("Linux version 7.0.12-linuxkit", {"PING_ON_DOCKER_DESKTOP": "1"}))

    def test_ping_check_abstains(self):
        bot._ping_reliable = False
        with patch("bot.ping_series", AsyncMock()) as series:
            res = asyncio.run(bot.run_single_check({"type": "ping", "url": "93.184.216.34"}))
        self.assertEqual(res, (None, bot.PING_UNRELIABLE_MSG, None))
        series.assert_not_called()


class TestLoneReporter(unittest.TestCase):
    def setUp(self):
        bot._lone_reporters.clear()
        bot._peer_suspects.clear()

    def _votes(self, mac_status):
        return [{"node": "DE", "status": "up", "local": True}, {"node": "PL", "status": "up"},
                {"node": "IT", "status": "up"}, {"node": "MAC", "status": mac_status}]

    def test_unstable_reporter_is_ignored_for_a_while(self):
        self.assertTrue(bot.note_lone_reporter("https://x.example/", "MAC", self._votes("unstable"), now=100.0))
        with patch("bot.time.monotonic", return_value=100.0 + bot.LONE_REPORTER_HOLD - 1), \
             patch("bot.database.get_resources_by_urls") as lookup:
            n = bot.note_peer_reported_down("MAC", [{"url": "https://x.example/", "status": "down"}])
        self.assertEqual(n, 0)
        lookup.assert_not_called()

    def test_heard_again_after_the_hold(self):
        bot.note_lone_reporter("https://x.example/", "MAC", self._votes("unstable"), now=100.0)
        with patch("bot.time.monotonic", return_value=100.0 + bot.LONE_REPORTER_HOLD + 1), \
             patch("bot.database.get_resources_by_urls", return_value=[]) as lookup:
            bot.note_peer_reported_down("MAC", [{"url": "https://x.example/", "status": "down"}])
        lookup.assert_called_once()

    def test_counted_lone_vote_is_heard(self):
        # Only MAC fails it, but its vote counts: its next report confirms DEGRADED
        for status in ("down", "degraded"):
            self.assertFalse(bot.note_lone_reporter("https://x.example/", "MAC", self._votes(status), now=100.0))
        self.assertNotIn(("https://x.example/", "MAC"), bot._lone_reporters)


class TestBlockedForPeers(_DbCase):
    def test_blocked_abstains_only_for_peers(self):
        self.assertIsNone(bot.for_peers(False, bot.BLOCKED_TARGET_MSG))
        self.assertIs(bot.for_peers(False, "Timeout"), False)
        self.assertIs(bot.for_peers(True, "40 ms"), True)

    def test_mirrored_blocked_target_reports_skip(self):
        database.save_probe_targets_batch([{"url": "home.example.org", "type": "ping"}], "peer@example.org")
        database.update_probe_target_result("home.example.org", "down", None, "Timeout")
        rep = {"id": "probe_home.example.org", "url": "home.example.org", "type": "ping", "is_probe_only": True}
        with patch("bot.check_network_probe", AsyncMock(return_value=(False, bot.BLOCKED_TARGET_MSG, None))):
            asyncio.run(bot.check_group_task([rep], asyncio.Semaphore(1)))
        t = next(t for t in database.get_active_probe_targets() if t["url"] == "home.example.org")
        self.assertEqual(t["last_status"], "skip")


if __name__ == "__main__":
    unittest.main()
