import asyncio
import json
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
        with patch("bot.time.time", return_value=100.0 + bot.LONE_REPORTER_HOLD - 1), \
             patch("bot.database.get_resources_by_urls") as lookup:
            n = bot.note_peer_reported_down("MAC", [{"url": "https://x.example/", "status": "down"}])
        self.assertEqual(n, 0)
        lookup.assert_not_called()

    def test_heard_again_after_the_hold(self):
        bot.note_lone_reporter("https://x.example/", "MAC", self._votes("unstable"), now=100.0)
        with patch("bot.time.time", return_value=100.0 + bot.LONE_REPORTER_HOLD + 1), \
             patch("bot.database.get_resources_by_urls", return_value=[]) as lookup:
            bot.note_peer_reported_down("MAC", [{"url": "https://x.example/", "status": "down"}])
        lookup.assert_called_once()

    def test_counted_lone_vote_is_heard(self):
        # Only MAC fails it, but its vote counts: its next report confirms DEGRADED
        for status in ("down", "degraded"):
            self.assertFalse(bot.note_lone_reporter("https://x.example/", "MAC", self._votes(status), now=100.0))
        self.assertNotIn(("https://x.example/", "MAC"), bot._lone_reporters)


class TestUnconfirmedReport(unittest.TestCase):
    def setUp(self):
        bot._lone_reporters.clear()

    def test_reporter_answering_up_is_held_briefly(self):
        votes = [{"node": "DE", "status": "up", "local": True}, {"node": "PL", "status": "up"}]
        self.assertTrue(bot.note_lone_reporter("gluek.info", "PL", votes, now=100.0))
        self.assertEqual(bot._lone_reporters[("gluek.info", "PL")], (100.0 + bot.UNCONFIRMED_REPORT_HOLD, 1))


class TestEscalatingHold(_DbCase):
    URL = "smtp://chatmail.uk"

    def setUp(self):
        super().setUp()
        bot._lone_reporters.clear()
        bot._lone_reporters_loaded = True

    def _vote(self, status, now):
        votes = [{"node": "DE", "status": "up", "local": True}, {"node": "PL", "status": status}]
        bot.note_lone_reporter(self.URL, "PL", votes, now=now)
        return bot._lone_reporters.get((self.URL, "PL"))

    def test_doubles_up_to_two_hours(self):
        now, holds = 1_000_000.0, []
        for _ in range(6):
            until, _streak = self._vote("up", now)
            holds.append(int(until - now) // 60)
            now = until + 1  # its next report, right after the hold
        self.assertEqual(holds, [10, 20, 40, 80, 120, 120])

    def test_confirmed_report_starts_over(self):
        now = 1_000_000.0
        self._vote("up", now)
        self._vote("up", now + 700)
        self.assertIsNone(self._vote("down", now + 2000))
        until, streak = self._vote("up", now + 2100)
        self.assertEqual((int(until - now - 2100), streak), (bot.UNCONFIRMED_REPORT_HOLD, 1))

    def test_no_answer_changes_nothing(self):
        now = 1_000_000.0
        first = self._vote("up", now)
        self.assertEqual(self._vote("unknown", now + 60), first)

    def test_survives_a_restart(self):
        now = time.time()
        self._vote("up", now)
        bot._lone_reporters.clear()
        bot._lone_reporters_loaded = False  # as after a restart
        self.assertTrue(bot.report_held(self.URL, "PL", now + 60))
        self.assertFalse(bot.report_held(self.URL, "PL", now + bot.UNCONFIRMED_REPORT_HOLD + 1))


class TestTrimPeerChats(_DbCase):
    def test_keeps_newest_and_deletes_in_chunks(self):
        b = MagicMock()
        b.rpc.get_message_ids.return_value = list(range(1, 1101))
        with patch("bot.database.get_all_peers", return_value=[{"chat_id": 7, "node_name": "PL"}, {"chat_id": None}]):
            n = bot.trim_peer_chats(b, 1)
        self.assertEqual(n, 1100 - bot.PEER_CHAT_KEEP)
        deleted = [i for call in b.rpc.delete_messages.call_args_list for i in call.args[1]]
        self.assertEqual(deleted, list(range(1, 1101 - bot.PEER_CHAT_KEEP)))
        self.assertTrue(all(len(c.args[1]) <= bot.PEER_CHAT_TRIM_CHUNK for c in b.rpc.delete_messages.call_args_list))
        b.rpc.get_message_ids.assert_called_once_with(1, 7, False, False)

    def test_short_chat_is_left_alone(self):
        b = MagicMock()
        b.rpc.get_message_ids.return_value = list(range(5))
        with patch("bot.database.get_all_peers", return_value=[{"chat_id": 7}]):
            self.assertEqual(bot.trim_peer_chats(b, 1), 0)
        b.rpc.delete_messages.assert_not_called()


class TestPeerHello(unittest.TestCase):
    def test_retried_until_securejoin_is_done(self):
        b = MagicMock()
        b.rpc.send_msg.side_effect = [RuntimeError("e2e encryption unavailable")] * 2 + [42]
        sleeps = []
        self.assertTrue(bot.send_peer_hello_when_ready(b, 1, 49, "[UPTIME_PEER_HELLO]", "DE", sleep=sleeps.append))
        self.assertEqual(b.rpc.send_msg.call_count, 3)
        self.assertEqual(sleeps, [bot.PEER_HELLO_RETRY_INTERVAL] * 2)

    def test_admin_told_when_it_never_goes_out(self):
        b = MagicMock()
        b.rpc.send_msg.side_effect = RuntimeError("e2e encryption unavailable")
        loop = MagicMock()
        loop.is_running.return_value = True
        with patch.object(bot, "PEER_HELLO_RETRY_FOR", 0), patch.object(bot, "async_event_loop", loop), \
             patch("bot.asyncio.run_coroutine_threadsafe") as run, \
             patch("bot.send_admin_notification", MagicMock(return_value="coro")) as notify:
            self.assertFalse(bot.send_peer_hello_when_ready(b, 1, 49, "[UPTIME_PEER_HELLO]", "DE", sleep=lambda s: None))
        self.assertIn("Peering Not Completed", notify.call_args.args[0])
        run.assert_called_once_with("coro", loop)


class TestHealth(unittest.TestCase):
    def test_health_json(self):
        resp = asyncio.run(bot.handle_health(MagicMock()))
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.text), {"status": "ok", "version": bot.VERSION})
        self.assertEqual(resp.headers["Cache-Control"], "no-store")


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


class TestPeerFlood(_DbCase):
    """A peer with a broken network reports dozens of targets DOWN that are UP here."""

    def setUp(self):
        super().setUp()
        bot._peer_flood_until.clear()
        bot._peer_suspects.clear()

    def tearDown(self):
        bot._peer_flood_until.clear()
        bot._peer_suspects.clear()
        super().tearDown()

    def _report(self, n):
        return [{"url": f"https://t{i}.example/", "status": "down"} for i in range(n)]

    def _up_here(self, n):
        return [{"url": f"https://t{i}.example/", "status": "up", "alert_state": "up", "dc_chat_id": 5}
                for i in range(n)]

    def test_few_targets_are_voted_as_before(self):
        with patch("bot.database.get_resources_by_urls", return_value=self._up_here(3)), \
             patch("bot.database.get_chat_alert_mode", return_value="quorum"):
            self.assertEqual(bot.note_peer_reported_down("MAC", self._report(3)), 3)
        self.assertEqual(len(bot._peer_suspects), 3)
        self.assertNotIn("MAC", bot._peer_flood_until)

    def test_flood_is_ignored_and_the_peer_held(self):
        with patch("bot.database.get_resources_by_urls", return_value=self._up_here(bot.PEER_FLOOD_TARGETS)), \
             patch("bot.database.get_chat_alert_mode", return_value="quorum"):
            self.assertEqual(bot.note_peer_reported_down("MAC", self._report(bot.PEER_FLOOD_TARGETS)), 0)
        self.assertEqual(bot._peer_suspects, {})
        self.assertGreater(bot._peer_flood_until["MAC"], time.time())

    def test_held_peer_is_not_even_looked_up(self):
        bot._peer_flood_until["MAC"] = time.time() + 60
        with patch("bot.database.get_resources_by_urls") as lookup:
            self.assertEqual(bot.note_peer_reported_down("MAC", self._report(2)), 0)
        lookup.assert_not_called()

    def test_heard_again_after_the_hold(self):
        bot._peer_flood_until["MAC"] = time.time() - 1
        with patch("bot.database.get_resources_by_urls", return_value=self._up_here(2)), \
             patch("bot.database.get_chat_alert_mode", return_value="quorum"):
            self.assertEqual(bot.note_peer_reported_down("MAC", self._report(2)), 2)

    def test_other_peers_are_not_affected(self):
        bot._peer_flood_until["MAC"] = time.time() + 60
        with patch("bot.database.get_resources_by_urls", return_value=self._up_here(2)), \
             patch("bot.database.get_chat_alert_mode", return_value="quorum"):
            self.assertEqual(bot.note_peer_reported_down("PL", self._report(2)), 2)


if __name__ == "__main__":
    unittest.main()
