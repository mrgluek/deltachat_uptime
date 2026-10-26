import asyncio
import collections
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_peer_scaling.db"


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


class TestTrimFallback(unittest.TestCase):
    def test_missing_message_does_not_stop_the_chunk(self):
        b = MagicMock()
        b.rpc.get_message_ids.return_value = list(range(1, 31))  # 10 to delete, 20 kept
        gone = {3}

        def delete(accid, ids):
            if any(i in gone for i in ids):
                raise RuntimeError(f"Message Msg#{min(gone)} does not exist")
        b.rpc.delete_messages.side_effect = delete
        with patch("bot.database.get_all_peers", return_value=[{"chat_id": 11, "node_name": "DE"}]):
            self.assertEqual(bot.trim_peer_chats(b, 1), 9)  # all but the one already gone


class TestTelemetryInterval(_DbCase):
    def test_steps(self):
        self.assertEqual([bot.telemetry_interval(n) for n in (0, 7, 10, 11, 20, 21, 50)],
                         [120, 120, 120, 180, 180, 300, 300])

    def test_offline_threshold_follows_the_announced_interval(self):
        bot._peer_telemetry_interval.clear()
        self.assertEqual(bot.peer_offline_after("old@example.org"), 360)
        peer = {"email": "Slow@example.org", "node_name": "SLOW"}
        with patch("bot.database.get_all_peers", return_value=[]):
            bot._note_peer_announcement(peer, {"telemetry_interval": 300})
        self.assertEqual(bot.peer_offline_after("slow@example.org"), 900)

    def test_audit_uses_per_peer_threshold(self):
        now = 1_000_000
        database.add_or_update_peer("fast@example.org", "FAST", 1, now - 400)
        database.add_or_update_peer("slow@example.org", "SLOW", 2, now - 400)
        offline = database.audit_peers_offline(360, now, {"slow@example.org": 900})
        self.assertEqual([p["email"] for p in offline], ["fast@example.org"])


class TestVoteSample(unittest.TestCase):
    def setUp(self):
        bot._node_vote_history.clear()
        bot._node_unstable_until.clear()

    def _peers(self, n):
        return [{"email": f"p{i}@example.org", "node_name": f"N{i}", "last_seen": 1000 + i} for i in range(n)]

    def test_small_mesh_asks_everyone(self):
        peers = self._peers(7)
        self.assertEqual(bot.pick_vote_peers(peers), peers)

    def test_large_mesh_asks_the_most_stable(self):
        peers = self._peers(12)
        now = time.time()
        for i in range(12):  # N0..N4 often failed alone, the others never
            bot._node_vote_history[f"N{i}"] = collections.deque([(now, i < 5)] * 10)
        bot._node_unstable_until["N11"] = now + 600
        picked = [p["node_name"] for p in bot.pick_vote_peers(peers, now=now)]
        self.assertEqual(len(picked), 7)
        self.assertNotIn("N11", picked[:6])  # unstable goes last among the stable ones
        self.assertEqual(set(picked[:6]), {"N5", "N6", "N7", "N8", "N9", "N10"})

    def test_reporter_is_always_asked(self):
        peers = self._peers(12)
        now = time.time()
        bot._node_vote_history["N0"] = collections.deque([(now, True)] * 10)
        picked = [p["node_name"] for p in bot.pick_vote_peers(peers, {"N0"}, now=now)]
        self.assertEqual(len(picked), 7)
        self.assertEqual(picked[0], "N0")

    def test_history_records_lone_failures(self):
        votes = [{"node": "L", "status": "up", "local": True}, {"node": "A", "status": "up"},
                 {"node": "B", "status": "up"}, {"node": "C", "status": "down"}]
        bot.note_vote_outliers("https://x.example/", votes, now=time.time())
        self.assertEqual(bot.node_lone_failure_share("C"), 1.0)
        self.assertEqual(bot.node_lone_failure_share("A"), 0.0)
        self.assertNotIn("L", bot._node_vote_history)


class TestStats(_DbCase):
    def test_report_renders(self):
        b = MagicMock()
        b.rpc.get_info.return_value = {"database_dir": "/nonexistent/dc.db"}
        b.rpc.list_transports.return_value = [{"addr": "uptimebot@chatmail.example"}]
        bot.stat_event("mail_in")
        text = bot.build_stats_report(b, 1)
        self.assertIn(f"v{bot.VERSION}", text)
        self.assertIn("**Peers**", text)
        self.assertIn("`uptimebot@chatmail.example`", text)
        self.assertIn("Received", text)

    @patch("bot._is_dc_admin", return_value=False)
    def test_admin_only(self, _):
        b = MagicMock()
        event = MagicMock()
        bot.stats_command(b, 1, event)
        self.assertIn("only for the administrator", b.rpc.send_msg.call_args.args[2].text)

    def test_stat_events_expire_after_an_hour(self):
        bot._stat_events["x"].clear()
        bot.stat_event("x", now=1000.0)
        bot.stat_event("x", now=2000.0)
        self.assertEqual(bot.stat_last_hour("x", now=4700.0), 1)


if __name__ == "__main__":
    unittest.main()
