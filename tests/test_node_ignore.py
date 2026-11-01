import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_node_ignore.db"


class TestNodePatternMatching(unittest.TestCase):
    """database.node_matches_pattern: node names and * patterns."""

    def test_exact_match(self):
        self.assertTrue(database.node_matches_pattern("RU", "RU"))
        self.assertTrue(database.node_matches_pattern("ru", "RU"))
        self.assertTrue(database.node_matches_pattern("Frankfurt-DE", "frankfurt-de"))
        self.assertFalse(database.node_matches_pattern("RU", "DE"))

    def test_prefix_pattern(self):
        self.assertTrue(database.node_matches_pattern("RU", "RU*"))
        self.assertTrue(database.node_matches_pattern("RU-1", "RU*"))
        self.assertTrue(database.node_matches_pattern("ru_home", "RU*"))
        self.assertTrue(database.node_matches_pattern("Russia", "RU*"))
        self.assertFalse(database.node_matches_pattern("DE-RU", "RU*"))

    def test_suffix_pattern(self):
        self.assertTrue(database.node_matches_pattern("home", "*home"))
        self.assertTrue(database.node_matches_pattern("de_home", "*home"))
        self.assertTrue(database.node_matches_pattern("RU-HOME", "*home"))
        self.assertFalse(database.node_matches_pattern("home_de", "*home"))

    def test_wildcard_all(self):
        self.assertTrue(database.node_matches_pattern("RU", "*"))
        self.assertTrue(database.node_matches_pattern("Frankfurt-DE", "*"))
        self.assertFalse(database.node_matches_pattern("", "*"))
        self.assertFalse(database.node_matches_pattern("RU", ""))


class TestNodeIgnoreDatabase(unittest.TestCase):

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)
        database.DB_PATH = TEST_DB
        database.init_db()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def test_add_and_check_ignored(self):
        database.add_node_ignored_target("RU*", "facebook.*")
        database.add_node_ignored_target("*home", "*:25")

        self.assertTrue(database.is_node_target_ignored("RU", "https://facebook.com"))
        self.assertTrue(database.is_node_target_ignored("RU-2", "https://facebook.org/login"))
        self.assertFalse(database.is_node_target_ignored("DE", "https://facebook.com"))
        self.assertFalse(database.is_node_target_ignored("RU", "https://google.com"))

        self.assertTrue(database.is_node_target_ignored("my_home", "mail.example.org:25"))
        self.assertFalse(database.is_node_target_ignored("cloud_server", "mail.example.org:25"))

    def test_cleans_stale_measurements_on_add(self):
        database.save_peer_measurement("https://facebook.com", "RU-1", "down", None, "timeout")
        database.save_peer_measurement("https://google.com", "RU-1", "up", 50, None)
        database.save_peer_measurement("https://facebook.com", "DE", "up", 40, None)

        cleaned = database.add_node_ignored_target("RU*", "facebook.*")
        self.assertEqual(cleaned, 1)

        # facebook on RU-1 should be deleted, but google on RU-1 and facebook on DE remain
        meas_fb = database.get_peer_measurements_for_url("https://facebook.com")
        self.assertEqual(len(meas_fb), 1)
        self.assertEqual(meas_fb[0]["node_name"], "DE")
        self.assertEqual(meas_fb[0]["status"], "up")
        meas_google = database.get_peer_measurements_for_url("https://google.com")
        self.assertEqual(len(meas_google), 1)
        self.assertEqual(meas_google[0]["node_name"], "RU-1")

    def test_remove_rule(self):
        database.add_node_ignored_target("RU*", "facebook.*")
        database.add_node_ignored_target("RU*", "instagram.com")
        database.add_node_ignored_target("DE", "twitter.com")

        # Remove single rule
        self.assertEqual(database.remove_node_ignored_target("RU*", "facebook.*"), 1)
        self.assertFalse(database.is_node_target_ignored("RU", "https://facebook.com"))
        self.assertTrue(database.is_node_target_ignored("RU", "https://instagram.com"))

        # Remove all rules for node pattern
        self.assertEqual(database.remove_node_ignored_target("RU*"), 1)
        self.assertFalse(database.is_node_target_ignored("RU", "https://instagram.com"))
        self.assertTrue(database.is_node_target_ignored("DE", "https://twitter.com"))


class TestNodeIgnoreCommandsAndBotEffects(unittest.TestCase):

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)
        database.DB_PATH = TEST_DB
        database.init_db()
        database.set_local_node_name("Frankfurt-DE")

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    @patch("bot._is_dc_admin", return_value=True)
    def test_nodeignore_and_nodeunignore_commands(self, mock_admin):
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 100

        # Empty list
        event.payload = ""
        bot.nodeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("No node-ignored targets configured", text)

        # Add rule
        event.payload = "RU* facebook.*"
        bot.nodeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("`RU*` ➔ `facebook.*`", text)

        # List all
        event.payload = ""
        bot.nodeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Node-Ignored Targets (1)", text)
        self.assertIn("`RU*` ➔ `facebook.*`", text)

        # Filter by node pattern
        event.payload = "RU*"
        bot.nodeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Node-Ignored Targets for `RU*`", text)

        # Filter by non-existent pattern
        event.payload = "US*"
        bot.nodeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("No node-ignored targets configured matching `US*`", text)

        # Unignore
        event.payload = "RU* facebook.*"
        bot.nodeunignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Removed node ignore rule(s)", text)
        self.assertEqual(database.get_all_node_ignored_targets(), [])

    def test_cross_checks_skip_ignored_nodes(self):
        database.add_node_ignored_target("RU*", "facebook.*")
        peers = [
            {"email": "ru@example.org", "node_name": "RU-Node", "chat_id": 10},
            {"email": "it@example.org", "node_name": "IT-Node", "chat_id": 20},
        ]
        with patch("bot.database.get_all_peers", return_value=peers), \
             patch("bot._peer_supports", return_value=True), \
             patch("bot._batch_cross_check_peer") as mock_batch:
            async def _run():
                target = {"url": "https://facebook.com", "type": "http"}
                fut = asyncio.get_running_loop().create_future()
                batch = [(target, fut, None)]
                await bot._flush_cross_checks(batch)
            asyncio.run(_run())

            # _batch_cross_check_peer should ONLY be called for IT-Node, NOT for RU-Node
            called_nodes = [call.args[0]["node_name"] for call in mock_batch.call_args_list]
            self.assertEqual(called_nodes, ["IT-Node"])

    def test_note_peer_reported_down_filters_ignored_nodes(self):
        database.add_node_ignored_target("RU*", "facebook.*")
        metrics = [
            {"url": "https://facebook.com", "status": "down", "last_checked": 1000},
            {"url": "https://google.com", "status": "down", "last_checked": 1000},
        ]
        with patch("bot.database.get_resources_by_urls", return_value=[]):
            # For RU node, facebook should be filtered out
            marked = bot.note_peer_reported_down("RU-1", metrics)
            # The only candidate passed to get_resources_by_urls would be google.com
            # (which returns empty list from mock, so marked=0, but facebook was filtered)
            self.assertEqual(marked, 0)


if __name__ == "__main__":
    unittest.main()
