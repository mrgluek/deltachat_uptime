import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_probe_ignore.db"


class TestIgnoreMatching(unittest.TestCase):
    """database.target_matches_ignore: targets, hosts and * patterns."""

    def check(self, url, pattern):
        return database.target_matches_ignore(url, [pattern])

    def test_exact_target(self):
        self.assertTrue(self.check("https://nine.testrun.org/", "https://nine.testrun.org/"))
        self.assertTrue(self.check("https://nine.testrun.org/", "https://nine.testrun.org"))  # trailing slash
        self.assertTrue(self.check("dnd.wb.ru:25", "DND.wb.ru:25"))
        self.assertFalse(self.check("dnd.wb.ru:465", "dnd.wb.ru:25"))

    def test_host_covers_all_its_targets(self):
        for url in ("https://nine.testrun.org/", "http://nine.testrun.org/x", "nine.testrun.org:25", "nine.testrun.org"):
            with self.subTest(url):
                self.assertTrue(self.check(url, "nine.testrun.org"))
        self.assertFalse(self.check("https://other.testrun.org/", "nine.testrun.org"))

    def test_port_pattern(self):
        self.assertTrue(self.check("dnd.wb.ru:25", "*:25"))
        self.assertTrue(self.check("[2a00::1]:25", "*:25"))
        self.assertFalse(self.check("dnd.wb.ru:2525", "*:25"))
        self.assertFalse(self.check("https://site.example.org/", "*:25"))
        self.assertTrue(self.check("https://site.example.org/", "*:443"))  # default https port
        self.assertTrue(self.check("http://site.example.org:8080/", "*:8080"))

    def test_domain_pattern(self):
        self.assertTrue(self.check("https://nine.testrun.org/", "*.testrun.org"))
        self.assertTrue(self.check("nine.testrun.org:25", "*.testrun.org"))
        self.assertFalse(self.check("https://testrun.org/", "*.testrun.org"))
        self.assertTrue(self.check("https://testrun.org/", "*testrun.org"))
        self.assertFalse(self.check("https://testrun.org.evil.example/", "*.testrun.org"))

    def test_regex_characters_are_literal(self):
        self.assertFalse(self.check("https://nineXtestrun.org/", "nine.testrun.org"))
        self.assertFalse(self.check("https://ninextestrun.org/", "*.testrun.org"))
        self.assertTrue(self.check("[2a00::1]:443", "[2a00::1]:*"))


class TestIgnoreCommandsAndEffects(unittest.TestCase):

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        database.set_local_node_name("RU2")

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _mirror(self, *urls):
        database.save_probe_targets_batch([{"url": u, "type": "tcp" if ":" in u and "://" not in u else "http"} for u in urls], "de@example.org")

    def _probe_urls(self):
        return sorted(t["url"] for t in database.get_active_probe_targets())

    def test_pattern_removes_and_blocks_mirrored_targets(self):
        self._mirror("dnd.wb.ru:25", "chat.example.net:25", "https://site.example.org/")
        database.save_peer_measurement("dnd.wb.ru:25", "RU2", "down", None, "timeout")
        self.assertEqual(database.add_ignored_probe_target("*:25"), 2)
        self.assertEqual(self._probe_urls(), ["https://site.example.org/"])
        self.assertEqual(database.get_peer_measurements_for_url("dnd.wb.ru:25"), [])

        self._mirror("new.example.net:25")  # later targets matching the pattern are not mirrored
        self.assertEqual(self._probe_urls(), ["https://site.example.org/"])
        self.assertTrue(database.is_probe_target_ignored("other.example.com:25"))
        self.assertFalse(database.is_probe_target_ignored("https://site.example.org/"))

    @patch("bot._is_dc_admin", return_value=True)
    def test_commands(self, mock_admin):
        self._mirror("https://nine.testrun.org/")
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 1

        event.payload = "*.TestRun.org"
        bot.probeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Pattern `*.testrun.org`", text)
        self.assertIn("1 mirrored target(s)", text)

        event.payload = "nine.testrun.org"
        bot.probeignore_command(mock_bot, 1, event)
        self.assertIn("Host `nine.testrun.org`", mock_bot.rpc.send_msg.call_args.args[2].text)

        event.payload = ""
        bot.probeignore_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("`*.testrun.org`", text)
        self.assertIn("`nine.testrun.org`", text)

        event.payload = "*.testrun.org"
        bot.probeunignore_command(mock_bot, 1, event)
        self.assertEqual([i["url"] for i in database.get_all_ignored_probe_targets()], ["nine.testrun.org"])

    def test_cross_check_answer_abstains_for_pattern(self):
        database.add_ignored_probe_target("*:25")
        targets = [{"id": 0, "url": "dnd.wb.ru:25", "type": "tcp"}]
        with patch("bot.run_single_check") as check, patch("bot._dc_send_msg_with_stats") as send:
            import asyncio
            asyncio.run(bot._answer_batch_cross_check(MagicMock(), 1, 9, "req", targets))
        check.assert_not_called()
        results = json.loads(send.call_args.args[3].text.split("\n")[1])["results"]
        self.assertEqual(results[0]["status"], "skip")


if __name__ == "__main__":
    unittest.main()
