import unittest
from unittest.mock import MagicMock, patch

import bot
import database
from test_audit4_fixes import AuditCase


class TestTrimKeepsRetiredInstances(AuditCase):
    def run_trim(self, mode):
        database.set_config("app_retire", mode)
        database.set_chat_webxdc(10, 28)
        database.add_retire_entries(10, [(5, 1)])
        rpc = MagicMock()
        rpc.get_chatlist_entries.side_effect = lambda acc, flags, q, c: [10] if flags == 0 else []
        rpc.get_message_ids.return_value = list(range(1, 31))
        rpc.get_message.return_value = {"timestamp": 1}
        deleted_ids = []
        rpc.delete_messages.side_effect = lambda acc, ids: deleted_ids.extend(ids)
        client = MagicMock()
        client.rpc = rpc
        with patch.object(database, "get_all_peers", return_value=[]), patch("bot.time.time", return_value=200000):
            bot.trim_user_chats(client, 1)
        return deleted_ids

    def test_mode_on_keeps_listed_instance(self):
        ids = self.run_trim("on")
        self.assertNotIn(5, ids)
        self.assertNotIn(28, ids)
        self.assertIn(6, ids)

    def test_mode_dry_and_off_trim_as_before(self):
        for mode in ("dry", "off"):
            self.assertIn(5, self.run_trim(mode), mode)

    def test_retire_ids_helper(self):
        database.add_retire_entries(10, [(5, 1), (6, 1)])
        database.add_retire_entries(11, [(7, 1)])
        self.assertEqual(database.get_retire_message_ids(), {5, 6, 7})


if __name__ == "__main__":
    unittest.main()
