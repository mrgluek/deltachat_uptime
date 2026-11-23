"""3.0.3: trim of hidden status update carriers found in the core database."""
import os
import sqlite3
import time
import unittest
from unittest.mock import MagicMock, patch

import bot
import database
from test_audit4_fixes import AuditCase

NOW = 2_000_000
_REAL_CONNECT = sqlite3.connect
BIG = '0=1\nE={"updates":[{"payload":{"chat":"x","pad":"' + "x" * 3000 + '"}}]}'


class FakeRpc:
    def __init__(self, db_path, delete_error=None):
        self.db_path = db_path
        self.deleted = []
        self.calls = []
        self.info_calls = 0

    def get_info(self, accid):
        self.info_calls += 1
        return {"database_dir": self.db_path}

    def delete_messages(self, accid, ids):
        self.calls.append(list(ids))
        self.deleted.extend(ids)
        conn = _REAL_CONNECT(self.db_path)
        conn.executemany("DELETE FROM msgs WHERE id = ?", [(i,) for i in ids])
        conn.commit()
        conn.close()


class TestHiddenTrim(AuditCase):
    def setUp(self):
        super().setUp()
        self.core = os.path.join(self.tmp.name, "dc.db")
        conn = sqlite3.connect(self.core)
        conn.execute("CREATE TABLE msgs (id INTEGER PRIMARY KEY, chat_id INTEGER, from_id INTEGER, type INTEGER, "
                     "hidden INTEGER, timestamp INTEGER, param TEXT)")
        rows = []
        old = NOW - 3 * 86400
        # ids 1..1500 qualify (hidden carriers of the bot, old, big)
        for i in range(1, 1501):
            rows.append((i, 12, 1, 10, 1, old, BIG))
        # Never touch: visible, young, small, someone else's, other type, no E= marker
        rows += [(2001, 12, 1, 10, 0, old, BIG), (2002, 12, 1, 10, 1, NOW - 3600, BIG),
                 (2003, 12, 1, 10, 1, old, "0=1"), (2004, 12, 2, 10, 1, old, BIG),
                 (2005, 12, 1, 80, 1, old, BIG), (2006, 12, 1, 10, 1, old, "0=1\n" + "y" * 3000)]
        # Plenty of ordinary small messages
        rows += [(10000 + i, 12, 1 if i % 2 else 2, 10, i % 2, old, "0=1") for i in range(18000)]
        conn.executemany("INSERT INTO msgs VALUES (?,?,?,?,?,?,?)", rows)
        conn.commit()
        conn.close()
        self.rpc = FakeRpc(self.core)
        self.bot = MagicMock()
        self.bot.rpc = self.rpc
        self.stack.enter_context(patch.object(bot, "_storage_config_dir", None))
        self.opens = []
        real = sqlite3.connect
        self.stack.enter_context(patch.object(bot.sqlite3, "connect", side_effect=lambda *a, **k: (self.opens.append(a[0]), real(*a, **k))[1]))
        for key in ("hidden_trimmed", "hidden_bytes"):
            bot._bot_stats[key] = 0
        bot._bot_stats["hidden_candidates"] = None
        bot._hidden_trim_warned.clear()

    def remaining(self):
        conn = sqlite3.connect(self.core)
        try:
            return {r[0] for r in conn.execute("SELECT id FROM msgs")}
        finally:
            conn.close()

    def core_opens(self):
        return [o for o in self.opens if "dc.db" in str(o)]

    def test_default_mode_is_dry_and_deletes_nothing(self):
        self.assertEqual(bot.get_hidden_trim_mode(), "dry")
        self.assertEqual(bot.trim_hidden_status_updates(self.bot, 1, NOW), 0)
        self.assertEqual(self.rpc.calls, [])
        self.assertEqual(bot._bot_stats["hidden_candidates"], bot.HIDDEN_TRIM_MAX)
        self.assertGreater(bot._bot_stats["hidden_bytes"], 500 * 3000)
        self.assertEqual(len(self.core_opens()), 1)

    def test_off_does_not_open_the_core_database(self):
        database.set_config("hidden_trim", "off")
        bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertEqual(self.core_opens(), [])
        self.assertEqual(self.rpc.calls, [])

    def test_on_bounds_connections_and_calls_per_pass(self):
        database.set_config("hidden_trim", "on")
        deleted = bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertEqual(deleted, 500)
        self.assertEqual(len(self.core_opens()), 1)
        self.assertLessEqual(len(self.rpc.calls), 10)
        self.assertTrue(all(len(c) <= 50 for c in self.rpc.calls))
        self.assertEqual(self.rpc.deleted, list(range(1, 501)))  # oldest first

    def test_backlog_clears_over_passes_and_leaves_everything_else(self):
        database.set_config("hidden_trim", "on")
        total = 0
        for _ in range(5):
            total += bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertEqual(total, 1500)
        left = self.remaining()
        self.assertFalse(left & set(range(1, 1501)))
        self.assertTrue({2001, 2002, 2003, 2004, 2005, 2006} <= left)
        self.assertEqual(len(left), 6 + 18000)
        self.assertEqual(bot._bot_stats["hidden_trimmed"], 1500)
        self.assertEqual(bot.trim_hidden_status_updates(self.bot, 1, NOW), 0)  # nothing left, no deletes

    def test_protected_ids_are_never_deleted(self):
        database.set_config("hidden_trim", "on")
        with patch.object(database, "get_retained_message_ids", return_value={1, 2, 3}), \
                patch.object(database, "get_peer_rt_message_ids", return_value={4, 5}):
            bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertFalse(set(self.rpc.deleted) & {1, 2, 3, 4, 5})
        self.assertIn(6, self.rpc.deleted)

    def test_peer_channel_id_added_during_the_pass_is_protected(self):
        database.set_config("hidden_trim", "on")
        real = database.get_peer_rt_message_ids
        state = {"n": 0}

        def late():
            state["n"] += 1
            return {10} if state["n"] > 1 else real()
        with patch.object(database, "get_peer_rt_message_ids", side_effect=late):
            bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertNotIn(10, self.rpc.deleted)

    def test_young_messages_are_kept(self):
        database.set_config("hidden_trim", "on")
        # 12 hours after the carriers were written: none is 24 h old
        self.assertEqual(bot.trim_hidden_status_updates(self.bot, 1, NOW - 3 * 86400 + 43200), 0)
        self.assertEqual(self.rpc.calls, [])

    def test_missing_database_is_harmless_and_warned_once(self):
        database.set_config("hidden_trim", "on")
        self.rpc.db_path = os.path.join(self.tmp.name, "nope", "dc.db")
        with self.assertLogs(bot.logger, level="WARNING") as logs:
            self.assertEqual(bot.trim_hidden_status_updates(self.bot, 1, NOW), 0)
            self.assertEqual(bot.trim_hidden_status_updates(self.bot, 1, NOW), 0)
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(self.rpc.calls, [])

    def test_rpc_without_info_falls_back_to_the_only_account_dir(self):
        database.set_config("hidden_trim", "dry")
        acc = os.path.join(self.tmp.name, "cfg", "accounts", "uuid1")
        os.makedirs(acc)
        os.replace(self.core, os.path.join(acc, "dc.db"))
        self.rpc.get_info = MagicMock(side_effect=RuntimeError("no"))
        with patch.object(bot, "_storage_config_dir", os.path.join(self.tmp.name, "cfg")):
            bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertEqual(bot._bot_stats["hidden_candidates"], 500)

    def test_database_is_opened_read_only(self):
        database.set_config("hidden_trim", "dry")
        bot.trim_hidden_status_updates(self.bot, 1, NOW)
        self.assertTrue(all("mode=ro" in str(o) for o in self.core_opens()))
        with self.assertRaises(sqlite3.OperationalError):
            conn = sqlite3.connect(f"file:{self.core}?mode=ro", uri=True)
            conn.execute("DELETE FROM msgs")

    def test_command_shows_and_sets_the_mode(self):
        sent = []
        event = MagicMock()
        event.msg.from_id = 7
        event.payload = ""
        with patch.object(bot, "_is_dc_admin", return_value=True), \
                patch.object(bot, "_dc_send_msg_with_stats", side_effect=lambda b, a, c, m, **k: sent.append(m.text)), \
                patch.object(bot, "_command_allowed", return_value=True, create=True):
            bot.hiddentrim_command(self.bot, 1, event)
            event.payload = "on"
            bot.hiddentrim_command(self.bot, 1, event)
            event.payload = "bogus"
            bot.hiddentrim_command(self.bot, 1, event)
        self.assertIn("`dry`", sent[0])
        self.assertEqual(database.get_config("hidden_trim"), "on")
        self.assertIn("Usage", sent[2])


if __name__ == "__main__":
    unittest.main()
