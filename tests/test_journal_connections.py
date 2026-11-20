"""The 30 s journal pass must not open a database connection per outage row."""
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

try:
    import deltachat2
except ImportError:
    module = MagicMock()
    module.MsgData = lambda **kwargs: type("MsgData", (), kwargs)()
    sys.modules["deltachat2"] = module
try:
    import deltabot_cli
except ImportError:
    module = MagicMock()
    module.BotCli.return_value.on.side_effect = lambda *a, **kw: lambda f: f
    sys.modules["deltabot_cli"] = module

import bot
import database


class CountConnections:
    """Counts database._connect() calls, which every get_config()/reader makes."""

    def __enter__(self):
        self.calls = 0
        real = database._connect

        def counting(*args, **kwargs):
            self.calls += 1
            return real(*args, **kwargs)

        self.patcher = patch.object(database, "_connect", counting)
        self.patcher.start()
        return self

    def __exit__(self, *exc):
        self.patcher.stop()


class TestGetConfigs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "configs.db")
        database.init_db()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def test_missing_keys_are_absent_and_values_match_get_config(self):
        database.set_config("a", "1")
        database.set_config("b", "off")
        found = database.get_configs(["a", "b", "missing", "a"])
        self.assertEqual(found, {"a": "1", "b": "off"})
        self.assertEqual(found["b"], database.get_config("b"))
        self.assertIsNone(found.get("missing"))

    def test_empty_input_opens_no_connection(self):
        with CountConnections() as counter:
            self.assertEqual(database.get_configs([]), {})
            self.assertEqual(database.get_configs(k for k in ()), {})
        self.assertEqual(counter.calls, 0)

    def test_more_keys_than_one_query_holds_still_uses_one_connection(self):
        for i in range(0, 1200, 3):
            database.set_config(f"k{i}", str(i))
        with CountConnections() as counter:
            found = database.get_configs(f"k{i}" for i in range(1200))
        self.assertEqual(counter.calls, 1)
        self.assertEqual(len(found), 400)
        self.assertEqual(found["k1197"], "1197")

    def test_parse_chat_report_partial_matches_the_getter(self):
        self.assertEqual(database.parse_chat_report_partial(None), 10)
        self.assertEqual(database.parse_chat_report_partial("off"), "off")
        self.assertEqual(database.parse_chat_report_partial("0"), 0)
        self.assertEqual(database.parse_chat_report_partial("45"), 45)
        database.set_chat_report_partial(7, 45)
        self.assertEqual(database.get_chat_report_partial(7), 45)


class TestJournalConnections(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "journal.db")
        database.init_db()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def seed_ended_outages(self, chats, per_chat):
        """Ended partial outages whose start was already journaled, so each row owes a partial_end."""
        now = int(time.time())
        for chat in chats:
            database.get_or_create_chat_token(chat)
            for i in range(per_chat):
                rid = database.add_resource(chat, f"https://e{chat}-{i}.example.org", f"R{chat}-{i}", "http")
                database.update_resource_alert_state(rid, "up", "[]", 0)
                database.start_partial_outage(rid, now - 3600, "[]")
                database.end_partial_outage(rid, now - 1800)
        for row in database.get_partial_journal_rows():
            database.set_config(f"journal:partial_start:{row['dc_chat_id']}:{row['partial_id']}", "1")

    def events(self, chat, kind):
        return [e for e in database.get_recent_chat_events(chat, 5000) if e["kind"] == kind]

    def test_partial_pass_uses_a_constant_number_of_connections(self):
        self.seed_ended_outages([1, 2, 3], 4)
        with CountConnections() as small:
            bot._journal_partial_events()
        self.assertLessEqual(small.calls, 3)

    def test_partial_pass_connections_do_not_grow_with_the_journal(self):
        self.seed_ended_outages([1, 2, 3], 60)
        self.assertEqual(len(database.get_partial_journal_rows()), 180)
        with CountConnections() as counter:
            bot._journal_partial_events()
        self.assertLessEqual(counter.calls, 3)
        for chat in (1, 2, 3):
            self.assertEqual(len(self.events(chat, "partial_end")), 60)

    def test_results_stay_per_chat_with_off_and_single_chat_filter(self):
        self.seed_ended_outages([1, 2, 3], 5)
        database.set_chat_report_partial(2, "off")
        bot._journal_partial_events(chat_id=1)
        self.assertEqual(len(self.events(1, "partial_end")), 5)
        self.assertEqual(len(self.events(2, "partial_end")), 0)
        self.assertEqual(len(self.events(3, "partial_end")), 0)
        bot._journal_partial_events()
        self.assertEqual(len(self.events(1, "partial_end")), 5)  # once per outage
        self.assertEqual(len(self.events(2, "partial_end")), 0)  # chat 2 is off
        self.assertEqual(len(self.events(3, "partial_end")), 5)

    def test_ended_outage_without_a_journaled_start_stays_silent(self):
        self.seed_ended_outages([1], 3)
        row = database.get_partial_journal_rows()[0]
        with database._writer_transaction() as conn:
            conn.execute("DELETE FROM config WHERE key = ?", (f"journal:partial_start:1:{row['partial_id']}",))
        bot._journal_partial_events()
        self.assertEqual(len(self.events(1, "partial_end")), 2)

    def test_incident_pass_uses_one_connection_for_all_ended_events(self):
        events = [{"id": i, "resource_id": 1, "went_down_at": 100, "went_up_at": 200} for i in range(1, 51)]
        events.append({"id": 99, "resource_id": 1, "went_down_at": 100, "went_up_at": None})
        for i in range(1, 51, 2):
            database.set_config(f"journal:incident_start:1:{i}", "1")
        added = []
        with patch.object(database, "add_chat_event", lambda *a, **kw: added.append((a[1], kw.get("once")))), \
                patch.object(bot, "_journal_outage_text", return_value="text"), \
                CountConnections() as counter:
            bot._journal_incident_events(1, events, {1: {"name": "R"}}, 1000)
        self.assertLessEqual(counter.calls, 3)
        self.assertEqual(sorted(once for kind, once in added if kind == "incident_end"), list(range(1, 51, 2)))


if __name__ == "__main__":
    unittest.main()
