"""The 30 s journal pass must not open a database connection per outage row."""
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing, contextmanager
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

    def test_pending_partial_pass_searches_the_ended_index(self):
        statements = []
        conn = sqlite3.connect(database.DB_PATH)
        conn.set_trace_callback(statements.append)
        with patch.object(database, "_connect", return_value=conn):
            database.get_partial_journal_rows(pending_only=True)
        with closing(sqlite3.connect(database.DB_PATH)) as conn:
            plan = conn.execute("EXPLAIN QUERY PLAN " + statements[0]).fetchall()
        self.assertTrue(any("SEARCH po USING INDEX idx_partial_outages_ended" in row[3] for row in plan), plan)

    def test_pending_partial_pass_excludes_unjournaled_ends(self):
        now = int(time.time())
        with database._writer_transaction() as conn:
            conn.execute("INSERT INTO resources(id, dc_chat_id, url) VALUES (1, 7, 'https://one.example.org'), "
                         "(2, 8, 'https://two.example.org')")
            conn.executemany("INSERT INTO partial_outages(id, resource_id, started_at, ended_at) VALUES (?, ?, ?, ?)",
                             [(i, 1, now - 60, now) for i in range(1, 201)] +
                             [(201, 1, now - 60, None), (202, 2, now - 60, None),
                              (203, 1, now - 31 * 86400, now - 31 * 86400)])
            conn.executemany("INSERT INTO config(key, value) VALUES (?, '1')", [
                ("journal:partial_start:7:2",), ("journal:partial_end:7:2",),
                ("journal:partial_start:7:3",), ("journal:partial_start:8:202",),
                ("journal:partial_start:7:203",), ("journal:partial_start:7:04",),
                ("journal:partial_start:8:5",),
            ])
        for chat in (None, 7, "7"):
            self.assertEqual([r["partial_id"] for r in database.get_partial_journal_rows(chat, pending_only=True)],
                             [3, 201])
        self.assertEqual(len(database.get_partial_journal_rows()), 202)

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

    def test_journal_writes_scale_with_new_events(self):
        now = 1_800_000_000
        events = [{"id": n, "resource_id": 1, "went_down_at": now - 3600, "went_up_at": now - 1800}
                  for n in range(1, 2006)]
        events[-1]["went_up_at"] = None
        events[-2]["went_up_at"] = None
        resource = {"name": "Settled", "url": "https://settled.example.org"}
        database.add_resource(1, resource["url"], resource["name"], "http")
        database.add_resource(1, "https://new.example.org", "New", "http")
        database.add_resource(2, "https://off.example.org", "Off", "http")
        database.set_chat_report_partial(2, "off")
        database.update_resource_alert_state(2, "degraded", "[]")
        database.update_resource_alert_state(3, "degraded", "[]")
        with database._writer_transaction() as conn:
            conn.executemany(
                "INSERT INTO partial_outages(id, resource_id, started_at, ended_at, notice_state) "
                "VALUES (?, 1, ?, ?, -1)",
                ((i, now - 3600, now - 1800) for i in range(1, 2003)),
            )
            conn.executemany(
                "INSERT INTO partial_outages(id, resource_id, started_at, ended_at, notice_state) "
                "VALUES (?, ?, ?, NULL, 0)",
                [(2003, 2, now - 1200), (2004, 2, now - 60), (2005, 2, now - 1200), (2006, 3, now - 1200)],
            )
            conn.executemany("INSERT INTO config VALUES (?, '1')", (
                (f"journal:{kind}_{phase}:1:{i}",)
                for i in range(1, 2001) for kind in ("partial", "incident") for phase in ("start", "end")
            ))
            conn.executemany("INSERT INTO config VALUES (?, ?)", [
                ("journal:partial_start:1:2001", "1"),
                ("journal:partial_start:1:2005", None),  # Existing key still blocks a repeat start.
                ("journal:incident_start:1:2001", "1"),
                ("journal:incident_start:1:2005", "1"),
            ])
        holds = []
        transaction = database._writer_transaction

        @contextmanager
        def counting():
            holds.append(1)
            with transaction() as conn:
                yield conn

        with patch.object(database, "_writer_transaction", counting), patch.object(time, "time", return_value=now):
            for _ in range(2):
                bot._journal_partial_events()
                bot._journal_incident_events(1, events, {1: resource}, now)
        with database._writer_transaction() as conn:
            result = conn.execute("SELECT ts, kind, text FROM chat_events WHERE kind LIKE 'partial_%' "
                                  "OR kind LIKE 'incident_%' ORDER BY id").fetchall()
        self.assertEqual(result, [
            (now, "partial_end", "✅ Settled recovered after 30m"),
            (now, "partial_start", "🟠 New is partially down"),
            (now, "incident_end", "✅ Settled recovered after 30m"),
            (now, "incident_start", "🔴 Settled is down"),
        ])
        self.assertEqual(len(holds), len(result))


if __name__ == "__main__":
    unittest.main()
