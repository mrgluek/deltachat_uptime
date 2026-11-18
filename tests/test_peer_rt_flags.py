import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import bot
import database


EMAIL = "peer@example.org"
FINGERPRINT = "AB" * 20
CHAT_ID = 123
CARRIER = dict(cid="0123456789abcdef", msg_id=456, key_out=b"a" * 32,
               key_in=b"b" * 32, created_at=789)


class TestPeerRTFlags(unittest.TestCase):
    def setUp(self):
        database.close_db()
        temp_dir = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(database, "DB_PATH", os.path.join(temp_dir, "test.db")))
        self.addCleanup(database.close_db)
        database.init_db()
        self.add_peer()

    def add_peer(self):
        database.add_or_update_peer(EMAIL, "Peer Name", CHAT_ID, fingerprint=FINGERPRINT)

    def invoke(self, command, payload=None, *, admin=True):
        msg = SimpleNamespace(chat_id=42, from_id=51)
        event = SimpleNamespace(msg=msg, payload=payload)
        rpc_bot = MagicMock()
        with patch.object(bot, "_is_dc_admin", return_value=admin), \
             patch.object(bot, "_dc_send_msg_with_stats") as send:
            command(rpc_bot, 1, event)
        send.assert_called_once()
        return send.call_args.args[3].text

    def set_flag(self, payload=None, *, admin=True):
        return self.invoke(bot.peerrt_command, payload, admin=admin)

    def assert_carrier(self, mode, stored):
        expected = {f"rt_{key}": value if stored else None for key, value in CARRIER.items()}
        self.assertEqual(database.get_peer_rt(FINGERPRINT), dict(expected, rt_mode=mode))

    def test_default_and_invalid_flags(self):
        self.assertEqual(database.get_peer_rt_flag(), "off")
        self.assertIn("`off`", self.set_flag())
        for invalid in ("auto", "yes", "canary extra", "Peer Name canary"):
            with self.subTest(invalid=invalid):
                self.assertIn("Usage:", self.set_flag(invalid))
        self.assertIsNone(database.get_config("peer_rt"))
        with self.assertRaises(ValueError):
            database.set_peer_rt_flag("yes")
        with self.assertRaises(ValueError):
            database.set_peer_rt_mode(EMAIL, "canary")
        database.set_config("peer_rt", "invalid")
        self.assertEqual(database.get_peer_rt_flag(), "off")
        self.assert_carrier("auto", False)

    def test_capability_updates_and_leaves_base_order_intact(self):
        base = ["batch_check", "smtp_check"]
        self.assertEqual(bot._own_peer_caps(), base)
        for value in ("Canary", " ON  ", "off"):
            with self.subTest(value=value):
                flag = value.strip().lower()
                self.assertIn(f"`{flag}`", self.set_flag(value))
                self.assertEqual(database.get_peer_rt_flag(), flag)
                self.assertEqual(bot._own_peer_caps(), base if flag == "off" else base + ["rt1"])

    def test_replayed_answer_advertises_current_capability(self):
        caps = bot._own_peer_caps()
        cached = ("CHECK_RESP", {"req_id": "req", "caps": caps})
        with patch.object(bot._inbound_probes, "cached_answer", return_value=cached), \
             patch.object(bot, "_send_peer_check_answer") as send:
            database.set_peer_rt_flag("on")
            self.assertTrue(bot._resend_cached_probe_answer(MagicMock(), 1, CHAT_ID, {}, "req"))
            self.assertIn("rt1", send.call_args.args[2]["caps"])
            database.set_peer_rt_flag("off")
            self.assertTrue(bot._resend_cached_probe_answer(MagicMock(), 1, CHAT_ID, {}, "req"))
            self.assertEqual(send.call_args.args[2]["caps"], caps)
        self.assertNotIn("rt1", cached[1]["caps"])

    def test_admin_only(self):
        for payload in (None, "on", "Peer Name on"):
            with self.subTest(payload=payload):
                self.assertIn("only for the administrator", self.set_flag(payload, admin=False))
        self.assertEqual(database.get_peer_rt_flag(), "off")
        self.assert_carrier("auto", False)

    def test_peer_mode_by_name_and_email(self):
        for identifier, mode in (("peer name", "ON"), ("PEER@example.org", "off"),
                                 ("Peer Name", "auto")):
            with self.subTest(identifier=identifier, mode=mode):
                self.assertIn(f"`{mode.lower()}`", self.set_flag(f"  {identifier}   {mode}  "))
                self.assert_carrier(mode.lower(), False)
        self.assertIn("not found", self.set_flag("Unknown Peer on"))
        self.assertIn("not found", self.set_flag("unknown@example.org off"))
        self.assert_carrier("auto", False)

    def test_peers_displays_preview_per_peer(self):
        other = "other@example.org"
        database.add_or_update_peer(other, "Other Peer")
        self.assertEqual(self.invoke(bot.peers_command).count("iroh: off"), 2)
        database.set_peer_rt_flag("canary")
        database.set_peer_rt_mode(EMAIL, "on")
        self.assertIn("iroh: mail only (mode: on)", self.invoke(bot.peers_command))
        self.assertIn("iroh: off\n", self.invoke(bot.peers_command))
        database.set_peer_rt_flag("on")
        database.set_peer_rt_mode(other, "off")
        self.assertIn("iroh: off (mode: off)", self.invoke(bot.peers_command))
        database.set_peer_rt_mode(EMAIL, "auto")
        self.assertIn("iroh: mail only\n", self.invoke(bot.peers_command))
        self.assertNotIn("mode: auto", self.invoke(bot.peers_command))

    def test_carrier_cleanup_preserves_mode(self):
        database.set_peer_rt_flag("on")
        database.set_peer_rt_mode(EMAIL, "on")
        self.assertTrue(database.set_peer_rt(FINGERPRINT.lower(), **CARRIER))
        self.assert_carrier("on", True)
        database.clear_peer_rt(FINGERPRINT)
        self.assert_carrier("on", False)

        database.set_peer_rt(FINGERPRINT, **CARRIER)
        database.delete_chat_data(CHAT_ID)
        self.assert_carrier("on", False)
        self.assertEqual(database.get_peer_rt_flag(), "on")

        database.set_peer_rt(FINGERPRINT, **CARRIER)
        database.set_peer_rt_flag("off")
        self.assert_carrier("on", False)

        database.set_peer_rt_flag("canary")
        database.set_peer_rt(FINGERPRINT, **CARRIER)
        database.cleanup_old_records()
        self.assert_carrier("on", True)
        database.set_peer_rt_mode(EMAIL, "auto")
        self.assert_carrier("auto", False)

    def test_removal_drops_carrier_with_peer_row(self):
        database.set_peer_rt_flag("on")
        database.set_peer_rt_mode(EMAIL, "on")
        self.assertTrue(database.set_peer_rt(FINGERPRINT, **CARRIER))
        self.assertTrue(database.remove_peer(EMAIL))
        self.assertIsNone(database.get_peer_rt(FINGERPRINT))
        self.assertFalse(database.set_peer_rt(FINGERPRINT, **CARRIER))
        self.add_peer()
        self.assert_carrier("auto", False)

    def test_old_database_migration_preserves_peer(self):
        old_path = database.DB_PATH + ".old"
        with closing(sqlite3.connect(old_path)) as conn, conn:
            conn.execute("""
                CREATE TABLE peers (email TEXT PRIMARY KEY, node_name TEXT, chat_id INTEGER,
                                    last_seen INTEGER, created_at INTEGER, fingerprint TEXT)
            """)
            conn.execute("INSERT INTO peers VALUES (?, ?, ?, ?, ?, ?)",
                         (EMAIL, "Old Peer", CHAT_ID, 1, 2, FINGERPRINT))
        with patch.object(database, "DB_PATH", old_path):
            database.init_db()
            database.init_db()
            self.assertEqual(database.get_peer_rt_flag(), "off")
            self.assert_carrier("auto", False)
            self.assertEqual(database.get_peer(EMAIL)["node_name"], "Old Peer")
            self.assertEqual(database.get_peer(EMAIL)["chat_id"], CHAT_ID)

    def test_carrier_migration_preserves_capability_and_hourly_budget(self):
        now = CARRIER["created_at"]
        retry, hourly_limit = bot.PEER_RT_OFFER_RETRY, bot.PEER_RT_OFFERS_PER_HOUR
        database.set_peer_rt_flag("on")
        self.assertTrue(database.reserve_peer_rt_offer(FINGERPRINT, now, retry, hourly_limit))
        database.save_peer_rt_offer(FINGERPRINT, CARRIER["cid"], CARRIER["msg_id"], CARRIER["key_out"])
        self.assertTrue(database.set_peer_rt(FINGERPRINT, **CARRIER))
        database.close_db()
        with closing(sqlite3.connect(database.DB_PATH)) as conn, conn:
            conn.execute("ALTER TABLE peers DROP COLUMN rt_capable")
            conn.execute("DROP TABLE peer_rt_offer_attempts")
            conn.execute("CREATE TABLE peer_rt_offer_attempts (fingerprint TEXT NOT NULL, attempted_at INTEGER NOT NULL)")
            conn.execute("INSERT INTO peer_rt_offer_attempts VALUES (?, ?)", (FINGERPRINT, now))
        database.init_db()
        self.assertTrue(database.get_peer(EMAIL)["rt_capable"])
        database.set_peer_rt_flag("off")
        database.set_peer_rt_flag("on")
        self.assertTrue(database.reserve_peer_rt_offer(FINGERPRINT, now + 1, retry, hourly_limit))
        database.set_peer_rt_flag("off")
        database.set_peer_rt_flag("on")
        self.assertFalse(database.reserve_peer_rt_offer(FINGERPRINT, now + 2, retry, hourly_limit))
        self.assertTrue(database.reserve_peer_rt_offer(FINGERPRINT, now + retry + 1, retry, hourly_limit))
        self.assertFalse(database.reserve_peer_rt_offer(FINGERPRINT, now + 2 * retry + 1, retry, hourly_limit))
