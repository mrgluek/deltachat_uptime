import json
import os
import sqlite3
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_peer_fingerprint.db"

SELF_FP = "D58B5E6C55482F94F9F5B84B6FB9FE3AD2658082"
RU_FP = "DEC0E8D11FC4686F2C715C56F8C9AD699BC19AD8"
EVIL_FP = "9E1B0E5B8CB9CAE6A9D4F0D558C6D85CE9BD3041"


def _wrap(tag: str, payload: dict) -> str:
    return f"[{tag}]\n{json.dumps(payload)}\n[/{tag}]"


def _grouped(fp: str) -> str:
    """Fingerprint as Delta Chat prints it: groups of four, five groups per line."""
    groups = [fp[i:i + 4] for i in range(0, len(fp), 4)]
    return " ".join(groups[:5]) + "\n" + " ".join(groups[5:])


def _encinfo(peer_addr: str, peer_fp: str) -> str:
    """get_contact_encryption_info() text as returned by deltachat-rpc-server."""
    return (
        "Messages are end-to-end encrypted.\nFingerprints:\n\n"
        f"Me (uptimebot@chatmail.uk):\n{_grouped(SELF_FP)}\n\n"
        f"{peer_addr} ({peer_addr}):\n{_grouped(peer_fp)}\n\n"
        f"Relays:\n{peer_addr}"
    )


class TestPeerFingerprintBinding(unittest.TestCase):
    """Peers are identified by their key, so a bot switching relays keeps its peering."""

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot.pending_peer_checks.clear()
        bot._processed_msg_ids.clear()
        bot._dns_cache.clear()
        dns_patcher = patch("bot.resolve_host_safe", AsyncMock(return_value=["93.184.216.34"]))
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        bot.pending_peer_checks.clear()
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    # ---- helpers -------------------------------------------------------------

    def _make_bot(self, sender_addr: str, fp: str | None):
        mock_bot = MagicMock()
        contact = MagicMock()
        contact.address = sender_addr
        mock_bot.rpc.get_contact.return_value = contact
        mock_bot.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        mock_bot.rpc.get_contact_encryption_info.return_value = _encinfo(sender_addr, fp) if fp else "No encryption."
        return mock_bot

    def _event(self, text: str, chat_id: int, padlock: bool = True):
        event = MagicMock()
        event.msg.is_info = False
        event.msg.from_id = 42
        event.msg.chat_id = chat_id
        event.msg.text = text
        event.msg.show_padlock = padlock
        return event

    def _metrics(self, url="https://peer-target.example.org"):
        return _wrap("UPTIME_PEER_METRICS", {
            "metrics": [{"url": url, "type": "http", "status": "up", "latency_ms": 7}],
        })

    def _measured_by(self, url="https://peer-target.example.org"):
        return [m["node_name"] for m in database.get_peer_measurements_for_url(url)]

    # ---- fingerprint parsing -------------------------------------------------

    def test_normalize_fingerprint(self):
        self.assertEqual(database.normalize_fingerprint(_grouped(RU_FP).lower()), RU_FP)
        self.assertEqual(database.normalize_fingerprint("DE:C0:" + RU_FP[4:]), RU_FP)
        self.assertIsNone(database.normalize_fingerprint("DEC0E8D1"))
        self.assertIsNone(database.normalize_fingerprint(None))
        self.assertIsNone(database.normalize_fingerprint(MagicMock()))

    def test_peer_fingerprint_is_the_peer_block_not_ours(self):
        mock_bot = self._make_bot("ruptimebot@chatmail.uk", RU_FP)
        self.assertEqual(bot._get_peer_fingerprint(mock_bot, 1, 42, "ruptimebot@chatmail.uk"), RU_FP)
        # Address in the header differs (e.g. contact shows another relay): the single non-"Me" key is used
        self.assertEqual(bot._get_peer_fingerprint(mock_bot, 1, 42, "other@example.org"), RU_FP)

    def test_peer_fingerprint_unavailable(self):
        mock_bot = self._make_bot("ruptimebot@chatmail.uk", None)
        self.assertIsNone(bot._get_peer_fingerprint(mock_bot, 1, 42, "ruptimebot@chatmail.uk"))
        mock_bot.rpc.get_contact_encryption_info.side_effect = Exception("special contact")
        self.assertIsNone(bot._get_peer_fingerprint(mock_bot, 1, 42, "ruptimebot@chatmail.uk"))

    # ---- migration of peers stored without a key -----------------------------

    def test_fingerprint_column_added_to_existing_db(self):
        database.close_db()
        os.remove(TEST_DB)
        conn = sqlite3.connect(TEST_DB)
        conn.execute("CREATE TABLE peers (email TEXT PRIMARY KEY, node_name TEXT, chat_id INTEGER, last_seen INTEGER)")
        conn.execute("INSERT INTO peers VALUES ('old@example.org', 'Old', 5, 0)")
        conn.commit()
        conn.close()

        database.init_db()
        peer = database.get_peer("old@example.org")
        self.assertIn("fingerprint", peer)
        self.assertIsNone(peer["fingerprint"])

    def test_legacy_peer_on_new_relay_is_bound_by_its_chat(self):
        """The RU case: stored as ruptimebo@chat.gluek.info, now sends from ruptimebot@chatmail.uk in chat 27."""
        database.add_or_update_peer("ruptimebo@chat.gluek.info", "RU", 27)
        database.save_probe_targets_batch([{"url": "https://mirrored.example.org"}], "ruptimebo@chat.gluek.info")

        mock_bot = self._make_bot("ruptimebot@chatmail.uk", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27))

        self.assertEqual(self._measured_by(), ["RU"])
        self.assertIsNone(database.get_peer("ruptimebo@chat.gluek.info"))
        peer = database.get_peer("ruptimebot@chatmail.uk")
        self.assertEqual(peer["fingerprint"], RU_FP)
        self.assertEqual(peer["chat_id"], 27)
        sources = {t["url"]: t.get("source_peer") for t in database.get_active_probe_targets()}
        self.assertEqual(sources["https://mirrored.example.org"], "ruptimebot@chatmail.uk")

    def test_legacy_peer_with_same_address_is_bound(self):
        database.add_or_update_peer("ru@example.org", "RU", 27)
        mock_bot = self._make_bot("ru@example.org", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27))

        self.assertEqual(database.get_peer("ru@example.org")["fingerprint"], RU_FP)
        self.assertEqual(self._measured_by(), ["RU"])

    def test_legacy_peer_not_matched_by_chat_without_a_key(self):
        database.add_or_update_peer("ruptimebo@chat.gluek.info", "RU", 27)
        mock_bot = self._make_bot("ruptimebot@chatmail.uk", None)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27))

        self.assertEqual(self._measured_by(), [])
        self.assertIsNotNone(database.get_peer("ruptimebo@chat.gluek.info"))

    def test_legacy_peer_not_matched_by_chat_when_unencrypted(self):
        database.add_or_update_peer("ruptimebo@chat.gluek.info", "RU", 27)
        mock_bot = self._make_bot("ruptimebot@chatmail.uk", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27, padlock=False))

        self.assertEqual(self._measured_by(), [])
        self.assertIsNone(database.get_peer("ruptimebo@chat.gluek.info")["fingerprint"])

    # ---- key-bound peers -----------------------------------------------------

    def test_bound_peer_accepted_from_any_relay_address(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)

        mock_bot = self._make_bot("ru@relay-b.example", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27))
        self.assertEqual(self._measured_by(), ["RU"])
        self.assertEqual(database.get_peer_by_fingerprint(RU_FP)["email"], "ru@relay-b.example")

        # ...and back to the first relay
        mock_bot = self._make_bot("ru@relay-a.example", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics("https://second.example.org"), chat_id=27))
        self.assertEqual(self._measured_by("https://second.example.org"), ["RU"])
        self.assertEqual(database.get_peer_by_fingerprint(RU_FP)["email"], "ru@relay-a.example")
        self.assertEqual(len(database.get_all_peers()), 1)

    def test_bound_peer_moved_to_new_chat(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        mock_bot = self._make_bot("ru@relay-a.example", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=99))

        self.assertEqual(database.get_peer_by_fingerprint(RU_FP)["chat_id"], 99)

    def test_same_address_other_key_is_dropped(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        mock_bot = self._make_bot("ru@relay-a.example", EVIL_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27))

        self.assertEqual(self._measured_by(), [])
        self.assertEqual(database.get_peer("ru@relay-a.example")["fingerprint"], RU_FP)

    def test_bound_peer_unencrypted_is_dropped(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        mock_bot = self._make_bot("ru@relay-a.example", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(self._metrics(), chat_id=27, padlock=False))

        self.assertEqual(self._measured_by(), [])

    def test_fingerprint_is_never_replaced(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=EVIL_FP)
        self.assertEqual(database.get_peer("ru@relay-a.example")["fingerprint"], RU_FP)
        self.assertIsNone(database.bind_peer_identity("missing@example.org", fingerprint=RU_FP))

    def test_cross_check_answer_from_new_relay_address_is_counted(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        import asyncio
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        fut = loop.create_future()
        responses = []
        bot.pending_peer_checks["req-fp"] = (fut, 1, responses, {27})

        mock_bot = self._make_bot("ru@relay-b.example", RU_FP)
        text = _wrap("UPTIME_PEER_CHECK_RESP", {"req_id": "req-fp", "url": "https://site.example.org", "status": "up", "latency_ms": 5})
        bot.on_new_message(mock_bot, 1, self._event(text, chat_id=27))

        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["node_name"], "RU")

    # ---- address conflicts on rename -----------------------------------------

    def test_rename_drops_stale_row_of_same_bot(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.add_or_update_peer("ru@relay-b.example", "RU (re-added)", 30)
        updated = database.bind_peer_identity("ru@relay-a.example", new_email="ru@relay-b.example")

        self.assertEqual(updated["email"], "ru@relay-b.example")
        self.assertEqual(updated["fingerprint"], RU_FP)
        self.assertEqual(len(database.get_all_peers()), 1)

    def test_rename_blocked_by_row_of_other_key(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.add_or_update_peer("ru@relay-b.example", "Other", 30, fingerprint=EVIL_FP)
        updated = database.bind_peer_identity("ru@relay-a.example", new_email="ru@relay-b.example")

        self.assertEqual(updated["email"], "ru@relay-a.example")
        self.assertEqual(database.get_peer("ru@relay-b.example")["fingerprint"], EVIL_FP)

    # ---- handshake and commands ----------------------------------------------

    def test_hello_with_token_binds_key(self):
        token = database.create_peer_invite_token()
        mock_bot = self._make_bot("new@relay.example", RU_FP)
        bot.on_new_message(mock_bot, 1, self._event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "RU", "invite_token": token}), chat_id=27))

        self.assertEqual(database.get_peer("new@relay.example")["fingerprint"], RU_FP)

    @patch("bot._is_dc_admin", return_value=True)
    def test_addpeer_securejoin_binds_invite_fingerprint(self, mock_is_admin):
        mock_bot = MagicMock()
        mock_bot.rpc.check_qr.return_value = {"kind": "askVerifyContact", "address": "ru@relay-a.example", "fingerprint": RU_FP}
        mock_bot.rpc.secure_join.return_value = 27
        event = MagicMock()
        event.msg.chat_id = 1
        event.payload = "https://i.delta.chat/#invite token=abc RU"
        bot.addpeer_command(mock_bot, 1, event)
        self.assertEqual(database.get_peer("ru@relay-a.example")["fingerprint"], RU_FP)

        # Re-adding the same bot from an invite showing another relay keeps one row
        mock_bot.rpc.check_qr.return_value = {"kind": "askVerifyContact", "address": "ru@relay-b.example", "fingerprint": RU_FP}
        mock_bot.rpc.secure_join.return_value = 28
        event.payload = "https://i.delta.chat/#invite2 token=def RU"
        bot.addpeer_command(mock_bot, 1, event)
        peers = database.get_all_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["email"], "ru@relay-b.example")
        self.assertEqual(peers[0]["chat_id"], 28)

    @patch("bot._is_dc_admin", return_value=True)
    def test_rmpeer_by_key_prefix(self, mock_is_admin):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.add_or_update_peer("it@relay.example", "IT", 42, fingerprint="DEC0" + EVIL_FP[4:])
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 1

        event.payload = "DEC0"  # too short
        bot.rmpeer_command(mock_bot, 1, event)
        event.payload = "dec0 e8d1"  # unique prefix, grouped as /peers shows it
        bot.rmpeer_command(mock_bot, 1, event)

        self.assertIsNone(database.get_peer("ru@relay-a.example"))
        self.assertIsNotNone(database.get_peer("it@relay.example"))
        self.assertIn("removed", mock_bot.rpc.send_msg.call_args.args[2].text)

    @patch("bot._is_dc_admin", return_value=True)
    def test_peers_command_shows_key(self, mock_is_admin):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.add_or_update_peer("old@example.org", "Old", 5)
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 1
        bot.peers_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("DEC0 E8D1 1FC4 686F", text)
        self.assertIn("not bound yet", text)


    # ---- node names ----------------------------------------------------------

    def test_renamed_peer_node_is_picked_up_with_measurements(self):
        database.add_or_update_peer("ru@relay-a.example", "RU", 27, fingerprint=RU_FP)
        database.save_peer_measurement("https://old.example.org", "RU", "up", 5)
        mock_bot = self._make_bot("ru@relay-a.example", RU_FP)
        text = _wrap("UPTIME_PEER_METRICS", {"node_name": "RU 🏠", "metrics": [
            {"url": "https://peer-target.example.org", "type": "http", "status": "up", "latency_ms": 7}]})
        bot.on_new_message(mock_bot, 1, self._event(text, chat_id=27))

        self.assertEqual(database.get_peer("ru@relay-a.example")["node_name"], "RU 🏠")
        self.assertEqual(self._measured_by(), ["RU 🏠"])
        self.assertEqual([m["node_name"] for m in database.get_peer_measurements_for_url("https://old.example.org")], ["RU 🏠"])

    @patch("bot._is_dc_admin", return_value=True)
    def test_nodename_moves_local_measurements_and_announces(self, mock_is_admin):
        database.set_local_node_name("DE")
        database.save_peer_measurement("https://site.example.org", "DE", "up", 5)
        bot.last_peer_telemetry_broadcast = 12345.0
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 1
        event.payload = "🇩🇪 DE"
        bot.nodename_command(mock_bot, 1, event)

        self.assertEqual(database.get_local_node_name(), "🇩🇪 DE")
        self.assertEqual([m["node_name"] for m in database.get_peer_measurements_for_url("https://site.example.org")], ["🇩🇪 DE"])
        self.assertEqual(bot.last_peer_telemetry_broadcast, 0.0)


if __name__ == "__main__":
    unittest.main()
