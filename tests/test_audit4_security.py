import asyncio
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from aiohttp.test_utils import make_mocked_request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bot
import database


class TestAuditSecurity(unittest.TestCase):
    FP = "AB" * 20

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        self.tmp = tempfile.TemporaryDirectory()
        database.DB_PATH = str(Path(self.tmp.name) / "security.db")
        database.init_db()
        env = patch.dict(os.environ, {"ADMIN_DC_EMAIL": "", "ADMIN_DC_FINGERPRINT": ""})
        env.start()
        self.addCleanup(env.stop)
        bot._admin_missing_fp_logged.clear()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        self.tmp.cleanup()
        bot._admin_missing_fp_logged.clear()

    def sender(self, address="owner@example.org", chat_type="Single", encrypted=True):
        client = MagicMock()
        client.rpc.get_contact.return_value.address = address
        client.rpc.get_basic_chat_info.return_value = {"chat_type": chat_type}
        event = MagicMock()
        event.msg.from_id = 42
        event.msg.chat_id = 50
        event.msg.is_info = False
        event.msg.show_padlock = encrypted
        return client, event

    def test_f01_non_global_addresses_blocked(self):
        for addr in ("100.64.0.1", "100.100.100.200", "198.18.0.1", "192.0.0.1",
                     "127.0.0.1", "169.254.1.1", "224.0.0.1", "::ffff:100.64.0.1", "fc00::1"):
            with self.subTest(addr=addr):
                self.assertTrue(bot._is_blocked_ip(ipaddress.ip_address(addr)))
        for addr in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "200::1", "300::1"):
            with self.subTest(addr=addr):
                self.assertFalse(bot._is_blocked_ip(ipaddress.ip_address(addr)))

    def test_f01_any_blocked_dns_answer_rejects_target(self):
        answers = [(2, 1, 6, "", ("93.184.216.34", 0)),
                   (2, 1, 6, "", ("100.100.100.200", 0))]
        bot._dns_cache.clear()
        with patch("socket.getaddrinfo", return_value=answers):
            self.assertFalse(bot.is_safe_target_url("https://mixed-security.example", "http"))

    def test_f02_configured_key_requires_exact_match(self):
        database.set_admin_email("owner@example.org")
        database.set_admin_fingerprint(self.FP)
        client, _ = self.sender()
        for fp, allowed in ((self.FP, True), ("CD" * 20, False), (None, False),
                            (self.FP + "," + "CD" * 20, False)):
            with self.subTest(fp=fp), patch("bot._get_contact_fingerprint", return_value=fp):
                self.assertIs(bot._is_dc_admin(client, 1, 42), allowed)
        self.assertIsNone(database.get_config("admin_chat_id"))

    def test_f02_email_bootstrap_only_without_key(self):
        database.set_admin_email("owner@example.org")
        client, _ = self.sender("OWNER@example.org")
        self.assertTrue(bot._is_dc_admin(client, 1, 42))
        client.rpc.get_contact.return_value.address = "other@example.org"
        self.assertFalse(bot._is_dc_admin(client, 1, 42))

    def test_f02_missing_key_warning_once_per_sender_per_hour(self):
        database.set_admin_fingerprint(self.FP)
        client, _ = self.sender()
        with patch("bot._get_contact_fingerprint", return_value=None), \
             patch("bot.time.monotonic", side_effect=[0, 3599, 3600, 3600]), \
             patch.object(bot.logger, "warning") as warning:
            for sender in (42, 42, 42, 43):
                self.assertFalse(bot._is_dc_admin(client, 1, sender, 50))
        self.assertEqual(warning.call_count, 3)
        self.assertIn("fingerprint unavailable", warning.call_args.args[0])
        self.assertIsNone(database.get_config("admin_chat_id"))

    def test_f02_database_authorization_rejects_partial_fingerprint(self):
        database.set_admin_email("owner@example.org")
        database.set_admin_fingerprint(self.FP)
        self.assertTrue(database.is_authorized_sender("owner@example.org", self.FP))
        self.assertFalse(database.is_authorized_sender("owner@example.org", "FF" + self.FP))
        self.assertFalse(database.is_authorized_sender("owner@example.org", None))

    def test_f06_environment_owner_prevents_claim(self):
        client, event = self.sender("attacker@example.org")
        for settings in ({"ADMIN_DC_EMAIL": " Owner@Example.org "},
                         {"ADMIN_DC_FINGERPRINT": self.FP}):
            with self.subTest(settings=settings), patch.dict(os.environ, settings):
                bot.initadmin_command(client, 1, event)
                self.assertIn("Admin is already set", client.rpc.send_msg.call_args.args[2].text)
                self.assertFalse(database.claim_admin("attacker@example.org"))
                self.assertIsNone(database.get_config("admin_dc_email"))
        client.rpc.get_contact.assert_not_called()

    def test_f06_environment_owner_authorization(self):
        client, _ = self.sender()
        with patch.dict(os.environ, {"ADMIN_DC_EMAIL": "OWNER@example.org"}):
            self.assertTrue(bot._is_dc_admin(client, 1, 42))
            self.assertEqual(database.get_admin_email(), "owner@example.org")
        with patch.dict(os.environ, {"ADMIN_DC_FINGERPRINT": self.FP}), \
             patch("bot._get_contact_fingerprint", return_value=self.FP):
            self.assertTrue(bot._is_dc_admin(client, 1, 42))
            self.assertEqual(database.get_admin_fingerprint(), self.FP)

    def test_f06_initial_claim_stores_owner_together(self):
        client, event = self.sender()
        with patch("bot._get_contact_fingerprint", return_value=self.FP):
            bot.initadmin_command(client, 1, event)
        self.assertEqual(database.get_effective_admin(), ("owner@example.org", self.FP))
        self.assertIn("now the admin", client.rpc.send_msg.call_args.args[2].text)
        client.rpc.get_contact.return_value.address = "second@example.org"
        bot.initadmin_command(client, 1, event)
        self.assertIn("Admin is already set", client.rpc.send_msg.call_args.args[2].text)
        self.assertEqual(database.get_effective_admin(), ("owner@example.org", self.FP))

    def test_f06_concurrent_claim_has_one_winner(self):
        barrier = threading.Barrier(2)

        def claim(index):
            barrier.wait(timeout=5)
            return database.claim_admin(f"owner{index}@example.org", str(index) * 40)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, (1, 2)))
        self.assertEqual(sum(results), 1)
        winner = results.index(True) + 1
        self.assertEqual(database.get_effective_admin(), (f"owner{winner}@example.org", str(winner) * 40))
        self.assertFalse(database.claim_admin("third@example.org"))

    @patch("bot._is_dc_admin", return_value=True)
    def test_f13_group_invite_has_no_secret(self, _admin):
        client, event = self.sender(chat_type="Group")
        with patch("bot.database.create_peer_invite_token") as create:
            bot.invitepeer_command(client, 1, event)
        create.assert_not_called()
        client.rpc.get_chat_securejoin_qr_code.assert_not_called()
        self.assertEqual(client.rpc.send_msg.call_args.args[2].text,
                         "Use this command in a private chat with the bot.")

    @patch("bot._is_dc_admin", return_value=True)
    def test_f13_encrypted_private_invite_emits_token(self, _admin):
        client, event = self.sender()
        client.rpc.get_chat_securejoin_qr_code.return_value = "https://i.delta.chat/#invite"
        bot.invitepeer_command(client, 1, event)
        reply = client.rpc.send_msg.call_args.args[2].text
        token = reply.split("token=", 1)[1].split()[0]
        self.assertTrue(database.consume_peer_invite_token(token))

    @patch("bot._is_dc_admin", return_value=True)
    def test_f13_unencrypted_private_invite_has_no_token(self, _admin):
        client, event = self.sender(encrypted=False)
        with patch("bot.database.create_peer_invite_token") as create:
            bot.invitepeer_command(client, 1, event)
        create.assert_not_called()
        self.assertIn("encrypted private chat", client.rpc.send_msg.call_args.args[2].text)

    def test_f14_status_headers_on_success_and_errors(self):
        token = database.get_or_create_chat_token(50)
        for status, requested_token in ((200, token), (404, "missing"), (429, token)):
            request = make_mocked_request("GET", "/" + requested_token, match_info={"token": requested_token})
            with self.subTest(status=status), patch("bot.check_rate_limit", return_value=status != 429), \
                 patch("bot.dc_bot_instance", None):
                response = asyncio.run(bot.handle_status_page(request))
            self.assertEqual(response.status, status)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            if status == 429:
                self.assertEqual(response.headers["Retry-After"], "60")

    def test_f15_redact_url_credentials_and_secret_values(self):
        self.assertEqual(bot.redact_url("https://user:password@example.org/health?token=secret&view=full"),
                         "https://example.org/health?token=***&view=full")
        for name in bot._SECRET_QUERY_NAMES | {"TOKEN", "session_token", "api-key", "%74oken"}:
            with self.subTest(name=name):
                url = f"https://example.org/?{name}=sensitive&ok=unchanged"
                self.assertEqual(bot.redact_url(url), f"https://example.org/?{name}=***&ok=unchanged")
        plain = "https://example.org/health?view=full&empty=#section"
        self.assertEqual(bot.redact_url(plain), plain)
        self.assertEqual(bot.redact_url("name: https://u:p@example.org/a?key=x&key=y"),
                         "name: https://example.org/a?key=***&key=***")
        for malformed in (None, "https://[broken?token=secret", "not a url", "https://user:pass@"):
            with self.subTest(malformed=malformed):
                self.assertIsInstance(bot.redact_url(malformed), str)

    def test_f15_sync_logs_counts_and_ids_without_payload(self):
        client, event = self.sender()
        payload = [{"url": "https://user:password@example.org/health?token=sync-secret",
                    "type": "http", "name": "private-monitor-name"}]
        event.msg.text = "[UPTIME_BOT_SYNC_DATA]" + json.dumps(payload) + "[/UPTIME_BOT_SYNC_DATA]"
        with self.assertLogs(bot.logger, level="INFO") as logs:
            bot.on_new_message(client, 1, event)
        logged = "\n".join(logs.output)
        self.assertIn("Received 1 item(s)", logged)
        self.assertIn("Added resource id=", logged)
        for secret in ("sync-secret", "private-monitor-name", "password", "https://"):
            self.assertNotIn(secret, logged)
        self.assertEqual(len(database.get_resources(50)), 1)

    def test_f15_oversize_sync_rejected_before_parse(self):
        client, event = self.sender()
        for text in ("x" * (bot.SYNC_MAX_BYTES + 1), "é" * (bot.SYNC_MAX_BYTES // 2 + 1)):
            event.msg.text = "[UPTIME_BOT_SYNC_DATA]" + text + "[/UPTIME_BOT_SYNC_DATA]"
            with patch("bot.json.loads") as parse, self.assertLogs(bot.logger, level="WARNING") as logs:
                bot.on_new_message(client, 1, event)
            parse.assert_not_called()
            self.assertIn("Payload exceeds 64 KB", "\n".join(logs.output))
        self.assertEqual(database.get_resources(50), [])

    def test_f15_sync_error_does_not_log_payload_from_exception(self):
        client, event = self.sender()
        event.msg.text = "[UPTIME_BOT_SYNC_DATA][][/UPTIME_BOT_SYNC_DATA]"
        with patch("bot.json.loads", side_effect=ValueError("private-payload")), \
             self.assertLogs(bot.logger, level="ERROR") as logs:
            bot.on_new_message(client, 1, event)
        self.assertNotIn("private-payload", "\n".join(logs.output))

    def test_f15_minute_summary_redacts_monitor_name(self):
        stats = {"up": 1, "down": 0, "skipped": 0, "lat_sum": 10, "lat_n": 1,
                 "slowest": (10, "https://user:password@example.org/?token=summary-secret")}
        with patch.object(bot, "_check_stats", stats), self.assertLogs(bot.logger, level="INFO") as logs:
            bot.log_check_summary(0)
        logged = "\n".join(logs.output)
        self.assertNotIn("password", logged)
        self.assertNotIn("summary-secret", logged)
        self.assertIn("token=***", logged)

    def test_f15_title_error_redacts_url_and_exception(self):
        url = "https://user:password@example.org/health?token=title-secret"
        with patch("bot.is_safe_target_url", return_value=True), \
             patch("bot._safe_url_opener", side_effect=OSError(url)), \
             self.assertLogs(bot.logger, level="WARNING") as logs:
            self.assertIsNone(bot.fetch_html_title(url))
        logged = "\n".join(logs.output)
        self.assertNotIn("password", logged)
        self.assertNotIn("title-secret", logged)
        self.assertIn("token=***", logged)

    def test_f16_trace_summary_hides_private_hops(self):
        output = " 1  172.17.0.1  1 ms  1 ms  1 ms\n 2  10.0.0.1  301 ms  301 ms  301 ms\n"
        self.assertEqual(bot.summarize_traceroute(output),
                         "trace: +300 ms between hop 1 private hop and hop 2 private hop")
        synthetic = "+300 ms between hop 1 172.17.0.1 and hop 2 10.0.0.1"
        self.assertEqual(bot.redact_private_hops(synthetic),
                         "+300 ms between hop 1 private hop and hop 2 private hop")
        with patch.dict(bot._path_traces, {"8.8.8.8": (time.time(), synthetic)}):
            self.assertNotIn("172.17.0.1", bot.path_trace_hint("8.8.8.8"))

    def test_f16_non_global_hops_hidden_public_hops_kept(self):
        for address in ("127.0.0.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "192.0.0.1",
                        "::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1"):
            with self.subTest(address=address):
                self.assertEqual(bot.redact_private_hops(f"hop 1 {address}"), "hop 1 private hop")
        public = "hop 1 8.8.8.8 and hop 2 2606:4700:4700::1111"
        self.assertEqual(bot.redact_private_hops(public), public)


if __name__ == "__main__":
    unittest.main()
