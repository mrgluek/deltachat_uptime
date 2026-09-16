import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_security_db.db"


class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        with bot._rate_limit_lock:
            bot._rate_limits.clear()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except OSError:
                pass
        for suffix in ["-wal", "-shm"]:
            fpath = TEST_DB + suffix
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    def test_is_safe_target_url_blocks_local_domain_suffixes(self):
        """Verify .local, .internal, .lan, and .localdomain domains are blocked."""
        self.assertFalse(bot.is_safe_target_url("http://gateway.local", "http"))
        self.assertFalse(bot.is_safe_target_url("http://service.internal", "http"))
        self.assertFalse(bot.is_safe_target_url("http://nas.lan:8080", "http"))
        self.assertFalse(bot.is_safe_target_url("http://router.localdomain", "http"))
        self.assertFalse(bot.is_safe_target_url("device.local:22", "tcp"))
        self.assertFalse(bot.is_safe_target_url("switch.lan", "ping"))

    def test_is_safe_target_url_blocks_dns_resolving_to_private_ips(self):
        """Verify that hostnames resolving to loopback or private ranges are blocked."""
        with patch('socket.getaddrinfo') as mock_dns:
            # Resolving to loopback
            mock_dns.return_value = [(2, 1, 6, '', ('127.0.0.1', 0))]
            self.assertFalse(bot.is_safe_target_url("https://rebinding.evil.org", "http"))

            # Resolving to private 10.x
            mock_dns.return_value = [(2, 1, 6, '', ('10.20.30.40', 0))]
            self.assertFalse(bot.is_safe_target_url("https://intranet.company.org", "http"))

            # Resolving to cloud metadata
            mock_dns.return_value = [(2, 1, 6, '', ('169.254.169.254', 0))]
            self.assertFalse(bot.is_safe_target_url("https://metadata.victim.com", "http"))

            # Resolving to public IP
            mock_dns.return_value = [(2, 1, 6, '', ('93.184.216.34', 0))]
            self.assertTrue(bot.is_safe_target_url("https://example.com", "http"))

    def test_fetch_html_title_blocks_unsafe_urls(self):
        """Verify fetch_html_title returns None for unsafe URLs without making HTTP requests."""
        with patch('urllib.request.urlopen') as mock_urlopen:
            self.assertIsNone(bot.fetch_html_title("http://127.0.0.1:8080"))
            self.assertIsNone(bot.fetch_html_title("http://169.254.169.254/latest/meta-data/"))
            self.assertIsNone(bot.fetch_html_title("http://localhost/admin"))
            mock_urlopen.assert_not_called()

    def test_add_command_rejects_unsafe_targets(self):
        """Verify /add command refuses to register private/internal targets."""
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = 42
        mock_event.payload = "http://127.0.0.1:9000 LocalTarget"

        bot.add_command(mock_bot, 1, mock_event)

        # Ensure no resource was added
        resources = database.get_resources(42)
        self.assertEqual(len(resources), 0)

        # Check rejection message sent
        sent_calls = mock_bot.rpc.send_msg.call_args_list
        self.assertTrue(any("Cannot check internal, local, or private network targets" in str(c) for c in sent_calls))

    def test_run_single_check_rejects_unsafe_targets(self):
        """Verify run_single_check directly rejects probing internal/private targets."""
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(bot.run_single_check({
                "url": "http://10.0.0.1:80",
                "type": "http"
            }))
            is_up, details, latency = res
            self.assertFalse(is_up)
            self.assertIn("Target blocked", details)
            self.assertIsNone(latency)
        finally:
            loop.close()

    def test_rate_limiting_sliding_window(self):
        """Verify check_rate_limit correctly restricts requests within window."""
        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "198.51.100.1"}
        mock_request.remote = "127.0.0.1"

        self.assertTrue(bot.check_rate_limit(mock_request, bucket="test", max_requests=3, window_seconds=60))
        self.assertTrue(bot.check_rate_limit(mock_request, bucket="test", max_requests=3, window_seconds=60))
        self.assertTrue(bot.check_rate_limit(mock_request, bucket="test", max_requests=3, window_seconds=60))
        self.assertFalse(bot.check_rate_limit(mock_request, bucket="test", max_requests=3, window_seconds=60))

    def test_handle_status_page_rate_limiting(self):
        """Verify handle_status_page returns 429 with Retry-After when rate limit is exceeded."""
        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "198.51.100.2"}
        mock_request.match_info = {"token": "abcdef123456"}

        loop = asyncio.new_event_loop()
        try:
            # Exhaust rate limit (120 requests allowed)
            for _ in range(120):
                bot.check_rate_limit(mock_request, bucket="web_status", max_requests=120, window_seconds=60)

            resp = loop.run_until_complete(bot.handle_status_page(mock_request))
            self.assertEqual(resp.status, 429)
            self.assertEqual(resp.headers.get("Retry-After"), "60")
        finally:
            loop.close()

    def test_web_application_client_max_size(self):
        """Verify web.Application is configured with client_max_size=256KB to prevent DoS."""
        with patch('aiohttp.web.Application') as mock_app_cls, \
             patch('aiohttp.web.AppRunner') as mock_runner_cls, \
             patch('aiohttp.web.TCPSite') as mock_site_cls, \
             patch('asyncio.sleep', side_effect=asyncio.CancelledError):
            mock_app = MagicMock()
            mock_app_cls.return_value = mock_app

            mock_runner = MagicMock()
            mock_runner.setup = unittest.mock.AsyncMock()
            mock_runner_cls.return_value = mock_runner

            mock_site = MagicMock()
            mock_site.start = unittest.mock.AsyncMock()
            mock_site_cls.return_value = mock_site

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(bot._run_web_server())
            except asyncio.CancelledError:
                pass
            finally:
                loop.close()

            mock_app_cls.assert_called_once_with(client_max_size=256 * 1024)


if __name__ == "__main__":
    unittest.main()
