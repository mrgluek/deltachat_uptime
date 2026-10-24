import asyncio
import os
import sys
import socket
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

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
        bot._dns_cache.clear()
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

    def test_is_safe_target_url_allows_yggdrasil_ipv6(self):
        """Hosts with a Yggdrasil (200::/7) AAAA record alongside a public A record must not be blocked."""
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, '', ('176.109.110.102', 0)),
                (30, 1, 6, '', ('200:d2ac:1e73:514f:1fae:84b:717c:e04d', 0, 0, 0)),
            ]
            self.assertTrue(bot.is_safe_target_url("https://cm1.wwire.su", "http"))
        self.assertTrue(bot.is_safe_target_url("http://[200:d2ac:1e73:514f:1fae:84b:717c:e04d]", "http"))
        # Other reserved ranges stay blocked
        self.assertFalse(bot.is_safe_target_url("http://240.0.0.1", "http"))

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


class TestDnsPinning(unittest.TestCase):
    """DNS rebinding protection: validated answers are pinned for their TTL and re-validated afterwards."""

    PUBLIC = [(2, 1, 6, '', ('93.184.216.34', 0))]
    LOOPBACK = [(2, 1, 6, '', ('127.0.0.1', 0))]

    def setUp(self):
        bot._dns_cache.clear()

    def tearDown(self):
        bot._dns_cache.clear()

    def _ttl_left(self, host):
        import time
        return bot._dns_cache[host][0] - time.monotonic()

    def test_rebinding_after_validation_uses_pinned_answer(self):
        """The connection must reuse the answer that passed validation, not a fresh lookup."""
        with patch('socket.getaddrinfo', return_value=self.PUBLIC) as mock_dns:
            self.assertTrue(bot.is_safe_target_url("https://rebind.example.org", "http"))
        with patch('socket.getaddrinfo', return_value=self.LOOPBACK) as mock_dns, \
             patch('bot._query_with_ttl', AsyncMock(return_value=(["127.0.0.1"], 0))) as mock_query:
            ips = asyncio.run(bot.resolve_host_safe("rebind.example.org"))
            self.assertEqual(ips, ["93.184.216.34"])
            mock_dns.assert_not_called()
            mock_query.assert_not_called()

    def test_rebinding_after_expiry_is_blocked(self):
        with patch('socket.getaddrinfo', return_value=self.PUBLIC):
            self.assertTrue(bot.is_safe_target_url("https://rebind.example.org", "http"))
        # Expire the pinned answer; the attacker now answers with a loopback address
        bot._dns_cache["rebind.example.org"] = (0, bot._dns_cache["rebind.example.org"][1])
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["127.0.0.1"], 0))):
            with self.assertRaises(bot.BlockedAddressError):
                asyncio.run(bot.resolve_host_safe("rebind.example.org"))

    def test_record_ttl_is_used_and_clamped(self):
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 120))):
            asyncio.run(bot.resolve_host_safe("ttl120.example.org"))
        self.assertAlmostEqual(self._ttl_left("ttl120.example.org"), 120, delta=2)

        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 0))):
            asyncio.run(bot.resolve_host_safe("ttl0.example.org"))
        self.assertAlmostEqual(self._ttl_left("ttl0.example.org"), bot.DNS_CACHE_MIN_TTL, delta=2)

        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 86400))):
            asyncio.run(bot.resolve_host_safe("ttlday.example.org"))
        self.assertAlmostEqual(self._ttl_left("ttlday.example.org"), bot.DNS_CACHE_MAX_TTL, delta=2)

    def test_mixed_public_and_private_answer_is_blocked(self):
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34", "10.0.0.5"], 60))):
            with self.assertRaises(bot.BlockedAddressError):
                asyncio.run(bot.resolve_host_safe("mixed.example.org"))
        with patch('socket.getaddrinfo', return_value=self.PUBLIC + [(2, 1, 6, '', ('192.168.1.1', 0))]):
            self.assertFalse(bot.is_safe_target_url("https://mixed2.example.org", "http"))

    def test_system_resolver_fallback_when_dns_query_fails(self):
        async def run():
            loop = asyncio.get_running_loop()
            with patch('bot._query_with_ttl', AsyncMock(side_effect=OSError("no dns"))), \
                 patch.object(loop, 'getaddrinfo', AsyncMock(return_value=self.PUBLIC)):
                return await bot.resolve_host_safe("fallback.example.org")
        self.assertEqual(asyncio.run(run()), ["93.184.216.34"])
        self.assertAlmostEqual(self._ttl_left("fallback.example.org"), bot.DNS_CACHE_DEFAULT_TTL, delta=2)

    def test_literal_ips_are_validated_without_dns(self):
        self.assertEqual(asyncio.run(bot.resolve_host_safe("93.184.216.34")), ["93.184.216.34"])
        with self.assertRaises(bot.BlockedAddressError):
            asyncio.run(bot.resolve_host_safe("169.254.169.254"))
        self.assertFalse(bot.is_safe_target_url("[::1]:22", "tcp"))

    def test_safe_resolver_filters_by_family_and_blocks_private(self):
        resolver = bot.SafeResolver()
        # has_route_to is pinned: the result must not depend on whether the test machine has IPv6
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34", "2606:2800:220:1::1"], 60))), \
             patch('bot.has_route_to', return_value=True):
            v4 = asyncio.run(resolver.resolve("dual.example.org", 443, socket.AF_INET))
            both = asyncio.run(resolver.resolve("dual.example.org", 443, socket.AF_UNSPEC))
        self.assertEqual([r["host"] for r in v4], ["93.184.216.34"])
        self.assertEqual(len(both), 2)
        self.assertEqual(v4[0]["hostname"], "dual.example.org")

        with patch('bot._query_with_ttl', AsyncMock(return_value=(["127.0.0.1"], 60))):
            with self.assertRaises(bot.BlockedAddressError):
                asyncio.run(resolver.resolve("evil.example.org", 80, socket.AF_INET))

    def test_safe_resolver_skips_ipv6_without_route(self):
        resolver = bot.SafeResolver()
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34", "2606:2800:220:1::1"], 60))), \
             patch('bot.has_route_to', return_value=False):
            both = asyncio.run(resolver.resolve("dual2.example.org", 443, socket.AF_UNSPEC))
            self.assertEqual([r["host"] for r in both], ["93.184.216.34"])
            with self.assertRaises(bot.NoIPv6Error):
                asyncio.run(resolver.resolve("dual2.example.org", 443, socket.AF_INET6))

    def test_pick_probe_addresses(self):
        ips = ["93.184.216.34", "2606:2800:220:1::1"]
        with patch('bot.has_route_to', return_value=True):
            self.assertEqual(bot.pick_probe_addresses("h", ips), ips)
            self.assertEqual(bot.pick_probe_addresses("h", ips, 6), ["2606:2800:220:1::1"])
            self.assertEqual(bot.pick_probe_addresses("h", ips, 4), ["93.184.216.34"])
            with self.assertRaises(bot.NoAddressForFamilyError):
                bot.pick_probe_addresses("h", ["93.184.216.34"], 6)
        with patch('bot.has_route_to', return_value=False):
            # A dual-stack host is checked over IPv4; an IPv6-only one cannot be checked here
            self.assertEqual(bot.pick_probe_addresses("h", ips), ["93.184.216.34"])
            with self.assertRaises(bot.NoIPv6Error):
                bot.pick_probe_addresses("h", ["2606:2800:220:1::1"])

    def test_has_route_to(self):
        self.assertTrue(bot.has_route_to("127.0.0.1"))
        with patch('socket.socket.connect', side_effect=OSError(101, "Network is unreachable")):
            self.assertFalse(bot.has_route_to("2606:2800:220:1::1"))

    def test_tcp_error_of_preferred_address_is_kept(self):
        """The IPv4 error is reported, not the error of the IPv6 address tried after it."""
        async def fail(ip, port, **kw):
            raise OSError(111 if ":" not in ip else 101, f"failed {ip}")
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34", "2606:2800:220:1::1"], 60))), \
             patch('bot.has_route_to', return_value=True), \
             patch('socket.getaddrinfo', return_value=self.PUBLIC), \
             patch('asyncio.open_connection', side_effect=fail):
            is_up, details, _ = asyncio.run(bot.run_single_check({"type": "tcp", "url": "dual3.example.org:22"}))
        self.assertFalse(is_up)
        self.assertIn("93.184.216.34", details)

    def test_ipv6_only_target_is_skipped_without_ipv6(self):
        with patch('bot.has_route_to', return_value=False), patch('asyncio.open_connection', AsyncMock()) as mock_open:
            is_up, details, _ = asyncio.run(bot.run_single_check({"type": "tcp", "url": "[2606:2800:220:1::1]:443"}))
            self.assertIsNone(is_up)
            self.assertEqual(details, bot.NO_IPV6_MSG)
            mock_open.assert_not_called()
            is_up, _, _ = asyncio.run(bot.run_single_check({"type": "ping", "url": "2606:2800:220:1::1"}))
            self.assertIsNone(is_up)

    def test_ipv6_ping_and_tcp(self):
        mock_aioping = MagicMock()
        mock_aioping.ping = AsyncMock(return_value=0.01)
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch('bot.has_route_to', return_value=True), patch.object(bot, 'aioping', mock_aioping), \
             patch('asyncio.open_connection', AsyncMock(return_value=(MagicMock(), writer))) as mock_open:
            self.assertTrue(asyncio.run(bot.run_single_check({"type": "ping", "url": "2606:2800:220:1::1"}))[0])
            self.assertEqual(mock_aioping.ping.call_args.args[0], "2606:2800:220:1::1")
            self.assertTrue(asyncio.run(bot.run_single_check({"type": "tcp", "url": "[2606:2800:220:1::1]:443"}))[0])
            self.assertEqual(mock_open.call_args.args[:2], ("2606:2800:220:1::1", 443))

    def _ping_v4(self, **patches):
        """run_single_check on a public IPv4 ping target; aioping has no raw socket (as in hosted containers)."""
        mock_aioping = MagicMock()
        mock_aioping.ping = AsyncMock(side_effect=PermissionError("Operation not permitted"))
        with patch('bot.has_route_to', return_value=True), patch.object(bot, 'aioping', mock_aioping), \
             patch.multiple('bot', **patches):
            return asyncio.run(bot.run_single_check({"type": "ping", "url": "93.184.216.34"}))

    def test_ping_falls_back_to_datagram_icmp_socket(self):
        dgram = AsyncMock(return_value=0.012)
        with patch('asyncio.create_subprocess_exec', AsyncMock()) as mock_exec:
            is_up, details, ms = self._ping_v4(_dgram_ping=dgram)
        self.assertTrue(is_up)
        self.assertEqual(ms, 12)
        self.assertEqual(dgram.call_args.args[0], "93.184.216.34")
        mock_exec.assert_not_called()

    def test_datagram_ping_timeout_is_down(self):
        is_up, details, _ = self._ping_v4(_dgram_ping=AsyncMock(side_effect=asyncio.TimeoutError()))
        self.assertFalse(is_up)
        self.assertEqual(details, "Timeout")

    def test_no_ping_method_is_not_checked_instead_of_down(self):
        dgram = AsyncMock(side_effect=bot.PingSocketUnavailable("Permission denied"))
        with patch('asyncio.create_subprocess_exec', AsyncMock(side_effect=FileNotFoundError(2, "No such file", "ping"))):
            is_up, details, ms = self._ping_v4(_dgram_ping=dgram)
        self.assertIsNone(is_up)  # abstains in votes, like a node without IPv6
        self.assertEqual(details, bot.PING_UNAVAILABLE_MSG)
        self.assertIsNone(ms)

    def test_ping_binary_still_used_without_icmp_socket(self):
        proc = MagicMock(returncode=0)
        proc.communicate = AsyncMock(return_value=(b"64 bytes from 93.184.216.34: icmp_seq=1 ttl=55 time=12.3 ms\n" * 5, b""))
        dgram = AsyncMock(side_effect=bot.PingSocketUnavailable("Permission denied"))
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=proc)) as mock_exec:
            is_up, _, ms = self._ping_v4(_dgram_ping=dgram)
        self.assertTrue(is_up)
        self.assertEqual(ms, 12)
        self.assertEqual(mock_exec.call_args.args[0], "ping")

    def test_icmp_checksum(self):
        # Echo request type 8, id 0, seq 1, no payload: checksum 0xF7FE
        self.assertEqual(bot._icmp_checksum(struct.pack("!BBHHH", 8, 0, 0, 0, 1)), 0xF7FE)
        packet = struct.pack("!BBHHH", 8, 0, 0, 0, 7) + b"abc"  # odd length is zero padded
        csum = bot._icmp_checksum(packet)
        self.assertEqual(bot._icmp_checksum(packet[:2] + struct.pack("!H", csum) + packet[4:]), 0)

    def test_family_restricted_ping(self):
        mock_aioping = MagicMock()
        mock_aioping.ping = AsyncMock(return_value=0.01)
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34", "2606:2800:220:1::1"], 60))), \
             patch('bot.has_route_to', return_value=True), patch('socket.getaddrinfo', return_value=self.PUBLIC), \
             patch.object(bot, 'aioping', mock_aioping):
            asyncio.run(bot.run_single_check({"type": "ping", "url": "dual4.example.org", "family": 6}))
        self.assertEqual(mock_aioping.ping.call_args.args[0], "2606:2800:220:1::1")
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 60))), \
             patch('socket.getaddrinfo', return_value=self.PUBLIC):
            is_up, details, _ = asyncio.run(bot.run_single_check({"type": "ping", "url": "v4only.example.org", "family": 6}))
        self.assertFalse(is_up)
        self.assertIn("has no IPv6 address", details)

    def test_private_ipv6_blocked(self):
        for target, kind in (("fd42:42:42::1", "ping"), ("[fe80::1]:22", "tcp"), ("[::1]", "ping")):
            self.assertFalse(bot.is_safe_target_url(target, kind), target)
        self.assertTrue(bot.is_safe_target_url("[2606:2800:220:1::1]:443", "tcp"))

    def test_http_probe_never_connects_to_rebound_private_address(self):
        """End-to-end through aiohttp: a hostname answering 127.0.0.1 at connect time is not reached."""
        from aiohttp import web
        hits = []

        async def handler(request):
            hits.append(request.path)
            return web.Response(text="internal secret")

        async def run():
            app = web.Application()
            app.router.add_get("/", handler)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            try:
                with patch('bot._query_with_ttl', AsyncMock(return_value=(["127.0.0.1"], 0))):
                    async with aiohttp.ClientSession(connector=bot._make_safe_connector()) as sess:
                        with self.assertRaises(aiohttp.ClientConnectorError) as ctx:
                            await sess.get(f"http://rebound.example.org:{port}/")
                    self.assertIsInstance(ctx.exception.os_error, bot.BlockedAddressError)

                    # run_single_check reports it as blocked (validation saw a public answer earlier)
                    bot._dns_cache.clear()
                    with patch('bot.is_safe_target_url', return_value=True):
                        is_up, details, _ = await bot.run_single_check(
                            {"type": "http", "url": f"http://rebound.example.org:{port}/"})
                    self.assertFalse(is_up)
                    self.assertIn("Target blocked", details)
            finally:
                await runner.cleanup()

        asyncio.run(run())
        self.assertEqual(hits, [])

    def test_tcp_probe_connects_to_pinned_ip(self):
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 60))), \
             patch('socket.getaddrinfo', return_value=self.PUBLIC), \
             patch('asyncio.open_connection', AsyncMock(return_value=(MagicMock(), writer))) as mock_open:
            is_up, _, _ = asyncio.run(bot.run_single_check({"type": "tcp", "url": "tcp.example.org:443"}))
        self.assertTrue(is_up)
        self.assertEqual(mock_open.call_args.args[:2], ("93.184.216.34", 443))

    def test_probe_resolves_with_record_ttl_without_blocking_lookup(self):
        """Checks resolve asynchronously first, so the cache holds the real TTL and getaddrinfo is not used."""
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 200))), \
             patch('socket.getaddrinfo', side_effect=AssertionError("blocking lookup")) as mock_dns, \
             patch('asyncio.open_connection', AsyncMock(return_value=(MagicMock(), writer))):
            is_up, _, _ = asyncio.run(bot.run_single_check({"type": "tcp", "url": "ttl-tcp.example.org:443"}))
        self.assertTrue(is_up)
        mock_dns.assert_not_called()
        self.assertAlmostEqual(self._ttl_left("ttl-tcp.example.org"), 200, delta=2)

    def test_tcp_probe_blocked_after_rebinding(self):
        with patch('socket.getaddrinfo', return_value=self.PUBLIC):
            self.assertTrue(bot.is_safe_target_url("tcp-rebind.example.org:22", "tcp"))
        bot._dns_cache["tcp-rebind.example.org"] = (0, ("93.184.216.34",))
        with patch('bot.is_safe_target_url', return_value=True), \
             patch('bot._query_with_ttl', AsyncMock(return_value=(["127.0.0.1"], 0))), \
             patch('asyncio.open_connection', AsyncMock()) as mock_open:
            is_up, details, _ = asyncio.run(bot.run_single_check({"type": "tcp", "url": "tcp-rebind.example.org:22"}))
        self.assertFalse(is_up)
        self.assertIn("Target blocked", details)
        mock_open.assert_not_called()

    def test_ping_uses_pinned_ip(self):
        mock_aioping = MagicMock()
        mock_aioping.ping = AsyncMock(return_value=0.01)
        with patch.object(bot, 'aioping', mock_aioping), \
             patch('socket.getaddrinfo', return_value=self.PUBLIC), \
             patch('bot._query_with_ttl', AsyncMock(return_value=(["93.184.216.34"], 60))):
            is_up, _, _ = asyncio.run(bot.run_single_check({"type": "ping", "url": "ping.example.org"}))
        self.assertTrue(is_up)
        self.assertEqual(mock_aioping.ping.call_args.args[0], "93.184.216.34")

    def test_title_fetch_does_not_connect_to_rebound_address(self):
        """The urllib opener connects to the pinned address; a private answer is refused."""
        with patch('bot.is_safe_target_url', return_value=True), \
             patch('socket.getaddrinfo', return_value=self.LOOPBACK), \
             patch('socket.create_connection') as mock_connect:
            self.assertIsNone(bot.fetch_html_title("http://title-rebind.example.org/"))
            mock_connect.assert_not_called()

    def test_aiodns_resolver_is_reused_per_event_loop(self):
        """Queries share one long-lived resolver per loop; channels are not created and closed per query."""
        created = []

        def fake_resolver(*args, **kwargs):
            resolver = MagicMock()
            resolver.query = AsyncMock(return_value=[MagicMock(host="93.184.216.34", ttl=60)])
            created.append(resolver)
            return resolver

        async def run():
            for i in range(5):
                bot._dns_cache.clear()
                await bot.resolve_host_safe(f"reuse{i}.example.org")

        with patch.object(bot.aiodns, "DNSResolver", side_effect=fake_resolver):
            asyncio.run(run())
            self.assertEqual(len(created), 1)
            self.assertEqual(created[0].query.await_count, 10)  # A + AAAA per lookup
            created[0].close.assert_not_called()

            asyncio.run(run())  # a new event loop gets its own resolver
            self.assertEqual(len(created), 2)

    def test_cache_is_bounded(self):
        with patch.object(bot, 'DNS_CACHE_MAX_ENTRIES', 3):
            for i in range(10):
                bot._dns_cache_put(f"h{i}.example.org", ["93.184.216.34"], 60)
            self.assertLessEqual(len(bot._dns_cache), 3)


if __name__ == "__main__":
    unittest.main()
