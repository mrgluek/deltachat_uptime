"""blockcheck: probes against local fake servers, the DNS / SNI / Host decisions, and the error tag."""
import asyncio
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

TEST_DB = "test_blockcheck.db"
os.environ["DB_PATH"] = TEST_DB

try:
    import deltachat2  # noqa: F401
except ImportError:
    sys.modules['deltachat2'] = MagicMock()
try:
    import deltabot_cli  # noqa: F401
except ImportError:
    class MockBotCli:
        def __init__(self, *args, **kwargs):
            pass
        def on(self, *args, **kwargs):
            return lambda func: func
        def on_init(self, func):
            return func
        def on_start(self, func):
            return func
    sys.modules['deltabot_cli'] = MagicMock(BotCli=MockBotCli)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import blockcheck as bc  # noqa: E402
import bot  # noqa: E402

HOST = "blocked.test"


def make_cert(directory):
    key, crt = os.path.join(directory, "k.pem"), os.path.join(directory, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "2", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"],
                   check=True, capture_output=True)
    return crt, key


class TlsServer:
    """TLS server that resets connections announcing `blocked_sni` (like DPI) and records every SNI."""
    def __init__(self, crt, key, blocked_sni=None, hang=False):
        self.seen = []
        self.blocked_sni = blocked_sni
        self.hang = hang
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.ctx.sni_callback = self._sni

    def _sni(self, sock, name, ctx):
        self.seen.append(name)
        if self.blocked_sni is not None and name == self.blocked_sni:
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR   # aborts the handshake
        return None

    async def start(self):
        self.server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=self.ctx)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


class RawResetServer:
    """Plain TCP server: closes at once when the first bytes mention `blocked_host`, else answers."""
    def __init__(self, blocked_host):
        self.blocked_host = blocked_host

    async def _handle(self, reader, writer):
        data = await reader.read(512)
        if self.blocked_host.encode() in data:
            sock = writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")  # RST
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


@unittest.skipUnless(shutil.which("openssl"), "openssl needed for a test certificate")
class TestProbes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.mkdtemp()
        self.crt, self.key = make_cert(self.dir)

    async def asyncTearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    async def test_tls_answer_and_no_sni_is_really_none(self):
        srv = TlsServer(self.crt, self.key)
        await srv.start()
        try:
            self.assertEqual(await bc.probe_tls("127.0.0.1", srv.port, None), bc.ANSWER)
            self.assertEqual(await bc.probe_tls("127.0.0.1", srv.port, HOST), bc.ANSWER)
        finally:
            await srv.stop()
        self.assertEqual(srv.seen, [None, HOST])

    async def test_blocked_sni_gets_an_aborted_handshake_but_no_sni_passes(self):
        srv = TlsServer(self.crt, self.key, blocked_sni=HOST)
        await srv.start()
        try:
            self.assertEqual(await bc.probe_tls("127.0.0.1", srv.port, None), bc.ANSWER)
            self.assertEqual(await bc.probe_tls("127.0.0.1", srv.port, bc.CONTROL_SNI), bc.ANSWER)
            # the aborted handshake arrives as a TLS alert (the server answered), a real DPI sends RST or nothing:
            # that is what the RawResetServer / silent-server tests cover
            self.assertIn(await bc.probe_tls("127.0.0.1", srv.port, HOST), (bc.ANSWER, bc.RESET))
        finally:
            await srv.stop()

    async def test_tls_badcert_when_name_does_not_match(self):
        srv = TlsServer(self.crt, self.key)
        await srv.start()
        try:
            self.assertEqual(await bc.probe_tls("127.0.0.1", srv.port, "other.test", verify_name="other.test"), bc.BADCERT)
        finally:
            await srv.stop()

    async def test_connection_refused_is_noconnect(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertEqual(await bc.probe_tls("127.0.0.1", port, HOST), bc.NOCONNECT)
        self.assertEqual(await bc.probe_http("127.0.0.1", port, HOST), bc.NOCONNECT)

    async def test_silent_server_is_timeout(self):
        writers = []
        server = await asyncio.start_server(lambda r, w: writers.append(w), "127.0.0.1", 0)   # accepts, never answers
        port = server.sockets[0].getsockname()[1]
        try:
            self.assertEqual(await bc.probe_tls("127.0.0.1", port, HOST, timeout=0.5), bc.TIMEOUT)
            self.assertEqual(await bc.probe_http("127.0.0.1", port, HOST, timeout=0.5), bc.TIMEOUT)
        finally:
            for w in writers:
                w.transport.abort()
            server.close()
            await server.wait_closed()

    async def test_http_host_reset_vs_answer(self):
        srv = RawResetServer(HOST)
        await srv.start()
        try:
            self.assertEqual(await bc.probe_http("127.0.0.1", srv.port, HOST), bc.RESET)
            self.assertEqual(await bc.probe_http("127.0.0.1", srv.port, bc.CONTROL_HOST), bc.ANSWER)
        finally:
            await srv.stop()


class TestDiagnose(unittest.IsolatedAsyncioTestCase):
    """The decision table, with the probes replaced."""
    def run_diag(self, real, control, public=(), pub_real=None, use_tls=True, system=("10.0.0.1",)):
        async def real_probe(ip, port, host, tls, verify=False):
            return pub_real if (ip in public and pub_real) else real
        with patch.object(bc, "resolve_public", AsyncMock(return_value=list(public))), \
             patch.object(bc, "_real_probe", real_probe), \
             patch.object(bc, "_control_probe", AsyncMock(return_value=control)):
            return asyncio.run(bc.diagnose(HOST, 443 if use_tls else 80, use_tls, list(system)))

    def test_sni_block(self):
        self.assertEqual(self.run_diag(bc.RESET, bc.ANSWER), bc.TAG_SNI)
        self.assertEqual(self.run_diag(bc.TIMEOUT, bc.ANSWER), bc.TAG_SNI)

    def test_host_block_for_plain_http(self):
        self.assertEqual(self.run_diag(bc.RESET, bc.ANSWER, use_tls=False), bc.TAG_HOST)

    def test_both_fail_is_not_a_name_block(self):
        self.assertIsNone(self.run_diag(bc.TIMEOUT, bc.TIMEOUT))
        self.assertIsNone(self.run_diag(bc.NOCONNECT, bc.NOCONNECT))
        self.assertIsNone(self.run_diag(bc.RESET, bc.RESET))

    def test_working_target_gets_no_tag(self):
        self.assertIsNone(self.run_diag(bc.ANSWER, bc.ANSWER))

    def test_dns_spoofing(self):
        self.assertEqual(self.run_diag(bc.BADCERT, bc.ANSWER, public=["93.184.216.34"], pub_real=bc.ANSWER), bc.TAG_DNS)

    def test_different_dns_but_both_work_is_nothing(self):
        # geo-DNS: another address, and ours answers as well
        self.assertIsNone(self.run_diag(bc.ANSWER, bc.ANSWER, public=["93.184.216.34"], pub_real=bc.ANSWER))

    def test_same_dns_answer_skips_the_dns_branch(self):
        self.assertEqual(self.run_diag(bc.RESET, bc.ANSWER, public=["10.0.0.1"]), bc.TAG_SNI)

    def test_public_address_down_too_is_no_dns_tag(self):
        self.assertIsNone(self.run_diag(bc.TIMEOUT, bc.TIMEOUT, public=["93.184.216.34"], pub_real=bc.TIMEOUT))

    def test_no_addresses(self):
        self.assertIsNone(asyncio.run(bc.diagnose(HOST, 443, True, [])))


class TestTagText(unittest.TestCase):
    def test_split_and_join(self):
        self.assertEqual(bc.split_tag("SNI block? Timeout"), ("SNI block?", "Timeout"))
        self.assertEqual(bc.split_tag("Timeout"), (None, "Timeout"))
        self.assertEqual(bc.with_tag(bc.TAG_DNS, "SSL: x"), "DNS spoofing? SSL: x")
        self.assertEqual(bc.with_tag(None, "Timeout"), "Timeout")

    def test_vote_line_keeps_tag_whole(self):
        long_error = "Cannot connect to host blocked.test:443 ssl:default [" + "Connection reset by peer " * 10 + "]"
        short = bot.short_vote_error(bc.with_tag(bc.TAG_SNI, long_error))
        self.assertTrue(short.startswith("SNI block? "))
        self.assertLessEqual(len(short), bot.VOTE_ERROR_MAX)
        self.assertEqual(bot.short_vote_error("SNI block? Timeout"), "SNI block? Timeout")

    def test_vote_line_in_format_votes(self):
        votes = [{"node": "RU", "status": "down", "error": "SNI block? Connection reset by peer"},
                 {"node": "DE", "status": "up", "latency_ms": 40}]
        line = bot.format_votes(votes)
        self.assertIn("RU (SNI block? Connection reset by peer)", line)


class TestAnnotate(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bc._cache.clear()
        self.res = {"type": "http", "url": f"https://{HOST}/"}

    async def annotate(self, result, tag=bc.TAG_SNI, resource=None):
        with patch.object(bot, "probe_addresses", AsyncMock(return_value=["203.0.113.5"])), \
             patch.object(bc, "diagnose", AsyncMock(return_value=tag)) as diag:
            out = await bot._annotate_block(resource or self.res, result)
        return out, diag

    async def test_tag_is_added_to_a_connection_failure(self):
        out, diag = await self.annotate((False, "Timeout", 30000))
        self.assertEqual(out, (False, "SNI block? Timeout", 30000))
        diag.assert_awaited_once_with(HOST, 443, True, ["203.0.113.5"])

    async def test_plain_http_uses_port_80(self):
        out, diag = await self.annotate((False, "Timeout", 1), tag=bc.TAG_HOST, resource={"type": "http", "url": f"http://{HOST}/x"})
        self.assertEqual(out[1], "HTTP Host block? Timeout")
        diag.assert_awaited_once_with(HOST, 80, False, ["203.0.113.5"])

    async def test_results_that_are_not_connection_failures_are_untouched(self):
        for result in [(True, "200 - OK", 5), (None, bot.NO_IPV6_MSG, None), (False, "503 - Service Unavailable", 5),
                       (False, '200 OK (Missing keyword: "x")', 5), (False, bot.BLOCKED_TARGET_MSG, None),
                       (False, "SNI block? Timeout", 5)]:
            out, diag = await self.annotate(result)
            self.assertEqual(out, result)
            diag.assert_not_awaited()

    async def test_other_monitor_types_and_ip_literals_are_untouched(self):
        for res in [{"type": "tcp", "url": f"{HOST}:443"}, {"type": "ping", "url": HOST}, {"type": "http", "url": "https://203.0.113.5/"}]:
            out, diag = await self.annotate((False, "Timeout", 1), resource=res)
            self.assertEqual(out, (False, "Timeout", 1))
            diag.assert_not_awaited()

    async def test_no_tag_leaves_the_error_alone(self):
        out, _ = await self.annotate((False, "Timeout", 1), tag=None)
        self.assertEqual(out, (False, "Timeout", 1))

    async def test_diagnosis_failure_never_breaks_the_check(self):
        with patch.object(bot, "probe_addresses", AsyncMock(side_effect=OSError("dns"))):
            out = await bot._annotate_block(self.res, (False, "Timeout", 1))
        self.assertEqual(out, (False, "Timeout", 1))


class TestCache(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bc._cache.clear()

    async def test_second_call_uses_the_cache(self):
        with patch.object(bc, "diagnose", AsyncMock(return_value=bc.TAG_SNI)) as diag:
            self.assertEqual(await bc.diagnose_cached(HOST, 443, True, ["1.2.3.4"]), bc.TAG_SNI)
            self.assertEqual(await bc.diagnose_cached(HOST, 443, True, ["1.2.3.4"]), bc.TAG_SNI)
        diag.assert_awaited_once()

    async def test_none_is_cached_too_and_errors_give_none(self):
        with patch.object(bc, "diagnose", AsyncMock(side_effect=RuntimeError("boom"))) as diag:
            self.assertIsNone(await bc.diagnose_cached(HOST, 443, True, ["1.2.3.4"]))
            self.assertIsNone(await bc.diagnose_cached(HOST, 443, True, ["1.2.3.4"]))
        diag.assert_awaited_once()

    async def test_disabled(self):
        with patch.object(bc, "ENABLED", False), patch.object(bc, "diagnose", AsyncMock()) as diag:
            self.assertIsNone(await bc.diagnose_cached(HOST, 443, True, ["1.2.3.4"]))
        diag.assert_not_awaited()


def tearDownModule():
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(TEST_DB + suffix)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
