"""smtp:// monitors: target parsing, the STARTTLS dialogue against a local fake server, and peers."""
import asyncio
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

TEST_DB = "test_smtp_check.db"
os.environ["DB_PATH"] = TEST_DB

# Mock packages if not installed (CI runs without the full Delta Chat stack)
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
import bot  # noqa: E402

HOST = "mail.test"  # the name in the test certificate; probe_addresses is patched to 127.0.0.1


class TestSmtpTargetParsing(unittest.TestCase):
    def test_parse_smtp_targets(self):
        self.assertEqual(bot.parse_target("smtp://chatmail.uk"), ("smtp", "smtp://chatmail.uk"))
        self.assertEqual(bot.parse_target("SMTP://Mail.Example.org"), ("smtp", "smtp://mail.example.org"))
        # the default port is dropped, so smtp://x and smtp://x:25 are the same monitor
        self.assertEqual(bot.parse_target("smtp://chatmail.uk:25"), ("smtp", "smtp://chatmail.uk"))
        self.assertEqual(bot.parse_target("smtp://chatmail.uk:465"), ("smtp", "smtp://chatmail.uk:465"))
        self.assertEqual(bot.parse_target("smtp://[2a00:da00::1]:587"), ("smtp", "smtp://[2a00:da00::1]:587"))
        self.assertEqual(bot.parse_target("smtp://[2a00:da00::1]"), ("smtp", "smtp://[2a00:da00::1]"))

    def test_parse_smtp_invalid(self):
        for bad in ("smtp://", "smtp://host/path", "smtp://user@host", "smtp://host:abc",
                    "smtp://host:70000", "smtp://[not-ipv6]:25", "smtp://bad_host!"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bot.parse_target(bad)

    def test_host_port(self):
        self.assertEqual(bot._smtp_host_port("smtp://chatmail.uk"), ("chatmail.uk", 25))
        self.assertEqual(bot._smtp_host_port("smtp://chatmail.uk:465"), ("chatmail.uk", 465))
        self.assertEqual(bot._smtp_host_port("smtp://[2a00::1]:587"), ("2a00::1", 587))
        self.assertEqual(bot._target_host("smtp://[2a00::1]", "smtp"), "2a00::1")

    def test_ssrf_filter(self):
        self.assertTrue(bot.is_safe_target_url("smtp://1.1.1.1", "smtp"))
        self.assertFalse(bot.is_safe_target_url("smtp://127.0.0.1", "smtp"))
        self.assertFalse(bot.is_safe_target_url("smtp://10.0.0.5:25", "smtp"))
        self.assertFalse(bot.is_safe_target_url("smtp://localhost", "smtp"))
        self.assertFalse(bot.is_safe_target_url("smtp://1.1.1.1", "tcp"))  # type must match

    def test_has_tls_certificate(self):
        self.assertTrue(bot.has_tls_certificate("smtp://chatmail.uk"))
        self.assertTrue(bot.has_tls_certificate("https://chatmail.uk"))
        self.assertFalse(bot.has_tls_certificate("http://chatmail.uk"))
        self.assertFalse(bot.has_tls_certificate("chatmail.uk:25"))

    def test_probeignore_matches_smtp(self):
        # "*:25" (all SMTP port checks) also covers smtp:// monitors, whose port 25 is implicit
        self.assertTrue(bot.database.target_matches_ignore("smtp://dnd.wb.ru", ["*:25"]))
        self.assertTrue(bot.database.target_matches_ignore("smtp://dnd.wb.ru", ["dnd.wb.ru"]))
        self.assertFalse(bot.database.target_matches_ignore("smtp://dnd.wb.ru:465", ["*:25"]))

    def test_peer_batch_accepts_smtp(self):
        targets = bot._parse_batch_targets([{"url": "smtp://1.1.1.1", "type": "smtp"},
                                            {"url": "smtp://127.0.0.1", "type": "smtp"}])
        self.assertEqual(targets[0]["type"], "smtp")
        self.assertIsNone(targets[1])  # private address refused, position kept


def _make_cert(tmp: str, name: str) -> tuple[str, str]:
    cert, key = os.path.join(tmp, f"{name}.pem"), os.path.join(tmp, f"{name}.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    return cert, key


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI needed for the test certificate")
class TestSmtpHandshake(unittest.IsolatedAsyncioTestCase):
    """A real asyncio SMTP server on 127.0.0.1 with a self-signed certificate for mail.test."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = _make_cert(cls.tmp, HOST)
        cls.other_cert, cls.other_key = _make_cert(cls.tmp, "other.test")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    async def asyncSetUp(self):
        self.commands = []
        self.greeting = b"220 mail.test ESMTP\r\n"
        self.offer_starttls = True
        self.implicit = False
        self.server_cert = (self.cert, self.key)
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        # the bot trusts our test CA (the certificate itself) instead of the system store
        trusting = ssl.create_default_context(cafile=self.cert)
        self.patches = [
            patch("bot.probe_addresses", AsyncMock(return_value=["127.0.0.1"])),
            patch("bot.ssl.create_default_context", return_value=trusting),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in self.patches:
            p.stop()
        self.server.close()
        await self.server.wait_closed()

    def _server_ctx(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*self.server_cert)
        return ctx

    async def _handle(self, reader, writer):
        try:
            if self.implicit:
                await writer.start_tls(self._server_ctx())
            writer.write(self.greeting)
            await writer.drain()
            if not self.greeting.startswith(b"220"):
                return
            while True:
                line = await reader.readline()
                if not line:
                    return
                cmd = line.decode().strip()
                self.commands.append(cmd.split(" ", 1)[0].upper())
                if cmd.upper().startswith("EHLO"):
                    ext = b"250-STARTTLS\r\n" if self.offer_starttls and not self.implicit else b""
                    writer.write(b"250-mail.test\r\n250-PIPELINING\r\n" + ext + b"250 8BITMIME\r\n")
                elif cmd.upper() == "STARTTLS":
                    writer.write(b"220 2.0.0 Ready to start TLS\r\n")
                    await writer.drain()
                    try:
                        await writer.start_tls(self._server_ctx())
                    except (ssl.SSLError, ConnectionError):
                        return  # the client refused our certificate
                    continue
                elif cmd.upper() == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    return
                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    def url(self):
        return f"smtp://{HOST}:{self.port}"

    async def test_starttls_ok(self):
        cert = await asyncio.wait_for(bot.smtp_tls_handshake(self.url()), 10)
        self.assertIn("notAfter", cert)
        self.assertEqual(self.commands, ["EHLO", "STARTTLS", "QUIT"])

    async def test_implicit_tls_ok(self):
        self.implicit = True
        with patch("bot.SMTP_IMPLICIT_TLS_PORTS", (self.port,)):
            cert = await asyncio.wait_for(bot.smtp_tls_handshake(self.url()), 10)
        self.assertIn("notAfter", cert)
        self.assertEqual(self.commands, ["EHLO", "QUIT"])

    async def test_no_starttls(self):
        self.offer_starttls = False
        with self.assertRaisesRegex(bot.SMTPCheckError, "STARTTLS not offered"):
            await asyncio.wait_for(bot.smtp_tls_handshake(self.url()), 10)

    async def test_bad_greeting(self):
        self.greeting = b"554 5.7.1 go away\r\n"
        with self.assertRaisesRegex(bot.SMTPCheckError, "greeting 554"):
            await asyncio.wait_for(bot.smtp_tls_handshake(self.url()), 10)

    async def test_wrong_hostname_certificate(self):
        self.server_cert = (self.other_cert, self.other_key)  # valid shape, but for other.test
        with self.assertRaises(ssl.SSLError) as cm:
            await asyncio.wait_for(bot.smtp_tls_handshake(self.url()), 10)
        self.assertTrue(bot._short_ssl_error(cm.exception).startswith("SSL: "))

    async def test_check_ssl_expiry_smtp(self):
        exp_ts, err = await bot.check_ssl_expiry(self.url())
        self.assertIsNone(err)
        self.assertGreater(exp_ts, 0)

    async def test_run_single_check_smtp(self):
        resource = {"id": 0, "url": self.url(), "type": "smtp"}
        with patch("bot._prewarm_target_dns", AsyncMock(return_value=True)), \
             patch("bot.is_safe_target_url", return_value=True):
            is_up, details, latency = await bot.run_single_check(resource)
            self.assertTrue(is_up, details)
            self.assertIsInstance(latency, int)

            self.offer_starttls = False
            is_up, details, _ = await bot.run_single_check(resource)
            self.assertFalse(is_up)
            self.assertEqual(details, "SMTP: STARTTLS not offered")

            self.offer_starttls = True
            self.server_cert = (self.other_cert, self.other_key)
            is_up, details, _ = await bot.run_single_check(resource)
            self.assertFalse(is_up)
            self.assertTrue(details.startswith("SSL: "), details)


class TestSmtpPeers(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bot._peer_caps.clear()
        bot._note_peer_caps("new@x.org", [bot.PEER_CAP_BATCH_CHECK, bot.PEER_CAP_SMTP_CHECK])
        bot._note_peer_caps("old@x.org", [bot.PEER_CAP_BATCH_CHECK])
        self.new, self.old = {"email": "new@x.org"}, {"email": "old@x.org"}

    def tearDown(self):
        bot._peer_caps.clear()

    def test_own_caps_announce_smtp(self):
        self.assertIn(bot.PEER_CAP_SMTP_CHECK, bot.OWN_PEER_CAPS)

    def test_peer_can_check(self):
        smtp = {"type": "smtp", "url": "smtp://1.1.1.1"}
        self.assertTrue(bot._peer_can_check(self.new, smtp))
        self.assertFalse(bot._peer_can_check(self.old, smtp))
        self.assertTrue(bot._peer_can_check(self.old, {"type": "http", "url": "https://1.1.1.1"}))

    async def test_batch_skips_old_peers_for_smtp(self):
        sent = {}

        async def fake_batch(peer, items, results):
            sent[peer["email"]] = [t["type"] for _, t in items]

        fut_smtp, fut_http = asyncio.get_running_loop().create_future(), asyncio.get_running_loop().create_future()
        batch = [({"type": "smtp", "url": "smtp://1.1.1.1"}, fut_smtp, None),
                 ({"type": "http", "url": "https://1.1.1.1"}, fut_http, None)]
        with patch("bot.database.get_all_peers", return_value=[self.new, self.old]), \
             patch("bot._batch_cross_check_peer", side_effect=fake_batch):
            await bot._flush_cross_checks(batch)
        self.assertEqual(sorted(sent["new@x.org"]), ["http", "smtp"])
        self.assertEqual(sent["old@x.org"], ["http"])
        self.assertTrue(fut_smtp.done() and fut_http.done())


def tearDownModule():
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(TEST_DB + suffix):
            os.remove(TEST_DB + suffix)


if __name__ == "__main__":
    unittest.main()
