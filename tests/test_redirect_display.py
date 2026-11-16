"""/ping shows where a redirect leads: the trail kept by _safe_http_request and its text."""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_PATH"] = "test_redirect_display.db"

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


class _Resp:
    def __init__(self, status, location=None, url=None):
        self.status = status
        self.headers = {"Location": location} if location else {}
        self.url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _Session:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **kwargs):
        return self.responses[url]

    head = get


class TestFormat(unittest.TestCase):
    def test_none_without_redirects(self):
        self.assertIsNone(bot.format_redirects([]))
        self.assertIsNone(bot.format_redirects(None))

    def test_single_and_chain(self):
        self.assertEqual(bot.format_redirects([(301, "https://example.com/")]), "`301` → `https://example.com/`")
        self.assertEqual(bot.format_redirects([(301, "https://a.example/"), (302, "https://b.example/x")]),
                         "`301` → `https://a.example/` → `302` → `https://b.example/x`")

    def test_secrets_are_redacted_and_long_urls_cut(self):
        text = bot.format_redirects([(302, "https://example.com/cb?token=abc123&x=1")])
        self.assertNotIn("abc123", text)
        self.assertIn("x=1", text)
        long = bot.format_redirects([(302, "https://example.com/" + "a" * 500)])
        self.assertLessEqual(len(long), bot.REDIRECT_URL_MAX + 20)
        self.assertIn("…", long)


class TestTrail(unittest.TestCase):
    def setUp(self):
        bot._dns_cache.clear()
        p = patch("bot._query_with_ttl", AsyncMock(return_value=(["93.184.216.34"], 60)))
        p.start()
        self.addCleanup(p.stop)

    def run_fetch(self, sess, url, trail_first=True):
        async def go():
            bot._redirect_trail.set([])
            async with bot._safe_http_request(sess, "GET", url) as resp:
                status = resp.status
            return status, bot.last_redirect_trail()
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            return asyncio.run(go())

    def test_hops_are_recorded_with_absolute_urls(self):
        sess = _Session({
            "https://site.example/": _Resp(301, "/new", "https://site.example/"),
            "https://site.example/new": _Resp(302, "https://other.example/", "https://site.example/new"),
            "https://other.example/": _Resp(200, url="https://other.example/"),
        })
        status, trail = self.run_fetch(sess, "https://site.example/")
        self.assertEqual(status, 200)
        self.assertEqual(trail, [(301, "https://site.example/new"), (302, "https://other.example/")])

    def test_no_redirect_empty_trail(self):
        sess = _Session({"https://site.example/": _Resp(200, url="https://site.example/")})
        self.assertEqual(self.run_fetch(sess, "https://site.example/"), (200, []))

    def test_second_request_starts_a_new_trail(self):
        sess = _Session({
            "https://site.example/": _Resp(301, "/new", "https://site.example/"),
            "https://site.example/new": _Resp(200, url="https://site.example/new"),
        })

        async def go():
            bot._redirect_trail.set([])
            async with bot._safe_http_request(sess, "HEAD", "https://site.example/new") as r:
                pass
            async with bot._safe_http_request(sess, "GET", "https://site.example/") as r:
                pass
            async with bot._safe_http_request(sess, "GET", "https://site.example/new") as r:
                pass
            return bot.last_redirect_trail()
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            self.assertEqual(asyncio.run(go()), [])  # the last request had no redirect

    def test_without_a_trail_nothing_breaks(self):
        sess = _Session({"https://site.example/": _Resp(200, url="https://site.example/")})

        async def go():
            bot._redirect_trail.set(None)
            async with bot._safe_http_request(sess, "GET", "https://site.example/") as r:
                return r.status
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            self.assertEqual(asyncio.run(go()), 200)

    def test_run_single_check_resets_the_trail(self):
        async def go():
            bot._redirect_trail.set([(301, "https://stale.example/")])
            with patch.object(bot, "_run_single_check", AsyncMock(return_value=(True, "200 - OK", 5))):
                await bot.run_single_check({"type": "http", "url": "https://site.example/"})
            return bot.last_redirect_trail()
        self.assertEqual(asyncio.run(go()), [])


def tearDownModule():
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove("test_redirect_display.db" + suffix)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
