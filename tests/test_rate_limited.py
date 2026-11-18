"""A target that answers 429 Too Many Requests is not counted as down: the check abstains."""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_PATH"] = "test_rate_limited.db"

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
    def __init__(self, status):
        self.status = status
        self.headers = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _run(status_for, method="GET"):
    calls = []

    def fake_request(sess, m, url, **kwargs):
        calls.append(m)
        return _Resp(status_for(m))

    async def go():
        resource = {"type": "http", "url": "https://site.example/", "http_method": method}
        session = MagicMock(closed=False)
        with patch.object(bot, "_prewarm_target_dns", AsyncMock(return_value=True)), \
             patch.object(bot, "is_safe_target_url", return_value=True), \
             patch.object(bot, "_safe_http_request", fake_request):
            return await bot._run_single_check(resource, session, 100)
    return asyncio.run(go()), calls


class TestRateLimited(unittest.TestCase):
    def test_429_on_get_abstains(self):
        (ok, msg, _ms), _ = _run(lambda m: 429)
        self.assertIsNone(ok)
        self.assertEqual(msg, bot.RATE_LIMITED_MSG)

    def test_429_on_head_then_get_abstains(self):
        (ok, msg, _ms), calls = _run(lambda m: 429, method="")
        self.assertIsNone(ok)
        self.assertEqual(calls, ["HEAD", "GET"])

    def test_other_errors_still_fail(self):
        (ok, msg, _ms), _ = _run(lambda m: 503)
        self.assertIs(ok, False)
        self.assertTrue(msg.startswith("503"))

    def test_success_still_succeeds(self):
        with patch.object(bot, "_read_body_limited", AsyncMock(return_value=b"ok")):
            (ok, msg, _ms), _ = _run(lambda m: 200)
        self.assertIs(ok, True)


def tearDownModule():
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove("test_rate_limited.db" + suffix)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    unittest.main()
