"""A body that stops after a few KB (the TSPU freeze): _read_body_limited, the message and the tag."""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ["DB_PATH"] = "test_body_freeze.db"

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
import blockcheck  # noqa: E402


class _Content:
    """Hands out `chunks`, then behaves as `ending`: 'eof', 'stall' (TimeoutError) or 'reset'."""
    def __init__(self, chunks, ending):
        self.chunks, self.ending = list(chunks), ending

    async def read(self, n=-1):
        if self.chunks:
            data = self.chunks.pop(0)
            if n > 0 and len(data) > n:
                self.chunks.insert(0, data[n:])
                data = data[:n]
            return data
        if self.ending == "eof":
            return b""
        if self.ending == "stall":
            raise asyncio.TimeoutError()
        raise ConnectionResetError()


class _Resp:
    def __init__(self, chunks, ending="eof", length=None, headers=None):
        self.content = _Content(chunks, ending)
        self.content_length = length
        self.headers = headers or {}


def run(coro):
    return asyncio.run(coro)


class TestReadBody(unittest.TestCase):
    def test_complete_body(self):
        resp = _Resp([b"a" * 1000, b"b" * 500], "eof", length=1500)
        self.assertEqual(len(run(bot._read_body_limited(resp, 16384))), 1500)

    def test_reads_until_the_limit_across_chunks(self):
        resp = _Resp([b"x" * 4000] * 10, "stall", length=40000)
        self.assertEqual(len(run(bot._read_body_limited(resp, 10000))), 10000)   # stops at the limit, no stall

    def test_stall_after_a_few_kb_raises(self):
        resp = _Resp([b"x" * 3000, b"x" * 2000], "stall", length=2_000_000)
        with self.assertRaises(bot.BodyStalled) as ctx:
            run(bot._read_body_limited(resp, 16384))
        self.assertEqual((ctx.exception.received, ctx.exception.expected), (5000, 2_000_000))

    def test_reset_after_a_few_kb_raises(self):
        resp = _Resp([b"x" * 3000], "reset", length=100000)
        with self.assertRaises(bot.BodyStalled):
            run(bot._read_body_limited(resp, 16384))

    def test_early_close_without_error_raises(self):
        resp = _Resp([b"x" * 3000], "eof", length=100000)
        with self.assertRaises(bot.BodyStalled):
            run(bot._read_body_limited(resp, 16384))

    def test_compressed_body_may_be_shorter_than_announced_no_false_stall(self):
        # decoded size differs from Content-Length; an early EOF of an encoded body is not judged
        resp = _Resp([b"x" * 3000], "eof", length=100000, headers={"Content-Encoding": "gzip"})
        self.assertEqual(len(run(bot._read_body_limited(resp, 16384))), 3000)

    def test_unknown_length_is_one_read_as_before(self):
        for length in (None, MagicMock(), True, 0):
            resp = _Resp([b"x" * 3000], "stall", length=length)
            self.assertEqual(len(run(bot._read_body_limited(resp, 16384))), 3000)   # never raises, never loops

    def test_stream_without_length_may_stay_silent(self):
        resp = _Resp([], "stall", length=None)
        with self.assertRaises(asyncio.TimeoutError):   # as before: swallowed by the caller's generic handler
            run(bot._read_body_limited(resp, 16384))


class TestMessage(unittest.TestCase):
    def test_freeze_tag_below_64kb(self):
        self.assertEqual(bot.stalled_body_message(bot.BodyStalled(10 * 1024, 2 * 1024 * 1024)),
                         "Freeze? Stalled after 10 KB of 2.0 MB")
        self.assertEqual(bot.stalled_body_message(bot.BodyStalled(700, 5000)), "Freeze? Stalled after 700 B of 5 KB")

    def test_no_tag_above_64kb_it_is_a_slow_link(self):
        self.assertEqual(bot.stalled_body_message(bot.BodyStalled(100 * 1024, 5 * 1024 * 1024)),
                         "Stalled after 100 KB of 5.0 MB")

    def test_vote_line_keeps_the_tag(self):
        text = bot.stalled_body_message(bot.BodyStalled(10 * 1024, 2 * 1024 * 1024))
        self.assertEqual(bot.short_vote_error(text), text)
        self.assertEqual(blockcheck.split_tag(text)[0], "Freeze?")

    def test_tagged_error_is_not_diagnosed_again(self):
        async def go():
            with patch.object(blockcheck, "diagnose_cached", AsyncMock(return_value=blockcheck.TAG_SNI)) as d, \
                 patch.object(bot, "probe_addresses", AsyncMock(return_value=["203.0.113.5"])):
                res = await bot._annotate_block({"type": "http", "url": "https://site.example/f"}, (False, "Freeze? Stalled after 10 KB of 2.0 MB", 9))
                return res, d
        res, d = run(go())
        self.assertEqual(res, (False, "Freeze? Stalled after 10 KB of 2.0 MB", 9))
        d.assert_not_awaited()


def tearDownModule():
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove("test_body_freeze.db" + suffix)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()


class TestRealServer(unittest.IsolatedAsyncioTestCase):
    """aiohttp client against a server that announces 2 MB, sends a few KB and then goes silent."""
    async def asyncSetUp(self):
        import aiohttp
        from aiohttp import web
        self.aiohttp = aiohttp
        self.release = asyncio.Event()

        async def frozen(request):
            resp = web.StreamResponse(headers={"Content-Length": str(2 * 1024 * 1024)})
            await resp.prepare(request)
            await resp.write(b"x" * 6000)
            try:
                await asyncio.wait_for(self.release.wait(), 30)
            except asyncio.TimeoutError:
                pass
            return resp

        async def fine(request):
            return web.Response(body=b"y" * 5000)

        app = web.Application()
        app.router.add_get("/frozen", frozen)
        app.router.add_get("/fine", fine)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.release.set()
        await self.runner.cleanup()

    async def test_frozen_body_is_a_stall(self):
        timeout = self.aiohttp.ClientTimeout(total=1.5)
        async with self.aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(f"http://127.0.0.1:{self.port}/frozen") as resp:
                with self.assertRaises(bot.BodyStalled) as ctx:
                    await bot._read_body_limited(resp, 16384)
        self.assertEqual(ctx.exception.received, 6000)
        self.assertEqual(ctx.exception.expected, 2 * 1024 * 1024)

    async def test_normal_body_is_read_whole(self):
        async with self.aiohttp.ClientSession() as sess:
            async with sess.get(f"http://127.0.0.1:{self.port}/fine") as resp:
                self.assertEqual(len(await bot._read_body_limited(resp, 16384)), 5000)
