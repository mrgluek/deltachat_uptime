"""Regression coverage for audit findings F07, F08 and F11."""
import asyncio
import concurrent.futures
import contextlib
import json
import os
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import make_mocked_request

import bot
import database
from outbox import Outbox, PRIO_ALERT, PRIO_PEER, PRIO_REPLY, PRIO_TELEMETRY, PRIO_UPDATE


class DatabaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, 'limits.db')
        database.init_db()
        self.client = MagicMock()
        self.event = types.SimpleNamespace(payload='', msg=types.SimpleNamespace(
            is_info=False, from_id=42, chat_id=50, show_padlock=True, text=''))
        bot._command_windows.clear()
        bot._command_warnings.clear()
        bot._chat_ping_anti_spam.clear()
        bot._dashboard_cache.clear()
        bot._rate_limits.clear()
        bot._dns_cache.clear()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(bot, '_is_dc_admin', return_value=False))
        self.send = self.stack.enter_context(patch.object(bot, '_dc_send_msg_with_stats'))

    def tearDown(self):
        self.stack.close()
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def receive(self, tag, data):
        self.event.msg.text = f'[{tag}]{data}[/{tag}]'
        bot.on_new_message(self.client, 1, self.event)


class TestMonitorLimits(DatabaseCase):
    def test_defaults_and_transactional_concurrent_limits(self):
        self.assertEqual(database.MAX_MONITORS_PER_CHAT, 300)
        self.assertEqual(database.MAX_MONITORS_TOTAL, 3000)
        with patch.object(database, 'MAX_MONITORS_PER_CHAT', 2), patch.object(database, 'MAX_MONITORS_TOTAL', 3):
            def add(index):
                try:
                    return database.add_resource(50, f'https://example.org/{index}', 'Test', 'http')
                except database.MonitorLimitError:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(add, range(20)))
            self.assertEqual(sum(value is not None for value in results), 2)
            database.add_resource(51, 'https://example.org/third', 'Third', 'http')
            with self.assertRaisesRegex(database.MonitorLimitError, '3 monitors in total'):
                database.add_resource(52, 'https://example.org/fourth', 'Fourth', 'http')
        self.assertEqual(len(database.get_all_resources()), 3)

    def test_existing_monitors_survive_lower_limits_and_remain_editable(self):
        ids = [database.add_resource(50, f'https://example.org/{n}', f'Monitor {n}', 'http') for n in range(90)]
        with patch.object(database, 'MAX_MONITORS_PER_CHAT', 1), patch.object(database, 'MAX_MONITORS_TOTAL', 1):
            with self.assertRaises(database.MonitorLimitError):
                database.add_resource(50, 'https://new.example.org', 'New', 'http')
            self.assertIsNone(database.add_resource(50, 'https://example.org/0', 'Duplicate', 'http'))
            self.assertTrue(database.set_resource_keyword(50, ids[0], 'still works'))
            database.update_resource_status(ids[0], 'up', 1)
        rows = database.get_resources(50)
        self.assertEqual(len(rows), 90)
        self.assertEqual(rows[0]['status'], 'up')
        self.assertTrue(all(not row.get('maintenance_until') for row in rows))

    def test_field_boundaries_and_keyword_update(self):
        url = 'https://example.org/' + 'x' * (2048 - len('https://example.org/'))
        rid = database.add_resource(50, url, 'n' * 100, 'http', expected_keyword='k' * 200)
        self.assertTrue(rid)
        for args in ((url + 'x', 'name', 'kw'), ('https://other.org', 'n' * 101, 'kw'),
                     ('https://other.org', 'name', 'k' * 201)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                database.add_resource(50, args[0], args[1], 'http', expected_keyword=args[2])
        with self.assertRaisesRegex(ValueError, '200'):
            database.set_resource_keyword(50, rid, 'k' * 201)
        self.assertEqual(database.get_resource_by_id(rid)['expected_keyword'], 'k' * 200)

    def test_add_and_sync_explain_quotas(self):
        with patch.object(database, 'MAX_MONITORS_PER_CHAT', 1), patch.object(bot, 'is_safe_target_url', return_value=True):
            database.add_resource(50, 'https://existing.example', 'Existing', 'http')
            self.event.payload = 'https://new.example New'
            bot.add_command(self.client, 1, self.event)
            self.assertIn('1 monitors per chat', self.send.call_args.args[3].text)
            self.receive('UPTIME_BOT_SYNC_DATA', json.dumps([{'url': 'https://sync.example', 'type': 'http'}]))
            self.assertTrue(any('1 monitors per chat' in c.args[3].text for c in self.send.call_args_list))
        self.assertEqual(len(database.get_resources(50)), 1)

    def test_add_and_keyword_reject_lengths_before_dns(self):
        with patch.object(bot, 'is_safe_target_url') as safe:
            for payload, limit in [('https://example.org/' + 'x' * 2048, '2048'),
                                   ('https://example.org ' + 'n' * 101, '100'),
                                   ('https://example.org Name ' + 'k' * 201, '200')]:
                self.event.payload = payload
                bot.add_command(self.client, 1, self.event)
                self.assertIn(limit, self.send.call_args.args[3].text)
            safe.assert_not_called()
        self.event.payload = '1 ' + 'k' * 201
        bot.keyword_command(self.client, 1, self.event)
        self.assertIn('200', self.send.call_args.args[3].text)
        self.assertEqual(database.get_resources(50), [])

    def test_node_rename_rejects_oversize_name_without_changing_existing(self):
        database.set_local_node_name('Existing')
        self.event.payload = 'n' * 101
        with patch.object(bot, '_is_dc_admin', return_value=True):
            bot.nodename_command(self.client, 1, self.event)
        self.assertEqual(database.get_local_node_name(), 'Existing')
        self.assertIn('100', self.send.call_args.args[3].text)
        with self.assertRaises(ValueError):
            database.set_local_node_name('n' * 101)

    def test_sync_and_peer_fields_rejected_without_truncating(self):
        items = [{'url': 'https://example.org/' + 'x' * 2048, 'type': 'http'},
                 {'url': 'https://example.org/name', 'name': 'n' * 101, 'type': 'http'},
                 {'url': 'https://example.org/kw', 'expected_keyword': 'k' * 201, 'type': 'http'}]
        self.receive('UPTIME_BOT_SYNC_DATA', json.dumps(items))
        self.assertEqual(database.get_resources(50), [])
        with patch.object(bot, 'is_safe_target_url', return_value=True):
            self.assertEqual(bot._parse_batch_targets(items), [None, None, None])
        database.save_probe_targets_batch(items, 'peer@example.org')
        database.save_peer_measurements_batch('Peer', items, 'peer@example.org')
        self.assertEqual(database.get_active_probe_targets(), [])
        with contextlib.closing(database._connect()) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM peer_measurements').fetchone()[0], 0)

    def test_sync_valid_keyword_preserved(self):
        self.receive('UPTIME_BOT_SYNC_DATA', json.dumps([{'url': 'https://example.org', 'type': 'http',
                                                        'name': 'Valid', 'expected_keyword': 'required'}]))
        self.assertEqual(database.get_resources(50)[0]['expected_keyword'], 'required')

    def test_payload_byte_limits_precede_json_and_rpc(self):
        for tag, content in [('UPTIME_BOT_SYNC_DATA', '😀' * (bot.SYNC_MAX_BYTES // 3)),
                             ('UPTIME_PEER_METRICS', 'x' * (bot.PEER_MAX_BYTES + 1)),
                             ('UPTIME_PEER_CHECK_REQ', '😀' * (bot.PEER_MAX_BYTES // 3))]:
            with self.subTest(tag=tag), patch.object(bot.json, 'loads') as loads:
                self.receive(tag, content)
                loads.assert_not_called()
        self.client.rpc.get_basic_chat_info.assert_not_called()

    def test_largest_produced_telemetry_and_cross_check_batches_fit(self):
        # json.dumps escapes an astral character as two six-byte surrogate escapes.
        url = 'https://example.org/' + '😀' * (2048 - len('https://example.org/'))
        metrics = [dict(url=url[:2048 - len(str(n))] + str(n), type='http',
                        expected_keyword='😀' * 200, status='up') for n in range(200)]
        peer = {'email': 'peer@example.org', 'chat_id': 701}
        with patch.object(bot, 'dc_bot_instance', self.client), patch.object(bot, 'dc_accid', 1), \
             patch.object(database, 'get_all_peers', return_value=[peer]), \
             patch.object(database, 'get_all_resources', return_value=metrics), \
             patch.object(database, 'get_active_probe_targets', return_value=[]), \
             patch.object(bot, '_filter_peer_shareable_resources', side_effect=lambda b, a, r: r), \
             patch.object(bot, '_resolve_peer_chat_id', AsyncMock(return_value=701)), \
             patch.object(bot, '_get_self_addr', return_value='self@example.org'), \
             patch.object(bot, '_telemetry_sent_at', {}), patch.object(bot, '_telemetry_last_sent', {}):
            asyncio.run(bot.broadcast_telemetry_to_peers())
        wire = self.send.call_args.args[3].text.encode('utf-8')
        self.assertGreater(len(wire), 256 * 1024)
        self.assertLess(len(wire), bot.PEER_MAX_BYTES)
        payload = json.loads(wire.decode().split('\n', 1)[1].rsplit('\n', 1)[0])
        self.assertEqual(len(payload['metrics']), 200)
        self.assertLess(len(json.dumps({'targets': metrics[:bot.CROSS_CHECK_BATCH_MAX]}).encode()), bot.PEER_MAX_BYTES)


class TestCommandBudget(DatabaseCase):
    def test_sliding_window_sender_chat_admin_and_warning(self):
        calls = []
        handler = bot.command_budget(lambda b, a, e: calls.append((e.msg.chat_id, e.msg.from_id)))
        with patch.object(bot.time, 'monotonic', return_value=100) as clock:
            for _ in range(30):
                handler(self.client, 1, self.event)
            clock.return_value = 130
            for _ in range(10):
                handler(self.client, 1, self.event)
            self.assertEqual(len(calls), 30)
            self.send.assert_called_once()
            self.assertIn('Slow down', self.send.call_args.args[3].text)
            self.event.msg.from_id = 43
            for _ in range(31):
                handler(self.client, 1, self.event)
            self.assertEqual(len(calls), 60)
            self.send.assert_called_once()  # warning is shared by chat
            self.event.msg.from_id = 42
            self.event.msg.chat_id = 51
            handler(self.client, 1, self.event)
            self.assertEqual(len(calls), 61)
            self.event.msg.chat_id = 50
            clock.return_value = 160
            handler(self.client, 1, self.event)
            self.assertEqual(len(calls), 62)
            with patch.object(bot, '_is_dc_admin', return_value=True):
                for _ in range(40):
                    handler(self.client, 1, self.event)
            self.assertEqual(len(calls), 102)

    def test_state_is_bounded_and_expiring(self):
        handler = bot.command_budget(lambda *args: None)
        with patch.object(bot, 'COMMAND_MAX_KEYS', 100), patch.object(bot.time, 'monotonic', return_value=100) as clock:
            for n in range(2000):
                self.event.msg.from_id = n
                handler(self.client, 1, self.event)
            self.assertLessEqual(len(bot._command_windows), 100)
            clock.return_value = 161
            handler(self.client, 1, self.event)
            self.assertEqual(len(bot._command_windows), 1)

    def test_registered_commands_share_budget(self):
        for _ in range(31):
            bot.donate_command(self.client, 1, self.event)
        self.assertEqual(self.send.call_count, 31)  # 30 replies + one warning
        self.assertIn('Slow down', self.send.call_args.args[3].text)
        bot.list_command(self.client, 1, self.event)
        self.assertEqual(self.send.call_count, 31)


class TestOutboxCapacity(unittest.TestCase):
    def test_capacity_evicts_replies_before_alerts_or_protocol(self):
        now = [100.0]
        outbox = Outbox(max_pending=3, clock=lambda: now[0])
        outbox._thread = object()
        alert = outbox.submit(lambda: 1, PRIO_ALERT)
        peer = outbox.submit(lambda: 2, PRIO_PEER)
        reply = outbox.submit(lambda: 3, PRIO_REPLY, key='reply')
        with self.assertLogs('uptime_bot', level='WARNING') as logs:
            outbox.submit(lambda: 4, PRIO_TELEMETRY)
            outbox.submit(lambda: 5, PRIO_REPLY)
            now[0] += 60
            outbox.submit(lambda: 6, PRIO_UPDATE)
        self.assertEqual(len(logs.output), 2)
        self.assertIsNone(reply.result())
        self.assertFalse(alert.done())
        self.assertFalse(peer.done())
        self.assertEqual(outbox.stats['dropped'], 3)
        self.assertEqual(sum(outbox.waiting().values()), 3)
        self.assertNotIn('reply', outbox._by_key)
        self.assertLessEqual(len(outbox._heap), 3)

    def test_merge_and_expiry_free_capacity(self):
        now = [100.0]
        outbox = Outbox(max_pending=2, clock=lambda: now[0])
        outbox._thread = object()
        future = outbox.submit(lambda: 1, key='merged')
        self.assertIs(outbox.submit(lambda: 2, key='merged'), future)
        expired = outbox.submit(lambda: 3, PRIO_PEER, expires_in=1)
        now[0] += 2
        outbox.submit(lambda: 4, PRIO_ALERT)
        self.assertIsNone(expired.result())
        self.assertEqual(outbox.stats['expired'], 1)
        self.assertEqual(outbox.stats['dropped'], 0)


class TestDeadlines(DatabaseCase):
    def test_ping_cooldown_precedes_parsing_and_dns(self):
        bot._chat_ping_anti_spam[50] = time.time()
        self.event.payload = 'https://slow.example'
        with patch.object(bot, 'parse_target') as parse, patch.object(bot, 'is_safe_target_url') as safe:
            bot.ping_command(self.client, 1, self.event)
        parse.assert_not_called()
        safe.assert_not_called()
        self.assertIn('Please wait', self.send.call_args.args[3].text)

    def test_synchronous_dns_deadline_and_bounded_admission(self):
        release = threading.Event()
        def lookup(*args):
            release.wait(2)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]
        slots = threading.BoundedSemaphore(1)
        started = time.monotonic()
        try:
            with patch.object(bot, '_dns_slots', slots), patch.object(bot, 'DNS_DEADLINE', .03), \
                 patch.object(socket, 'getaddrinfo', side_effect=lookup):
                with self.assertRaises(TimeoutError):
                    bot.resolve_host_safe_sync('slow.example')
                with self.assertRaisesRegex(TimeoutError, 'capacity'):
                    bot.resolve_host_safe_sync('another.example')
                self.assertLess(time.monotonic() - started, .3)
        finally:
            release.set()

    def test_async_dns_deadline_keeps_event_loop_responsive(self):
        async def scenario():
            async def slow(*args):
                await asyncio.sleep(2)
            with patch.object(bot, 'DNS_DEADLINE', .03), patch.object(bot, '_query_with_ttl', side_effect=slow):
                task = asyncio.create_task(bot.resolve_host_safe('slow.example'))
                await asyncio.sleep(.005)
                self.assertFalse(task.done())
                with self.assertRaises(TimeoutError):
                    await task
        asyncio.run(scenario())

    def test_dns_timeout_does_not_release_slots_for_still_queued_work(self):
        release = threading.Event()
        slots = threading.BoundedSemaphore(2)
        def lookup(*args):
            release.wait(2)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]
        async def scenario():
            with self.assertRaises(TimeoutError):
                await bot.resolve_host_safe('first.example')
            with self.assertRaises(TimeoutError):
                await bot.resolve_host_safe('queued.example')
            with self.assertRaisesRegex(TimeoutError, 'capacity'):
                await bot.resolve_host_safe('rejected.example')
            self.assertFalse(slots.acquire(blocking=False))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            try:
                with patch.object(bot, 'dns_executor', executor), patch.object(bot, '_dns_slots', slots), \
                     patch.object(bot, 'DNS_DEADLINE', .02), patch.object(bot, 'aiodns', None), \
                     patch.object(socket, 'getaddrinfo', side_effect=lookup):
                    asyncio.run(scenario())
            finally:
                release.set()

    def test_title_worker_does_not_block_handler_and_adds_without_title(self):
        release, started, finished = threading.Event(), threading.Event(), threading.Event()
        real_add = database.add_resource
        def title(url):
            started.set()
            release.wait(2)
            return None
        def add(*args, **kwargs):
            result = real_add(*args, **kwargs)
            finished.set()
            return result
        try:
            self.event.payload = 'https://example.org'
            with patch.object(bot, 'is_safe_target_url', return_value=True), \
                 patch.object(bot, 'fetch_html_title', side_effect=title), \
                 patch.object(database, 'add_resource', side_effect=add):
                before = time.monotonic()
                bot.add_command(self.client, 1, self.event)
                self.assertLess(time.monotonic() - before, .2)
                self.assertTrue(started.wait(1))
                self.assertEqual(database.get_resources(50), [])
                release.set()
                self.assertTrue(finished.wait(1))
                # Worker must also finish its reply before patches/database teardown.
                deadline = time.monotonic() + 1
                while not self.send.called and time.monotonic() < deadline:
                    time.sleep(.001)
            self.assertEqual(database.get_resources(50)[0]['name'], 'https://example.org')
        finally:
            release.set()

    def test_http_and_title_slow_drip_end_at_total_deadline(self):
        async def scenario():
            tasks = set()
            async def drip(reader, writer):
                task = asyncio.current_task()
                tasks.add(task)
                try:
                    request = await reader.readuntil(b'\r\n\r\n')
                    if b'/headers' in request:
                        for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n':
                            writer.write(bytes([byte]))
                            await writer.drain()
                            await asyncio.sleep(.01)
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 20000\r\nContent-Type: text/html\r\n\r\n')
                    await writer.drain()
                    while True:
                        writer.write(b'x')
                        await writer.drain()
                        await asyncio.sleep(.01)
                except (ConnectionError, asyncio.CancelledError):
                    pass
                finally:
                    writer.close()
                    with contextlib.suppress(ConnectionError):
                        await writer.wait_closed()
                    tasks.discard(task)
            server = await asyncio.start_server(drip, '127.0.0.1', 0)
            url = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}/'
            import aiohttp
            connector = aiohttp.TCPConnector
            try:
                with patch.object(bot, '_prewarm_target_dns', AsyncMock(return_value=True)), \
                     patch.object(bot, 'is_safe_target_url', return_value=True), \
                     patch.object(bot, '_make_safe_connector', side_effect=lambda **kw: connector(**kw)), \
                     patch.object(bot, 'HTTP_TOTAL_DEADLINE', .08):
                    before = time.monotonic()
                    result = await bot.run_single_check({'url': url + 'headers', 'type': 'http', 'expected_keyword': 'marker'})
                    self.assertEqual(result[:2], (False, 'Timeout'))
                    self.assertLess(time.monotonic() - before, .4)
                    before = time.monotonic()
                    self.assertIsNone(await bot._fetch_html_title(url, timeout=.08))
                    self.assertLess(time.monotonic() - before, .4)
            finally:
                server.close()
                await server.wait_closed()
                for task in list(tasks):
                    task.cancel()
                await asyncio.gather(*list(tasks), return_exceptions=True)
        asyncio.run(scenario())

    def test_smtp_cancelled_cleanup_cannot_extend_deadline(self):
        async def slow(*args):
            await asyncio.sleep(2)
        async def scenario():
            reader = types.SimpleNamespace(readline=slow)
            writer = MagicMock()
            writer.wait_closed = AsyncMock(side_effect=slow)
            with patch.object(bot, '_prewarm_target_dns', AsyncMock(return_value=True)), \
                 patch.object(bot, 'is_safe_target_url', return_value=True), \
                 patch.object(bot, '_open_pinned_streams', AsyncMock(return_value=(reader, writer))), \
                 patch.object(bot, 'HTTP_TOTAL_DEADLINE', .03):
                started = time.monotonic()
                result = await asyncio.wait_for(bot.run_single_check({'url': 'smtp://mail.example', 'type': 'smtp'}), .5)
                self.assertEqual(result[:2], (False, 'Timeout'))
                self.assertLess(time.monotonic() - started, .3)
                writer.transport.abort.assert_called_once()
                writer.wait_closed.assert_not_awaited()
        asyncio.run(scenario())

    def test_http_cleanup_is_in_overall_deadline(self):
        async def scenario():
            class Request:
                async def __aenter__(self):
                    return types.SimpleNamespace(status=200, headers={})
                async def __aexit__(self, *args):
                    await asyncio.sleep(2)
            session = types.SimpleNamespace(head=lambda *a, **k: Request(), closed=False)
            with patch.object(bot, '_prewarm_target_dns', AsyncMock(return_value=True)), \
                 patch.object(bot, 'is_safe_target_url', return_value=True), \
                 patch.object(bot, 'HTTP_TOTAL_DEADLINE', .03):
                started = time.monotonic()
                result = await bot.run_single_check({'url': 'https://example.org', 'type': 'http'}, session)
                self.assertEqual(result[:2], (False, 'Timeout'))
                self.assertLess(time.monotonic() - started, .3)
        asyncio.run(scenario())

    def test_redirect_and_head_get_share_deadline(self):
        async def scenario():
            import aiohttp
            class Request:
                async def __aenter__(self):
                    await asyncio.sleep(.03)
                    return types.SimpleNamespace(status=405, headers={})
                async def __aexit__(self, *args):
                    pass
            session = types.SimpleNamespace(head=lambda *a, **k: Request(), get=lambda *a, **k: Request(), closed=False)
            with patch.object(bot, '_prewarm_target_dns', AsyncMock(return_value=True)), \
                 patch.object(bot, 'is_safe_target_url', return_value=True), \
                 patch.object(bot, 'HTTP_TOTAL_DEADLINE', .04), \
                 patch.object(database, 'set_url_http_method'):
                self.assertEqual((await bot.run_single_check({'url': 'https://example.org', 'type': 'http'}, session))[:2],
                                 (False, 'Timeout'))
            class Redirect(Request):
                async def __aenter__(self):
                    await asyncio.sleep(.03)
                    return types.SimpleNamespace(status=302, headers={'Location': '/next'}, url='https://example.org')
            session.head = lambda *a, **k: Redirect()
            with patch.object(bot, '_prewarm_target_dns', AsyncMock(return_value=True)), \
                 patch.object(bot, 'is_safe_target_url', return_value=True), patch.object(bot, 'HTTP_TOTAL_DEADLINE', .05):
                self.assertEqual((await bot.run_single_check({'url': 'https://example.org', 'type': 'http'}, session))[:2],
                                 (False, 'Timeout'))
        asyncio.run(scenario())


class TestWebLimits(DatabaseCase):
    def request(self, remote='93.184.216.34', forwarded=None, token='test'):
        return types.SimpleNamespace(remote=remote, headers={'X-Forwarded-For': forwarded} if forwarded else {},
                                     match_info={'token': token})

    def test_untrusted_forwarding_ignored_and_trusted_chain_rightmost(self):
        self.assertEqual(bot.get_client_ip(self.request(forwarded='1.1.1.1')), '93.184.216.34')
        self.assertEqual(bot.get_client_ip(self.request('127.0.0.1', '1.1.1.1, 8.8.8.8, 10.0.0.2')), '8.8.8.8')
        self.assertEqual(bot.get_client_ip(self.request('::1', '8.8.8.8')), '8.8.8.8')
        with patch.object(bot, 'TRUSTED_PROXIES', ()):
            self.assertEqual(bot.get_client_ip(self.request('127.0.0.1', '8.8.8.8')), '127.0.0.1')

    def test_forged_headers_cannot_bypass_budget(self):
        for n in range(10):
            allowed = bot.check_rate_limit(self.request(forwarded=f'1.1.1.{n}'), max_requests=1)
            self.assertEqual(allowed, n == 0)
        self.assertEqual(len(bot._rate_limits), 1)

    def test_20000_buckets_stay_bounded_and_expire(self):
        with patch.object(bot.time, 'monotonic', return_value=100) as clock:
            for n in range(20000):
                self.assertTrue(bot.check_rate_limit(self.request(f'client-{n}')))
            self.assertEqual(len(bot._rate_limits), 10000)
            clock.return_value = 161
            bot.check_rate_limit(self.request())
            self.assertEqual(len(bot._rate_limits), 1)

    def test_cache_hit_expiry_and_render_off_event_loop(self):
        token = database.get_or_create_chat_token(50)
        request = self.request(token=token)
        threads = []
        def render(*args, **kwargs):
            threads.append(threading.get_ident())
            return f'<html>{len(threads)}</html>'
        with patch.object(bot, 'dc_bot_instance', None), patch.object(bot, 'get_dashboard_html', side_effect=render), \
             patch.object(bot.time, 'monotonic', return_value=100) as clock:
            first = asyncio.run(bot.handle_status_page(request))
            second = asyncio.run(bot.handle_status_page(request))
            self.assertEqual(first.text, second.text)
            self.assertEqual(len(threads), 1)
            self.assertNotEqual(threads[0], threading.get_ident())
            clock.return_value = 116
            third = asyncio.run(bot.handle_status_page(request))
            self.assertNotEqual(first.text, third.text)
            self.assertEqual(len(threads), 2)
            for response in (first, second, third):
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
                self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')

    def test_concurrent_render_cap_returns_503(self):
        async def scenario():
            gate, all_started = asyncio.Event(), asyncio.Event()
            count = 0
            async def blocked(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 4:
                    all_started.set()
                await gate.wait()
                return None
            with patch.object(bot, 'run_db', side_effect=blocked):
                tasks = [asyncio.create_task(bot.handle_status_page(self.request(token=str(n)))) for n in range(4)]
                await asyncio.wait_for(all_started.wait(), 1)
                response = await bot.handle_status_page(self.request(token='overflow'))
                self.assertEqual(response.status, 503)
                self.assertEqual(response.headers['Retry-After'], '15')
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                gate.set()
                await asyncio.gather(*tasks)
        asyncio.run(scenario())
