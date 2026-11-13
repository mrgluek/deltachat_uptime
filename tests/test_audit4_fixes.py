"""Admission, identity, incident and retention regressions from audit 4."""
import asyncio
import collections
import contextlib
import json
import os
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from deltachat2 import JsonRpcError, MessageState
from outbox import Outbox


class AuditCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, 'audit.db')
        database.init_db()
        bot._processed_msg_ids.clear()
        self.client = MagicMock()
        self.client.rpc.get_basic_chat_info.return_value = {'chat_type': 'Single'}
        self.client.rpc.send_msg.return_value = 123
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in [('dc_bot_instance', self.client), ('dc_accid', 1),
                            ('async_event_loop', None), ('dc_outbox', Outbox()),
                            ('_inbound_probes', bot.InboundProbeAdmission())]:
            self.stack.enter_context(patch.object(bot, name, value))
        self.stack.enter_context(patch.object(bot, '_record_peer_activity'))
        self.stack.enter_context(patch.object(bot, '_get_self_addr', return_value='self@example.org'))
        self.clock = self.stack.enter_context(patch('bot.time.time', return_value=1000000))
        bot._incident_last_edit_state.clear()

    def tearDown(self):
        self.stack.close()
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    def peer(self, name='Evil', email='evil@example.org', chat=701):
        database.add_or_update_peer(email, name, chat, fingerprint=('B' if name == 'Evil' else 'C') * 40)
        return database.get_peer(email)

    def event(self, tag, data, chat=701):
        return types.SimpleNamespace(msg=types.SimpleNamespace(
            is_info=False, from_id=42, chat_id=chat, show_padlock=True,
            text=f'[{tag}]\n{json.dumps(data)}\n[/{tag}]'))

    def receive(self, peer, tag, data):
        with patch.object(bot, '_get_verified_peer_for_msg', return_value=(peer, peer['email'])):
            bot.on_new_message(self.client, 1, self.event(tag, data, peer['chat_id']))


class TestProbeAdmission(AuditCase):
    def flood(self, batch=False, repeated=False):
        async def scenario():
            gate, started, done = asyncio.Event(), asyncio.Event(), asyncio.Event()
            active = collections.Counter()
            calls, peak = [], collections.Counter()
            expected = 1 if repeated else 20
            finished = 0

            async def probe(target):
                who = target['url']
                calls.append(who)
                active[who] += 1
                peak[who] = max(peak[who], active[who])
                if len(calls) == expected:
                    started.set()
                await gate.wait()
                active[who] -= 1
                return True, None, 1

            def sent(*args, **kwargs):
                nonlocal finished
                finished += 1
                if finished == expected:
                    done.set()

            evil, honest = self.peer(), self.peer('Honest', 'honest@example.org', 702)
            tag = 'UPTIME_PEER_CHECK_BATCH_REQ' if batch else 'UPTIME_PEER_CHECK_REQ'
            with patch.object(bot, 'run_single_check', side_effect=probe), \
                 patch.object(bot, 'is_safe_target_url', return_value=True) as safe, \
                 patch.object(bot, '_dc_send_msg_with_stats', side_effect=sent) as send:
                for i in range(240 if repeated else 100):
                    target = dict(url='https://evil.example', type='http')
                    data = dict(req_id='replay' if repeated else str(i), **({'targets': [target]} if batch else target))
                    self.receive(evil, tag, data)
                if not repeated:
                    # Another peer still gets its own ten reservations while Evil is saturated.
                    for i in range(10):
                        target = dict(url='https://honest.example', type='http')
                        self.receive(honest, tag, dict(req_id=str(i), **({'targets': [target]} if batch else target)))
                await asyncio.wait_for(started.wait(), 3)
                self.assertEqual(len(calls), expected)
                self.assertLessEqual(peak['https://evil.example'], 10)
                self.assertEqual(sum(bot._inbound_probes.outstanding.values()), expected)
                self.assertEqual(safe.call_count, expected)  # drops never validate targets
                send.assert_not_called()
                tasks = asyncio.all_tasks() - {asyncio.current_task()}
                gate.set()
                await asyncio.wait_for(asyncio.gather(*tasks), 3)
                self.assertEqual(sum(bot._inbound_probes.outstanding.values()), 0)
            return calls
        return asyncio.run(scenario())

    def test_240_identical_ids_start_one_probe(self):
        self.assertEqual(len(self.flood(repeated=True)), 1)

    def test_distinct_single_requests_bound_outstanding_and_do_not_starve_other_peer(self):
        self.flood()

    def test_batch_requests_use_the_same_admission(self):
        self.flood(batch=True)

    def test_large_batch_reserves_bounded_workers_and_leaves_room_for_another_peer(self):
        async def scenario():
            gate, started = asyncio.Event(), asyncio.Event()
            calls = []

            async def probe(target):
                calls.append(target['url'])
                if len(calls) == 20:
                    started.set()
                await gate.wait()
                return True, None, 1

            evil, honest = self.peer(), self.peer('Honest', 'honest@example.org', 702)
            targets = [dict(url=f'https://evil.example/{i}', type='http') for i in range(100)]
            with patch.object(bot, 'run_single_check', side_effect=probe), \
                 patch.object(bot, 'is_safe_target_url', return_value=True), \
                 patch.object(bot, '_dc_send_msg_with_stats') as send:
                self.receive(evil, 'UPTIME_PEER_CHECK_BATCH_REQ', dict(req_id='large', targets=targets))
                self.receive(evil, 'UPTIME_PEER_CHECK_BATCH_REQ', dict(req_id='excess', targets=targets))
                for i in range(10):
                    self.receive(honest, 'UPTIME_PEER_CHECK_REQ', dict(req_id=str(i), url='https://honest.example', type='http'))
                await asyncio.wait_for(started.wait(), 3)
                self.assertEqual(len(calls), 20)
                self.assertEqual(sum(bot._inbound_probes.outstanding.values()), 20)
                tasks = asyncio.all_tasks() - {asyncio.current_task()}
                self.assertLessEqual(len(tasks), 21)  # 20 workers and one batch coordinator
                gate.set()
                await asyncio.wait_for(asyncio.gather(*tasks), 3)
                self.assertEqual(len(calls), 110)
                self.assertEqual(send.call_count, 11)
                self.assertFalse(bot._inbound_probes.outstanding)
        asyncio.run(scenario())

    def test_failed_multi_slot_reservation_returns_all_slots(self):
        admission = bot.InboundProbeAdmission()
        peers = [dict(email=f'{i}@example.org') for i in range(3)]
        first = admission.acquire(peers[0], 'one', 10)
        second = admission.acquire(peers[1], 'two', 9)
        self.assertIsNone(admission.acquire(peers[2], 'too-large', 2))
        third = admission.acquire(peers[2], 'one-left')
        self.assertIsNotNone(third)
        for reservation in (first, second, third):
            admission.release(reservation)
        self.assertFalse(admission.outstanding)

    def test_single_and_batch_share_replay_identity(self):
        peer = self.peer()
        with patch.object(bot, 'is_safe_target_url', return_value=False):
            self.receive(peer, 'UPTIME_PEER_CHECK_REQ', dict(req_id='same', url='https://example.org', type='http'))
        with patch.object(bot, '_parse_batch_targets') as parse:
            self.receive(peer, 'UPTIME_PEER_CHECK_BATCH_REQ', dict(req_id='same', targets=[{}]))
        parse.assert_not_called()

    def test_rate_window_ttl_cache_bound_and_warning_throttle(self):
        admission, peer = bot.InboundProbeAdmission(), self.peer()
        with patch('bot.time.monotonic', return_value=1000) as clock, self.assertLogs('uptime_bot', 'WARNING') as logs:
            for i in range(120):
                identity = admission.acquire(peer, str(i))
                self.assertIsNotNone(identity)
                admission.release(identity)
            for i in range(20):
                self.assertIsNone(admission.acquire(peer, 'over'))
            self.assertEqual(len(logs.output), 1)
            clock.return_value = 1061
            self.assertIsNone(admission.acquire(peer, '0'))  # replay outlives rate window
            identity = admission.acquire(peer, 'fresh')
            admission.release(identity)
            clock.return_value = 1601
            identity = admission.acquire(peer, '0')
            self.assertIsNotNone(identity)
            admission.release(identity)
            admission.seen = collections.OrderedDict(((str(i), 'id'), 1601) for i in range(10000))
            self.assertIsNone(admission.acquire(peer, 'cache-full'))


class TestPeerNames(AuditCase):
    def test_hello_ack_and_telemetry_cannot_replace_honests_measurement(self):
        evil = self.peer()
        self.peer('Honest', 'honest@example.org', 702)
        url = 'https://example.org'
        database.save_peer_measurement(url, 'Honest', 'down')
        for tag in ('UPTIME_PEER_HELLO', 'UPTIME_PEER_HELLO_ACK'):
            for name in ('Honest', 'hONest', database.get_local_node_name()):
                self.receive(evil, tag, dict(node_name=name))
                self.assertEqual(database.get_peer(evil['email'])['node_name'], 'Evil')
        with patch.object(bot, 'is_safe_target_url', return_value=True):
            self.receive(evil, 'UPTIME_PEER_METRICS', dict(node_name='Honest', metrics=[dict(url=url, type='http', status='up')]))
        rows = {r['node_name']: r for r in database.get_peer_measurements_for_url(url)}
        self.assertEqual(rows['Honest']['status'], 'down')
        self.assertEqual(rows['Evil']['status'], 'up')

    def test_enrollment_and_database_rename_reject_collisions(self):
        self.peer('Honest', 'honest@example.org', 702)
        token = database.create_peer_invite_token()
        with patch.object(bot, '_get_verified_peer_for_msg', return_value=(None, 'new@example.org')), \
             patch.object(bot, '_get_peer_fingerprint', return_value='D' * 40):
            bot.on_new_message(self.client, 1, self.event('UPTIME_PEER_HELLO', dict(node_name='Honest', invite_token=token)))
        enrolled = database.get_peer('new@example.org')
        self.assertIsNotNone(enrolled)
        self.assertNotEqual(enrolled['node_name'].casefold(), 'honest')
        self.assertFalse(database.rename_peer_node('new@example.org', 'Honest'))


class TestKeywordGroups(AuditCase):
    def test_missing_keyword_is_down_in_either_representative_order(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                url = f'https://example.org/{reverse}'
                a = database.add_resource(1, url, 'A', 'http')
                b = database.add_resource(2, url, 'B', 'http', expected_keyword='required-marker')
                group = [database.get_resource_by_id(a), database.get_resource_by_id(b)]
                if reverse:
                    group.reverse()

                async def probe(target, *args, **kwargs):
                    return not bool(target.get('expected_keyword')), 'Missing keyword' if target.get('expected_keyword') else None, 1

                with patch.object(bot, 'check_network_probe', side_effect=probe), \
                     patch.object(bot, 'check_host_internet_connectivity', AsyncMock(return_value=True)), \
                     patch.object(bot, '_peer_cross_check_allowed', AsyncMock(return_value=False)), \
                     patch.object(bot, '_quorum_resource_ids', AsyncMock(return_value=set())), \
                     patch.object(bot, 'check_ssl_expiry', AsyncMock(return_value=(None, None))), \
                     patch.object(bot, 'handle_check_result', AsyncMock()), \
                     patch('bot.asyncio.sleep', AsyncMock()):
                    asyncio.run(bot.check_group_task(group, asyncio.Semaphore(20)))
                self.assertEqual(database.get_resource_by_id(a)['status'], 'up')
                self.assertEqual(database.get_resource_by_id(b)['status'], 'down')
                self.assertNotEqual(bot._cross_check_key(group[0]), bot._cross_check_key(group[1]))
                self.assertEqual(bot._cross_check_key(dict(url=url)), bot._cross_check_key(dict(url=url, expected_keyword='')))


class TestIncidentResolution(AuditCase):
    def test_new_failure_between_snapshot_and_resolution_stays_ongoing(self):
        a = database.add_resource(1, 'https://a.example', 'A', 'http')
        b = database.add_resource(1, 'https://b.example', 'B', 'http')
        database.update_resource_status(a, 'down', 1)
        inc = database.get_active_incident(1)
        database.update_incident_msg_id(inc['id'], 123)
        database.update_resource_status(a, 'up', 0)
        resolve = database.resolve_incident

        def interleaving(*args):
            database.update_resource_status(b, 'down', 1)
            self.assertFalse(resolve(*args))
            return False

        with patch.object(database, 'resolve_incident', side_effect=interleaving), \
             patch.object(bot, '_queue_incident_message') as queue:
            asyncio.run(bot.sync_chat_incident_state(1))
        current = database.get_incident_by_id(1, inc['id'])
        self.assertEqual(current['status'], 'ongoing')
        self.assertIsNone(current['resolved_at'])
        self.assertTrue(database.get_active_incidents_for_chat(1))
        self.assertTrue(all(not call.kwargs.get('resolved') for call in queue.call_args_list))
        database.update_resource_status(b, 'up', 0)
        self.assertTrue(resolve(inc['id']))


class TestMeasurementRetention(AuditCase):
    def test_future_and_old_claims_clamped_and_local_retention_wins(self):
        peer = self.peer()
        database.save_peer_measurements_batch('Evil', [dict(url='https://future.example', status='up', last_checked=2**62)])
        database.save_peer_measurement('https://old.example', 'Evil', 'down', last_checked=-2**62)
        rows = {r['url']: r for r in database.get_all_peer_measurements()}
        self.assertEqual(rows['https://future.example']['last_checked'], 1000060)
        self.assertEqual(rows['https://old.example']['last_checked'], 1000000 - 7 * 86400)
        self.assertTrue(all(r['received_at'] == 1000000 for r in rows.values()))
        self.assertTrue(all(r['source_peer'] == peer['fingerprint'] for r in rows.values()))
        self.clock.return_value += 7 * 86400 + 1
        self.assertEqual(database.cleanup_old_records()['peer_measurements'], 2)

    def test_per_source_quota_survives_rename_and_keeps_other_peer(self):
        self.peer()
        self.peer('Honest', 'honest@example.org', 702)
        database.save_peer_measurement('https://honest.example', 'Honest', 'down')
        for batch in range(6):
            database.save_peer_measurements_batch('Evil', [dict(url=f'https://example.org/{batch}/{i}', status='up') for i in range(200)])
        self.assertTrue(database.rename_peer_node('evil@example.org', 'Renamed'))
        database.save_peer_measurement('https://new.example', 'Renamed', 'up')
        rows = database.get_all_peer_measurements()
        self.assertEqual(sum(r['source_peer'] == 'B' * 40 for r in rows), 1000)
        self.assertEqual(sum(r['node_name'] == 'Honest' for r in rows), 1)
        self.assertNotIn('https://example.org/0/0', {r['url'] for r in rows})

    def test_inactive_mirrored_targets_pruned(self):
        database.save_probe_targets_batch([dict(url='https://stale.example', type='http')], 'evil@example.org')
        self.clock.return_value += 7 * 86400 + 1
        database.save_probe_targets_batch([dict(url='https://active.example', type='http')], 'honest@example.org')
        self.assertEqual(database.cleanup_old_records()['probe_targets'], 1)
        self.assertEqual([r['url'] for r in database.get_active_probe_targets()], ['https://active.example'])

    def test_binding_a_key_moves_the_existing_source_quota(self):
        database.add_or_update_peer('legacy@example.org', 'Legacy', 701)
        database.save_peer_measurement('https://legacy.example', 'Legacy', 'up')
        database.bind_peer_identity('legacy@example.org', fingerprint='A' * 40)
        self.assertEqual(database.get_all_peer_measurements()[0]['source_peer'], 'A' * 40)


class TestRejectedAlerts(AuditCase):
    def incident(self):
        rid = database.add_resource(1, 'https://example.org', 'Example', 'http')
        database.update_resource_status(rid, 'down', 1)
        database.set_chat_report_full(1, 0)
        return database.get_active_incident(1)['id']

    def test_definite_incident_rejection_retries_after_five_minutes_and_caps(self):
        inc = self.incident()
        self.client.rpc.send_msg.side_effect = JsonRpcError('rejected')
        for attempt in range(3):
            with self.assertRaises(JsonRpcError):
                bot._deliver_incident_message(inc, 1, 'Down', False)
            row = database.get_incident_by_id(1, inc)
            self.assertEqual(row['message_attempts'], attempt + 1)
            self.assertEqual(row['message_claimed'], int(attempt == 2))
            bot._deliver_incident_message(inc, 1, 'Down', False)
            self.assertEqual(self.client.rpc.send_msg.call_count, attempt + 1)
            database.close_db()  # retry budget and timestamp survive restart
            self.clock.return_value += 300
        bot._deliver_incident_message(inc, 1, 'Down', False)
        self.assertEqual(self.client.rpc.send_msg.call_count, 3)

    def test_uncertain_incident_error_keeps_claim_and_success_stores_id(self):
        inc = self.incident()
        self.client.rpc.send_msg.side_effect = RuntimeError('transport')
        with self.assertRaises(RuntimeError):
            bot._deliver_incident_message(inc, 1, 'Down', False)
        self.clock.return_value += 600
        bot._deliver_incident_message(inc, 1, 'Down', False)
        self.assertEqual(self.client.rpc.send_msg.call_count, 1)
        self.assertEqual(database.get_incident_by_id(1, inc)['message_claimed'], 1)
        rid = database.add_resource(2, 'https://other.example', 'Other', 'http')
        database.update_resource_status(rid, 'down', 1)
        other = database.get_active_incident(2)['id']
        database.set_chat_report_full(2, 0)
        self.client.rpc.send_msg.side_effect = None
        bot._deliver_incident_message(other, 2, 'Down', False)
        self.assertEqual(database.get_incident_by_id(2, other)['msg_id'], 123)

    def test_partial_start_and_end_retry_caps_and_success(self):
        rid = database.add_resource(1, 'https://partial.example', 'Partial', 'http')
        database.set_chat_report_partial(1, 0)
        votes = json.dumps([dict(node='one', status='down'), dict(node='two', status='up')])
        database.update_resource_alert_state(rid, 'degraded', votes, 999000)
        database.start_partial_outage(rid, 999000, '["one"]')
        partial_id = database.get_partial_outages(rid)[0]['id']
        with patch.object(bot, 'is_node_unstable', return_value=False):
            self.client.rpc.send_msg.side_effect = JsonRpcError('rejected')
            with self.assertRaises(JsonRpcError):
                bot._deliver_degraded_notices(1)
            self.assertEqual(database.get_partial_outages(rid)[0]['notice_state'], 0)
            bot._deliver_degraded_notices(1)
            self.assertEqual(self.client.rpc.send_msg.call_count, 1)
            self.clock.return_value += 300
            self.client.rpc.send_msg.side_effect = None
            bot._deliver_degraded_notices(1)
            self.assertEqual(database.get_partial_outages(rid)[0]['notice_state'], 2)
            database.end_partial_outage(rid, int(self.clock.return_value))
            database.update_resource_alert_state(rid, 'up', votes)
            self.client.rpc.send_msg.side_effect = JsonRpcError('rejected')
            for attempt in range(3):
                with self.assertRaises(JsonRpcError):
                    bot._deliver_degraded_notices(1)
                row = database.get_partial_outages(rid)[0]
                self.assertEqual(row['notice_state'], 3 if attempt == 2 else 2)
                self.assertEqual(row['end_attempts'], attempt + 1)
                self.clock.return_value += 300
            bot._deliver_degraded_notices(1)
            self.assertFalse(database.claim_partial_notice(partial_id, False))

    def test_uncertain_partial_error_keeps_claim(self):
        rid = database.add_resource(1, 'https://partial.example', 'Partial', 'http')
        database.set_chat_report_partial(1, 0)
        database.update_resource_alert_state(rid, 'degraded', '[]', 999000)
        database.start_partial_outage(rid, 999000, '[]')
        self.client.rpc.send_msg.side_effect = TimeoutError('unknown result')
        with self.assertRaises(TimeoutError):
            bot._deliver_degraded_notices(1)
        self.assertEqual(database.get_partial_outages(rid)[0]['notice_state'], 1)
        self.clock.return_value += 600
        bot._deliver_degraded_notices(1)
        self.assertEqual(self.client.rpc.send_msg.call_count, 1)

    def test_partial_start_rejections_exhaust_three_attempts(self):
        rid = database.add_resource(1, 'https://partial.example', 'Partial', 'http')
        database.set_chat_report_partial(1, 0)
        database.update_resource_alert_state(rid, 'degraded', '[]', 999000)
        database.start_partial_outage(rid, 999000, '[]')
        self.client.rpc.send_msg.side_effect = JsonRpcError('rejected')
        for attempt in range(3):
            with self.assertRaises(JsonRpcError):
                bot._deliver_degraded_notices(1)
            row = database.get_partial_outages(rid)[0]
            self.assertEqual(row['start_attempts'], attempt + 1)
            self.assertEqual(row['notice_state'], 1 if attempt == 2 else 0)
            self.clock.return_value += 300
        bot._deliver_degraded_notices(1)
        self.assertEqual(self.client.rpc.send_msg.call_count, 3)


class TestDelayedPin(AuditCase):
    def test_pin_requires_elapsed_time_and_server_delivery_and_retries_failed_lookup(self):
        database.set_chat_report_app(1, 'on')
        database.set_chat_webxdc(1, 400)
        database.set_config('webxdc_app_version:1', str(bot.WEBXDC_APP_VERSION))
        self.client.rpc.get_existing_msg_ids.side_effect = lambda accid, ids: ids
        with patch.object(bot, 'queue_status_app') as queue:
            bot._post_status_line(1, self.client, 1, '')
            msg_id = database.get_chat_webxdc(1)['status_line_msg_id']
            self.assertEqual(database.get_config('webxdc_line_posted_at:1'), '1000000')
            self.client.rpc.get_message.return_value = {'state': MessageState.OUT_DELIVERED}
            self.clock.return_value += 59
            bot._pin_status_line(1, self.client, 1, msg_id)
            self.client.rpc.set_pinned_message_state.assert_not_called()
            self.client.rpc.get_message.assert_not_called()
            self.clock.return_value += 1
            for state in (MessageState.OUT_PENDING, MessageState.OUT_FAILED, 'OutPending'):
                self.client.rpc.get_message.return_value = {'state': state}
                bot._pin_status_line(1, self.client, 1, msg_id)
                self.client.rpc.set_pinned_message_state.assert_not_called()
            self.client.rpc.get_message.side_effect = RuntimeError('offline')
            with self.assertLogs('uptime_bot', 'WARNING'):
                bot._deliver_status_app(1, self.client, 1)
            self.assertEqual(database.get_config('webxdc_pin_pending:1'), str(msg_id))
            self.client.rpc.set_pinned_message_state.assert_not_called()
            database.close_db()
            self.client.rpc.get_message.side_effect = None
            self.client.rpc.get_message.return_value = {'state': 'OutDelivered'}
            self.clock.return_value += 30
            bot._deliver_status_app(1, self.client, 1)
            self.client.rpc.set_pinned_message_state.assert_called_once_with(1, msg_id, True)
            self.assertEqual(database.get_config('webxdc_pin_pending:1'), '')
            queue.assert_called_once_with(1, self.client, 1, known_msg_id=400)
