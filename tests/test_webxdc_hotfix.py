"""Significant status hashes, periodic measurements and cap regressions."""
import copy
import json
import unittest
from unittest.mock import patch

import test_webxdc_status as status_tests
import bot
import database
from outbox import Outbox


class TestWebxdcHotfix(unittest.TestCase):
    setUp = status_tests.TestWebxdcStatus.setUp
    tearDown = status_tests.TestWebxdcStatus.tearDown
    set_fields = status_tests.TestWebxdcStatus.set_fields
    push = status_tests.TestWebxdcStatus.push
    existing = status_tests.TestWebxdcStatus.existing

    def votes(self, latency, status='up', error=None):
        self.set_fields(self.rid, last_votes=json.dumps([
            dict(node='London', status=status, latency_ms=latency, error=error)]))

    def test_volatile_fields_do_not_change_significant_or_line_hash(self):
        self.votes(10)
        state = bot.build_status_state(1)
        for field in ('latency_ms', 'error', 'uptime30', 'generated_at'):
            later = copy.deepcopy(state)
            if field in ('latency_ms', 'error'):
                later['monitors'][0]['nodes'][0][field] = 99 if field == 'latency_ms' else 'Timeout'
            elif field == 'uptime30':
                later['monitors'][0][field] = 98.5
            else:
                later[field] += 60
            with self.subTest(field=field):
                self.assertEqual(bot.status_state_hash(state), bot.status_state_hash(later))
                self.assertEqual(bot._status_line_hash(bot.status_line_text(state)),
                                 bot._status_line_hash(bot.status_line_text(later)))
                if field != 'generated_at':
                    self.assertNotEqual(bot.status_full_state_hash(state), bot.status_full_state_hash(later))

    def test_significant_fields_change_hash(self):
        self.votes(10)
        state = bot.build_status_state(1)
        changes = [
            lambda s: s['monitors'][0]['nodes'][0].update(status='down'),
            lambda s: s['monitors'][0]['nodes'][0].update(node='Paris'),
            *[lambda s, key=key: s['monitors'][0].update({key: 'changed'})
              for key in ('id', 'status', 'name', 'url', 'type', 'since')],
            lambda s: s.update(event_serial=999),
            lambda s: s['events'].append(dict(ts=10001, kind='incident_start', text='Down')),
            lambda s: s['incidents'].append(dict(id=1, status='ongoing')),
            lambda s: s['partial_outages'].append(dict(monitor='Example', started_at=10000)),
            lambda s: s['counts'].update(up=2),
            lambda s: s.update(chat='Renamed'),
            lambda s: s.update(details_omitted=True),
            lambda s: s['monitors'][0].update(details_omitted=True),
        ]
        for index, change in enumerate(changes):
            later = copy.deepcopy(state)
            change(later)
            with self.subTest(change=index):
                self.assertNotEqual(bot.status_state_hash(state), bot.status_state_hash(later))

    def test_refresh_at_1800_only_if_full_state_changed_and_persists(self):
        self.existing()
        self.votes(10)
        self.push()
        database.close_db()
        self.votes(11, error='Transient detail')
        with patch('bot.time.time', return_value=11799):
            self.push()
            bot._deliver_status_app(1, self.client, 1)
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch('bot.time.time', return_value=11800):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        payload = json.loads(self.rpc.send_webxdc_status_update.call_args.args[2])['payload']
        self.assertEqual(payload['monitors'][0]['nodes'][0]['latency_ms'], 11)
        self.rpc.send_edit_request.assert_not_called()
        with patch('bot.time.time', return_value=13600):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)

    def test_volatile_changes_use_no_outbox_tokens_before_refresh(self):
        self.existing()
        self.votes(10)
        self.push()
        self.votes(11)
        ob = Outbox()
        ob._thread = object()
        with patch.object(bot, 'dc_outbox', ob), patch('bot.time.time', return_value=10060):
            self.push()
            self.assertFalse(ob.waiting())

    def test_first_state_bypasses_full_cap_but_later_updates_do_not(self):
        self.existing()
        database.set_config('webxdc_updates:1', json.dumps([9800] * 30))
        self.push()
        self.rpc.send_webxdc_status_update.assert_called_once()
        self.assertEqual(len(json.loads(database.get_config('webxdc_updates:1'))), 31)
        self.votes(12, status='down')
        with patch('bot.time.time', return_value=10060), self.assertLogs('uptime_bot', 'WARNING'):
            self.push()
            bot._deliver_status_app(1, self.client, 1)
        self.rpc.send_webxdc_status_update.assert_called_once()

    def test_zero_update_count_bypasses_cap_even_with_matching_hash(self):
        self.existing()
        self.push()
        database.set_config('webxdc_update_count:1', '0')
        database.set_config('webxdc_updates:1', json.dumps([9800] * 30))
        with patch('bot.time.time', return_value=10060):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        self.assertEqual(database.get_config('webxdc_update_count:1'), '1')

    def test_reposted_instance_gets_first_state_with_full_cap(self):
        self.existing()
        self.push()
        database.set_config('webxdc_updates:1', json.dumps([9800] * 30))
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: [i for i in ids if i != 321]
        with patch('bot.time.time', return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        self.assertEqual(database.get_config('webxdc_update_count:1'), '1')
        self.assertNotEqual(database.get_chat_webxdc(1)['webxdc_msg_id'], 321)
        self.assertEqual(len(json.loads(database.get_config('webxdc_updates:1'))), 31)

    def test_refresh_respects_cap_and_core_interval(self):
        self.existing()
        self.votes(10)
        self.push()
        self.votes(11)
        self.rpc.get_webxdc_info.return_value = {'send_update_interval': 1900000}
        with patch('bot.time.time', return_value=11800):
            self.push()
        self.rpc.send_webxdc_status_update.assert_called_once()
        self.rpc.get_webxdc_info.return_value = {'send_update_interval': 10000}
        database.set_config('webxdc_updates:1', json.dumps([11700] * 30))
        with patch('bot.time.time', return_value=11800), self.assertLogs('uptime_bot', 'WARNING'):
            self.push()
        self.rpc.send_webxdc_status_update.assert_called_once()

    def test_cap_warning_shared_by_scheduler_delivery_and_line_once_per_hour(self):
        self.existing()
        self.push()
        self.set_fields(self.rid, status='down')
        database.set_config('webxdc_updates:1', json.dumps([10000] * 30))
        with patch.object(bot, '_stat_events', bot.collections.defaultdict(bot.collections.deque)):
            with self.assertLogs('uptime_bot', 'WARNING') as logs:
                for now in (10120, 10180, 13720):
                    # Keep the cap full even after the first rolling hour expires.
                    database.set_config('webxdc_updates:1', json.dumps([now - 120] * 30))
                    with patch('bot.time.time', return_value=now):
                        self.push()
                        bot._deliver_status_app(1, self.client, 1)
                        bot._update_status_line(1, self.client, 1)
                        database.close_db()
            self.assertEqual(len(logs.output), 2)
            self.assertTrue(all('Status app update capped in chat 1: 30 attempts in the last hour' in line
                                for line in logs.output))
            self.assertGreater(bot.stat_last_hour('status_app_capped', 13720), 0)
        self.rpc.send_webxdc_status_update.assert_called_once()
        self.rpc.send_edit_request.assert_not_called()

    def test_new_config_keys_deleted_with_chat(self):
        for key in ('webxdc_full_state_hash:1', 'webxdc_cap_warning_at:1'):
            database.set_config(key, 'value')
        database.delete_chat_data(1)
        for key in ('webxdc_full_state_hash:1', 'webxdc_cap_warning_at:1'):
            self.assertIsNone(database.get_config(key))

    def test_sixty_minute_checks_with_one_real_change_send_three_updates(self):
        self.existing()
        sent_at = []
        for minute in range(60):
            self.votes(10 + minute)
            if minute == 15:
                self.set_fields(self.rid, status='down', last_changed=10900)
            before = self.rpc.send_webxdc_status_update.call_count
            with patch('bot.time.time', return_value=10000 + minute * 60):
                self.push()
            if self.rpc.send_webxdc_status_update.call_count != before:
                sent_at.append(minute)
        # Initial snapshot, real change, then a measurement refresh 30 minutes later.
        self.assertEqual(sent_at, [0, 15, 45])
        self.assertEqual(self.rpc.send_edit_request.call_count, 1)
        self.assertEqual(len(json.loads(database.get_config('webxdc_updates:1'))), 4)
