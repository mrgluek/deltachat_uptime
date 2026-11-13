"""Stage 3b retention, rotation, journal and notification regressions."""
import asyncio
import json
import unittest
from unittest.mock import patch

import test_webxdc_status as status_tests
import bot
import database


class TestStage3b(unittest.TestCase):
    setUp = status_tests.TestWebxdcStatus.setUp
    tearDown = status_tests.TestWebxdcStatus.tearDown
    set_fields = status_tests.TestWebxdcStatus.set_fields
    push = status_tests.TestWebxdcStatus.push
    existing = status_tests.TestWebxdcStatus.existing

    def journal(self, kind=None):
        rows = database.get_recent_chat_events(1, 100)
        return [r for r in rows if kind is None or r['kind'] == kind]

    def test_summary_categories_names_limits_and_paused(self):
        state = {'counts': {'up': 83, 'down': 0, 'partial': 0}, 'monitors': []}
        self.assertEqual(bot.status_app_summary(state), '🟢 83 up')
        state['counts'] = {'up': 80, 'down': 2, 'partial': 1}
        state['monitors'] = [dict(status='down', name=n) for n in ('cm.dc09.xyz', 'mail.x')]
        state['monitors'] += [dict(status='partial', name='site'), dict(status='paused', name='paused')]
        self.assertEqual(bot.status_app_summary(state), '🔴 2 down: cm.dc09.xyz, mail.x · 🟠 1 partial: site · 🟢 80 up')
        state['counts']['down'] = 5
        state['monitors'] = [dict(status='down', name=n) for n in ('a', 'b', 'c', 'd', 'e')]
        self.assertIn('5 down: a, b, c +2', bot.status_app_summary(state))
        state['counts'] = dict(up=80, down=5, partial=5)
        state['monitors'] = [dict(status=status, name='longname' * 30) for status in ('down', 'partial') for _ in range(5)]
        summary = bot.status_app_summary(state)
        self.assertLessEqual(len(summary), 120)
        self.assertEqual(summary.count('+2'), 2)
        self.assertIn('…', summary)
        state['counts'] = dict(up=0, down=1, partial=0)
        self.assertIn('longnamelongnamelon…', bot.status_app_summary(state))

    def test_summary_document_descr_and_hash(self):
        self.set_fields(self.rid, status='down')
        self.push()
        args = self.rpc.send_webxdc_status_update.call_args.args
        update = json.loads(args[2])
        self.assertEqual(update['summary'], '🔴 1 down: Example · 🟢 0 up')
        self.assertEqual(update['document'], update['summary'])
        self.assertEqual(args[3], update['summary'])
        state = bot.build_status_state(1)
        original = bot.status_state_hash(state)
        with patch.object(bot, 'status_app_summary', return_value='changed'):
            self.assertNotEqual(original, bot.status_state_hash(state))

    def test_trim_preserves_references_recent_twenty_and_skips_missing(self):
        database.set_chat_webxdc(1, 2)
        inc = database.create_incident(1, 1)
        database.update_incident_msg_id(inc, 3)
        self.rpc.get_chatlist_entries.side_effect = lambda acc, flags, q, c: [10, 11] if flags == 0 else [12]
        self.rpc.get_message_ids.return_value = list(range(1, 51))
        self.rpc.get_message.side_effect = lambda acc, mid: (_ for _ in ()).throw(RuntimeError('missing')) if mid == 4 else {'timestamp': 1}
        self.rpc.delete_messages.side_effect = lambda acc, ids: (_ for _ in ()).throw(RuntimeError('missing')) if 5 in ids else None
        with patch.object(database, 'get_all_peers', return_value=[dict(chat_id=11)]), patch('bot.time.time', return_value=200000):
            deleted = bot.trim_user_chats(self.client, 1)
        self.assertEqual(deleted, 52)  # 26 per non-peer chat, including archived chat.
        for call in self.rpc.delete_messages.call_args_list:
            self.assertFalse({2, 3, *range(31, 51)} & set(call.args[1]))
        self.assertNotIn(11, [c.args[1] for c in self.rpc.get_message_ids.call_args_list])

    def test_trim_stops_at_cutoff_and_contains_failures(self):
        self.rpc.get_chatlist_entries.return_value = [10]
        self.rpc.get_message_ids.return_value = list(range(1, 51))
        self.rpc.get_message.side_effect = lambda acc, mid: {'timestamp': 1 if mid < 6 else 200000}
        with patch('bot.time.time', return_value=200000):
            self.assertEqual(bot.trim_user_chats(self.client, 1), 5)
        self.assertEqual(self.rpc.get_message.call_count, 6)
        self.rpc.get_chatlist_entries.side_effect = RuntimeError('offline')
        with self.assertLogs('uptime_bot', level='WARNING'):
            self.assertEqual(bot.trim_user_chats(self.client, 1), 0)

    def test_trim_bound_and_no_incoming_outgoing_filter(self):
        self.rpc.get_chatlist_entries.return_value = [10, 12]
        self.rpc.get_message_ids.return_value = list(range(1, 4000))
        self.rpc.get_message.return_value = {'timestamp': 1, 'from_id': 42}
        with patch('bot.time.time', return_value=200000):
            self.assertEqual(bot.trim_user_chats(self.client, 1), 2000)
        self.assertEqual(self.rpc.get_message.call_count, 2000)
        self.assertTrue(all(c.args[2:] == (False, False) for c in self.rpc.get_message_ids.call_args_list))

    def test_rotation_by_age(self):
        self.existing()
        database.set_config('webxdc_posted_at:1', '1')
        with patch('bot.time.time', return_value=8 * 86400):
            self.push()
        self.rpc.send_msg.assert_called_once()
        self.assertEqual(database.get_config('webxdc_update_count:1'), '1')
        self.assertEqual(database.get_config('webxdc_posted_at:1'), str(8 * 86400))
        self.rpc.set_pinned_message_state.assert_called_once()
        self.rpc.delete_messages.assert_not_called()

    def test_rotation_by_count_and_hourly_guard(self):
        self.existing()
        database.set_config('webxdc_update_count:1', '500')
        self.push()
        self.rpc.send_msg.assert_not_called()
        self.assertEqual(database.get_config('webxdc_update_count:1'), '501')
        database.set_config('webxdc_reposted_at:1', '9999')
        self.push()
        self.rpc.send_msg.assert_not_called()
        with patch('bot.time.time', return_value=13600):
            self.push()
        self.rpc.send_msg.assert_called_once()
        self.assertEqual(database.get_config('webxdc_update_count:1'), '1')

    def test_dirty_skips_debounce_but_not_core_interval_or_cap(self):
        self.existing()
        self.rpc.get_webxdc_info.return_value = {'send_update_max_size': 128000, 'send_update_interval': 20000}
        self.push()
        database.set_resource_maintenance(1, self.rid, 12000)
        with patch('bot.time.time', return_value=10019):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 1)
        with patch('bot.time.time', return_value=10020):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        database.set_resource_maintenance(1, self.rid, 0)
        database.set_config('webxdc_updates:1', json.dumps([10000] * 30))
        with patch('bot.time.time', return_value=10040):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 2)
        self.assertTrue(bot.status_app_dirty(1))

    def test_monitor_edits_journal_and_dirty_transaction(self):
        self.assertEqual(len(self.journal('monitor_added')), 1)
        self.push()
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET name = 'New', url = 'https://new.example', type = 'tcp' WHERE id = ?", (self.rid,))
        self.assertTrue(bot.status_app_dirty(1))
        self.assertEqual(len(self.journal('monitor_renamed')), 1)
        self.assertEqual(len(self.journal('monitor_changed')), 1)
        database.set_resource_maintenance(1, self.rid, 20000)
        database.set_resource_maintenance(1, self.rid, 0)
        self.assertEqual(len(self.journal('monitor_pause')), 2)
        database.delete_resource(1, self.rid)
        self.assertEqual(len(self.journal('monitor_removed')), 1)

    def test_incident_events_delay_only_mode_recovery_and_dedup(self):
        database.set_chat_report_app(1, 'only')
        database.set_chat_report_full(1, 5)
        with patch('bot.time.time', return_value=10000):
            database.update_resource_status(self.rid, 'down', 1, 'Timeout')
            asyncio.run(bot.sync_chat_incident_state(1))
        self.assertFalse(self.journal('incident_start'))
        with patch('bot.time.time', return_value=10300):
            asyncio.run(bot.sync_chat_incident_state(1))
            asyncio.run(bot.sync_chat_incident_state(1))
        self.assertEqual(len(self.journal('incident_start')), 1)
        with patch('bot.time.time', return_value=10400):
            database.update_resource_status(self.rid, 'up', 0)
            asyncio.run(bot.sync_chat_incident_state(1))
        self.assertEqual(len(self.journal('incident_end')), 1)
        self.rpc.send_msg.assert_not_called()

    def test_short_outage_has_no_journal_alert(self):
        database.set_chat_report_full(1, 5)
        database.update_resource_status(self.rid, 'down', 1)
        asyncio.run(bot.sync_chat_incident_state(1))
        with patch('bot.time.time', return_value=10001):
            database.update_resource_status(self.rid, 'up', 0)
            asyncio.run(bot.sync_chat_incident_state(1))
        self.assertFalse(self.journal('incident_start'))
        self.assertFalse(self.journal('incident_end'))

    def test_partial_events_delay_only_mode_recovery_and_off(self):
        database.set_chat_report_app(1, 'only')
        database.set_chat_report_partial(1, 5)
        database.update_resource_alert_state(self.rid, 'degraded', '[]', 10000)
        database.start_partial_outage(self.rid, 10000, '[]')
        asyncio.run(bot._check_report_notices())
        self.assertFalse(self.journal('partial_start'))
        with patch('bot.time.time', return_value=10300):
            asyncio.run(bot._check_report_notices())
            asyncio.run(bot._check_report_notices())
        self.assertEqual(len(self.journal('partial_start')), 1)
        database.end_partial_outage(self.rid, 10400)
        database.update_resource_alert_state(self.rid, 'up', '[]', 0)
        with patch('bot.time.time', return_value=10400):
            asyncio.run(bot._check_report_notices())
        self.assertEqual(len(self.journal('partial_end')), 1)
        self.rpc.send_msg.assert_not_called()
        database.set_chat_report_partial(1, 'off')
        database.update_resource_alert_state(self.rid, 'degraded', '[]', 10500)
        database.start_partial_outage(self.rid, 10500, '[]')
        with patch('bot.time.time', return_value=11000):
            asyncio.run(bot._check_report_notices())
        self.assertEqual(len(self.journal('partial_start')), 1)

    def test_events_pruned_and_payload_budget_with_twenty_unicode_entries(self):
        database.add_chat_event(1, 'incident_start', 'old', ts=1)
        for i in range(20):
            database.add_chat_event(1, 'incident_end', '🔥' * 200, ts=4000000)
        events = bot.build_status_state(1)['events']
        self.assertEqual(len(events), 20)
        self.assertLessEqual(len(json.dumps(events, ensure_ascii=False, separators=(',', ':')).encode()), 2048)
        self.assertTrue(all(len(e['text']) <= 140 for e in events))
        with patch('database.time.time', return_value=4000000):
            cleaned = database.cleanup_old_records()
        self.assertEqual(cleaned['chat_events'], 1)
        self.assertEqual(len(self.journal('incident_end')), 20)

    def test_info_composition_persistence_and_no_monitor_info(self):
        self.existing()
        self.push()
        self.assertNotIn('info', json.loads(self.rpc.send_webxdc_status_update.call_args.args[2]))
        ids = [database.add_chat_event(1, kind, f'event {i}\nline') for i, kind in enumerate(('incident_start', 'incident_end', 'partial_start', 'partial_end', 'incident_start'))]
        with patch('bot.time.time', return_value=10060):
            self.push()
        update = json.loads(self.rpc.send_webxdc_status_update.call_args.args[2])
        self.assertEqual(update['info'], 'event 0 line | event 1 line | event 2 line | +2 more')
        self.assertEqual(database.get_config('webxdc_last_info_event_id:1'), str(ids[-1]))
        database.close_db()
        database.add_chat_event(1, 'monitor_added', 'added')
        with patch('bot.time.time', return_value=10120):
            self.push()
        self.assertNotIn('info', json.loads(self.rpc.send_webxdc_status_update.call_args.args[2]))

    def test_failed_info_send_is_not_acknowledged(self):
        self.existing()
        database.add_chat_event(1, 'incident_start', 'down')
        self.rpc.send_webxdc_status_update.side_effect = RuntimeError('offline')
        with self.assertLogs('uptime_bot', level='WARNING'):
            self.push()
        self.assertIsNone(database.get_config('webxdc_last_info_event_id:1'))
        self.assertEqual(database.get_config('webxdc_update_count:1'), None)

    def test_immediate_incident_and_partial_events_in_on_mode(self):
        database.set_chat_report_full(1, 0)
        database.update_resource_status(self.rid, 'down', 1)
        asyncio.run(bot.sync_chat_incident_state(1))
        self.assertEqual(len(self.journal('incident_start')), 1)
        second = database.add_resource(1, 'https://second.example', 'Second', 'http')
        database.set_chat_report_partial(1, 0)
        database.update_resource_alert_state(second, 'degraded', '[]', 10000)
        database.start_partial_outage(second, 10000, '[]')
        asyncio.run(bot._check_report_notices())
        self.assertEqual(len(self.journal('partial_start')), 1)

    def test_identical_journal_entries_still_change_hash_and_ids_survive_pruning(self):
        for _ in range(20):
            database.add_chat_event(1, 'incident_start', 'same', ts=1)
        before = bot.status_state_hash(bot.build_status_state(1))
        last = database.add_chat_event(1, 'incident_start', 'same', ts=1)
        self.assertNotEqual(before, bot.status_state_hash(bot.build_status_state(1)))
        with patch('database.time.time', return_value=4000000):
            database.cleanup_old_records()
        next_id = database.add_chat_event(1, 'incident_start', 'new', ts=4000000)
        self.assertGreater(next_id, last)

    def test_journal_migration_is_idempotent(self):
        database.init_db()
        database.init_db()
        database.add_resource(1, 'https://once.example', 'Once', 'http')
        self.assertEqual(sum(r['text'] == '➕ Added monitor Once' for r in self.journal()), 1)

    def test_partial_escalation_never_becomes_a_late_recovery_event(self):
        database.set_chat_report_app(1, 'only')
        database.set_chat_report_partial(1, 0)
        database.update_resource_alert_state(self.rid, 'degraded', '[]', 10000)
        database.start_partial_outage(self.rid, 10000, '[]')
        asyncio.run(bot._check_report_notices())
        self.assertEqual(len(self.journal('partial_start')), 1)
        database.end_partial_outage(self.rid, 10001, notify_end=False)
        database.update_resource_alert_state(self.rid, 'down', '[]')
        asyncio.run(bot._check_report_notices())
        database.update_resource_alert_state(self.rid, 'up', '[]')
        asyncio.run(bot._check_report_notices())
        self.assertFalse(self.journal('partial_end'))
