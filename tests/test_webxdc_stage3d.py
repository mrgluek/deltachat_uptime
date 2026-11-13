"""Pinned status lines, compact names, incident snapshots and app layout."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch, call

import test_webxdc_status as status_tests
import bot
import database
from monitor_names import short_journal_text
from outbox import Outbox


class TestStage3d(unittest.TestCase):
    setUp = status_tests.TestWebxdcStatus.setUp
    tearDown = status_tests.TestWebxdcStatus.tearDown
    set_fields = status_tests.TestWebxdcStatus.set_fields
    push = status_tests.TestWebxdcStatus.push
    existing = status_tests.TestWebxdcStatus.existing

    def test_short_names(self):
        for resource, expected in [
            ({'name': 'https://user:pass@chat.example.net:25/path?q=x#f'}, 'chat.example.net:25'),
            ({'name': '', 'url': 'https://cm.example.cc/path/'}, 'cm.example.cc'),
            ({'url': 'https://cm.example.cc/'}, 'cm.example.cc'),
            ({'url': 'tcp://user:pass@chat.example.net:25/path'}, 'chat.example.net:25'),
            ({'name': ' My custom name ', 'url': 'https://other/'}, 'My custom name'),
            ({}, 'Monitor'),
            ({'name': 'a' * 40}, 'a' * 29 + '…'),
            ({'url': 'https://' + 'ä' * 40 + '.net/path'}, 'ä' * 29 + '…'),
            ({'url': 'https://[2001:db8::1]:443/path'}, '[2001:db8::1]:443'),
        ]:
            with self.subTest(resource=resource):
                self.assertEqual(bot.short_monitor_name(resource), expected)

    def test_counts_only_and_named_line_limits(self):
        state = {'counts': dict(up=53, partial=1, down=2), 'monitors': [
            dict(status='down', name='https://chat.example.net/path'),
            dict(status='down', name='', url='https://chat.example.net:25/a'),
            dict(status='partial', name='https://cm.example.cc/long/path')]}
        self.assertEqual(bot.status_app_summary(state), '🟢 53 up · 🟠 1 partial · 🔴 2 down')
        self.assertEqual(bot.status_line_text(state), '🔴 2 down: chat.example.net, chat.example.net:25 · 🟠 1 partial: cm.example.cc · 🟢 53 up')
        update = json.loads(bot._status_update_json(state, 60000))
        self.assertNotIn('document', update)
        self.assertEqual(update['summary'], bot.status_app_summary(state))
        for status in ('down', 'partial'):
            state['counts'][status] = 9
            state['monitors'] += [dict(status=status, name='x' * 60) for _ in range(9)]
        line = bot.status_line_text(state)
        self.assertLessEqual(len(line), 120)
        self.assertEqual(line.count('+6'), 2)
        self.assertEqual(bot.status_line_text({'counts': dict(up=53, partial=0, down=0)}), '🟢 53 up')
        self.assertEqual(bot.status_app_summary({'counts': dict(up=53, partial=0, down=0)}), '🟢 53 up · 🟠 0 partial · 🔴 0 down')

    def test_order_pins_line_and_persists_after_reopen(self):
        self.push()
        sends = self.rpc.send_msg.call_args_list
        self.assertEqual(len(sends), 2)
        self.assertTrue(sends[0].args[2].file.endswith('status.xdc'))
        self.assertEqual(sends[1].args[2].text, '🟢 1 up')
        self.rpc.set_pinned_message_state.assert_called_once_with(1, 401, True)
        database.close_db()
        saved = database.get_chat_webxdc(1)
        self.assertEqual((saved['webxdc_msg_id'], saved['status_line_msg_id']), (400, 401))
        self.assertEqual(saved['status_line_hash'], bot._status_line_hash('🟢 1 up'))
        database.init_db()  # Additive migration can run repeatedly.
        self.assertEqual(database.get_chat_webxdc(1), saved)

    def test_edit_changed_unchanged_and_shared_cap(self):
        self.existing()
        self.push()
        self.rpc.send_edit_request.assert_not_called()
        self.set_fields(self.rid, status='down')
        with patch('bot.time.time', return_value=10059):
            self.push()
        self.rpc.send_edit_request.assert_not_called()
        with patch('bot.time.time', return_value=10060):
            self.push()
        self.rpc.send_edit_request.assert_called_once_with(1, 322, '🔴 1 down: Example · 🟢 0 up')
        self.assertEqual(len(json.loads(database.get_config('webxdc_updates:1'))), 3)
        with patch('bot.time.time', return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_edit_request.call_count, 1)
        database.set_config('webxdc_updates:1', json.dumps([10060] * 29))
        self.set_fields(self.rid, status='up')
        with patch('bot.time.time', return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 3)
        self.assertEqual(self.rpc.send_edit_request.call_count, 1)  # App used the last slot.
        with patch('bot.time.time', return_value=13661):
            self.push()
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, 3)
        self.assertEqual(self.rpc.send_edit_request.call_count, 2)  # Pending line reconciled alone.

    def test_dirty_edit_bypasses_debounce_respects_core_interval(self):
        self.existing()
        self.push()
        self.rpc.get_webxdc_info.return_value = {'send_update_interval': 20000}
        self.set_fields(self.rid, status='down', name='Renamed')
        with patch('bot.time.time', return_value=10019):
            self.push()
        self.rpc.send_edit_request.assert_not_called()
        with patch('bot.time.time', return_value=10020):
            self.push()
        self.rpc.send_edit_request.assert_called_once_with(1, 322, '🔴 1 down: Renamed · 🟢 0 up')

    def test_missing_line_reposts_and_pins_and_guards_repeat(self):
        self.existing()
        self.push()
        self.set_fields(self.rid, status='down')
        self.rpc.send_edit_request.side_effect = RuntimeError('message gone')
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: [i for i in ids if i == 321]
        with patch('bot.time.time', return_value=10060):
            self.push()
        self.rpc.send_msg.assert_called_once()
        self.assertEqual(self.rpc.send_msg.call_args.args[2].text, '🔴 1 down: Example · 🟢 0 up')
        self.rpc.set_pinned_message_state.assert_any_call(1, 400, True)
        self.set_fields(self.rid, status='up')
        with patch('bot.time.time', return_value=10120):
            self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 1)

    def test_ambiguous_edit_failure_does_not_repost(self):
        self.existing()
        self.push()
        self.set_fields(self.rid, status='down')
        self.rpc.send_edit_request.side_effect = RuntimeError('offline')
        with patch('bot.time.time', return_value=10060), self.assertLogs('uptime_bot', level='WARNING'):
            self.push()
        self.rpc.send_msg.assert_not_called()
        self.assertEqual(database.get_chat_webxdc(1)['status_line_hash'], bot._status_line_hash('🟢 1 up'))
        with patch('bot.time.time', return_value=10090):
            self.push()
        self.assertEqual(self.rpc.send_edit_request.call_count, 1)

    def test_rotation_and_v1_migration_unpin_old_messages(self):
        for migrate in (False, True):
            with self.subTest(migrate=migrate):
                self.existing()
                database.set_config('webxdc_reposted_at:1', '1')
                if migrate:
                    database.set_config('webxdc_app_version:1', '1')
                    database.set_chat_status_line(1, None, None)
                else:
                    database.set_config('webxdc_update_count:1', '501')
                self.rpc.reset_mock()
                self.push()
                self.assertEqual(self.rpc.send_msg.call_count, 2)
                saved = database.get_chat_webxdc(1)
                self.rpc.set_pinned_message_state.assert_any_call(1, saved['status_line_msg_id'], True)
                self.rpc.set_pinned_message_state.assert_any_call(1, 321, False)
                if not migrate:
                    self.rpc.set_pinned_message_state.assert_any_call(1, 322, False)
                self.assertNotIn(call(1, saved['webxdc_msg_id'], True), self.rpc.set_pinned_message_state.call_args_list)
                self.push()
                self.assertEqual(self.rpc.send_msg.call_count, 2)

    def test_trim_exempts_line(self):
        self.existing()
        self.rpc.get_chatlist_entries.return_value = [10]
        self.rpc.get_message_ids.return_value = [321, 322] + list(range(1, 25))
        self.rpc.get_message.return_value = {'timestamp': 1}
        with patch('bot.time.time', return_value=200000):
            bot.trim_user_chats(self.client, 1)
        for args in self.rpc.delete_messages.call_args_list:
            self.assertFalse({321, 322} & set(args.args[1]))

    def test_info_counts_voters_and_compacts_historical_journal(self):
        votes = [{'node': 'flag' + str(i), 'status': 'down' if i < 5 else 'up'} for i in range(8)]
        votes.append({'node': 'abstention', 'status': 'unknown'})
        resource = dict(name='https://user:pass@cm.example.cc/path', last_votes=json.dumps(votes))
        self.assertEqual(bot._journal_outage_text(resource, '🔴'), '🔴 cm.example.cc is down (5 of 8 nodes)')
        self.assertEqual(bot._journal_outage_text(resource, '🟠'), '🟠 cm.example.cc is partially down (5 of 8 nodes)')
        self.assertEqual(bot._journal_outage_text(resource, '', 300), '✅ cm.example.cc recovered after 5m')
        self.assertEqual(bot._journal_outage_text({'url': 'https://a/'}, '🔴'), '🔴 a is down')
        self.set_fields(self.rid, name=resource['name'], last_votes=resource['last_votes'])
        database.add_chat_event(1, 'incident_start', resource['name'] + ' is down (nodes: flag0, flag1)')
        self.assertEqual(database.get_recent_chat_events(1)[0]['text'], 'cm.example.cc is down')
        database.add_resource(1, 'https://empty-name.example/path', '', 'http')
        self.assertEqual(database.get_recent_chat_events(1)[0]['text'], '➕ Added monitor empty-name.example')
        text = short_journal_text('➖ Removed monitor ' + 'a' * 60)
        self.assertEqual(text, '➖ Removed monitor ' + 'a' * 29 + '…')
        self.assertEqual(bot.status_app_info([{'text': 'a'}, {'text': 'b'}, {'text': 'c'}, {'text': 'd'}]), 'a | b | c | +1 more')

    def test_payload_incidents_partials_and_budget_priority(self):
        self.set_fields(self.rid, name='https://example.org/long/path')
        incident = database.create_incident(1, 9000)
        database.update_resource_status(self.rid, 'down', 1)
        self.assertTrue(database.get_incident_downtime_events(incident))
        database.start_partial_outage(self.rid, 9200, '[]')
        state = bot.build_status_state(1)
        self.assertEqual(state['incidents'][0]['names'], ['example.org'])
        self.assertEqual(state['incidents'][0]['count'], 1)
        self.assertEqual(state['partial_outages'][0], dict(monitor='example.org', started_at=9200, ended_at=None))
        state['partial_outages'][0]['monitor'] = '🔥' * 30000
        update = json.loads(bot._status_update_json(copy.deepcopy(state), 60000))
        self.assertTrue(update['payload']['partial_outages_omitted'])
        self.assertTrue(update['payload']['incidents'])
        state['incidents'] *= 20
        state['events'] *= 20
        encoded = bot._status_update_json(state, 1200)
        self.assertLessEqual(len(encoded.encode()), 1200)
        self.assertTrue(state['incidents_omitted'])
        self.assertTrue(state['events_omitted'])
        self.assertFalse(state.get('details_omitted', False))

    def test_legacy_column_migration(self):
        with database._writer_transaction() as conn:
            conn.execute("ALTER TABLE chats DROP COLUMN status_line_msg_id")
            conn.execute("ALTER TABLE chats DROP COLUMN status_line_hash")
        database.init_db()
        saved = database.get_chat_webxdc(1)
        self.assertIsNone(saved['status_line_msg_id'])
        self.assertIsNone(saved['status_line_hash'])
        database.init_db()

    def test_new_long_renames_keep_both_short_labels(self):
        self.set_fields(self.rid, name='a' * 200)
        self.set_fields(self.rid, name='b' * 200)
        renamed = next(e for e in database.get_recent_chat_events(1) if e['kind'] == 'monitor_renamed')
        self.assertEqual(renamed['text'], '✏️ Renamed monitor ' + 'a' * 29 + '… to ' + 'b' * 29 + '…')

    def test_queued_line_post_rechecks_mode_and_ambiguous_failure_is_guarded(self):
        ob = Outbox()
        ob._thread = object()
        with patch.object(bot, 'dc_outbox', ob):
            self.push()
            with ob._cond:
                job = ob._next_job()
            ob._run(job)  # App posted, line queued with its own mail token.
            self.assertEqual(self.rpc.send_msg.call_count, 1)
            database.set_chat_report_app(1, 'off')
            with ob._cond:
                job = ob._next_job()
            ob._run(job)
        self.assertEqual(self.rpc.send_msg.call_count, 1)
        database.set_chat_report_app(1, 'on')
        self.rpc.send_msg.side_effect = RuntimeError('offline')
        with self.assertLogs('uptime_bot', level='WARNING'):
            self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)
        self.push()
        self.assertEqual(self.rpc.send_msg.call_count, 2)

    def test_incident_and_partial_payload_limits_and_dates(self):
        with patch('bot.time.time', return_value=4000000):
            old = database.create_incident(1, 1)
            database.resolve_incident(old, 2)
            for i in range(25):
                database.create_incident(1, 3990000 + i)
            incident = database.get_recent_incidents(1, 1)[0]['id']
            for i in range(7):
                rid = database.add_resource(1, f'https://node{i}.example/path', '', 'http')
                database.update_resource_status(rid, 'down', 1)
                # All concurrent failures belong to the same ongoing incident.
                for event in database.get_unlinked_open_downtime_events(1):
                    database.link_downtime_event_to_incident(event['id'], incident)
            for i in range(12):
                database.start_partial_outage(self.rid, 3995000 + i * 2, '[]')
                database.end_partial_outage(self.rid, 3995001 + i * 2)
            state = bot.build_status_state(1)
        self.assertEqual(len(state['incidents']), 20)
        self.assertEqual(state['incidents'][0]['count'], 7)
        self.assertEqual(len(state['incidents'][0]['names']), 5)
        self.assertEqual(len(state['partial_outages']), 10)
        self.assertGreater(state['incidents'][0]['started_at'], state['incidents'][-1]['started_at'])
        self.assertGreater(state['partial_outages'][0]['started_at'], state['partial_outages'][-1]['started_at'])

    def test_html_structure_and_live_filter_without_searching_nodes(self):
        source = (Path(bot.__file__).parent / 'webxdc/index.html').read_text()
        for token in ('id="filter"', 'id="clear"', 'Incidents', 'Partial outages', 'Recent events', '<h1>Uptime Status</h1>'):
            self.assertIn(token, source)
        self.assertNotIn('innerHTML', source)
        if not shutil.which('node'):
            return
        script = source.split('<script>')[1].split('</script>')[0]
        harness = '''const assert = require('assert');
const nodes = new Map();
function node() { return {textContent:'', value:'', hidden:false, children:[], listeners:{},
  append(...items) { this.children.push(...items); }, replaceChildren() { this.children=[]; },
  addEventListener(name, cb) { this.listeners[name]=cb; }}; }
global.document = {getElementById(id) { if (!nodes.has(id)) nodes.set(id,node()); return nodes.get(id); }, createElement:node};
global.window = {};
'''
        checks = '''
render({monitors:[{id:1,name:'Mail',url:'https://Example.net/a',status:'down',nodes:[{node:'NODEONLY'}]},
{id:2,name:'Other',url:'https://other',status:'up'}],counts:{down:1,up:1},generated_at:10000});
const filter=document.getElementById('filter');
filter.value='EXAMPLE'; filter.listeners.input();
assert.equal(document.getElementById('filtered').textContent, '1 of 2');
assert.equal(document.getElementById('monitors').children.length,1);
filter.value='NODEONLY'; filter.listeners.input();
assert.equal(document.getElementById('filtered').textContent, '0 of 2');
document.getElementById('clear').listeners.click();
assert.equal(document.getElementById('monitors').children.length,2);
assert.equal(document.getElementById('journal').hidden,true);
assert.equal(document.getElementById('incidents-section').hidden,true);
assert.equal(document.getElementById('partials-section').hidden,true);
'''
        result = subprocess.run(['node', '-e', harness + script + checks], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
