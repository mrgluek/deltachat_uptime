import os
import sys
import unittest
import time
import datetime
import asyncio
import sqlite3
from unittest.mock import MagicMock, patch, ANY

# Setup test environment
TEST_DB = "test_uptime.db"
os.environ["DB_PATH"] = TEST_DB

# Mock packages if not installed
try:
    import deltachat2
except ImportError:
    mock_deltachat2 = MagicMock()
    class MsgData:
        def __init__(self, text="", file="", override_sender_name=None):
            self.text = text
            self.file = file
            self.override_sender_name = override_sender_name
    mock_deltachat2.MsgData = MsgData
    sys.modules['deltachat2'] = mock_deltachat2

try:
    import deltabot_cli
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
        def start(self):
            pass
    mock_deltabot_cli = MagicMock()
    mock_deltabot_cli.BotCli = MockBotCli
    sys.modules['deltabot_cli'] = mock_deltabot_cli

try:
    import emoji
except ImportError:
    sys.modules['emoji'] = MagicMock()

# Add parent directory to sys.path so we can import database and bot
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
import bot

class TestUptimeBot(unittest.TestCase):
    def setUp(self):
        database.DB_PATH = TEST_DB
        database.init_db()

    def tearDown(self):
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except OSError:
                pass
        # Clean WAL and shared memory files if they exist
        for suffix in ["-wal", "-shm"]:
            fpath = TEST_DB + suffix
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    def test_parse_target(self):
        # 1. HTTP/HTTPS targets
        self.assertEqual(bot.parse_target("http://google.com"), ("http", "http://google.com"))
        self.assertEqual(bot.parse_target("https://my-app.info/health"), ("http", "https://my-app.info/health"))
        
        # 2. TCP targets
        self.assertEqual(bot.parse_target("127.0.0.1:8080"), ("tcp", "127.0.0.1:8080"))
        self.assertEqual(bot.parse_target("gluek.info:22"), ("tcp", "gluek.info:22"))
        
        # 3. Ping targets
        self.assertEqual(bot.parse_target("gluek.info"), ("ping", "gluek.info"))
        self.assertEqual(bot.parse_target("8.8.8.8"), ("ping", "8.8.8.8"))
        
        # 4. Invalid targets
        with self.assertRaises(ValueError):
            bot.parse_target("")
        with self.assertRaises(ValueError):
            bot.parse_target("invalid target name with spaces")
        with self.assertRaises(ValueError):
            bot.parse_target("gluek.info:invalidport")

    def test_format_duration(self):
        self.assertEqual(bot.format_duration(45), "45s")
        self.assertEqual(bot.format_duration(90), "1m 30s")
        self.assertEqual(bot.format_duration(3665), "1h 1m")

    def test_database_chat_tokens(self):
        chat_id_1 = 12345
        chat_id_2 = 67890
        
        # Generating and retrieving tokens
        token_1 = database.get_or_create_chat_token(chat_id_1)
        self.assertEqual(len(token_1), 12)
        
        # Retrieve again -> should be the same
        self.assertEqual(database.get_or_create_chat_token(chat_id_1), token_1)
        
        # Generating for chat 2 -> should be different
        token_2 = database.get_or_create_chat_token(chat_id_2)
        self.assertNotEqual(token_1, token_2)
        
        # Mapping token back to chat ID
        self.assertEqual(database.get_chat_id_by_token(token_1), chat_id_1)
        self.assertEqual(database.get_chat_id_by_token(token_2), chat_id_2)
        self.assertIsNone(database.get_chat_id_by_token("nonexistent"))

    def test_database_resources(self):
        chat_id = 999
        
        # Add resource
        r_id = database.add_resource(chat_id, "https://gluek.info", "Gluek Main Page", "http")
        self.assertIsNotNone(r_id)
        
        # Add duplicate resource -> should fail and return None
        dup_id = database.add_resource(chat_id, "https://gluek.info", "Gluek Dup", "http")
        self.assertIsNone(dup_id)
        
        # Retrieve resources for chat
        res = database.get_resources(chat_id)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["id"], r_id)
        self.assertEqual(res[0]["name"], "Gluek Main Page")
        self.assertEqual(res[0]["status"], "unknown")
        
        # Retrieve all resources
        all_res = database.get_all_resources()
        self.assertIn(r_id, [r["id"] for r in all_res])
        
        # Delete resource
        deleted = database.delete_resource(chat_id, r_id)
        self.assertTrue(deleted)
        
        # Retrieve again -> should be empty
        self.assertEqual(len(database.get_resources(chat_id)), 0)

    def test_uptime_math(self):
        chat_id = 888
        now = int(time.time())
        
        # Add resource
        r_id = database.add_resource(chat_id, "https://google.com", "Google Test", "http")
        self.assertIsNotNone(r_id)
        
        # Override SQLite DEFAULT created_at constraint manually for tracking duration
        conn = database.sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("UPDATE resources SET created_at = ? WHERE id = ?", (now - 200, r_id))
        conn.commit()
        conn.close()
        
        # Case 1: Brand new resource with no downtime has 100% uptime
        with patch('time.time', return_value=now):
            self.assertEqual(database.get_resource_uptime_30d(r_id), 100.0)
        
        # Case 2: Transition to DOWN 100 seconds ago, and still DOWN
        with patch('time.time', return_value=now - 100):
            database.update_resource_status(r_id, "down", 1)
            
        # Overall uptime should be less than 100.0%
        with patch('time.time', return_value=now):
            uptime = database.get_resource_uptime_30d(r_id)
            self.assertTrue(0.0 <= uptime < 100.0)
            
        # Case 3: Transition to UP 50 seconds ago (recovered)
        with patch('time.time', return_value=now - 50):
            database.update_resource_status(r_id, "up", 0)
            
        with patch('time.time', return_value=now):
            # Total tracking time is 200s (now - created_at).
            # Downtime was from now-100 to now-50 (50s).
            # Uptime should be (200 - 50) / 200 = 75.0%
            uptime = database.get_resource_uptime_30d(r_id)
            self.assertAlmostEqual(uptime, 75.0, places=1)

    @patch('bot._is_dc_admin')
    @patch('bot._dc_send_msg_with_stats')
    def test_url_command(self, mock_send_with_stats, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.payload = "https://up.gluek.info"
        
        bot.url_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_config("base_url"), "https://up.gluek.info")

    @patch('bot._is_dc_admin')
    @patch('bot._dc_send_msg_with_stats')
    def test_resilient_command(self, mock_send_with_stats, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg = MagicMock()
        mock_event.msg.from_id = 123
        mock_event.msg.chat_id = 456

        # Case 1: Status query when disabled
        database.set_config("resilient", "0")
        mock_event.payload = ""
        bot.resilient_command(mock_bot, 1, mock_event)
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("currently disabled", args[3].text)

        # Case 2: Turn ON with /resilient on
        mock_event.payload = "on"
        bot.resilient_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_config("resilient"), "1")
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("Resilient sending mode enabled", args[3].text)

        # Case 3: Status query when enabled
        mock_event.payload = ""
        bot.resilient_command(mock_bot, 1, mock_event)
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("currently enabled", args[3].text)

        # Case 4: Turn OFF with /resilient off
        mock_event.payload = "off"
        bot.resilient_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_config("resilient"), "0")
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("Resilient sending mode disabled", args[3].text)

    @patch('bot._is_dc_admin')
    @patch('bot._dc_send_msg_with_stats')
    def test_transports_command_with_resilient_mode(self, mock_send_with_stats, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_bot.rpc.list_transports.return_value = [
            {"addr": "uptimebot@chatmail.uk"},
            {"addr": "uptimebot@chat.gluek.info"}
        ]
        mock_bot.rpc.get_config.return_value = "uptimebot@chatmail.uk"
        mock_bot.rpc.get_connectivity.return_value = 3000
        mock_bot.rpc.get_connectivity_html.return_value = '<div class="green dot"><b>chatmail.uk:</b> Connected</div><div class="green dot"><b>chat.gluek.info:</b> Connected</div>'

        mock_event = MagicMock()
        mock_event.msg.from_id = 123
        mock_event.msg.chat_id = 456

        # Scenario 1: Resilient mode OFF -> only active/primary has "✔︎ Used for sending:"
        database.set_config("resilient", "0")
        bot.transports_command(mock_bot, 1, mock_event)
        text = mock_send_with_stats.call_args[0][3].text
        self.assertIn("🔌 **Mail Relays (Transports)**", text)
        self.assertIn("**🔄 Working** ✔︎ Used for sending: `uptimebot@chatmail.uk`", text)
        self.assertIn("**🔄 Working**: `uptimebot@chat.gluek.info`", text)

        # Scenario 2: Resilient mode ON -> BOTH transports have "✔︎ Used for sending:"
        database.set_config("resilient", "1")
        bot.transports_command(mock_bot, 1, mock_event)
        text_resilient = mock_send_with_stats.call_args[0][3].text
        self.assertIn("**🔄 Working** ✔︎ Used for sending: `uptimebot@chatmail.uk`", text_resilient)
        self.assertIn("**🔄 Working** ✔︎ Used for sending: `uptimebot@chat.gluek.info`", text_resilient)

    def test_setup_resilient_mode_sends_to_all_transports(self):
        mock_bot = MagicMock()
        mock_bot.rpc.send_msg.return_value = 999
        mock_bot.rpc.list_transports.return_value = [
            {"addr": "primary@example.com"},
            {"addr": "backup@example.com"}
        ]
        mock_bot.rpc.get_config.side_effect = lambda accid, key: "primary@example.com" if key in ("configured_addr", "addr") else None
        mock_bot.rpc.get_message.return_value = {"state": 26}

        bot._setup_resilient_mode(mock_bot)

        # Resilient mode enabled
        database.set_config("resilient", "1")

        msg_data = deltachat2.MsgData(text="Test message")
        
        with patch('time.sleep', return_value=None):
            res_id = mock_bot.rpc.send_msg(1, 100, msg_data)
            self.assertEqual(res_id, 999)
            time.sleep(0.2)

        # Verify resend_messages was called for backup transport
        mock_bot.rpc.resend_messages.assert_called_with(1, [999])

    @patch('bot._is_dc_admin')
    @patch('bot._dc_send_msg_with_stats')
    def test_sync_command_and_rate_limit(self, mock_send_with_stats, mock_is_admin):
        chat_id = 777
        mock_bot = MagicMock()
        mock_chat_info = MagicMock()
        mock_chat_info.chat_type = "Group"
        mock_bot.rpc.get_basic_chat_info.return_value = mock_chat_info
        
        # Add some initial resources
        database.add_resource(chat_id, "https://google.com", "Google", "http")
        database.add_resource(chat_id, "8.8.8.8", "DNS", "ping")
        
        # Clear rate-limiting cache for this test
        bot.last_sync_times.clear()
        
        # Scenario 1: First sync trigger by non-admin should work
        mock_is_admin.return_value = False
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.from_id = 999  # Non-admin
        
        bot.sync_command(mock_bot, 1, mock_event)
        
        # Verify message sent with sync data
        self.assertTrue(mock_send_with_stats.called)
        sent_data = mock_send_with_stats.call_args[0][3]
        self.assertIn("[UPTIME_BOT_SYNC_DATA]", sent_data.text)
        self.assertIn("https://google.com", sent_data.text)
        self.assertIn("8.8.8.8", sent_data.text)
        
        # Reset mock
        mock_send_with_stats.reset_mock()
        
        # Scenario 2: Second sync trigger by non-admin immediately should be rate-limited
        bot.sync_command(mock_bot, 1, mock_event)
        self.assertTrue(mock_send_with_stats.called)
        sent_data = mock_send_with_stats.call_args[0][3]
        self.assertIn("rate-limited", sent_data.text)
        
        # Reset mock
        mock_send_with_stats.reset_mock()
        
        # Scenario 3: Admin trigger immediately after should bypass rate limit
        mock_is_admin.return_value = True
        admin_event = MagicMock()
        admin_event.msg.chat_id = chat_id
        admin_event.msg.from_id = 111  # Admin
        
        bot.sync_command(mock_bot, 1, admin_event)
        self.assertTrue(mock_send_with_stats.called)
        sent_data = mock_send_with_stats.call_args[0][3]
        self.assertIn("[UPTIME_BOT_SYNC_DATA]", sent_data.text)

    @patch('bot._dc_send_msg_with_stats')
    def test_sync_parsing_in_on_new_message(self, mock_send_with_stats):
        chat_id = 888
        mock_bot = MagicMock()
        
        # Create a mock event representing a sync payload from another bot
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.from_id = 555  # From another bot (not 1)
        mock_event.msg.is_info = False
        
        sync_payload = (
            "🔄 **Uptime Bot Synchronization**\n"
            "[UPTIME_BOT_SYNC_DATA]\n"
            '[{"url": "https://new-resource.org", "name": "New Resource", "type": "http", "interval": 60}]\n'
            "[/UPTIME_BOT_SYNC_DATA]"
        )
        mock_event.msg.text = sync_payload
        
        # Trigger on_new_message
        bot.on_new_message(mock_bot, 1, mock_event)
        
        # Verify it was added to database
        resources = database.get_resources(chat_id)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["url"], "https://new-resource.org")
        self.assertEqual(resources[0]["name"], "New Resource")
        self.assertEqual(resources[0]["type"], "http")
        
        # Verify sync complete message was sent
        self.assertTrue(mock_send_with_stats.called)
        sent_data = mock_send_with_stats.call_args[0][3]
        self.assertIn("Sync Complete!", sent_data.text)
        self.assertIn("new-resource.org", sent_data.text)
        
        # Reset database and mock
        database.delete_resource(chat_id, resources[0]["id"])
        mock_send_with_stats.reset_mock()
        
        # Scenario: Message sent by self (from_id == 1) should be ignored
        mock_event_self = MagicMock()
        mock_event_self.msg.chat_id = chat_id
        mock_event_self.msg.from_id = 1  # Self
        mock_event_self.msg.is_info = False
        mock_event_self.msg.text = sync_payload
        
        bot.on_new_message(mock_bot, 1, mock_event_self)
        
        # Verify nothing was added
        self.assertEqual(len(database.get_resources(chat_id)), 0)
        self.assertFalse(mock_send_with_stats.called)

    @patch('bot._dc_send_msg_with_stats')
    def test_sync_validation_security(self, mock_send_with_stats):
        chat_id = 999
        mock_bot = MagicMock()
        
        # Test 1: Malicious interval (1s) should be forced to 60s
        # Test 2: Invalid URL should be skipped
        # Test 3: Mismatched type (google.com http) should be skipped (since google.com is ping, not http)
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.from_id = 555
        mock_event.msg.is_info = False
        
        sync_payload = (
            "🔄 **Uptime Bot Synchronization**\n"
            "[UPTIME_BOT_SYNC_DATA]\n"
            '['
            '  {"url": "https://valid-target.org", "name": "Valid", "type": "http", "interval": 1},'
            '  {"url": "invalid-url-here", "name": "Invalid URL", "type": "http", "interval": 60},'
            '  {"url": "google.com", "name": "Mismatched Type", "type": "http", "interval": 60}'
            ']\n'
            "[/UPTIME_BOT_SYNC_DATA]"
        )
        mock_event.msg.text = sync_payload
        
        bot.on_new_message(mock_bot, 1, mock_event)
        
        # Verify only the valid target was added
        resources = database.get_resources(chat_id)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["url"], "https://valid-target.org")
        
        # Verify interval was forced to 60 (not 1)
        self.assertEqual(resources[0]["interval"], 60)
        
        # Clean up database
        database.delete_resource(chat_id, resources[0]["id"])

    @patch.dict('os.environ', {
        'DISPLAY_NAME': 'Custom Bot Name',
        'STATUS_TEXT': 'Custom status info text',
        'AVATAR_PATH': 'custom_icon.png'
    })
    @patch('os.path.exists')
    def test_profile_customization(self, mock_exists):
        mock_exists.side_effect = lambda path: 'custom_icon.png' in path or 'icon.png' in path
        
        mock_bot = MagicMock()
        mock_bot.rpc.get_all_account_ids.return_value = [1]
        
        # Trigger on_init
        bot.on_init(mock_bot, [])
        
        # Verify set_config calls
        calls = mock_bot.rpc.set_config.call_args_list
        config_dict = {call[0][1]: call[0][2] for call in calls}
        
        self.assertEqual(config_dict.get("displayname"), "Custom Bot Name")
        self.assertEqual(config_dict.get("selfstatus"), "Custom status info text")
        self.assertTrue(config_dict.get("selfavatar").endswith("custom_icon.png"))

    def test_is_group_chat(self):
        # 1. Test dictionary format
        self.assertFalse(bot.is_group_chat({"type": 1}))
        self.assertTrue(bot.is_group_chat({"type": 2}))
        self.assertTrue(bot.is_group_chat({"type": 3}))
        self.assertFalse(bot.is_group_chat({"chat_type": "Single"}))
        self.assertTrue(bot.is_group_chat({"chat_type": "Group"}))
        self.assertFalse(bot.is_group_chat({}))

        # 2. Test object format
        class MockChat:
            def __init__(self, c_type=None, chat_type=None):
                if c_type is not None:
                    self.type = c_type
                if chat_type is not None:
                    self.chat_type = chat_type
                    
        self.assertFalse(bot.is_group_chat(MockChat(c_type=1)))
        self.assertTrue(bot.is_group_chat(MockChat(c_type=2)))
        self.assertFalse(bot.is_group_chat(MockChat(chat_type="Single")))
        self.assertTrue(bot.is_group_chat(MockChat(chat_type="Group")))
        self.assertFalse(bot.is_group_chat(MockChat()))

    def test_user_agent_header(self):
        self.assertEqual(
            bot.USER_AGENT,
            f"DeltaChat-Uptime-Bot/{bot.VERSION} (https://git.gluek.info/gluek/deltachat_uptime)"
        )
        self.assertIn("DeltaChat-Uptime-Bot/", bot.USER_AGENT)

    def test_database_ssl_fields(self):
        chat_id = 777
        r_id = database.add_resource(chat_id, "https://ssl-test.org", "SSL Site", "http")
        self.assertIsNotNone(r_id)
        
        # Initial SSL fields should be None / default
        res = database.get_resources(chat_id)
        self.assertEqual(len(res), 1)
        self.assertIsNone(res[0]["ssl_expiry_date"])
        self.assertIsNone(res[0]["ssl_last_checked"])
        self.assertEqual(res[0]["ssl_alert_state"], 0)
        
        # Update SSL info
        now_ts = int(time.time())
        exp_ts = now_ts + 86400 * 30
        database.update_resource_ssl(r_id, exp_ts, now_ts, 7)
        
        res = database.get_resources(chat_id)
        self.assertEqual(res[0]["ssl_expiry_date"], exp_ts)
        self.assertEqual(res[0]["ssl_last_checked"], now_ts)
        self.assertEqual(res[0]["ssl_alert_state"], 7)
        
        # Update alert state only
        database.update_ssl_alert_state(r_id, 3)
        res = database.get_resources(chat_id)
        self.assertEqual(res[0]["ssl_alert_state"], 3)

    def test_check_ssl_expiry(self):
        import datetime
        mock_cert = {"notAfter": "Aug 20 12:00:00 2026 GMT"}
        expected_dt = datetime.datetime(2026, 8, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        expected_ts = int(expected_dt.timestamp())
        
        mock_ssl_obj = MagicMock()
        mock_ssl_obj.getpeercert.return_value = mock_cert
        
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = mock_ssl_obj
        mock_writer.wait_closed = MagicMock()
        
        # Async coroutine for open_connection
        async def mock_open_conn(*args, **kwargs):
            return MagicMock(), mock_writer
            
        with patch('asyncio.open_connection', side_effect=mock_open_conn):
            import asyncio
            ts, err = asyncio.run(bot.check_ssl_expiry("https://valid-ssl.com"))
            self.assertEqual(ts, expected_ts)
            self.assertIsNone(err)

    def test_check_ssl_expiry_errors(self):
        import ssl
        import asyncio
        
        # 1. Invalid hostname
        ts, err = asyncio.run(bot.check_ssl_expiry("http://"))
        self.assertIsNone(ts)
        self.assertIn("Invalid hostname", err)
        
        # 2. SSLCertVerificationError
        async def mock_ssl_err(*args, **kwargs):
            raise ssl.SSLCertVerificationError("certificate has expired")
            
        with patch('asyncio.open_connection', side_effect=mock_ssl_err):
            ts, err = asyncio.run(bot.check_ssl_expiry("https://expired.org"))
            self.assertIsNone(ts)
            self.assertIn("SSL verification error", err)
            
        # 3. TimeoutError
        async def mock_timeout(*args, **kwargs):
            raise asyncio.TimeoutError()
            
        with patch('asyncio.open_connection', side_effect=mock_timeout):
            ts, err = asyncio.run(bot.check_ssl_expiry("https://timeout.org"))
            self.assertIsNone(ts)
            self.assertIn("SSL check timeout", err)

    def test_ssl_alert_transitions_and_renewal(self):
        import asyncio
        chat_id = 54321
        r_id = database.add_resource(chat_id, "https://monitored-site.com", "My Site", "http")
        
        # Mock bot instance for notifications
        mock_bot = MagicMock()
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1
        
        now = int(time.time())
        semaphore = asyncio.Semaphore(10)
        
        # Helper to run check_group_task
        def run_group_check(expiry_offset_days):
            fake_exp = now + int(expiry_offset_days * 86400)
            mock_cert = {"notAfter": datetime.datetime.fromtimestamp(fake_exp, tz=datetime.timezone.utc).strftime('%b %d %H:%M:%S %Y GMT')}
            mock_ssl_obj = MagicMock()
            mock_ssl_obj.getpeercert.return_value = mock_cert
            mock_writer = MagicMock()
            mock_writer.get_extra_info.return_value = mock_ssl_obj
            
            async def mock_open_conn(*args, **kwargs):
                return MagicMock(), mock_writer
                
            with patch('asyncio.open_connection', side_effect=mock_open_conn), \
                 patch('bot.run_single_check', return_value=(True, "200 - OK")):
                res_list = database.get_resources(chat_id)
                asyncio.run(bot.check_group_task(res_list, semaphore))
                
        # 1. 30 days remaining -> no alert (state 0)
        run_group_check(30)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 0)
        mock_bot.rpc.send_msg.assert_not_called()
        
        # 2. 6 days remaining -> 7-day alert (state 7)
        # Advance ssl_last_checked so check runs
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(6)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 7)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 1)
        alert_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("7 Days", alert_text)
        
        # 3. 5.5 days remaining -> no duplicate alert (still state 7)
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(5.5)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 7)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 1) # count remains 1
        
        # 4. 2 days remaining -> 3-day alert (state 3)
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(2)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 3)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 2)
        alert_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("3 Days", alert_text)
        
        # 5. 0.5 days remaining (12h) -> 1-day alert (state 1)
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(0.5)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 1)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 3)
        alert_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("24 Hours", alert_text)
        
        # 6. -0.1 days remaining (expired) -> Expired alert (state -1)
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(-0.1)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], -1)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 4)
        alert_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Expired", alert_text)
        
        # 7. Certificate renewed (90 days remaining) -> Reset alert state to 0
        database.update_resource_ssl(r_id, r["ssl_expiry_date"], now - 4000, r["ssl_alert_state"])
        run_group_check(90)
        r = database.get_resources(chat_id)[0]
        self.assertEqual(r["ssl_alert_state"], 0)
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 4) # no extra alert sent on quiet reset

    def test_list_command_ssl_formatting(self):
        chat_id = 6666
        now = int(time.time())
        
        # 1. HTTPS with valid cert (>7d)
        r1 = database.add_resource(chat_id, "https://site-valid.com", "Site Valid", "http")
        database.update_resource_ssl(r1, now + 86400 * 60, now, 0)
        
        # 2. HTTPS with expiring cert (2d)
        r2 = database.add_resource(chat_id, "https://site-expiring.com", "Site Expiring", "http")
        database.update_resource_ssl(r2, now + 86400 * 2, now, 3)
        
        # 3. HTTPS with expired cert (-1d)
        r3 = database.add_resource(chat_id, "https://site-expired.com", "Site Expired", "http")
        database.update_resource_ssl(r3, now - 86400 * 1, now, -1)
        
        # 4. HTTP without SSL
        r4 = database.add_resource(chat_id, "http://plain-http.com", "Plain HTTP", "http")
        
        mock_bot = MagicMock()
        mock_bot.rpc.get_config.return_value = "bot@example.com"
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        
        bot.list_command(mock_bot, 1, mock_event)
        
        calls = mock_bot.rpc.send_msg.call_args_list
        self.assertEqual(len(calls), 1)
        text = calls[0][0][2].text
        
        self.assertIn("Site Valid", text)
        self.assertIn("🔒 `60d` left", text)
        self.assertIn("Site Expiring", text)
        self.assertIn("⚠️ `2d` left", text)
        self.assertIn("Site Expired", text)
        self.assertIn("🚨 Expired", text)
        self.assertIn("Plain HTTP", text)
        # Plain HTTP should not have SSL tag
        self.assertNotIn("Plain HTTP**\n  Target: `http://plain-http.com` (HTTP)\n  Uptime 30d: `100.00%` | Status: `UNKNOWN` | SSL", text)

    def test_database_down_msg_id(self):
        chat_id = 9988
        r_id = database.add_resource(chat_id, "https://msg-track.org", "Track Site", "http")
        self.assertIsNotNone(r_id)
        
        # Initial last_down_msg_id should be None
        res = database.get_resources(chat_id)
        self.assertEqual(len(res), 1)
        self.assertIsNone(res[0]["last_down_msg_id"])
        
        # Update last_down_msg_id
        database.update_resource_down_msg_id(r_id, 45678)
        res = database.get_resources(chat_id)
        self.assertEqual(res[0]["last_down_msg_id"], 45678)
        
        # Reset to None
        database.update_resource_down_msg_id(r_id, None)
        res = database.get_resources(chat_id)
        self.assertIsNone(res[0]["last_down_msg_id"])

    def test_check_host_internet_connectivity(self):
        import asyncio
        bot._canary_last_checked = 0.0
        bot._host_outage_active = False
        
        # Case 1: Online - open_connection succeeds
        mock_writer = MagicMock()
        mock_writer.wait_closed = MagicMock()
        async def mock_open_conn(*args, **kwargs):
            return MagicMock(), mock_writer
            
        with patch('asyncio.open_connection', side_effect=mock_open_conn):
            is_online = asyncio.run(bot.check_host_internet_connectivity(timeout=1.0, max_age=0.0))
            self.assertTrue(is_online)
            self.assertFalse(bot._host_outage_active)
            
        # Case 2: Offline - open_connection fails for all canaries
        bot._canary_last_checked = 0.0
        async def mock_open_conn_fail(*args, **kwargs):
            raise OSError("Network unreachable")
            
        with patch('asyncio.open_connection', side_effect=mock_open_conn_fail):
            is_online = asyncio.run(bot.check_host_internet_connectivity(timeout=1.0, max_age=0.0))
            self.assertFalse(is_online)
            self.assertTrue(bot._host_outage_active)

    def test_host_outage_suppression(self):
        import asyncio
        chat_id = 1122
        r_id = database.add_resource(chat_id, "https://outage-test.org", "Outage Test", "http")
        database.update_resource_status(r_id, "up", 0)
        
        mock_bot = MagicMock()
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1
        
        # Simulate target check failing AND host internet being down
        with patch('bot.run_single_check', return_value=(False, "Connection timeout")), \
             patch('bot.check_host_internet_connectivity', return_value=False), \
             patch('asyncio.sleep', return_value=None):
            res_list = database.get_resources(chat_id)
            semaphore = asyncio.Semaphore(5)
            asyncio.run(bot.check_group_task(res_list, semaphore))
            
        # Resource should NOT transition to DOWN in DB
        res = database.get_resources(chat_id)[0]
        self.assertEqual(res["status"], "up")
        
        # No alert message should have been sent to chat
        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_not_called()

    def test_incident_database_operations(self):
        chat_id = 9911
        inc_id = database.create_incident(chat_id)
        self.assertIsInstance(inc_id, int)
        
        active = database.get_active_incident(chat_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["id"], inc_id)
        self.assertEqual(active["status"], "ongoing")
        self.assertIsNone(active["msg_id"])
        
        database.update_incident_msg_id(inc_id, 45678)
        active = database.get_active_incident(chat_id)
        self.assertEqual(active["msg_id"], 45678)
        
        database.resolve_incident(inc_id, summary="Resolved all")
        active_after = database.get_active_incident(chat_id)
        self.assertIsNone(active_after)
        
        recent = database.get_recent_incidents(chat_id, limit=5)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["id"], inc_id)
        self.assertEqual(recent[0]["status"], "resolved")
        self.assertEqual(recent[0]["summary"], "Resolved all")

    def test_downtime_events_error_reason_and_history(self):
        chat_id = 9922
        r_id = database.add_resource(chat_id, "https://failing.org", "Failing Site", "http")
        
        # Trigger DOWN with error reason
        database.update_resource_status(r_id, "down", 1, error_msg="Timeout after 10s")
        events = database.get_resource_downtime_events(r_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error_msg"], "Timeout after 10s")
        self.assertIsNone(events[0]["went_up_at"])
        
        # Trigger UP
        database.update_resource_status(r_id, "up", 0, error_msg="200 - OK")
        events_after = database.get_resource_downtime_events(r_id)
        self.assertEqual(len(events_after), 1)
        self.assertIsNotNone(events_after[0]["went_up_at"])

    def test_incident_lifecycle_and_message_editing(self):
        import asyncio
        chat_id = 9933
        r1_id = database.add_resource(chat_id, "https://site-a.org", "Site A", "http")
        r2_id = database.add_resource(chat_id, "https://site-b.org", "Site B", "http")
        
        mock_bot = MagicMock()
        mock_bot.rpc.send_msg.return_value = 10001
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1
        
        # 1. Site A goes DOWN -> incident created, send_msg called
        res_a = database.get_resources(chat_id)[0]
        asyncio.run(bot.handle_check_result(res_a, False, "500 - Server Error"))
        
        mock_bot.rpc.send_msg.assert_called_once()
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("🚨 **Incident #", msg_text)
        self.assertIn("Site A", msg_text)
        self.assertIn("DOWN", msg_text)
        
        active_inc = database.get_active_incident(chat_id)
        self.assertIsNotNone(active_inc)
        self.assertEqual(active_inc["msg_id"], 10001)
        
        # 2. Site B goes DOWN -> existing incident message edited in-place
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        
        res_b = database.get_resources(chat_id)[1]
        asyncio.run(bot.handle_check_result(res_b, False, "Connection refused"))
        
        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 10001)
        self.assertIn("Site A", edit_args[2])
        self.assertIn("Site B", edit_args[2])
        self.assertIn("2 / 2 monitors down", edit_args[2])
        
        # 3. Site A recovers -> message edited in-place showing partial recovery
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        
        res_a_down = next(r for r in database.get_resources(chat_id) if r["id"] == r1_id)
        asyncio.run(bot.handle_check_result(res_a_down, True, "200 - OK"))
        
        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 10001)
        self.assertIn("Ongoing (Partial Recovery)", edit_args[2])
        self.assertIn("1 / 2 monitors down", edit_args[2])
        
        # 4. Site B recovers -> all UP! Incident resolved, message edited to Resolved
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        
        res_b_down = next(r for r in database.get_resources(chat_id) if r["id"] == r2_id)
        asyncio.run(bot.handle_check_result(res_b_down, True, "200 - OK"))
        
        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 10001)
        self.assertIn("✅ **Incident #", edit_args[2])
        self.assertIn("Resolved", edit_args[2])
        self.assertIn("All 2 monitors operational", edit_args[2])
        
        # Incident in DB should now be resolved
        self.assertIsNone(database.get_active_incident(chat_id))

    def test_events_command(self):
        chat_id = 9944
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        
        # When no incidents
        bot.events_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("No incidents recorded in this chat", msg_text)
        
        # When incidents exist
        inc1_id = database.create_incident(chat_id, int(time.time()) - 300)
        database.resolve_incident(inc1_id, int(time.time()), "Resolved")
        inc2_id = database.create_incident(chat_id, int(time.time()))
        
        mock_bot.rpc.send_msg.reset_mock()
        bot.events_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Incident Log for this Chat", msg_text)
        self.assertIn(f"Incident #{inc1_id}", msg_text)
        self.assertIn(f"Incident #{inc2_id}", msg_text)
        self.assertIn("Ongoing", msg_text)
        self.assertIn("Resolved", msg_text)

    def test_history_command(self):
        chat_id = 9955
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        
        # 1. No payload -> guide & list of monitors
        mock_event.payload = ""
        r_id = database.add_resource(chat_id, "https://history-site.com", "History Site", "http")
        
        bot.history_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Monitor Downtime History Guide", msg_text)
        self.assertIn(f"ID: {r_id}", msg_text)
        self.assertIn("History Site", msg_text)
        
        # 2. Invalid ID payload
        mock_event.payload = "abc"
        bot.history_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Invalid monitor ID", msg_text)
        
        # 3. Nonexistent ID payload
        mock_event.payload = "99999"
        bot.history_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("not found in this chat", msg_text)
        
        # 4. Valid ID with downtime events
        database.update_resource_status(r_id, "down", 1, error_msg="HTTP 502 Bad Gateway")
        database.update_resource_status(r_id, "up", 0, error_msg="200 - OK")
        
        mock_event.payload = str(r_id)
        bot.history_command(mock_bot, 1, mock_event)
        msg_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn(f"Downtime History for ID {r_id}", msg_text)
        self.assertIn("Recorded Outages", msg_text)
        self.assertIn("HTTP 502 Bad Gateway", msg_text)

    def test_dashboard_ssl_and_incidents_html(self):
        now = int(time.time())
        resources = [
            {
                "id": 1,
                "name": "HTTPS Secure",
                "url": "https://secure.org",
                "type": "http",
                "status": "up",
                "last_checked": now,
                "ssl_expiry_date": now + 86400 * 45
            },
            {
                "id": 2,
                "name": "Ping Host",
                "url": "host.local",
                "type": "ping",
                "status": "up",
                "last_checked": now,
                "ssl_expiry_date": None
            }
        ]
        incidents = [
            {
                "id": 101,
                "status": "resolved",
                "started_at": now - 3600,
                "resolved_at": now - 1800,
                "summary": "Resolved"
            }
        ]
        # Link a downtime event for resource 1 to incident 101
        with database._lock:
            conn = sqlite3.connect(database.DB_PATH)
            conn.execute("INSERT INTO downtime_events (resource_id, went_down_at, went_up_at, error_msg, incident_id) VALUES (?, ?, ?, ?, ?)",
                         (1, now - 3600, now - 1800, "502 Bad Gateway", 101))
            conn.commit()
            conn.close()

        html_out = bot.get_dashboard_html("Test Chat", resources, 100.0, incidents)
        self.assertIn("SSL Cert", html_out)
        self.assertIn("45d left", html_out)
        self.assertIn("Recent Incidents", html_out)
        self.assertIn("Incident #101 — Resolved", html_out)
        self.assertIn("Affected Monitors:", html_out)
        self.assertIn("502 Bad Gateway", html_out)

    def test_stale_downtime_7d_notice_and_14d_warning(self):
        import asyncio
        import sqlite3
        now = int(time.time())
        chat_id = 4455
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "Stale App", "https://stale.org", "http", 60)

        # Mock bot instance & accid
        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1

        with patch.object(bot, '_dc_send_msg_with_stats') as mock_send:
            # 1. 7 days downtime -> Notice sent, level updated to 7
            database.update_resource_status(r_id, "down", 10, "Connection refused")
            # Manually backdate last_changed
            with database._lock:
                conn = sqlite3.connect(database.DB_PATH)
                conn.execute("UPDATE resources SET last_changed = ? WHERE id = ?", (now - 7 * 86400 - 100, r_id))
                conn.commit()
                conn.close()

            res = database.get_resource_by_id(r_id)
            asyncio.run(bot.check_stale_downtime_notifications(res, now))

            mock_send.assert_called_once()
            msg_text = mock_send.call_args[0][3].text
            self.assertIn("Downtime Notice (7 Days Unreachable)", msg_text)
            self.assertIn("Stale App", msg_text)
            self.assertIn(f"/remove {r_id}", msg_text)

            res_after_7d = database.get_resource_by_id(r_id)
            self.assertEqual(res_after_7d["stale_warning_level"], 7)

            # Running again without time advance -> no duplicate message
            mock_send.reset_mock()
            asyncio.run(bot.check_stale_downtime_notifications(res_after_7d, now))
            mock_send.assert_not_called()

            # 2. 14 days downtime -> Warning sent, level updated to 14
            with database._lock:
                conn = sqlite3.connect(database.DB_PATH)
                conn.execute("UPDATE resources SET last_changed = ? WHERE id = ?", (now - 14 * 86400 - 100, r_id))
                conn.commit()
                conn.close()

            res = database.get_resource_by_id(r_id)
            asyncio.run(bot.check_stale_downtime_notifications(res, now))

            mock_send.assert_called_once()
            msg_text_14 = mock_send.call_args[0][3].text
            self.assertIn("Downtime Warning (14 Days Unreachable)", msg_text_14)
            self.assertIn("30 days", msg_text_14)

            res_after_14d = database.get_resource_by_id(r_id)
            self.assertEqual(res_after_14d["stale_warning_level"], 14)

    def test_stale_downtime_30d_auto_cleanup(self):
        import asyncio
        import sqlite3
        now = int(time.time())
        chat_id = 4466
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "Dead App", "https://dead.org", "http", 60)

        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1

        with patch.object(bot, '_dc_send_msg_with_stats') as mock_send:
            database.update_resource_status(r_id, "down", 10, "Connection refused")
            with database._lock:
                conn = sqlite3.connect(database.DB_PATH)
                conn.execute("UPDATE resources SET last_changed = ? WHERE id = ?", (now - 30 * 86400 - 100, r_id))
                conn.commit()
                conn.close()

            res = database.get_resource_by_id(r_id)
            asyncio.run(bot.check_stale_downtime_notifications(res, now))

            mock_send.assert_called_once()
            msg_text_30 = mock_send.call_args[0][3].text
            self.assertIn("Auto-Cleanup (30 Days Unreachable)", msg_text_30)
            self.assertIn("Dead App", msg_text_30)

            # Resource should be deleted from database
            self.assertIsNone(database.get_resource_by_id(r_id))

    def test_stale_warning_level_reset_on_recovery(self):
        now = int(time.time())
        chat_id = 4477
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "Flaky App", "https://flaky.org", "http", 60)

        # Set down and level = 14
        database.update_resource_status(r_id, "down", 5, "Connection error")
        database.update_stale_warning_level(r_id, 14)
        self.assertEqual(database.get_resource_by_id(r_id)["stale_warning_level"], 14)

    def test_incident_resolves_when_failing_monitor_removed(self):
        import asyncio
        chat_id = 8822
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://good.org", "Good App", "http", 60)
        r2 = database.add_resource(chat_id, "https://bad.org", "Bad App", "http", 60)

        database.update_resource_status(r1, "up", 0)
        database.update_resource_status(r2, "down", 3, "HTTP 500")

        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1

        # Sync -> active incident created
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        inc = database.get_active_incident(chat_id)
        self.assertIsNotNone(inc)
        database.update_incident_msg_id(inc["id"], 77001)

        # Now user removes Bad App
        event = MagicMock()
        event.msg.chat_id = chat_id
        event.payload = str(r2)
        with patch.object(bot, '_dc_send_msg_with_stats'):
            bot.remove_command(bot.dc_bot_instance, bot.dc_accid, event)

        # Sync state
        asyncio.run(bot.sync_chat_incident_state(chat_id))

        # Incident should now be resolved!
        self.assertIsNone(database.get_active_incident(chat_id))
        resolved_inc = database.get_incident_by_id(chat_id, inc["id"])
        self.assertEqual(resolved_inc["status"], "resolved")
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_with(
            1, 77001, unittest.mock.ANY
        )
        edited_text = bot.dc_bot_instance.rpc.send_edit_request.call_args[0][2]
        self.assertIn("Resolved", edited_text)
        self.assertIn("All 1 monitors operational", edited_text)
        self.assertNotIn("Good App", edited_text)

    def test_incident_resolves_when_all_monitors_removed(self):
        import asyncio
        chat_id = 8833
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://onlybad.org", "Only Bad App", "http", 60)
        database.update_resource_status(r1, "down", 3, "HTTP 500")

        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.send_msg.return_value = 10001
        bot.dc_accid = 1

        asyncio.run(bot.sync_chat_incident_state(chat_id))
        inc = database.get_active_incident(chat_id)
        self.assertIsNotNone(inc)
        database.update_incident_msg_id(inc["id"], 77002)

        # Remove the only resource and re-sync
        database.delete_resource(chat_id, r1)
        asyncio.run(bot.sync_chat_incident_state(chat_id))

        self.assertIsNone(database.get_active_incident(chat_id))
        resolved_inc = database.get_incident_by_id(chat_id, inc["id"])
        self.assertEqual(resolved_inc["status"], "resolved")

    def test_audit_and_auto_close_stale_active_incidents(self):
        import asyncio
        chat_id_1 = 8844
        chat_id_2 = 8855
        database.get_or_create_chat_token(chat_id_1)
        database.get_or_create_chat_token(chat_id_2)

        # Chat 1: Had an old active incident in DB, but its resource is currently UP
        r1 = database.add_resource(chat_id_1, "https://healed.org", "Healed App", "http", 60)
        database.update_resource_status(r1, "up", 0)
        inc1_id = database.create_incident(chat_id_1, int(time.time()) - 3600)
        database.update_incident_msg_id(inc1_id, 77003)

        # Chat 2: Has an active incident and resource is still DOWN
        r2 = database.add_resource(chat_id_2, "https://failing.org", "Failing App", "http", 60)
        database.update_resource_status(r2, "down", 5, "Connection refused")
        inc2 = database.get_active_incident(chat_id_2)
        inc2_id = inc2["id"]
        database.update_incident_msg_id(inc2_id, 77004)

        active_incidents = database.get_all_active_incidents()
        self.assertEqual(len(active_incidents), 2)

        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1

        # Simulate periodic scheduler audit
        for inc in active_incidents:
            asyncio.run(bot.sync_chat_incident_state(inc["dc_chat_id"]))

        # Chat 1 incident must be automatically self-healed and resolved!
        self.assertIsNone(database.get_active_incident(chat_id_1))
        inc1 = database.get_incident_by_id(chat_id_1, inc1_id)
        self.assertEqual(inc1["status"], "resolved")

        # Chat 2 incident must remain ongoing
        inc2 = database.get_active_incident(chat_id_2)
        self.assertIsNotNone(inc2)
        self.assertEqual(inc2["id"], inc2_id)

    def test_get_incident_update_interval(self):
        # 0 - 1 min: 15s
        self.assertEqual(bot.get_incident_update_interval(0), 15)
        self.assertEqual(bot.get_incident_update_interval(59), 15)
        # 1 - 5 min: 30s
        self.assertEqual(bot.get_incident_update_interval(60), 30)
        self.assertEqual(bot.get_incident_update_interval(299), 30)
        # 5 min - 1 hour: 60s
        self.assertEqual(bot.get_incident_update_interval(300), 60)
        self.assertEqual(bot.get_incident_update_interval(3599), 60)
        # 1 hour - 24 hours: 300s (5 minutes)
        self.assertEqual(bot.get_incident_update_interval(3600), 300)
        self.assertEqual(bot.get_incident_update_interval(86399), 300)
        # > 24 hours: 3600s (1 hour)
        self.assertEqual(bot.get_incident_update_interval(86400), 3600)
        self.assertEqual(bot.get_incident_update_interval(86400 * 7), 3600)

    def test_incident_edit_rate_limiting_and_immediate_state_change(self):
        import asyncio
        chat_id = 9988
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://throttled.org", "Throttled App", "http", 60)
        database.update_resource_status(r1, "down", 3, "HTTP 500")

        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.send_msg.return_value = 55001
        bot.dc_accid = 1
        bot._incident_last_edit_state.clear()

        # 1. First sync -> sends new message and records last_edit_state
        asyncio.run(bot.sync_chat_incident_state(chat_id, force_update=False))
        inc = database.get_active_incident(chat_id)
        self.assertIsNotNone(inc)
        database.update_incident_msg_id(inc["id"], 55001)
        self.assertIn(inc["id"], bot._incident_last_edit_state)

        # 2. Immediate re-sync with NO state change -> throttled, no edit call!
        bot.dc_bot_instance.rpc.send_edit_request.reset_mock()
        asyncio.run(bot.sync_chat_incident_state(chat_id, force_update=False))
        bot.dc_bot_instance.rpc.send_edit_request.assert_not_called()

        # 3. Simulate 20 seconds passing (within first minute, 15s interval passed)
        last_t, sig = bot._incident_last_edit_state[inc["id"]]
        bot._incident_last_edit_state[inc["id"]] = (last_t - 20, sig)

        asyncio.run(bot.sync_chat_incident_state(chat_id, force_update=False))
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()

        # 4. Immediate state change (another resource added and failed) -> force_update/sig changed -> immediate edit!
        bot.dc_bot_instance.rpc.send_edit_request.reset_mock()
        r2 = database.add_resource(chat_id, "https://second.org", "Second App", "http", 60)
        database.update_resource_status(r2, "down", 1, "Connection refused")

        asyncio.run(bot.sync_chat_incident_state(chat_id, force_update=False))
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()

    def test_incident_resolved_message_only_shows_affected_monitors(self):
        import asyncio
        chat_id = 9991
        database.get_or_create_chat_token(chat_id)
        
        # 3 resources in chat: 1 failing and 2 healthy
        r1 = database.add_resource(chat_id, "https://affected.org", "Affected Site", "http", 60)
        r2 = database.add_resource(chat_id, "https://healthy1.org", "Healthy Site 1", "http", 60)
        r3 = database.add_resource(chat_id, "https://healthy2.org", "Healthy Site 2", "http", 60)
        
        database.update_resource_status(r2, "up", 0)
        database.update_resource_status(r3, "up", 0)
        
        # Site 1 goes down -> incident starts
        database.update_resource_status(r1, "down", 3, "HTTP 500")
        inc = database.get_active_incident(chat_id)
        inc_id = inc["id"]
        database.update_incident_msg_id(inc_id, 88801)
        
        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1
        
        # Site 1 recovers -> all UP, incident resolves
        database.update_resource_status(r1, "up", 0)
        
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        
        bot.dc_bot_instance.rpc.send_edit_request.assert_called_once()
        edited_text = bot.dc_bot_instance.rpc.send_edit_request.call_args[0][2]
        
        self.assertIn("All 3 monitors operational", edited_text)
        self.assertIn("Recovered Monitors:", edited_text)
        self.assertIn("Affected Site", edited_text)
        # Healthy sites that never went down MUST NOT be listed in the recovered breakdown
        self.assertNotIn("Healthy Site 1", edited_text)
        self.assertNotIn("Healthy Site 2", edited_text)

    def test_incident_split_after_one_hour_gap(self):
        import asyncio
        chat_id = 9992
        database.get_or_create_chat_token(chat_id)

        r1_id = database.add_resource(chat_id, "https://site-a.org", "Site A", "http")
        r2_id = database.add_resource(chat_id, "https://site-b.org", "Site B", "http")

        mock_bot = MagicMock()
        mock_bot.rpc.send_msg.side_effect = [20001, 20002]
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1

        t0 = 1000000

        # 1. Site A goes DOWN at t0 -> Incident #1 created with msg_id 20001
        with patch('time.time', return_value=t0):
            res_a = database.get_resources(chat_id)[0]
            asyncio.run(bot.handle_check_result(res_a, False, "500 - Server Error"))

        self.assertEqual(mock_bot.rpc.send_msg.call_count, 1)
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 1)
        inc1_id = active_incs[0]["id"]
        self.assertEqual(active_incs[0]["msg_id"], 20001)

        # 2. Site B goes DOWN at t0 + 4000s (> 1 hour gap) -> Incident #2 created with msg_id 20002!
        t1 = t0 + 4000
        with patch('time.time', return_value=t1):
            res_b = database.get_resources(chat_id)[1]
            asyncio.run(bot.handle_check_result(res_b, False, "Connection refused"))

        self.assertEqual(mock_bot.rpc.send_msg.call_count, 2)
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 2)
        inc2_id = active_incs[1]["id"]
        self.assertEqual(active_incs[1]["msg_id"], 20002)

        # 3. Site B recovers at t1 + 300s -> Incident #2 resolves, Incident #1 remains active
        t2 = t1 + 300
        mock_bot.rpc.send_edit_request.reset_mock()
        with patch('time.time', return_value=t2):
            res_b_down = next(r for r in database.get_resources(chat_id) if r["id"] == r2_id)
            asyncio.run(bot.handle_check_result(res_b_down, True, "200 - OK"))

        resolved_calls = [c for c in mock_bot.rpc.send_edit_request.call_args_list if c[0][1] == 20002]
        self.assertEqual(len(resolved_calls), 1)
        self.assertIn(f"Incident #{inc2_id}", resolved_calls[0][0][2])
        self.assertIn("Resolved", resolved_calls[0][0][2])
        self.assertIn("Site B", resolved_calls[0][0][2])

        # Verify only Incident #1 is still active
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 1)
        self.assertEqual(active_incs[0]["id"], inc1_id)

        # 4. Site A recovers at t2 + 500s -> Incident #1 resolves
        t3 = t2 + 500
        mock_bot.rpc.send_edit_request.reset_mock()
        with patch('time.time', return_value=t3):
            res_a_down = next(r for r in database.get_resources(chat_id) if r["id"] == r1_id)
            asyncio.run(bot.handle_check_result(res_a_down, True, "200 - OK"))

        resolved_calls = [c for c in mock_bot.rpc.send_edit_request.call_args_list if c[0][1] == 20001]
        self.assertEqual(len(resolved_calls), 1)
        self.assertIn(f"Incident #{inc1_id}", resolved_calls[0][0][2])
        self.assertIn("Resolved", resolved_calls[0][0][2])
        self.assertIn("Site A", resolved_calls[0][0][2])

        # Both incidents resolved
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 0)

    def test_database_migration_from_legacy_schema(self):
        import tempfile
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            legacy_db_path = tf.name

        try:
            # Create old schema table without incident_id column
            conn = sqlite3.connect(legacy_db_path)
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE downtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_id INTEGER,
                    went_down_at INTEGER,
                    went_up_at INTEGER,
                    error_msg TEXT
                )
            ''')
            conn.commit()
            conn.close()

            # Now run init_db pointing to this legacy db
            with patch('database.DB_PATH', legacy_db_path):
                database.init_db()

            # Verify incident_id column was added successfully
            conn = sqlite3.connect(legacy_db_path)
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(downtime_events)")
            columns = [r[1] for r in cur.fetchall()]
            self.assertIn("incident_id", columns)
            conn.close()
        finally:
            if os.path.exists(legacy_db_path):
                os.remove(legacy_db_path)

    def test_incident_reopened_on_service_flapping_within_one_hour(self):
        import asyncio
        chat_id = 9993
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "https://flapping-site.org", "Flapping Site", "http")

        mock_bot = MagicMock()
        mock_bot.rpc.send_msg.return_value = 30001
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1

        t0 = 1000000

        # 1. Goes DOWN at t0 -> Incident #1 created with send_msg
        with patch('time.time', return_value=t0):
            res = database.get_resources(chat_id)[0]
            asyncio.run(bot.handle_check_result(res, False, "502 - Bad Gateway"))

        mock_bot.rpc.send_msg.assert_called_once()
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 1)
        inc1_id = active_incs[0]["id"]
        self.assertEqual(active_incs[0]["msg_id"], 30001)

        # 2. Recovers at t0 + 300s -> Incident #1 resolves with send_edit_request
        t1 = t0 + 300
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        with patch('time.time', return_value=t1):
            res_down = database.get_resources(chat_id)[0]
            asyncio.run(bot.handle_check_result(res_down, True, "200 - OK"))

        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 30001)
        self.assertIn("Resolved", edit_args[2])
        self.assertEqual(len(database.get_active_incidents_for_chat(chat_id)), 0)

        # 3. Flaps DOWN again at t1 + 300s (T = t0 + 600s, < 1 hour) -> Reopens Incident #1!
        t2 = t1 + 300
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        with patch('time.time', return_value=t2):
            res_up = database.get_resources(chat_id)[0]
            asyncio.run(bot.handle_check_result(res_up, False, "Connection timed out"))

        # MUST NOT send a new message
        mock_bot.rpc.send_msg.assert_not_called()
        # MUST edit existing message back to Ongoing
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 30001)
        self.assertIn(f"Incident #{inc1_id}", edit_args[2])
        self.assertIn("Ongoing", edit_args[2])
        self.assertIn("Flapping Site", edit_args[2])

        # Active incidents in DB should now show Incident #1 active again
        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 1)
        self.assertEqual(active_incs[0]["id"], inc1_id)
        self.assertEqual(active_incs[0]["status"], "ongoing")

        # 4. Finally recovers at t2 + 300s (T = t0 + 900s) -> Resolves again
        t3 = t2 + 300
        mock_bot.rpc.send_msg.reset_mock()
        mock_bot.rpc.send_edit_request.reset_mock()
        with patch('time.time', return_value=t3):
            res_down2 = database.get_resources(chat_id)[0]
            asyncio.run(bot.handle_check_result(res_down2, True, "200 - OK"))

        mock_bot.rpc.send_msg.assert_not_called()
        mock_bot.rpc.send_edit_request.assert_called_once()
        edit_args = mock_bot.rpc.send_edit_request.call_args[0]
        self.assertEqual(edit_args[1], 30001)
        self.assertIn(f"Incident #{inc1_id}", edit_args[2])
        self.assertIn("Resolved", edit_args[2])
        self.assertEqual(len(database.get_active_incidents_for_chat(chat_id)), 0)

    def test_delete_by_numeric_id(self):
        chat_id = 9994
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "https://delete-id.org", "Delete ID Site", "http")

        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = None
        mock_event.payload = str(r_id)

        bot.remove_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Removed monitor", sent_text)
        self.assertIn("Delete ID Site", sent_text)
        self.assertEqual(len(database.get_resources(chat_id)), 0)

    def test_delete_by_url_target(self):
        chat_id = 9995
        database.get_or_create_chat_token(chat_id)
        database.add_resource(chat_id, "https://delete-url.org/api", "Delete URL Site", "http")

        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = None
        mock_event.payload = "https://delete-url.org/api"

        bot.remove_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Removed monitor", sent_text)
        self.assertIn("Delete URL Site", sent_text)
        self.assertEqual(len(database.get_resources(chat_id)), 0)

    def test_delete_by_quote_incident_msg_id(self):
        import asyncio
        chat_id = 9996
        database.get_or_create_chat_token(chat_id)
        r_id = database.add_resource(chat_id, "https://quote-inc.org", "Quote Inc Site", "http")

        # 1. Trigger incident -> msg_id = 40001
        mock_bot = MagicMock()
        mock_bot.rpc.send_msg.return_value = 40001
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1

        res = database.get_resources(chat_id)[0]
        asyncio.run(bot.handle_check_result(res, False, "503 - Service Unavailable"))

        active_incs = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(active_incs), 1)
        self.assertEqual(active_incs[0]["msg_id"], 40001)

        # 2. User sends /delete replying to message 40001
        mock_bot.rpc.send_msg.reset_mock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = {"message_id": 40001, "text": "🚨 Incident #1 — Ongoing\n• https://quote-inc.org"}
        mock_event.payload = ""

        bot.remove_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Removed monitor", sent_text)
        self.assertIn("Quote Inc Site", sent_text)
        self.assertEqual(len(database.get_resources(chat_id)), 0)

    def test_delete_by_quote_text_url_matching(self):
        chat_id = 9997
        database.get_or_create_chat_token(chat_id)
        database.add_resource(chat_id, "https://quote-text.org", "Quote Text Site", "http")

        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = {"text": "Notice: https://quote-text.org has been unreachable for 7 days."}
        mock_event.payload = ""

        bot.remove_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Removed monitor", sent_text)
        self.assertIn("Quote Text Site", sent_text)
        self.assertEqual(len(database.get_resources(chat_id)), 0)

    def test_delete_by_quote_unrelated_message_silently_ignored(self):
        chat_id = 9998
        database.get_or_create_chat_token(chat_id)
        database.add_resource(chat_id, "https://my-own-site.org", "My Site", "http")

        # Quoting a message from another bot in the chat (unrelated URL)
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = {"message_id": 77777, "text": "Alert from Other Bot: https://other-bot-server.org"}
        mock_event.payload = ""

        bot.remove_command(mock_bot, 1, mock_event)
        # Must NOT send any message (silent ignore to allow the other bot to respond)
        mock_bot.rpc.send_msg.assert_not_called()
        # Must NOT delete this bot's monitor
        self.assertEqual(len(database.get_resources(chat_id)), 1)

    def test_delete_no_args_no_quote_shows_usage(self):
        chat_id = 9999
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = None
        mock_event.payload = ""

        bot.remove_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Usage:", sent_text)
        self.assertIn("Reply `/delete`", sent_text)

    def test_add_with_keyword_and_keyword_command(self):
        chat_id = 9911
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.payload = 'https://api.mytest.com "API Service" "status:ok"'

        bot.add_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Added monitor", sent_text)
        self.assertIn("Expected Keyword: `status:ok`", sent_text)

        resources = database.get_resources(chat_id)
        self.assertEqual(len(resources), 1)
        res = resources[0]
        self.assertEqual(res["expected_keyword"], "status:ok")

        # Update keyword via /keyword command
        mock_bot.rpc.send_msg.reset_mock()
        mock_event.payload = f'{res["id"]} "health:green"'
        bot.keyword_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        self.assertIn("Set expected keyword", mock_bot.rpc.send_msg.call_args[0][2].text)
        self.assertEqual(database.get_resource_by_id(res["id"])["expected_keyword"], "health:green")

        # Clear keyword via /keyword <id> none
        mock_bot.rpc.send_msg.reset_mock()
        mock_event.payload = f'{res["id"]} none'
        bot.keyword_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        self.assertIn("Cleared expected keyword", mock_bot.rpc.send_msg.call_args[0][2].text)
        self.assertIsNone(database.get_resource_by_id(res["id"])["expected_keyword"])

    def test_pause_and_resume_commands_and_maintenance_suppression(self):
        chat_id = 9912
        res_id = database.add_resource(chat_id, "https://maint-test.org", "Maint Site", "http")

        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = None

        # 1. /pause 1 30m
        mock_event.payload = f"{res_id} 30m"
        bot.pause_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Maintenance Mode Enabled", sent_text)
        self.assertIn("Maint Site", sent_text)

        res = database.get_resource_by_id(res_id)
        now = int(time.time())
        self.assertGreater(res["maintenance_until"], now + 1700)

        # 2. Check result failure during maintenance should NOT trigger incident
        asyncio.run(bot.handle_check_result(res, False, "500 - Internal Error"))
        incidents = database.get_active_incidents_for_chat(chat_id)
        self.assertEqual(len(incidents), 0)

        # 3. /resume 1
        mock_bot.rpc.send_msg.reset_mock()
        mock_event.payload = str(res_id)
        bot.resume_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        self.assertIn("Resumed Monitoring", mock_bot.rpc.send_msg.call_args[0][2].text)
        res = database.get_resource_by_id(res_id)
        self.assertEqual(res["maintenance_until"], 0)

    def test_pause_by_quote_reply(self):
        chat_id = 9913
        res_id = database.add_resource(chat_id, "https://pause-quote.org", "Pause Quote Site", "http")

        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        mock_event.msg.quote = {"text": "Alert: https://pause-quote.org is down!"}
        mock_event.payload = "2h"

        bot.pause_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        sent_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("Maintenance Mode Enabled", sent_text)
        self.assertIn("Pause Quote Site", sent_text)

        res = database.get_resource_by_id(res_id)
        now = int(time.time())
        self.assertGreater(res["maintenance_until"], now + 7100)

    def test_latency_tracking_in_database(self):
        chat_id = 9914
        res_id = database.add_resource(chat_id, "https://latency-test.org", "Latency Site", "http")

        database.update_resource_latency(res_id, 145)
        res = database.get_resource_by_id(res_id)
        self.assertEqual(res["last_latency_ms"], 145)

        # Verify /list formatting includes latency
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = chat_id
        bot.list_command(mock_bot, 1, mock_event)
        mock_bot.rpc.send_msg.assert_called_once()
        list_text = mock_bot.rpc.send_msg.call_args[0][2].text
        self.assertIn("⚡ `145ms`", list_text)

    def test_run_single_check_keyword_assertion(self):
        # 1. Matching keyword -> UP
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.content.read = unittest.mock.AsyncMock(return_value=b"<html><body>Welcome to My Site</body></html>")

        class MockSessionContext:
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            def get(self, url, allow_redirects=True):
                class MockGetContext:
                    async def __aenter__(self):
                        return mock_resp
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockGetContext()

        with patch('aiohttp.ClientSession', return_value=MockSessionContext()):
            res = {"type": "http", "url": "https://test-kw.org", "expected_keyword": "Welcome to My Site"}
            is_up, details, lat = asyncio.run(bot.run_single_check(res))
            self.assertTrue(is_up)
            self.assertIn("200 - OK", details)
            self.assertIsNotNone(lat)

            # 2. Missing keyword -> DOWN with details
            res["expected_keyword"] = "NonExistentString"
            is_up, details, lat = asyncio.run(bot.run_single_check(res))
            self.assertFalse(is_up)
            self.assertIn("Missing keyword", details)

    def test_run_single_check_auto_error_detection(self):
        # Database connection error inside HTTP 200 -> DOWN
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.content.read = unittest.mock.AsyncMock(return_value=b"<h1>Error establishing a database connection</h1>")

        class MockSessionContext:
            async def __aenter__(self):
                return self
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
            def get(self, url, allow_redirects=True):
                class MockGetContext:
                    async def __aenter__(self):
                        return mock_resp
                    async def __aexit__(self, exc_type, exc_val, exc_tb):
                        pass
                return MockGetContext()

        with patch('aiohttp.ClientSession', return_value=MockSessionContext()):
            res = {"type": "http", "url": "https://test-db-error.org", "expected_keyword": None}
            is_up, details, lat = asyncio.run(bot.run_single_check(res))
            self.assertFalse(is_up)
            self.assertIn("Database connection error detected", details)

    def test_peer_database_operations(self):
        # 1. Local node name
        self.assertEqual(database.get_local_node_name(), "Node-1")
        database.set_local_node_name("Frankfurt-DE")
        self.assertEqual(database.get_local_node_name(), "Frankfurt-DE")

        # 2. Add and get peer
        database.add_or_update_peer("peer1@example.com", "Helsinki-DO", 101, 1700000000)
        p = database.get_peer("peer1@example.com")
        self.assertIsNotNone(p)
        self.assertEqual(p["email"], "peer1@example.com")
        self.assertEqual(p["node_name"], "Helsinki-DO")
        self.assertEqual(p["chat_id"], 101)
        self.assertEqual(p["last_seen"], 1700000000)

        # 3. Update peer
        database.add_or_update_peer("peer1@example.com", "Helsinki-Updated", 102, 1700000500)
        p = database.get_peer("peer1@example.com")
        self.assertEqual(p["node_name"], "Helsinki-Updated")
        self.assertEqual(p["chat_id"], 102)
        self.assertEqual(p["last_seen"], 1700000500)

        # 4. Get by chat ID
        p_by_chat = database.get_peer_by_chat_id(102)
        self.assertIsNotNone(p_by_chat)
        self.assertEqual(p_by_chat["email"], "peer1@example.com")

        # 5. List peers
        database.add_or_update_peer("peer2@example.com", "RU-Moscow", 202)
        all_peers = database.get_all_peers()
        self.assertEqual(len(all_peers), 2)

        # 6. Update last seen
        database.update_peer_last_seen("peer2@example.com", 1700001000)
        p2 = database.get_peer("peer2@example.com")
        self.assertEqual(p2["last_seen"], 1700001000)

        # 7. Remove peer
        self.assertTrue(database.remove_peer("peer1@example.com"))
        self.assertIsNone(database.get_peer("peer1@example.com"))
        self.assertFalse(database.remove_peer("nonexistent@example.com"))

        # 8. Peer measurements
        database.save_peer_measurement("https://mysite.org", "RU-Moscow", "up", 45, "200 - OK", 1700000000)
        measurements = database.get_peer_measurements_for_url("https://mysite.org")
        self.assertEqual(len(measurements), 1)
        self.assertEqual(measurements[0]["node_name"], "RU-Moscow")
        self.assertEqual(measurements[0]["status"], "up")
        self.assertEqual(measurements[0]["latency_ms"], 45)

        # 9. Batch peer measurements
        batch = [
            {"url": "https://site1.org", "status": "up", "latency_ms": 25},
            {"url": "https://site2.org", "status": "down", "latency_ms": None, "error_msg": "Timeout"}
        ]
        database.save_peer_measurements_batch("Helsinki-DO", batch)
        all_m = database.get_all_peer_measurements()
        self.assertEqual(len(all_m), 3) # 1 from previous + 2 from batch

    @patch('bot._is_dc_admin')
    def test_nodename_command(self, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = 123
        mock_event.msg.from_id = 10

        # View current
        mock_event.payload = ""
        bot.nodename_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("Current local probe node name", args[2].text)

        # Set new
        mock_event.payload = "Frankfurt-Primary"
        bot.nodename_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_local_node_name(), "Frankfurt-Primary")

        # Non-admin denied
        mock_is_admin.return_value = False
        bot.nodename_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("only for the administrator", args[2].text)

    @patch('bot._is_dc_admin')
    def test_peers_and_addpeer_rmpeer_commands(self, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_bot.rpc.create_contact.return_value = 50
        mock_bot.rpc.create_chat_by_contact_id.return_value = 999
        mock_event = MagicMock()
        mock_event.msg.chat_id = 123
        mock_event.msg.from_id = 10

        # 1. Empty peers
        mock_event.payload = ""
        bot.peers_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("No remote peers configured", args[2].text)

        # 2. Add peer invalid email
        mock_event.payload = "invalidemail RU"
        bot.addpeer_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("Invalid email address", args[2].text)

        # 3. Add peer valid
        mock_event.payload = "ruptime@gluek.info RU-Moscow"
        bot.addpeer_command(mock_bot, 1, mock_event)
        peer = database.get_peer("ruptime@gluek.info")
        self.assertIsNotNone(peer)
        self.assertEqual(peer["node_name"], "RU-Moscow")
        self.assertEqual(peer["chat_id"], 999)

        # Verify hello handshake sent to 1:1 chat
        send_calls = mock_bot.rpc.send_msg.call_args_list
        hello_sent = any("[UPTIME_PEER_HELLO]" in str(call) for call in send_calls)
        self.assertTrue(hello_sent)

        # 4. View peers with configured peer
        bot.peers_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("Network Stats:", args[2].text)
        self.assertIn("RU-Moscow", args[2].text)
        self.assertIn("ruptime@gluek.info", args[2].text)

        # 5. Invitepeer command
        mock_bot.rpc.get_chat_securejoin_qr_code.return_value = "https://i.delta.chat/#testinvite123"
        bot.invitepeer_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("https://i.delta.chat/#testinvite123", args[2].text)

        # 6. Add peer via SecureJoin invite link
        mock_bot.rpc.check_qr.return_value = {"address": "securebot@chatmail.uk", "contact_id": 55}
        mock_bot.rpc.secure_join.return_value = 888
        mock_event.payload = "https://i.delta.chat/#testinvite123 London-Node"
        bot.addpeer_command(mock_bot, 1, mock_event)
        peer_sj = database.get_peer("securebot@chatmail.uk")
        self.assertIsNotNone(peer_sj)
        self.assertEqual(peer_sj["node_name"], "London-Node")
        self.assertEqual(peer_sj["chat_id"], 888)

        # 7. Remove peer
        mock_event.payload = "ruptime@gluek.info"
        bot.rmpeer_command(mock_bot, 1, mock_event)
        self.assertIsNone(database.get_peer("ruptime@gluek.info"))

    def test_peer_protocol_messages_in_on_new_message(self):
        mock_bot = MagicMock()
        contact_mock = MagicMock()
        contact_mock.address = "probe2@gluek.info"
        mock_bot.rpc.get_contact.return_value = contact_mock

        mock_event = MagicMock()
        mock_event.msg.is_info = False
        mock_event.msg.from_id = 77
        mock_event.msg.chat_id = 888

        # 1. Incoming [UPTIME_PEER_HELLO]
        mock_event.msg.text = '[UPTIME_PEER_HELLO]\n{"node_name": "Helsinki-DO", "version": "2.0.0"}\n[/UPTIME_PEER_HELLO]'
        bot.on_new_message(mock_bot, 1, mock_event)
        p = database.get_peer("probe2@gluek.info")
        self.assertIsNotNone(p)
        self.assertEqual(p["node_name"], "Helsinki-DO")
        self.assertEqual(p["chat_id"], 888)

        # Check that ACK was sent back
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("[UPTIME_PEER_HELLO_ACK]", args[2].text)

        # 2. Incoming [UPTIME_PEER_HELLO_ACK]
        mock_event.msg.text = '[UPTIME_PEER_HELLO_ACK]\n{"node_name": "Helsinki-Updated", "version": "2.0.0"}\n[/UPTIME_PEER_HELLO_ACK]'
        bot.on_new_message(mock_bot, 1, mock_event)
        p = database.get_peer("probe2@gluek.info")
        self.assertEqual(p["node_name"], "Helsinki-Updated")

        # 3. Incoming [UPTIME_PEER_METRICS]
        mock_event.msg.text = (
            '[UPTIME_PEER_METRICS]\n'
            '{"node_name": "Helsinki-Updated", "timestamp": 1700000000, "metrics": ['
            '{"url": "https://api.mytest.org", "status": "up", "latency_ms": 38}'
            ']}\n'
            '[/UPTIME_PEER_METRICS]'
        )
        bot.on_new_message(mock_bot, 1, mock_event)
        measurements = database.get_peer_measurements_for_url("https://api.mytest.org")
        self.assertEqual(len(measurements), 1)
        self.assertEqual(measurements[0]["node_name"], "Helsinki-Updated")
        self.assertEqual(measurements[0]["latency_ms"], 38)

        # 4. Incoming [UPTIME_PEER_CHECK_RESP]
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        fut = loop.create_future()
        responses = []
        bot.pending_peer_checks["req123"] = (fut, 1, responses)

        mock_event.msg.text = (
            '[UPTIME_PEER_CHECK_RESP]\n'
            '{"req_id": "req123", "url": "https://api.mytest.org", "status": "up", "latency_ms": 42, "node_name": "Helsinki-Updated"}\n'
            '[/UPTIME_PEER_CHECK_RESP]'
        )
        bot.on_new_message(mock_bot, 1, mock_event)
        self.assertTrue(fut.done())
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["latency_ms"], 42)

    def test_dashboard_renders_multi_node_badges(self):
        database.set_local_node_name("Frankfurt-DE")
        database.save_peer_measurement("https://multinode.org", "Helsinki-DO", "up", 35)
        database.save_peer_measurement("https://multinode.org", "RU-Moscow", "down", None, "502 Bad Gateway")

        resources = [{
            "id": 1,
            "dc_chat_id": 1234,
            "name": "MultiNode Service",
            "url": "https://multinode.org",
            "type": "http",
            "status": "up",
            "last_checked": int(time.time()),
            "last_latency_ms": 18
        }]

        html_out = bot.get_dashboard_html("Test Chat", resources, 100.0)
        self.assertIn("Frankfurt-DE", html_out)
        self.assertIn("Helsinki-DO", html_out)
        self.assertIn("RU-Moscow", html_out)
        self.assertIn("35ms", html_out)
        self.assertIn("18ms", html_out)

    def test_cross_probe_incident_verification(self):
        database.set_local_node_name("Frankfurt-DE")
        database.add_or_update_peer("peer@example.com", "Helsinki-DO", 101)

        rep = {"id": 1, "url": "https://cross-check-test.org", "type": "http", "name": "Cross Check"}
        group = [{"id": 1, "dc_chat_id": 100, "url": "https://cross-check-test.org", "type": "http", "name": "Cross Check", "status": "up"}]

        # 1. Simulate peer confirms DOWN
        with patch('asyncio.sleep', unittest.mock.AsyncMock()), \
             patch('bot.run_single_check', unittest.mock.AsyncMock(return_value=(False, "502 Bad Gateway", 100))), \
             patch('bot.check_host_internet_connectivity', unittest.mock.AsyncMock(return_value=True)), \
             patch('bot.request_peer_cross_checks', unittest.mock.AsyncMock(return_value=[{"node_name": "Helsinki-DO", "status": "down", "error_msg": "502"}])), \
             patch('bot.handle_check_result', unittest.mock.AsyncMock()) as mock_handle:
            sem = asyncio.Semaphore(1)
            asyncio.run(bot.check_group_task(group, sem))
            self.assertTrue(mock_handle.called)
            args, _ = mock_handle.call_args
            # Verify error message contains confirmed node
            self.assertIn("Confirmed by Helsinki-DO", args[2])

        # 2. Simulate peer reports UP (Regional issue)
        with patch('asyncio.sleep', unittest.mock.AsyncMock()), \
             patch('bot.run_single_check', unittest.mock.AsyncMock(return_value=(False, "502 Bad Gateway", 100))), \
             patch('bot.check_host_internet_connectivity', unittest.mock.AsyncMock(return_value=True)), \
             patch('bot.request_peer_cross_checks', unittest.mock.AsyncMock(return_value=[{"node_name": "Helsinki-DO", "status": "up", "latency_ms": 42}])), \
             patch('bot.handle_check_result', unittest.mock.AsyncMock()) as mock_handle:
            sem = asyncio.Semaphore(1)
            asyncio.run(bot.check_group_task(group, sem))
            self.assertTrue(mock_handle.called)
            args, _ = mock_handle.call_args
            # Verify error message contains reachable node info
            self.assertIn("Reachable from Helsinki-DO: 42ms", args[2])

    def test_dynamic_suffix_routing_between_different_bots(self):
        mock_bot_de = MagicMock()
        orig_parse_de = MagicMock()
        mock_bot_de._parse_command = orig_parse_de
        contact_de = MagicMock()
        contact_de.address = "uptimebot@chatmail.uk"
        mock_bot_de.rpc.get_contact.return_value = contact_de
        mock_bot_de.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}

        database.set_local_node_name("🇩🇪 DE")
        bot.setup_custom_command_parser(mock_bot_de)

        # 1. Bot DE with command /status@up -> matches
        event = MagicMock()
        event.msg.text = "/status@up"
        event.msg.chat_id = 100
        event.msg.__getitem__.side_effect = lambda k: "/status@up" if k == "text" else 100
        mock_bot_de._parse_command(1, event)
        # Should call original _parse_command with parsed command
        self.assertTrue(orig_parse_de.called)

        # 2. Bot RU (address ruptimebot@chat.gluek.info) with /status@up -> rejected
        mock_bot_ru = MagicMock()
        orig_parse_ru = MagicMock()
        mock_bot_ru._parse_command = orig_parse_ru
        contact_ru = MagicMock()
        contact_ru.address = "ruptimebot@chat.gluek.info"
        mock_bot_ru.rpc.get_contact.return_value = contact_ru
        mock_bot_ru.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}

        database.set_local_node_name("🇷🇺 RU")
        bot.setup_custom_command_parser(mock_bot_ru)

        event_ru = MagicMock()
        event_ru.msg.text = "/status@up"
        event_ru.msg.chat_id = 100
        event_ru.msg.__getitem__.side_effect = lambda k: "/status@up" if k == "text" else 100
        mock_bot_ru._parse_command(1, event_ru)
        self.assertEqual(event_ru.command, "")

        # 3. Bot RU with /status@ruptime -> matches
        event_ru_ok = MagicMock()
        event_ru_ok.msg.text = "/status@ruptime"
        event_ru_ok.msg.chat_id = 100
        event_ru_ok.msg.__getitem__.side_effect = lambda k: "/status@ruptime" if k == "text" else 100
        mock_bot_ru._parse_command(1, event_ru_ok)
        self.assertTrue(orig_parse_ru.called)

    def test_probe_targets_database_and_mirroring(self):
        targets = [
            {"url": "https://mirrored1.org", "name": "Mirrored 1", "type": "http", "expected_keyword": "hello"},
            {"url": "https://mirrored2.org", "name": "Mirrored 2", "type": "http"}
        ]
        database.save_probe_targets_batch(targets, "probe@example.com")
        active = database.get_active_probe_targets()
        self.assertEqual(len(active), 2)
        urls = [a["url"] for a in active]
        self.assertIn("https://mirrored1.org", urls)
        self.assertIn("https://mirrored2.org", urls)

        # Update probe target result
        database.update_probe_target_result("https://mirrored1.org", "up", 35, None)
        active_after = database.get_active_probe_targets()
        m1 = next(a for a in active_after if a["url"] == "https://mirrored1.org")
        self.assertEqual(m1["last_status"], "up")
        self.assertEqual(m1["last_latency_ms"], 35)

    def test_check_group_task_probe_only(self):
        database.set_local_node_name("RU-Moscow")
        group = [{
            "id": "probe_https://probeonly.org",
            "dc_chat_id": 0,
            "url": "https://probeonly.org",
            "name": "Probe Only Target",
            "type": "http",
            "is_probe_only": True
        }]
        sem = asyncio.Semaphore(1)
        with patch('bot.run_single_check', unittest.mock.AsyncMock(return_value=(True, "200 OK", 45))):
            asyncio.run(bot.check_group_task(group, sem))
        
        meas = database.get_peer_measurements_for_url("https://probeonly.org")
        self.assertTrue(any(m["node_name"] == "RU-Moscow" and m["latency_ms"] == 45 for m in meas))

    @patch('bot._is_dc_admin')
    def test_probe_ignore_and_unignore_commands(self, mock_is_admin):
        mock_is_admin.return_value = True
        mock_bot = MagicMock()
        mock_event = MagicMock()
        mock_event.msg.chat_id = 99
        mock_event.msg.from_id = 1
        database.set_local_node_name("RU-Probe")

        # 1. Ignore URL
        mock_event.payload = "https://blocked-in-ru.org"
        bot.probeignore_command(mock_bot, 1, mock_event)
        self.assertTrue(database.is_probe_target_ignored("https://blocked-in-ru.org"))
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("ignored", args[2].text)

        # 2. Incoming probe targets batch containing the ignored URL
        database.save_probe_targets_batch([
            {"url": "https://blocked-in-ru.org", "name": "Blocked"},
            {"url": "https://allowed.org", "name": "Allowed"}
        ], "de_node@chatmail.uk")
        active = database.get_active_probe_targets()
        urls = [a["url"] for a in active]
        self.assertNotIn("https://blocked-in-ru.org", urls)
        self.assertIn("https://allowed.org", urls)

        # 3. List ignored URLs
        mock_event.payload = ""
        bot.probeignore_command(mock_bot, 1, mock_event)
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("https://blocked-in-ru.org", args[2].text)

        # 4. Unignore URL
        mock_event.payload = "https://blocked-in-ru.org"
        bot.probeunignore_command(mock_bot, 1, mock_event)
        self.assertFalse(database.is_probe_target_ignored("https://blocked-in-ru.org"))
        args, kwargs = mock_bot.rpc.send_msg.call_args
        self.assertIn("removed from probe ignore list", args[2].text)

        # 5. Re-sync saves the unignored URL
        database.save_probe_targets_batch([
            {"url": "https://blocked-in-ru.org", "name": "Blocked"}
        ], "de_node@chatmail.uk")
        active_after = database.get_active_probe_targets()
        urls_after = [a["url"] for a in active_after]
        self.assertIn("https://blocked-in-ru.org", urls_after)

    def test_peer_liveness_audit_and_recovery(self):
        now = int(time.time())
        # 1. Setup peer with last_seen 10 minutes ago
        database.add_or_update_peer("dead_probe@example.com", "Dead-Probe", 111, now - 600)
        
        # 2. Audit offline peers (threshold 360s)
        offline = database.audit_peers_offline(threshold_seconds=360, now=now)
        self.assertEqual(len(offline), 1)
        self.assertEqual(offline[0]["email"], "dead_probe@example.com")
        self.assertEqual(offline[0]["is_offline"], 1)

        # 3. Second audit does not re-alert already offline peers
        offline2 = database.audit_peers_offline(threshold_seconds=360, now=now)
        self.assertEqual(len(offline2), 0)

        # 4. Peer recovers after 100 seconds
        recovered, downtime_sec, peer_data = database.update_peer_last_seen("dead_probe@example.com", now + 100)
        self.assertTrue(recovered)
        self.assertEqual(downtime_sec, 100)
        self.assertEqual(peer_data["node_name"], "Dead-Probe")

        # 5. Subsequent update does not trigger recovery again
        rec2, _, _ = database.update_peer_last_seen("dead_probe@example.com", now + 120)
        self.assertFalse(rec2)

    def test_send_admin_notification(self):
        database.set_config("admin_chat_id", "777")
        bot.dc_bot_instance = MagicMock()
        bot.dc_accid = 1
        with patch.object(bot, '_dc_send_msg_with_stats') as mock_send:
            asyncio.run(bot.send_admin_notification("Test Admin Alert"))
            mock_send.assert_called_once()
            args, _ = mock_send.call_args
            self.assertEqual(args[2], 777)
            self.assertIn("Test Admin Alert", args[3].text)

    def test_is_safe_target_url_ssrf_blocking(self):
        # Allowed public targets
        self.assertTrue(bot.is_safe_target_url("https://google.com", "http"))
        self.assertTrue(bot.is_safe_target_url("https://sub.domain.org/path?q=1", "http"))
        self.assertTrue(bot.is_safe_target_url("example.com:443", "tcp"))
        self.assertTrue(bot.is_safe_target_url("8.8.8.8", "ping"))

        # Blocked dangerous SSRF targets
        self.assertFalse(bot.is_safe_target_url("http://localhost/admin", "http"))
        self.assertFalse(bot.is_safe_target_url("http://127.0.0.1:8080", "http"))
        self.assertFalse(bot.is_safe_target_url("http://169.254.169.254/latest/meta-data/", "http"))
        self.assertFalse(bot.is_safe_target_url("http://10.0.0.1", "http"))
        self.assertFalse(bot.is_safe_target_url("http://192.168.1.1", "http"))
        self.assertFalse(bot.is_safe_target_url("http://172.16.0.1", "http"))
        self.assertFalse(bot.is_safe_target_url("http://0.0.0.0", "http"))
        self.assertFalse(bot.is_safe_target_url("127.0.0.1:5432", "tcp"))
        self.assertFalse(bot.is_safe_target_url("127.0.0.1", "ping"))
        self.assertFalse(bot.is_safe_target_url("invalid url!!", "http"))

    def test_peer_telemetry_deduplication(self):
        mock_bot = MagicMock()
        contact_mock = MagicMock()
        contact_mock.address = "mesh_peer@gluek.info"
        mock_bot.rpc.get_contact.return_value = contact_mock
        database.add_or_update_peer("mesh_peer@gluek.info", "Mesh-Node", 999)

        mock_event = MagicMock()
        mock_event.msg.is_info = False
        mock_event.msg.from_id = 12
        mock_event.msg.chat_id = 999
        mock_event.msg.text = (
            '[UPTIME_PEER_METRICS]\n'
            '{"node_name": "Mesh-Node", "msg_id": "test_unique_msg_1", "metrics": ['
            '{"url": "https://service-unique.org", "status": "up", "latency_ms": 25}'
            ']}\n'
            '[/UPTIME_PEER_METRICS]'
        )

        # First delivery: processed and saved
        bot.on_new_message(mock_bot, 1, mock_event)
        m = database.get_peer_measurements_for_url("https://service-unique.org")
        self.assertEqual(len(m), 1)

        # Clear measurements to verify duplicate is ignored
        with database._lock:
            conn = sqlite3.connect(database.DB_PATH)
            conn.cursor().execute("DELETE FROM peer_measurements")
            conn.commit()
            conn.close()

        # Second delivery with same msg_id: ignored!
        bot.on_new_message(mock_bot, 1, mock_event)
        m_after = database.get_peer_measurements_for_url("https://service-unique.org")
        self.assertEqual(len(m_after), 0)

if __name__ == '__main__':
    unittest.main()



