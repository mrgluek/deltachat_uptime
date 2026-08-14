import os
import sys
import unittest
import time
import datetime
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
        database.set_config("resilient_mode", "0")
        mock_event.payload = ""
        bot.resilient_command(mock_bot, 1, mock_event)
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("currently DISABLED", args[3].text)

        # Case 2: Turn ON with /resilient on
        mock_event.payload = "on"
        bot.resilient_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_config("resilient"), "1")

        # Case 3: Status query when enabled
        mock_event.payload = ""
        bot.resilient_command(mock_bot, 1, mock_event)
        args, kwargs = mock_send_with_stats.call_args
        self.assertIn("currently ENABLED", args[3].text)

        # Case 4: Turn OFF with /resilient off
        mock_event.payload = "off"
        bot.resilient_command(mock_bot, 1, mock_event)
        self.assertEqual(database.get_config("resilient"), "0")

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

    def test_dashboard_ssl_html(self):
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
        html_out = bot.get_dashboard_html("Test Chat", resources, 100.0)
        self.assertIn("SSL Cert", html_out)
        self.assertIn("45d left", html_out)

if __name__ == '__main__':
    unittest.main()

