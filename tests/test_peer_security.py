import asyncio
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_peer_security_db.db"


def _wrap(tag: str, payload: dict) -> str:
    return f"[{tag}]\n{json.dumps(payload)}\n[/{tag}]"


class TestPeerFederationSecurity(unittest.TestCase):
    """Peer protocol hardening: who may become a peer, which messages are accepted, what is disclosed."""

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot.pending_peer_checks.clear()
        bot._processed_msg_ids.clear()
        bot._admin_chat_membership_cache.clear()
        bot._telemetry_rotation_offsets.clear()
        self.orig_dc_bot = bot.dc_bot_instance
        self.orig_accid = bot.dc_accid

    def tearDown(self):
        bot.dc_bot_instance = self.orig_dc_bot
        bot.dc_accid = self.orig_accid
        bot.pending_peer_checks.clear()
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            fpath = TEST_DB + suffix
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    # ---- helpers -------------------------------------------------------------

    def _make_bot(self, sender_addr: str, chat_type: str = "Single"):
        mock_bot = MagicMock()
        contact = MagicMock()
        contact.address = sender_addr
        mock_bot.rpc.get_contact.return_value = contact
        mock_bot.rpc.get_basic_chat_info.return_value = {"chat_type": chat_type}
        return mock_bot

    def _make_event(self, text: str, chat_id: int = 500, padlock: bool = True):
        event = MagicMock()
        event.msg.is_info = False
        event.msg.from_id = 42
        event.msg.chat_id = chat_id
        event.msg.text = text
        event.msg.show_padlock = padlock
        return event

    def _sent_texts(self, mock_bot):
        return [c.args[2].text for c in mock_bot.rpc.send_msg.call_args_list]

    def _metrics(self, url="https://peer-target.example.org", sender_email="attacker@evil.example", node="Fake"):
        return _wrap("UPTIME_PEER_METRICS", {
            "node_name": node,
            "sender_email": sender_email,
            "metrics": [{"url": url, "type": "http", "status": "down", "latency_ms": 1}],
        })

    # ---- HELLO / HELLO_ACK ---------------------------------------------------

    def test_hello_from_unknown_sender_without_token_is_ignored(self):
        mock_bot = self._make_bot("stranger@evil.example")
        event = self._make_event(_wrap("UPTIME_PEER_HELLO", {"node_name": "Evil"}))

        bot.on_new_message(mock_bot, 1, event)

        self.assertIsNone(database.get_peer("stranger@evil.example"))
        self.assertEqual(database.get_all_peers(), [])
        self.assertFalse(any("UPTIME_PEER_HELLO_ACK" in t for t in self._sent_texts(mock_bot)))

    def test_hello_with_invalid_token_is_ignored(self):
        database.create_peer_invite_token()
        mock_bot = self._make_bot("stranger@evil.example")
        event = self._make_event(_wrap("UPTIME_PEER_HELLO", {"node_name": "Evil", "invite_token": "guessed-token"}))

        bot.on_new_message(mock_bot, 1, event)

        self.assertIsNone(database.get_peer("stranger@evil.example"))

    def test_invite_token_is_single_use(self):
        token = database.create_peer_invite_token()

        first = self._make_bot("probe-a@example.org")
        bot.on_new_message(first, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "A", "invite_token": token}), chat_id=501))
        self.assertIsNotNone(database.get_peer("probe-a@example.org"))
        self.assertTrue(any("UPTIME_PEER_HELLO_ACK" in t for t in self._sent_texts(first)))

        second = self._make_bot("probe-b@example.org")
        bot.on_new_message(second, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "B", "invite_token": token}), chat_id=502))
        self.assertIsNone(database.get_peer("probe-b@example.org"))

    def test_invite_token_expires(self):
        token = database.create_peer_invite_token(ttl_seconds=60, now=1_000_000)
        self.assertFalse(database.consume_peer_invite_token(token, now=1_000_061))
        token2 = database.create_peer_invite_token(ttl_seconds=60, now=1_000_000)
        self.assertTrue(database.consume_peer_invite_token(token2, now=1_000_030))

    def test_hello_with_token_in_group_chat_is_ignored(self):
        token = database.create_peer_invite_token()
        mock_bot = self._make_bot("probe@example.org", chat_type="Group")
        bot.on_new_message(mock_bot, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "A", "invite_token": token})))

        self.assertIsNone(database.get_peer("probe@example.org"))
        # The token was not burnt by the rejected attempt
        self.assertTrue(database.consume_peer_invite_token(token))

    def test_hello_payload_sender_email_cannot_impersonate_peer(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("stranger@evil.example")
        bot.on_new_message(mock_bot, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "Hijacked", "sender_email": "trusted@example.org"})))

        self.assertEqual(database.get_peer("trusted@example.org")["node_name"], "Trusted")
        self.assertIsNone(database.get_peer("stranger@evil.example"))

    def test_hello_ack_from_unknown_sender_is_ignored(self):
        mock_bot = self._make_bot("stranger@evil.example")
        bot.on_new_message(mock_bot, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO_ACK", {"node_name": "Evil"})))
        self.assertIsNone(database.get_peer("stranger@evil.example"))

    def test_hello_from_known_peer_updates_without_token(self):
        database.add_or_update_peer("trusted@example.org", "Old-Name", 700)
        mock_bot = self._make_bot("trusted@example.org")
        bot.on_new_message(mock_bot, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO", {"node_name": "New-Name"}), chat_id=700))

        self.assertEqual(database.get_peer("trusted@example.org")["node_name"], "New-Name")
        self.assertTrue(any("UPTIME_PEER_HELLO_ACK" in t for t in self._sent_texts(mock_bot)))

    def test_securejoin_placeholder_is_rebound_to_real_address(self):
        database.add_or_update_peer("peer_888@securejoin", "London", 888)
        mock_bot = self._make_bot("real-probe@chatmail.example")
        bot.on_new_message(mock_bot, 1, self._make_event(
            _wrap("UPTIME_PEER_HELLO_ACK", {"node_name": "London"}), chat_id=888))

        self.assertIsNone(database.get_peer("peer_888@securejoin"))
        peer = database.get_peer("real-probe@chatmail.example")
        self.assertIsNotNone(peer)
        self.assertEqual(peer["chat_id"], 888)

    # ---- METRICS ---------------------------------------------------------------

    def test_metrics_from_non_peer_are_dropped(self):
        mock_bot = self._make_bot("attacker@evil.example")
        bot.on_new_message(mock_bot, 1, self._make_event(self._metrics()))

        self.assertEqual(database.get_peer_measurements_for_url("https://peer-target.example.org"), [])
        self.assertEqual(database.get_active_probe_targets(), [])

    def test_metrics_spoofing_peer_in_payload_are_dropped(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("attacker@evil.example")
        bot.on_new_message(mock_bot, 1, self._make_event(
            self._metrics(sender_email="trusted@example.org", node="Trusted"), chat_id=700))

        self.assertEqual(database.get_peer_measurements_for_url("https://peer-target.example.org"), [])
        self.assertEqual(database.get_active_probe_targets(), [])

    def test_unencrypted_metrics_from_peer_are_dropped(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("trusted@example.org")
        bot.on_new_message(mock_bot, 1, self._make_event(self._metrics(), chat_id=700, padlock=False))

        self.assertEqual(database.get_peer_measurements_for_url("https://peer-target.example.org"), [])

    def test_metrics_from_peer_in_group_chat_are_dropped(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("trusted@example.org", chat_type="Group")
        bot.on_new_message(mock_bot, 1, self._make_event(self._metrics(), chat_id=9000))

        self.assertEqual(database.get_peer_measurements_for_url("https://peer-target.example.org"), [])

    def test_metrics_from_peer_use_stored_node_name(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("trusted@example.org")
        bot.on_new_message(mock_bot, 1, self._make_event(self._metrics(node="Spoofed-Name"), chat_id=700))

        measurements = database.get_peer_measurements_for_url("https://peer-target.example.org")
        self.assertEqual(len(measurements), 1)
        self.assertEqual(measurements[0]["node_name"], "Trusted")
        targets = database.get_active_probe_targets()
        self.assertEqual(targets[0]["source_peer"], "trusted@example.org")

    def test_probe_targets_are_capped_per_peer(self):
        targets = [{"url": f"https://t{i}.example.org", "type": "http"} for i in range(10)]
        database.save_probe_targets_batch(targets, "peer@example.org", max_per_source=3)
        database.save_probe_targets_batch(
            [{"url": "https://another.example.org", "type": "http"}], "peer@example.org", max_per_source=3)
        self.assertEqual(len(database.get_active_probe_targets()), 3)

        # Refreshing already known targets is still allowed
        database.save_probe_targets_batch(targets[:3], "peer@example.org", max_per_source=3)
        self.assertEqual(len(database.get_active_probe_targets()), 3)

        # Another peer has its own budget
        database.save_probe_targets_batch(targets[5:7], "other@example.org", max_per_source=3)
        self.assertEqual(len(database.get_active_probe_targets()), 5)

    def test_remove_peer_drops_its_probe_targets(self):
        database.add_or_update_peer("peer@example.org", "P", 1)
        database.save_probe_targets_batch([{"url": "https://mirrored.example.org", "type": "http"}], "peer@example.org")
        database.save_probe_targets_batch([{"url": "https://kept.example.org", "type": "http"}], "other@example.org")

        self.assertTrue(database.remove_peer("peer@example.org"))
        urls = [t["url"] for t in database.get_active_probe_targets()]
        self.assertEqual(urls, ["https://kept.example.org"])

    # ---- CHECK_REQ / CHECK_RESP -----------------------------------------------

    def test_check_request_from_non_peer_is_ignored(self):
        mock_bot = self._make_bot("attacker@evil.example")
        event = self._make_event(_wrap("UPTIME_PEER_CHECK_REQ", {
            "req_id": "abc", "url": "https://victim.example.org", "type": "http"}))

        with patch("bot.run_single_check", AsyncMock(return_value=(True, "200 - OK", 5))) as mock_check, \
             patch("bot.is_safe_target_url", return_value=True):
            bot.on_new_message(mock_bot, 1, event)
            mock_check.assert_not_called()
        self.assertEqual(mock_bot.rpc.send_msg.call_count, 0)

    def _pending(self, req_id, senders):
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        fut = loop.create_future()
        responses = []
        bot.pending_peer_checks[req_id] = (fut, len(senders), responses, set(senders))
        return fut, responses

    def _resp(self, req_id, status="up"):
        return _wrap("UPTIME_PEER_CHECK_RESP", {
            "req_id": req_id, "url": "https://site.example.org", "status": status,
            "latency_ms": 10, "node_name": "Spoofed"})

    def test_check_response_from_non_peer_is_ignored(self):
        fut, responses = self._pending("req1", ["trusted@example.org"])
        mock_bot = self._make_bot("attacker@evil.example")
        bot.on_new_message(mock_bot, 1, self._make_event(self._resp("req1")))

        self.assertEqual(responses, [])
        self.assertFalse(fut.done())
        self.assertEqual(database.get_peer_measurements_for_url("https://site.example.org"), [])

    def test_check_response_from_peer_not_asked_is_ignored(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        database.add_or_update_peer("other@example.org", "Other", 701)
        fut, responses = self._pending("req2", ["trusted@example.org"])

        mock_bot = self._make_bot("other@example.org")
        bot.on_new_message(mock_bot, 1, self._make_event(self._resp("req2"), chat_id=701))

        self.assertEqual(responses, [])
        self.assertFalse(fut.done())

    def test_check_response_without_pending_request_is_not_stored(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        mock_bot = self._make_bot("trusted@example.org")
        bot.on_new_message(mock_bot, 1, self._make_event(self._resp("unknown-req"), chat_id=700))

        self.assertEqual(database.get_peer_measurements_for_url("https://site.example.org"), [])

    def test_check_response_counted_once_per_peer(self):
        database.add_or_update_peer("trusted@example.org", "Trusted", 700)
        database.add_or_update_peer("other@example.org", "Other", 701)
        fut, responses = self._pending("req3", ["trusted@example.org", "other@example.org"])

        mock_bot = self._make_bot("trusted@example.org")
        event = self._make_event(self._resp("req3"), chat_id=700)
        bot.on_new_message(mock_bot, 1, event)
        bot.on_new_message(mock_bot, 1, event)

        self.assertEqual(len(responses), 1)
        self.assertFalse(fut.done())
        self.assertEqual(responses[0]["node_name"], "Trusted")

    # ---- Outbound disclosure ---------------------------------------------------

    def _broadcast(self, admin_email=None, chat_members=None):
        mock_bot = MagicMock()
        mock_bot.rpc.lookup_contact_id_by_addr.return_value = 99 if admin_email else None
        mock_bot.rpc.get_chat_contacts.side_effect = lambda accid, chat_id: (chat_members or {}).get(chat_id, [])
        bot.dc_bot_instance = mock_bot
        bot.dc_accid = 1
        if admin_email:
            database.set_admin_email(admin_email)
        with patch.object(bot, "_dc_send_msg_with_stats") as mock_send, \
             patch.object(bot, "_get_self_addr", return_value="me@example.org"):
            asyncio.run(bot.broadcast_telemetry_to_peers())
        sent = {}
        for c in mock_send.call_args_list:
            chat_id = c.args[2]
            text = c.args[3].text
            sent[chat_id] = json.loads(text.split("\n", 1)[1].rsplit("\n", 1)[0])
        return sent

    def _seed_resources(self):
        database.add_resource(100, "https://admin-site.example.org", "Admin Secret Name", "http")
        database.add_resource(200, "https://user-site.example.org", "Other User Site", "http")
        database.add_resource(300, "https://group-site.example.org", "Admin Group Site", "http")

    def _urls(self, payload):
        return sorted(m["url"] for m in payload["metrics"])

    def test_broadcast_admin_scope_only_shares_admin_chats(self):
        database.add_or_update_peer("peer@example.org", "P", 555)
        database.set_config("admin_chat_id", "100")
        self._seed_resources()

        sent = self._broadcast(admin_email="admin@example.org", chat_members={300: [99, 12], 200: [13]})

        self.assertEqual(self._urls(sent[555]), ["https://admin-site.example.org", "https://group-site.example.org"])
        self.assertNotIn("Admin Secret Name", json.dumps(sent[555]))

    def test_broadcast_all_scope_shares_every_chat(self):
        database.add_or_update_peer("peer@example.org", "P", 555)
        database.set_peer_share_scope("all")
        self._seed_resources()

        sent = self._broadcast()
        self.assertEqual(len(sent[555]["metrics"]), 3)

    def test_broadcast_none_scope_only_returns_requested_probe_results(self):
        database.add_or_update_peer("peer-a@example.org", "A", 555)
        database.add_or_update_peer("peer-b@example.org", "B", 556)
        database.set_peer_share_scope("none")
        self._seed_resources()
        database.save_probe_targets_batch([{"url": "https://a-target.example.org", "type": "http"}], "peer-a@example.org")

        sent = self._broadcast()
        self.assertEqual(self._urls(sent[555]), ["https://a-target.example.org"])
        self.assertNotIn(556, sent)

    def test_broadcast_does_not_relay_probe_targets_to_other_peers(self):
        database.add_or_update_peer("peer-a@example.org", "A", 555)
        database.add_or_update_peer("peer-b@example.org", "B", 556)
        database.set_config("admin_chat_id", "100")
        database.add_resource(100, "https://admin-site.example.org", "Admin", "http")
        database.save_probe_targets_batch([{"url": "https://a-private.example.org", "type": "http"}], "peer-a@example.org")

        sent = self._broadcast()
        self.assertIn("https://a-private.example.org", self._urls(sent[555]))
        self.assertNotIn("https://a-private.example.org", self._urls(sent[556]))
        self.assertIn("https://admin-site.example.org", self._urls(sent[556]))

    def test_cross_check_skipped_for_monitors_outside_share_scope(self):
        database.add_or_update_peer("peer@example.org", "P", 101)
        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.lookup_contact_id_by_addr.return_value = None
        bot.dc_accid = 1
        group = [{"id": 1, "dc_chat_id": 200, "url": "https://user-site.example.org", "type": "http",
                  "name": "User", "status": "up"}]

        with patch("asyncio.sleep", AsyncMock()), \
             patch("bot.run_single_check", AsyncMock(return_value=(False, "502 Bad Gateway", 100))), \
             patch("bot.check_host_internet_connectivity", AsyncMock(return_value=True)), \
             patch("bot.request_peer_cross_checks", AsyncMock(return_value=[])) as mock_cross, \
             patch("bot.handle_check_result", AsyncMock()):
            asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
            mock_cross.assert_not_called()

    @patch("bot.fetch_html_title", return_value=None)
    @patch("bot._is_dc_admin", return_value=False)
    @patch("bot.run_single_check")
    @patch("bot.request_peer_cross_checks")
    def test_ping_from_non_admin_does_not_reach_peers_by_default(self, mock_cross, mock_check, mock_is_admin, mock_title):
        mock_check.return_value = (True, "200 - OK", 35)
        database.add_or_update_peer("peer@example.org", "P", 777)
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 12345
        event.payload = "https://example.com"

        bot.ping_command(mock_bot, 1, event)
        mock_cross.assert_not_called()

    # ---- Commands --------------------------------------------------------------

    @patch("bot._is_dc_admin", return_value=True)
    def test_invitepeer_and_addpeer_carry_one_time_token(self, mock_is_admin):
        mock_bot = MagicMock()
        mock_bot.rpc.get_chat_securejoin_qr_code.return_value = "https://i.delta.chat/#invite"
        event = MagicMock()
        event.msg.chat_id = 1
        event.payload = ""

        bot.invitepeer_command(mock_bot, 1, event)
        reply = mock_bot.rpc.send_msg.call_args.args[2].text
        token = reply.split("token=", 1)[1].split()[0]
        self.assertTrue(database.consume_peer_invite_token(token))

        mock_bot.rpc.reset_mock()
        mock_bot.rpc.check_qr.return_value = {"address": "remote@chatmail.example"}
        mock_bot.rpc.secure_join.return_value = 321
        event.payload = "https://i.delta.chat/#invite token=abc123 Frankfurt DE"
        bot.addpeer_command(mock_bot, 1, event)

        peer = database.get_peer("remote@chatmail.example")
        self.assertEqual(peer["node_name"], "Frankfurt DE")
        hello = next(c.args[2].text for c in mock_bot.rpc.send_msg.call_args_list if c.args[1] == 321)
        self.assertEqual(json.loads(hello.split("\n")[1])["invite_token"], "abc123")

    @patch("bot._is_dc_admin", return_value=True)
    def test_peershare_command(self, mock_is_admin):
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = 1

        event.payload = "none"
        bot.peershare_command(mock_bot, 1, event)
        self.assertEqual(database.get_peer_share_scope(), "none")

        event.payload = "everything"
        bot.peershare_command(mock_bot, 1, event)
        self.assertEqual(database.get_peer_share_scope(), "none")
        self.assertIn("Usage", mock_bot.rpc.send_msg.call_args.args[2].text)

        mock_is_admin.return_value = False
        event.payload = "all"
        bot.peershare_command(mock_bot, 1, event)
        self.assertEqual(database.get_peer_share_scope(), "none")


class _FakeResp:
    def __init__(self, status, location=None, url=""):
        self.status = status
        self.headers = {"Location": location} if location else {}
        self.url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append((url, kwargs))
        return self.responses[url]

    head = get


class TestSafeRedirects(unittest.TestCase):
    def setUp(self):
        bot._dns_cache.clear()

    def _run(self, coro):
        return asyncio.run(coro)

    async def _fetch_status(self, sess, url):
        async with bot._safe_http_request(sess, "GET", url) as resp:
            return resp.status

    def test_redirect_to_private_address_is_blocked(self):
        sess = _FakeSession({
            "https://public.example.org/": _FakeResp(302, "http://127.0.0.1:8080/admin", "https://public.example.org/"),
        })
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            with self.assertRaises(Exception) as ctx:
                self._run(self._fetch_status(sess, "https://public.example.org/"))
        self.assertIn("blocked", str(ctx.exception))
        self.assertEqual(len(sess.requested), 1)
        self.assertFalse(sess.requested[0][1]["allow_redirects"])

    def test_safe_redirect_is_followed(self):
        sess = _FakeSession({
            "https://public.example.org/": _FakeResp(301, "/new", "https://public.example.org/"),
            "https://public.example.org/new": _FakeResp(200, url="https://public.example.org/new"),
        })
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            status = self._run(self._fetch_status(sess, "https://public.example.org/"))
        self.assertEqual(status, 200)
        self.assertEqual([u for u, _ in sess.requested], ["https://public.example.org/", "https://public.example.org/new"])

    def test_redirect_loop_is_bounded(self):
        sess = _FakeSession({
            "https://loop.example.org/": _FakeResp(302, "https://loop.example.org/", "https://loop.example.org/"),
        })
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            with self.assertRaises(Exception):
                self._run(self._fetch_status(sess, "https://loop.example.org/"))
        self.assertEqual(len(sess.requested), bot._MAX_SAFE_REDIRECTS + 1)

    def test_title_fetch_redirect_to_private_address_is_blocked(self):
        import urllib.error
        opener = bot._safe_url_opener()
        handler = next(h for h in opener.handlers if h.__class__.__name__ == "_SafeRedirectHandler")
        req = MagicMock()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/")


if __name__ == "__main__":
    unittest.main()
