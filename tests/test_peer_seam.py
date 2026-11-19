import asyncio
import json
import unittest
from concurrent.futures import Future
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox
from test_peer_scaling import _DbCase


class TestPeerSend(unittest.TestCase):
    def test_mail_matches_pre_seam_format_and_outbox_options(self):
        local = {"node_name": "Zürich 🛰️", "sender_email": "local@example.org", "version": "2.42.0"}
        target = {"url": "https://site.example.org", "type": "http", "expected_keyword": "café", "family": 6}
        req = {"req_id": "abc", "node_name": local["node_name"], "caps": ["batch_check"]}
        result = {"status": "up", "latency_ms": 12, "error_msg": None}
        cases = (
            ("HELLO", dict(local, invite_token="token"), bot.PRIO_PEER, None, "peer hello"),
            ("HELLO_ACK", local, bot.PRIO_PEER, None, "peer hello ack"),
            ("CHECK_REQ", dict(req, **target), bot.PRIO_PEER, 6.5, "cross-check request"),
            ("CHECK_RESP", dict(req, url=target["url"], **result), bot.PRIO_PEER, bot.PEER_ANSWER_TTL,
             "cross-check answer"),
            ("CHECK_BATCH_REQ", dict(req, targets=[target]), bot.PRIO_PEER, bot.CROSS_CHECK_BATCH_TIMEOUT,
             "batch cross-check request"),
            ("CHECK_BATCH_RESP", dict(req, results=[result]), bot.PRIO_PEER, bot.PEER_ANSWER_TTL,
             "batch cross-check answer"),
            ("METRICS", dict(local, metrics=[dict(target, **result)]), bot.PRIO_TELEMETRY, 120,
             "telemetry to peer@example.org"),
        )

        rpc_bot = MagicMock()
        rpc_bot.rpc.send_msg.return_value = 42
        peer = bot._PeerDestination(rpc_bot, 1, 7)
        with patch.object(bot, "dc_outbox", Outbox()) as outbox, \
             patch.object(outbox, "submit", wraps=outbox.submit) as submit, \
             patch.object(bot, "stat_event"), patch.object(database, "record_peer_traffic"):
            for kind, payload, priority, expires_in, label in cases:
                with self.subTest(kind=kind):
                    key = ("telemetry", 7) if kind == "METRICS" else None
                    mail_kind = {"CHECK_BATCH_REQ": "peer_vote", "METRICS": "peer_metrics"}.get(kind, "peer_other")
                    send = bot.peer_send(peer, kind, payload, priority=priority, expires_in=expires_in,
                                         label=label, key=key, mail_kind=mail_kind)
                    # The envelope and default json.dumps settings from the former send sites.
                    expected = f"[UPTIME_PEER_{kind}]\n{json.dumps(payload)}\n[/UPTIME_PEER_{kind}]"
                    accid, chat_id, message = rpc_bot.rpc.send_msg.call_args.args
                    self.assertEqual((accid, chat_id, send), (1, 7, 42))
                    self.assertEqual(message.text.encode("utf-8"), expected.encode("utf-8"))
                    self.assertEqual(submit.call_args.kwargs,
                                     dict(priority=priority, expires_in=expires_in, label=label, key=key, kind=mail_kind))

    def test_securejoin_hello_keeps_outbox_future_and_peer_traffic_count(self):
        rpc_bot = MagicMock()
        rpc_bot.rpc.send_msg.return_value = 42
        peer = bot._PeerDestination(rpc_bot, 1, 7, securejoin_hello=True)
        payload = {"node_name": "Zürich", "invite_token": "token"}
        expected = f"[UPTIME_PEER_HELLO]\n{json.dumps(payload)}\n[/UPTIME_PEER_HELLO]"
        with patch.object(bot, "dc_outbox", Outbox()) as outbox, \
             patch.object(outbox, "submit", wraps=outbox.submit) as submit, \
             patch.object(bot, "stat_event") as stat, patch.object(database, "record_peer_traffic") as traffic:
            future = bot.peer_send(peer, "HELLO", payload, priority=bot.PRIO_PEER, expires_in=None, label="peer hello")
        self.assertEqual(future.result(), 42)
        self.assertEqual(rpc_bot.rpc.send_msg.call_args.args[2].text.encode(), expected.encode())
        self.assertEqual(submit.call_args.kwargs,
                         dict(priority=bot.PRIO_PEER, expires_in=None, label="peer hello", key=None, kind="peer_other"))
        traffic.assert_called_once_with("HELLO", "mail", "out", len(expected.encode()))
        stat.assert_not_called()

    def test_callbacks_run_at_delivery(self):
        rpc_bot = MagicMock()
        peer = bot._PeerDestination(rpc_bot, 1, 7)
        calls = []
        rpc_bot.rpc.send_msg.side_effect = lambda *_: calls.append("rpc")
        with patch.object(bot.dc_outbox, "submit", return_value=Future()) as submit, \
             patch.object(bot, "stat_event"), patch.object(database, "record_peer_traffic"):
            bot.peer_send(peer, "CHECK_REQ", {"req_id": "abc"}, priority=bot.PRIO_PEER, expires_in=6.5,
                          label="cross-check request", before_send=lambda: calls.append("before"),
                          after_send=lambda: calls.append("after"))
            self.assertEqual(calls, [])
            submit.call_args.args[0]()
        self.assertEqual(calls, ["before", "rpc", "after"])


class TestPeerHandlers(_DbCase):
    def setUp(self):
        super().setUp()
        self.chat_id = 700
        self.url = "https://site.example.org"
        self.rpc_bot = MagicMock()
        database.add_or_update_peer("trusted@example.org", "Trusted", self.chat_id)
        self.peer = database.get_peer("trusted@example.org")
        self.enterContext(patch.object(bot, "async_event_loop", None))
        self.enterContext(patch.object(bot, "is_safe_target_url", return_value=True))

    def test_check_req_probes_and_answers(self):
        data = {"req_id": "abc", "url": self.url, "expected_keyword": "hello", "family": 6}
        with patch.object(bot, "_submit_inbound_probe") as submit, \
             patch.object(bot, "_prewarm_target_dns", AsyncMock(return_value=True)), \
             patch.object(bot, "run_single_check", AsyncMock(return_value=(True, None, 12))) as check, \
             patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.handle_peer_check_req(self.rpc_bot, 1, self.peer, self.chat_id, data)
            peer, req_id, reply = submit.call_args.args
            self.assertEqual((peer, req_id), (self.peer, "abc"))
            asyncio.run(reply())
        check.assert_awaited_once_with({"id": 0, "url": self.url, "type": "http",
                                        "expected_keyword": "hello", "family": 6})
        self.assertEqual(send.call_args.args[:3], (self.rpc_bot, 1, self.chat_id))
        response = json.loads(send.call_args.args[3].text.splitlines()[1])
        self.assertEqual((response["req_id"], response["status"], response["latency_ms"]), ("abc", "up", 12))

    def test_check_batch_req_reserves_workers_and_keeps_refused_positions(self):
        data = {"req_id": "abc", "targets": [{"url": self.url, "type": "http"}, "invalid"]}
        with patch.object(bot, "_submit_inbound_probe") as submit, \
             patch.object(bot, "_answer_batch_cross_check", AsyncMock()) as answer:
            bot.handle_peer_check_batch_req(self.rpc_bot, 1, self.peer, self.chat_id, data)
            peer, req_id, reply, workers = submit.call_args.args
            self.assertEqual((peer, req_id, workers), (self.peer, "abc", 2))
            asyncio.run(reply())
        answer.assert_awaited_once_with(self.rpc_bot, 1, self.chat_id, "abc",
                                       [{"id": 0, "url": self.url, "type": "http",
                                         "expected_keyword": None, "family": None}, None], 2,
                                       fingerprint=None, via="mail")

    def test_check_resp_stores_only_the_first_answer_for_a_chat(self):
        future, responses, chats = Future(), [], {self.chat_id}
        timing = bot._PeerRtt("ping", self.peer)
        data = {"req_id": "abc", "url": self.url, "status": "up", "latency_ms": 12}
        with patch.object(bot, "pending_peer_checks", {"abc": (future, 1, responses, chats)}), \
             patch.object(bot, "_pending_peer_rtt", {"abc": {self.chat_id: timing}}):
            bot.handle_peer_check_resp(self.rpc_bot, 1, self.peer, self.chat_id + 1, data)
            self.assertFalse(future.done())
            bot.handle_peer_check_resp(self.rpc_bot, 1, self.peer, self.chat_id, data)
            bot.handle_peer_check_resp(self.rpc_bot, 1, self.peer, self.chat_id, dict(data, status="down"))
        self.assertEqual(chats, set())
        self.assertEqual(future.result(), [dict(data, node_name="Trusted", error_msg=None)])
        self.assertEqual(timing.answer[1], "Trusted")
        measurement, = database.get_peer_measurements_for_url(self.url)
        self.assertEqual(measurement["status"], "up")

    def test_check_batch_resp_accepts_only_expected_chat_and_positions(self):
        future = Future()
        data = {"req_id": "abc", "results": [{"url": self.url, "status": "up", "latency_ms": 12}]}
        with patch.object(bot, "pending_batch_checks", {"abc": (future, self.chat_id, 2)}):
            bot.handle_peer_check_batch_resp(self.rpc_bot, 1, self.peer, self.chat_id + 1, data)
            self.assertFalse(future.done())
            bot.handle_peer_check_batch_resp(self.rpc_bot, 1, self.peer, self.chat_id, data)
        self.assertEqual(future.result(), [
            {"url": None, "status": "up", "latency_ms": 12, "error_msg": None, "node_name": "Trusted"},
            {"url": None, "status": "unknown", "latency_ms": None, "error_msg": None, "node_name": "Trusted"},
        ])

    def test_metrics_saves_measurements_mirrors_targets_and_deduplicates(self):
        data = {"msg_id": "abc", "metrics": [{"url": self.url, "type": "http", "status": "down", "latency_ms": 12}]}
        with patch.object(bot, "_processed_msg_ids", set()), patch.object(bot, "_scheduler_cache", {}), \
             patch.object(bot, "note_peer_reported_down") as report:
            bot.handle_peer_metrics(self.rpc_bot, 1, self.peer, self.chat_id, data)
            bot.handle_peer_metrics(self.rpc_bot, 1, self.peer, self.chat_id, data)
        measurement, = database.get_peer_measurements_for_url(self.url)
        target, = database.get_active_probe_targets()
        self.assertEqual((measurement["node_name"], measurement["status"]), ("Trusted", "down"))
        self.assertEqual((target["url"], target["source_peer"]), (self.url, self.peer["email"]))
        report.assert_called_once()
        self.assertEqual(report.call_args.args[0], "Trusted")
