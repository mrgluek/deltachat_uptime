import asyncio
import collections
import json
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
from outbox import Outbox
from test_peer_seam import _DbCase, inline_peer_metrics


class _PeerCase(_DbCase):
    url = "https://site.example.org"

    def setUp(self):
        super().setUp()
        self.rpc_bot = MagicMock()
        self.peer = self.add_peer("trusted@example.org", "Trusted", 700)
        self.enterContext(patch.object(bot, "async_event_loop", None))
        self.enterContext(patch.object(bot, "is_safe_target_url", return_value=True))

    def add_peer(self, email, name, chat, **kwargs):
        database.add_or_update_peer(email, name, chat, **kwargs)
        return database.get_peer(email)


class TestPeerAnswerCache(_PeerCase):
    def setUp(self):
        super().setUp()
        self.admission = self.enterContext(patch.object(bot, "_inbound_probes", bot.InboundProbeAdmission()))
        self.outbox = self.enterContext(patch.object(bot, "dc_outbox", Outbox()))
        self.enterContext(patch.object(bot, "_prewarm_target_dns", AsyncMock(return_value=True)))
        self.check = self.enterContext(patch.object(bot, "run_single_check", AsyncMock(return_value=(True, None, 12))))

    def request(self, req_id="abc", *, peer=None, batch=False):
        peer = peer or self.peer
        target = {"url": self.url, "type": "http"}
        data = {"req_id": req_id, "node_name": "Same name in every request"}
        if batch:
            bot.handle_peer_check_batch_req(self.rpc_bot, 1, peer, peer["chat_id"], dict(data, targets=[target]))
        else:
            bot.handle_peer_check_req(self.rpc_bot, 1, peer, peer["chat_id"], dict(data, **target))

    def sent(self):
        return [(args[1], args[2].text) for args, _ in self.rpc_bot.rpc.send_msg.call_args_list]

    def test_repeats_resend_the_same_answer_without_admission(self):
        with patch.object(self.admission, "acquire", wraps=self.admission.acquire) as acquire, \
             patch.object(self.outbox, "submit", wraps=self.outbox.submit) as submit:
            for batch, kind, label in ((False, "CHECK_RESP", "cross-check answer"),
                                       (True, "CHECK_BATCH_RESP", "batch cross-check answer")):
                with self.subTest(kind=kind):
                    self.rpc_bot.rpc.send_msg.reset_mock()
                    self.check.reset_mock()
                    acquire.reset_mock()
                    submit.reset_mock()
                    for _ in range(3):
                        self.request(kind, batch=batch)
                    sent = self.sent()
                    self.assertEqual(len(sent), 2)
                    self.assertTrue(sent[0][1].startswith(f"[UPTIME_PEER_{kind}]\n"))
                    self.assertEqual(sent, [sent[0]] * 2)
                    self.check.assert_awaited_once()
                    acquire.assert_called_once_with(self.peer, kind, 1)
                    self.assertEqual(self.admission.outstanding, {})
                    self.assertEqual([c.kwargs for c in submit.call_args_list], [
                        dict(priority=bot.PRIO_PEER, expires_in=bot.PEER_ANSWER_TTL, label=label,
                             key=("peer_answer", self.peer["email"], kind), kind="peer_other"),
                    ] * 2)

    def test_repeat_during_probe_is_ignored(self):
        async def scenario(batch):
            started, finish = asyncio.Event(), asyncio.Event()

            async def probe(_):
                started.set()
                await finish.wait()
                return True, None, 12

            self.check.side_effect = probe
            self.request(str(batch), batch=batch)
            pending = asyncio.all_tasks() - {asyncio.current_task()}
            await asyncio.wait_for(started.wait(), 5)
            self.request(str(batch), batch=batch)
            self.assertEqual(self.sent(), [])
            self.assertEqual(dict(self.admission.outstanding), {self.peer["email"]: 1})
            finish.set()
            await asyncio.wait_for(asyncio.gather(*pending), 5)
            self.assertEqual(len(self.sent()), 1)
            self.check.assert_awaited_once()

        for batch in (False, True):
            with self.subTest(batch=batch):
                self.rpc_bot.rpc.send_msg.reset_mock()
                self.check.reset_mock()
                asyncio.run(scenario(batch))

    def test_cache_starts_when_the_answer_is_sent(self):
        with patch.object(self.outbox, "submit", side_effect=lambda *args, **kwargs: Future()) as submit, \
             patch.object(bot, "time", wraps=bot.time) as clock:
            clock.monotonic.return_value = 1000
            self.request()
            clock.monotonic.return_value = 1010
            self.request()  # queued for mail
            self.assertEqual(self.sent(), [])
            submit.assert_called_once()
            self.check.assert_awaited_once()
            submit.call_args.args[0]()  # deliver the original

            clock.monotonic.return_value = 1129
            self.request()
            self.assertEqual(submit.call_count, 2)
            self.check.assert_awaited_once()
            submit.call_args.args[0]()  # a replay does not extend the cache lifetime

            clock.monotonic.return_value = 1130
            self.request()
            self.assertEqual(self.check.await_count, 2)
            self.assertEqual(submit.call_count, 3)

    def test_cache_evicts_the_oldest_answer_and_drops_expired_entries(self):
        key = self.peer["email"]
        with patch.object(bot, "time", wraps=bot.time) as clock:
            for i in range(2001):
                clock.monotonic.return_value = 1000 + i / 100
                self.admission.remember_answer((key, str(i)), "CHECK_RESP", {"req_id": str(i)}, via="mail")
            self.assertEqual(len(self.admission.answers), 2000)
            self.assertEqual(self.admission.reserve_replay(self.peer, "0", "mail"), (False, None))
            self.assertEqual(self.admission.reserve_replay(self.peer, "1", "mail")[1][1], {"req_id": "1"})
            self.assertEqual(self.admission.reserve_replay(self.peer, "2000", "mail")[1][1], {"req_id": "2000"})
            clock.monotonic.return_value = 1140
            self.assertEqual(self.admission.reserve_replay(self.peer, "2000", "mail"), (False, None))
            self.assertEqual(self.admission.answers, {})

    def test_same_req_id_is_isolated_by_verified_peer_identity(self):
        peer_a = self.add_peer("a@example.org", "A", 701, fingerprint="A" * 40)
        peer_b = self.add_peer("b@example.org", "B", 702, fingerprint="B" * 40)
        self.check.side_effect = [(True, None, 12), (False, "timeout", 37)]
        self.request(peer=peer_a)
        self.request(peer=peer_b)
        self.request(peer=dict(peer_a, email="relay@example.org", chat_id=703))
        self.request(peer=peer_b)

        sent = self.sent()
        self.assertEqual([chat for chat, _ in sent], [701, 702, 703, 702])
        self.assertEqual([json.loads(message.splitlines()[1])["latency_ms"] for _, message in sent], [12, 37, 12, 37])
        self.assertEqual(self.check.await_count, 2)


class TestPeerMetricsDedupe(_PeerCase):
    def setUp(self):
        super().setUp()
        inline_peer_metrics(self)
        self.enterContext(patch.object(bot, "_processed_msg_ids", bot._ProcessedMessageIds()))
        self.enterContext(patch.object(bot, "_peer_metrics_timestamps", collections.OrderedDict()))
        self.enterContext(patch.object(bot, "_scheduler_cache", {}))
        self.report = self.enterContext(patch.object(bot, "note_peer_reported_down"))

    def metrics(self, msg_id, *, peer=None, **fields):
        peer = peer or self.peer
        status = fields.pop("status", "up")
        data = {"msg_id": msg_id, "metrics": [{"url": self.url, "type": "http", "status": status, "name": msg_id}]}
        bot.handle_peer_metrics(self.rpc_bot, 1, peer, peer["chat_id"], dict(data, **fields))

    def assert_applied(self, expected_name, expected_status):
        measurement, = database.get_peer_measurements_for_url(self.url)
        target, = database.get_active_probe_targets()
        self.assertEqual(measurement["status"], expected_status)
        self.assertEqual(target["name"], expected_name)

    def test_processed_message_ids_evict_in_insertion_order(self):
        with patch.object(bot, "_record_peer_activity"):
            for i in range(2000):
                self.metrics(str(i), metrics=[])
            self.metrics("0", metrics=[])  # a duplicate leaves the FIFO position alone
            self.metrics("2000", metrics=[])
            identity = bot._peer_identity(self.peer)
            self.assertEqual(list(bot._processed_msg_ids), [(identity, str(i)) for i in range(1, 2001)])
            self.metrics("0", metrics=[])
            self.assertEqual(list(bot._processed_msg_ids), [(identity, str(i)) for i in range(2, 2001)]
                             + [(identity, "0")])

    def test_stale_metrics_keep_the_newer_measurement_and_target_and_refresh_last_seen(self):
        with patch.object(database, "time", wraps=database.time) as clock:
            self.metrics("new", timestamp=200)
            last_seen = database.get_peer(self.peer["email"])["last_seen"]
            clock.time.return_value = last_seen + 10
            self.metrics("old", timestamp=100, status="down", node_name="Old name")
        self.assert_applied("new", "up")
        peer = database.get_peer(self.peer["email"])
        self.assertEqual(peer["last_seen"], last_seen + 10)
        self.assertEqual(peer["node_name"], self.peer["node_name"])
        self.report.assert_called_once()

    def test_newer_and_equal_timestamps_apply_with_message_id_dedupe(self):
        self.metrics("old", timestamp=100, status="down")
        self.assert_applied("old", "down")
        self.metrics("new", timestamp=200)
        self.assert_applied("new", "up")
        self.metrics("same timestamp", timestamp=200, status="down")
        self.metrics("same timestamp", timestamp=200)
        self.assert_applied("same timestamp", "down")
        self.assertEqual(self.report.call_count, 3)

    def test_missing_and_invalid_timestamps_apply_without_resetting_the_guard(self):
        self.metrics("new", timestamp=200)
        self.metrics("missing", status="down")
        self.assert_applied("missing", "down")
        self.metrics("invalid", timestamp="300")
        self.assert_applied("invalid", "up")
        self.metrics("old", timestamp=100, status="down")
        self.assert_applied("invalid", "up")

    def test_timestamps_are_peer_specific_and_reset_on_removal(self):
        other = self.add_peer("other@example.org", "Other", 701)
        self.metrics("new", timestamp=200)
        self.metrics("other", peer=other, timestamp=100)
        self.assertEqual(self.report.call_count, 2)

        bound = database.bind_peer_identity(self.peer["email"], fingerprint="A" * 40)
        self.metrics("bound", peer=bound, timestamp=200)
        with patch.object(bot, "_is_dc_admin", return_value=True):
            bot.rmpeer_command(self.rpc_bot, 1, SimpleNamespace(payload=self.peer["email"],
                                                               msg=SimpleNamespace(from_id=1, chat_id=123)))
        self.assertIsNone(database.get_peer(self.peer["email"]))
        self.assertNotIn(bound["fingerprint"], bot._peer_metrics_timestamps)
        peer = self.add_peer(self.peer["email"], "Re-added", 702)
        self.metrics("after removal", peer=peer, timestamp=100, status="down")
        self.assertEqual(self.report.call_count, 4)
        self.assertEqual(self.report.call_args.args[0], "Re-added")

    def test_unapplied_batches_do_not_advance_the_timestamp(self):
        self.metrics("empty", timestamp=200, metrics=[])
        self.metrics("valid", timestamp=100)
        self.assert_applied("valid", "up")
