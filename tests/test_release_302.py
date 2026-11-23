"""3.0.2: probe admission under a grid batch, own-fingerprint cache, trim without the realtime lock."""
import asyncio
import json
import threading
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import database
import dc_fingerprint
from test_audit4_fixes import AuditCase

SELF_FP = "D58B5E6C55482F94F9F5B84B6FB9FE3AD2658082"
PEER_FP = "DEC0E8D11FC4686F2C715C56F8C9AD699BC19AD8"


def sent_texts(client):
    return [call.args[2].text for call in client.rpc.send_msg.call_args_list]


class TestProbeAdmissionUnderGrid(AuditCase):
    timeout = 10

    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.object(bot, "_prewarm_target_dns", return_value=True))
        self.stack.enter_context(patch.object(bot, "is_safe_target_url", return_value=True))
        # Send the answer straight to the fake client
        self.sent = []
        self.stack.enter_context(patch.object(
            bot, "_send_peer_check_answer", side_effect=lambda dest, kind, payload, **kw: self.sent.append((kind, payload))))

    def test_batch_reserves_at_most_five_slots(self):
        peer = self.peer()
        admission = bot.InboundProbeAdmission()
        outcome, reservation = admission.acquire(peer, "grid", min(bot.PEER_BATCH_WORKERS_MAX, 11))
        self.assertIs(outcome, bot._ProbeAdmission.ACCEPTED)
        self.assertEqual(reservation[1], 5)
        outcome, second = admission.acquire(peer, "urgent", 1)
        self.assertIs(outcome, bot._ProbeAdmission.ACCEPTED)

    def test_request_that_does_not_fit_gets_the_free_slots(self):
        peer = self.peer()
        admission = bot.InboundProbeAdmission()
        _, first = admission.acquire(peer, "a", 8)
        outcome, second = admission.acquire(peer, "b", 5)
        self.assertIs(outcome, bot._ProbeAdmission.ACCEPTED)
        self.assertEqual(second[1], 2)  # only 2 left under the per-requester cap
        self.assertEqual(admission.reduced, 1)
        outcome, none = admission.acquire(peer, "c", 1)
        self.assertEqual((outcome, none), (bot._ProbeAdmission.REJECTED, None))
        self.assertEqual(admission.rejected, 1)
        admission.release(first)
        admission.release(second)
        self.assertFalse(admission.outstanding)

    def test_global_pool_remainder_is_handed_out(self):
        admission = bot.InboundProbeAdmission()
        holders = [admission.acquire(dict(email=f"{i}@example.org"), "x", 10)[1] for i in range(2)]
        outcome, small = admission.acquire(dict(email="late@example.org"), "y", 4)
        self.assertEqual((outcome, small), (bot._ProbeAdmission.REJECTED, None))
        admission2 = bot.InboundProbeAdmission()
        a = admission2.acquire(dict(email="1@example.org"), "x", 10)[1]
        b = admission2.acquire(dict(email="2@example.org"), "x", 8)[1]
        outcome, c = admission2.acquire(dict(email="3@example.org"), "y", 5)
        self.assertEqual(c[1], 2)

    def test_urgent_batch_during_a_grid_batch_is_answered_not_dropped(self):
        async def scenario():
            gate = asyncio.Event()
            started = []

            async def probe(target):
                started.append(target["url"])
                if "grid" in target["url"]:
                    await gate.wait()
                return True, None, 1

            peer = self.peer()
            grid = [dict(url=f"https://grid.example/{i}", type="http") for i in range(11)]
            urgent = [dict(url="https://urgent.example", type="http")]
            with patch.object(bot, "run_single_check", side_effect=probe):
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(req_id="grid", targets=grid))
                # A second grid batch of the same requester takes the rest of its cap
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(req_id="grid2", targets=grid))
                await asyncio.sleep(0.2)
                self.assertEqual(bot._inbound_probes.outstanding[bot._peer_identity(peer)], 10)
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(req_id="urgent", targets=urgent))
                # Nothing of the grid batches has finished, yet the cap is full: answered "busy" at once
                answers = {p["req_id"]: p for kind, p in self.sent}
                self.assertEqual(set(answers), {"urgent"})
                self.assertEqual(answers["urgent"]["results"][0]["status"], "skip")
                self.assertIn("Busy", answers["urgent"]["results"][0]["error_msg"])
                self.assertEqual(bot._inbound_probes.rejected, 1)
                gate.set()
                tasks = asyncio.all_tasks() - {asyncio.current_task()}
                await asyncio.wait_for(asyncio.gather(*tasks), self.timeout)
            return started
        asyncio.run(scenario())

    def test_urgent_batch_fits_next_to_one_grid_batch(self):
        async def scenario():
            gate = asyncio.Event()

            async def probe(target):
                if "grid" in target["url"]:
                    await gate.wait()
                return True, None, 1

            peer = self.peer()
            grid = [dict(url=f"https://grid.example/{i}", type="http") for i in range(11)]
            with patch.object(bot, "run_single_check", side_effect=probe), \
                 patch.object(bot, "_answer_batch_cross_check", wraps=bot._answer_batch_cross_check) as answer:
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(req_id="grid", targets=grid))
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(
                    req_id="urgent", targets=[dict(url="https://urgent.example", type="http")]))
                async with asyncio.timeout(self.timeout):
                    while not any(p["req_id"] == "urgent" for _, p in self.sent):
                        await asyncio.sleep(0.01)
                urgent = [p for _, p in self.sent if p["req_id"] == "urgent"][0]
                self.assertEqual(urgent["results"][0]["status"], "up")  # really checked, not busy
                self.assertEqual(answer.call_args_list[0].args[5], 5)  # grid batch: 5 workers
                gate.set()
                tasks = asyncio.all_tasks() - {asyncio.current_task()}
                await asyncio.wait_for(asyncio.gather(*tasks), self.timeout)
            return
        asyncio.run(scenario())

    def test_reduced_batch_runs_with_the_granted_workers(self):
        async def scenario():
            peer = self.peer()
            admission = bot._inbound_probes
            _, held = admission.acquire(peer, "held", 8)
            targets = [dict(url=f"https://t.example/{i}", type="http") for i in range(5)]
            with patch.object(bot, "run_single_check", AsyncMock(return_value=(True, None, 1))), \
                 patch.object(bot, "_answer_batch_cross_check", AsyncMock()) as answer:
                self.receive(peer, "UPTIME_PEER_CHECK_BATCH_REQ", dict(req_id="b", targets=targets))
                tasks = asyncio.all_tasks() - {asyncio.current_task()}
                await asyncio.wait_for(asyncio.gather(*tasks), self.timeout)
            self.assertEqual(answer.call_args.args[5], 2)
            admission.release(held)
        asyncio.run(scenario())

    def test_busy_replies_are_bounded_and_not_sent_over_the_rate_limit(self):
        peer = self.peer()
        admission = bot.InboundProbeAdmission()
        allowed = sum(admission.allow_busy_reply(peer, f"r{i}") for i in range(100))
        self.assertEqual(allowed, bot.PEER_BUSY_REPLIES_PER_MINUTE)
        self.assertFalse(admission.allow_busy_reply(peer, ""))
        self.assertFalse(admission.allow_busy_reply(peer, "x" * 65))

    def test_single_request_rejection_is_answered_with_skip(self):
        peer = self.peer()
        _, held = bot._inbound_probes.acquire(peer, "held", 10)
        self.receive(peer, "UPTIME_PEER_CHECK_REQ", dict(req_id="one", url="https://x.example", type="http"))
        kind, payload = self.sent[0]
        self.assertEqual((kind, payload["req_id"], payload["status"]), ("CHECK_RESP", "one", "skip"))
        self.assertEqual(bot._inbound_probes.rejected, 1)
        bot._inbound_probes.release(held)

    def test_rejection_counter_in_stats_events(self):
        peer = self.peer()
        _, held = bot._inbound_probes.acquire(peer, "held", 10)
        before = bot.stat_last_hour("probe_rejected")
        for i in range(3):
            self.receive(peer, "UPTIME_PEER_CHECK_REQ", dict(req_id=f"n{i}", url="https://x.example", type="http"))
        self.assertEqual(bot.stat_last_hour("probe_rejected") - before, 3)
        bot._inbound_probes.release(held)


class TestOwnFingerprintCache(unittest.TestCase):
    def make_bot(self):
        mock_bot = MagicMock()
        mock_bot.rpc.get_chat_securejoin_qr_code.return_value = f"https://i.delta.chat/#{SELF_FP}&v=3&i=a&s=b"
        return mock_bot

    def test_one_rpc_call_for_the_process_lifetime(self):
        rpc = self.make_bot().rpc
        for _ in range(1000):
            self.assertEqual(dc_fingerprint.get_self_fingerprint(rpc, 1), SELF_FP)
        self.assertEqual(rpc.get_chat_securejoin_qr_code.call_count, 1)

    def test_1000_incoming_peer_messages_cost_at_most_one_qr_call(self):
        mock_bot = self.make_bot()
        info = (f"Messages are end-to-end encrypted.\nFingerprints:\n\nMe:\n{SELF_FP}\n\n"
                f"Peer:\n{PEER_FP}\n\nRelays:\npeer@example.org")
        mock_bot.rpc.get_contact_encryption_info.return_value = info
        for _ in range(1000):
            self.assertEqual(bot._get_peer_fingerprint(mock_bot, 1, 42, "peer@example.org"), PEER_FP)
        self.assertLessEqual(mock_bot.rpc.get_chat_securejoin_qr_code.call_count, 1)

    def test_failures_are_not_cached_and_accounts_are_separate(self):
        rpc = MagicMock()
        rpc.get_chat_securejoin_qr_code.side_effect = [Exception("down"), f"https://i.delta.chat/#{SELF_FP}&v=3"]
        self.assertIsNone(dc_fingerprint.get_self_fingerprint(rpc, 1))
        self.assertEqual(dc_fingerprint.get_self_fingerprint(rpc, 1), SELF_FP)
        self.assertEqual(rpc.get_chat_securejoin_qr_code.call_count, 2)
        rpc.get_chat_securejoin_qr_code.side_effect = None
        rpc.get_chat_securejoin_qr_code.return_value = f"https://i.delta.chat/#{PEER_FP}&v=3"
        self.assertEqual(dc_fingerprint.get_self_fingerprint(rpc, 2), PEER_FP)
        self.assertEqual(dc_fingerprint.get_self_fingerprint(rpc, 1), SELF_FP)
        dc_fingerprint.forget_self_fingerprint(rpc, 1)
        self.assertEqual(dc_fingerprint.get_self_fingerprint(rpc, 1), PEER_FP)


class TestTrimWithoutLock(unittest.TestCase):
    def test_delete_rpc_runs_without_the_lock_in_chunks_of_50(self):
        calls, held = [], []

        class Rpc:
            def delete_messages(self, accid, ids):
                held.append(bot._peer_rt_lock._is_owned())
                calls.append(list(ids))

        fake = MagicMock()
        fake.rpc = Rpc()
        old = list(range(1000, 1430))
        with patch.object(database, "get_peer_rt_message_ids", return_value={1010, 1011}):
            deleted = bot._delete_trimmed_messages(fake, 1, old)
        self.assertEqual(deleted, 428)
        self.assertEqual(len(calls), 9)
        self.assertTrue(all(len(c) <= 50 for c in calls))
        self.assertFalse(any(held))
        self.assertFalse({1010, 1011} & {i for c in calls for i in c})

    def test_other_thread_can_take_the_lock_while_a_delete_runs(self):
        in_rpc, release, got_lock = threading.Event(), threading.Event(), threading.Event()

        class Rpc:
            def delete_messages(self, accid, ids):
                in_rpc.set()
                release.wait(5)

        fake = MagicMock()
        fake.rpc = Rpc()
        with patch.object(database, "get_peer_rt_message_ids", return_value=set()):
            worker = threading.Thread(target=bot._delete_trimmed_messages, args=(fake, 1, [1, 2, 3]))
            worker.start()
            self.assertTrue(in_rpc.wait(5))

            def take():
                with bot._peer_rt_lock:
                    got_lock.set()
            t = threading.Thread(target=take)
            t.start()
            self.assertTrue(got_lock.wait(2), "lock held across delete_messages")
            release.set()
            worker.join(5)
            t.join(5)

    def test_failed_chunk_is_retried_one_by_one(self):
        class Rpc:
            def __init__(self):
                self.calls = []

            def delete_messages(self, accid, ids):
                self.calls.append(list(ids))
                if len(ids) > 1 or ids == [2]:
                    raise Exception("gone")

        fake = MagicMock()
        fake.rpc = Rpc()
        with patch.object(database, "get_peer_rt_message_ids", return_value=set()):
            self.assertEqual(bot._delete_trimmed_messages(fake, 1, [1, 2, 3]), 2)


if __name__ == "__main__":
    unittest.main()
