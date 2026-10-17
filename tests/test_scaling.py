"""Behaviour that keeps the bot usable with 1000+ monitors: hung targets, batched peer
cross-checks, telemetry ordering, quiet logs and one DB transaction per check."""
import asyncio
import json
import logging
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_scaling.db"


def _wrap(tag: str, payload: dict) -> str:
    return f"[{tag}]\n{json.dumps(payload)}\n[/{tag}]"


def _unwrap(text: str) -> dict:
    return json.loads(text.split("\n", 1)[1].rsplit("\n", 1)[0])


class _FailingRequest:
    """Async context manager standing in for session.head()/get() that raises on enter."""

    def __init__(self, exc):
        self.exc = exc

    async def __aenter__(self):
        raise self.exc

    async def __aexit__(self, *a):
        return False


class TestScaling(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot.pending_peer_checks.clear()
        bot.pending_batch_checks.clear()
        bot._peer_caps.clear()
        bot._cross_check_queue.clear()
        bot._cross_check_flush_task = None
        bot._peer_batch_semaphore = None
        bot._telemetry_rotation_offsets.clear()
        bot._telemetry_last_sent.clear()
        bot._check_stats.update(up=0, down=0, skipped=0, lat_sum=0, lat_n=0, slowest=(0, ""))
        self.saved = (bot.dc_bot_instance, bot.dc_accid, bot.async_event_loop)
        bot._dns_cache.clear()
        dns_patcher = patch("bot.resolve_host_safe", AsyncMock(return_value=["93.184.216.34"]))
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        bot.dc_bot_instance, bot.dc_accid, bot.async_event_loop = self.saved
        bot._peer_batch_semaphore = None
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _peer_bot(self, sender_addr: str):
        mock_bot = MagicMock()
        contact = MagicMock()
        contact.address = sender_addr
        mock_bot.rpc.get_contact.return_value = contact
        mock_bot.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        return mock_bot

    def _event(self, text: str, chat_id: int):
        event = MagicMock()
        event.msg.is_info = False
        event.msg.from_id = 42
        event.msg.chat_id = chat_id
        event.msg.text = text
        event.msg.show_padlock = True
        return event

    # ---- 1. Hung targets -------------------------------------------------------

    def _http_check_with_head_error(self, exc):
        session = MagicMock()
        session.closed = False
        session.head = MagicMock(return_value=_FailingRequest(exc))
        session.get = MagicMock(return_value=_FailingRequest(aiohttp.ServerDisconnectedError()))
        with patch("bot.is_safe_target_url", return_value=True):
            result = asyncio.run(bot.run_single_check({"type": "http", "url": "https://hang.example.org/"}, session=session))
        return result, session

    def test_head_timeout_does_not_retry_with_get(self):
        (is_up, details, _), session = self._http_check_with_head_error(asyncio.TimeoutError())
        self.assertFalse(is_up)
        self.assertEqual(details, "Timeout")
        session.get.assert_not_called()

    def test_other_head_errors_still_fall_back_to_get(self):
        # Some servers drop HEAD requests but answer GET
        _, session = self._http_check_with_head_error(aiohttp.ServerDisconnectedError())
        session.get.assert_called_once()

    def test_concurrency_fits_connection_pool(self):
        self.assertGreaterEqual(bot.CHECK_CONCURRENCY, 200)

    # ---- 2. Batched cross-checks -----------------------------------------------

    def test_failing_targets_share_one_batch_message(self):
        database.add_or_update_peer("it@example.org", "IT", 700)
        database.add_or_update_peer("old@example.org", "Old", 701)
        bot._note_peer_caps("it@example.org", [bot.PEER_CAP_BATCH_CHECK])
        it_bot = self._peer_bot("it@example.org")
        sent = []

        async def run():
            bot.async_event_loop = asyncio.get_running_loop()
            bot.dc_bot_instance, bot.dc_accid = MagicMock(), 1
            legacy = AsyncMock(side_effect=lambda t, timeout, peers: [
                {"node_name": "Old", "status": "down", "url": t["url"]}])
            with patch.object(bot, "CROSS_CHECK_BATCH_WINDOW", 0.05), \
                 patch.object(bot, "request_peer_cross_checks", legacy), \
                 patch.object(bot, "_dc_send_msg_with_stats", side_effect=lambda b, a, chat, m: sent.append((chat, m.text))):
                tasks = [asyncio.create_task(bot.request_peer_cross_checks_batched({"url": u, "type": "http"}))
                         for u in ("https://a.example.org", "https://b.example.org", "https://a.example.org")]
                while not bot.pending_batch_checks:
                    await asyncio.sleep(0.01)
                # The capable peer answers the batch: positions follow the request
                req = _unwrap(sent[0][1])
                answer = _wrap("UPTIME_PEER_CHECK_BATCH_RESP", {"req_id": req["req_id"], "results": [
                    {"status": "up", "latency_ms": 30}, {"status": "skip", "error_msg": "No IPv6"}]})
                bot.on_new_message(it_bot, 1, self._event(answer, 700))
                return await asyncio.gather(*tasks), req, legacy

        (res_a, res_b, res_a2), req, legacy = asyncio.run(run())
        batch_msgs = [t for chat, t in sent if "UPTIME_PEER_CHECK_BATCH_REQ" in t]
        self.assertEqual(len(batch_msgs), 1)  # one message for all targets
        self.assertEqual(sent[0][0], 700)
        self.assertEqual([t["url"] for t in req["targets"]], ["https://a.example.org", "https://b.example.org"])
        self.assertEqual(req["caps"], bot.OWN_PEER_CAPS)
        # The old peer still gets one classic request per (deduplicated) target
        self.assertEqual(legacy.call_count, 2)
        self.assertEqual([p["email"] for p in legacy.call_args.kwargs["peers"]], ["old@example.org"])

        self.assertEqual(res_a, res_a2)  # the same target asked twice shares the answers
        it_a = next(r for r in res_a if r["node_name"] == "IT")
        self.assertEqual((it_a["status"], it_a["latency_ms"], it_a["url"]), ("up", 30, "https://a.example.org"))
        self.assertIn("Old", {r["node_name"] for r in res_a})
        it_b = next(r for r in res_b if r["node_name"] == "IT")
        self.assertEqual(it_b["status"], "unknown")  # "skip" is stored as unknown
        stored = database.get_peer_measurements_for_url("https://a.example.org")
        self.assertEqual([(m["node_name"], m["status"]) for m in stored], [("IT", "up")])

    def test_batch_request_is_answered_in_one_message(self):
        database.add_or_update_peer("ru@example.org", "RU2", 702)
        bot.async_event_loop = None
        req = _wrap("UPTIME_PEER_CHECK_BATCH_REQ", {"req_id": "r1", "caps": ["batch_check"], "targets": [
            {"url": "https://ok.example.org", "type": "http"},
            {"url": "http://127.0.0.1/", "type": "http"},
            "not a target",
            {"url": "2a00::1", "type": "ping", "family": 6},
        ]})
        check = AsyncMock(side_effect=[(True, "200 - OK", 12), (None, bot.NO_IPV6_MSG, None)])
        with patch("bot.run_single_check", check), \
             patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.on_new_message(self._peer_bot("ru@example.org"), 1, self._event(req, 702))
        self.assertEqual(check.call_count, 2)  # the refused ones are not checked
        self.assertEqual(check.call_args_list[1].args[0]["family"], 6)
        self.assertEqual(send.call_count, 1)
        resp = _unwrap(send.call_args.args[3].text)
        self.assertEqual(resp["req_id"], "r1")
        self.assertEqual([r["status"] for r in resp["results"]], ["up", "skip", "skip", "skip"])
        self.assertEqual(resp["results"][1]["error_msg"], "Target refused")
        self.assertIn(bot.PEER_CAP_BATCH_CHECK, bot._peer_caps["ru@example.org"])

    def test_batch_request_from_non_peer_is_ignored(self):
        req = _wrap("UPTIME_PEER_CHECK_BATCH_REQ", {"req_id": "r2", "targets": [{"url": "https://x.example.org"}]})
        with patch("bot.run_single_check", AsyncMock()) as check, patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.on_new_message(self._peer_bot("attacker@evil.example"), 1, self._event(req, 703))
        check.assert_not_called()
        send.assert_not_called()

    def test_batch_response_from_other_chat_is_ignored(self):
        database.add_or_update_peer("it@example.org", "IT", 700)
        database.add_or_update_peer("other@example.org", "Other", 704)
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        fut = loop.create_future()
        bot.pending_batch_checks["r3"] = (fut, 700, 1)
        bot.async_event_loop = None
        resp = _wrap("UPTIME_PEER_CHECK_BATCH_RESP", {"req_id": "r3", "results": [{"status": "up"}]})
        bot.on_new_message(self._peer_bot("other@example.org"), 1, self._event(resp, 704))
        self.assertFalse(fut.done())
        # From the right chat; missing positions come back as unknown
        resp = _wrap("UPTIME_PEER_CHECK_BATCH_RESP", {"req_id": "r3", "results": []})
        bot.on_new_message(self._peer_bot("it@example.org"), 1, self._event(resp, 700))
        self.assertEqual(fut.result()[0]["status"], "unknown")

    def test_caps_learned_from_telemetry(self):
        database.add_or_update_peer("it@example.org", "IT", 700)
        metrics = _wrap("UPTIME_PEER_METRICS", {"node_name": "IT", "caps": ["batch_check"], "metrics": []})
        bot.on_new_message(self._peer_bot("it@example.org"), 1, self._event(metrics, 700))
        self.assertTrue(bot._peer_supports({"email": "IT@example.org"}, bot.PEER_CAP_BATCH_CHECK))

    # ---- 3. Logs ---------------------------------------------------------------

    def test_minute_summary(self):
        for args in ((True, 20, "a"), (True, 80, "slow.example.org"), (False, None, "b"), (None, None, "v6")):
            bot._count_check(*args)
        with self.assertLogs("uptime_bot", level="INFO") as logs:
            bot.log_check_summary(running=3)
        self.assertIn("4 (2 up, 1 down, 1 skipped), avg latency 50 ms, slowest slow.example.org (80 ms); running now: 3",
                      logs.output[0])
        self.assertEqual(bot._check_stats["up"], 0)  # reset

    def test_routine_up_is_logged_at_debug(self):
        group = [{"id": 1, "dc_chat_id": 100, "url": "https://fine.example.org", "type": "http",
                  "name": "Fine", "status": "up", "consecutive_failures": 0}]
        with patch("bot.run_single_check", AsyncMock(return_value=(True, "200 - OK", 9))), \
             patch("bot.handle_check_result", AsyncMock()), \
             patch.object(database, "record_check_results"):
            with self.assertLogs("uptime_bot", level="DEBUG") as logs:
                asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
        line = next(r for r in logs.records if "Check result" in r.getMessage())
        self.assertEqual(line.levelno, logging.DEBUG)

    # ---- 4. Telemetry ----------------------------------------------------------

    def test_telemetry_sends_changes_first_then_rotates(self):
        email = "it@example.org"
        metrics = [{"url": f"https://m{i}.example.org", "status": "up"} for i in range(450)]
        self.assertEqual(len(bot.pick_telemetry_batch(email, metrics[:150], 200)), 150)  # all fits

        bot._telemetry_last_sent[email] = {m["url"]: "up" for m in metrics}
        for i in (5, 300, 449):
            metrics[i]["status"] = "down"
        first = bot.pick_telemetry_batch(email, metrics, 200)
        self.assertEqual(len(first), 200)
        self.assertEqual([m["url"] for m in first[:3]], [metrics[i]["url"] for i in (5, 300, 449)])
        # Once sent, the changes are no longer "changed": the next batch continues the rotation
        bot._telemetry_last_sent[email].update({m["url"]: m["status"] for m in first})
        second = bot.pick_telemetry_batch(email, metrics, 200)
        self.assertFalse({m["url"] for m in first[3:]} & {m["url"] for m in second})

    # ---- 5. One transaction per check ------------------------------------------

    def test_record_check_results_writes_status_and_measurement_together(self):
        r1 = database.add_resource(100, "https://shared.example.org", "A", "http")
        r2 = database.add_resource(200, "https://shared.example.org", "B", "http")
        database.record_check_results(
            [{"id": r1, "status": "down", "consecutive_failures": 1, "error_msg": "502", "latency_ms": 40},
             {"id": r2, "status": "down", "consecutive_failures": 1, "error_msg": "502", "latency_ms": 40}],
            ("https://shared.example.org", "DE", "down", 40, "502"))
        self.assertEqual(database.get_resource_by_id(r1)["status"], "down")
        self.assertEqual(len(database.get_resource_downtime_events(r2)), 1)
        self.assertEqual(database.get_peer_measurements_for_url("https://shared.example.org")[0]["status"], "down")

    def test_check_group_task_writes_once(self):
        r1 = database.add_resource(100, "https://shared.example.org", "A", "http")
        r2 = database.add_resource(200, "https://shared.example.org", "B", "http")
        group = [database.get_resource_by_id(r1), database.get_resource_by_id(r2)]
        with patch("bot.run_single_check", AsyncMock(return_value=(True, "200 - OK", 9))), \
             patch.object(database, "record_check_results", wraps=database.record_check_results) as record, \
             patch.object(database, "batch_update_resource_status") as single, \
             patch.object(database, "save_peer_measurement") as measure:
            asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
        record.assert_called_once()
        self.assertEqual([u["id"] for u in record.call_args.args[0]], [r1, r2])
        single.assert_not_called()
        measure.assert_not_called()
        self.assertEqual(database.get_resource_by_id(r2)["status"], "up")


if __name__ == "__main__":
    unittest.main()
