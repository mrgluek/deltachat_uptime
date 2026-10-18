"""The paced outbox: priorities, merging by key, expiry, pacing - and its use for incident
messages and reactions while a backlog is waiting."""
import asyncio
import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database
import outbox
from outbox import Outbox, PRIO_ALERT, PRIO_REPLY, PRIO_UPDATE, PRIO_PEER, PRIO_TELEMETRY

TEST_DB = "test_uptime_outbox.db"


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def queued(burst=100, clock=None):
    """An outbox that queues (as if started) but has no worker: the test drains it by hand."""
    ob = Outbox(rate_per_minute=60, burst=burst, clock=clock or FakeClock())
    ob._thread = object()
    return ob


def drain(ob):
    """Sends everything waiting, in the order the worker would; returns the labels sent."""
    sent = []
    while True:
        with ob._cond:
            while ob._heap and ob._heap[0][2].done:
                ob._heap.pop(0)
            if not ob._heap:
                return sent
            job = ob._next_job()
        ob._run(job)
        sent.append(job.label)


class TestOutbox(unittest.TestCase):
    def test_not_started_sends_inline(self):
        ob = Outbox()
        fut = ob.submit(lambda: 42)
        self.assertEqual(fut.result(timeout=0), 42)

    def test_priorities_then_arrival_order(self):
        ob = queued()
        for prio, label in ((PRIO_TELEMETRY, "telemetry"), (PRIO_REPLY, "reply 1"), (PRIO_PEER, "peer"),
                            (PRIO_ALERT, "alert"), (PRIO_REPLY, "reply 2"), (PRIO_UPDATE, "update")):
            ob.submit(lambda: None, priority=prio, label=label)
        self.assertEqual(drain(ob), ["alert", "reply 1", "reply 2", "update", "peer", "telemetry"])

    def test_same_key_merges_into_waiting_job(self):
        ob = queued()
        ob.submit(lambda: "first", priority=PRIO_REPLY, label="before")
        f1 = ob.submit(lambda: "old text", priority=PRIO_UPDATE, key=("incident", 1), label="incident")
        ob.submit(lambda: None, priority=PRIO_UPDATE, label="other update")
        f2 = ob.submit(lambda: "new text", priority=PRIO_UPDATE, key=("incident", 1), label="incident")
        self.assertIs(f1, f2)
        # Sent once, with the latest content, in the place of the first one
        self.assertEqual(drain(ob), ["before", "incident", "other update"])
        self.assertEqual(f1.result(timeout=0), "new text")
        self.assertEqual(ob.stats["merged"], 1)
        self.assertEqual(ob.stats["sent"], 3)

    def test_merge_with_more_urgent_priority_moves_up(self):
        ob = queued()
        ob.submit(lambda: None, priority=PRIO_REPLY, label="reply")
        f = ob.submit(lambda: "duration", priority=PRIO_UPDATE, key=("incident", 7), label="incident")
        ob.submit(lambda: "status change", priority=PRIO_ALERT, key=("incident", 7), label="incident")
        self.assertEqual(drain(ob), ["incident", "reply"])
        self.assertEqual(f.result(timeout=0), "status change")
        self.assertEqual(ob.waiting(), {})

    def test_expired_job_is_dropped_without_a_token(self):
        clock = FakeClock()
        ob = queued(burst=1, clock=clock)
        sent = []
        f = ob.submit(lambda: sent.append("late"), priority=PRIO_PEER, expires_in=20, label="answer")
        ob.submit(lambda: sent.append("telemetry"), priority=PRIO_TELEMETRY, label="telemetry")
        clock.t += 21
        drain(ob)
        self.assertEqual(sent, ["telemetry"])  # the single token went to the job still wanted
        self.assertIsNone(f.result(timeout=0))
        self.assertEqual(ob.stats["expired"], 1)

    def test_failed_send_is_reported_on_the_future(self):
        ob = queued()

        def boom():
            raise RuntimeError("relay said no")
        f = ob.submit(boom, label="x")
        drain(ob)
        self.assertIsInstance(f.exception(timeout=0), RuntimeError)
        self.assertEqual(ob.stats["failed"], 1)

    def test_worker_paces_after_burst(self):
        ob = Outbox(rate_per_minute=600, burst=2)  # 10 a second after a burst of 2
        ob.start()
        t0 = time.monotonic()
        futs = [ob.submit(lambda: time.monotonic(), label=str(i)) for i in range(6)]
        times = [f.result(timeout=5) for f in futs]
        self.assertLess(times[1] - t0, 0.05)              # the burst goes at once
        self.assertGreater(times[-1] - t0, 0.35)          # the other 4 at ~0.1 s each
        self.assertLess(times[-1] - t0, 1.0)

    def test_urgent_job_overtakes_a_waiting_backlog(self):
        ob = Outbox(rate_per_minute=600, burst=1)
        order = []
        lock = threading.Lock()

        def job(name):
            def f():
                with lock:
                    order.append(name)
            return f
        ob.start()
        for i in range(5):
            ob.submit(job(f"telemetry {i}"), priority=PRIO_TELEMETRY)
        time.sleep(0.05)  # the first one goes, the rest wait for tokens (one every 0.1 s)
        last = ob.submit(job("alert"), priority=PRIO_ALERT)
        last.result(timeout=5)
        self.assertLessEqual(order.index("alert"), 2)

    def test_defaults_match_relay_headroom(self):
        # chatmail: 60 a minute, burst 10; the core sends a few messages of its own
        self.assertLess(outbox.RATE_PER_MINUTE, 60)
        self.assertLess(outbox.BURST, 10)


class TestOutboxInBot(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        self.saved = (bot.dc_bot_instance, bot.dc_accid)
        bot._incident_last_edit_state.clear()
        self.ob = queued()
        patcher = patch.object(bot, "dc_outbox", self.ob)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        bot.dc_bot_instance, bot.dc_accid = self.saved
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def test_incident_updates_merge_while_waiting(self):
        chat_id = 4321
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://one.example.org", "One", "http", 60)
        database.update_resource_status(r1, "down", 1, "HTTP 500")
        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.send_msg.return_value = 777
        bot.dc_accid = 1

        # New incident, then a second monitor fails, then the throttle passes - all before sending
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        r2 = database.add_resource(chat_id, "https://two.example.org", "Two", "http", 60)
        database.update_resource_status(r2, "down", 1, "Timeout")
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        self.assertEqual(sum(self.ob.waiting().values()), 1)
        self.assertEqual(self.ob.waiting(), {"alert": 1})

        drain(self.ob)
        # One message, with both monitors, and its id stored for later edits
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()
        text = bot.dc_bot_instance.rpc.send_msg.call_args.args[2].text
        self.assertIn("One", text)
        self.assertIn("Two", text)
        self.assertEqual(database.get_active_incident(chat_id)["msg_id"], 777)

        # Resolved: an edit of that message, as an alert
        database.update_resource_status(r1, "up", 0)
        database.update_resource_status(r2, "up", 0)
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        self.assertEqual(self.ob.waiting(), {"alert": 1})
        drain(self.ob)
        self.assertEqual(bot.dc_bot_instance.rpc.send_edit_request.call_args.args[1], 777)
        self.assertIn("Resolved", bot.dc_bot_instance.rpc.send_edit_request.call_args.args[2])

    def test_outage_resolved_before_first_message_still_reported(self):
        chat_id = 4322
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://blip.example.org", "Blip", "http", 60)
        database.update_resource_status(r1, "down", 1, "HTTP 502")
        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.send_msg.return_value = 778
        bot.dc_accid = 1
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        database.update_resource_status(r1, "up", 0)
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        drain(self.ob)
        bot.dc_bot_instance.rpc.send_msg.assert_called_once()  # one message: the resolved one
        self.assertIn("Resolved", bot.dc_bot_instance.rpc.send_msg.call_args.args[2].text)

    def test_duration_refresh_is_low_priority(self):
        chat_id = 4323
        database.get_or_create_chat_token(chat_id)
        r1 = database.add_resource(chat_id, "https://long.example.org", "Long", "http", 60)
        database.update_resource_status(r1, "down", 1, "HTTP 500")
        bot.dc_bot_instance = MagicMock()
        bot.dc_bot_instance.rpc.send_msg.return_value = 779
        bot.dc_accid = 1
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        drain(self.ob)
        inc_id = database.get_active_incident(chat_id)["id"]
        last_t, sig = bot._incident_last_edit_state[inc_id]
        bot._incident_last_edit_state[inc_id] = (last_t - 301, sig)
        asyncio.run(bot.sync_chat_incident_state(chat_id))
        self.assertEqual(self.ob.waiting(), {"update": 1})

    def test_hourglass_replaced_by_final_reaction(self):
        mock_bot = MagicMock()
        bot._react(mock_bot, 1, 55, "⏳")
        bot._react(mock_bot, 1, 55, "☑️")
        drain(self.ob)
        mock_bot.rpc.send_reaction.assert_called_once_with(1, 55, ["☑️"])

    def test_telemetry_bookkeeping_only_after_sending(self):
        mock_bot = MagicMock()
        done = []
        bot._dc_send_msg_with_stats(mock_bot, 1, 9, MagicMock(), priority=PRIO_TELEMETRY,
                                    key=("telemetry", 9), after_send=lambda: done.append(1))
        self.assertEqual(done, [])
        drain(self.ob)
        self.assertEqual(done, [1])


if __name__ == "__main__":
    unittest.main()
