import asyncio
import json
import os
import sqlite3
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_quorum.db"
URL = "http://quorum-target.example.org"
CHAT = 100  # the admin's chat, so its monitors are within the default "admin" peer share scope


def _peer(node, status, latency_ms=None):
    return {"node_name": node, "status": status, "latency_ms": latency_ms,
            "error_msg": None if status == "up" else "timeout"}


class TestQuorumDecision(unittest.TestCase):
    """decide_quorum / next_alert_state: the rules, without I/O."""

    def setUp(self):
        bot._alert_streaks.clear()

    def _votes(self, down: int, up: int, abstain: int = 0):
        votes = [{"node": "L", "status": "down" if down else "up", "local": True}]
        down, up = (down - 1, up) if down else (down, up - 1)
        votes += [{"node": f"D{i}", "status": "down"} for i in range(down)]
        votes += [{"node": f"U{i}", "status": "up"} for i in range(up)]
        votes += [{"node": f"A{i}", "status": "unknown"} for i in range(abstain)]
        return votes

    def test_majority_table(self):
        cases = {
            # (nodes down, nodes up): state
            (0, 4): "up", (1, 3): "degraded", (2, 2): "degraded", (3, 1): "down", (4, 0): "down",
            (1, 4): "degraded", (2, 3): "degraded", (3, 2): "down",
            (1, 2): "degraded", (2, 1): "down",
            (1, 1): "degraded", (2, 0): "down",
        }
        for (down, up), expected in cases.items():
            with self.subTest(down=down, up=up):
                self.assertEqual(bot.decide_quorum(self._votes(down, up)), expected)

    def test_single_voter_is_local_decision(self):
        self.assertEqual(bot.decide_quorum(self._votes(1, 0)), "down")
        self.assertEqual(bot.decide_quorum(self._votes(0, 1)), "up")
        # Peers that did not answer or could not check abstain
        self.assertEqual(bot.decide_quorum(self._votes(1, 0, abstain=3)), "down")

    def test_abstaining_nodes_do_not_count(self):
        # 2 down of 3 voters (2 abstain): majority
        self.assertEqual(bot.decide_quorum(self._votes(2, 1, abstain=2)), "down")

    def test_degraded_needs_two_votes_both_ways(self):
        self.assertEqual(bot.next_alert_state(1, "up", "degraded"), "up")
        self.assertEqual(bot.next_alert_state(1, "up", "degraded"), "degraded")
        self.assertEqual(bot.next_alert_state(1, "degraded", "up"), "degraded")
        self.assertEqual(bot.next_alert_state(1, "degraded", "up"), "up")

    def test_streak_resets_on_other_result(self):
        self.assertEqual(bot.next_alert_state(2, "up", "degraded"), "up")
        self.assertEqual(bot.next_alert_state(2, "up", "up"), "up")
        self.assertEqual(bot.next_alert_state(2, "up", "degraded"), "up")

    def test_down_is_immediate_both_ways(self):
        self.assertEqual(bot.next_alert_state(3, "up", "down"), "down")
        self.assertEqual(bot.next_alert_state(3, "degraded", "down"), "down")
        self.assertEqual(bot.next_alert_state(3, "down", "up"), "up")
        self.assertEqual(bot.next_alert_state(3, "down", "degraded"), "degraded")

    def test_format_votes(self):
        votes = bot.build_votes("DE", False, None, "timeout",
                                [_peer("IT", "up", 196), _peer("RU", "down"), {"node_name": "RU2", "status": "skip"},
                                 _peer("IT", "down")])  # a second answer from IT is ignored
        self.assertEqual(bot.format_votes(votes), "🔴 DE, RU · 🟢 IT (196ms) · ⚪ RU2 (no result)")
        self.assertEqual(bot._votes_summary(votes), "Unreachable from DE, RU; reachable from IT")


class TestQuorumChecks(unittest.TestCase):
    """check_group_task with quorum alerting: what is stored and announced."""

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot._alert_streaks.clear()
        bot._vote_cache.clear()
        bot._degraded_notify_queue.clear()
        bot._admin_chat_membership_cache.clear()
        self.orig_dc_bot, self.orig_accid = bot.dc_bot_instance, bot.dc_accid
        bot.dc_bot_instance, bot.dc_accid = None, None
        database.set_local_node_name("DE")
        database.set_config("admin_chat_id", str(CHAT))
        for i, node in enumerate(["IT", "RU", "RU2"]):
            database.add_or_update_peer(f"{node.lower()}@example.org", node, 200 + i)
        self.rid = database.add_resource(CHAT, URL, "Target", "http")

    def tearDown(self):
        bot.dc_bot_instance, bot.dc_accid = self.orig_dc_bot, self.orig_accid
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _run(self, local_up: bool, peers: list[dict]):
        """One check of the target; returns (handle_check_result calls, queued notices, cross-check mock)."""
        group = database.get_resources(CHAT)
        notices = MagicMock()
        cross = AsyncMock(return_value=peers)
        result = (True, None, 50) if local_up else (False, "timeout", None)
        with patch("bot.asyncio.sleep", AsyncMock()), \
             patch("bot.run_single_check", AsyncMock(return_value=result)), \
             patch("bot.check_host_internet_connectivity", AsyncMock(return_value=True)), \
             patch("bot.request_peer_cross_checks_batched", cross), \
             patch("bot._queue_degraded_notice", notices), \
             patch("bot.handle_check_result", AsyncMock()) as handle:
            asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
        return handle, notices, cross

    def _resource(self):
        return database.get_resource_by_id(self.rid)

    def test_only_this_node_fails_is_degraded_not_down(self):
        peers_up = [_peer("IT", "up", 196), _peer("RU", "up", 188), _peer("RU2", "up", 145)]
        handle, notices, _ = self._run(False, peers_up)
        self.assertTrue(handle.call_args.args[1])  # first vote: still UP
        self.assertEqual(self._resource()["status"], "up")
        notices.assert_not_called()

        handle, notices, _ = self._run(False, peers_up)
        r = self._resource()
        self.assertEqual(r["status"], "up")
        self.assertEqual(r["alert_state"], "degraded")
        self.assertIn("Unreachable from DE", handle.call_args.args[2])
        self.assertEqual(notices.call_args.args[0], "start")
        outages = database.get_partial_outages(self.rid)
        self.assertEqual(len(outages), 1)
        self.assertEqual(json.loads(outages[0]["nodes_down"]), ["DE"])

    def test_majority_down_is_down_at_once(self):
        handle, notices, _ = self._run(False, [_peer("IT", "up", 196), _peer("RU", "down"), _peer("RU2", "down")])
        self.assertFalse(handle.call_args.args[1])
        r = self._resource()
        self.assertEqual(r["status"], "down")
        self.assertEqual(r["alert_state"], "down")
        self.assertIn("Unreachable from DE, RU, RU2; reachable from IT", handle.call_args.args[2])
        votes = json.loads(r["last_votes"])
        self.assertEqual([v["node"] for v in votes], ["DE", "IT", "RU", "RU2"])
        notices.assert_not_called()

    def test_half_down_is_degraded(self):
        peers = [_peer("IT", "up", 196), _peer("RU", "down"), _peer("RU2", "up", 145)]
        self._run(False, peers)
        self._run(False, peers)
        self.assertEqual(self._resource()["alert_state"], "degraded")
        self.assertEqual(self._resource()["status"], "up")

    def test_no_peer_answers_falls_back_to_local(self):
        handle, _, _ = self._run(False, [])
        self.assertFalse(handle.call_args.args[1])
        self.assertEqual(self._resource()["status"], "down")

    def test_offline_peers_mean_local_decision(self):
        conn = sqlite3.connect(TEST_DB)
        conn.execute("UPDATE peers SET is_offline = 1")
        conn.commit()
        conn.close()
        handle, _, cross = self._run(False, [])
        self.assertFalse(handle.call_args.args[1])
        self.assertEqual(self._resource()["alert_state"], "down")

    def test_local_mode_keeps_old_behaviour(self):
        database.set_chat_alert_mode(CHAT, "local")
        handle, notices, _ = self._run(False, [_peer("IT", "up", 196), _peer("RU", "up", 1), _peer("RU2", "up", 1)])
        self.assertFalse(handle.call_args.args[1])
        self.assertIn("Reachable from IT: 196ms", handle.call_args.args[2])
        # Peers' answers are still kept for the alert text
        self.assertEqual(len(json.loads(self._resource()["last_votes"])), 4)
        notices.assert_not_called()

    def test_not_shared_with_peers_means_local_decision(self):
        database.set_config("admin_chat_id", "999")  # CHAT is no longer the admin's chat
        handle, _, cross = self._run(False, [_peer("IT", "up", 1)])
        self.assertFalse(handle.call_args.args[1])
        cross.assert_not_called()

    def test_degraded_recovers_after_two_good_votes(self):
        peers_up = [_peer("IT", "up", 1), _peer("RU", "up", 1), _peer("RU2", "up", 1)]
        self._run(False, peers_up)
        self._run(False, peers_up)
        self.assertEqual(self._resource()["alert_state"], "degraded")

        _, notices, _ = self._run(True, peers_up)
        self.assertEqual(self._resource()["alert_state"], "degraded")
        notices.assert_not_called()
        _, notices, _ = self._run(True, peers_up)
        r = self._resource()
        self.assertEqual(r["alert_state"], "up")
        self.assertEqual(notices.call_args.args[0], "end")
        self.assertIsNotNone(database.get_partial_outages(self.rid)[0]["ended_at"])

    def test_down_to_degraded_when_others_recover(self):
        self._run(False, [_peer("IT", "down"), _peer("RU", "down"), _peer("RU2", "down")])
        self.assertEqual(self._resource()["status"], "down")
        bot._vote_cache.clear()  # next peer round
        handle, notices, _ = self._run(False, [_peer("IT", "up", 1), _peer("RU", "up", 1), _peer("RU2", "up", 1)])
        r = self._resource()
        self.assertEqual(r["status"], "up")  # the incident ends: most nodes reach it again
        self.assertEqual(r["alert_state"], "degraded")
        self.assertEqual(notices.call_args.args[0], "start")

    def test_degraded_to_down(self):
        peers_up = [_peer("IT", "up", 1), _peer("RU", "up", 1), _peer("RU2", "up", 1)]
        self._run(False, peers_up)
        self._run(False, peers_up)
        bot._vote_cache.clear()
        self._run(False, [_peer("IT", "down"), _peer("RU", "down"), _peer("RU2", "up", 1)])
        r = self._resource()
        self.assertEqual(r["status"], "down")
        self.assertEqual(r["alert_state"], "down")
        self.assertIsNotNone(database.get_partial_outages(self.rid)[0]["ended_at"])

    def test_healthy_target_does_not_ask_peers(self):
        _, _, cross = self._run(True, [])
        cross.assert_not_called()

    def test_degraded_target_reuses_peer_answers(self):
        peers_up = [_peer("IT", "up", 1), _peer("RU", "up", 1), _peer("RU2", "up", 1)]
        self._run(False, peers_up)
        self._run(False, peers_up)  # fresh: still failing for the first time (not in alert yet)
        _, _, cross = self._run(False, peers_up)  # degraded, nothing changed locally: cached answers
        cross.assert_not_called()
        _, _, cross = self._run(True, peers_up)  # this node's result changed: ask again
        cross.assert_called_once()

    def test_switch_to_local_closes_degraded_quietly(self):
        peers_up = [_peer("IT", "up", 1), _peer("RU", "up", 1), _peer("RU2", "up", 1)]
        self._run(False, peers_up)
        self._run(False, peers_up)
        database.set_chat_alert_mode(CHAT, "local")
        handle, notices, _ = self._run(False, peers_up)
        r = self._resource()
        self.assertEqual(r["status"], "down")
        self.assertEqual(r["alert_state"], "down")
        self.assertIsNotNone(database.get_partial_outages(self.rid)[0]["ended_at"])
        notices.assert_not_called()


class TestQuorumTexts(unittest.TestCase):

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        self.orig_dc_bot, self.orig_accid = bot.dc_bot_instance, bot.dc_accid
        bot._degraded_notify_queue.clear()
        bot._admin_chat_membership_cache.clear()

    def tearDown(self):
        bot.dc_bot_instance, bot.dc_accid = self.orig_dc_bot, self.orig_accid
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _votes_json(self):
        return json.dumps(bot.build_votes("DE", False, None, "timeout",
                                          [_peer("IT", "up", 196), _peer("RU", "down"), _peer("RU2", "down")]))

    def test_incident_message_shows_votes(self):
        text = bot.format_incident_message(7, 1700000000, [{
            "id": 1, "name": "Site", "url": URL, "type": "http", "status": "down",
            "went_down_at": 1700000000, "went_up_at": None, "last_votes": self._votes_json()}])
        self.assertIn("🛰️ 🔴 DE, RU, RU2 · 🟢 IT (196ms)", text)

    def test_degraded_notice_groups_starts_and_ends(self):
        r1 = {"id": 1, "name": "One", "url": "http://one.example.org", "dc_chat_id": CHAT}
        r2 = {"id": 2, "name": None, "url": "http://two.example.org", "dc_chat_id": CHAT}
        votes = json.loads(self._votes_json())
        text = bot.format_degraded_notice([("start", r1, votes, None), ("end", r2, votes, 1)])
        self.assertIn("🟠 **Partial Outage** — 1 monitor(s)", text)
        self.assertIn("**One**", text)
        self.assertIn("✅ **Partial Outage Resolved**", text)
        self.assertIn("http://two.example.org", text)
        self.assertIn("Not counted as downtime", text)

    def test_notices_flushed_once_per_chat(self):
        mock_bot = MagicMock()
        bot.dc_bot_instance, bot.dc_accid = mock_bot, 1
        votes = json.loads(self._votes_json())
        r1 = {"id": 1, "name": "One", "url": "http://one.example.org", "dc_chat_id": CHAT}
        r2 = {"id": 2, "name": "Two", "url": "http://two.example.org", "dc_chat_id": CHAT}
        r3 = {"id": 3, "name": "Three", "url": "http://three.example.org", "dc_chat_id": 555}

        async def scenario():
            with patch("bot.DEGRADED_NOTIFY_WINDOW", 0):
                bot._queue_degraded_notice("start", r1, votes)
                bot._queue_degraded_notice("start", r2, votes)
                bot._queue_degraded_notice("start", r3, votes)
                await bot._degraded_flush_task

        with patch("bot._dc_send_msg_with_stats") as send:
            asyncio.run(scenario())
        chats = sorted(c.args[2] for c in send.call_args_list)
        self.assertEqual(chats, [CHAT, 555])
        text = next(c.args[3].text for c in send.call_args_list if c.args[2] == CHAT)
        self.assertIn("2 monitor(s)", text)

    def test_list_and_status_show_degraded(self):
        rid = database.add_resource(CHAT, URL, "Target", "http")
        conn = sqlite3.connect(TEST_DB)
        conn.execute("UPDATE resources SET status = 'up', alert_state = 'degraded', last_votes = ? WHERE id = ?",
                     (self._votes_json(), rid))
        conn.commit()
        conn.close()
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = CHAT

        bot.list_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("🟠", text)
        self.assertIn("DEGRADED", text)
        self.assertIn("🔴 DE, RU, RU2", text)

        bot.status_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("🟠 Degraded: `1`", text)
        self.assertIn("Alert mode: `quorum`", text)

    def test_alertmode_command(self):
        database.add_or_update_peer("it@example.org", "IT", 200)
        mock_bot = MagicMock()
        mock_bot.rpc.lookup_contact_id_by_addr.return_value = None
        event = MagicMock()
        event.msg.chat_id = CHAT

        event.payload = ""
        bot.alertmode_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("`quorum`", text)
        self.assertIn("at least 2 of 2", text)

        event.payload = "local"
        bot.alertmode_command(mock_bot, 1, event)
        self.assertEqual(database.get_chat_alert_mode(CHAT), "local")

        event.payload = "sometimes"
        bot.alertmode_command(mock_bot, 1, event)
        self.assertIn("Usage", mock_bot.rpc.send_msg.call_args.args[2].text)
        self.assertEqual(database.get_chat_alert_mode(CHAT), "local")

    def test_alert_columns_added_to_existing_db(self):
        database.close_db()
        os.remove(TEST_DB)
        conn = sqlite3.connect(TEST_DB)
        conn.execute("CREATE TABLE resources (id INTEGER PRIMARY KEY, dc_chat_id INTEGER, name TEXT, url TEXT, type TEXT, status TEXT)")
        conn.execute("INSERT INTO resources VALUES (1, 5, 'Old', 'http://old.example.org', 'http', 'down')")
        conn.commit()
        conn.close()
        database.init_db()
        r = database.get_resource_by_id(1)
        self.assertEqual(r["alert_state"], "up")
        self.assertIsNone(r["last_votes"])
        self.assertEqual(database.get_partial_outages(1), [])

    def test_ignored_target_abstains_in_cross_check(self):
        database.add_ignored_probe_target("http://blocked.example.org")
        mock_bot = MagicMock()
        targets = [{"id": 0, "url": "http://blocked.example.org", "type": "http"},
                   {"id": 0, "url": "http://fine.example.org", "type": "http"}]
        with patch("bot.run_single_check", AsyncMock(return_value=(False, "timeout", None))) as check, \
             patch("bot._dc_send_msg_with_stats") as send:
            asyncio.run(bot._answer_batch_cross_check(mock_bot, 1, 9, "req", targets))
        results = json.loads(send.call_args.args[3].text.split("\n")[1])["results"]
        self.assertEqual([r["status"] for r in results], ["skip", "down"])
        check.assert_called_once()

    def test_offline_peers_not_asked(self):
        database.add_or_update_peer("it@example.org", "IT", 200)
        database.add_or_update_peer("ru@example.org", "RU", 201)
        conn = sqlite3.connect(TEST_DB)
        conn.execute("UPDATE peers SET is_offline = 1 WHERE email = 'ru@example.org'")
        conn.commit()
        conn.close()
        asked = []

        async def fake_single(target, timeout=8.0, peers=None):
            asked.extend(p["email"] for p in peers)
            return []

        fut_holder = {}

        async def scenario():
            fut = asyncio.get_running_loop().create_future()
            fut_holder["f"] = fut
            await bot._flush_cross_checks([({"url": URL, "type": "http"}, fut)])

        with patch("bot.request_peer_cross_checks", fake_single):
            asyncio.run(scenario())
        self.assertEqual(asked, ["it@example.org"])


class TestPeerReportedDown(unittest.TestCase):
    """Stage 2: this node reaches a target, peers report it DOWN in their telemetry."""

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot._alert_streaks.clear()
        bot._vote_cache.clear()
        bot._peer_suspects.clear()
        bot._admin_chat_membership_cache.clear()
        self.orig_dc_bot, self.orig_accid = bot.dc_bot_instance, bot.dc_accid
        bot.dc_bot_instance, bot.dc_accid = None, None
        database.set_local_node_name("DE")
        database.set_config("admin_chat_id", str(CHAT))
        for i, node in enumerate(["IT", "RU", "RU2"]):
            database.add_or_update_peer(f"{node.lower()}@example.org", node, 200 + i)
        self.rid = database.add_resource(CHAT, URL, "Target", "http")
        self._set(status="up")

    def tearDown(self):
        bot.dc_bot_instance, bot.dc_accid = self.orig_dc_bot, self.orig_accid
        bot._peer_suspects.clear()
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _set(self, **fields):
        conn = sqlite3.connect(TEST_DB)
        for k, v in fields.items():
            conn.execute(f"UPDATE resources SET {k} = ? WHERE id = ?", (v, self.rid))
        conn.commit()
        conn.close()

    def _report(self, node="RU", url=URL, age=10):
        import time
        return bot.note_peer_reported_down(node, [{"url": url, "status": "down", "last_checked": int(time.time()) - age}])

    def _run(self, peers):
        group = database.get_resources(CHAT)
        notices = MagicMock()
        cross = AsyncMock(return_value=peers)
        with patch("bot.asyncio.sleep", AsyncMock()), \
             patch("bot.run_single_check", AsyncMock(return_value=(True, None, 40))), \
             patch("bot.check_host_internet_connectivity", AsyncMock(return_value=True)), \
             patch("bot.request_peer_cross_checks_batched", cross), \
             patch("bot._queue_degraded_notice", notices), \
             patch("bot.handle_check_result", AsyncMock()) as handle:
            asyncio.run(bot.check_group_task(group, asyncio.Semaphore(1)))
        return handle, notices, cross

    def test_report_marks_up_quorum_monitor(self):
        self.assertEqual(self._report(), 1)
        self.assertIn(URL, bot._peer_suspects)

    def test_report_ignored_when_not_applicable(self):
        cases = [
            ("old result", {}, {"age": 3600}),
            ("unknown url", {}, {"url": "http://other.example.org"}),
            ("already down", {"status": "down"}, {}),
            ("degraded", {"alert_state": "degraded"}, {}),
            ("maintenance", {"maintenance_until": 4102444800}, {}),
        ]
        for label, fields, kwargs in cases:
            with self.subTest(label):
                bot._peer_suspects.clear()
                self._set(status="up", alert_state="up", maintenance_until=0)
                self._set(**fields)
                self.assertEqual(self._report(**kwargs), 0)
        bot._peer_suspects.clear()
        self._set(status="up", alert_state="up", maintenance_until=0)
        database.set_chat_alert_mode(CHAT, "local")
        self.assertEqual(self._report(), 0)

    def test_up_here_but_most_nodes_down_is_down(self):
        self._report()
        handle, notices, cross = self._run([_peer("IT", "down"), _peer("RU", "down"), _peer("RU2", "down")])
        cross.assert_called_once()
        self.assertFalse(handle.call_args.args[1])
        r = database.get_resource_by_id(self.rid)
        self.assertEqual(r["status"], "down")
        self.assertIn("Unreachable from IT, RU, RU2; reachable from DE", handle.call_args.args[2])
        self.assertNotIn(URL, bot._peer_suspects)

    def test_up_here_minority_down_is_degraded_after_two_reports(self):
        peers = [_peer("IT", "up", 1), _peer("RU", "down"), _peer("RU2", "down")]
        self._report()
        self._run(peers)
        self.assertEqual(database.get_resource_by_id(self.rid)["alert_state"], "up")

        bot._vote_cache.clear()  # next telemetry round, two minutes later
        self._report()
        _, notices, _ = self._run(peers)
        r = database.get_resource_by_id(self.rid)
        self.assertEqual(r["alert_state"], "degraded")
        self.assertEqual(r["status"], "up")
        self.assertEqual(notices.call_args.args[0], "start")

    def test_report_without_fresh_cross_check_waits(self):
        self._report()
        self._run([_peer("IT", "up", 1), _peer("RU", "down"), _peer("RU2", "up", 1)])
        self._report()  # a second peer reports right away: peers were just asked
        _, _, cross = self._run([])
        cross.assert_not_called()
        self.assertIn(URL, bot._peer_suspects)  # kept for a later check

    def test_no_report_no_vote(self):
        _, _, cross = self._run([])
        cross.assert_not_called()

    def test_telemetry_message_marks_target(self):
        mock_bot = MagicMock()
        contact = MagicMock()
        contact.address = "ru@example.org"
        mock_bot.rpc.get_contact.return_value = contact
        mock_bot.rpc.get_basic_chat_info.return_value = {"chat_type": "Single"}
        event = MagicMock()
        event.msg.is_info = False
        event.msg.from_id = 42
        event.msg.chat_id = 201
        event.msg.show_padlock = True
        import time
        event.msg.text = "[UPTIME_PEER_METRICS]\n" + json.dumps({"metrics": [
            {"url": URL, "type": "http", "status": "down", "last_checked": int(time.time())}]}) + "\n[/UPTIME_PEER_METRICS]"
        with patch("bot.is_safe_target_url", return_value=True):
            bot.on_new_message(mock_bot, 1, event)
        self.assertEqual(bot._peer_suspects[URL][1], "RU")


class TestPartialOutageDisplay(unittest.TestCase):

    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        self.rid = database.add_resource(CHAT, URL, "Target", "http")
        conn = sqlite3.connect(TEST_DB)
        votes = json.dumps(bot.build_votes("DE", True, 40, None, [_peer("RU", "down"), _peer("IT", "up", 9)]))
        conn.execute("UPDATE resources SET status = 'up', alert_state = 'degraded', last_votes = ? WHERE id = ?",
                     (votes, self.rid))
        conn.commit()
        conn.close()
        database.start_partial_outage(self.rid, 1700000000, json.dumps(["RU"]))
        database.end_partial_outage(self.rid, 1700000600)
        database.start_partial_outage(self.rid, 1700001000, json.dumps(["RU", "RU2"]))

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def test_status_page(self):
        html_out = bot.get_dashboard_html("Chat", database.get_resources(CHAT), 100.0, [],
                                          partial_outages=database.get_chat_partial_outages(CHAT))
        self.assertIn("1 Service(s) Unreachable From Some Regions", html_out)
        self.assertIn('class="indicator degraded"', html_out)
        self.assertIn("DEGRADED", html_out)
        self.assertIn("Last vote: 🔴 RU · 🟢 DE (40ms), IT (9ms)", html_out)
        self.assertIn("🟠 Partial Outages", html_out)
        self.assertIn("unreachable from RU, RU2", html_out)
        self.assertIn("(10m", html_out)  # the ended one lasted 10 minutes

    def test_events_without_incidents_lists_partial_outages(self):
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = CHAT
        bot.events_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("No incidents recorded", text)
        self.assertIn("🟠 **Partial Outages (2", text)
        self.assertIn("`Ongoing`", text)
        self.assertIn("**Target**", text)

    def test_history_lists_partial_outages(self):
        mock_bot = MagicMock()
        event = MagicMock()
        event.msg.chat_id = CHAT
        event.payload = str(self.rid)
        bot.history_command(mock_bot, 1, event)
        text = mock_bot.rpc.send_msg.call_args.args[2].text
        self.assertIn("Partial Outages (2 most recent, not downtime)", text)
        self.assertIn("unreachable from RU", text)


if __name__ == "__main__":
    unittest.main()
