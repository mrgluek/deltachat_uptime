import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot
import database

TEST_DB = "test_uptime_degraded.db"

# traceroute -n from a home connection to a relay behind a congested peering (2026-10-24)
TRACE = """traceroute to 185.68.247.62 (185.68.247.62), 20 hops max, 40 byte packets
 1  192.168.1.1  1.425 ms  0.944 ms  0.846 ms
 2  * * *
 3  63.130.172.41  11.287 ms  10.662 ms  10.765 ms
 4  * * *
 5  171.75.9.210  23.313 ms  19.296 ms  19.501 ms
 6  213.19.194.214  488.834 ms  118.426 ms  217.638 ms
 7  79.104.235.205  544.049 ms  355.532 ms  541.095 ms
 8  * * 81.211.5.207  539.325 ms
 9  * 92.63.203.97  527.849 ms  540.647 ms
10  * * *
12  * 185.68.247.62  533.273 ms  536.683 ms
"""


class TestAssessPing(unittest.TestCase):
    def test_healthy(self):
        self.assertEqual(bot.assess_ping([44, 45, 43, 46, 44], 5, 44.0), (True, "44 ms"))

    def test_one_lost_echo_is_not_degraded(self):
        self.assertEqual(bot.assess_ping([44, 45, 43, 46], 5, 44.0), (True, "44 ms, loss 20%"))

    def test_loss_is_degraded(self):
        state, details = bot.assess_ping([547, 548, 555], 5, 60.0)
        self.assertEqual(state, bot.CHECK_DEGRADED)
        self.assertEqual(details, "548 ms, loss 40%, usual 60 ms")

    def test_slow_without_loss_is_degraded(self):
        self.assertEqual(bot.assess_ping([550] * 5, 5, 60.0)[0], bot.CHECK_DEGRADED)

    def test_small_absolute_rise_is_not_degraded(self):
        # 5 -> 20 ms is four times the usual round trip, but nobody notices 15 ms
        self.assertIs(bot.assess_ping([20] * 5, 5, 5.0)[0], True)

    def test_no_baseline_judges_loss_only(self):
        self.assertIs(bot.assess_ping([900] * 5, 5, None)[0], True)
        state, details = bot.assess_ping([900, 901], 5, None)
        self.assertEqual(state, bot.CHECK_DEGRADED)
        self.assertNotIn("usual", details)


class TestPingBaseline(unittest.TestCase):
    def test_first_sample_starts_it(self):
        self.assertEqual(bot.next_ping_baseline(None, 60, False), 60.0)

    def test_degraded_samples_do_not_move_it(self):
        self.assertEqual(bot.next_ping_baseline(60.0, 550, True), 60.0)
        self.assertIsNone(bot.next_ping_baseline(None, 550, True))

    def test_follows_faster_quickly_and_slower_slowly(self):
        down = bot.next_ping_baseline(100.0, 50, False)
        up = bot.next_ping_baseline(100.0, 150, False)
        self.assertLess(down, 90)
        self.assertLess(up, 105)


class TestTraceroute(unittest.TestCase):
    def test_finds_the_biggest_rise(self):
        self.assertEqual(bot.summarize_traceroute(TRACE),
                         "trace: +323 ms between hop 6 213.19.194.214 and hop 7 79.104.235.205")

    def test_flat_path_has_no_hint(self):
        flat = " 1  10.0.0.1  1.0 ms  1.1 ms  1.2 ms\n 2  198.51.100.1  20.0 ms  21.0 ms  20.5 ms\n"
        self.assertEqual(bot.summarize_traceroute(flat), "")

    def test_ipv6_hops(self):
        out = " 1  2001:db8::1  1.0 ms  1.0 ms  1.0 ms\n 2  2001:db8:1::2  300.0 ms  310.0 ms  305.0 ms\n"
        self.assertEqual(bot.summarize_traceroute(out),
                         "trace: +304 ms between hop 1 2001:db8::1 and hop 2 2001:db8:1::2")


class TestDegradedVotes(unittest.TestCase):
    def setUp(self):
        bot._node_unstable_until.clear()

    def _votes(self, *statuses):
        return [{"node": f"N{i}", "status": s, "local": i == 0, "latency_ms": 50 if s == "up" else None,
                 "error": None if s == "up" else "550 ms, loss 60%, usual 60 ms"}
                for i, s in enumerate(statuses)]

    def test_check_status(self):
        self.assertEqual(bot.check_status(None), "skip")
        self.assertEqual(bot.check_status(bot.CHECK_DEGRADED), "degraded")
        self.assertEqual(bot.check_status(True), "up")
        self.assertEqual(bot.check_status(False), "down")

    def test_one_degraded_node_makes_degraded(self):
        self.assertEqual(bot.decide_quorum(self._votes("degraded", "up", "up")), "degraded")

    def test_degraded_never_makes_down(self):
        self.assertEqual(bot.decide_quorum(self._votes("degraded", "degraded", "degraded")), "degraded")

    def test_down_majority_still_down(self):
        self.assertEqual(bot.decide_quorum(self._votes("down", "down", "degraded")), "down")

    def test_single_degraded_voter_stays_up(self):
        # Without peers this node decides alone, and a reachable target is not DOWN
        self.assertEqual(bot.decide_quorum(self._votes("degraded")), "up")

    def test_vote_entry_keeps_degraded(self):
        v = bot._vote_entry("HOME", "degraded", 548, "548 ms, loss 40%")
        self.assertEqual((v["status"], v["error"]), ("degraded", "548 ms, loss 40%"))

    def test_format_and_summary(self):
        votes = [{"node": "HOME", "status": "degraded", "error": "548 ms, loss 60%, usual 60 ms"},
                 {"node": "DE", "status": "up", "latency_ms": 44}]
        self.assertEqual(bot.format_votes(votes), "🟠 HOME (548 ms, loss 60%, usual 60 ms) · 🟢 DE (44ms)")
        self.assertEqual(bot._votes_summary(votes), "Degraded path from HOME; reachable from DE")

    def test_degraded_outliers_make_a_node_unstable(self):
        votes = self._votes("degraded", "up", "up")
        self.assertTrue(bot.is_outlier_down(votes[0], votes))
        bot._node_unstable_until["N0"] = 4102444800  # far future
        masked = bot.mask_unstable_votes(votes)
        self.assertEqual(masked[0]["status"], "unstable")


class TestPingSeries(unittest.TestCase):
    def setUp(self):
        self.orig_db = database.DB_PATH
        database.close_db()
        database.DB_PATH = TEST_DB
        database.init_db()
        bot._ping_baseline_cache.clear()
        bot._path_traces.clear()

    def tearDown(self):
        database.close_db()
        database.DB_PATH = self.orig_db
        for suffix in ["", "-wal", "-shm"]:
            if os.path.exists(TEST_DB + suffix):
                os.remove(TEST_DB + suffix)

    def _check(self, dgram):
        no_raw = MagicMock()
        no_raw.ping = AsyncMock(side_effect=PermissionError("Operation not permitted"))
        with patch('bot.has_route_to', return_value=True), patch.object(bot, 'aioping', no_raw), \
             patch.object(bot, '_dgram_ping', dgram), patch.object(bot, 'PING_SPACING', 0), \
             patch.object(bot, 'path_trace_hint', return_value="trace: +324 ms between hop 6 a and hop 7 b"):
            return asyncio.run(bot.run_single_check({"type": "ping", "url": "93.184.216.34"}))

    def test_sends_five_echoes_and_reports_median(self):
        dgram = AsyncMock(side_effect=[0.040, 0.044, 0.050, 0.041, 0.043])
        is_up, details, ms = self._check(dgram)
        self.assertEqual(dgram.call_count, 5)
        self.assertIs(is_up, True)
        self.assertEqual((details, ms), ("43 ms", 43))
        self.assertAlmostEqual(database.get_ping_baseline("93.184.216.34"), 43.0)

    def test_lossy_path_is_degraded_with_trace(self):
        bot.note_ping_sample("93.184.216.34", 60, False)
        lost = asyncio.TimeoutError()
        dgram = AsyncMock(side_effect=[0.547, lost, 0.548, lost, lost])
        is_up, details, ms = self._check(dgram)
        self.assertEqual(is_up, bot.CHECK_DEGRADED)
        self.assertEqual(details, "547 ms, loss 60%, usual 60 ms; trace: +324 ms between hop 6 a and hop 7 b")
        self.assertEqual(ms, 547)
        self.assertEqual(database.get_ping_baseline("93.184.216.34"), 60.0)  # not learned

    def test_all_lost_is_down(self):
        is_up, details, _ = self._check(AsyncMock(side_effect=asyncio.TimeoutError()))
        self.assertIs(is_up, False)
        self.assertEqual(details, "Timeout")

    def test_unreachable_host_error(self):
        err = OSError(113, "No route to host")
        is_up, details, _ = self._check(AsyncMock(side_effect=err))
        self.assertIs(is_up, False)
        self.assertEqual(details, "Ping failed: No route to host")


class TestAutoAccount(unittest.TestCase):
    def _args(self, account=None):
        args = MagicMock(account=account)
        args.cmd = bot.dc_cli.__class__  # anything not named _serve_cmd
        return args

    def _serve_args(self, account=None):
        def _serve_cmd(*_):
            pass
        return MagicMock(account=account, cmd=_serve_cmd)

    def test_creates_account_on_serve_without_configured_one(self):
        b = MagicMock()
        b.rpc.get_all_account_ids.return_value = []
        b.rpc.add_account.return_value = 1
        b.rpc.get_config.return_value = "abc@chatmail.example"
        bot.ensure_configured_account(b, self._serve_args())
        b.rpc.set_config.assert_any_call(1, "bot", "1")
        b.rpc.init_transports.assert_called_once_with(1, None)

    def test_reuses_unconfigured_account(self):
        b = MagicMock()
        b.rpc.get_all_account_ids.return_value = [3]
        b.rpc.is_configured.return_value = False
        bot.ensure_configured_account(b, self._serve_args())
        b.rpc.add_account.assert_not_called()
        b.rpc.init_transports.assert_called_once_with(3, None)

    def test_nothing_when_configured_or_not_serving(self):
        b = MagicMock()
        b.rpc.get_all_account_ids.return_value = [1]
        b.rpc.is_configured.return_value = True
        bot.ensure_configured_account(b, self._serve_args())
        bot.ensure_configured_account(b, self._args())
        b.rpc.init_transports.assert_not_called()

    def test_failure_is_logged_not_raised(self):
        b = MagicMock()
        b.rpc.get_all_account_ids.return_value = []
        b.rpc.init_transports.side_effect = RuntimeError("no relay answered")
        bot.ensure_configured_account(b, self._serve_args())
        b.logger.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
