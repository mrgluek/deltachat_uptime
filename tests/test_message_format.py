"""Compact outage messages keep every node's flags and probe details."""
import json
import unittest
from unittest.mock import patch

import bot


class TestMessageFormat(unittest.TestCase):
    def setUp(self):
        self.started = 1794513600  # 2026-11-12 20:00:00 UTC
        self.now = self.started + 300
        self.votes = [
            {"node": "🇷🇺🏢", "status": "down", "error": "Timeout"},
            {"node": "🇫🇷", "status": "degraded", "error": "550 ms, loss 60%, usual 60 ms"},
            {"node": "🇩🇪", "status": "up", "latency_ms": 252},
            {"node": "🇮🇹", "status": "unstable"},
            {"node": "🇬🇧", "status": "unknown"},
        ]
        self.resource = {
            "id": 120, "name": "https://cm.project26.cc", "url": "https://cm.project26.cc",
            "type": "http", "status": "down", "went_down_at": self.started,
            "went_up_at": None, "last_votes": json.dumps(self.votes),
        }
        clock = patch("bot.time.time", return_value=self.now)
        clock.start()
        self.addCleanup(clock.stop)
        uptime = patch("bot.database.get_resource_uptime_30d", return_value=99.92)
        uptime.start()
        self.addCleanup(uptime.stop)

    def assert_plain_with_votes(self, text, votes=None):
        self.assertNotIn("**", text)
        self.assertNotIn("`", text)
        self.assertNotIn("_", text)
        votes = self.votes if votes is None else votes
        self.assertIn(bot.format_votes(votes), text)
        for vote in votes:
            self.assertIn(vote["node"], text)

    def incident(self, resource=None, resolved=False):
        return bot.format_incident_message(
            7, self.started, [resource or self.resource], is_resolved=resolved,
            resolved_at=self.now if resolved else None, total_chat_monitors=3)

    def test_partial_start_is_compact_and_keeps_all_votes(self):
        text = bot.format_degraded_notice([("start", self.resource, self.votes, None)])
        self.assertEqual(text.splitlines()[0], "🟠 Partial outage: 1 monitor(s) unreachable from some nodes")
        self.assertIn("\n🟠 #120 https://cm.project26.cc\n  " + bot.format_votes(self.votes), text)
        self.assertTrue(text.endswith("Not counted as downtime (most nodes reach them)."))
        self.assertNotIn("Target:", text)
        self.assert_plain_with_votes(text)

    def test_partial_resolved_has_duration_without_footer(self):
        text = bot.format_degraded_notice([("end", self.resource, self.votes, self.started)])
        self.assertEqual(text.splitlines()[0], "✅ Partial outage resolved: 1 monitor(s) reachable from all nodes")
        self.assertIn("🟢 #120 https://cm.project26.cc after 5m 0s", text)
        self.assertNotIn("Not counted", text)
        self.assert_plain_with_votes(text)

    def test_mixed_partial_notice_has_one_footer_and_all_monitor_votes(self):
        other = dict(self.resource, id=121, name="Mail")
        text = bot.format_degraded_notice([
            ("start", self.resource, self.votes, None),
            ("end", other, self.votes, self.started),
        ])
        self.assertEqual(text.count("Not counted as downtime"), 1)
        self.assertEqual(text.count(bot.format_votes(self.votes)), 2)
        self.assertIn("🟢 #121 Mail after 5m 0s", text)
        self.assert_plain_with_votes(text)

    def test_ongoing_is_compact_and_keeps_all_votes(self):
        text = self.incident()
        self.assertEqual(text.splitlines()[0], "🚨 Incident #7 · Ongoing (started 2026-11-12 20:00:00 UTC, active 5m 0s)")
        self.assertIn("Affected: 1 / 3 monitors down", text)
        self.assertIn("🔴 #120 https://cm.project26.cc (HTTP) · down 5m 0s · 30d 99.92%\n  🛰️ " + bot.format_votes(self.votes), text)
        self.assertNotIn("Target:", text)
        self.assert_plain_with_votes(text)

    def test_resolved_keeps_all_votes_even_when_operational(self):
        recovered = dict(self.resource, status="up", went_up_at=self.now)
        text = self.incident(recovered, resolved=True)
        self.assertEqual(text.splitlines()[0], "✅ Incident #7 resolved · 5m 0s (2026-11-12 20:00:00 → 2026-11-12 20:05:00 UTC)")
        self.assertIn("All 3 monitors operational\n🟢 #120 https://cm.project26.cc (HTTP) · 30d 99.92%", text)
        self.assertNotIn("Target:", text)
        self.assert_plain_with_votes(text)

    def test_resolved_with_still_partial_keeps_every_node(self):
        recovered = dict(self.resource, status="up", went_up_at=self.now, alert_state="degraded")
        text = self.incident(recovered, resolved=True)
        self.assertIn("\n  🟠 still partial: " + bot.format_votes(self.votes), text)
        self.assertNotIn("Still unreachable", text)
        self.assert_plain_with_votes(text)

    def test_partial_recovery_keeps_votes_for_down_and_recovered_monitors(self):
        recovered = dict(self.resource, id=121, status="up", went_up_at=self.now)
        text = bot.format_incident_message(7, self.started, [self.resource, recovered], total_chat_monitors=3)
        self.assertIn("Affected: 1 / 3 monitors down", text)
        self.assertIn("🟢 #121 https://cm.project26.cc (HTTP) · recovered 20:05:00 UTC · 30d 99.92%", text)
        self.assertEqual(text.count(bot.format_votes(self.votes)), 2)
        self.assert_plain_with_votes(text)

    def test_target_only_when_name_differs_in_every_message_type(self):
        for name in (None, self.resource["url"], "Chatmail"):
            resource = dict(self.resource, name=name)
            messages = [
                bot.format_degraded_notice([("start", resource, self.votes, None)]),
                bot.format_degraded_notice([("end", resource, self.votes, self.started)]),
                self.incident(resource),
                self.incident(resource, resolved=True),
                self.incident(dict(resource, status="up", went_up_at=self.now)),
            ]
            for text in messages:
                with self.subTest(name=name, header=text.splitlines()[0]):
                    self.assertEqual(text.count("  Target: " + resource["url"]), int(name == "Chatmail"))
                    self.assert_plain_with_votes(text)

    def test_single_node_votes_are_preserved(self):
        for status in ("down", "up", "degraded", "unstable"):
            votes = [dict(self.votes[0], status=status)]
            resource = dict(self.resource, last_votes=json.dumps(votes), alert_state="degraded")
            for resolved in (False, True):
                with self.subTest(status=status, resolved=resolved):
                    self.assert_plain_with_votes(self.incident(resource, resolved=resolved), votes)

    def test_ongoing_preserves_slowdown_note(self):
        resource = dict(self.resource, last_changed=self.now - 8 * 86400, interval=60)
        text = self.incident(resource)
        self.assertIn(bot.slowdown_note(resource, self.now), text)
        self.assertIn("🐢 checked every", text)
        self.assert_plain_with_votes(text)

    def test_resolved_without_monitors(self):
        text = bot.format_incident_message(7, self.started, [], True, self.now, total_chat_monitors=0)
        self.assertIn("All monitored resources removed or operational", text)
        self.assertNotIn("**", text)
        self.assertNotIn("`", text)


if __name__ == "__main__":
    unittest.main()
