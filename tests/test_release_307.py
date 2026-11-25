"""3.0.7: deltas also for chats whose snapshot only fits the wire limit with node details omitted."""
import json
import unittest

import bot
from test_release_305 import Base, STEP, accept, significant


class TestDeltaWithOmittedDetails(Base):
    """A big chat (84 monitors, 7 nodes) at a tight update size limit: every snapshot drops node details
    (latency, error). Before 3.0.7 this forced a full snapshot for every update, so the busiest chats,
    which dominate storage, never got a delta."""

    def setUp(self):
        super().setUp()
        self.rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 60000, "sendUpdateInterval": 10000}

    def tighten(self):
        # Make the full snapshot exceed the limit but the one without node details fit.
        for rid in self.rids:
            self.set_fields(rid, last_votes=json.dumps([{"node": f"node{n}", "status": "up", "latency_ms": 20 + n,
                                                         "error": "x" * 60} for n in range(self.nodes)]))

    def test_deltas_are_used_when_snapshot_drops_node_details(self):
        self.make_monitors()
        self.tighten()
        self.existing()
        first, first_size = self.deliver()
        self.assertTrue(first["payload"].get("details_omitted"), "test data must force details_omitted")
        self.assertEqual(first["payload"]["snap"], 1)
        current = accept(None, first["payload"])
        sizes = []
        for i in range(1, 20):
            self.now += STEP
            self.flip(self.rids[i])
            update, size = self.deliver()
            self.assertEqual(update["payload"].get("delta"), 1, f"update {i} must be a delta")
            self.assertTrue(update["payload"].get("details_omitted"))
            sizes.append(size)
            current = accept(current, update["payload"])
            self.assertEqual(significant(current), significant(bot.build_status_state(1)), f"update {i}")
        self.assertLess(max(sizes), first_size * 0.1)
        self.now += STEP
        self.flip(self.rids[30])
        update, _ = self.deliver()
        self.assertEqual(update["payload"].get("snap"), 1, "the 20th update is a snapshot again")


if __name__ == "__main__":
    unittest.main()
