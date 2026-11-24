"""3.0.5: delta updates in the status app (stored updates are small deltas, with periodic snapshots)."""
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import deltachat2
except ImportError:
    module = MagicMock()
    module.MsgData = lambda **kw: type("MsgData", (), kw)()
    sys.modules["deltachat2"] = module
try:
    import deltabot_cli
except ImportError:
    module = MagicMock()
    module.BotCli.return_value.on.side_effect = lambda *a, **kw: lambda f: f
    sys.modules["deltabot_cli"] = module

import bot
import database
from outbox import Outbox

MONITORS = 84
NODES = 7
STEP = 400  # seconds between updates: inside the hourly cap (status line edits count too), far from the 30 minute refresh


def js_order(m):
    return ({"down": 0, "partial": 1, "up": 2, "paused": 3}.get(m["status"], 4), m["id"])


def apply_delta(current, delta):
    """Python port of mergeDelta in webxdc/index.html."""
    by_id = {m["id"]: m for m in current["monitors"]}
    for i in delta.get("rm", []):
        by_id.pop(i, None)
    for m in delta.get("chg", []):
        by_id[m["id"]] = m
    nxt = {k: v for k, v in delta.items() if k not in ("delta", "base", "chg", "rm")}
    nxt["monitors"] = sorted(by_id.values(), key=js_order)
    return nxt


def accept(current, payload):
    """Python port of acceptPayload: returns the new current state."""
    if payload.get("delta"):
        if current is None:
            return current
        held = current.get("generated_at") or 0
        if payload["generated_at"] > held and payload["base"] <= held:
            return apply_delta(current, payload)
        return current
    if current is None or (payload.get("generated_at") or 0) >= (current.get("generated_at") or 0):
        return payload
    return current


def significant(state):
    """What a delta must reproduce exactly."""
    return [(m["id"], m["name"], m["url"], m["type"], m["status"], m["since"],
             [(n["node"], n["status"]) for n in m["nodes"]]) for m in state["monitors"]]


class Base(unittest.TestCase):
    version = "6"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = database.DB_PATH
        database.close_db()
        database.DB_PATH = os.path.join(self.tmp.name, "r305.db")
        database.init_db()
        self.rpc = MagicMock()
        self.rpc.send_msg.side_effect = lambda *a: next(itertools.count(500))
        self.rpc.get_existing_msg_ids.side_effect = lambda acc, ids: ids
        self.rpc.get_basic_chat_info.return_value = {"name": "Test chat"}
        self.rpc.get_webxdc_info.return_value = {"sendUpdateMaxSize": 128000, "sendUpdateInterval": 10000}
        self.rpc.get_chat_contacts.return_value = [1, 2, 3]
        self.client = MagicMock(rpc=self.rpc)
        self.now = 1_000_000
        self.patches = [patch.object(bot, "dc_outbox", Outbox()), patch.object(bot, "dc_bot_instance", self.client),
                        patch.object(bot, "dc_accid", 1), patch.dict(os.environ, {"DC_DB_DIR": self.tmp.name}),
                        patch("bot.time.time", side_effect=lambda: self.now)]
        for p in self.patches:
            p.start()
        database.set_chat_report_app(1, "on")
        self.rids = []

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        database.close_db()
        database.DB_PATH = self.old_path
        self.tmp.cleanup()

    nodes = NODES

    def votes(self, rid, tag=""):
        return json.dumps([{"node": f"node{n}", "status": "up", "latency_ms": 20 + (rid + n) % 50,
                            "error": None} for n in range(self.nodes)])

    def make_monitors(self, count=MONITORS):
        for i in range(count):
            rid = database.add_resource(1, f"https://example{i}.org/health", f"Example monitor {i}", "http")
            self.set_fields(rid, status="up", last_changed=900_000 + i, last_votes=self.votes(rid))
            self.rids.append(rid)

    def set_fields(self, rid, **values):
        with database._writer_transaction() as conn:
            conn.execute("UPDATE resources SET " + ", ".join(k + " = ?" for k in values) + " WHERE id = ?",
                         (*values.values(), rid))

    def flip(self, rid):
        row = database.get_resources(1)
        status = next(r["status"] for r in row if r["id"] == rid)
        self.set_fields(rid, status="down" if status == "up" else "up", last_changed=self.now)

    def existing(self, version=None):
        database.set_chat_webxdc(1, 321)
        database.set_chat_status_line(1, 322, bot._status_line_hash(bot.status_line_text(bot.build_status_state(1))))
        database.set_config("webxdc_app_version:1", version or self.version)
        database.set_config("webxdc_posted_at:1", str(self.now))

    def deliver(self):
        before = self.rpc.send_webxdc_status_update.call_count
        bot._deliver_status_app(1, self.client, 1, known_msg_id=321)
        # keep the line hash current so line edits never matter
        database.set_chat_status_line(1, 322, bot._status_line_hash(bot.status_line_text(bot.build_status_state(1))))
        calls = self.rpc.send_webxdc_status_update.call_args_list
        if len(calls) == before:
            return None
        return json.loads(calls[-1][0][2]), len(calls[-1][0][2].encode())


class TestDeltaSizes(Base):
    def test_one_monitor_change_is_a_small_delta_and_snapshot_keeps_size(self):
        self.make_monitors()
        self.existing()
        first, first_size = self.deliver()
        self.assertEqual(first["payload"]["snap"], 1)
        self.assertGreater(first_size, 30000)
        self.now += STEP
        self.flip(self.rids[40])
        update, size = self.deliver()
        self.assertEqual(update["payload"]["delta"], 1)
        self.assertEqual([m["id"] for m in update["payload"]["chg"]], [self.rids[40]])
        self.assertLess(size, 3000)
        self.assertEqual(update["payload"]["base"], first["payload"]["generated_at"])


class TestSequence(Base):
    def run_sequence(self, mode=None, n=100, seed=7):
        self.make_monitors()
        self.existing()
        if mode:
            database.set_config("status_app_delta", mode)
        rng = random.Random(seed)
        sent = []
        current = None
        states = []
        for i in range(n):
            if i:
                self.now += STEP
                for rid in rng.sample(self.rids, rng.randint(1, 3)):
                    self.flip(rid)
            result = self.deliver()
            self.assertIsNotNone(result, f"update {i} was not sent")
            update, size = result
            sent.append((update["payload"], size))
            current = accept(current, update["payload"])
            expected = bot.build_status_state(1)
            self.assertEqual(significant(current), significant(expected), f"update {i}")
            states.append(current)
        return sent

    def test_hundred_updates_are_at_least_8_times_smaller_and_snapshots_where_required(self):
        sent = self.run_sequence()
        delta_total = sum(size for _, size in sent)
        snapshot_total = None
        # same sequence, switched off: snapshots only
        self.tearDown(); self.setUp()
        off = self.run_sequence(mode="off")
        snapshot_total = sum(size for _, size in off)
        self.assertGreaterEqual(snapshot_total, 8 * delta_total, (snapshot_total, delta_total))
        snaps = [i for i, (p, _) in enumerate(sent) if not p.get("delta")]
        self.assertEqual(snaps[0], 0)
        for i in range(0, 100, 20):
            self.assertIn(i, snaps)
        self.assertEqual(snaps, [0, 20, 40, 60, 80])
        self.assertTrue(all(not p.get("delta") and p.get("snap") for p, _ in off))

    def test_dropped_update_is_ignored_then_healed_by_snapshot(self):
        sent = self.run_sequence(n=25)
        current = None
        for i, (payload, _) in enumerate(sent):
            if i == 5:
                continue  # lost on this device
            current = accept(current, payload)
            if 5 < i < 20:
                self.assertEqual(current["generated_at"], sent[4][0]["generated_at"], i)
        self.assertEqual(current["generated_at"], sent[24][0]["generated_at"])
        self.assertEqual(significant(current), significant(bot.build_status_state(1)))

    def test_snapshot_on_refresh_and_when_record_is_missing_or_bad(self):
        self.make_monitors()
        self.existing()
        self.deliver()
        self.now += STEP
        self.flip(self.rids[1])
        self.assertEqual(self.deliver()[0]["payload"].get("delta"), 1)
        # record missing
        database.set_config("webxdc_sent:1", "")
        self.now += STEP
        self.flip(self.rids[2])
        self.assertNotIn("delta", self.deliver()[0]["payload"])
        # unreadable record
        for bad in ("not json", "[1]", '{"g":"x","m":{}}'):
            database.set_config("webxdc_sent:1", bad)
            self.now += STEP
            self.flip(self.rids[3])
            self.assertNotIn("delta", self.deliver()[0]["payload"], bad)
        # refresh: only latency drift, 30 minutes later
        self.now += 2000
        votes = json.loads(self.votes(self.rids[0]))
        votes[0]["latency_ms"] = 999
        self.set_fields(self.rids[0], last_votes=json.dumps(votes))
        update, _ = self.deliver()
        self.assertNotIn("delta", update["payload"])
        self.assertEqual(update["payload"]["snap"], 1)

    def test_monitor_added_and_removed(self):
        self.make_monitors(10)
        self.existing()
        self.deliver()
        current = accept(None, self.rpc.send_webxdc_status_update.call_args[0][2] and
                         json.loads(self.rpc.send_webxdc_status_update.call_args[0][2])["payload"])
        self.now += STEP
        database.delete_resource(1, self.rids[3])
        rid = database.add_resource(1, "https://new.example.org", "New", "http")
        self.set_fields(rid, status="up", last_changed=self.now, last_votes=self.votes(rid))
        update, _ = self.deliver()
        payload = update["payload"]
        self.assertEqual(payload.get("delta"), 1)
        self.assertEqual(payload["rm"], [self.rids[3]])
        self.assertEqual([m["id"] for m in payload["chg"]], [rid])
        current = accept(current, payload)
        self.assertEqual(significant(current), significant(bot.build_status_state(1)))


class TestVersionAndSwitch(Base):
    def test_version_5_instance_gets_snapshots_only_and_no_record(self):
        self.make_monitors(10)
        self.existing(version="5")
        for i in range(4):
            self.now += STEP
            self.flip(self.rids[i])
            update, _ = self.deliver()
            self.assertNotIn("delta", update["payload"])
            self.assertNotIn("snap", update["payload"])
        self.assertIsNone(database.get_config("webxdc_sent:1"))
        self.rpc.send_msg.assert_not_called()  # no forced re-post

    def test_mode_off_sends_snapshots_and_keeps_record_current(self):
        self.make_monitors(10)
        self.existing()
        self.deliver()
        database.set_config("status_app_delta", "off")
        self.now += STEP
        self.flip(self.rids[0])
        self.assertNotIn("delta", self.deliver()[0]["payload"])
        record = json.loads(database.get_config("webxdc_sent:1"))
        self.assertEqual(record["g"], self.now)
        database.set_config("status_app_delta", "on")
        self.now += STEP
        self.flip(self.rids[1])
        update = self.deliver()[0]["payload"]
        self.assertEqual(update["base"], record["g"])
        self.assertEqual([m["id"] for m in update["chg"]], [self.rids[1]])

    def test_failed_send_does_not_advance_record(self):
        self.make_monitors(10)
        self.existing()
        self.deliver()
        before = database.get_config("webxdc_sent:1")
        self.rpc.send_webxdc_status_update.side_effect = RuntimeError("offline")
        self.now += STEP
        self.flip(self.rids[0])
        before_calls = self.rpc.send_webxdc_status_update.call_count
        bot._deliver_status_app(1, self.client, 1, known_msg_id=321)
        self.assertEqual(self.rpc.send_webxdc_status_update.call_count, before_calls + 1)  # it was tried
        self.assertEqual(database.get_config("webxdc_sent:1"), before)

    def test_command_and_mode_parsing(self):
        self.assertEqual(bot.get_status_app_delta_mode(), "on")
        database.set_config("status_app_delta", " OFF ")
        self.assertEqual(bot.get_status_app_delta_mode(), "off")
        database.set_config("status_app_delta", "junk")
        self.assertEqual(bot.get_status_app_delta_mode(), "on")
        event = MagicMock()
        event.msg.chat_id = 9
        event.payload = "off"
        with patch.object(bot, "_is_dc_admin", return_value=True), patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.appdelta_command(self.client, 1, event)
        self.assertEqual(database.get_config("status_app_delta"), "off")
        self.assertIn("off", send.call_args[0][3].text)
        event.payload = "maybe"
        with patch.object(bot, "_is_dc_admin", return_value=False), patch.object(bot, "_dc_send_msg_with_stats") as send:
            bot.appdelta_command(self.client, 1, event)
        self.assertEqual(database.get_config("status_app_delta"), "off")

    def test_instance_versions_accepted_without_repost(self):
        self.assertTrue(bot._status_app_version_ok("5"))
        self.assertTrue(bot._status_app_version_ok("6"))
        self.assertFalse(bot._status_app_version_ok("4"))
        self.assertFalse(bot._status_app_version_ok(None))
        self.assertEqual(bot.WEBXDC_DELTA_APP_VERSION, 6)


class TestPerUpdateBounds(Base):
    def test_config_and_database_calls_per_update_for_150_monitors(self):
        self.nodes = 3  # 150 monitors x 7 nodes would not fit one update at all
        self.make_monitors(150)
        self.existing()
        self.deliver()
        self.now += STEP
        self.flip(self.rids[100])
        reads, writes, conns = [], [], []
        real_get, real_gets, real_set = database.get_config, database.get_configs, database.set_config
        real_connect = database._connect
        with patch.object(database, "get_config", side_effect=lambda k, *a, **kw: (reads.append(k), real_get(k, *a, **kw))[1]), \
                patch.object(database, "get_configs", side_effect=lambda ks: (reads.extend(list(ks)), real_gets(ks))[1]), \
                patch.object(database, "set_config", side_effect=lambda k, v: (writes.append(k), real_set(k, v))[1]), \
                patch.object(database, "_connect", side_effect=lambda *a, **kw: (conns.append(1), real_connect(*a, **kw))[1]):
            update, _ = self.deliver()
        self.assertEqual(update["payload"].get("delta"), 1)
        # one batched read for both new keys, nothing else new
        extra_reads = [r for r in reads if r in ("webxdc_sent:1", "status_app_delta")]
        self.assertEqual(extra_reads, ["webxdc_sent:1", "status_app_delta"])
        self.assertEqual([w for w in writes if w.startswith("webxdc_sent")], ["webxdc_sent:1"])
        self.assertEqual(sum(w.startswith("webxdc_sent") for w in writes), 1)
        # no connection per monitor: the whole update, including building the state, stays far below 150
        self.assertLess(len(conns), 60, len(conns))
        # the delta itself does no database work: compute it with the database patched out
        state = bot.build_status_state(1)
        record = bot._status_sent_record(state)
        prev = {"g": state["generated_at"] - 1, "m": dict(record["m"])}
        with patch.object(database, "_connect", side_effect=AssertionError("database used")), \
                patch.object(database, "get_config", side_effect=AssertionError("config read")), \
                patch.object(database, "get_configs", side_effect=AssertionError("config read")):
            bot._status_delta_json(state, prev, record, 60000, None, 80000)


@unittest.skipUnless(shutil.which("node"), "Node.js is needed to run the app merge")
class TestAppMerge(unittest.TestCase):
    def test_js_merge_matches_the_python_port(self):
        html = (Path(__file__).resolve().parents[1] / "webxdc/index.html").read_text()
        code = html.split("// DELTA-BEGIN")[1].split("// DELTA-END")[0]
        harness = ("const order = {down: 0, partial: 1, up: 2, paused: 3};\n"
                   "let currentState; let rendered = [];\n"
                   "function render(s) { currentState = s; rendered.push(s); }\n"
                   "const newer = state => !currentState || (state && (state.generated_at || 0) >= (currentState.generated_at || 0));\n"
                   + code + "\n"
                   "const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
                   "for (const p of cases) acceptPayload(p);\n"
                   "console.log(JSON.stringify(currentState));\n")

        def mon(i, status="up", since=1):
            return {"id": i, "name": f"m{i}", "url": f"u{i}", "type": "http", "status": status, "since": since,
                    "nodes": [{"node": "n", "status": status}]}
        base = {"generated_at": 100, "chat": "c", "counts": {}, "monitors": [mon(1), mon(2), mon(3)]}
        sequence = [
            {"delta": 1, "base": 90, "generated_at": 95, "chg": [mon(9)], "rm": []},      # no state yet: ignored
            base,
            {"delta": 1, "base": 100, "generated_at": 110, "chg": [mon(2, "down", 105), mon(7)], "rm": [3],
             "chat": "c2", "counts": {"down": 1}, "events_omitted": True},
            {"delta": 1, "base": 120, "generated_at": 130, "chg": [mon(1, "down", 125)], "rm": []},  # missed one
            {"delta": 1, "base": 110, "generated_at": 105, "chg": [mon(1, "down", 125)], "rm": []},  # older
            {"delta": 1, "base": 110, "generated_at": 140, "chg": [mon(1, "down", 135)], "rm": [7]},
        ]
        expected = None
        for payload in sequence:
            expected = accept(expected, payload)
        result = subprocess.run(["node", "-e", harness], input=json.dumps(sequence), capture_output=True,
                                text=True, check=True)
        self.assertEqual(json.loads(result.stdout), expected)
        self.assertEqual([m["id"] for m in expected["monitors"]], [1, 2])
        self.assertEqual(expected["generated_at"], 140)


if __name__ == "__main__":
    unittest.main()
