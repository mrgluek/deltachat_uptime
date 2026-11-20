import asyncio
from contextlib import ExitStack
from functools import wraps
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Lock
import unittest

ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def capture(path):
    """Run the offline benchmark in a separate process to isolate its audit hook."""
    sys.path.insert(0, str(ROOT))
    import database
    from tools.loadbench.gen_db import EPOCH
    from tools.loadbench.measure import Clock, Meter, patch
    from tools.loadbench.scenarios import Bench, import_bot_offline, prepare, report_notices, status_apps

    bot, violations = import_bot_offline()
    result = {}
    for name, workload in (("report_notices", report_notices), ("status_apps", status_apps)):
        clock = Clock(EPOCH)
        with ExitStack() as stack:
            directory = Path(stack.enter_context(TemporaryDirectory()))
            scratch = directory / "fixture.db"
            shutil.copyfile(path, scratch)
            stack.enter_context(patch(database, "DB_PATH", str(scratch)))
            stack.enter_context(patch(database, "time", clock))
            stack.callback(database.close_db)
            stack.callback(database.invalidate_uptime_cache)
            bench = Bench(name, bot, Meter(), clock, stack)
            prepare(bench)

            if name == "report_notices":
                by_chat = {}
                capture_lock = Lock()

                def record(obj, method, kind, chat_arg):
                    original = getattr(obj, method)

                    @wraps(original)
                    def wrapped(*args, **kwargs):
                        with capture_lock:
                            by_chat.setdefault(f"{clock.offset}:{args[chat_arg]}", []).append((kind, args, kwargs))
                        return original(*args, **kwargs)

                    stack.enter_context(patch(obj, method, wrapped))

                record(database, "add_chat_event", "journal", 0)
                record(bot, "_queue_incident_message", "message", 1)
                asyncio.run(workload(bench))
                # Different chats can interleave. Each chat's internal order is significant.
                output = by_chat
                count = sum(len(rows) for rows in by_chat.values())
            else:
                states = []
                original = bot.build_status_state

                def record_state(chat, *args, **kwargs):
                    state = original(chat, *args, **kwargs)
                    states.append((clock.offset, chat, digest(state), bot.status_state_hash(state)))
                    return state

                stack.enter_context(patch(bot, "build_status_state", record_state))
                asyncio.run(workload(bench))
                output = sorted(states)
                count = len(states)
            result[name] = (digest(output), count, bench.communications()["mails_queued_by_priority"])
    bot.db_executor.shutdown()
    bot.rpc_executor.shutdown()
    if violations:
        raise AssertionError(violations)
    return result


class LoadbenchGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.db"
            subprocess.run([sys.executable, "-m", "tools.loadbench.gen_db", "--db", str(fixture)],
                           cwd=ROOT, check=True, capture_output=True, timeout=60)
            run = subprocess.run([sys.executable, __file__, "--capture", str(fixture)],
                                 cwd=ROOT, check=True, capture_output=True, text=True, timeout=120)
        cls.results = json.loads(run.stdout)

    def test_report_notice_messages_and_journal_calls_match_baseline(self):
        # Captured at ce40db3 with the default 10,000-monitor fixture.
        self.assertEqual(self.results["report_notices"], [
            "440a0260066c6d855065348efd2c6174869c0f1ccfe70a2d151a0fef44ae2099", 3577, {"alert": 304},
        ])

    def test_status_states_and_hashes_match_baseline_for_every_chat(self):
        self.assertEqual(self.results["status_apps"], [
            "5780355a943af6864f17b2f9eab807f5dcfb2acb4c70488b3b1d8064fb023481", 600, {"update": 180},
        ])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--capture":
        print(json.dumps(capture(Path(sys.argv[2]))))
    else:
        unittest.main()
