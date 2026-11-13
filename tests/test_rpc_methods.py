"""Every rpc.<method> the bot calls must exist in the installed core (mocks hide typos)."""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestRpcMethodNames(unittest.TestCase):
    def test_used_methods_exist_in_core(self):
        binary = shutil.which("deltachat-rpc-server")
        if not binary:
            self.skipTest("deltachat-rpc-server not installed")
        out = subprocess.run([binary, "--openrpc"], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        if out.returncode != 0 or not out.stdout.strip().startswith("{"):
            self.skipTest("this core cannot print its OpenRPC schema")
        known = {m["name"] for m in json.loads(out.stdout)["methods"]}
        used = set()
        for name in ("bot.py", "outbox.py", "transports_view.py"):
            used |= set(re.findall(r"\brpc\.([a-z_0-9]+)", (ROOT / name).read_text()))
        self.assertEqual(sorted(u for u in used if u not in known), [])


if __name__ == "__main__":
    unittest.main()
