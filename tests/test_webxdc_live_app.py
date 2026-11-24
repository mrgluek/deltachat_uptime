"""Exercise the app's realtime recovery with a fake clock and webxdc channel."""
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which("node"), "Node.js is needed to exercise the app JavaScript")
class TestLiveApp(unittest.TestCase):
    def test_rejoins_after_silence_and_restarts_hello_loop(self):
        html = (Path(__file__).resolve().parents[1] / "webxdc/index.html").read_text()
        script = html.split('// Live updates over the webxdc realtime channel')[1].split('</script>')[0]
        harness = r'''
const assert = require('node:assert/strict');
let now = 1000, interval, joins = [];
Date.now = () => now;
const setInterval = (fn, ms) => { interval = ms; return 1; };
const clearInterval = () => { interval = null; };
const document = {getElementById: () => ({addEventListener() {}})};
const localStorage = {setItem() {}, removeItem() {}, getItem() {return null;}};
const newer = () => false;
const acceptPayload = () => {};
const render = () => {};
const webxdc = {joinRealtimeChannel() {
  const ch = {sent: [], left: false, setListener(fn) {this.listener = fn;},
    send(bytes) {this.sent.push(JSON.parse(new TextDecoder().decode(bytes)).t);},
    leave() {this.left = true;}};
  joins.push(ch); return ch;
}};
const window = {webxdc};
'''
        checks = r'''
startLive();
assert.equal(interval, 5000);
now += 1000;
joins[0].listener(new TextEncoder().encode(JSON.stringify({t:'state',u:{payload:{}}})));
assert.equal(interval, 60000);
now += 120000;
liveTick();
assert.equal(joins.length, 1);
joins[0].listener(new TextEncoder().encode(JSON.stringify({t:'pong', ts:now/1000})));
now += 179999;
liveTick();
assert.equal(joins.length, 1);
now += 1;
liveTick();
assert.equal(joins[0].left, true);
assert.equal(joins.length, 2);
assert.deepEqual(joins[1].sent, ['hello']);
assert.equal(interval, 5000);
now += 180000;
liveTick(); // Also recover if the first state never arrived.
assert.equal(joins[1].left, true);
assert.equal(joins.length, 3);
stopLive();
assert.equal(joins[2].left, true);
assert.equal(interval, null);
'''
        result = subprocess.run([shutil.which("node"), "-e", harness + "// Live updates over the webxdc realtime channel" + script + checks],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
