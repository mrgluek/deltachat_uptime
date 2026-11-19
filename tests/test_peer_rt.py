import hmac
import json
import unittest
from unittest.mock import patch

import peer_rt as rt


KEY_OUT = b"a" * 32
KEY_IN = b"b" * 32
EPOCH = "a1b2c3d4" * 4
RECIPIENT = "f00d1234" * 4
PEER = "A" * 40
OTHER_PEER = "B" * 40


class Clock:
    def __init__(self):
        self.now = 100_000

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestFrameCodec(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.replay = rt.ReplayWindow(clock=self.clock)

    def encode(self, kind="ping", seq=1, body=None, **kwargs):
        return rt.encode(kind, EPOCH, seq, body, KEY_OUT, recipient=RECIPIENT, clock=self.clock, **kwargs)

    def decode(self, data, key=KEY_OUT, peer=PEER):
        return rt.decode(data, key, peer=peer, replay=self.replay, clock=self.clock)

    @staticmethod
    def sign(frame):
        unsigned = {key: value for key, value in frame.items() if key != "h"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(KEY_OUT, canonical, "sha256").hexdigest()

    def test_round_trip_every_kind(self):
        bodies = {
            "hello": {},
            "ping": {},
            "pong": {"e": EPOCH, "s": 1},
            "ack": {"e": RECIPIENT, "s": [0, 3, 10]},
            "req": {"url": "https://example.org", "req_id": "1"},
            "resp": {"status": "up", "req_id": "1"},
            "breq": {"targets": [{"url": "https://example.org"}], "req_id": "2"},
            "bresp": {"results": [{"status": "up"}], "req_id": "2"},
            "metrics": {"metrics": [{"name": "Zürich"}]},
        }
        self.assertEqual(set(bodies), rt.RT_KINDS)
        for seq, (kind, body) in enumerate(bodies.items()):
            with self.subTest(kind=kind):
                ack = int(kind in {"req", "resp", "breq", "bresp"})
                data = self.encode(kind, seq, body, ack=ack)
                self.assertIsInstance(data, bytes)
                expected = {"v": 2, "k": kind, "e": EPOCH, "r": RECIPIENT, "s": seq,
                            "ts": self.clock.now, "a": ack, "b": body}
                self.assertEqual(self.decode(data), dict(expected, h=self.sign(expected)))

    def test_tampered_body_timestamp_and_sequence(self):
        data = self.encode("req", body={"site": "original"})
        for field, value in (("b", {"site": "changed"}), ("ts", self.clock.now + 1), ("s", 2), ("r", EPOCH)):
            with self.subTest(field=field):
                altered = dict(json.loads(data), **{field: value})
                with self.assertRaisesRegex(rt.FrameError, "HMAC"):
                    self.decode(json.dumps(altered).encode())
        self.assertEqual(self.decode(data)["s"], 1)

    def test_wrong_key_and_other_directions_key(self):
        data = self.encode()
        for key in (b"wrong", KEY_IN):
            with self.subTest(key=key):
                with self.assertRaisesRegex(rt.FrameError, "HMAC"):
                    self.decode(data, key=key)
        self.assertEqual(self.decode(data)["s"], 1)

    def test_timestamp_window_in_both_directions(self):
        for seq, difference in enumerate((-121, -120, 120, 121)):
            with self.subTest(difference=difference):
                frame = rt.encode("ping", EPOCH, seq, {}, KEY_OUT, recipient=RECIPIENT,
                                  clock=lambda: self.clock() + difference)
                if abs(difference) > 120:
                    with self.assertRaisesRegex(rt.FrameError, "timestamp"):
                        self.decode(frame)
                    self.assertEqual(self.decode(self.encode(seq=seq))["s"], seq)
                else:
                    self.assertEqual(self.decode(frame)["ts"], self.clock() + difference)
        self.clock.advance(0.5)
        frame = dict(json.loads(self.encode()), ts=10**400)
        frame["h"] = self.sign(frame)
        with self.assertRaisesRegex(rt.FrameError, "timestamp"):
            self.decode(json.dumps(frame).encode())

    def test_replay_is_per_peer_and_epoch(self):
        data = self.encode()
        self.decode(data)
        with self.assertRaisesRegex(rt.FrameError, "replay"):
            self.decode(data)
        self.decode(data, peer=OTHER_PEER)
        next_epoch = rt.encode("ping", "01234567" * 4, 1, {}, KEY_OUT, recipient=RECIPIENT, clock=self.clock)
        self.decode(next_epoch)
        self.clock.advance(299)
        with self.assertRaisesRegex(rt.FrameError, "replay"):
            self.decode(self.encode())
        self.clock.advance(1)
        self.decode(self.encode())

    def test_full_replay_window_keeps_unexpired_entries(self):
        with patch.object(rt, "RT_REPLAY_MAX_ENTRIES", 2):
            self.decode(self.encode(seq=1))
            self.decode(self.encode(seq=2))
            with self.assertRaisesRegex(rt.FrameError, "full replay window"):
                self.decode(self.encode(seq=3))
            with self.assertRaisesRegex(rt.FrameError, "replay"):
                self.decode(self.encode(seq=1))
            self.decode(self.encode(seq=3), peer=OTHER_PEER)
            self.clock.advance(300)
            self.decode(self.encode(seq=3))

    def test_size_limit_applies_to_entire_frame(self):
        available = rt.RT_PEER_MAX_BYTES - len(self.encode(body=""))
        data = self.encode(body="x" * available)
        self.assertEqual(len(data), 100_000)
        self.assertEqual(self.decode(data)["b"], "x" * available)
        with self.assertRaisesRegex(rt.FrameError, "too large"):
            self.encode(body="x" * (available + 1))
        with patch.object(rt.json, "loads") as loads:
            with self.assertRaisesRegex(rt.FrameError, "too large"):
                self.decode(data + b" ")
            loads.assert_not_called()

    def test_invalid_json_and_frame_shape(self):
        data = self.encode(body={})
        for invalid in (b"{", b"\xff", b"[]", b"{}", data.replace(b'"a":0', b'"a":0,"a":0')):
            with self.subTest(invalid=invalid):
                with self.assertRaises(rt.FrameError):
                    self.decode(invalid)
        for key, value in (("e", "abc"), ("r", None), ("s", -1), ("a", True), ("ts", "100000")):
            with self.subTest(key=key):
                frame = dict(json.loads(data), **{key: value})
                frame["h"] = self.sign(frame)
                with self.assertRaises(rt.FrameError):
                    self.decode(json.dumps(frame).encode())
        with self.assertRaisesRegex(rt.FrameError, "ack payload"):
            self.encode("ack", body={"e": RECIPIENT, "s": ["1"]})
        with self.assertRaisesRegex(rt.FrameError, "frame JSON"):
            self.encode(body={"value": float("nan")})

    def test_unknown_version_and_kind_have_valid_hmac(self):
        for field, value, error in (("v", 1, "version"), ("k", "other", "kind")):
            with self.subTest(field=field):
                frame = dict(json.loads(self.encode()), **{field: value})
                frame["h"] = self.sign(frame)
                with self.assertRaisesRegex(rt.FrameError, error):
                    self.decode(json.dumps(frame).encode())
        with self.assertRaisesRegex(rt.FrameError, "kind"):
            self.encode("other")

    def test_canonical_json_stable_across_object_order_and_whitespace(self):
        data = self.encode("req", body={"z": {"b": 2, "a": "café"}, "a": [1]})
        self.assertEqual(data, self.encode("req", body={"a": [1], "z": {"a": "café", "b": 2}}))
        frame = json.loads(data)
        self.assertEqual(frame["h"], self.sign(frame))
        shuffled = dict(reversed(list(frame.items())))
        reformatted = json.dumps(shuffled, indent=2, ensure_ascii=False).encode("utf-8")
        self.assertEqual(self.decode(reformatted), frame)

    def test_hmac_uses_constant_time_comparison(self):
        data = self.encode()
        tag = json.loads(data)["h"]
        with patch.object(rt.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            self.decode(data)
        compare.assert_called_once_with(tag, tag)


class TestPeerRateLimit(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.limiter = rt.TokenBucketLimiter(clock=self.clock)

    def test_frame_burst_refill_and_peer_isolation(self):
        for _ in range(50):
            self.assertTrue(self.limiter.allow(PEER, 1))
        self.assertFalse(self.limiter.allow(PEER, 1))
        self.assertTrue(self.limiter.allow(OTHER_PEER, 1))
        self.clock.advance(0.5)
        for _ in range(10):
            self.assertTrue(self.limiter.allow(PEER, 1))
        self.assertFalse(self.limiter.allow(PEER, 1))

    def test_byte_budget_and_refill(self):
        for _ in range(20):
            self.assertTrue(self.limiter.allow(PEER, rt.RT_PEER_MAX_BYTES))
        self.assertFalse(self.limiter.allow(PEER, 1))
        self.assertTrue(self.limiter.allow(OTHER_PEER, rt.RT_PEER_MAX_BYTES))
        self.clock.advance(3)
        self.assertTrue(self.limiter.allow(PEER, rt.RT_PEER_MAX_BYTES))
        self.assertFalse(self.limiter.allow(PEER, 1))

    def test_log_once_per_peer_per_ten_minutes(self):
        log = rt.LogOnce(clock=self.clock)
        self.assertTrue(log.should_log(PEER))
        self.assertFalse(log.should_log(PEER))
        self.clock.advance(599)
        self.assertFalse(log.should_log(PEER))
        self.assertTrue(log.should_log(OTHER_PEER))
        self.clock.advance(1)
        self.assertTrue(log.should_log(PEER))
        self.assertFalse(log.should_log(OTHER_PEER))


class TestPeerAckAndHealth(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.tracker = rt.AckTracker(clock=self.clock)
        self.channel = rt.PeerChannelState(clock=self.clock)

    def test_ack_removes_pending_and_expiration_calls_once(self):
        expired = []
        for seq, ack in enumerate((0, 1, 1)):
            self.tracker.track({"s": seq, "a": ack}, expired.append)
        self.assertFalse(self.tracker.ack(0))
        self.assertFalse(self.tracker.ack(99))
        self.clock.advance(2)
        self.tracker.expire()
        self.assertEqual(expired, [])
        self.assertTrue(self.tracker.ack(1))
        self.assertFalse(self.tracker.ack(1))
        self.clock.advance(1)
        self.tracker.expire()
        self.tracker.expire()
        self.assertEqual(expired, [2])
        self.assertFalse(self.tracker.ack(2))

    def test_late_ack_does_not_cancel_timeout(self):
        expired = []
        self.tracker.track({"s": 1, "a": 1}, expired.append)
        self.clock.advance(3)
        self.assertFalse(self.tracker.ack(1))
        self.tracker.expire()
        self.assertEqual(expired, [1])

    def test_valid_frames_restore_health_and_stale_channel_goes_down(self):
        self.assertFalse(self.channel.is_up)
        self.channel.on_frame()
        self.assertTrue(self.channel.is_up)
        self.clock.advance(89)
        self.assertTrue(self.channel.is_up)
        self.clock.advance(1)
        self.assertFalse(self.channel.is_up)
        self.channel.on_frame()
        self.assertTrue(self.channel.is_up)

    def test_consecutive_ack_timeouts_take_channel_down(self):
        self.channel.on_frame()
        self.channel.on_ack_timeout()
        self.assertTrue(self.channel.is_up)
        self.channel.on_ack()
        self.channel.on_ack_timeout()
        self.assertTrue(self.channel.is_up)
        self.channel.on_frame()
        self.channel.on_ack_timeout()
        self.assertFalse(self.channel.is_up)
        self.channel.on_frame()
        self.assertTrue(self.channel.is_up)
        self.channel.on_ack_timeout()
        self.assertTrue(self.channel.is_up)
