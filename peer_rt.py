"""Wire format and per-peer state for the realtime peer channel."""

import hmac
import json
import re
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass

RT_VERSION = 2
RT_PEER_MAX_BYTES = 100_000
RT_TIMESTAMP_SKEW = 120
RT_REPLAY_WINDOW = 300
RT_FRAME_RATE = 20
RT_FRAME_BURST = 50
RT_BYTES_PER_MINUTE = 2_000_000
RT_REPLAY_MAX_ENTRIES = RT_FRAME_RATE * RT_REPLAY_WINDOW + RT_FRAME_BURST
RT_LOG_INTERVAL = 600
RT_ACK_TIMEOUT = 3
RT_ACK_FAILURES = 2
RT_CHANNEL_TIMEOUT = 90

_MAIL_KINDS = frozenset({"req", "resp", "breq", "bresp", "metrics"})
RT_HEALTH_KINDS = frozenset({"hello", "ping", "pong"})
RT_KINDS = _MAIL_KINDS | RT_HEALTH_KINDS | {"ack"}
_FRAME_FIELDS = {"v", "k", "e", "r", "s", "ts", "a", "b", "h"}
_EPOCH = re.compile(r"[0-9a-f]{32}")
_HMAC_HEX = re.compile(r"[0-9a-f]{64}")


class FrameError(ValueError):
    """The frame could not be encoded or accepted."""


def _canonical_json(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise FrameError("Invalid frame JSON") from exc


def _signature(frame, key: bytes) -> str:
    return hmac.digest(key, _canonical_json(frame), "sha256").hex()


def _is_seq(value) -> bool:
    return type(value) is int and value >= 0


def _is_epoch(value) -> bool:
    return isinstance(value, str) and _EPOCH.fullmatch(value) is not None


def _validate_frame(frame: dict):
    if type(frame["v"]) is not int or frame["v"] != RT_VERSION:
        raise FrameError("Unknown frame version")
    kind = frame["k"]
    if not isinstance(kind, str) or kind not in RT_KINDS:
        raise FrameError("Unknown frame kind")
    if not _is_epoch(frame["e"]):
        raise FrameError("Invalid frame epoch")
    if not _is_epoch(frame["r"]) and not (kind == "hello" and frame["r"] is None):
        raise FrameError("Invalid recipient epoch")
    if not _is_seq(frame["s"]) or type(frame["ts"]) is not int:
        raise FrameError("Invalid frame sequence or timestamp")
    if type(frame["a"]) is not int or frame["a"] not in (0, 1):
        raise FrameError("Invalid frame ack flag")
    body = frame["b"]
    if kind in _MAIL_KINDS and not isinstance(body, dict):
        raise FrameError("Invalid mail payload")
    if kind == "ack" and (
        not isinstance(body, dict) or body.keys() != {"e", "s"} or not _is_epoch(body["e"])
        or not isinstance(body["s"], list) or not all(map(_is_seq, body["s"]))
    ):
        raise FrameError("Invalid ack payload")
    if kind == "pong" and (
        not isinstance(body, dict) or body.keys() != {"e", "s"}
        or not _is_epoch(body["e"])
        or not _is_seq(body["s"])
    ):
        raise FrameError("Invalid pong payload")


def encode(kind: str, epoch: str, seq: int, body, key: bytes, *, recipient: str | None, ack: int = 0,
           clock: Callable[[], float] = time.time) -> bytes:
    """Encode a frame with the sender's directional key and a Unix timestamp."""
    frame = {
        "v": RT_VERSION, "k": kind, "e": epoch, "r": recipient, "s": seq, "ts": int(clock()),
        "a": int(ack) if isinstance(ack, bool) else ack, "b": body,
    }
    _validate_frame(frame)
    frame["h"] = _signature(frame, key)
    data = _canonical_json(frame)
    if len(data) > RT_PEER_MAX_BYTES:
        raise FrameError("Frame too large")
    return data


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise FrameError("Duplicate JSON key")
    return result


class ReplayWindow:
    """Remember authenticated sequences for 300 seconds per peer."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._seen = OrderedDict()
        self._counts = Counter()

    def accept(self, peer: Hashable, epoch: str, seq: int) -> bool:
        now = self._clock()
        while self._seen and next(iter(self._seen.values())) <= now:
            (expired_peer, _, _), _ = self._seen.popitem(last=False)
            self._counts[expired_peer] -= 1
            if not self._counts[expired_peer]:
                del self._counts[expired_peer]
        entry = (peer, epoch, seq)
        if entry in self._seen or self._counts[peer] >= RT_REPLAY_MAX_ENTRIES:
            # Keep every unexpired sequence even when a peer exhausts its window.
            return False
        self._seen[entry] = now + RT_REPLAY_WINDOW
        self._counts[peer] += 1
        return True


def authenticate(data: bytes, key: bytes, *, clock: Callable[[], float] = time.time) -> dict:
    """Authenticate one incoming frame using a verified peer's incoming key."""
    if len(data) > RT_PEER_MAX_BYTES:
        raise FrameError("Frame too large")
    try:
        frame = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        raise FrameError("Invalid frame JSON") from exc
    if not isinstance(frame, dict) or frame.keys() != _FRAME_FIELDS:
        raise FrameError("Invalid frame fields")
    tag = frame.pop("h")
    if not isinstance(tag, str) or not _HMAC_HEX.fullmatch(tag):
        raise FrameError("Invalid frame HMAC")
    if not hmac.compare_digest(_signature(frame, key), tag):
        raise FrameError("Invalid frame HMAC")
    _validate_frame(frame)
    now = clock()
    if not now - RT_TIMESTAMP_SKEW <= frame["ts"] <= now + RT_TIMESTAMP_SKEW:
        raise FrameError("Frame timestamp out of range")
    frame["h"] = tag
    return frame


def decode(data: bytes, key: bytes, *, peer: Hashable, replay: ReplayWindow,
           clock: Callable[[], float] = time.time) -> dict:
    frame = authenticate(data, key, clock=clock)
    if not replay.accept(peer, frame["e"], frame["s"]):
        raise FrameError("Frame replay or full replay window")
    return frame


@dataclass
class _Bucket:
    timestamp: float
    frames: float = RT_FRAME_BURST
    byte_count: float = RT_BYTES_PER_MINUTE


class TokenBucketLimiter:
    """Apply frame and byte budgets to incoming data before decoding it."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._buckets = {}

    def allow(self, peer: Hashable, size: int) -> bool:
        if size < 0:
            raise ValueError("Frame size must be nonnegative")
        now = self._clock()
        bucket = self._buckets.setdefault(peer, _Bucket(now))
        elapsed = now - bucket.timestamp
        bucket.timestamp = now
        bucket.frames = min(RT_FRAME_BURST, bucket.frames + elapsed * RT_FRAME_RATE)
        bucket.byte_count = min(RT_BYTES_PER_MINUTE, bucket.byte_count + elapsed * RT_BYTES_PER_MINUTE / 60)
        if bucket.frames < 1 or bucket.byte_count < size:
            return False
        bucket.frames -= 1
        bucket.byte_count -= size
        return True


class LogOnce:
    """Decide whether to log for a peer, at most once per ten minutes."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._until = OrderedDict()

    def should_log(self, peer: Hashable) -> bool:
        now = self._clock()
        while self._until and next(iter(self._until.values())) <= now:
            self._until.popitem(last=False)
        if peer in self._until:
            return False
        self._until[peer] = now + RT_LOG_INTERVAL
        return True


class AckTracker:
    """Track acknowledgments for one peer. Call expire from the owning loop."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._pending: dict[int, tuple[float, Callable[[int], None]]] = {}

    def track(self, frame: dict, on_timeout: Callable[[int], None]):
        if frame["a"] == 1:
            seq = frame["s"]
            if seq in self._pending:
                raise ValueError("Sequence already awaiting acknowledgment")
            self._pending[seq] = (self._clock() + RT_ACK_TIMEOUT, on_timeout)

    def ack(self, seq: int) -> bool:
        pending = self._pending.pop(seq, None)
        if pending is None:
            return False
        deadline, on_timeout = pending
        if self._clock() >= deadline:
            on_timeout(seq)
            return False
        return True

    def discard(self, seq: int) -> bool:
        return self._pending.pop(seq, None) is not None

    def expire(self):
        now = self._clock()
        due = [seq for seq, (deadline, _) in self._pending.items() if deadline <= now]
        for seq in due:
            pending = self._pending.get(seq)
            if pending is not None and pending[0] <= now:
                del self._pending[seq]
                _, on_timeout = pending
                on_timeout(seq)


class PeerChannelState:
    """Track valid frames and consecutive acknowledgment failures for one peer."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._last_frame_at = None
        self._ack_failures = 0
        self._ack_failed_at = None

    @property
    def is_up(self) -> bool:
        return (self._last_frame_at is not None
                and self._clock() - self._last_frame_at < RT_CHANNEL_TIMEOUT
                and self._ack_failures < RT_ACK_FAILURES)

    @property
    def last_frame_at(self) -> float | None:
        return self._last_frame_at

    @property
    def ack_failed_at(self) -> float | None:
        return self._ack_failed_at

    def on_frame(self, received_at=None):
        seen_at = self._clock() if received_at is None else received_at
        if self._last_frame_at is None or seen_at > self._last_frame_at:
            self._last_frame_at = seen_at
        if self._ack_failed_at is not None and seen_at >= self._ack_failed_at:
            # Fresh traffic can restore the channel even while sends are using mail.
            self._ack_failures = 0
            self._ack_failed_at = None

    def on_ack(self):
        self._ack_failures = 0
        self._ack_failed_at = None
        self.on_frame()

    def on_ack_timeout(self):
        self._ack_failures += 1
        if self._ack_failures == RT_ACK_FAILURES:
            self._ack_failed_at = self._clock()
