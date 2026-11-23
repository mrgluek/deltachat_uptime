"""Micro-benchmark for the 3.0.2 changes; run it from the repository root, with the project environment.

    python -m tools.loadbench.release302

Prints, per scenario, the RPC calls and timings of the current tree:
  fingerprint  1,000 incoming encrypted peer messages: get_chat_securejoin_qr_code calls
  trim         one peer-chat trim pass of 430 messages (3.8 ms per delete, measured on de2): delete
               RPC calls, the largest call, the longest wait of a second thread that wants
               _peer_rt_lock (the event thread and the event loop in production)
  admission    one requester sends two 11-target grid batches and then an urgent request: how many
               slots the first batch holds and how the urgent request is answered
No network, no Delta Chat core: the RPC is an in-memory stub.
"""
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
SELF_FP = "D58B5E6C55482F94F9F5B84B6FB9FE3AD2658082"
PEER_FP = "DEC0E8D11FC4686F2C715C56F8C9AD699BC19AD8"


def fingerprint(bot):
    rpc = MagicMock()
    rpc.get_chat_securejoin_qr_code.return_value = f"https://i.delta.chat/#{SELF_FP}&v=3&i=a&s=b"
    rpc.get_contact_encryption_info.return_value = (
        f"Messages are end-to-end encrypted.\nFingerprints:\n\nMe:\n{SELF_FP}\n\nPeer:\n{PEER_FP}\n\nRelays:\nx@example.org")
    fake = MagicMock()
    fake.rpc = rpc
    start = time.process_time()
    for _ in range(1000):
        assert bot._get_peer_fingerprint(fake, 1, 42, "peer@example.org") == PEER_FP
    cpu = time.process_time() - start
    return {"qr_calls_per_1000_messages": rpc.get_chat_securejoin_qr_code.call_count,
            "cpu_ms_with_stub_rpc": round(cpu * 1000, 1)}


def trim(bot):
    state = {"calls": 0, "max_chunk": 0}

    class Rpc:
        def delete_messages(self, accid, ids):
            state["calls"] += 1
            state["max_chunk"] = max(state["max_chunk"], len(ids))
            time.sleep(0.0038 * len(ids))

    fake = MagicMock()
    fake.rpc = Rpc()
    waits = []
    stop = threading.Event()

    def contender():
        while not stop.is_set():
            t = time.monotonic()
            with bot._peer_rt_lock:
                waits.append(time.monotonic() - t)
            time.sleep(0.01)

    thread = threading.Thread(target=contender)
    thread.start()
    start = time.monotonic()
    with patch.object(bot.database, "get_peer_rt_message_ids", return_value=set()):
        deleted = bot._delete_trimmed_messages(fake, 1, list(range(430)))
    wall = time.monotonic() - start
    stop.set()
    thread.join()
    return {"deleted": deleted, "delete_rpc_calls": state["calls"], "largest_delete_call": state["max_chunk"],
            "pass_wall_ms": round(wall * 1000), "longest_lock_wait_ms": round(max(waits) * 1000, 1)}


def admission(bot):
    peer = {"email": "a@example.org", "fingerprint": "A" * 40}
    adm = bot.InboundProbeAdmission()
    workers = min(getattr(bot, "PEER_BATCH_WORKERS_MAX", 10), 11)
    _, grid = adm.acquire(peer, "grid", workers)
    adm.acquire(peer, "grid2", workers)
    outcome, urgent = adm.acquire(peer, "urgent", 1)
    busy = hasattr(adm, "allow_busy_reply") and outcome is bot._ProbeAdmission.REJECTED
    if urgent:
        answer = "accepted (reduced slots)"
    elif busy:
        answer = "rejected, busy answer sent at once"
    else:
        answer = "rejected, silently dropped (requester waits 25 s)"
    return {"slots_held_by_first_grid_batch": grid[1] if grid else 0, "urgent_request_after_two_grid_batches": answer}


def main():
    import bot
    for name, fn in (("fingerprint", fingerprint), ("trim", trim), ("admission", admission)):
        print(f"{name}: {fn(bot)}")


if __name__ == "__main__":
    main()
