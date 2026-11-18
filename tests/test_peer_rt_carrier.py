import base64
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import bot
import database
from outbox import Outbox


EMAIL = "peer@example.org"
FP = "BB" * 20
CHAT = 123
CONTACT = 21
CID = "0123456789abcdef"
KEY = b"k" * 32
DAY = 86400


def envelope(kind, cid=CID, key=KEY, **fields):
    payload = dict(v=1, cid=cid)
    if kind != "RESET":
        payload["key"] = base64.b64encode(key).decode("ascii")
    payload.update(fields)
    marker = f"UPTIME_PEER_RT_{kind}"
    return f"[{marker}]{json.dumps(payload, separators=(',', ':'))}[/{marker}]"


class TestPeerRTCarrier(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(database, "DB_PATH", os.path.join(directory, "test.db")))
        self.enterContext(patch.dict(os.environ, {"DC_DB_DIR": directory}))
        self.enterContext(patch.object(bot, "_peer_caps", {}))
        self.enterContext(patch.object(bot, "dc_outbox", Outbox()))
        self.enterContext(patch.object(bot, "stat_event"))
        self.traffic = self.enterContext(patch.object(database, "record_peer_traffic"))
        self.now = 1_800_000_000
        self.enterContext(patch.object(bot.time, "time", side_effect=lambda: self.now))
        self.addCleanup(database.close_db)
        database.init_db()
        database.set_peer_rt_flag("on")
        self.self_fp = "AA" * 20
        self.contacts = {}
        self.chat_contacts = {}
        self.ids = {}
        self.add_peer(EMAIL, FP, CHAT, CONTACT)

        self.bot = MagicMock()
        self.rpc = self.bot.rpc
        self.rpc.get_chat_securejoin_qr_code.side_effect = lambda *_: f"https://i.delta.chat/#{self.self_fp}&a=local"
        self.rpc.get_contact.side_effect = lambda _, contact: SimpleNamespace(address=self.contacts[contact][0])
        self.rpc.get_contact_encryption_info.side_effect = self.encryption_info
        self.rpc.get_chat_contacts.side_effect = lambda _, chat: self.chat_contacts[chat]
        self.rpc.get_basic_chat_info.return_value = dict(chat_type="Single", is_encrypted=True)
        self.rpc.get_message_ids.side_effect = lambda _, chat, *_args: self.ids[chat][:]
        self.rpc.send_msg.side_effect = self.send_msg
        self.next_id = 500
        for method in ("send_webxdc_realtime_advertisement", "send_webxdc_realtime_data", "leave_webxdc_realtime"):
            self.addCleanup(getattr(self.rpc, method).assert_not_called)

    def encryption_info(self, _, contact):
        fp = self.contacts[contact][1]
        return f"Self:\n{self.self_fp}\n\nPeer:\n{fp}"

    def send_msg(self, _, chat, msg_data):
        self.next_id += 1
        self.ids.setdefault(chat, []).append(self.next_id)
        return self.next_id

    def add_peer(self, email, fingerprint, chat, contact, caps=("rt1",)):
        self.contacts[contact] = email, fingerprint
        self.chat_contacts[chat] = [contact]
        self.ids[chat] = []
        database.add_or_update_peer(email, email, chat, fingerprint=fingerprint)
        bot._note_peer_caps(email, list(caps))

    def audit(self, seconds=0):
        self.now += seconds
        bot.audit_peer_rt_carriers(self.bot, 1, self.now)

    def receive(self, kind, *, text=None, msg_id=400, **overrides):
        params = dict(id=msg_id, from_id=CONTACT, chat_id=CHAT, is_info=False, show_padlock=True,
                      view_type="Webxdc" if kind == "OFFER" else "Text",
                      file_bytes=500 if kind == "OFFER" else 0, timestamp=self.now,
                      text=envelope(kind) if text is None else text)
        params.update(overrides)
        self.ids.setdefault(params["chat_id"], []).append(msg_id)
        bot.on_new_message(self.bot, 1, SimpleNamespace(msg=SimpleNamespace(**params)))

    def row(self):
        return database.get_peer(EMAIL)

    def accept_pending(self, key=KEY):
        cid = self.row()["rt_offer_cid"]
        self.assertIsNotNone(cid)
        self.receive("ACCEPT", text=envelope("ACCEPT", cid=cid, key=key))

    def sent(self, kind):
        marker = f"[UPTIME_PEER_RT_{kind}]"
        return [call.args[2] for call in self.rpc.send_msg.call_args_list if call.args[2].text.startswith(marker)]

    def test_owner_sends_one_message_with_exact_offer_and_xdc(self):
        with patch.object(bot.secrets, "token_hex", return_value=CID) as cid, \
             patch.object(bot.secrets, "token_bytes", return_value=KEY) as key:
            self.audit()
        cid.assert_called_once_with(8)
        key.assert_called_once_with(32)
        self.rpc.send_msg.assert_called_once()
        accid, chat, msg = self.rpc.send_msg.call_args.args
        self.assertEqual((accid, chat), (1, CHAT))
        self.assertEqual(msg.text.encode("ascii"), envelope("OFFER").encode("ascii"))
        self.assertEqual(Path(msg.file).name, "peer.xdc")
        self.assertEqual(self.row()["rt_offer_msg_id"], self.next_id)
        self.assertIsNone(self.row()["rt_cid"])
        self.audit(600)
        self.rpc.send_msg.assert_called_once()

    def test_non_owner_stores_local_id_and_directional_keys(self):
        self.self_fp = "CC" * 20
        self.audit()
        self.rpc.send_msg.assert_not_called()
        key_out = b"o" * 32
        with patch.object(bot.secrets, "token_bytes", return_value=key_out) as generate:
            self.receive("OFFER", msg_id=351)
        generate.assert_called_once_with(32)
        self.assertEqual(database.get_peer_rt(FP), dict(rt_cid=CID, rt_msg_id=351, rt_key_out=key_out,
                                                       rt_key_in=KEY, rt_created_at=self.now, rt_mode="auto"))
        accept, = self.sent("ACCEPT")
        self.assertEqual(accept.text, envelope("ACCEPT", key=key_out))
        self.assertIsNone(accept.file)

    def test_owner_accepts_only_matching_valid_key_and_cid(self):
        self.audit()
        pending = self.row()
        self.receive("ACCEPT")
        self.receive("ACCEPT", text=envelope("ACCEPT", cid=pending["rt_offer_cid"], key=b"short"))
        self.assertIsNone(self.row()["rt_msg_id"])
        self.accept_pending()
        self.assertEqual(database.get_peer_rt(FP), dict(rt_cid=pending["rt_offer_cid"],
                                                       rt_msg_id=pending["rt_offer_msg_id"],
                                                       rt_key_out=pending["rt_offer_key"], rt_key_in=KEY,
                                                       rt_created_at=self.now, rt_mode="auto"))
        self.assertIsNone(self.row()["rt_offer_msg_id"])
        self.receive("ACCEPT", text=envelope("ACCEPT", cid=pending["rt_offer_cid"], key=b"n" * 32))
        self.assertEqual(self.row()["rt_key_in"], KEY)
        self.rpc.send_msg.assert_called_once()

    def test_owner_ignores_offer_from_non_owner(self):
        self.receive("OFFER")
        self.assertIsNone(self.row()["rt_cid"])
        self.rpc.send_msg.assert_not_called()

    def test_inbound_rejects_invalid_or_untrusted_offers(self):
        self.self_fp = "CC" * 20
        self.contacts[41] = "unknown@example.org", "DD" * 20
        self.contacts[42] = EMAIL, "DD" * 20
        for overrides in (
            {"from_id": 41}, {"from_id": 42}, {"show_padlock": False}, {"chat_id": 900},
            {"view_type": "File"}, {"file_bytes": 0}, {"file_bytes": 4097}, {"is_forwarded": True},
            {"text": envelope("OFFER", cid="garbage")}, {"text": envelope("OFFER", key=b"short")},
            {"text": envelope("OFFER", v=True)}, {"text": envelope("OFFER", v=2)},
            {"text": envelope("OFFER", extra="x" * 512)},
        ):
            with self.subTest(overrides=overrides):
                self.receive("OFFER", **overrides)
                self.assertIsNone(self.row()["rt_cid"])
        self.rpc.get_basic_chat_info.return_value = dict(chat_type="Group", is_encrypted=True)
        self.receive("OFFER")
        self.assertIsNone(self.row()["rt_cid"])
        self.rpc.send_msg.assert_not_called()

    def test_duplicate_offer_and_replay_after_rotation_are_idempotent(self):
        self.self_fp = "CC" * 20
        initial_time = self.now
        self.receive("OFFER")
        first = self.row()
        self.now += 5
        self.receive("OFFER", text=envelope("OFFER", key=b"m" * 32), msg_id=401)
        self.assertEqual(self.row(), first)
        self.now += 14 * DAY
        self.receive("OFFER", text=envelope("OFFER", cid="aaaabbbbccccdddd"), msg_id=402)
        second = self.row()
        self.receive("OFFER", timestamp=initial_time, msg_id=403)
        self.assertEqual(self.row(), second)
        self.assertEqual(len(self.sent("ACCEPT")), 2)

    def test_flag_mode_and_mixed_mesh_gate(self):
        for flag, mode in (("off", "on"), ("canary", "auto"), ("on", "off")):
            with self.subTest(flag=flag, mode=mode):
                database.set_peer_rt_flag(flag)
                database.set_peer_rt_mode(EMAIL, mode)
                self.audit()
                with patch.object(bot, "help_command") as greet:
                    self.self_fp = "CC" * 20
                    self.receive("OFFER")
                    greet.assert_not_called()
                    self.self_fp = "AA" * 20
                self.assertIsNone(self.row()["rt_cid"])
        database.set_peer_rt_flag("on")
        database.set_peer_rt_mode(EMAIL, "auto")
        bot._note_peer_caps(EMAIL, ["batch_check"])
        self.audit()
        self.self_fp = "CC" * 20
        self.receive("OFFER")
        self.assertIsNone(self.row()["rt_cid"])
        self.rpc.send_msg.assert_not_called()
        bot._note_peer_caps(EMAIL, ["rt1"])
        database.remove_peer(EMAIL)
        database.add_or_update_peer(EMAIL, "Unbound", CHAT)
        self.self_fp = "AA" * 20
        self.audit()
        self.self_fp = "CC" * 20
        self.receive("OFFER")
        self.assertIsNone(self.row()["fingerprint"])
        self.rpc.send_msg.assert_not_called()

    def test_canary_explicit_on_and_trusted_destination(self):
        database.set_peer_rt_flag("canary")
        database.set_peer_rt_mode(EMAIL, "on")
        self.chat_contacts[CHAT] = [22]
        self.contacts[22] = EMAIL, "DD" * 20
        self.audit()
        self.chat_contacts[CHAT] = [CONTACT]
        self.rpc.get_basic_chat_info.return_value = dict(chat_type="Single", is_encrypted=False)
        self.audit()
        self.rpc.send_msg.assert_not_called()
        self.rpc.get_basic_chat_info.return_value = dict(chat_type="Single", is_encrypted=True)
        self.audit()
        self.rpc.send_msg.assert_called_once()

    def test_queued_mail_rechecks_downgraded_capabilities(self):
        with patch.object(bot.dc_outbox, "submit") as submit:
            self.audit()
            send = submit.call_args.args[0]
            self.assertEqual(submit.call_args.kwargs["kind"], "peer_other")
        bot.handle_peer_metrics(self.bot, 1, self.row(), CHAT, {"caps": ["batch_check"]})
        self.assertIs(send(), bot.SKIP_SEND)
        self.rpc.send_msg.assert_not_called()

    def test_rotation_keeps_old_message_until_accept(self):
        self.audit()
        self.accept_pending()
        old = self.row()
        self.audit(14 * DAY - 1)
        self.assertEqual(len(self.sent("OFFER")), 1)
        self.audit(1)
        new = self.row()
        self.assertEqual(len(self.sent("OFFER")), 2)
        self.assertEqual(new["rt_msg_id"], old["rt_msg_id"])
        self.assertNotEqual(new["rt_cid"], new["rt_offer_cid"])
        self.assertNotEqual(new["rt_key_out"], new["rt_offer_key"])
        self.assertEqual(database.get_peer_rt_message_ids(), {old["rt_msg_id"], new["rt_offer_msg_id"]})
        self.accept_pending()
        self.assertEqual(self.row()["rt_msg_id"], new["rt_offer_msg_id"])
        self.assertEqual(database.get_peer_rt_message_ids(), {new["rt_offer_msg_id"]})
        self.rpc.delete_messages.assert_not_called()

    def test_trims_protect_active_and_pending_carrier_ids(self):
        self.audit()
        pending = self.row()["rt_offer_msg_id"]
        self.accept_pending()
        self.audit(14 * DAY)
        rotation = self.row()["rt_offer_msg_id"]
        self.ids[CHAT] = [pending, 75, rotation] + list(range(1000, 1020))
        bot.trim_peer_chats(self.bot, 1)
        self.rpc.delete_messages.assert_called_once_with(1, [75])
        self.rpc.delete_messages.reset_mock()

        # A formerly bound chat may now be listed as a user chat after a relay change.
        database.bind_peer_identity(EMAIL, chat_id=CHAT + 1)
        self.rpc.get_chatlist_entries.return_value = [CHAT]
        self.rpc.get_message.return_value = dict(timestamp=self.now - 60 * DAY)
        bot.trim_user_chats(self.bot, 1)
        self.rpc.delete_messages.assert_called_once_with(1, [75])

    def test_lost_carrier_reoffers_after_retry_floor(self):
        self.audit()
        self.accept_pending()
        active = self.row()
        self.ids[CHAT].remove(active["rt_msg_id"])
        self.audit(599)
        self.assertEqual(len(self.sent("OFFER")), 1)
        self.audit(1)
        self.assertEqual(len(self.sent("OFFER")), 2)
        self.assertTrue(self.row()["rt_lost"])

    def test_deleted_pending_carrier_event_allows_retry(self):
        self.audit()
        pending = self.row()["rt_offer_msg_id"]
        bot.on_peer_rt_carrier_deleted(self.bot, 1, {"msgId": pending, "kind": "WebxdcInstanceDeleted"})
        self.assertIsNone(self.row()["rt_offer_msg_id"])
        self.audit(600)
        self.assertEqual(len(self.sent("OFFER")), 2)

    def test_lost_non_owner_resets_at_most_hourly(self):
        self.self_fp = "CC" * 20
        self.receive("OFFER")
        bot.on_peer_rt_carrier_deleted(self.bot, 1, {"msg_id": 400})
        self.audit()
        self.assertEqual([m.text for m in self.sent("RESET")], [envelope("RESET")])
        self.audit(3599)
        self.assertEqual(len(self.sent("RESET")), 1)
        self.audit(1)
        self.assertEqual(len(self.sent("RESET")), 2)
        self.assertEqual(self.sent("OFFER"), [])

    def test_remote_reset_must_match_owner_carrier_or_pending_offer(self):
        self.audit()
        self.accept_pending()
        self.receive("RESET")
        self.assertIsNone(self.row()["rt_lost"])
        cid = self.row()["rt_cid"]
        self.receive("RESET", text=envelope("RESET", cid=cid))
        self.audit(600)
        pending = self.row()["rt_offer_cid"]
        self.assertIsNotNone(pending)
        self.receive("RESET", text=envelope("RESET", cid=cid))
        self.assertEqual(self.row()["rt_offer_cid"], pending)
        self.receive("RESET", text=envelope("RESET", cid=pending))
        self.assertIsNone(self.row()["rt_offer_cid"])

    def test_offer_failures_obey_peer_and_global_limits(self):
        with patch.object(self.rpc, "send_msg", side_effect=RuntimeError("offline")) as failed:
            self.audit()
            self.audit(599)
            failed.assert_called_once()
            self.audit(1)
            self.audit(600)
            self.audit(600)
            self.assertEqual(failed.call_count, 3)
        fourth = "DD" * 20
        self.add_peer("other@example.org", fourth, CHAT + 1, CONTACT + 1)
        self.audit(1799)
        self.rpc.send_msg.assert_not_called()
        self.audit(1)
        self.rpc.send_msg.assert_called_once()
        self.assertEqual(self.rpc.send_msg.call_args.args[1], CHAT + 1)

    def test_rmpeer_and_downgrade_release_carriers(self):
        database.set_peer_rt_mode(EMAIL, "on")
        self.audit()
        self.accept_pending()
        bot.handle_peer_metrics(self.bot, 1, self.row(), CHAT, {"caps": ["batch_check"]})
        self.assertEqual(self.row()["rt_mode"], "on")
        self.assertIsNone(self.row()["rt_cid"])
        self.assertEqual(database.get_peer_rt_message_ids(), set())
        self.audit(600)
        self.assertEqual(len(self.sent("OFFER")), 1)
        bot._note_peer_caps(EMAIL, ["rt1"])
        self.audit()
        self.assertTrue(self.row()["rt_offer_msg_id"])
        with patch.object(bot, "_is_dc_admin", return_value=True):
            bot.rmpeer_command(self.bot, 1, SimpleNamespace(payload=EMAIL, msg=SimpleNamespace(from_id=10, chat_id=50)))
        self.assertIsNone(database.get_peer_rt(FP))
        self.assertEqual(database.get_peer_rt_message_ids(), set())

    def test_metrics_without_caps_releases_carrier_but_keeps_other_caps(self):
        self.audit()
        self.accept_pending()
        bot._note_peer_caps(EMAIL, ["rt1", "batch_check"])
        bot.handle_peer_metrics(self.bot, 1, self.row(), CHAT, {})
        self.assertIsNone(self.row()["rt_msg_id"])
        self.assertEqual(bot._peer_caps[EMAIL], {"batch_check"})

    def test_peers_reports_carrier_state(self):
        event = SimpleNamespace(msg=SimpleNamespace(from_id=10, chat_id=50))

        def peers():
            with patch.object(bot, "_is_dc_admin", return_value=True):
                bot.peers_command(self.bot, 1, event)
            return self.rpc.send_msg.call_args.args[2].text

        self.assertIn("iroh: mail only", peers())
        self.audit()
        self.assertIn("iroh: offer sent", peers())
        self.accept_pending()
        self.now += 2 * DAY
        self.assertIn("iroh: carrier ok (age 2d)", peers())

    def test_xdc_is_cached_deterministic_and_tiny(self):
        xdc = Path(bot.build_peer_xdc())
        data = xdc.read_bytes()
        self.assertLess(len(data), 4096)
        with zipfile.ZipFile(xdc) as archive:
            self.assertEqual(archive.namelist(), ["index.html", "manifest.toml"])
            self.assertIn(b"bot-to-bot channel, nothing to do here", archive.read("index.html"))
        with patch.object(bot.zipfile, "ZipFile", side_effect=AssertionError("cache miss")):
            self.assertEqual(bot.build_peer_xdc(), str(xdc))
        xdc.unlink()
        self.now += DAY
        self.assertEqual(Path(bot.build_peer_xdc()).read_bytes(), data)

    def test_metrics_count_all_carrier_mail_kinds(self):
        self.audit()
        self.accept_pending()
        self.self_fp = "CC" * 20
        self.receive("OFFER", msg_id=401)
        self.ids[CHAT].remove(401)
        self.audit()
        self.receive("RESET")
        counts = {(args[0], args[2]) for args, _ in self.traffic.call_args_list}
        self.assertEqual(counts, {(kind, direction) for kind in bot._PEER_RT_MAIL_KINDS for direction in ("in", "out")})


if __name__ == "__main__":
    unittest.main()
