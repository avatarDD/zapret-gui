# tests/test_notify_bot.py
"""Двусторонний бот Telegram (core/notify_bot) и кнопки в очереди."""

import unittest
from unittest import mock

from core import notify, notify_bot as nb

ST = {"enabled": True, "interactive": True, "token": "T", "chat_id": "100",
      "allowed_users": [], "transport": "", "proxy": "", "events": {}}


class TestAccess(unittest.TestCase):

    def test_private_chat_owner_only(self):
        self.assertTrue(nb.authorized(100, 100, ST))
        self.assertFalse(nb.authorized(100, 7, ST))
        self.assertFalse(nb.authorized(200, 200, ST))

    def test_group_needs_explicit_users(self):
        st = dict(ST, chat_id="-5")
        self.assertFalse(nb.authorized(-5, 7, st))
        st["allowed_users"] = ["7"]
        self.assertTrue(nb.authorized(-5, 7, st))
        self.assertFalse(nb.authorized(-5, 8, st))


class TestReceipts(unittest.TestCase):

    def test_single_use_and_ttl(self):
        data = nb.receipt("smart_undo", "id1")
        self.assertLessEqual(len(data.encode()), 64)
        self.assertEqual(nb.redeem(data), ("smart_undo", "id1"))
        self.assertIsNone(nb.redeem(data))
        old = nb.receipt("smart_undo", "id2")
        with mock.patch.object(nb.time, "time",
                               return_value=nb.time.time()
                               + nb.RECEIPT_TTL + 1):
            self.assertIsNone(nb.redeem(old))
        self.assertIsNone(nb.redeem("чужое"))


class TestUpdates(unittest.TestCase):

    def setUp(self):
        p = mock.patch.object(nb, "_api", return_value={"ok": True})
        self.api = p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(nb, "_send")
        self.send = p.start()
        self.addCleanup(p.stop)

    def _cb(self, data, user=100, chat=100):
        return {"callback_query": {
            "id": "q", "from": {"id": user}, "data": data,
            "message": {"message_id": 5, "chat": {"id": chat}}}}

    def test_button_runs_action_once(self):
        calls = []
        with mock.patch.dict(nb.ACTIONS,
                             {"smart_undo": lambda a: calls.append(a) or "ok"}):
            data = nb.receipt("smart_undo", "id1")
            self.assertEqual(nb.handle_update(self._cb(data), ST),
                             "smart_undo")
            self.assertEqual(nb.handle_update(self._cb(data), ST), "stale")
        self.assertEqual(calls, ["id1"])
        methods = [c.args[1] for c in self.api.call_args_list]
        self.assertIn("editMessageReplyMarkup", methods)
        self.send.assert_called_once_with(ST, "ok")

    def test_action_survives_telegram_errors(self):
        calls = []
        self.api.side_effect = RuntimeError("сеть")
        self.send.side_effect = RuntimeError("сеть")
        with mock.patch.dict(nb.ACTIONS,
                             {"smart_undo": lambda a: calls.append(a) or "ok"}):
            data = nb.receipt("smart_undo", "id1")
            self.assertEqual(nb.handle_update(self._cb(data), ST),
                             "smart_undo")
        self.assertEqual(calls, ["id1"])

    def test_stranger_is_denied(self):
        data = nb.receipt("smart_undo", "id1")
        self.assertEqual(nb.handle_update(self._cb(data, user=7), ST),
                         "denied")
        # Квитанция чужим нажатием не сгорает.
        self.assertEqual(nb.redeem(data), ("smart_undo", "id1"))

    def test_commands(self):
        msg = {"message": {"text": "/help@zg_bot", "chat": {"id": 100},
                           "from": {"id": 100}}}
        self.assertEqual(nb.handle_update(msg, ST), "command")
        self.assertIn("/status", self.send.call_args.args[1])
        self.assertEqual(nb.handle_update(
            {"message": {"text": "привет", "chat": {"id": 100},
                         "from": {"id": 100}}}, ST), "ignored")
        self.assertEqual(nb.handle_update(
            {"message": {"text": "/status", "chat": {"id": 100},
                         "from": {"id": 9}}}, ST), "denied")
        self.assertIn("Не знаю", nb.command_reply("/rm -rf"))
        self.assertIsNone(nb.command_reply("текст"))

    def test_status_command_survives_errors(self):
        with mock.patch.dict(nb.COMMANDS,
                             {"/status": mock.Mock(side_effect=OSError("x"))}):
            self.assertIn("Не вышло", nb.command_reply("/status"))


class TestOffset(unittest.TestCase):

    def setUp(self):
        import shutil
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="bot-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        p = mock.patch.object(nb, "_offset_path",
                              return_value=self.dir + "/bot.json")
        p.start()
        self.addCleanup(p.stop)
        nb._state.update(offset=None, token="")
        self.addCleanup(nb._state.update, offset=None, token="")

    def test_offset_survives_restart_and_resets_for_other_bot(self):
        upd = {"result": [{"update_id": 41, "message": {"text": "x"}}]}
        with mock.patch.object(nb, "_api", return_value=upd) as api:
            nb.poll_once(ST)
            self.assertEqual(api.call_args.args[2]["offset"], 0)
            nb._state.update(offset=None)               # «перезапуск»
            nb.poll_once(ST)
            self.assertEqual(api.call_args.args[2]["offset"], 42)
            nb.poll_once(dict(ST, token="OTHER"))
            self.assertEqual(api.call_args.args[2]["offset"], 0)


class TestMarkup(unittest.TestCase):

    def test_buttons_only_for_interactive_and_known_actions(self):
        buttons = [{"text": "Отменить", "action": "smart_undo", "arg": "1"},
                   {"text": "?", "action": "rm_rf", "arg": ""}]
        self.assertIsNone(notify._markup(dict(ST, interactive=False),
                                         buttons))
        m = notify._markup(ST, buttons)
        row = m["inline_keyboard"][0]
        self.assertEqual([b["text"] for b in row], ["Отменить"])
        self.assertTrue(row[0]["callback_data"].startswith(nb.PREFIX))
        self.assertIsNone(notify._markup(ST, None))


if __name__ == "__main__":
    unittest.main()
