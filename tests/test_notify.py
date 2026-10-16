# tests/test_notify.py
"""Уведомления в Telegram (core/notify): очередь, повторы, порядок,
поиск чата, токен вне журнала."""

import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import notify


class NotifyCase(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm
        self.dir = tempfile.mkdtemp(prefix="notify-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager
        self.cfg.set("notify", "telegram", {
            "enabled": True, "token": "111:SECRET", "chat_id": "42",
            "transport": "", "proxy": ""})
        notify._recent.clear()
        self.addCleanup(notify._recent.clear)
        # Поток-отправитель в тестах не нужен.
        p = mock.patch.object(notify, "_ensure_worker", lambda: None)
        p.start()
        self.addCleanup(p.stop)
        self.sent = []

    def fake_call(self, fail_on=None):
        def _call(st, method, payload=None):
            if fail_on and fail_on(payload):
                raise RuntimeError("Telegram: недоступен")
            self.sent.append(payload["text"])
            return {"ok": True}
        return _call


class TestQueue(NotifyCase):

    def test_disabled_not_queued(self):
        self.cfg.set("notify", "telegram", "enabled", False)
        self.assertFalse(notify.event("site_down", "x"))
        self.assertEqual(notify._load_queue(), [])

    def test_event_kind_off(self):
        self.cfg.set("notify", "events", {"site_down": False})
        self.assertFalse(notify.event("site_down", "x"))
        self.assertTrue(notify.event("tunnel", "y"))

    def test_dedup(self):
        self.assertTrue(notify.event("tunnel", "same"))
        self.assertFalse(notify.event("tunnel", "same"))
        self.assertEqual(len(notify._load_queue()), 1)

    def test_flush_in_order(self):
        notify.event("tunnel", "one")
        notify.event("tunnel", "two")
        with mock.patch.object(notify, "_call", self.fake_call()):
            r = notify.flush()
        self.assertEqual(r["sent"], 2)
        self.assertTrue(self.sent[0].endswith("one"))
        self.assertEqual(notify._load_queue(), [])

    def test_failure_keeps_queue_and_order(self):
        notify.event("tunnel", "one")
        notify.event("tunnel", "two")
        with mock.patch.object(notify, "_call", self.fake_call(
                fail_on=lambda p: p["text"].endswith("one"))):
            r = notify.flush()
        self.assertFalse(r["ok"])
        self.assertEqual(r["sent"], 0)
        self.assertEqual([m["text"] for m in notify._load_queue()],
                         ["one", "two"])

    def test_old_messages_dropped(self):
        notify._save_queue([{"ts": time.time() - notify.MAX_AGE - 5,
                             "kind": "tunnel", "text": "old"}])
        with mock.patch.object(notify, "_call", self.fake_call()):
            r = notify.flush()
        self.assertEqual(r["sent"], 0)
        self.assertEqual(notify._load_queue(), [])

    def test_queue_capped(self):
        for i in range(notify.MAX_QUEUE + 10):
            notify.event("tunnel", "m%d" % i)
        q = notify._load_queue()
        self.assertEqual(len(q), notify.MAX_QUEUE)
        self.assertEqual(q[-1]["text"], "m%d" % (notify.MAX_QUEUE + 9))


class TestReviewEdges(NotifyCase):

    def test_rejected_message_dropped_queue_continues(self):
        notify.event("update", "too long")
        notify.event("tunnel", "next")

        def _call(st, method, payload=None):
            if payload["text"].endswith("too long"):
                raise notify.Rejected("Telegram: 400 message is too long")
            self.sent.append(payload["text"])
            return {"ok": True}
        with mock.patch.object(notify, "_call", _call):
            r = notify.flush()
        self.assertEqual(r["sent"], 1)
        self.assertEqual(notify._load_queue(), [])

    def test_flush_single_flight(self):
        notify.event("tunnel", "one")
        self.assertTrue(notify._flush_lock.acquire(blocking=False))
        try:
            r = notify.flush()
        finally:
            notify._flush_lock.release()
        self.assertTrue(r.get("busy"))
        self.assertEqual(len(notify._load_queue()), 1)

    def test_no_dedup_for_transitions(self):
        self.assertTrue(notify.event("site_down", "X", dedup=False))
        self.assertTrue(notify.event("site_down", "X", dedup=False))

    def test_api_clear_token(self):
        from api.notify import _merged
        self.assertEqual(_merged({"token": ""})["token"], "111:SECRET")
        self.assertEqual(_merged({"clear_token": True})["token"], "")

    def test_config_get_masks_token(self):
        from api.config_api import _mask_notify_token
        data = {"notify": {"telegram": {"token": "111:SECRET"}}}
        _mask_notify_token(data)
        self.assertEqual(data["notify"]["telegram"]["token"], "***")


class TestHealthcheckTransitions(NotifyCase):

    def test_down_once_then_up_with_auto_reset(self):
        from core import healthcheck as hc
        self.cfg.set("healthcheck", "services", [])
        self.cfg.set("healthcheck", "custom_domains", ["x.test"])
        self.cfg.set("healthcheck", "consecutive_failures", 2)
        self.cfg.set("healthcheck", "auto_reset", True)
        self.cfg.set("healthcheck", "outage_guard", False)
        h = hc.HealthcheckDaemon()
        events = []
        results = iter([False] * 6 + [True, True])
        with mock.patch("core.diagnostics.check_http",
                        lambda url, timeout=8, **_kw: {"ok": next(results)}), \
                mock.patch.object(hc, "_notify",
                                  lambda k, t: events.append(k)), \
                mock.patch("core.strategy_state.clear_host",
                           lambda host, flush=False: {"removed": 0}):
            for _ in range(8):
                h._tick()
        self.assertEqual(events, ["site_down", "site_up"])


class TestPure(unittest.TestCase):

    def test_chats_from_updates(self):
        ups = [
            {"message": {"chat": {"id": 1, "first_name": "Ann",
                                  "type": "private"}}},
            {"message": {"chat": {"id": -100, "title": "Дом",
                                  "type": "group"}}},
            {"message": {"chat": {"id": 1, "first_name": "Ann"}}},
        ]
        chats = notify.chats_from_updates(ups)
        self.assertEqual([c["id"] for c in chats], ["1", "-100"])
        self.assertEqual(chats[1]["title"], "Дом")

    def test_format_text(self):
        self.assertEqual(notify.format_text("hi", "router"),
                         "zapret-gui · router\nhi")

    def test_scrub(self):
        self.assertNotIn("SECRET", notify._scrub(
            "url .../bot111:SECRET/send failed", "111:SECRET"))


class TestSendNow(NotifyCase):

    def test_missing_chat(self):
        st = notify.settings()
        st["chat_id"] = ""
        self.assertFalse(notify.send_now("x", st)["ok"])

    def test_error_has_no_token(self):
        import urllib.error

        class Opener:
            def open(self, req, timeout=0):
                raise urllib.error.URLError("fail at " + req.full_url)
        with mock.patch.object(notify, "_opener", lambda st: Opener()):
            r = notify.send_now("x")
        self.assertFalse(r["ok"])
        self.assertNotIn("SECRET", r["error"])


if __name__ == "__main__":
    unittest.main()
