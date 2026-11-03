# tests/test_geneva_auto_api.py
"""
REST и MCP режима «Авто» geneva: формы ответов, коды HTTP, двухшаговое
включение через confirm_token.

Менеджер режима подменён фейком: здесь проверяется граница (маршруты,
инструменты, разрешения), а не цикл режима — его гоняет
test_geneva_auto_manager.
"""

import json
import unittest
from unittest import mock

from core import geneva_auto_manager as am
from core import shell_exec
from core.mcp import registry
from tests._wsgi_client import WSGIClient, build_test_app


class FakeAuto:
    def __init__(self):
        self.enabled = False
        self.running = False
        self.calls = []

    def status(self, all_services=False):
        self.calls.append(("status", all_services))
        return {"enabled": self.enabled, "running": self.running,
                "phase": "watching" if self.running else "off",
                "services": [{"key": "dns:93.184.216.53",
                              "status": "applied"}],
                "groups": [], "search": {}, "problems": [], "counts": {},
                "journal": [{"ts": 1, "text": "x"}] * 50}

    def enable(self, confirm=False):
        self.calls.append(("enable", confirm))
        if not confirm:
            return {"ok": False, "error_code": "need_confirm",
                    "need_confirm": ["engine"], "error": "переключится"}
        self.enabled = self.running = True
        return {"ok": True, "enabled": True}

    def disable(self, reason=""):
        self.calls.append(("disable", reason))
        self.enabled = self.running = False
        return {"ok": True, "enabled": False}

    def reset(self, key):
        self.calls.append(("reset", key))
        if key != "dns:93.184.216.53":
            return {"ok": False, "error_code": "not_found",
                    "error": "сервиса нет"}
        return {"ok": True, "key": key}


class _Base(unittest.TestCase):
    def setUp(self):
        self.auto = FakeAuto()
        p = mock.patch.object(am, "get_geneva_auto_manager",
                              return_value=self.auto)
        p.start()
        self.addCleanup(p.stop)


class TestRest(_Base):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_status(self):
        data = self.client.get_json("/api/geneva/auto")
        self.assertTrue(data["ok"])
        self.assertEqual(data["services"][0]["key"], "dns:93.184.216.53")
        self.client.get_json("/api/geneva/auto?all=1")
        self.assertEqual(self.auto.calls[-1], ("status", True))

    def test_enable_needs_confirm_then_enables(self):
        status, body = self.client._call(
            "POST", "/api/geneva/auto/enable", body=b"{}",
            content_type="application/json")
        self.assertTrue(status.startswith("409"), status)
        self.assertEqual(json.loads(body)["error_code"], "need_confirm")
        status, body = self.client._call(
            "POST", "/api/geneva/auto/enable",
            body=json.dumps({"confirm": True}).encode(),
            content_type="application/json")
        self.assertTrue(status.startswith("200"), status)
        self.assertEqual(self.auto.calls[-1], ("enable", True))

    def test_confirm_must_be_true_literal(self):
        self.client._call("POST", "/api/geneva/auto/enable",
                          body=json.dumps({"confirm": "yes"}).encode(),
                          content_type="application/json")
        self.assertEqual(self.auto.calls[-1], ("enable", False))

    def test_found(self):
        self.auto.found = lambda: {"ok": True, "items": [
            {"strategy": "S", "services": [{"name": "youtube.com"}]}],
            "working": "", "auto_enabled": True}
        data = self.client.get_json("/api/geneva/found")
        self.assertTrue(data["ok"])
        self.assertEqual(data["items"][0]["services"][0]["name"],
                         "youtube.com")

    def test_disable_and_reset(self):
        self.assertTrue(self.client.post_json("/api/geneva/auto/disable",
                                              {})["ok"])
        self.assertEqual(self.auto.calls[-1][0], "disable")
        ok = self.client.post_json("/api/geneva/auto/reset",
                                   {"key": "dns:93.184.216.53"})
        self.assertTrue(ok["ok"])
        status, _ = self.client._call(
            "POST", "/api/geneva/auto/reset",
            body=json.dumps({"key": "dns:1.1.1.1"}).encode(),
            content_type="application/json")
        self.assertTrue(status.startswith("404"), status)
        status, _ = self.client._call(
            "POST", "/api/geneva/auto/reset", body=b"{}",
            content_type="application/json")
        self.assertTrue(status.startswith("400"), status)


class TestMcp(_Base):
    CONTROL = {"control": True}

    def setUp(self):
        super().setUp()
        registry.load_tools()

    def data(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             self.CONTROL if perms is None else perms)[
            "structuredContent"]

    def test_status_is_read_only(self):
        st = self.data("geneva_auto_status", {}, perms={})
        self.assertTrue(st["ok"])
        self.assertEqual(len(st["journal"]), 30)
        self.assertIn("hint", st)                     # выключен
        self.data("geneva_auto_status", {"all": True}, perms={})
        self.assertEqual(self.auto.calls[-1], ("status", True))

    def test_enable_two_steps(self):
        with mock.patch("core.bypass_engine.is_geneva_active",
                        return_value=False):
            first = self.data("geneva_auto_enable")
        self.assertFalse(first["ok"])
        self.assertTrue(first["need_confirm"])
        self.assertIn("nfqws2", first["consequences"])
        self.assertFalse(self.auto.enabled)
        token = first["confirm_token"]
        second = self.data("geneva_auto_enable", {"confirm_token": token})
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["reverse"], "geneva_auto_disable")
        self.assertTrue(self.auto.enabled)
        # токен одноразовый
        again = self.data("geneva_auto_enable", {"confirm_token": token})
        self.assertFalse(again["ok"])

    def test_confirm_via_shell_confirm_path(self):
        first = self.data("geneva_auto_enable")
        record, refusal = shell_exec.take_confirm(first["confirm_token"])
        self.assertIsNone(refusal)
        self.assertEqual(record["scope"], "control")
        res = shell_exec.run_confirmed(record)
        self.assertTrue(res["ok"])
        self.assertTrue(self.auto.enabled)

    def test_foreign_token_refused(self):
        other = shell_exec.pending_confirm("reboot", "reboot", "x",
                                           scope="dangerous")
        res = self.data("geneva_auto_enable",
                        {"confirm_token": other["confirm_token"]})
        self.assertFalse(res["ok"])
        self.assertFalse(self.auto.enabled)

    def test_control_required(self):
        res = registry.call("geneva_auto_enable", {}, {})
        self.assertTrue(res.get("isError"))
        res = registry.call("geneva_auto_disable", {}, {})
        self.assertTrue(res.get("isError"))

    def test_disable_and_reset(self):
        self.auto.enabled = self.auto.running = True
        res = self.data("geneva_auto_disable")
        self.assertTrue(res["ok"])
        self.assertEqual(res["reverse"], "geneva_auto_enable")
        self.assertFalse(self.auto.enabled)
        res = self.data("geneva_auto_reset", {"key": "dns:93.184.216.53"})
        self.assertTrue(res["ok"])

    def test_already_running(self):
        self.auto.running = True
        res = self.data("geneva_auto_enable")
        self.assertTrue(res["already"])


if __name__ == "__main__":
    unittest.main()
