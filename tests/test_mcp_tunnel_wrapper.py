# tests/test_mcp_tunnel_wrapper.py
"""
Обвязка AWG/sing-box/mihomo через MCP: tunnel_log, tunnel_diagnostics,
tunnel_settings.

Стережём три вещи. Лог и снимок — чтение, но ключи AWG (PrivateKey в
`setconf_text`) модели не уходят. Отказ называет, что есть. Настройки
пишутся тем же кодом, что и в GUI (`core/engine_common.py`), и ответ
несёт `before` — прежние значения, чтобы вернуть их руками.

Настоящие движки не запускаются: менеджеры подменены.
"""

import unittest
from unittest import mock

from core import engine_common
from core import tunnels_control as control
from core.mcp import registry
from core.mcp.tools import tunnels as tools


WRITE = {"tunnels_write": True}


class FakeCM:
    def __init__(self):
        self.data = {}

    def get(self, section, key=None, default=None):
        return self.data.get(section, {}).get(key, default)

    def set(self, section, key, value):
        self.data.setdefault(section, {})[key] = value

    def save(self):
        pass


class FakeLogManager:
    def __init__(self, text="", ok=True, exists=True):
        self.text, self.ok, self.exists = text, ok, exists
        self.asked = []

    def read_log(self, *args):
        self.asked.append(args)
        if not self.ok:
            return {"ok": False, "error": "Некорректное имя"}
        return {"ok": True, "log": self.text, "exists": self.exists,
                "debug": False}


class Base(unittest.TestCase):

    def setUp(self):
        registry.load_tools()
        self.cm = FakeCM()
        p = mock.patch.object(engine_common, "_cm", return_value=self.cm)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(control, "instances",
                              side_effect=lambda eng: ["main"])
        p.start()
        self.addCleanup(p.stop)

    def data(self, name, args, perms=None):
        return registry.call(name, args,
                             WRITE if perms is None else perms
                             )["structuredContent"]

    def manager(self, fake):
        p = mock.patch.object(tools, "_wrapper_manager",
                              side_effect=lambda eng: fake)
        p.start()
        self.addCleanup(p.stop)


class TestTunnelLog(Base):

    def test_tail_and_filter(self):
        fake = FakeLogManager("a\nERROR one\nb\nerror two\nc")
        self.manager(fake)
        out = self.data("tunnel_log", {"engine": "singbox", "name": "main",
                                       "contains": "error", "lines": 1},
                        perms={})
        self.assertTrue(out["ok"])
        self.assertEqual(out["log"], "error two")
        # С фильтром хвост берётся шире, чем просили строк.
        self.assertEqual(fake.asked[0], ("main", tools.LOG_LINES_MAX))

    def test_opera_needs_no_name(self):
        fake = FakeLogManager("x\ny")
        self.manager(fake)
        out = self.data("tunnel_log", {"engine": "opera", "lines": 5},
                        perms={})
        self.assertTrue(out["ok"])
        self.assertEqual(fake.asked[0], (5,))

    def test_usque_config_name_maps_to_iface(self):
        fake = FakeLogManager("up")
        fake.list_configs = lambda: [{"name": "warp", "iface": "usque0"}]
        self.manager(fake)
        out = self.data("tunnel_log", {"engine": "usque", "name": "warp"},
                        perms={})
        self.assertTrue(out["ok"])
        self.assertEqual(fake.asked[0][0], "usque0")

    def test_missing_name_lists_known(self):
        out = self.data("tunnel_log", {"engine": "mihomo"}, perms={})
        self.assertFalse(out["ok"])
        self.assertEqual(out["known_names"], ["main"])

    def test_awg_without_debug_log_hints_debug(self):
        self.manager(FakeLogManager("", exists=False))
        out = self.data("tunnel_log", {"engine": "awg", "name": "main"},
                        perms={})
        self.assertTrue(out["ok"])
        self.assertIn("debug=true", out["hint"])

    def test_engine_refusal_passes_through(self):
        self.manager(FakeLogManager(ok=False))
        out = self.data("tunnel_log", {"engine": "singbox", "name": "x"},
                        perms={})
        self.assertFalse(out["ok"])
        self.assertIn("known_names", out)


class TestTunnelDiagnostics(Base):

    def test_awg_private_key_is_masked(self):
        fake = mock.Mock()
        fake.diagnostics.return_value = {
            "name": "main",
            "setconf_text": "[Interface]\nPrivateKey = c2VjcmV0c2VjcmV0\n",
        }
        self.manager(fake)
        out = self.data("tunnel_diagnostics",
                        {"engine": "awg", "name": "main"}, perms={})
        self.assertTrue(out["ok"])
        self.assertNotIn("c2VjcmV0c2VjcmV0",
                         out["diagnostics"]["setconf_text"])

    def test_awg_unknown_config_refused(self):
        fake = mock.Mock()
        self.manager(fake)
        out = self.data("tunnel_diagnostics",
                        {"engine": "awg", "name": "nope"}, perms={})
        self.assertFalse(out["ok"])
        fake.diagnostics.assert_not_called()

    def test_proxy_engine_snapshot(self):
        fake = mock.Mock()
        fake.diagnostics.return_value = {"ok": True, "diagnostics": {
            "engine": "mihomo", "name": "main", "active": True}}
        self.manager(fake)
        out = self.data("tunnel_diagnostics",
                        {"engine": "mihomo", "name": "main"}, perms={})
        self.assertTrue(out["diagnostics"]["active"])

    def _big(self):
        fake = mock.Mock()
        fake.diagnostics.return_value = {
            "name": "main",
            "active": True,
            "routes": {"table_v4": "x" * 20000},
            "log_tail": ["line %d %s" % (i, "y" * 100) for i in range(400)],
            "errors": [],
        }
        self.manager(fake)
        p = mock.patch("core.mcp.tools._paging.response_budget",
                       return_value=8 * 1024)
        p.start()
        self.addCleanup(p.stop)

    def test_oversize_snapshot_comes_by_sections(self):
        self._big()
        out = self.data("tunnel_diagnostics",
                        {"engine": "awg", "name": "main"}, perms={})
        self.assertTrue(out["ok"], out)
        self.assertNotIn("truncated", out)
        self.assertTrue(out["diagnostics"]["active"])
        self.assertIn("routes", out["sections_omitted"])
        self.assertIn("log_tail", out["sections_omitted"])
        self.assertIn("sections=", out["hint"])

    def test_omitted_section_reachable_trimmed(self):
        self._big()
        out = self.data("tunnel_diagnostics",
                        {"engine": "awg", "name": "main",
                         "sections": ["routes"]}, perms={})
        self.assertTrue(out["ok"], out)
        self.assertEqual(list(out["diagnostics"]), ["routes"])
        self.assertEqual(out["sections_trimmed"], ["routes"])
        self.assertIn("обрезано", out["diagnostics"]["routes"]["table_v4"])

    def test_unknown_section_lists_all(self):
        self._big()
        out = self.data("tunnel_diagnostics",
                        {"engine": "awg", "name": "main",
                         "sections": ["nope"]}, perms={})
        self.assertFalse(out["ok"])
        self.assertIn("routes", out["sections_all"])

    def test_unknown_config_lists_known(self):
        fake = mock.Mock()
        fake.diagnostics.return_value = {"ok": False,
                                         "error": "Конфиг не найден"}
        self.manager(fake)
        out = self.data("tunnel_diagnostics",
                        {"engine": "singbox", "name": "nope"}, perms={})
        self.assertFalse(out["ok"])
        self.assertEqual(out["known_names"], ["main"])


class TestTunnelSettings(Base):

    def setUp(self):
        super().setUp()
        p = mock.patch.object(tools, "_autostart_names", return_value=[])
        self.names = p.start()
        self.addCleanup(p.stop)

    def test_needs_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        self.assertNotIn("tunnel_settings", names)
        self.assertIn("tunnel_log", names)
        self.assertIn("tunnel_diagnostics", names)

    def test_read_only_call_changes_nothing(self):
        out = self.data("tunnel_settings", {"engine": "awg"})
        self.assertTrue(out["ok"])
        self.assertEqual(out["changed"], [])
        self.assertEqual(out["settings"]["go_memory"],
                         engine_common.GO_MEM_DEFAULTS)
        self.assertEqual(self.cm.data, {})

    def test_debug_and_memory_with_before(self):
        out = self.data("tunnel_settings", {
            "engine": "mihomo", "debug": True,
            "go_memory": {"enabled": True, "memlimit_mb": 48}})
        self.assertTrue(out["ok"])
        self.assertEqual(out["changed"], ["debug", "go_memory"])
        self.assertFalse(out["before"]["debug"])
        self.assertTrue(out["settings"]["debug"])
        self.assertEqual(out["settings"]["go_memory"]["memlimit_mb"], 48)
        self.assertTrue(self.cm.data["mihomo"]["debug_log"])

    def test_out_of_range_refused_by_schema(self):
        from core.mcp import schema
        with self.assertRaises(schema.SchemaError):
            registry.call("tunnel_settings", {
                "engine": "singbox", "go_memory": {"gogc": 5000}}, WRITE)
        self.assertEqual(self.cm.data, {})

    def test_autostart_unknown_config(self):
        out = self.data("tunnel_settings", {
            "engine": "singbox",
            "autostart": {"name": "nope", "enabled": True}})
        self.assertFalse(out["ok"])
        self.assertEqual(out["known_names"], ["main"])

    def test_autostart_goes_through_engine_module(self):
        with mock.patch("core.singbox_autostart.set_autostart",
                        return_value={"ok": True}) as sa, \
                mock.patch("core.singbox_autostart.regenerate") as regen:
            out = self.data("tunnel_settings", {
                "engine": "singbox",
                "autostart": {"name": "main", "enabled": True}})
        self.assertTrue(out["ok"])
        sa.assert_called_once_with("main", True)
        regen.assert_called_once()

    def test_awg_autostart_uses_autostart_manager(self):
        am = mock.Mock()
        am.set_enabled.return_value = {"ok": True}
        with mock.patch("core.awg_autostart_manager."
                        "get_awg_autostart_manager", return_value=am):
            out = self.data("tunnel_settings", {
                "engine": "awg",
                "autostart": {"name": "main", "enabled": False}})
        self.assertTrue(out["ok"])
        am.set_enabled.assert_called_once_with("main", False)


if __name__ == "__main__":
    unittest.main()
