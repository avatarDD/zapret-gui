# tests/test_diagnostics_conflicts.py
"""Тесты детекции конфликтов окружения (core/diagnostics.evaluate_conflicts)."""

import unittest
from unittest import mock

from core.diagnostics import evaluate_conflicts, _KNOWN_TOOL_MARKERS


class TestEvaluateConflicts(unittest.TestCase):

    def test_no_conflicts(self):
        self.assertEqual(evaluate_conflicts(set(), set()), [])

    def test_getdomains_marker(self):
        w = evaluate_conflicts({"/opt/etc/init.d/S99getdomains"}, set())
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "getdomains")
        self.assertIn("getdomains", w[0]["title"])
        self.assertTrue(w[0]["hint"])

    def test_foreign_daemon(self):
        w = evaluate_conflicts(set(), {"xray"})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "proc-xray")

    def test_combined(self):
        w = evaluate_conflicts(
            {"/usr/bin/podkop", "/opt/sbin/xkeen"},
            {"redsocks"})
        ids = {x["id"] for x in w}
        self.assertEqual(ids, {"podkop", "xkeen", "proc-redsocks"})

    def test_unrelated_paths_ignored(self):
        self.assertEqual(
            evaluate_conflicts({"/usr/bin/python3", "/opt/zapret2/bin"},
                               {"sing-box", "mihomo"}),
            [])

    def test_custom_markers(self):
        markers = ({"id": "x", "name": "X", "paths": ("/a",), "hint": "h"},)
        w = evaluate_conflicts({"/a"}, set(), markers=markers, daemons={})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "x")

    def test_marker_structure_valid(self):
        # Каждый встроенный маркер имеет обязательные поля.
        for m in _KNOWN_TOOL_MARKERS:
            self.assertTrue(m["id"] and m["name"] and m["paths"] and m["hint"])


if __name__ == "__main__":
    unittest.main()


class TestSystemInfoExtras(unittest.TestCase):
    """Диски и наличие утилит в «Системной информации».

    Раньше при отсутствии `ip` поля адресов/шлюза/интерфейсов молча
    оставались пустыми, и было непонятно — так и надо или что-то сломано.
    А свободного места не показывалось вовсе, хотя забитая флешка на
    роутере — штатная причина «не ставится / не сохраняется».
    """

    def test_disk_usage_shape(self):
        from core.diagnostics import _get_disk_usage
        disks = _get_disk_usage()
        self.assertIsInstance(disks, list)
        for d in disks:
            for key in ("label", "path", "total_mb", "free_mb", "used_percent"):
                self.assertIn(key, d)
            self.assertGreater(d["total_mb"], 0)
            self.assertGreaterEqual(d["used_percent"], 0)
            self.assertLessEqual(d["used_percent"], 100)
            self.assertLessEqual(d["free_mb"], d["total_mb"])

    def test_disk_usage_deduplicates_same_filesystem(self):
        # /opt и каталог конфига обычно на одном разделе — не дублируем.
        from core.diagnostics import _get_disk_usage
        disks = _get_disk_usage()
        paths = [d["path"] for d in disks]
        self.assertEqual(len(paths), len(set(paths)))


class TestWanIpValue(unittest.TestCase):
    """`wan_ip` — это локальный src-адрес, и он не должен нести оформление."""

    def test_returns_empty_string_when_unavailable(self):
        from core.system_info import _get_wan_ip
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertEqual(_get_wan_ip(), "")

    def test_no_dash_placeholder_in_data(self):
        # Раньше возвращался символ «—» — оформление в данных, из-за чего
        # его нельзя было отличить от реального значения.
        from core.system_info import _get_wan_ip
        with mock.patch("subprocess.run", side_effect=OSError):
            self.assertNotIn("—", _get_wan_ip())

    def test_parses_src_from_ip_route(self):
        from core.system_info import _get_wan_ip
        out = mock.Mock(returncode=0,
                        stdout="8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0")
        with mock.patch("subprocess.run", return_value=out):
            self.assertEqual(_get_wan_ip(), "192.168.1.50")

    def test_truncated_output_does_not_crash(self):
        from core.system_info import _get_wan_ip
        out = mock.Mock(returncode=0, stdout="8.8.8.8 dev eth0 src")
        with mock.patch("subprocess.run", return_value=out):
            self.assertEqual(_get_wan_ip(), "")


class TestSystemInfoArch(unittest.TestCase):
    """Архитектура должна совпадать с той, по которой ставятся сборки.

    `platform.machine()` (=`uname -m`) на MIPS отдаёт "mips" и для
    little-, и для big-endian — из-за этого «Диагностика» показывала
    `mips` там, где страницы установки правильно определяли `mipsel`.
    """

    def test_arch_matches_installer_detection(self):
        from core import system_info
        from core.ext_binary_installer import detect_arch
        info = system_info.get_system_info()
        self.assertEqual(info["arch"], detect_arch())

    def test_raw_uname_is_still_reported(self):
        import platform
        from core import system_info
        info = system_info.get_system_info()
        self.assertEqual(info["arch_uname"], platform.machine())

    def test_mips_router_reports_mipsel_not_mips(self):
        from core import system_info
        with mock.patch("core.ext_binary_installer.detect_arch",
                        return_value="mipsel"), \
             mock.patch("platform.machine", return_value="mips"):
            info = system_info.get_system_info()
        self.assertEqual(info["arch"], "mipsel")
        self.assertEqual(info["arch_uname"], "mips")

    def test_falls_back_to_uname_when_detection_fails(self):
        from core import system_info
        with mock.patch("core.ext_binary_installer.detect_arch",
                        side_effect=OSError("нет uname")), \
             mock.patch("platform.machine", return_value="armv7l"):
            info = system_info.get_system_info()
        self.assertEqual(info["arch"], "armv7l")
