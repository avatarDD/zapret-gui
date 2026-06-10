# tests/test_singbox_debug.py
"""Режим отладки sing-box (issue #149).

Включённый debug подмешивает overlay {"log":{"level":"debug"}} вторым -c при
запуске — но ТОЛЬКО если билд умеет merge нескольких -c (graceful fallback).
Плюс хвост лог-файла для просмотра в UI («видно, почему не работает»).
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock


class _FakePlatform:
    def __init__(self, base):
        self.run_dir = os.path.join(base, "run")
        self.config_dir = os.path.join(base, "cfg")
        os.makedirs(self.run_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)

    def config_path(self, name):
        return os.path.join(self.config_dir, name + ".json")

    def pid_path(self, name):
        return os.path.join(self.run_dir, "singbox-%s.pid" % name)

    def log_path(self, name):
        return os.path.join(self.run_dir, "%s.log" % name)


class TestSingboxDebug(unittest.TestCase):

    def setUp(self):
        from core.singbox_manager import SingboxManager
        self.tmp = tempfile.mkdtemp(prefix="zg-sb-")
        self.mgr = SingboxManager()
        self.platform = _FakePlatform(self.tmp)
        self._pp = mock.patch.object(self.mgr, "_platform",
                                     return_value=self.platform)
        self._pp.start()

    def tearDown(self):
        self._pp.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_overlay_is_valid_debug_json(self):
        path = self.mgr._ensure_debug_overlay()
        self.assertTrue(path and os.path.isfile(path))
        with open(path) as f:
            ov = json.load(f)
        self.assertEqual(ov["log"]["level"], "debug")
        self.assertFalse(ov["log"]["disabled"])

    def test_read_log_missing_file(self):
        r = self.mgr.read_log("inst")
        self.assertTrue(r["ok"])
        self.assertFalse(r["exists"])
        self.assertEqual(r["log"], "")

    def test_read_log_returns_tail(self):
        with open(self.platform.log_path("inst"), "w") as f:
            for i in range(500):
                f.write("line %d\n" % i)
        r = self.mgr.read_log("inst", lines=10)
        self.assertTrue(r["exists"])
        self.assertIn("line 499", r["log"])
        self.assertNotIn("line 100", r["log"])   # обрезано до последних 10

    def test_read_log_rejects_bad_name(self):
        r = self.mgr.read_log("../../etc/passwd")
        self.assertFalse(r["ok"])

    def test_extra_cfg_empty_when_disabled(self):
        with mock.patch.object(self.mgr, "_debug_enabled", return_value=False):
            self.assertEqual(self.mgr._debug_extra_cfg("sing-box", "/c.json"),
                             [])

    def test_extra_cfg_empty_when_merge_unsupported(self):
        # debug включён, но `check -c a -c b` падает → overlay не применяем.
        with mock.patch.object(self.mgr, "_debug_enabled", return_value=True), \
             mock.patch("core.singbox_manager._run",
                        return_value=(1, "", "merge not supported")):
            self.assertEqual(self.mgr._debug_extra_cfg("sing-box", "/c.json"),
                             [])

    def test_extra_cfg_uses_overlay_when_supported(self):
        with mock.patch.object(self.mgr, "_debug_enabled", return_value=True), \
             mock.patch("core.singbox_manager._run", return_value=(0, "", "")):
            extra = self.mgr._debug_extra_cfg("sing-box", "/c.json")
        self.assertEqual(extra[0], "-c")
        self.assertEqual(extra[1], self.mgr._debug_overlay_path())


if __name__ == "__main__":
    unittest.main()
