# tests/test_selfcheck.py
"""
Unit-тесты для core/selfcheck.py — самодиагностика zapret-gui.

Прогон реальных секций безопасен (только чтение системы); subprocess-
прогон юнит-тестов проверяем на маленьком подмножестве (pattern), чтобы
не уйти в долгую рекурсию полного discover.
"""

import time
import unittest

from core import selfcheck


class TestParseUnittestOutput(unittest.TestCase):

    def test_ok(self):
        out = "....\n-----\nRan 107 tests in 0.055s\n\nOK\n"
        r = selfcheck.parse_unittest_output(out)
        self.assertTrue(r["ok"])
        self.assertEqual(r["ran"], 107)
        self.assertAlmostEqual(r["duration"], 0.055)
        self.assertEqual(r["summary"], "OK")

    def test_ok_with_skipped(self):
        out = "Ran 10 tests in 1.5s\n\nOK (skipped=2)\n"
        r = selfcheck.parse_unittest_output(out)
        self.assertTrue(r["ok"])
        self.assertEqual(r["skipped"], 2)
        self.assertIn("skipped=2", r["summary"])

    def test_failed(self):
        out = ("E..F\n-----\nRan 1178 tests in 1.029s\n\n"
               "FAILED (failures=1, errors=24, skipped=3)\n")
        r = selfcheck.parse_unittest_output(out)
        self.assertFalse(r["ok"])
        self.assertEqual(r["ran"], 1178)
        self.assertEqual(r["failures"], 1)
        self.assertEqual(r["errors"], 24)
        self.assertEqual(r["skipped"], 3)
        self.assertIn("FAILED", r["summary"])

    def test_garbage(self):
        r = selfcheck.parse_unittest_output("traceback: boom")
        self.assertFalse(r["ok"])
        self.assertEqual(r["ran"], 0)


class TestSections(unittest.TestCase):

    def _assert_section_shape(self, sec):
        self.assertIn("title", sec)
        self.assertTrue(sec["checks"], "секция не должна быть пустой")
        for c in sec["checks"]:
            self.assertIn(c["level"], ("ok", "warn", "fail", "info"))
            self.assertIsInstance(c["ok"], bool)

    def test_check_python(self):
        sec = selfcheck.check_python()
        self._assert_section_shape(sec)
        names = [c["name"] for c in sec["checks"]]
        self.assertIn("Python", names)
        self.assertIn("модуль bottle", names)
        # unittest проверяется наравне с остальным stdlib: на Entware
        # python3-light он в отдельном пакете, без него selfcheck
        # пропускает прогон юнит-тестов.
        self.assertIn("stdlib unittest", names)
        py = next(c for c in sec["checks"] if c["name"] == "Python")
        self.assertTrue(py["ok"])  # мы на >=3.8

    def test_check_system_tools(self):
        sec = selfcheck.check_system_tools()
        self._assert_section_shape(sec)
        names = [c["name"] for c in sec["checks"]]
        self.assertIn("ip", names)
        self.assertIn("firewall-бэкенд (iptables или nft)", names)

    def test_check_engines_and_config(self):
        for sec in (selfcheck.check_engines(), selfcheck.check_config()):
            self._assert_section_shape(sec)

    def test_run_all_without_tests(self):
        res = selfcheck.run_all(include_tests=False)
        self.assertIn("sections", res)
        self.assertIsNone(res["tests"])
        self.assertEqual(len(res["sections"]), 5)
        self.assertIn("summary", res)
        # ok согласован с количеством fail-чеков
        self.assertEqual(res["ok"], res["summary"]["fail"] == 0)


class TestRunUnitTests(unittest.TestCase):

    def test_subset_runs(self):
        r = selfcheck.run_unit_tests(pattern="test_routing_storage.py",
                                     timeout=120)
        self.assertTrue(r.get("ok"), r)
        self.assertGreater(r.get("ran", 0), 0)
        self.assertIn("OK", r.get("summary", ""))

    def test_missing_tests_dir(self):
        from unittest import mock
        with mock.patch.object(selfcheck, "INSTALL_DIR", "/nonexistent-xyz"):
            r = selfcheck.run_unit_tests()
        self.assertFalse(r["ok"])
        self.assertTrue(r["skipped_run"])
        self.assertIn("tests/", r["error"])

    def test_missing_unittest_module(self):
        # Entware python3-light без python3-unittest: не «FAILED», а
        # честный пропуск с подсказкой, какой пакет доустановить.
        from unittest import mock
        with mock.patch.object(selfcheck.importlib.util, "find_spec",
                               return_value=None):
            r = selfcheck.run_unit_tests()
        self.assertFalse(r["ok"])
        self.assertTrue(r["skipped_run"])
        self.assertIn("python3-unittest", r["error"])

    def test_run_all_with_skipped_tests_not_failed(self):
        # Поставка без tests/ — не провал: итог зависит только от секций
        # (раньше «тесты FAILED — каталог не найден» роняли весь итог).
        from unittest import mock
        skipped = {"ok": False, "skipped_run": True,
                   "error": "каталог tests/ не найден (/x)"}
        with mock.patch.object(selfcheck, "run_unit_tests",
                               return_value=skipped):
            res = selfcheck.run_all(include_tests=True)
        self.assertEqual(res["ok"], res["summary"]["fail"] == 0)
        self.assertTrue(res["tests"]["skipped_run"])


class TestAsyncRunner(unittest.TestCase):

    def test_start_and_status(self):
        r = selfcheck.start_async(include_tests=False)
        self.assertTrue(r["ok"])
        # Повторный старт, пока идёт — отлуп (или прогон уже успел
        # закончиться — тогда тоже ок).
        r2 = selfcheck.start_async(include_tests=False)
        if not r2.get("ok"):
            self.assertIn("уже идёт", r2["error"])
        deadline = time.time() + 60
        while time.time() < deadline:
            st = selfcheck.status()
            if not st["running"] and st["result"] is not None:
                break
            time.sleep(0.2)
        st = selfcheck.status()
        self.assertFalse(st["running"])
        self.assertIsInstance(st["result"], dict)
        self.assertIn("sections", st["result"])


if __name__ == "__main__":
    unittest.main()
