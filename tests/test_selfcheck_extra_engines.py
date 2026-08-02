# tests/test_selfcheck_extra_engines.py
"""
Самодиагностика: секция «Доп. движки и прокси».

Покрывает компоненты, которых в selfcheck раньше не было вовсе
(usque/WARP-MASQUE, WARP-in-WARP, Telegram-прокси, Opera Proxy), и
главное — ловит рассогласование настроек usque: autostart/watchdog без
usque.enabled не работают, потому что _apply_usque_autostart_on_boot и
UsqueWatchdog.reconfigure() требуют ОБА флага.
"""

import shutil
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import selfcheck


def _by_name(section, needle):
    return [c for c in section["checks"] if needle in c["name"]]


class _IsolatedConfig(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="selfcheck-test-")
        self._saved = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self._tmp)
        cm_mod._config_manager.load()

    def tearDown(self):
        cm_mod._config_manager = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestExtraEnginesSection(_IsolatedConfig):

    def test_section_shape(self):
        sec = selfcheck.check_extra_engines()
        self.assertEqual(sec["name"], "extra_engines")
        self.assertTrue(sec["checks"])
        for c in sec["checks"]:
            for key in ("name", "ok", "level", "details"):
                self.assertIn(key, c)

    def test_covers_all_new_components(self):
        sec = selfcheck.check_extra_engines()
        names = " | ".join(c["name"] for c in sec["checks"])
        for needle in ("usque", "WARP-in-WARP", "Telegram", "Opera"):
            self.assertIn(needle, names)

    def test_not_installed_is_info_not_failure(self):
        # Неустановленный опциональный компонент не должен валить прогон.
        sec = selfcheck.check_extra_engines()
        self.assertTrue(all(c["ok"] for c in sec["checks"]), sec["checks"])

    def test_autostart_without_enabled_warns(self):
        cm = cm_mod.get_config_manager()
        cm.set("usque", "autostart", True)
        cm.set("usque", "enabled", False)
        sec = selfcheck.check_extra_engines()
        found = _by_name(sec, "usque: автозапуск")
        self.assertTrue(found)
        self.assertEqual(found[0]["level"], "warn")
        self.assertFalse(found[0]["ok"])

    def test_watchdog_without_enabled_warns(self):
        cm = cm_mod.get_config_manager()
        cm.set("usque", "watchdog", "enabled", True)
        cm.set("usque", "enabled", False)
        sec = selfcheck.check_extra_engines()
        found = _by_name(sec, "usque: watchdog")
        self.assertTrue(found)
        self.assertEqual(found[0]["level"], "warn")

    def test_consistent_settings_do_not_warn(self):
        cm = cm_mod.get_config_manager()
        cm.set("usque", "enabled", True)
        cm.set("usque", "autostart", True)
        cm.set("usque", "watchdog", "enabled", True)
        sec = selfcheck.check_extra_engines()
        warns = [c for c in sec["checks"]
                 if c["level"] == "warn" and "usque" in c["name"]]
        self.assertEqual(warns, [])

    def test_warp_in_warp_configured_but_down_warns(self):
        # Режим задан, а туннели лежат — это проблема, а не «выключено».
        fake = mock.Mock()
        fake.get_status.return_value = {
            "active": False, "mode": "masque_awg",
            "outer_running": True, "inner_running": False, "route_ok": False,
        }
        with mock.patch("core.warp_in_warp.get_warp_in_warp_manager",
                        return_value=fake):
            sec = selfcheck.check_extra_engines()
        found = _by_name(sec, "WARP-in-WARP")
        self.assertTrue(found)
        self.assertEqual(found[0]["level"], "warn")

    def test_detector_exception_does_not_break_section(self):
        with mock.patch("core.usque_manager.get_usque_manager",
                        side_effect=RuntimeError("boom")):
            sec = selfcheck.check_extra_engines()
        self.assertTrue(_by_name(sec, "usque (WARP/MASQUE)"))


class TestSectionWiredIntoRun(unittest.TestCase):

    def test_run_all_includes_extra_engines(self):
        # Секция должна реально попадать в прогон, а не просто существовать.
        called = []

        def _cb(step, index, total):
            called.append((step, index, total))

        with mock.patch.object(selfcheck, "run_unit_tests",
                               return_value={"ok": True, "ran": 0}):
            res = selfcheck.run_all(include_tests=False, progress_cb=_cb)
        steps = [c[0] for c in called]
        self.assertIn("check_extra_engines", steps)
        # Прогресс должен быть считаемым: шаги нумеруются подряд от 0 и
        # знают общее количество, иначе полосе в GUI неоткуда взяться.
        self.assertEqual([c[1] for c in called], list(range(len(called))))
        self.assertTrue(all(c[2] == len(called) for c in called))
        # У шага есть человекочитаемое имя — иначе в GUI поедет
        # «check_extra_engines» вместо русской подписи.
        self.assertIn("check_extra_engines", selfcheck._PROGRESS_TITLES)
        names = [s["name"] for s in res["sections"]]
        self.assertIn("extra_engines", names)


if __name__ == "__main__":
    unittest.main()
