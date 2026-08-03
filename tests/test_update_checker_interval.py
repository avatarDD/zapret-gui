# tests/test_update_checker_interval.py
"""
Интервал фоновой проверки обновлений.

Регрессия: interval_hours приходит из общего PUT /api/config без всякой
валидации. При 0 (или мусоре) `stop_evt.wait(0)` возвращался мгновенно и
цикл сваливался в непрерывный опрос GitHub. Один проход check_all() — это
~9 обращений к GitHub API при неавторизованном лимите 60 запросов в час,
то есть мгновенный бан и бесполезная нагрузка на роутер.
"""

import unittest

from core import update_checker as uc
import core.update_checker as uc


class TestSaneInterval(unittest.TestCase):

    def test_zero_and_negative_clamped_to_minimum(self):
        for bad in (0, -1, -100, 0.0001):
            self.assertEqual(uc._sane_interval_hours(bad),
                             uc.MIN_CHECK_INTERVAL_HOURS, bad)

    def test_garbage_falls_back_to_default(self):
        for bad in ("abc", None, "", [], float("nan")):
            self.assertEqual(uc._sane_interval_hours(bad),
                             uc.DEFAULT_CHECK_INTERVAL_HOURS, repr(bad))

    def test_sane_values_pass_through(self):
        self.assertEqual(uc._sane_interval_hours(6), 6)
        self.assertEqual(uc._sane_interval_hours("12"), 12)

    def test_absurdly_large_capped(self):
        self.assertEqual(uc._sane_interval_hours(10 ** 9),
                         uc.MAX_CHECK_INTERVAL_HOURS)

    def test_minimum_is_not_zero(self):
        # Защита от «починили обратно»: минимум обязан быть > 0, иначе
        # wait() снова станет мгновенным.
        self.assertGreater(uc.MIN_CHECK_INTERVAL_HOURS, 0)


class TestDaemonStartStopRace(unittest.TestCase):

    def test_restart_does_not_leave_two_loops(self):
        # _stop() не дожидается потока; _start() раньше сбрасывал ОБЩЕЕ
        # событие, и старый цикл продолжал работать рядом с новым —
        # двойной опрос GitHub. Теперь у каждого запуска своё событие,
        # поэтому старое остаётся взведённым.
        d = uc.UpdateCheckerDaemon()
        d._start()
        first_evt = d._stop_evt
        first_thread = d._thread
        d._stop()
        self.assertTrue(first_evt.is_set())

        d._start()
        second_evt = d._stop_evt
        self.assertIsNot(second_evt, first_evt, "событие переиспользовано")
        # Событие первого цикла обязано остаться взведённым после
        # повторного старта — иначе он проснётся и продолжит работу.
        self.assertTrue(first_evt.is_set(), "старый цикл был разбужен заново")
        self.assertFalse(second_evt.is_set())

        d._stop()
        for t in (first_thread, d._thread):
            if t:
                t.join(timeout=2)


if __name__ == "__main__":
    unittest.main()


class TestVersionComparison(unittest.TestCase):
    """«Обновление есть» = версия НОВЕЕ, а не «отличается».

    Строковое `!=` давало абсурд: у usque установлено 4.2.1, «последней»
    значилась 0.3.0 (её брали из запасного репозитория-донора), и GUI
    предлагал обновиться назад.
    """

    def test_older_latest_is_not_an_update(self):
        self.assertFalse(uc._is_newer("0.3.0", "4.2.1"))

    def test_newer_latest_is_an_update(self):
        self.assertTrue(uc._is_newer("4.2.1", "4.2.0"))
        self.assertTrue(uc._is_newer("1.19.29", "1.19.27"))

    def test_compare_is_numeric_not_lexicographic(self):
        """'1.9.7' > '1.13.0' как строки, но 1.13 новее."""
        self.assertFalse(uc._is_newer("1.9.7", "1.13.0"))
        self.assertTrue(uc._is_newer("1.13.0", "1.9.7"))

    def test_same_version_is_not_an_update(self):
        self.assertFalse(uc._is_newer("1.0.4", "1.0.4"))
        self.assertFalse(uc._is_newer("v1.0.4", "1.0.4"))

    def test_missing_side_is_not_an_update(self):
        self.assertFalse(uc._is_newer("", "1.0"))
        self.assertFalse(uc._is_newer("1.0", ""))

    def test_unparseable_falls_back_to_inequality(self):
        """Нестандартный формат — лучше предложить, чем потерять."""
        self.assertTrue(uc._is_newer("20260726-ab13e3d", "20260101-000000f"))
        self.assertFalse(uc._is_newer("abc", "abc"))


class TestAwgResultContract(unittest.TestCase):
    """Страница «Обновления» читает те же поля, что отдаёт установщик AWG.

    Раньше читались несуществующие ключи (`installed.version`,
    `latest.version`, `has_update`), поэтому AmneziaWG всегда показывал
    «–» и не предлагал обновление — при том что своя страница AWG новую
    версию видела.
    """

    def _run_with(self, payload):
        from unittest import mock
        inst = mock.Mock()
        inst.check_for_updates.return_value = payload
        with mock.patch("core.awg_installer.get_awg_installer",
                        return_value=inst):
            return uc._check_awg()

    def test_versions_and_flag_are_extracted(self):
        row = self._run_with({
            "ok": True,
            "installed": {"installed": True, "go_version": "0.2.18",
                          "tools_version": "1.0.20260223", "tag": "old"},
            "latest_go": "3.0.3", "latest_tools": "3.0.20260730",
            "latest_tag": "awg-bin-go-3.0.3-tools-3.0.20260730",
            "update_available": True,
        })
        self.assertTrue(row["installed"])
        self.assertEqual(row["current"], "0.2.18")
        self.assertEqual(row["latest"], "3.0.3")
        self.assertTrue(row["has_update"])

    def test_no_update_when_installer_says_so(self):
        row = self._run_with({
            "ok": True,
            "installed": {"installed": True, "go_version": "3.0.3"},
            "latest_go": "3.0.3", "update_available": False,
        })
        self.assertFalse(row["has_update"])
        self.assertEqual(row["current"], "3.0.3")

    def test_failed_check_reports_error_not_silence(self):
        row = self._run_with({"ok": False, "error": "нет манифеста"})
        self.assertFalse(row["has_update"])
        self.assertIn("error", row)


