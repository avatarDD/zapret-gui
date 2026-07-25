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
