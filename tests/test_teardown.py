# tests/test_teardown.py
"""Тесты best-effort очистки runtime-артефактов (core/teardown.py)."""

import unittest
from unittest import mock

from core import teardown


class TestTeardownRun(unittest.TestCase):

    def test_run_returns_zero(self):
        # На чистой среде (нет nfqws/хуков) run() не должен падать.
        self.assertEqual(teardown.run(), 0)

    def test_run_invokes_all_steps(self):
        with mock.patch.object(teardown, "_disable_autostart") as a, \
             mock.patch.object(teardown, "_stop_nfqws") as s, \
             mock.patch.object(teardown, "_remove_firewall") as f, \
             mock.patch.object(teardown, "_remove_persistence") as p:
            self.assertEqual(teardown.run(), 0)
            a.assert_called_once()
            s.assert_called_once()
            f.assert_called_once()
            p.assert_called_once()

    def test_step_exception_is_isolated(self):
        # Если менеджер бросает — обёртка ловит и не пробрасывает наружу.
        with mock.patch("core.nfqws_manager.get_nfqws_manager",
                        side_effect=RuntimeError("boom")):
            try:
                teardown._stop_nfqws()  # не должно бросать
            except Exception:  # noqa: BLE001
                self.fail("_stop_nfqws пробросил исключение")

    def test_remove_persistence_removes_files(self):
        from core import firewall_persistence as fp
        with mock.patch.object(fp, "remove_hooks",
                               return_value={"removed": []}), \
             mock.patch("os.path.exists", return_value=False):
            # Не должно падать, даже если файлов нет.
            teardown._remove_persistence()


if __name__ == "__main__":
    unittest.main()
