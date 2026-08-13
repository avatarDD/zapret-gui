# tests/test_update_checker_stale_path.py
"""Регрессия discussion #102: «Обновления» держали «Установлен: Да» сутками.

Проверка обновлений ходит в GitHub и потому кешируется (по умолчанию раз
в 24 часа), но вместе с сетевыми данными из кеша отдавался и локальный
факт «установлен». Файл, найденный при проверке, мог исчезнуть — и
страница показывала «Установлен: Да» для программы, которой на роутере
нет, споря с её собственной страницей установки.

Здесь проверяем, что `get_cached_results()` сверяет путь с диском, гасит
строку и объясняет, что именно исчезло, а живой файл не трогает.
"""

import os
import tempfile
import unittest
from unittest import mock


class TestRevalidateCachedResults(unittest.TestCase):

    def setUp(self):
        import core.update_checker as uc
        self.uc = uc
        self._saved = uc._results
        self.addCleanup(self._restore)

    def _restore(self):
        self.uc._results = self._saved

    def _set_cache(self, rows, updates_count=0):
        self.uc._results = {
            "ok": True,
            "results": rows,
            "updates_count": updates_count,
            "checked_at": 1000,
        }

    def test_vanished_binary_turns_row_off(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "usque")
            self._set_cache([{"name": "usque",
                              "display_name": "usque (WARP/MASQUE)",
                              "installed": True, "current": "4.2.1",
                              "latest": "4.2.2", "has_update": True,
                              "path": path, "path_mtime": 123}], 1)

            # Файла нет — строка обязана погаснуть и показать, что пропало.
            res = self.uc.get_cached_results()

        row = res["results"][0]
        self.assertFalse(row["installed"])
        self.assertFalse(row["has_update"])
        self.assertEqual(row["current"], "")
        self.assertEqual(row["vanished_path"], path)
        self.assertEqual(res["updates_count"], 0)

    def test_live_binary_row_survives(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "usque")
            with open(path, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(path, 0o755)
            self._set_cache([{"name": "usque", "installed": True,
                              "current": "4.2.1", "latest": "4.2.2",
                              "has_update": True, "path": path}], 1)

            res = self.uc.get_cached_results()

        row = res["results"][0]
        self.assertTrue(row["installed"])
        self.assertTrue(row["has_update"])
        self.assertEqual(row["path"], path)
        self.assertNotIn("vanished_path", row)
        self.assertEqual(res["updates_count"], 1)

    def test_row_without_path_untouched(self):
        """GUI сам себе путь не ищет — гасить его нечем и незачем."""
        self._set_cache([{"name": "gui", "installed": True,
                          "current": "0.24.12", "latest": "0.24.12",
                          "has_update": False}])

        row = self.uc.get_cached_results()["results"][0]

        self.assertTrue(row["installed"])

    def test_cache_itself_not_rewritten(self):
        """Сверка отдаёт копию: кеш проверки не должен затираться."""
        with tempfile.TemporaryDirectory() as d:
            self._set_cache([{"name": "usque", "installed": True,
                              "current": "4.2.1", "latest": "4.2.1",
                              "has_update": False,
                              "path": os.path.join(d, "usque")}])
            self.uc.get_cached_results()

        self.assertTrue(self.uc._results["results"][0]["installed"])

    def test_empty_cache(self):
        self.uc._results = {}
        res = self.uc.get_cached_results()
        self.assertEqual(res["results"], [])
        self.assertEqual(res["checked_at"], 0)


class TestInstalledTransitionLog(unittest.TestCase):
    """Появление бинарника должно оставлять след в логе — с путём."""

    def setUp(self):
        import core.update_checker as uc
        self.uc = uc
        self._saved = uc._results
        self.addCleanup(self._restore)

    def _restore(self):
        self.uc._results = self._saved

    def test_appearance_logged_with_path(self):
        self.uc._results = {
            "ok": True, "updates_count": 0, "checked_at": 1,
            "results": [{"name": "usque", "installed": False, "path": ""}],
        }
        with mock.patch.object(self.uc.log, "info") as info:
            self.uc._log_installed_transitions(
                [{"name": "usque", "installed": True, "current": "4.2.1",
                  "path": "/opt/usr/bin/usque"}])

        self.assertTrue(info.called)
        msg = info.call_args[0][0]
        self.assertIn("/opt/usr/bin/usque", msg)
        self.assertIn("4.2.1", msg)

    def test_disappearance_logged(self):
        self.uc._results = {
            "ok": True, "updates_count": 0, "checked_at": 1,
            "results": [{"name": "usque", "installed": True,
                         "path": "/opt/usr/bin/usque"}],
        }
        with mock.patch.object(self.uc.log, "info") as info:
            self.uc._log_installed_transitions(
                [{"name": "usque", "installed": False, "path": ""}])

        self.assertIn("/opt/usr/bin/usque", info.call_args[0][0])

    def test_no_log_without_previous_check(self):
        self.uc._results = {}
        with mock.patch.object(self.uc.log, "info") as info:
            self.uc._log_installed_transitions(
                [{"name": "usque", "installed": True, "path": "/x"}])

        self.assertFalse(info.called)


class TestUsqueEmptyBinaryNotInstalled(unittest.TestCase):
    """Нулевой файл — след оборванной закачки, а не установка."""

    def test_zero_size_binary_ignored(self):
        from core.usque_manager import UsqueManager
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "usque")
            open(path, "w").close()
            os.chmod(path, 0o755)
            with mock.patch("core.usque_manager.USQUE_BINARY_PATHS", (path,)):
                self.assertEqual(UsqueManager()._find_binary(), "")

            with open(path, "w") as f:
                f.write("#!/bin/sh\n")
            with mock.patch("core.usque_manager.USQUE_BINARY_PATHS", (path,)):
                self.assertEqual(UsqueManager()._find_binary(), path)


if __name__ == "__main__":
    unittest.main()
