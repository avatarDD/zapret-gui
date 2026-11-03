# tests/test_update_checker_ssl.py
"""Страница «Обновления» при сломанном SSL в Python и версия mihomo.

Регрессии с Keenetic (ноябрь 2026):
  * файл /opt/lib/libssl.so.3 повреждён («Structure needs cleaning»):
    `import ssl` падает, и каждая строка показывала свой вариант одной
    причины — «libssl.so.3: …», «unknown url type: https», у AWG вовсе
    «не найден релиз с manifest.json», — да ещё с советом про зеркало,
    который тут не поможет;
  * `mihomo -v` не укладывался в 3 с, и «Текущая» у mihomo была пустой.
"""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from core import ssl_health
from core import update_checker as uc


EUCLEAN_TEXT = ("libssl.so.3: cannot open shared object file: "
                "Structure needs cleaning")


class TestSslHealth(unittest.TestCase):

    def tearDown(self):
        ssl_health._cached = None

    def test_ok_when_ssl_imports(self):
        self.assertEqual(ssl_health.ssl_problem(refresh=True), "")

    def test_euclean_names_filesystem_and_fix(self):
        msg = ssl_health._diagnose(ImportError(EUCLEAN_TEXT))
        self.assertIn("файловой системы", msg)
        self.assertIn("libssl", msg)
        self.assertIn("opkg install --force-reinstall libopenssl", msg)

    def test_missing_module(self):
        msg = ssl_health._diagnose(ImportError("No module named '_ssl'"))
        self.assertIn("python3-openssl", msg)

    def test_looks_like_ssl_error(self):
        for text in (EUCLEAN_TEXT, "<urlopen error unknown url type: https>",
                     "No module named '_ssl'"):
            self.assertTrue(ssl_health.looks_like_ssl_error(text), text)
        self.assertFalse(ssl_health.looks_like_ssl_error(
            "The handshake operation timed out"))

    def test_import_failure_is_diagnosed(self):
        import builtins
        real = builtins.__import__

        def fake(name, *a, **kw):
            if name == "ssl":
                raise ImportError(EUCLEAN_TEXT)
            return real(name, *a, **kw)

        with mock.patch("builtins.__import__", side_effect=fake):
            msg = ssl_health.ssl_problem(refresh=True)
        self.assertIn("Structure needs cleaning", msg)

    def test_unreachable_message_skips_mirror_advice(self):
        from core.binary_installer import github_unreachable_message
        with mock.patch("core.ssl_health.ssl_problem",
                        return_value="SSL сломан"):
            msg = github_unreachable_message(
                OSError("unknown url type: https"))
        self.assertIn("SSL сломан", msg)
        self.assertNotIn("зеркало", msg)


class TestApplySslProblem(unittest.TestCase):

    def _rows(self):
        return [
            {"name": "zapret2", "installed": True, "current": "v1.0.6",
             "latest": "", "error": EUCLEAN_TEXT},
            {"name": "awg", "installed": False, "current": "", "latest": "",
             "error": "Не найден релиз с manifest.json в репозитории x"},
            {"name": "usque", "installed": True, "current": "4.2.1",
             "latest": "", "latest_source": "unknown",
             "note": "файл принадлежит пакету usque-keenetic"},
            {"name": "geneva", "installed": True, "current": "1.1.1",
             "latest": "1.1.1", "latest_source": "pinned"},
        ]

    def test_no_problem_leaves_rows(self):
        rows = self._rows()
        with mock.patch("core.ssl_health.ssl_problem", return_value=""):
            self.assertEqual(uc._apply_ssl_problem(rows), "")
        self.assertEqual(rows, self._rows())

    def test_problem_unifies_rows(self):
        rows = self._rows()
        with mock.patch("core.ssl_health.ssl_problem",
                        return_value="SSL сломан"):
            self.assertEqual(uc._apply_ssl_problem(rows), "SSL сломан")
        zapret, awg, usque, geneva = rows
        self.assertEqual(zapret["error"], "SSL сломан")
        self.assertEqual(zapret["note"], uc.SSL_ROW_NOTE)
        self.assertEqual(awg["note"], uc.SSL_ROW_NOTE)
        # Своя подпись строки (пакет usque-keenetic) важнее общей.
        self.assertEqual(usque["note"],
                         "файл принадлежит пакету usque-keenetic")
        # Закреплённая «последняя» известна без сети — строку не трогаем.
        self.assertNotIn("error", geneva)

    def test_check_all_exposes_ssl_error(self):
        row = {"name": "x", "display_name": "x", "installed": False,
               "current": "", "latest": "", "error": EUCLEAN_TEXT}
        names = ["_check_zapret", "_check_singbox", "_check_mihomo",
                 "_check_awg", "_check_gui", "_check_usque",
                 "_check_tgwsproxy", "_check_tgproto", "_check_opera",
                 "_check_geneva"]
        patches = [mock.patch.object(uc, n, return_value=dict(row))
                   for n in names]
        patches.append(mock.patch("core.ssl_health.ssl_problem",
                                  return_value="SSL сломан"))
        patches.append(mock.patch.object(uc, "_log_installed_transitions"))
        for p in patches:
            p.start()
        try:
            res = uc.check_all()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(res["ssl_error"], "SSL сломан")
        self.assertTrue(all(r["note"] == uc.SSL_ROW_NOTE
                            for r in res["results"]))


class TestMihomoVersion(unittest.TestCase):

    def test_parse_release(self):
        from core.mihomo_detector import parse_version
        self.assertEqual(parse_version(
            "Mihomo Meta v1.19.15 linux mipsle with go1.25.1 Thu Oct 2"),
            "1.19.15")

    def test_parse_alpha_is_not_go_version(self):
        from core.mihomo_detector import parse_version
        self.assertEqual(parse_version(
            "Mihomo Meta alpha-a1b2c3d linux arm64 with go1.25.1"),
            "alpha-a1b2c3d")

    def test_parse_empty(self):
        from core.mihomo_detector import parse_version
        self.assertEqual(parse_version(""), "")

    def test_one_probe_with_long_timeout_and_cache(self):
        from core import mihomo_detector as md
        with tempfile.NamedTemporaryFile() as f:
            det = md.MihomoDetector()
            out = "Mihomo Meta v1.19.15 linux mipsle\nUse tags: with_gvisor"
            with mock.patch.object(md, "_cmd_out",
                                   return_value=out) as run:
                self.assertEqual(det._probe_version(f.name), "1.19.15")
                self.assertTrue(det._detect_gvisor(f.name))
            run.assert_called_once()
            self.assertGreaterEqual(run.call_args.kwargs["timeout"], 10)

    def test_empty_output_is_not_cached(self):
        from core import mihomo_detector as md
        with tempfile.NamedTemporaryFile() as f:
            det = md.MihomoDetector()
            with mock.patch.object(md, "_cmd_out", return_value=""):
                self.assertEqual(det._probe_version(f.name), "")
            with mock.patch.object(md, "_cmd_out",
                                   return_value="Mihomo Meta v1.19.15"):
                self.assertEqual(det._probe_version(f.name), "1.19.15")


class TestMihomoStateFallback(unittest.TestCase):

    def _installed(self, path, state):
        from core import mihomo_installer as mi
        det = mock.Mock()
        det.detect_binary.return_value = {"installed": True, "path": path,
                                          "version": ""}
        with mock.patch.object(mi, "get_mihomo_detector",
                               return_value=det), \
                mock.patch.object(mi, "_read_state", return_value=state):
            return mi.MihomoInstaller().get_installed_version()

    def test_state_version_used_for_same_file(self):
        with tempfile.NamedTemporaryFile() as f:
            os.utime(f.name, (time.time() - 100, time.time() - 100))
            got = self._installed(f.name, {
                "version": "1.19.15", "binary": f.name,
                "installed_at": int(time.time())})
        self.assertEqual(got["version"], "1.19.15")

    def test_state_ignored_when_file_replaced(self):
        with tempfile.NamedTemporaryFile() as f:
            got = self._installed(f.name, {
                "version": "1.19.15", "binary": f.name,
                "installed_at": int(time.time()) - 86400})
        self.assertEqual(got["version"], "")

    def test_state_ignored_for_other_path(self):
        with tempfile.NamedTemporaryFile() as f:
            got = self._installed(f.name, {
                "version": "1.19.15", "binary": "/opt/other/mihomo",
                "installed_at": int(time.time())})
        self.assertEqual(got["version"], "")


if __name__ == "__main__":
    unittest.main()
