# tests/test_update_checker_sources.py
"""Страница «Обновления»: «последняя» — ровно то, что поставит кнопка.

Регрессии из разбора живого роутера:
  * проверка искала наши сборки в окне 30 релизов, установщик — в окне
    50; opera-bin-v1.28.0 лежала 48-й, и страница обещала апстримную
    1.30.0, которую установить нельзя;
  * у внешних установок (пакеты Entware amneziawg-go, usque-keenetic)
    «текущая» — версия пакета, «последняя» — версия нашей сборки, и
    «доступно» горело вечно;
  * кеш проверки не пересчитывался после установки.
"""

import json
import os
import tempfile
import unittest
from unittest import mock


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _gui_releases(n, start=0):
    return [{"tag_name": "v0.%d.0" % (start + i), "draft": False}
            for i in range(n)]


class TestReleaseWindow(unittest.TestCase):
    """Поиск сборки по префиксу листает страницы и одинаков для всех."""

    def setUp(self):
        import core.ext_binary_installer as ebi
        self.ebi = ebi
        ebi._releases_cache.clear()

    def _pages(self, pages):
        calls = []

        def fake(url, **kw):
            calls.append(url)
            page = int(url.rsplit("page=", 1)[1])
            return _Resp(pages[page - 1] if page <= len(pages) else [])
        return fake, calls

    def test_build_found_on_second_page(self):
        page1 = _gui_releases(self.ebi.RELEASES_PER_PAGE)
        page2 = _gui_releases(5, 1000) + [
            {"tag_name": "opera-bin-v1.28.0", "draft": False}]
        fake, calls = self._pages([page1, page2])
        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=fake):
            rel = self.ebi.github_release_by_prefix("avatarDD/zapret-gui",
                                                    "opera-bin-")
        self.assertEqual(rel.get("tag_name"), "opera-bin-v1.28.0")
        self.assertEqual(len(calls), 2)

    def test_list_releases_sees_same_build_as_installer(self):
        page1 = _gui_releases(self.ebi.RELEASES_PER_PAGE)
        page2 = [{"tag_name": "opera-bin-v1.28.0", "draft": False}]
        fake, _calls = self._pages([page1, page2])
        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=fake):
            out = self.ebi.list_releases("opera", force=True)
        self.assertEqual([r["tag"] for r in out["releases"]],
                         ["opera-bin-v1.28.0"])

    def test_not_found_is_distinguished_from_error(self):
        fake, _calls = self._pages([_gui_releases(3)])
        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=fake):
            rel = self.ebi.github_release_by_prefix("r", "opera-bin-")
        self.assertTrue(rel.get("not_found"))

        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=OSError("сеть")):
            rel = self.ebi.github_release_by_prefix("r", "opera-bin-")
        self.assertIn("error_detail", rel)
        self.assertFalse(rel.get("not_found"))

    def test_single_window_constant(self):
        """per_page для поиска наших сборок задан в одном месте."""
        import re
        src = open(self.ebi.__file__, encoding="utf-8").read()
        self.assertEqual(len(re.findall(r"per_page=50", src)), 0)


class TestOperaLatest(unittest.TestCase):

    def _check(self, rel, upstream="1.30.0", version="1.28.0"):
        from core.update_checker import _check_opera
        mgr = mock.Mock()
        mgr.detect.return_value = {"installed": True, "version": version,
                                   "binary": ""}
        with mock.patch("core.ext_binary_installer.github_release_by_prefix",
                        return_value=rel), \
             mock.patch("core.update_checker._github_latest",
                        return_value=upstream) as gl, \
             mock.patch("core.opera_proxy_manager.get_opera_proxy_manager",
                        return_value=mgr):
            return _check_opera(), gl

    def test_our_build_wins_and_badge_off(self):
        row, gl = self._check({"tag_name": "opera-bin-v1.28.0"})
        gl.assert_not_called()
        self.assertEqual(row["latest"], "1.28.0")
        self.assertEqual(row["latest_source"], "our")
        self.assertFalse(row["has_update"])

    def test_lookup_error_is_unknown_not_upstream(self):
        row, gl = self._check({"error_detail": "сеть"})
        gl.assert_not_called()
        self.assertEqual(row["latest"], "")
        self.assertEqual(row["latest_source"], "unknown")
        self.assertFalse(row["has_update"])

    def test_upstream_only_when_build_absent(self):
        row, gl = self._check({"error_detail": "нет", "not_found": True})
        gl.assert_called_once()
        self.assertEqual(row["latest"], "1.30.0")
        self.assertEqual(row["latest_source"], "upstream")
        self.assertIn("апстрим", row["note"])


class TestExternalAwg(unittest.TestCase):

    def test_opkg_install_marked_and_no_update(self):
        from core.update_checker import _check_awg
        inst = mock.Mock()
        inst.check_for_updates.return_value = {
            "ok": True, "latest_go": "3.1.20260828",
            "update_available": False,
            "installed": {"installed": True, "external": True, "tag": "",
                          "go_version": "v0.2.16-1",
                          "go_version_source": "opkg",
                          "amneziawg_go": "/opt/sbin/amneziawg-go"},
        }
        with mock.patch("core.awg_installer.get_awg_installer",
                        return_value=inst):
            row = _check_awg()
        self.assertEqual(row["external"], "opkg")
        self.assertEqual(row["version_source"], "opkg")
        self.assertFalse(row["has_update"])
        self.assertIn("внешняя установка", row["note"])


class TestUsquePackage(unittest.TestCase):

    def _check(self, version, pkg_version):
        from core.update_checker import _check_usque
        mgr = mock.Mock()
        mgr.detect.return_value = {"installed": True, "version": version,
                                   "binary": "/opt/usr/bin/usque"}
        with mock.patch("core.usque_manager.get_usque_manager",
                        return_value=mgr), \
             mock.patch("core.ext_binary_installer.github_release_by_prefix",
                        return_value={"tag_name": "usque-bin-v4.2.1"}), \
             mock.patch("core.ext_binary_installer._pkg_version",
                        return_value=pkg_version):
            return _check_usque()

    def test_package_version_not_compared_with_our_build(self):
        row = self._check("0.3.0", "0.3.0")
        self.assertEqual(row["latest"], "4.2.1")
        self.assertEqual(row["external"], "opkg")
        self.assertEqual(row["version_source"], "opkg")
        self.assertFalse(row["has_update"])
        self.assertIn("usque-keenetic", row["note"])

    def test_binary_version_compared_but_overwrite_warned(self):
        row = self._check("4.2.0", "0.3.0")
        self.assertEqual(row["version_source"], "binary")
        self.assertTrue(row["has_update"])
        self.assertIn("перезапишет", row["note"])

    def test_no_package_no_marks(self):
        row = self._check("4.2.0", "")
        self.assertNotIn("external", row)
        self.assertTrue(row["has_update"])


class TestRefreshAfterInstall(unittest.TestCase):

    def setUp(self):
        import core.update_checker as uc
        self.uc = uc
        self._saved = uc._results
        self.addCleanup(self._restore)

    def _restore(self):
        self.uc._results = self._saved

    def test_refresh_component_replaces_row(self):
        self.uc._results = {
            "ok": True, "updates_count": 1, "checked_at": 1,
            "results": [
                {"name": "opera", "installed": True, "current": "1.27.0",
                 "latest": "1.28.0", "has_update": True},
                {"name": "gui", "installed": True, "has_update": False},
            ]}
        fresh = {"name": "opera", "installed": True, "current": "1.28.0",
                 "latest": "1.28.0", "has_update": False}
        with mock.patch.dict(self.uc._CHECKERS,
                             {"opera": lambda: dict(fresh)}):
            self.uc.refresh_component("opera")
        rows = self.uc.get_cached_results()["results"]
        self.assertEqual(rows[0]["current"], "1.28.0")
        self.assertFalse(rows[0]["has_update"])
        self.assertEqual(self.uc._results["updates_count"], 0)

    def test_schedule_noop_without_cache(self):
        self.uc._results = {}
        self.assertFalse(self.uc.schedule_refresh("opera"))

    def test_installer_triggers_refresh(self):
        import core.ext_binary_installer as ebi
        with mock.patch("core.update_checker.schedule_refresh") as sr, \
             mock.patch.object(ebi, "_install_binary_by_name",
                               return_value={"ok": True}):
            ebi.install_binary_by_name("opera")
        sr.assert_called_once_with("opera")

    def test_changed_file_marks_row_stale(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "opera-proxy")
            with open(path, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(path, 0o755)
            os.utime(path, (2000, 2000))
            self.uc._results = {
                "ok": True, "updates_count": 1, "checked_at": 1,
                "results": [{"name": "opera", "installed": True,
                             "current": "1.27.0", "latest": "1.28.0",
                             "has_update": True, "path": path,
                             "path_mtime": 1000}]}
            with mock.patch.object(self.uc, "schedule_refresh") as sr:
                res = self.uc.get_cached_results()
        row = res["results"][0]
        self.assertTrue(row["stale"])
        self.assertFalse(row["has_update"])
        sr.assert_called_once_with("opera")


if __name__ == "__main__":
    unittest.main()
