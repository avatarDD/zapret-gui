# tests/test_catalog_updater.py
"""
Регрессия: «доступно обновление» каталогов сравнивалось с HEAD всей
ветки (любой посторонний коммит менял sha) → после успешного обновления
снова показывало «надо обновить». Теперь сравниваем по subpath каталогов.
"""

import unittest
from unittest import mock

from core import catalog_updater as cu


class TestRemoteInfoParsing(unittest.TestCase):

    def setUp(self):
        self.upd = cu.CatalogUpdater()

    def test_list_form(self):
        # commits?path=... → список (новые сверху).
        commits = [{"sha": "newsha", "commit": {"author": {"date": "2026-05-01"},
                                                "message": "update catalogs"}}]
        with mock.patch.object(cu, "_fetch_json", return_value=commits):
            r = self.upd.get_remote_info(force_refresh=True)
        self.assertTrue(r["ok"])
        self.assertEqual(r["sha"], "newsha")
        self.assertEqual(r["short_sha"], "newsha"[:7])

    def test_object_form_still_supported(self):
        obj = {"sha": "abc", "commit": {"author": {"date": "x"}, "message": "m"}}
        with mock.patch.object(cu, "_fetch_json", return_value=obj):
            r = self.upd.get_remote_info(force_refresh=True)
        self.assertEqual(r["sha"], "abc")

    def test_empty_list(self):
        with mock.patch.object(cu, "_fetch_json", return_value=[]):
            r = self.upd.get_remote_info(force_refresh=True)
        self.assertFalse(r["ok"])

    def test_url_uses_subpath_not_head(self):
        # Ключевая регрессия: сравниваем по subpath каталогов, не по HEAD.
        self.assertIn("path=", cu.GITHUB_COMMITS_API)
        self.assertIn("winws2", cu.GITHUB_COMMITS_API)
        self.assertNotIn("/commits/main", cu.GITHUB_COMMITS_API)


class TestComparison(unittest.TestCase):

    def setUp(self):
        self.upd = cu.CatalogUpdater()

    def _with(self, local_sha, remote_sha):
        commits = [{"sha": remote_sha,
                    "commit": {"author": {"date": "d"}, "message": "m"}}]
        return mock.patch.object(cu, "_fetch_json", return_value=commits), \
            mock.patch.object(cu, "_load_state",
                              return_value={"sha": local_sha} if local_sha else None)

    def test_no_update_when_same_sha(self):
        p1, p2 = self._with("sha1", "sha1")
        with p1, p2:
            r = self.upd.get_comparison(force_refresh=True)
        self.assertFalse(r["update_available"])

    def test_update_when_sha_differs(self):
        p1, p2 = self._with("old", "new")
        with p1, p2:
            r = self.upd.get_comparison(force_refresh=True)
        self.assertTrue(r["update_available"])

    def test_update_when_never_updated(self):
        p1, p2 = self._with(None, "new")
        with p1, p2:
            r = self.upd.get_comparison(force_refresh=True)
        self.assertTrue(r["update_available"])


if __name__ == "__main__":
    unittest.main()
