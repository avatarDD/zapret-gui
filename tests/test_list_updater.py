# tests/test_list_updater.py
"""Unit-тесты для core/list_updater.py."""

import unittest
from unittest import mock

from core import list_updater as lu


class FakeConfigManager:
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def save(self):
        return True


class TestMergePreservingManual(unittest.TestCase):

    def test_manual_preserved_and_upstream_removal(self):
        current = {"domains": ["a.com", "b.com", "manual.com"], "cidrs": []}
        remote = {"domains": ["a.com", "c.com"], "cidrs": []}
        prev = {"domains": ["a.com", "b.com"], "cidrs": []}
        # manual = current - prev = ["manual.com"]
        # result = remote ∪ manual = a.com, c.com, manual.com
        # b.com (был в prev, удалён в upstream, не ручной) — уходит.
        out = lu.merge_preserving_manual(current, remote, prev)
        self.assertEqual(out["domains"], ["a.com", "c.com", "manual.com"])

    def test_first_run_no_prev(self):
        current = {"domains": ["manual.com"], "cidrs": []}
        remote = {"domains": ["x.com"], "cidrs": []}
        prev = {"domains": [], "cidrs": []}
        out = lu.merge_preserving_manual(current, remote, prev)
        # всё current считается ручным на первом прогоне
        self.assertEqual(out["domains"], ["x.com", "manual.com"])

    def test_cidrs(self):
        out = lu.merge_preserving_manual(
            {"domains": [], "cidrs": ["1.1.1.0/24", "9.9.9.9/32"]},
            {"domains": [], "cidrs": ["1.1.1.0/24"]},
            {"domains": [], "cidrs": ["1.1.1.0/24"]})
        self.assertEqual(out["cidrs"], ["1.1.1.0/24", "9.9.9.9/32"])

    def test_no_duplicates(self):
        out = lu.merge_preserving_manual(
            {"domains": ["a.com"], "cidrs": []},
            {"domains": ["a.com"], "cidrs": []},
            {"domains": [], "cidrs": []})
        self.assertEqual(out["domains"], ["a.com"])


class TestRefreshOne(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.named_lists.get_config_manager",
                             return_value=self.fake)
        self._p.start()
        # Не дёргаем фоновый поток.
        self._pr = mock.patch.object(lu, "get_list_refresher",
                                     return_value=mock.Mock())
        self._pr.start()

    def tearDown(self):
        self._p.stop()
        self._pr.stop()

    def _make_list(self, domains=None):
        from core import named_lists
        r = named_lists.create("Test", source_url="https://x/list.lst")
        lid = r["list"]["id"]
        if domains:
            named_lists.update_fields(lid, {"domains": domains})
        return lid

    def test_ok_merge(self):
        lid = self._make_list(domains=["manual.com"])
        with mock.patch.object(lu, "_fetch",
                               return_value="a.com\nb.com\n"):
            r = lu.refresh_one(lid)
        self.assertTrue(r["ok"], msg=r.get("error"))
        from core import named_lists
        item = named_lists.get(lid)
        self.assertIn("a.com", item["domains"])
        self.assertIn("manual.com", item["domains"])  # ручное сохранено
        self.assertEqual(item["last_status"], "ok")
        self.assertEqual(item["_remote"]["domains"], ["a.com", "b.com"])

    def test_empty_not_clobbered(self):
        lid = self._make_list(domains=["keep.com"])
        with mock.patch.object(lu, "_fetch", return_value="\n# only comment\n"):
            r = lu.refresh_one(lid)
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("preserved"))
        from core import named_lists
        item = named_lists.get(lid)
        self.assertEqual(item["domains"], ["keep.com"])  # не затёрто
        self.assertEqual(item["last_status"], "empty")

    def test_fetch_error_not_clobbered(self):
        lid = self._make_list(domains=["keep.com"])
        with mock.patch.object(lu, "_fetch",
                               side_effect=RuntimeError("сеть: timeout")):
            r = lu.refresh_one(lid)
        self.assertFalse(r["ok"])
        from core import named_lists
        item = named_lists.get(lid)
        self.assertEqual(item["domains"], ["keep.com"])
        self.assertEqual(item["last_status"], "error")

    def test_no_source_url(self):
        from core import named_lists
        lid = named_lists.create("Plain")["list"]["id"]
        r = lu.refresh_one(lid)
        self.assertFalse(r["ok"])

    def test_managed_lists_filter(self):
        self._make_list()
        from core import named_lists
        named_lists.create("Plain")  # без source_url
        managed = lu.managed_lists()
        self.assertEqual(len(managed), 1)


class TestPresets(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.named_lists.get_config_manager",
                             return_value=self.fake)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_presets_added_flag(self):
        url = lu.CURATED_PRESETS[0]["url"]
        from core import named_lists
        named_lists.create("X", source_url=url)
        by_url = {p["url"]: p["added"] for p in lu.presets()}
        self.assertTrue(by_url[url])
        # Прочие — не добавлены.
        other = lu.CURATED_PRESETS[1]["url"]
        self.assertFalse(by_url[other])


if __name__ == "__main__":
    unittest.main()
