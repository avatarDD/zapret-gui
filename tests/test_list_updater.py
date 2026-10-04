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


class TestExtraUrls(unittest.TestCase):
    """Подсети сервиса — дополнительные источники того же списка (#102)."""

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.named_lists.get_config_manager",
                             return_value=self.fake)
        self._p.start()
        self._pr = mock.patch.object(lu, "get_list_refresher",
                                     return_value=mock.Mock())
        self._pr.start()
        self.tg = lu.preset_for_url(lu._BASE + "/Services/telegram.lst")

    def tearDown(self):
        self._p.stop()
        self._pr.stop()

    @staticmethod
    def _fake_fetch(url, transport=""):
        if "/Subnets/IPv4/" in url:
            return "91.108.4.0/22\n149.154.160.0/20\n"
        if "/Subnets/IPv6/" in url:
            return "2001:b28:f23d::/48\n"
        return "telegram.org\nt.me\n"

    def test_telegram_preset_has_subnets(self):
        self.assertIsNotNone(self.tg)
        extra = self.tg.get("extra_urls") or []
        self.assertTrue(any("/Subnets/IPv4/telegram.lst" in u for u in extra))
        self.assertTrue(any("/Subnets/IPv6/telegram.lst" in u for u in extra))

    def test_refresh_merges_domains_and_cidrs(self):
        from core import named_lists
        lid = named_lists.create("Telegram", source_url=self.tg["url"])["list"]["id"]
        named_lists.update_fields(lid, {"extra_urls": self.tg["extra_urls"]})
        with mock.patch.object(lu, "_fetch", side_effect=self._fake_fetch):
            r = lu.refresh_one(lid)
        self.assertTrue(r["ok"], msg=r.get("error"))
        item = named_lists.get(lid)
        self.assertEqual(item["domains"], ["telegram.org", "t.me"])
        self.assertIn("91.108.4.0/22", item["cidrs"])
        self.assertIn("2001:b28:f23d::/48", item["cidrs"])

    def test_legacy_list_gets_preset_subnets(self):
        # Список «Telegram», добавленный до появления extra_urls: поля нет —
        # подсети берутся из пресета.
        from core import named_lists
        lid = named_lists.create("Telegram", source_url=self.tg["url"])["list"]["id"]
        item = named_lists.get(lid)
        self.assertNotIn("extra_urls", item)
        self.assertEqual(lu.source_urls(item)[1:], self.tg["extra_urls"])

    def test_explicit_empty_extra_honored(self):
        from core import named_lists
        lid = named_lists.create("Telegram", source_url=self.tg["url"])["list"]["id"]
        named_lists.update_fields(lid, {"extra_urls": []})
        self.assertEqual(lu.source_urls(named_lists.get(lid)), [self.tg["url"]])

    def test_extra_failure_does_not_clobber(self):
        from core import named_lists
        lid = named_lists.create("Telegram", source_url=self.tg["url"])["list"]["id"]
        with mock.patch.object(lu, "_fetch", side_effect=self._fake_fetch):
            self.assertTrue(lu.refresh_one(lid)["ok"])

        def _broken(url, transport=""):
            if "/Subnets/" in url:
                raise RuntimeError("HTTP 404")
            return self._fake_fetch(url)

        with mock.patch.object(lu, "_fetch", side_effect=_broken):
            r = lu.refresh_one(lid)
        self.assertFalse(r["ok"])
        self.assertIn("Subnets", r["error"])
        item = named_lists.get(lid)
        self.assertIn("149.154.160.0/20", item["cidrs"])  # подсети на месте
        self.assertEqual(item["last_status"], "error")

    def test_add_preset_stores_extra_urls(self):
        from core import named_lists
        with mock.patch.object(lu, "is_safe_url", return_value=True), \
                mock.patch.object(lu, "_fetch", side_effect=self._fake_fetch):
            r = lu.add_preset(self.tg["url"])
        self.assertTrue(r["ok"], msg=r.get("error"))
        item = named_lists.get(r["id"])
        self.assertEqual(item["extra_urls"], self.tg["extra_urls"])
        self.assertIn("91.108.4.0/22", item["cidrs"])


if __name__ == "__main__":
    unittest.main()
