# tests/test_gui_updater.py
"""
Регрессия: проверка обновлений GUI использовала /releases/latest, и
бинарные релизы (singbox-bin-*/awg-bin-*/manual-*, тоже non-prerelease)
перебивали свежий vX.Y.Z → новый релиз GUI «не виден». Теперь выбираем
новейший релиз с тэгом-семвером, игнорируя бинарные.
"""

import json
import unittest
from unittest import mock

import core.gui_updater as gu
from core.gui_updater import GuiUpdater, _GUI_TAG_RE


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def read(self):
        return json.dumps(self._data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestGuiTagRegex(unittest.TestCase):

    def test_matches_gui_tags(self):
        for t in ("v0.21.9", "0.21.9", "v1.0", "v10.2.34"):
            self.assertTrue(_GUI_TAG_RE.match(t), t)

    def test_rejects_binary_tags(self):
        for t in ("singbox-bin-v1.14.0-alpha.26", "awg-bin-go-0.2.18-tools-1.0",
                  "manual-20260528170549", "v0.21.9-rc1"):
            self.assertFalse(_GUI_TAG_RE.match(t), t)


class TestFetchLatestGuiRelease(unittest.TestCase):

    def _patch(self, page1):
        def fake_urlopen(req, timeout=0):
            url = req.full_url
            return _FakeResp(page1 if "page=1" in url else [])
        return mock.patch.object(gu, "urlopen", fake_urlopen)

    def test_picks_gui_over_binary(self):
        page1 = [
            {"tag_name": "singbox-bin-v1.14.0", "prerelease": False, "draft": False},
            {"tag_name": "manual-20260528170549", "prerelease": False, "draft": False},
            {"tag_name": "v0.21.9", "prerelease": False, "draft": False,
             "body": "n", "html_url": "u"},
            {"tag_name": "v0.21.8", "prerelease": False, "draft": False},
        ]
        with self._patch(page1):
            rel = GuiUpdater()._fetch_github_latest_release()
        self.assertEqual(rel["tag_name"], "v0.21.9")

    def test_skips_prerelease_and_draft(self):
        page1 = [
            {"tag_name": "v0.22.0", "prerelease": True, "draft": False},
            {"tag_name": "v0.21.9", "prerelease": False, "draft": True},
            {"tag_name": "v0.21.8", "prerelease": False, "draft": False},
        ]
        with self._patch(page1):
            rel = GuiUpdater()._fetch_github_latest_release()
        self.assertEqual(rel["tag_name"], "v0.21.8")

    def test_raises_when_no_gui_release(self):
        page1 = [{"tag_name": "singbox-bin-v1", "prerelease": False, "draft": False}]
        with self._patch(page1):
            with self.assertRaises(Exception):
                GuiUpdater()._fetch_github_latest_release()


class TestSelfUpdateAssetSync(unittest.TestCase):
    """
    Regression для issue #144: self-update должен копировать import/ и
    запускать asset_importer.import_runtime_assets() — иначе обновлённый
    core/ ссылается на lua-скрипты, которых нет в /opt/zapret2/lua/, и
    nfqws2 падает с «LUA ERROR: invalid failure detector function ...».
    """

    def test_import_dir_is_copied_on_update(self):
        """import/ обязан быть в dirs_to_update — иначе bundled lua/blob/
        lists не доедут до /opt/zapret2/, а триггеры в новом core/ их
        ожидают."""
        import inspect
        src = inspect.getsource(GuiUpdater._do_update)
        # ищем литерал списка dirs_to_update — там обязан быть "import"
        self.assertIn('"import"', src,
                      "self-update должен копировать import/ "
                      "(см. issue #144)")

    def test_asset_importer_called_after_copy(self):
        """После копирования файлов self-update должен вызвать
        asset_importer.import_runtime_assets() — без этого новые bundled
        lua/blob/lists не попадут в /opt/zapret2/."""
        import inspect
        src = inspect.getsource(GuiUpdater._do_update)
        self.assertIn("import_runtime_assets", src,
                      "self-update должен синхронизировать import/ "
                      "с /opt/zapret2/ через asset_importer "
                      "(см. issue #144)")


class TestGuiListReleases(unittest.TestCase):
    """Выбор версии GUI: list_releases() отбирает тэги vX.Y[.Z],
    отсеивая бинарные релизы и предрелизы, и пробрасывает транспорт."""

    def test_filters_gui_tags(self):
        page1 = [
            {"tag_name": "singbox-bin-v1.14.0", "prerelease": False,
             "draft": False},
            {"tag_name": "v0.22.1", "prerelease": False, "draft": False,
             "published_at": "2026-06-12T00:00:00Z", "body": "n"},
            {"tag_name": "v0.22.0", "prerelease": False, "draft": False},
            {"tag_name": "v0.21.9-rc1", "prerelease": True, "draft": False},
            {"tag_name": "v0.21.8", "prerelease": False, "draft": True},
        ]

        def fake(url, transport="", timeout=0):
            return page1 if "page=1" in url else []

        with mock.patch.object(gu, "_http_get_json", side_effect=fake):
            r = GuiUpdater().list_releases()
        self.assertTrue(r["ok"])
        self.assertEqual([x["tag"] for x in r["releases"]],
                         ["v0.22.1", "v0.22.0"])
        self.assertEqual(r["releases"][0]["version"], "0.22.1")

    def test_transport_passed_and_cache(self):
        with mock.patch.object(gu, "_http_get_json",
                               return_value=[]) as hj:
            up = GuiUpdater()
            up.list_releases(transport="mihomo:proxy")
            up.list_releases(transport="mihomo:proxy")        # из кэша
            up.list_releases(transport="mihomo:proxy", force=True)
        self.assertEqual(hj.call_count, 2)
        self.assertEqual(hj.call_args.kwargs.get("transport"), "mihomo:proxy")

    def test_network_error_raises(self):
        import urllib.error
        with mock.patch.object(gu, "_http_get_json",
                               side_effect=urllib.error.URLError("x")):
            with self.assertRaises(RuntimeError):
                GuiUpdater().list_releases()


class TestGuiUpdateRef(unittest.TestCase):
    """update(tag/branch/'') резолвится в правильный archive-URL,
    транспорт пробрасывается в загрузку (latest by default)."""

    def _run(self, resolved="v9.9.9", **kw):
        up = GuiUpdater()
        seen = {}

        def fake_dl(url, dest, transport=""):
            seen["url"] = url
            seen["transport"] = transport
            return False    # обрываем до распаковки

        with mock.patch.object(up, "_download_file", side_effect=fake_dl), \
             mock.patch.object(up, "_resolve_latest_tag",
                               return_value=resolved):
            up._do_update(**kw)
        return seen

    def test_explicit_tag(self):
        seen = self._run(tag="v1.2.3", transport="awg:wg0")
        self.assertIn("/archive/refs/tags/v1.2.3.tar.gz", seen["url"])
        self.assertEqual(seen["transport"], "awg:wg0")

    def test_explicit_branch(self):
        seen = self._run(branch="dev")
        self.assertIn("/archive/refs/heads/dev.tar.gz", seen["url"])

    def test_default_is_latest_release(self):
        seen = self._run()
        self.assertIn("/archive/refs/tags/v9.9.9.tar.gz", seen["url"])

    def test_default_falls_back_to_main(self):
        seen = self._run(resolved="")
        self.assertIn("/archive/refs/heads/main.tar.gz", seen["url"])


if __name__ == "__main__":
    unittest.main()
