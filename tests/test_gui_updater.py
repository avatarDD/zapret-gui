# tests/test_gui_updater.py
"""
Регрессия: проверка обновлений GUI использовала /releases/latest, и
бинарные релизы (singbox-bin-*/awg-bin-*/manual-*, тоже non-prerelease)
перебивали свежий vX.Y.Z → новый релиз GUI «не виден». Теперь выбираем
новейший релиз с тэгом-семвером, игнорируя бинарные.
"""

import json
import os
import tempfile
import threading
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


class TestSelfUpdateCopiesTests(unittest.TestCase):
    """
    Regression: self-update должен копировать tests/, как это делает
    install.sh. Иначе после обновления через веб-интерфейс каталог
    tests/ исчезает, и самодиагностика рапортует «поставка без тестов»
    (хотя обновление прошло) — прогон юнит-тестов на устройстве молча
    пропадает.
    """

    def test_tests_dir_is_copied_on_update(self):
        """tests/ обязан быть в dirs_to_update — для самодиагностики,
        которая гоняет юнит-тесты прямо на устройстве."""
        import inspect
        src = inspect.getsource(GuiUpdater._do_update)
        self.assertIn('"tests"', src,
                      "self-update должен копировать tests/ "
                      "(паритет с install.sh)")


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


class TestGuiUpdateResultSurvives(unittest.TestCase):
    """
    Регрессия: «жму обновить — пишет, что идёт процесс, страница
    перезагружается, версия прежняя».

    Обновление длится дольше HTTP-запроса, поэтому его исход веб-клиент
    узнаёт опросом /api/gui/progress. Раньше результат жил только внутри
    обработчика POST и терялся — фронт по окончании операции рисовал
    успех независимо от того, что случилось. Теперь исход остаётся в
    get_operation_status()["last_result"].
    """

    def _failing_updater(self):
        up = GuiUpdater()
        up._download_file = lambda url, dest, transport="": False
        return up

    def test_failure_is_kept_in_last_result(self):
        up = self._failing_updater()
        res = up.update(tag="v9.9.9")
        self.assertFalse(res["ok"])

        st = up.get_operation_status()
        self.assertFalse(st["in_progress"])
        self.assertIsNotNone(st["last_result"])
        self.assertFalse(st["last_result"]["ok"])
        # Причина видна и в строке прогресса — не только в логе.
        self.assertIn("скачать", st["status"])

    def test_new_run_clears_previous_result(self):
        """Итог прошлого запуска не должен выдаваться за итог текущего."""
        up = self._failing_updater()
        up.update(tag="v9.9.9")
        self.assertIsNotNone(up.get_operation_status()["last_result"])

        seen = {}

        def slow_download(url, dest, transport=""):
            seen["last_result"] = up.get_operation_status()["last_result"]
            return False

        up._download_file = slow_download
        up.update(tag="v9.9.9")
        self.assertIsNone(seen["last_result"])

    def test_start_update_occupies_slot_synchronously(self):
        """start_update() возвращается уже с in_progress=True — иначе
        первый опрос прогресса примет «ещё не началось» за «уже всё»."""
        up = GuiUpdater()
        started = threading.Event()
        release = threading.Event()

        def blocking_download(url, dest, transport=""):
            started.set()
            release.wait(5)
            return False

        up._download_file = blocking_download
        try:
            r = up.start_update(tag="v9.9.9")
            self.assertTrue(r["in_progress"])
            st = up.get_operation_status()
            self.assertTrue(st["in_progress"])
            self.assertIsNone(st["last_result"])
            self.assertTrue(started.wait(5))
            # Пока идёт — второй запуск не стартует новую операцию.
            self.assertNotIn("started", up.start_update(tag="v9.9.9"))
        finally:
            release.set()


class TestGuiUpdateVerifiesInstalledVersion(unittest.TestCase):
    """
    Успех обязан подтверждаться диском: версия берётся из скачанного
    архива, а сверяется с core/version.py установленного каталога. Иначе
    обновление, не поменявшее ни файла, рапортует новую версию.
    """

    def _versions(self, app_dir, installed, src_dir, downloaded):
        return mock.patch.object(
            GuiUpdater, "_read_version_from_dir", autospec=True,
            side_effect=lambda _self, d: (installed if d == app_dir
                                          else downloaded))

    def test_stale_version_on_disk_is_failure(self):
        up, app_dir, src_dir = GuiUpdater(), "/app", "/src"
        with self._versions(app_dir, "0.24.13", src_dir, "0.24.15"):
            res = up._verify_installed(app_dir, src_dir)
        self.assertIsNotNone(res)
        self.assertFalse(res["ok"])
        self.assertIn("0.24.13", res["message"])
        self.assertIn("0.24.15", res["message"])

    def test_matching_version_passes(self):
        up, app_dir, src_dir = GuiUpdater(), "/app", "/src"
        with self._versions(app_dir, "0.24.15", src_dir, "0.24.15"):
            self.assertIsNone(up._verify_installed(app_dir, src_dir))


class TestGuiUpdateWorkDir(unittest.TestCase):
    """
    /tmp на Keenetic — tmpfs в RAM. Когда места не хватает, загрузка или
    распаковка обрывается на середине; проверяем место ДО сети и, если
    /tmp мал, уходим на раздел приложения.
    """

    def test_falls_back_to_app_partition(self):
        up = GuiUpdater()
        with tempfile.TemporaryDirectory() as parent:
            app_dir = os.path.join(parent, "zapret-gui")
            os.makedirs(app_dir)
            free = {"/tmp": 5}
            with mock.patch.object(gu.GuiUpdater, "_free_mb",
                                   staticmethod(lambda p: free.get(p, 900))):
                base, err = up._pick_work_base(app_dir)
            self.assertEqual(err, "")
            self.assertEqual(base, parent)

    def test_no_space_anywhere_is_reported_before_download(self):
        up = GuiUpdater()
        with mock.patch.object(gu.GuiUpdater, "_free_mb",
                               staticmethod(lambda p: 3)), \
             mock.patch.object(up, "_download_file") as dl:
            res = up._do_update(tag="v9.9.9")
        self.assertFalse(res["ok"])
        self.assertIn("места", res["message"])
        dl.assert_not_called()


class TestReplaceDirKeepsOldOnFailure(unittest.TestCase):
    """
    Каталог заменяется через <dir>.new + rename, а не «rmtree + copytree»:
    сорвавшееся обновление не должно оставлять GUI без core/ или web/.
    """

    def test_old_tree_survives_copy_error(self):
        with tempfile.TemporaryDirectory() as base:
            src = os.path.join(base, "src")
            dst = os.path.join(base, "dst")
            os.makedirs(src)
            os.makedirs(dst)
            with open(os.path.join(src, "f.txt"), "w") as f:
                f.write("new")
            with open(os.path.join(dst, "f.txt"), "w") as f:
                f.write("old")

            with mock.patch.object(gu.shutil, "copytree",
                                   side_effect=OSError(28, "No space")):
                with self.assertRaises(OSError):
                    GuiUpdater._replace_dir(src, dst)

            with open(os.path.join(dst, "f.txt")) as f:
                self.assertEqual(f.read(), "old")

    def test_swap_replaces_content(self):
        with tempfile.TemporaryDirectory() as base:
            src = os.path.join(base, "src")
            dst = os.path.join(base, "dst")
            os.makedirs(src)
            os.makedirs(dst)
            with open(os.path.join(src, "new.txt"), "w") as f:
                f.write("new")
            with open(os.path.join(dst, "gone.txt"), "w") as f:
                f.write("old")

            GuiUpdater._replace_dir(src, dst)

            self.assertEqual(sorted(os.listdir(dst)), ["new.txt"])
            self.assertEqual(sorted(os.listdir(base)), ["dst", "src"])


if __name__ == "__main__":
    unittest.main()
