# tests/test_update_checker_geneva.py
"""Строка geneva_c на странице «Обновления».

Политика (discussion #102, ноябрь 2026): geneva_c ставится свежим
релизом апстрима — «последняя» это апстримный тег через TTL-кеш, а не
закреплённый в манифесте. Сборка не из релиза (версия — хэш коммита)
обновлением не считается: «3477eee» начинается с цифр и наивное
сравнение приняло бы его за версию 3477.
"""

import unittest
from unittest import mock

from core import update_checker as uc
from core import ext_binary_installer as ebi


class FakeGeneva:
    def __init__(self, det):
        self.det = det

    def detect(self):
        return self.det


def _reset_geneva_cache():
    """TTL-кеш апстрима живёт в модуле — сбрасываем между тестами."""
    uc._geneva_upstream["ts"] = 0.0
    uc._geneva_upstream["tag"] = ""


class TestGenevaUpstreamLatest(unittest.TestCase):
    """geneva_upstream_latest: живой запрос не чаще раза в TTL."""

    def setUp(self):
        _reset_geneva_cache()

    def test_fetches_once_per_ttl(self):
        with mock.patch.object(uc, "_github_latest",
                               return_value="2.0.2") as gh:
            self.assertEqual(uc.geneva_upstream_latest(), "2.0.2")
            self.assertEqual(uc.geneva_upstream_latest(), "2.0.2")
            self.assertEqual(gh.call_count, 1)
        # после истечения TTL — снова живой запрос
        uc._geneva_upstream["ts"] -= uc._GENEVA_UPSTREAM_TTL + 1.0
        with mock.patch.object(uc, "_github_latest",
                               return_value="2.0.3") as gh:
            self.assertEqual(uc.geneva_upstream_latest(), "2.0.3")
            self.assertEqual(gh.call_count, 1)


class TestReleaseInfo(unittest.TestCase):

    def setUp(self):
        _reset_geneva_cache()

    def test_latest_follows_upstream(self):
        with mock.patch.object(uc, "geneva_upstream_latest",
                               return_value="2.0.2"):
            info = uc.geneva_release_info("")
        self.assertEqual(info["latest"], "2.0.2")
        self.assertEqual(info["tag"], "v2.0.2")
        self.assertFalse(info["has_update"])

    def test_upstream_unknown_falls_back_to_pin(self):
        # Апстрим ни разу не ответил — показываем проверенную версию из
        # манифеста: она заведомо ставится и не новее установленной.
        with mock.patch.object(uc, "geneva_upstream_latest",
                               return_value=""):
            info = uc.geneva_release_info("")
        self.assertEqual(info["latest"], ebi.GENEVA_VERSION)
        self.assertEqual(info["tag"], "v" + ebi.GENEVA_VERSION)

    def test_older_release_has_update(self):
        with mock.patch.object(uc, "geneva_upstream_latest",
                               return_value="2.0.2"):
            info = uc.geneva_release_info("0.9.1")
        self.assertTrue(info["release_build"])
        self.assertTrue(info["has_update"])

    def test_same_or_newer_release(self):
        with mock.patch.object(uc, "geneva_upstream_latest",
                               return_value="2.0.2"):
            self.assertTrue(uc.geneva_release_info("2.0.1")["has_update"])
            self.assertFalse(uc.geneva_release_info("2.0.2")["has_update"])
            self.assertFalse(
                uc.geneva_release_info("v2.0.2")["has_update"])
            self.assertFalse(uc.geneva_release_info("2.1.0")["has_update"])

    def test_commit_hash_is_not_a_version(self):
        with mock.patch.object(uc, "geneva_upstream_latest",
                               return_value="2.0.2"):
            info = uc.geneva_release_info("3477eee")
        self.assertFalse(info["release_build"])
        self.assertFalse(info["has_update"])


class TestCheckRow(unittest.TestCase):

    def setUp(self):
        _reset_geneva_cache()

    def _row(self, det, upstream="2.0.2"):
        # _github_latest по контракту возвращает тег уже без ведущего «v»
        with mock.patch("core.geneva_manager.get_geneva_manager",
                        return_value=FakeGeneva(det)), \
                mock.patch.object(uc, "_github_latest",
                                  return_value=upstream):
            return uc._check_geneva()

    def test_not_installed(self):
        row = self._row({"installed": False, "version": "", "binary": ""})
        self.assertEqual(row["name"], "geneva")
        self.assertFalse(row["installed"])
        self.assertEqual(row["latest"], "2.0.2")
        # Строка обычная: geneva больше не «закреплённый» движок.
        self.assertNotIn("pinned", row)
        self.assertNotIn("upstream_newer", row)
        self.assertNotIn("pin_reason", row)

    def test_upstream_ahead_of_installed_lights_update(self):
        # Ровно жалоба из discussion #102: апстрим ушёл вперёд — кнопка
        # обязана предлагать обновление, а не прятать его за «новая
        # придёт с обновлением GUI».
        row = self._row({"installed": True, "version": "2.0.1",
                         "binary": "/opt/usr/bin/geneva", "proto_ok": True},
                        upstream="2.0.2")
        self.assertTrue(row["has_update"])
        self.assertEqual(row["latest"], "2.0.2")

    def test_old_release_installed(self):
        row = self._row({"installed": True, "version": "0.9.0",
                         "binary": "/opt/usr/bin/geneva", "proto_ok": True})
        self.assertTrue(row["has_update"])
        self.assertEqual(row["path"], "/opt/usr/bin/geneva")

    def test_dev_build_gets_note(self):
        row = self._row({"installed": True, "version": "3477eee",
                         "binary": "/x/geneva", "proto_ok": True})
        self.assertFalse(row["has_update"])
        self.assertIn("не из релиза", row["note"])

    def test_binaries_entry_follows_latest_release(self):
        cfg = ebi.BINARIES["geneva"]
        # Политика: ставится ПОСЛЕДНИЙ релиз апстрима; пин — «проверенный
        # пол» с ручными хэшами и запасная «последняя» офлайн.
        self.assertEqual(cfg["release_tag"], "")
        self.assertEqual(cfg["pinned_tag"], "v" + ebi.GENEVA_VERSION)
        self.assertTrue(cfg["allow_unpinned"])
        tmpl = cfg["asset_template"]
        for arch, name in cfg["arch_map"].items():
            # arch_map — имена под пин; шаблон рендерит их же, но и для
            # любого иного тега релиза
            self.assertEqual(
                name, tmpl.format(version=ebi.GENEVA_VERSION, arch=arch))
            self.assertRegex(cfg["sha256_map"][arch], r"^[0-9a-f]{64}$")
        self.assertEqual(set(cfg["arch_map"]), set(cfg["sha256_map"]))

    def test_listed_in_check_all_and_refresh(self):
        self.assertIn("geneva", uc._CHECKERS)


if __name__ == "__main__":
    unittest.main()
