# tests/test_update_checker_geneva.py
"""Строка geneva_c на странице «Обновления».

«Последняя» — закреплённый релиз из BINARIES['geneva']: его ставит кнопка
и для него сверены sha256. Сборка не из релиза (версия — хэш коммита)
обновлением не считается: «3477eee» начинается с цифр и наивное сравнение
приняло бы его за версию 3477.
"""

import unittest
from unittest import mock

from core import update_checker as uc


class FakeGeneva:
    def __init__(self, det):
        self.det = det

    def detect(self):
        return self.det


class TestReleaseInfo(unittest.TestCase):

    def test_pinned_release(self):
        info = uc.geneva_release_info("")
        self.assertEqual(info["tag"], "v1.2.0")
        self.assertEqual(info["latest"], "1.2.0")
        self.assertFalse(info["has_update"])

    def test_older_release_has_update(self):
        info = uc.geneva_release_info("0.9.1")
        self.assertTrue(info["release_build"])
        self.assertTrue(info["has_update"])

    def test_same_or_newer_release(self):
        self.assertTrue(uc.geneva_release_info("1.1.1")["has_update"])
        self.assertFalse(uc.geneva_release_info("1.2.0")["has_update"])
        self.assertFalse(uc.geneva_release_info("v1.2.0")["has_update"])
        self.assertFalse(uc.geneva_release_info("1.3.0")["has_update"])

    def test_commit_hash_is_not_a_version(self):
        info = uc.geneva_release_info("3477eee")
        self.assertFalse(info["release_build"])
        self.assertFalse(info["has_update"])


class TestCheckRow(unittest.TestCase):

    def _row(self, det, upstream="v1.1.0"):
        with mock.patch("core.geneva_manager.get_geneva_manager",
                        return_value=FakeGeneva(det)), \
                mock.patch.object(uc, "_github_latest",
                                  return_value=upstream):
            return uc._check_geneva()

    def test_not_installed(self):
        row = self._row({"installed": False, "version": "", "binary": ""})
        self.assertEqual(row["name"], "geneva")
        self.assertFalse(row["installed"])
        self.assertEqual(row["latest"], "1.2.0")
        self.assertTrue(row["pinned"])
        self.assertEqual(row["upstream_latest"], "v1.1.0")
        self.assertFalse(row["upstream_newer"])

    def test_upstream_ahead_of_pin_is_reported(self):
        row = self._row({"installed": True, "version": "1.2.0",
                         "binary": "/opt/usr/bin/geneva", "proto_ok": True},
                        upstream="v1.3.0")
        self.assertFalse(row["has_update"])     # кнопка 1.3.0 не поставит
        self.assertTrue(row["upstream_newer"])

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

    def test_assets_follow_pinned_version(self):
        from core.ext_binary_installer import BINARIES
        cfg = BINARIES["geneva"]
        ver = cfg["release_tag"].lstrip("v")
        self.assertEqual(cfg["release_tag"], cfg["pinned_tag"])
        for arch, name in cfg["arch_map"].items():
            self.assertEqual(name, "geneva-%s-linux-%s.tar.gz" % (ver, arch))
            self.assertRegex(cfg["sha256_map"][arch], r"^[0-9a-f]{64}$")
        self.assertEqual(set(cfg["arch_map"]), set(cfg["sha256_map"]))

    def test_listed_in_check_all_and_refresh(self):
        self.assertIn("geneva", uc._CHECKERS)


if __name__ == "__main__":
    unittest.main()
