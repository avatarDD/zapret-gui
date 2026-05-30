# tests/test_singbox_installer_resolve.py
"""Тесты пагинации/фильтрации релизов в singbox_installer.

Регрессия: бинарный релиз (singbox-bin-* / manual-*) лежит за десятками
GUI-релизов (на 3-4-й странице) и одностраничный запрос его не видел.
"""

import unittest
from unittest import mock

from core.singbox_installer import SingboxInstaller


def _rel(tag, assets=None):
    return {"tag_name": tag, "assets": assets or []}


class TestResolveLatestTagPaginated(unittest.TestCase):

    def setUp(self):
        self.inst = SingboxInstaller()

    def test_finds_singbox_bin_on_later_page(self):
        # 100 GUI-релизов на стр.1, нужный singbox-bin-* — на стр.2.
        page1 = [_rel("v0.%d.0" % i) for i in range(100)]
        page2 = [_rel("v0.0.1"), _rel("singbox-bin-v1.14.0")]

        def fake_json(url, timeout=15):
            if url.endswith("page=1"):
                return page1
            if url.endswith("page=2"):
                return page2
            return []

        with mock.patch("core.singbox_installer._http_json",
                        side_effect=fake_json):
            self.assertEqual(self.inst._resolve_latest_tag(),
                             "singbox-bin-v1.14.0")

    def test_manual_fallback_validates_singbox_manifest(self):
        # Нет singbox-bin-*, есть два manual-*: один AWG, один sing-box.
        page1 = [_rel("manual-awg", [{"name": "manifest.json"}]),
                 _rel("manual-sb", [{"name": "manifest.json"}])]
        manifests = {
            "manual-awg": {"amneziawg_go": {"binaries": {}}},
            "manual-sb": {"sing_box": {"version": "1.14"}},
        }

        def fake_json(url, timeout=15):
            if "/releases?per_page" in url:
                return page1 if url.endswith("page=1") else []
            for tag, man in manifests.items():
                if "/download/%s/" % tag in url:
                    return man
            return {}

        with mock.patch("core.singbox_installer._http_json",
                        side_effect=fake_json):
            # должен пропустить AWG-манифест и взять sing-box
            self.assertEqual(self.inst._resolve_latest_tag(), "manual-sb")

    def test_raises_when_none(self):
        with mock.patch("core.singbox_installer._http_json",
                        side_effect=lambda url, timeout=15:
                        [_rel("v1.0.0")] if url.endswith("page=1") else []):
            with self.assertRaises(RuntimeError):
                self.inst._resolve_latest_tag()


if __name__ == "__main__":
    unittest.main()
