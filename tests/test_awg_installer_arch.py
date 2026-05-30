# tests/test_awg_installer_arch.py
"""
Тесты arch-aware выбора релиза в awg_installer: пустой/битый ручной
релиз (manifest без бинарников под нашу арх) не должен выбираться как
«последний» и не должен вызывать фантомное обновление.
Регрессия: manual-релиз с пустым manifest → "нет бинарников для arch".
"""

import unittest
from unittest import mock

from core.awg_installer import AwgInstaller


def _manifest(tag, arch=None, go_ver="0.2.18", tools_ver="1.0"):
    bins = {arch: {"filename": "x.tar.gz", "url": "u", "sha256": "h"}} if arch else {}
    return {
        "tag": tag,
        "amneziawg_go": {"version": go_ver, "binaries": dict(bins)},
        "amneziawg_tools": {"version": tools_ver, "binaries": dict(bins)},
    }


class TestSupportsArch(unittest.TestCase):

    def setUp(self):
        self.inst = AwgInstaller()

    def test_supported(self):
        m = _manifest("t", arch="mipsel-softfloat")
        self.assertTrue(self.inst._manifest_supports_arch(m, "mipsel-softfloat"))

    def test_empty_binaries_unsupported(self):
        m = _manifest("t", arch=None)  # binaries = {}
        self.assertFalse(self.inst._manifest_supports_arch(m, "mipsel-softfloat"))

    def test_other_arch_unsupported(self):
        m = _manifest("t", arch="aarch64")
        self.assertFalse(self.inst._manifest_supports_arch(m, "mipsel-softfloat"))

    def test_no_arch_always_true(self):
        self.assertTrue(self.inst._manifest_supports_arch({}, ""))


class TestResolveBestRelease(unittest.TestCase):

    def setUp(self):
        self.inst = AwgInstaller()

    def test_skips_empty_newer_picks_supporting(self):
        # Новее (manual-528) — пустой; старее (manual-513) — с mipsel.
        tags = ["manual-20260528170549", "manual-20260513153446"]
        manifests = {
            "manual-20260528170549": _manifest("manual-20260528170549", arch=None),
            "manual-20260513153446": _manifest("manual-20260513153446",
                                                arch="mipsel-softfloat"),
        }
        with mock.patch.object(self.inst, "_list_candidate_tags",
                               return_value=tags), \
             mock.patch.object(self.inst, "_fetch_manifest",
                               side_effect=lambda repo, t: manifests[t]):
            tag, m = self.inst._resolve_best_release("r", "awg-bin-v",
                                                     "mipsel-softfloat")
        self.assertEqual(tag, "manual-20260513153446")
        self.assertTrue(self.inst._manifest_supports_arch(m, "mipsel-softfloat"))

    def test_falls_back_to_first_when_none_support(self):
        tags = ["manual-A", "manual-B"]
        manifests = {"manual-A": _manifest("manual-A", arch=None),
                     "manual-B": _manifest("manual-B", arch="aarch64")}
        with mock.patch.object(self.inst, "_list_candidate_tags",
                               return_value=tags), \
             mock.patch.object(self.inst, "_fetch_manifest",
                               side_effect=lambda repo, t: manifests[t]):
            tag, _m = self.inst._resolve_best_release("r", "p", "mipsel-softfloat")
        self.assertEqual(tag, "manual-A")  # первый кандидат для диагностики

    def test_no_candidates_raises(self):
        with mock.patch.object(self.inst, "_list_candidate_tags",
                               return_value=[]):
            with self.assertRaises(RuntimeError):
                self.inst._resolve_best_release("r", "p", "x")

    def test_skips_foreign_singbox_manifest(self):
        # issue #111: единственный manifest.json — sing-box (нет
        # amneziawg_*). AWG-установщик не должен его брать, а обязан
        # выдать понятную ошибку (а не «нет бинарников»/тянуть sing-box).
        tags = ["manual-singbox"]
        singbox_manifest = {"schema": 1, "tag": "manual-singbox",
                            "sing_box": {"version": "1.14", "binaries": {
                                "mipsel-softfloat": {"url": "u"}}}}
        with mock.patch.object(self.inst, "_list_candidate_tags",
                               return_value=tags), \
             mock.patch.object(self.inst, "_fetch_manifest",
                               side_effect=lambda repo, t: singbox_manifest):
            with self.assertRaises(RuntimeError) as cm:
                self.inst._resolve_best_release("r", "awg-bin-v",
                                                "mipsel-softfloat")
        self.assertIn("AmneziaWG", str(cm.exception))

    def test_prefers_awg_over_foreign(self):
        # Среди кандидатов и sing-box (новее), и AWG (старее, с нужной
        # арх) — берём AWG, sing-box пропускаем.
        tags = ["manual-singbox", "manual-awg"]
        manifests = {
            "manual-singbox": {"tag": "manual-singbox",
                               "sing_box": {"binaries": {"mipsel-softfloat": {}}}},
            "manual-awg": _manifest("manual-awg", arch="mipsel-softfloat"),
        }
        with mock.patch.object(self.inst, "_list_candidate_tags",
                               return_value=tags), \
             mock.patch.object(self.inst, "_fetch_manifest",
                               side_effect=lambda repo, t: manifests[t]):
            tag, _m = self.inst._resolve_best_release("r", "awg-bin-v",
                                                      "mipsel-softfloat")
        self.assertEqual(tag, "manual-awg")


class TestCheckForUpdatesArch(unittest.TestCase):

    def setUp(self):
        self.inst = AwgInstaller()

    def _installed(self, tag):
        return {"installed": True, "tag": tag, "go_version": "0.2.18",
                "tools_version": "1.0", "external": False}

    def test_no_phantom_update_when_latest_unsupported(self):
        # latest manifest без нашей арх → update_available=False.
        m = _manifest("manual-528", arch=None)
        with mock.patch.object(self.inst, "_detect_arch",
                               return_value="mipsel-softfloat"), \
             mock.patch.object(self.inst, "get_manifest", return_value=m), \
             mock.patch.object(self.inst, "get_installed_version",
                               return_value=self._installed("manual-513")):
            r = self.inst.check_for_updates()
        self.assertTrue(r["ok"])
        self.assertFalse(r["update_available"])
        self.assertFalse(r["arch_supported"])
        self.assertEqual(r["arch"], "mipsel-softfloat")

    def test_update_offered_when_supported_and_tag_differs(self):
        m = _manifest("manual-600", arch="mipsel-softfloat")
        with mock.patch.object(self.inst, "_detect_arch",
                               return_value="mipsel-softfloat"), \
             mock.patch.object(self.inst, "get_manifest", return_value=m), \
             mock.patch.object(self.inst, "get_installed_version",
                               return_value=self._installed("manual-513")):
            r = self.inst.check_for_updates()
        self.assertTrue(r["update_available"])
        self.assertTrue(r["arch_supported"])
        self.assertIn("mipsel-softfloat", r["available_archs"])


if __name__ == "__main__":
    unittest.main()
