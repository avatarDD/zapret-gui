# tests/test_installer_releases.py
"""
Тесты задачи №8 (установка произвольной версии + локальный файл):
  - list_releases() у трёх установщиков (awg / sing-box / mihomo);
  - prepare_local_binary() (tar.gz / .gz / голый ELF / мусор);
  - install_local() у трёх установщиков.
"""

import gzip
import io
import os
import tarfile
import tempfile
import unittest
from unittest import mock

from core import binary_installer as bi


# Минимальный «ELF»: важна только сигнатура.
FAKE_ELF = b"\x7fELF" + b"\x00" * 60 + b"fake-binary-body"


def _make_tar_gz(path, members):
    """members: {имя_в_архиве: bytes}"""
    with tarfile.open(path, "w:gz") as tf:
        for name, body in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))


def _make_gz(path, body):
    with gzip.open(path, "wb") as f:
        f.write(body)


# ─────────────────── prepare_local_binary ────────────────────────


class TestPrepareLocalBinary(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _work(self):
        w = os.path.join(self.tmp, "work")
        os.makedirs(w, exist_ok=True)
        return w

    def test_raw_elf(self):
        src = os.path.join(self.tmp, "mihomo-noext")
        with open(src, "wb") as f:
            f.write(FAKE_ELF)
        r = bi.prepare_local_binary(src, "mihomo", self._work())
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["format"], "elf")
        with open(r["path"], "rb") as f:
            self.assertEqual(f.read(), FAKE_ELF)

    def test_single_gz(self):
        src = os.path.join(self.tmp, "mihomo-linux-arm64-v1.19.gz")
        _make_gz(src, FAKE_ELF)
        r = bi.prepare_local_binary(src, "mihomo", self._work())
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["format"], "gz")
        with open(r["path"], "rb") as f:
            self.assertEqual(f.read(), FAKE_ELF)

    def test_tar_gz_with_expected_name(self):
        src = os.path.join(self.tmp, "sing-box.tar.gz")
        _make_tar_gz(src, {"sing-box-1.11/sing-box": FAKE_ELF,
                           "sing-box-1.11/LICENSE": b"MIT"})
        r = bi.prepare_local_binary(src, "sing-box", self._work())
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["format"], "tar.gz")

    def test_tar_gz_single_file_any_name(self):
        # Один-единственный файл в архиве берём, даже если имя другое.
        src = os.path.join(self.tmp, "x.tgz")
        _make_tar_gz(src, {"renamed-binary": FAKE_ELF})
        r = bi.prepare_local_binary(src, "sing-box", self._work())
        self.assertTrue(r["ok"], r)

    def test_tar_gz_ambiguous_fails(self):
        src = os.path.join(self.tmp, "x.tar.gz")
        _make_tar_gz(src, {"one": FAKE_ELF, "two": FAKE_ELF})
        r = bi.prepare_local_binary(src, "sing-box", self._work())
        self.assertFalse(r["ok"])
        self.assertIn("sing-box", r["error"])

    def test_garbage_rejected(self):
        src = os.path.join(self.tmp, "garbage.bin")
        with open(src, "wb") as f:
            f.write(b"PK\x03\x04 definitely-not-elf")
        r = bi.prepare_local_binary(src, "mihomo", self._work())
        self.assertFalse(r["ok"])

    def test_gz_of_non_elf_rejected(self):
        src = os.path.join(self.tmp, "text.gz")
        _make_gz(src, b"#!/bin/sh\necho hi\n")
        r = bi.prepare_local_binary(src, "mihomo", self._work())
        self.assertFalse(r["ok"])
        self.assertIn("ELF", r["error"])

    def test_missing_file(self):
        r = bi.prepare_local_binary(os.path.join(self.tmp, "nope"),
                                    "mihomo", self._work())
        self.assertFalse(r["ok"])


# ─────────────────── list_releases ───────────────────────────────


class TestMihomoListReleases(unittest.TestCase):

    def _make(self):
        from core.mihomo_installer import MihomoInstaller
        return MihomoInstaller()

    def test_list_and_cache(self):
        inst = self._make()
        data = [
            {"tag_name": "v1.19.2", "draft": False, "prerelease": False,
             "published_at": "2025-05-01T00:00:00Z"},
            {"tag_name": "Prerelease-Alpha", "draft": False,
             "prerelease": True, "published_at": "2025-05-02T00:00:00Z"},
            {"tag_name": "v1.19.1", "draft": True},   # драфт — мимо
            {"no_tag": True},
        ]
        with mock.patch("core.mihomo_installer._http_json",
                        return_value=data) as hj:
            r1 = inst.list_releases()
            r2 = inst.list_releases()              # из кэша
        self.assertTrue(r1["ok"])
        tags = [x["tag"] for x in r1["releases"]]
        self.assertEqual(tags, ["v1.19.2", "Prerelease-Alpha"])
        self.assertEqual(r1["releases"][0]["version"], "1.19.2")
        self.assertTrue(r1["releases"][1]["prerelease"])
        self.assertIs(r1, r2)
        hj.assert_called_once()

    def test_force_refetches_and_transport_passed(self):
        inst = self._make()
        with mock.patch("core.mihomo_installer._http_json",
                        return_value=[]) as hj:
            inst.list_releases(transport="awg:wg0")
            inst.list_releases(transport="awg:wg0", force=True)
        self.assertEqual(hj.call_count, 2)
        self.assertEqual(hj.call_args.kwargs.get("transport"), "awg:wg0")

    def test_network_error_raises(self):
        import urllib.error
        inst = self._make()
        with mock.patch("core.mihomo_installer._http_json",
                        side_effect=urllib.error.URLError("down")):
            with self.assertRaises(RuntimeError):
                inst.list_releases()


class TestSingboxListReleases(unittest.TestCase):

    def test_filters_singbox_bin_tags(self):
        from core.singbox_installer import SingboxInstaller
        inst = SingboxInstaller()
        data = [
            {"tag_name": "v0.9.0"},                       # GUI-релиз — мимо
            {"tag_name": "singbox-bin-v1.12.4",
             "published_at": "2025-06-01T00:00:00Z"},
            {"tag_name": "manual-20250101010101"},        # manual — мимо
            {"tag_name": "awg-bin-go-0.2-tools-1.0"},     # чужой — мимо
            {"tag_name": "singbox-bin-v1.11.3", "draft": True},
            {"tag_name": "singbox-bin-v1.11.0"},
        ]
        with mock.patch.object(inst, "_list_all_releases",
                               return_value=data):
            r = inst.list_releases()
        self.assertTrue(r["ok"])
        self.assertEqual([x["tag"] for x in r["releases"]],
                         ["singbox-bin-v1.12.4", "singbox-bin-v1.11.0"])
        self.assertEqual(r["releases"][0]["version"], "1.12.4")

    def test_cache(self):
        from core.singbox_installer import SingboxInstaller
        inst = SingboxInstaller()
        with mock.patch.object(inst, "_list_all_releases",
                               return_value=[]) as la:
            inst.list_releases()
            inst.list_releases()
            inst.list_releases(force=True)
        self.assertEqual(la.call_count, 2)


class TestAwgListReleases(unittest.TestCase):

    SETTINGS = {
        "repo": "avatardd/zapret-gui", "tag_prefix": "awg-bin-",
        "installed_tag": "", "installed_go": "", "installed_tools": "",
        "installed_dir": "",
    }

    def test_filters_and_parses_versions(self):
        from core.awg_installer import AwgInstaller
        inst = AwgInstaller()
        man = [{"name": "manifest.json"}]
        data = [
            {"tag_name": "v0.9.0", "assets": man},          # без префикса
            {"tag_name": "awg-bin-go-0.2.18-tools-1.0.20241018",
             "assets": man, "published_at": "2025-04-01T00:00:00Z"},
            {"tag_name": "awg-bin-go-0.2.16-tools-1.0.20241018",
             "assets": []},                                  # без manifest
            {"tag_name": "manual-x", "assets": man},         # manual — мимо
            {"tag_name": "awg-bin-go-0.2.15-tools-1.0.20240713",
             "assets": man},
        ]
        with mock.patch.object(inst, "_settings",
                               return_value=dict(self.SETTINGS)), \
             mock.patch.object(inst, "_list_all_releases",
                               return_value=data):
            r = inst.list_releases()
        self.assertTrue(r["ok"])
        tags = [x["tag"] for x in r["releases"]]
        self.assertEqual(tags, ["awg-bin-go-0.2.18-tools-1.0.20241018",
                                "awg-bin-go-0.2.15-tools-1.0.20240713"])
        self.assertEqual(r["releases"][0]["go_version"], "0.2.18")
        self.assertEqual(r["releases"][0]["tools_version"], "1.0.20241018")

    def test_empty_raises(self):
        from core.awg_installer import AwgInstaller
        inst = AwgInstaller()
        with mock.patch.object(inst, "_settings",
                               return_value=dict(self.SETTINGS)), \
             mock.patch.object(inst, "_list_all_releases",
                               return_value=[]):
            with self.assertRaises(RuntimeError):
                inst.list_releases()


# ─────────────────── install_local ───────────────────────────────


class _FakePlatform:
    def __init__(self, binary):
        self._binary = binary
        self.binary_dir = os.path.dirname(binary)

    def binary_path(self, name=None):
        return self._binary


class TestMihomoInstallLocal(unittest.TestCase):

    def test_install_from_gz(self):
        from core import mihomo_installer as mi
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "mihomo-linux-arm64-v1.19.gz")
            _make_gz(src, FAKE_ELF)
            target = os.path.join(d, "bin", "mihomo")

            det = mock.Mock()
            det.detect_binary.return_value = {"version": "1.19.0"}
            with mock.patch.object(mi, "detect_mihomo_platform",
                                   return_value=_FakePlatform(target)), \
                 mock.patch.object(mi, "get_mihomo_detector",
                                   return_value=det), \
                 mock.patch.object(mi, "_save_state") as save:
                inst = mi.MihomoInstaller()
                r = inst.install_local(src, orig_name="mihomo.gz")

            self.assertTrue(r["ok"], r)
            self.assertEqual(r["version"], "1.19.0")
            self.assertEqual(r["warning"], "")
            self.assertTrue(os.path.isfile(target))
            self.assertTrue(os.access(target, os.X_OK))
            save.assert_called_once_with(tag="local", version="1.19.0",
                                         path=target)
            self.assertEqual(inst.get_operation_status()["status"], "done")

    def test_garbage_fails_without_touching_target(self):
        from core import mihomo_installer as mi
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "garbage")
            with open(src, "wb") as f:
                f.write(b"not an elf at all")
            target = os.path.join(d, "bin", "mihomo")
            with mock.patch.object(mi, "detect_mihomo_platform",
                                   return_value=_FakePlatform(target)), \
                 mock.patch.object(mi, "get_mihomo_detector",
                                   return_value=mock.Mock()):
                r = mi.MihomoInstaller().install_local(src)
            self.assertFalse(r["ok"])
            self.assertFalse(os.path.exists(target))

    def test_unknown_version_warns(self):
        from core import mihomo_installer as mi
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "raw-elf")
            with open(src, "wb") as f:
                f.write(FAKE_ELF)
            target = os.path.join(d, "bin", "mihomo")
            det = mock.Mock()
            det.detect_binary.return_value = {"version": ""}
            with mock.patch.object(mi, "detect_mihomo_platform",
                                   return_value=_FakePlatform(target)), \
                 mock.patch.object(mi, "get_mihomo_detector",
                                   return_value=det), \
                 mock.patch.object(mi, "_save_state"):
                r = mi.MihomoInstaller().install_local(src)
            self.assertTrue(r["ok"], r)
            self.assertIn("архитектура", r["warning"])


class TestSingboxInstallLocal(unittest.TestCase):

    def test_install_from_tar_gz(self):
        from core import singbox_installer as si
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "sing-box.tar.gz")
            _make_tar_gz(src, {"sing-box-1.12/sing-box": FAKE_ELF})
            target = os.path.join(d, "bin", "sing-box")

            det = mock.Mock()
            det.detect_binary.return_value = {"version": "1.12.4"}
            with mock.patch("core.singbox_platform.detect_singbox_platform",
                            return_value=_FakePlatform(target)), \
                 mock.patch.object(si, "get_singbox_detector",
                                   return_value=det), \
                 mock.patch.object(si, "_save_state") as save:
                r = si.SingboxInstaller().install_local(src)

            self.assertTrue(r["ok"], r)
            self.assertEqual(r["version"], "1.12.4")
            self.assertTrue(os.path.isfile(target))
            save.assert_called_once_with(tag="local", version="1.12.4",
                                         path=target)


class TestAwgInstallLocal(unittest.TestCase):

    SETTINGS = TestAwgListReleases.SETTINGS

    def _detector(self, binary_dir):
        det = mock.Mock()
        det.detect_platform.return_value = mock.Mock(binary_dir=binary_dir)
        det.detect_existing_awg.return_value = {}
        det.detect_architecture.return_value = {"artifact_arch": "aarch64"}
        return det

    def test_install_both_from_tar_gz(self):
        from core import awg_installer as ai
        with tempfile.TemporaryDirectory() as d:
            go_src = os.path.join(d, "amneziawg-go.tar.gz")
            _make_tar_gz(go_src, {"amneziawg-go": FAKE_ELF})
            tools_src = os.path.join(d, "tools.tar.gz")
            _make_tar_gz(tools_src, {"bin/awg": FAKE_ELF})
            bin_dir = os.path.join(d, "bin")

            inst = ai.AwgInstaller()
            with mock.patch.object(ai, "get_awg_detector",
                                   return_value=self._detector(bin_dir)), \
                 mock.patch.object(inst, "_settings",
                                   return_value=dict(self.SETTINGS)), \
                 mock.patch.object(inst, "_save_installed") as save, \
                 mock.patch.object(ai, "_detect_binary_version",
                                   return_value="0.2.18"):
                r = inst.install_local(go_path=go_src, tools_path=tools_src)

            self.assertTrue(r["ok"], r)
            self.assertEqual(sorted(r["installed"]),
                             ["amneziawg-go", "awg"])
            self.assertTrue(os.path.isfile(os.path.join(bin_dir,
                                                        "amneziawg-go")))
            self.assertTrue(os.path.isfile(os.path.join(bin_dir, "awg")))
            save.assert_called_once()
            self.assertEqual(save.call_args.kwargs["tag"], "local")

    def test_only_go_is_ok(self):
        from core import awg_installer as ai
        with tempfile.TemporaryDirectory() as d:
            go_src = os.path.join(d, "go.bin")
            with open(go_src, "wb") as f:
                f.write(FAKE_ELF)
            bin_dir = os.path.join(d, "bin")
            inst = ai.AwgInstaller()
            with mock.patch.object(ai, "get_awg_detector",
                                   return_value=self._detector(bin_dir)), \
                 mock.patch.object(inst, "_settings",
                                   return_value=dict(self.SETTINGS)), \
                 mock.patch.object(inst, "_save_installed"), \
                 mock.patch.object(ai, "_detect_binary_version",
                                   return_value=""):
                r = inst.install_local(go_path=go_src)
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["installed"], ["amneziawg-go"])
            self.assertFalse(os.path.exists(os.path.join(bin_dir, "awg")))
            self.assertIn("архитектура", r["warning"])

    def test_no_files_is_error(self):
        from core import awg_installer as ai
        r = ai.AwgInstaller().install_local()
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
