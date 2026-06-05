# tests/test_singbox_subsystem.py
"""
Unit-тесты для core/singbox_platform.py, singbox_detector.py,
singbox_autostart.py, singbox_installer.py — pure-функции.
"""

import os
import unittest
from unittest import mock

from core.singbox_platform import (
    SingboxPlatform, KeeneticSingbox, OpenWrtSingbox,
    GenericLinuxSingbox, detect_singbox_platform,
)
from core import singbox_detector
from core import singbox_autostart
from core import singbox_installer


# ─────── platform ───────

class TestPlatformPaths(unittest.TestCase):

    def test_keenetic_paths(self):
        p = KeeneticSingbox()
        self.assertTrue(p.binary_dir.startswith("/opt"))
        self.assertTrue(p.config_dir.startswith("/opt"))
        self.assertTrue(p.run_dir.startswith("/opt"))
        # init-priority S52 — после AWG
        self.assertEqual(p.init_priority, "S52")
        self.assertEqual(p.binary_path(), "/opt/usr/sbin/sing-box")
        self.assertEqual(p.config_path("my"), "/opt/etc/sing-box/my.json")
        self.assertEqual(p.pid_path("my"),
                          "/opt/var/run/sing-box/singbox-my.pid")

    def test_openwrt_paths(self):
        p = OpenWrtSingbox()
        self.assertEqual(p.binary_path(), "/usr/sbin/sing-box")
        # procd: init-script без S<N> префикса
        self.assertEqual(p.init_priority, "")
        # init_script_path без префикса
        self.assertTrue(p.init_script_path().endswith("/sing-box-gui"))

    def test_linux_paths(self):
        p = GenericLinuxSingbox()
        self.assertEqual(p.binary_path(), "/usr/local/bin/sing-box")
        # systemd-unit: .service
        self.assertTrue(p.init_script_path().endswith(".service"))


class TestPlatformAsDict(unittest.TestCase):

    def test_kind_included(self):
        d = KeeneticSingbox().as_dict()
        self.assertEqual(d["kind"], "keenetic")
        d = OpenWrtSingbox().as_dict()
        self.assertEqual(d["kind"], "openwrt")
        d = GenericLinuxSingbox().as_dict()
        self.assertEqual(d["kind"], "linux")


# ─────── detector ───────

class TestSingboxDetectorProbeVersion(unittest.TestCase):

    def setUp(self):
        self.det = singbox_detector.SingboxDetector()

    def test_parses_modern_output(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value="sing-box version 1.10.5"):
            v = self.det._probe_version("/opt/sing-box")
        self.assertEqual(v, "1.10.5")

    def test_parses_short(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value="sing-box 1.9.0\nEnvironment: linux"):
            v = self.det._probe_version("/opt/sing-box")
        self.assertEqual(v, "1.9.0")

    def test_empty_returns_empty(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value=""):
            self.assertEqual(self.det._probe_version("/opt/x"), "")

    def test_garbage_returns_first_line(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value="unexpected output here"):
            v = self.det._probe_version("/opt/x")
            self.assertEqual(v, "unexpected output here")


class TestSingboxDetectorBuildTags(unittest.TestCase):
    """Парсинг строки `Tags:` и определение clash_api."""

    _MODERN = ("sing-box version 1.12.0\n"
               "Environment: go1.23 linux/amd64\n"
               "Tags: with_quic,with_grpc,with_utls,with_clash_api\n"
               "Revision: abcdef\nCGO: disabled")
    _NO_CLASH = ("sing-box version 1.12.0\n"
                 "Tags: with_quic,with_grpc,with_utls\n"
                 "CGO: disabled")
    _NO_TAGS = "sing-box version 1.12.0\nCGO: disabled"

    def setUp(self):
        self.det = singbox_detector.SingboxDetector()

    def test_clash_api_present(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value=self._MODERN):
            info = self.det._probe_version_info("/opt/sing-box")
        self.assertEqual(info["version"], "1.12.0")
        self.assertIn("with_clash_api", info["tags"])
        self.assertTrue(info["has_clash_api"])

    def test_clash_api_absent(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value=self._NO_CLASH):
            info = self.det._probe_version_info("/opt/sing-box")
        self.assertTrue(info["tags"])              # теги распарсились
        self.assertFalse(info["has_clash_api"])    # но clash_api нет

    def test_no_tags_line(self):
        with mock.patch.object(singbox_detector, "_cmd_out",
                                return_value=self._NO_TAGS):
            info = self.det._probe_version_info("/opt/sing-box")
        self.assertEqual(info["tags"], [])         # строки Tags нет
        self.assertFalse(info["has_clash_api"])

    def test_detect_binary_surfaces_capability(self):
        with mock.patch.object(self.det, "detect_platform") as dp, \
             mock.patch("os.path.isfile", return_value=True), \
             mock.patch("os.access", return_value=True), \
             mock.patch.object(singbox_detector, "_cmd_out",
                                return_value=self._MODERN):
            dp.return_value.binary_path.return_value = "/opt/sing-box"
            info = self.det.detect_binary()
        self.assertTrue(info["installed"])
        self.assertTrue(info["has_clash_api"])
        self.assertIn("with_clash_api", info["tags"])


class TestSingboxDetectTun(unittest.TestCase):

    def test_tun_present(self):
        det = singbox_detector.SingboxDetector()
        with mock.patch("os.path.exists", return_value=True):
            r = det.detect_tun()
            self.assertTrue(r["available"])

    def test_tun_absent(self):
        det = singbox_detector.SingboxDetector()
        with mock.patch("os.path.exists", return_value=False):
            r = det.detect_tun()
            self.assertFalse(r["available"])


# ─────── autostart ───────

class TestSingboxAutostartSettings(unittest.TestCase):

    def setUp(self):
        # Каждый тест с непустым settings (truthy — иначе _save_settings'
        # выражение `cfg or {}` создаёт новый dict и теряет наши правки).
        class FakeMgr:
            def __init__(self): self.data = {"version": 1}
            def load(self): return self.data
        self.fake = FakeMgr()
        self._p1 = mock.patch("core.config_manager.get_config_manager",
                               return_value=self.fake)
        # save_config — module-level alias может отсутствовать в
        # config_manager (singbox_autostart его ловит через ImportError).
        # Патчим с create=True, чтобы тест не падал.
        self._p2 = mock.patch("core.config_manager.save_config",
                               return_value=None, create=True)
        self._p1.start()
        self._p2.start()

    def tearDown(self):
        self._p1.stop()
        self._p2.stop()

    def test_empty_list(self):
        self.assertEqual(singbox_autostart.list_autostart(), {})

    def test_set_and_list(self):
        singbox_autostart.set_autostart("my-vpn", True)
        a = singbox_autostart.list_autostart()
        self.assertEqual(a, {"my-vpn": True})

    def test_unset_removes(self):
        singbox_autostart.set_autostart("my-vpn", True)
        singbox_autostart.set_autostart("my-vpn", False)
        self.assertEqual(singbox_autostart.list_autostart(), {})

    def test_multiple(self):
        singbox_autostart.set_autostart("a", True)
        singbox_autostart.set_autostart("b", True)
        a = singbox_autostart.list_autostart()
        self.assertEqual(set(a.keys()), {"a", "b"})

    def test_empty_name_rejected(self):
        r = singbox_autostart.set_autostart("", True)
        self.assertFalse(r["ok"])


# ─────── installer ───────

class TestInstallerArchDetect(unittest.TestCase):

    def test_falls_back_gracefully(self):
        # На не-Entware-системе arch может быть unknown — installer
        # не должен падать.
        installer = singbox_installer.SingboxInstaller()
        arch = installer._detect_arch()
        # Просто возвращает строку (может быть пустая).
        self.assertIsInstance(arch, str)


class TestInstallerProgress(unittest.TestCase):

    def test_initial_idle(self):
        i = singbox_installer.SingboxInstaller()
        s = i.get_operation_status()
        self.assertEqual(s["status"], "idle")
        self.assertEqual(s["progress"], 0)

    def test_set_progress_updates(self):
        i = singbox_installer.SingboxInstaller()
        i._set_progress("downloading", 42, "test")
        s = i.get_operation_status()
        self.assertEqual(s["status"], "downloading")
        self.assertEqual(s["progress"], 42)
        self.assertEqual(s["message"], "test")


class TestInstallerNeedsReinstall(unittest.TestCase):
    """check_for_updates флагует переустановку, если в бинаре нет clash_api."""

    def _check(self, bin_info, manifest_ver="1.12.0"):
        i = singbox_installer.SingboxInstaller()
        fake_det = mock.Mock()
        fake_det.detect_binary.return_value = bin_info
        with mock.patch.object(singbox_installer, "get_singbox_detector",
                               return_value=fake_det), \
             mock.patch.object(i, "get_manifest", return_value={
                 "tag": "singbox-bin-v%s" % manifest_ver,
                 "sing_box": {"version": manifest_ver}}):
            return i.check_for_updates()

    def test_flags_reinstall_when_clash_api_missing(self):
        r = self._check({"installed": True, "version": "1.12.0",
                         "tags": ["with_quic", "with_utls"],
                         "has_clash_api": False})
        self.assertTrue(r["needs_reinstall"])
        self.assertFalse(r["has_update"])          # та же upstream-версия
        self.assertIn("clash_api", r["reinstall_reason"])

    def test_no_reinstall_when_clash_api_present(self):
        r = self._check({"installed": True, "version": "1.12.0",
                         "tags": ["with_quic", "with_clash_api"],
                         "has_clash_api": True})
        self.assertFalse(r["needs_reinstall"])
        self.assertEqual(r["reinstall_reason"], "")

    def test_no_reinstall_when_tags_unknown(self):
        # Теги не распарсились — не дёргаем пользователя ложной тревогой.
        r = self._check({"installed": True, "version": "1.12.0",
                         "tags": [], "has_clash_api": False})
        self.assertFalse(r["needs_reinstall"])

    def test_no_reinstall_when_not_installed(self):
        r = self._check({"installed": False, "version": "",
                         "tags": [], "has_clash_api": False})
        self.assertFalse(r["needs_reinstall"])


if __name__ == "__main__":
    unittest.main()
