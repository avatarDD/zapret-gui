# tests/test_ext_binary_installer.py
"""Unit-тесты для core/ext_binary_installer.py."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import ext_binary_installer as ebi


class TestDetectArch(unittest.TestCase):
    """Тесты определения архитектуры."""

    @mock.patch("subprocess.run")
    def test_aarch64(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="aarch64\n")
        self.assertEqual(ebi.detect_arch(), "aarch64")

    @mock.patch("subprocess.run")
    def test_x86_64(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="x86_64\n")
        self.assertEqual(ebi.detect_arch(), "x86_64")

    @mock.patch("subprocess.run")
    def test_mipsel(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="mipsel\n")
        self.assertEqual(ebi.detect_arch(), "mipsel")

    @mock.patch("subprocess.run")
    def test_armv7(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="armv7l\n")
        self.assertEqual(ebi.detect_arch(), "armv7")


class TestBinaries(unittest.TestCase):
    """Тесты конфигурации бинарников."""

    def test_all_binaries_have_required_fields(self):
        for name, cfg in ebi.BINARIES.items():
            self.assertIn("repo", cfg, "Missing repo for %s" % name)
            self.assertIn("dest", cfg, "Missing dest for %s" % name)
            self.assertIn("arch_map", cfg, "Missing arch_map for %s" % name)

    def test_all_destinations_absolute(self):
        for name, cfg in ebi.BINARIES.items():
            self.assertTrue(cfg["dest"].startswith("/"),
                            "dest must be absolute for %s" % name)

    def test_usque_has_mipsel(self):
        self.assertIn("mipsel", ebi.BINARIES["usque"]["arch_map"])

    def test_tgwsproxy_package_config(self):
        self.assertIn("tgwsproxy", ebi.BINARIES)
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(cfg.get("install_kind"), "package")
        self.assertEqual(cfg.get("package_name"), "tg-ws-proxy")

    def test_tgwsproxy_pinned_to_last_router_release(self):
        """Тег закреплён на 0.9.3 — последнем релизе с пакетами для роутера.

        Раньше здесь стоял пустой release_tag («ставить последний релиз»), и
        это было верно, пока апстрим оставался роутерным демоном на Go. В
        v1.0.0 spatiumstas/tg-ws-proxy-go переписан на Python и стал
        десктопным GUI-приложением: .ipk/.apk в релизах больше нет, только
        сборки PyInstaller. С пустым тегом установка уходила в
        /releases/latest и падала на 404.
        """
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(cfg.get("release_tag", ""), "0.9.3")
        self.assertEqual(cfg.get("release_tag"), cfg.get("pinned_tag"),
                         "sha256 в манифесте относятся к pinned_tag — теги "
                         "обязаны совпадать")
        self.assertTrue(cfg.get("allow_unpinned"))
        self.assertTrue(cfg.get("pinned_tag"))
        self.assertIn("opkg:aarch64", cfg.get("sha256_map", {}))
        self.assertIn("apk:aarch64", cfg.get("sha256_map", {}))
        # У known-good версии хэш должен быть для каждой архитектуры,
        # которую мы вообще предлагаем ставить.
        for mgr, arches in cfg["package_assets"].items():
            for arch in arches:
                self.assertEqual(
                    len(cfg["sha256_map"]["%s:%s" % (mgr, arch)]), 64,
                    "%s:%s" % (mgr, arch))

    def test_tgwsproxy_asset_selection_for_package_manager(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        pinned = cfg["pinned_tag"]
        self.assertEqual(
            ebi._resolve_asset_name(cfg, "aarch64", "opkg"),
            "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk" % pinned,
        )
        self.assertEqual(
            ebi._resolve_asset_name(cfg, "aarch64", "apk"),
            "tg-ws-proxy_%s-r1_openwrt_aarch64_generic.apk" % pinned,
        )

    def test_tgwsproxy_asset_suffixes_cover_every_arch(self):
        """Имя ассета версионировано, поэтому для «последнего релиза»
        нужен версионно-независимый хвост под каждую архитектуру."""
        cfg = ebi.BINARIES["tgwsproxy"]
        for mgr, arches in cfg["package_assets"].items():
            for arch, name in arches.items():
                suffix = ebi._asset_suffix_for(cfg, arch, mgr)
                self.assertTrue(suffix, "%s:%s" % (mgr, arch))
                self.assertTrue(name.endswith(suffix), name)

    def test_tgwsproxy_asset_suffixes_are_unambiguous(self):
        """mips/mipsel не должны матчить ассет друг друга.

        Ключи-синонимы (`aarch64` = семейный алиас таргета
        `aarch64_generic`) ведут на ОДИН ассет — их сравнивать не с чем.
        """
        cfg = ebi.BINARIES["tgwsproxy"]
        for mgr, arches in cfg["package_assets"].items():
            for arch, name in arches.items():
                for other_arch, other_name in arches.items():
                    if other_arch == arch or other_name == name:
                        continue
                    other = ebi._asset_suffix_for(cfg, other_arch, mgr)
                    self.assertFalse(name.endswith(other),
                                     "%s матчится суффиксом %s" % (name, other))

    def test_expected_sha256_for_package_manager(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(
            ebi._expected_sha256(cfg, "aarch64", "opkg"),
            "8ab049572108028a57dccab166102fee248f5e8ba486d8d8d1fdd9bdb4941a53",
        )
        self.assertEqual(
            ebi._expected_sha256(cfg, "aarch64", "apk"),
            "e205d4ad04364bda82f2991deabf94ebca2c8355018cd620980461a01a3da003",
        )

    def test_every_apk_asset_has_sha256(self):
        """Ассет без хэша = fail-closed отказ на закреплённой версии."""
        cfg = ebi.BINARIES["tgwsproxy"]
        for mgr, arches in cfg["package_assets"].items():
            for arch in arches:
                self.assertTrue(ebi._expected_sha256(cfg, arch, mgr),
                                "нет sha256 для %s:%s" % (mgr, arch))

    def test_openwrt_x86_64_build_is_available(self):
        """Issue #280: апстрим собирает x86_64 (config/openwrt/x86_64.config),
        а в манифесте его не было — на OpenWrt x86_64 движок было не
        поставить, хотя сборка существует."""
        cfg = ebi.BINARIES["tgwsproxy"]
        with mock.patch.object(ebi, "detect_openwrt_arch",
                               return_value="x86_64"):
            self.assertEqual(
                ebi._resolve_asset_name(cfg, "x86_64", "apk"),
                "tg-ws-proxy_%s-r1_openwrt_x86_64.apk" % cfg["pinned_tag"])
            self.assertTrue(ebi._expected_sha256(cfg, "x86_64", "apk"))

    def test_openwrt_target_wins_over_uname_family(self):
        """`uname -m` даёт armv7l и для cortex-a7, и для cortex-a9 —
        различает их только DISTRIB_ARCH, а apk сверяет арку пакета."""
        cfg = ebi.BINARIES["tgwsproxy"]
        for target in ("arm_cortex-a7", "arm_cortex-a9"):
            with mock.patch.object(ebi, "detect_openwrt_arch",
                                   return_value=target):
                self.assertEqual(
                    ebi._resolve_asset_name(cfg, "armv7", "apk"),
                    "tg-ws-proxy_%s-r1_openwrt_%s.apk"
                    % (cfg["pinned_tag"], target))

    def test_openwrt_target_ignored_for_opkg(self):
        """Entware ставит .ipk по семейству — таргет OpenWrt там ни при чём."""
        cfg = ebi.BINARIES["tgwsproxy"]
        with mock.patch.object(ebi, "detect_openwrt_arch",
                               return_value="aarch64_generic"):
            self.assertEqual(
                ebi._resolve_asset_name(cfg, "aarch64", "opkg"),
                "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk" % cfg["pinned_tag"])

    def test_family_key_used_when_distrib_arch_unreadable(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        with mock.patch.object(ebi, "detect_openwrt_arch", return_value=""):
            self.assertEqual(
                ebi._resolve_asset_name(cfg, "aarch64", "apk"),
                "tg-ws-proxy_%s-r1_openwrt_aarch64_generic.apk"
                % cfg["pinned_tag"])

    def test_detect_openwrt_arch_reads_distrib_arch(self):
        data = ("DISTRIB_ID='OpenWrt'\n"
                "DISTRIB_ARCH='arm_cortex-a7'\n")
        with mock.patch("builtins.open", mock.mock_open(read_data=data)):
            self.assertEqual(ebi.detect_openwrt_arch(), "arm_cortex-a7")

    def test_detect_openwrt_arch_absent_on_entware(self):
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertEqual(ebi.detect_openwrt_arch(), "")

    def test_installability_reports_openwrt_target(self):
        with mock.patch.object(ebi, "detect_arch", return_value="x86_64"), \
             mock.patch.object(ebi, "detect_openwrt_arch",
                               return_value="x86_64"), \
             mock.patch.object(ebi, "_package_manager", return_value="apk"):
            info = ebi.get_installability("tgwsproxy")
        self.assertTrue(info["installable"])
        self.assertEqual(info["arch"], "x86_64")
        # Синонимы одного и того же ассета в список не дублируются.
        self.assertEqual(len(info["supported_archs"]),
                         len(set(info["supported_archs"])))
        self.assertNotIn("aarch64_generic", info["supported_archs"])

    def test_pkg_version_matches_tag_ignores_build_revision(self):
        """opkg отдаёт `0.9.3-1`, тег релиза — `0.9.3`: без нормализации
        «уже актуально» не срабатывало никогда и пакет качался заново."""
        self.assertTrue(ebi._pkg_version_matches_tag("0.9.3-1", "0.9.3"))
        self.assertTrue(ebi._pkg_version_matches_tag("0.9.3-r1", "0.9.3"))
        self.assertTrue(ebi._pkg_version_matches_tag("0.9.3", "v0.9.3"))
        self.assertFalse(ebi._pkg_version_matches_tag("0.9.2-1", "0.9.3"))
        self.assertFalse(ebi._pkg_version_matches_tag("", "0.9.3"))


class TestGetInstallStatus(unittest.TestCase):
    """Тесты get_install_status."""

    @mock.patch("subprocess.run")
    @mock.patch("os.access", return_value=True)
    @mock.patch.object(ebi, "detect_arch", return_value="aarch64")
    def test_installed(self, mock_arch, mock_access, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="usque v1.2.3\n")

        def fake_isfile(path):
            return path == "/opt/usr/bin/usque"

        with mock.patch("os.path.isfile", side_effect=fake_isfile):
            status = ebi.get_install_status("usque")
            self.assertTrue(status["installed"])

    @mock.patch("os.path.isfile", return_value=False)
    def test_not_installed(self, mock_isfile):
        status = ebi.get_install_status("usque")
        self.assertFalse(status["installed"])

    def test_unknown_binary(self):
        status = ebi.get_install_status("nonexistent")
        self.assertFalse(status["installed"])
        self.assertIn("error", status)

    @mock.patch.object(ebi, "detect_arch", return_value="aarch64")
    @mock.patch.object(ebi, "_pkg_version", return_value="0.9.2")
    def test_tgwsproxy_installed_from_package(self, mock_pkg_version, mock_arch):
        status = ebi.get_install_status("tgwsproxy")
        self.assertTrue(status["installed"])
        self.assertEqual(status["version"], "0.9.2")
        self.assertEqual(status["binary"], "/opt/etc/init.d/S99tg-ws-proxy")


class TestGetVersion(unittest.TestCase):
    """Тесты _get_version."""

    @mock.patch("subprocess.run")
    def test_version_from_stdout(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="v1.2.3\n")
        v = ebi._get_version("/fake/binary")
        self.assertIn("1.2.3", v)

    @mock.patch("subprocess.run", side_effect=FileNotFoundError)
    def test_version_not_found(self, mock_run):
        v = ebi._get_version("/nonexistent")
        self.assertEqual(v, "")


class TestInstallBinaryByName(unittest.TestCase):
    """Тесты install_binary_by_name."""

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="opkg")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_release_tag_is_used_not_latest(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        mock_release.return_value = {
            "tag_name": ebi.BINARIES["tgwsproxy"]["pinned_tag"],
            "assets": [
                {
                    "name": "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk"
                            % ebi.BINARIES["tgwsproxy"]["pinned_tag"],
                    "browser_download_url": "https://example.invalid/tg-ws-proxy.ipk",
                }
            ],
        }

        with mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
            tmp = mock.Mock()
            tmp.__enter__ = mock.Mock(return_value=tmp)
            tmp.__exit__ = mock.Mock(return_value=False)
            tmp.name = "/tmp/tgwsproxy.ipk"
            mtmp.return_value = tmp
            with mock.patch("core.ext_binary_installer.open", mock.mock_open(read_data=b"abc"), create=True):
                with mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
                    h = mock.Mock()
                    h.hexdigest.return_value = ebi.BINARIES["tgwsproxy"]["sha256_map"]["opkg:aarch64"]
                    mhash.return_value = h
                    res = ebi.install_binary_by_name("tgwsproxy")

        self.assertTrue(res["ok"])
        mock_release.assert_called_once_with(
            "spatiumstas/tg-ws-proxy-go",
            ebi.BINARIES["tgwsproxy"]["release_tag"], transport="")

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._pkg_version")
    @mock.patch("core.ext_binary_installer.detect_arch")
    def test_skips_download_if_versions_match(self, mock_arch, mock_pkg_version, mock_release):
        # usque ставится как Entware-пакет (install_kind=package): проверка
        # «уже актуально» идёт через opkg (_pkg_version), а не _get_version.
        mock_arch.return_value = "aarch64"
        mock_pkg_version.return_value = "0.3.0"
        mock_release.return_value = {
            "tag_name": "v0.3.0",
            "assets": []
        }

        res = ebi.install_binary_by_name("usque")
        self.assertTrue(res["ok"])
        self.assertEqual(res.get("noop"), True)
        self.assertEqual(res["version"], "v0.3.0")

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="opkg")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_package_install_uses_pinned_release_and_sha(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        mock_release.return_value = {
            "tag_name": ebi.BINARIES["tgwsproxy"]["pinned_tag"],
            "assets": [
                {
                    "name": "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk"
                            % ebi.BINARIES["tgwsproxy"]["pinned_tag"],
                    "browser_download_url": "https://example.invalid/tg-ws-proxy.ipk",
                }
            ],
        }

        with mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
            tmp = mock.Mock()
            tmp.__enter__ = mock.Mock(return_value=tmp)
            tmp.__exit__ = mock.Mock(return_value=False)
            tmp.name = "/tmp/tgwsproxy.ipk"
            mtmp.return_value = tmp
            with mock.patch("core.ext_binary_installer.open", mock.mock_open(read_data=b"abc"), create=True):
                # sha256 mismatch is not our concern here — just make sure the
                # pinned release path is exercised without raising earlier errors.
                with mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
                    h = mock.Mock()
                    h.hexdigest.return_value = ebi.BINARIES["tgwsproxy"]["sha256_map"]["opkg:aarch64"]
                    mhash.return_value = h
                    res = ebi.install_binary_by_name("tgwsproxy")

        self.assertTrue(res["ok"])
        self.assertEqual(res["tag"], ebi.BINARIES["tgwsproxy"]["pinned_tag"])

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="opkg")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_sha256_missing_fails_closed(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        mock_release.return_value = {
            "tag_name": ebi.BINARIES["tgwsproxy"]["pinned_tag"],
            "assets": [
                {
                    "name": "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk"
                            % ebi.BINARIES["tgwsproxy"]["pinned_tag"],
                    "browser_download_url": "https://example.invalid/tg-ws-proxy.ipk",
                }
            ],
        }
        with mock.patch("core.ext_binary_installer._expected_sha256", return_value=""):
            with mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = "/tmp/tgwsproxy.ipk"
                mtmp.return_value = tmp
                res = ebi.install_binary_by_name("tgwsproxy")
        self.assertFalse(res["ok"])
        self.assertIn("SHA256", res["error"])

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="opkg")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_sha256_mismatch_fails(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        mock_release.return_value = {
            "tag_name": ebi.BINARIES["tgwsproxy"]["pinned_tag"],
            "assets": [
                {
                    "name": "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk"
                            % ebi.BINARIES["tgwsproxy"]["pinned_tag"],
                    "browser_download_url": "https://example.invalid/tg-ws-proxy.ipk",
                }
            ],
        }
        with mock.patch("core.ext_binary_installer._expected_sha256",
                        return_value="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"):
            with mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = "/tmp/tgwsproxy.ipk"
                mtmp.return_value = tmp
                with mock.patch("core.ext_binary_installer.open", mock.mock_open(read_data=b"abc"), create=True):
                    with mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
                        h = mock.Mock()
                        h.hexdigest.return_value = "0000000000000000000000000000000000000000000000000000000000000000"
                        mhash.return_value = h
                        with self.assertRaises(ebi.InstallError):
                            ebi.install_binary_by_name("tgwsproxy")

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="opkg")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="riscv64")
    def test_unsupported_arch_fails(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        res = ebi.install_binary_by_name("tgwsproxy")
        self.assertFalse(res["ok"])
        self.assertIn("не поддерживается", res["error"])

    @mock.patch("core.ext_binary_installer.github_release",
                return_value={"error_detail": "GitHub API HTTP error 403"})
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_release_api_error_fails(self, mock_arch, mock_release):
        res = ebi.install_binary_by_name("usque")
        self.assertFalse(res["ok"])
        self.assertIn("GitHub API", res["error"])

    @mock.patch("core.ext_binary_installer.github_release")
    @mock.patch("core.ext_binary_installer._package_manager", return_value="")
    @mock.patch("core.ext_binary_installer._verify_downloaded_file", return_value={"ok": True})
    @mock.patch("core.ext_binary_installer.download_file", return_value=True)
    @mock.patch("core.ext_binary_installer.install_binary", return_value=True)
    @mock.patch("subprocess.run")
    @mock.patch("core.ext_binary_installer._pkg_version", return_value="")
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_package_install_requires_pkg_manager(
        self, mock_arch, mock_pkg_version, mock_subprocess_run, mock_install,
        mock_download, mock_verify, mock_pkg_mgr, mock_release
    ):
        mock_subprocess_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        mock_release.return_value = {
            "tag_name": ebi.BINARIES["tgwsproxy"]["pinned_tag"],
            "assets": [
                {
                    "name": "tg-ws-proxy_%s-1_entware_aarch64-3.10.ipk"
                            % ebi.BINARIES["tgwsproxy"]["pinned_tag"],
                    "browser_download_url": "https://example.invalid/tg-ws-proxy.ipk",
                }
            ],
        }
        with mock.patch(
                "core.ext_binary_installer._expected_sha256",
                return_value=ebi.BINARIES["tgwsproxy"]["sha256_map"]["opkg:aarch64"]):
            with mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = "/tmp/tgwsproxy.ipk"
                mtmp.return_value = tmp
                with mock.patch("core.ext_binary_installer.open", mock.mock_open(read_data=b"abc"), create=True):
                    with mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
                        h = mock.Mock()
                        h.hexdigest.return_value = ebi.BINARIES["tgwsproxy"]["sha256_map"]["opkg:aarch64"]
                        mhash.return_value = h
                        res = ebi.install_binary_by_name("tgwsproxy")
        self.assertFalse(res["ok"])
        self.assertIn("Не найден opkg/apk", res["error"])


class TestTgwsproxyLatestRelease(unittest.TestCase):
    """
    tg-ws-proxy закреплён на 0.9.3 (см. TestBinaries), но механика поиска
    ассета по версионно-независимому суффиксу остаётся рабочей и нужной:
    имя ассета версионировано (`tg-ws-proxy_0.9.3-1_entware_aarch64-3.10.ipk`),
    и при установке любого другого тега — через allow_unpinned или после
    будущего переезда на новый источник — ассет обязан находиться по
    суффиксу, иначе установка упирается в fallback-URL с несуществующим
    именем файла.
    """

    def _release(self, tag, names):
        return {
            "tag_name": tag,
            "assets": [{"name": n,
                        "browser_download_url": "https://example.invalid/" + n}
                       for n in names],
        }

    def _install(self, release, sha_hex):
        with mock.patch("core.ext_binary_installer.github_release",
                        return_value=release) as m_release, \
             mock.patch("core.ext_binary_installer.detect_arch",
                        return_value="aarch64"), \
             mock.patch("core.ext_binary_installer._package_manager",
                        return_value="opkg"), \
             mock.patch("core.ext_binary_installer._pkg_version",
                        return_value=""), \
             mock.patch("core.ext_binary_installer._verify_downloaded_file",
                        return_value={"ok": True, "skipped": True}), \
             mock.patch("core.ext_binary_installer.download_file",
                        return_value=True) as m_download, \
             mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=0, stdout="", stderr="")), \
             mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp, \
             mock.patch("core.ext_binary_installer.open",
                        mock.mock_open(read_data=b"abc"), create=True), \
             mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
            tmp = mock.Mock()
            tmp.__enter__ = mock.Mock(return_value=tmp)
            tmp.__exit__ = mock.Mock(return_value=False)
            tmp.name = "/tmp/tgwsproxy.ipk"
            mtmp.return_value = tmp
            h = mock.Mock()
            h.hexdigest.return_value = sha_hex
            mhash.return_value = h
            res = ebi.install_binary_by_name("tgwsproxy")
        return res, m_release, m_download

    def test_pinned_tag_is_requested_not_latest(self):
        """Запрашиваем именно 0.9.3: /releases/latest у этого апстрима
        отдаёт десктопное приложение без пакетов для роутера (см. §7 скила
        telegram-tunnel)."""
        cfg = ebi.BINARIES["tgwsproxy"]
        release = self._release(
            cfg["pinned_tag"], [cfg["package_assets"]["opkg"]["aarch64"]])
        res, m_release, _ = self._install(
            release, cfg["sha256_map"]["opkg:aarch64"])
        self.assertTrue(res["ok"], res)
        m_release.assert_called_once_with("spatiumstas/tg-ws-proxy-go",
                                          cfg["release_tag"], transport="")

    def test_newer_release_asset_found_by_suffix(self):
        """Ключевой случай: в релизе 0.9.9 имени из манифеста нет."""
        release = self._release("0.9.9", [
            "tg-ws-proxy.pem",
            "tg-ws-proxy_0.9.9-1_entware_armv7-3.2.ipk",
            "tg-ws-proxy_0.9.9-1_entware_mips-3.4.ipk",
            "tg-ws-proxy_0.9.9-1_entware_mipsel-3.4.ipk",
            "tg-ws-proxy_0.9.9-1_entware_aarch64-3.10.ipk",
            "tg-ws-proxy_0.9.9-1_openwrt_aarch64_generic.ipk",
            "tg-ws-proxy_0.9.9-r1_openwrt_aarch64_generic.apk",
        ])
        res, _, m_download = self._install(release, "0" * 64)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["tag"], "0.9.9")
        url = m_download.call_args.args[0]
        self.assertTrue(
            url.endswith("tg-ws-proxy_0.9.9-1_entware_aarch64-3.10.ipk"), url)
        # Версия новее закреплённой — манифестного хэша для неё быть не
        # может, и это не замалчивается.
        self.assertFalse(res["sha256_verified"])
        self.assertFalse(res["sha256_pinned"])

    def test_pinned_release_still_checked_against_manifest(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        release = self._release(
            cfg["pinned_tag"], [cfg["package_assets"]["opkg"]["aarch64"]])
        res, _, _ = self._install(release, cfg["sha256_map"]["opkg:aarch64"])
        self.assertTrue(res["sha256_verified"])
        self.assertTrue(res["sha256_pinned"])

        with self.assertRaises(ebi.InstallError):
            self._install(release, "0" * 64)

    def test_already_installed_version_is_not_redownloaded(self):
        """opkg отдаёт версию с ревизией сборки — это та же версия."""
        cfg = ebi.BINARIES["tgwsproxy"]
        with mock.patch("core.ext_binary_installer.github_release",
                        return_value={"tag_name": cfg["pinned_tag"], "assets": []}), \
             mock.patch("core.ext_binary_installer.detect_arch",
                        return_value="aarch64"), \
             mock.patch("core.ext_binary_installer._package_manager",
                        return_value="opkg"), \
             mock.patch("core.ext_binary_installer._pkg_version",
                        return_value="%s-1" % cfg["pinned_tag"]), \
             mock.patch("core.ext_binary_installer.download_file") as m_download:
            res = ebi.install_binary_by_name("tgwsproxy")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res.get("noop"))
        m_download.assert_not_called()


class TestOperaLatestRelease(unittest.TestCase):
    """
    ЗАПАСНОЙ источник opera-proxy (апстрим Alexey71/opera-proxy).

    По умолчанию opera ставится из НАШЕЙ сборки со сверкой sha256 по
    manifest.json релиза. Прежний путь остался фолбэком, и его политика
    проверяется здесь: ставится ПОСЛЕДНИЙ релиз апстрима, манифестный
    sha256 действует для known-good версии (совпал тег — fail-closed,
    тег новее — установка разрешена, но помечена как несверенная).
    """

    @property
    def legacy(self):
        return ebi.BINARIES["opera"]["legacy_source"]

    def test_opera_installs_from_our_build_by_default(self):
        cfg = ebi.BINARIES["opera"]
        self.assertEqual(cfg["repo"], "avatarDD/zapret-gui")
        self.assertEqual(cfg["release_prefix"], "opera-bin-")
        self.assertEqual(cfg["manifest_asset"], "manifest.json")
        # Мягкой политики у основного пути быть не должно.
        self.assertFalse(cfg.get("allow_unpinned"))

    def test_config_asks_for_latest(self):
        cfg = self.legacy
        self.assertEqual(cfg.get("release_tag", ""), "")
        self.assertTrue(cfg.get("allow_unpinned"))
        self.assertTrue(cfg.get("pinned_tag"))
        # Хэши known-good версии на месте для всех архитектур сборок.
        for arch in cfg["arch_map"]:
            self.assertEqual(len(cfg["sha256_map"][arch]), 64, arch)

    def test_same_tag_ignores_v_prefix(self):
        self.assertTrue(ebi._same_tag("v1.28.0", "1.28.0"))
        self.assertTrue(ebi._same_tag("1.28.0", "v1.28.0"))
        self.assertFalse(ebi._same_tag("v1.28.0", "v1.27.0"))

    def _install(self, tag, sha_hex, verify_skipped=True):
        """Прогнать install_binary_by_name('opera') с подставленным релизом."""
        asset = self.legacy["arch_map"]["x86_64"]
        release = {
            "tag_name": tag,
            "assets": [{"name": asset,
                        "browser_download_url": "https://example.invalid/" + asset}],
        }
        verify = {"ok": True}
        if verify_skipped:
            verify["skipped"] = True

        with mock.patch("core.ext_binary_installer.github_release",
                        return_value=release) as m_release, \
             mock.patch("core.ext_binary_installer.detect_arch",
                        return_value="x86_64"), \
             mock.patch("core.ext_binary_installer._verify_downloaded_file",
                        return_value=verify), \
             mock.patch("core.ext_binary_installer.download_file",
                        return_value=True), \
             mock.patch("core.ext_binary_installer.install_binary",
                        return_value=True), \
             mock.patch("core.ext_binary_installer._get_version",
                        return_value=tag), \
             mock.patch("os.path.isfile", return_value=False), \
             mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp, \
             mock.patch("core.ext_binary_installer.open",
                        mock.mock_open(read_data=b"abc"), create=True), \
             mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
            tmp = mock.Mock()
            tmp.__enter__ = mock.Mock(return_value=tmp)
            tmp.__exit__ = mock.Mock(return_value=False)
            tmp.name = "/tmp/opera-proxy.bin"
            mtmp.return_value = tmp
            h = mock.Mock()
            h.hexdigest.return_value = sha_hex
            mhash.return_value = h
            res = ebi.install_binary_by_name("opera", _cfg=self.legacy)
        return res, m_release

    def test_latest_is_requested_not_pinned_tag(self):
        pinned = self.legacy["pinned_tag"]
        res, m_release = self._install(pinned,
                                       self.legacy["sha256_map"]["x86_64"])
        self.assertTrue(res["ok"], res)
        # Пустой тег = /releases/latest.
        m_release.assert_called_once_with("Alexey71/opera-proxy", "",
                                          transport="")

    def test_known_version_is_checked_against_manifest(self):
        pinned = self.legacy["pinned_tag"]
        res, _ = self._install(pinned,
                               self.legacy["sha256_map"]["x86_64"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["sha256_verified"])
        self.assertTrue(res["sha256_pinned"])

    def test_known_version_with_wrong_hash_is_refused(self):
        pinned = self.legacy["pinned_tag"]
        with self.assertRaises(ebi.InstallError):
            self._install(pinned, "0" * 64)

    def test_newer_version_installs_but_is_flagged_unverified(self):
        res, _ = self._install("v99.0.0", "0" * 64)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["tag"], "v99.0.0")
        self.assertFalse(res["sha256_verified"])
        self.assertFalse(res["sha256_pinned"])

    def test_newer_version_uses_release_checksums_when_published(self):
        """Если апстрим начнёт публиковать checksums — сверка снова строгая."""
        res, _ = self._install("v99.0.0", "0" * 64, verify_skipped=False)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["sha256_verified"])
        self.assertFalse(res["sha256_pinned"])

    def test_pinned_binaries_still_fail_closed_without_manifest_hash(self):
        """Остальные бинарники не должны стать «мягкими» из-за этой правки.

        У бинарника либо закреплён тэг (и хэш в манифесте), либо он —
        наша сборка, и тогда sha256 берётся из manifest.json релиза. Чего
        быть не должно — так это установки вообще без сверки.
        """
        for name in ("usque", "tgproto", "opera"):
            cfg = ebi.BINARIES[name]
            self.assertFalse(cfg.get("allow_unpinned"), name)
            self.assertTrue(cfg.get("release_tag")
                            or cfg.get("manifest_asset"), name)

    def test_known_version_without_manifest_hash_is_refused(self):
        """У allow_unpinned послабление действует только для версии НОВЕЕ
        закреплённой. Приехала ровно закреплённая, а хэша под эту
        архитектуру в манифесте нет — это дыра в манифесте, ставить
        нельзя."""
        pinned = self.legacy["pinned_tag"]
        with mock.patch("core.ext_binary_installer._expected_sha256",
                        return_value=""):
            res, _ = self._install(pinned, "0" * 64)
        self.assertFalse(res["ok"], res)
        self.assertIn("SHA256", res["error"])


if __name__ == "__main__":
    unittest.main()


class TestManifestInstall(unittest.TestCase):
    """Установка НАШЕЙ сборки: sha256 из manifest.json релиза.

    Хэш каждой сборки известен только после неё, поэтому в манифесте
    файла его нет — но проверка обязана оставаться fail-closed.
    """

    def setUp(self):
        self.cfg = {
            "repo": "avatarDD/zapret-gui",
            "release_prefix": "usque-bin-",
            "manifest_asset": "manifest.json",
            "manifest_section": "usque",
            "install_kind": "binary",
            "dest": "",
            "arch_map": {"mipsel": "mipsel-softfloat"},
        }

    def _release(self):
        return {"tag_name": "usque-bin-v4.2.1",
                "assets": [{"name": "manifest.json",
                            "browser_download_url": "https://x/manifest.json"}]}

    def _manifest(self, sha):
        return {"schema": 1, "tag": "usque-bin-v4.2.1",
                "usque": {"version": "4.2.1", "binaries": {
                    "mipsel": {"filename": "usque-4.2.1-mipsel-softfloat.gz",
                               "url": "https://x/usque-4.2.1-mipsel-softfloat.gz",
                               "sha256": sha, "size": 10}}}}

    def _run_install(self, payload, manifest_sha):
        import gzip
        import io
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, True)
        self.cfg["dest"] = os.path.join(tmpdir, "usque")

        blob = io.BytesIO()
        with gzip.GzipFile(fileobj=blob, mode="wb") as gz:
            gz.write(payload)
        gz_bytes = blob.getvalue()

        def fake_download(url, dest, timeout=None, transport=""):
            with open(dest, "wb") as f:
                f.write(gz_bytes)
            return True

        real_sha = hashlib.sha256(gz_bytes).hexdigest()
        sha = real_sha if manifest_sha == "real" else manifest_sha

        with mock.patch.object(ebi, "github_release_by_prefix",
                               return_value=self._release()), \
             mock.patch.object(ebi, "_manifest_entry",
                               return_value=dict(
                                   self._manifest(sha)["usque"]["binaries"]["mipsel"],
                                   version="4.2.1")), \
             mock.patch.object(ebi, "download_file", side_effect=fake_download), \
             mock.patch.object(ebi, "detect_arch", return_value="mipsel"):
            return ebi.install_binary_by_name("usque", _cfg=self.cfg)

    def test_good_checksum_installs_and_ungzips(self):
        res = self._run_install(b"#!/bin/true\n", "real")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["sha256_verified"])
        self.assertEqual(res["version"], "4.2.1")
        with open(self.cfg["dest"], "rb") as f:
            self.assertEqual(f.read(), b"#!/bin/true\n")
        self.assertTrue(os.access(self.cfg["dest"], os.X_OK))

    def test_checksum_mismatch_refuses_install(self):
        res = self._run_install(b"payload", "0" * 64)
        self.assertFalse(res["ok"])
        self.assertIn("SHA256", res["error"])
        self.assertFalse(os.path.exists(self.cfg["dest"]))

    def test_falls_back_to_legacy_source_when_no_our_build(self):
        """До первого usque-bin-* релиза установка обязана работать."""
        self.cfg["legacy_source"] = {"repo": "side-effect-tm/usque-keenetic",
                                     "release_tag": "v0.3.0",
                                     "install_kind": "package",
                                     "dest": "/tmp/usque"}
        with mock.patch.object(ebi, "github_release_by_prefix",
                               return_value={"error_detail": "нет релиза"}), \
             mock.patch.object(ebi, "detect_arch", return_value="mipsel"), \
             mock.patch.object(ebi, "_resolve_asset_name", return_value=""):
            res = ebi.install_binary_by_name("usque", _cfg=self.cfg)
        # Ушли на запасной источник (там своя ошибка про архитектуру),
        # а не выдали «нет сборки» сразу.
        self.assertFalse(res["ok"])
        self.assertIn("Архитектура", res["error"])


class TestReleaseListFiltering(unittest.TestCase):

    def test_only_our_binary_releases_are_listed(self):
        """Релизы самого GUI не должны попадать в выбор версии usque."""
        payload = [
            {"tag_name": "v0.24.0", "published_at": "", "draft": False},
            {"tag_name": "usque-bin-v4.2.1", "published_at": "", "draft": False},
            {"tag_name": "singbox-bin-v1.14", "published_at": "", "draft": False},
            {"tag_name": "usque-bin-v4.2.0", "published_at": "", "draft": False},
        ]

        class _Resp:
            def read(self):
                return json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        ebi._releases_cache.clear()
        with mock.patch("core.download_transport.urlopen_via",
                        return_value=_Resp()):
            out = ebi.list_releases("usque", force=True)
        self.assertTrue(out["ok"])
        self.assertEqual([r["tag"] for r in out["releases"]],
                         ["usque-bin-v4.2.1", "usque-bin-v4.2.0"])


class TestOwnBuildsConfig(unittest.TestCase):
    """opera-proxy и tg-mtproxy-client тоже собираем сами.

    Мотивы разные: у opera прежний путь почти всегда шёл без сверки
    sha256 (allow_unpinned + частые релизы апстрима), а у tgproto в
    ассетах апстрима нет aarch64/armv7 и они лежат под rolling-тэгом.
    """

    OWN = ("usque", "opera", "tgproto")

    def test_all_own_builds_come_from_our_repo_with_manifest(self):
        for name in self.OWN:
            cfg = ebi.BINARIES[name]
            self.assertEqual(cfg["repo"], "avatarDD/zapret-gui", name)
            self.assertTrue(cfg["release_prefix"].endswith("-bin-"), name)
            self.assertEqual(cfg["manifest_asset"], "manifest.json", name)
            self.assertEqual(cfg["manifest_section"], name, name)
            self.assertEqual(cfg.get("install_kind"), "binary", name)
            # Никаких «мягких» установок на основном пути.
            self.assertFalse(cfg.get("allow_unpinned"), name)

    def test_own_builds_cover_every_supported_arch(self):
        for name in self.OWN:
            self.assertEqual(
                sorted(ebi.BINARIES[name]["arch_map"]),
                ["aarch64", "armv7", "mips", "mipsel", "x86_64"], name)

    def test_every_own_build_keeps_a_fallback_source(self):
        """До первой публикации сборки установка обязана работать."""
        for name in self.OWN:
            legacy = ebi.BINARIES[name].get("legacy_source")
            self.assertTrue(legacy, name)
            self.assertNotEqual(legacy["repo"], "avatarDD/zapret-gui", name)
            self.assertTrue(legacy.get("dest"), name)

    def test_tgproto_build_closes_the_aarch64_gap(self):
        """Ради этого всё и затевалось: у апстрима aarch64/armv7 нет."""
        legacy = ebi.BINARIES["tgproto"]["legacy_source"]
        self.assertNotIn("aarch64", legacy["arch_map"])
        self.assertNotIn("armv7", legacy["arch_map"])
        self.assertIn("aarch64", ebi.BINARIES["tgproto"]["arch_map"])
        self.assertIn("armv7", ebi.BINARIES["tgproto"]["arch_map"])

    def test_manifest_sections_are_distinct(self):
        """Секции манифеста не должны пересекаться между бинарниками."""
        sections = [ebi.BINARIES[n]["manifest_section"] for n in self.OWN]
        self.assertEqual(len(sections), len(set(sections)))

    def test_fallback_used_when_our_release_is_missing(self):
        with mock.patch.object(ebi, "github_release_by_prefix",
                               return_value={"error_detail": "нет релиза"}), \
             mock.patch.object(ebi, "detect_arch", return_value="mipsel"), \
             mock.patch.object(ebi, "github_release") as gr:
            gr.return_value = {"error_detail": "stop"}
            ebi.install_binary_by_name("tgproto")
        self.assertEqual(gr.call_args.args[0], "necronicle/z2k")
