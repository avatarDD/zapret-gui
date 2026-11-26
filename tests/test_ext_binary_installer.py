# tests/test_ext_binary_installer.py
"""Unit-тесты для core/ext_binary_installer.py."""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from core import ext_binary_installer as ebi


def _elf(machine: int, little: bool = True, bits: int = 64) -> bytes:
    """Минимальный ELF-заголовок: дальше содержимое не важно, _elf_arch
    читает только e_ident/e_machine."""
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2 if bits == 64 else 1   # EI_CLASS
    head[5] = 1 if little else 2       # EI_DATA
    if little:
        head[18], head[19] = machine & 0xFF, machine >> 8
    else:
        head[18], head[19] = machine >> 8, machine & 0xFF
    return bytes(head) + b"\0" * 64


ELF_MIPSEL = _elf(0x08, little=True)


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
        # Запасной источник usque — Entware-пакет (install_kind=package):
        # проверка «уже актуально» идёт через opkg (_pkg_version), а не
        # _get_version. Основной источник usque — наша сборка по
        # манифесту, поэтому тест зовёт установщик прямо с legacy-конфигом
        # (_cfg), не трогая сеть GitHub.
        mock_arch.return_value = "aarch64"
        mock_pkg_version.return_value = "0.3.0"
        mock_release.return_value = {
            "tag_name": "v0.3.0",
            "assets": []
        }

        res = ebi.install_binary_by_name(
            "usque", _cfg=ebi.BINARIES["usque"]["legacy_source"])
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
    @mock.patch("core.ext_binary_installer.github_release_by_prefix",
                return_value={"error_detail": "GitHub API HTTP error 403"})
    @mock.patch("core.ext_binary_installer.detect_arch", return_value="aarch64")
    def test_release_api_error_fails(self, mock_arch, mock_prefix, mock_release):
        # Основной источник usque — наша сборка (github_release_by_prefix);
        # когда и он, и запасной пакетный релиз недоступны, установщик
        # обязан вернуть ошибку GitHub, не падая и не качая ничего.
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
             mock.patch("core.ext_binary_installer.verify_installed_binary",
                        return_value={"ok": True, "error": ""}), \
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
             mock.patch.object(ebi.subprocess, "run",
                               return_value=mock.Mock(returncode=0,
                                                      stdout="",
                                                      stderr="")), \
             mock.patch.object(ebi, "detect_arch", return_value="mipsel"):
            return ebi.install_binary_by_name("usque", _cfg=self.cfg)

    def test_good_checksum_installs_and_ungzips(self):
        res = self._run_install(ELF_MIPSEL, "real")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["sha256_verified"])
        self.assertEqual(res["version"], "4.2.1")
        with open(self.cfg["dest"], "rb") as f:
            self.assertEqual(f.read(), ELF_MIPSEL)
        self.assertTrue(os.access(self.cfg["dest"], os.X_OK))

    def test_script_payload_is_not_installed(self):
        """На месте движка не должен оказаться скрипт: так на
        /opt/usr/bin/geneva лёг init-скрипт из packaging/ релиза 2.0.1."""
        res = self._run_install(b"#!/bin/true\n", "real")
        self.assertFalse(res["ok"], res)
        self.assertIn("скрипт", res["error"])
        self.assertFalse(os.path.exists(self.cfg["dest"]))

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


class TestApkForeignArchRetry(unittest.TestCase):
    """issue #421: BPI-R4 (aarch64_cortex-a53) и пакет aarch64_generic —
    apk отказывает «uninstallable arch», а сборка там работает."""

    ERR = ("ERROR: unable to select packages:\n"
           "  tg-ws-proxy-0.9.3-r1:\n"
           "    error: uninstallable\n"
           "    arch: aarch64_generic\n")
    ERR_ONE_LINE = ("ERROR: unable to select packages: tg-ws-proxy-0.9.3-r1:"
                    " error: uninstallable arch: aarch64_generic satisfies:"
                    " world[tg-ws-proxy><Q1A0>]")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.arch_file = os.path.join(self.tmp, "arch")
        with open(self.arch_file, "w") as f:
            f.write("aarch64_cortex-a53\n")
        p = mock.patch.object(ebi, "APK_ARCH_FILE", self.arch_file)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp)

    def _run(self, first_err, host):
        fail = mock.Mock(returncode=1, stdout="", stderr=first_err)
        ok = mock.Mock(returncode=0, stdout="OK", stderr="")
        with mock.patch.object(ebi, "detect_arch", return_value=host), \
             mock.patch("subprocess.run", side_effect=[fail, ok]) as run:
            proc = ebi._run_pkg_install("apk", ["apk", "add", "x.apk"])
        return proc, run

    def test_same_family_retried_and_arch_persisted(self):
        proc, run = self._run(self.ERR_ONE_LINE, "aarch64")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(run.call_count, 2)
        with open(self.arch_file) as f:
            self.assertEqual(f.read().split(),
                             ["aarch64_cortex-a53", "aarch64_generic"])

    def test_multiline_apk_output(self):
        """Настоящий вывод apk 3 — многострочный."""
        proc, run = self._run(self.ERR, "aarch64")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(proc.returncode, 0)

    def test_foreign_family_not_retried(self):
        proc, run = self._run(self.ERR_ONE_LINE.replace(
            "aarch64_generic", "mipsel_24kc"), "aarch64")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(run.call_count, 1)
        with open(self.arch_file) as f:
            self.assertNotIn("mipsel_24kc", f.read())

    def test_arch_not_duplicated(self):
        with open(self.arch_file, "a") as f:
            f.write("aarch64_generic\n")
        self._run(self.ERR_ONE_LINE, "aarch64")
        with open(self.arch_file) as f:
            self.assertEqual(f.read().split().count("aarch64_generic"), 1)

    def test_opkg_not_retried(self):
        fail = mock.Mock(returncode=1, stdout="", stderr=self.ERR_ONE_LINE)
        with mock.patch("subprocess.run", return_value=fail) as run:
            ebi._run_pkg_install("opkg", ["opkg", "install", "x.ipk"])
        self.assertEqual(run.call_count, 1)


class TestGenevaFollowsLatestRelease(unittest.TestCase):
    """geneva_c ставится ПОСЛЕДНИМ релизом апстрима (discussion #102).

    release_tag пустой, имя ассета содержит версию тега и рендерится из
    asset_template; целостность новее пина — по SHA256SUMS релиза,
    ровно на пине — ещё и по манифестным хэшам.
    """

    GENEVA_REPO = "avatarDD/geneva_c"

    def _release(self, tag, asset_name):
        return {
            "tag_name": tag,
            "assets": [
                {
                    "name": asset_name,
                    "browser_download_url":
                        "https://example.invalid/" + asset_name,
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url":
                        "https://example.invalid/SHA256SUMS",
                },
            ],
        }

    def _install(self, mock_release, tag, asset_name):
        mock_release.return_value = self._release(tag, asset_name)
        with mock.patch("core.ext_binary_installer._package_manager",
                        return_value=""), \
                mock.patch("core.ext_binary_installer._verify_downloaded_file",
                           return_value={"ok": True}) as mock_verify, \
                mock.patch("core.ext_binary_installer.download_file",
                           return_value=True) as mock_download, \
                mock.patch("core.ext_binary_installer._unpack_if_needed",
                           return_value=("/tmp/geneva.tar.gz", None, "")), \
                mock.patch("core.ext_binary_installer.install_binary",
                           return_value=True), \
                mock.patch("core.ext_binary_installer.verify_installed_binary",
                           return_value={"ok": True}), \
                mock.patch("core.ext_binary_installer._get_version",
                           return_value=tag.lstrip("v")), \
                mock.patch("core.ext_binary_installer.detect_arch",
                           return_value="aarch64"), \
                mock.patch("core.ext_binary_installer.tempfile.NamedTemporaryFile") as mtmp:
            tmp = mock.Mock()
            tmp.__enter__ = mock.Mock(return_value=tmp)
            tmp.__exit__ = mock.Mock(return_value=False)
            tmp.name = "/tmp/geneva.tar.gz"
            mtmp.return_value = tmp
            res = ebi.install_binary_by_name("geneva")
        return res, mock_download

    @mock.patch("core.ext_binary_installer.github_release")
    def test_latest_release_rendered_from_template(self, mock_release):
        # Апстрим новее пина: точного имени из arch_map в релизе нет —
        # имя рендерит asset_template с фактическим тегом.
        res, mock_download = self._install(
            mock_release, "v2.0.4", "geneva-2.0.4-linux-aarch64.tar.gz")
        self.assertTrue(res["ok"])
        self.assertEqual(res["tag"], "v2.0.4")
        # ставим ПОСЛЕДНИЙ релиз: пустой тег = /releases/latest
        mock_release.assert_called_once_with(
            self.GENEVA_REPO, "", transport="")
        # качали именно отрендеренное имя, а не «пиновое» из arch_map
        self.assertEqual(mock_download.call_args[0][0],
                         "https://example.invalid/"
                         "geneva-2.0.4-linux-aarch64.tar.gz")
        # новее пина: манифестный sha256 не применяется, файл сумм
        # релиза проверен (v_res без skipped)
        self.assertFalse(res["sha256_pinned"])
        self.assertTrue(res["sha256_verified"])

    @mock.patch("core.ext_binary_installer.github_release")
    def test_release_at_pin_uses_manifest_sha(self, mock_release):
        # Апстрим стоит ровно на пине: имя из arch_map совпадает с ассетом,
        # и поверх файла сумм сверяется ещё и манифестный хэш.
        with mock.patch("core.ext_binary_installer.open",
                        mock.mock_open(read_data=b"abc"), create=True), \
                mock.patch("core.ext_binary_installer.hashlib.sha256") as mhash:
            h = mock.Mock()
            h.hexdigest.return_value = \
                ebi.BINARIES["geneva"]["sha256_map"]["aarch64"]
            mhash.return_value = h
            res, mock_download = self._install(
                mock_release, "v2.0.2", "geneva-2.0.2-linux-aarch64.tar.gz")
        self.assertTrue(res["ok"])
        self.assertEqual(res["tag"], "v2.0.2")
        self.assertEqual(mock_download.call_args[0][0],
                         "https://example.invalid/"
                         "geneva-2.0.2-linux-aarch64.tar.gz")
        self.assertTrue(res["sha256_pinned"])
        self.assertTrue(res["sha256_verified"])


class TestInstallBinaryReplaceRunning(unittest.TestCase):
    """install_binary меняет файл, который сейчас исполняется.

    Регрессия из обсуждения с пользователем: обновление geneva при
    включённом «Авто» падало
    «[Errno 26] Text file busy: '/opt/usr/bin/geneva'» — прежний
    install_binary копировал прямо поверх работающего бинарника,
    а open() на запись исполняемого файла ядро запрещает. Правильная
    схема — копия во временный файл рядом с целью + атомарный
    os.replace (меняет ссылку в каталоге, не трогая inode процесса).
    """

    def test_replaces_executing_binary(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory(prefix="etxtbsy-") as td:
            dest = os.path.join(td, "geneva")
            shutil.copy2(sys.executable, dest)
            victim = subprocess.Popen(
                [dest, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                # Жертва точно запущена: ждём, пока она встанет в sleep
                # (Popen возвращает управление раньше exec). Исчерпание
                # цикла — ошибка теста, а не молчаливый успех: без
                # for-else он мог пройти впустую, не проверив живой
                # случай.
                for _ in range(100):
                    if victim.poll() is not None:
                        self.fail("процесс-жертва не запустился")
                    try:
                        os.kill(victim.pid, 0)
                        # exec уже прошёл, если cmdline смотрится в нас
                        with open("/proc/%d/cmdline" % victim.pid, "rb") as f:
                            if b"sleep(30)" in f.read():
                                break
                    except OSError:
                        pass
                    time.sleep(0.05)
                else:
                    self.fail("жертва не исполнилась за 5 с — живой случай не проверен")
                src = os.path.join(td, "newbin")
                payload = b"stub-not-executed-" + os.urandom(32)
                with open(src, "wb") as f:
                    f.write(payload)
                self.assertTrue(ebi.install_binary(src, dest))
                with open(dest, "rb") as f:
                    self.assertEqual(f.read(), payload)
                # Работающий процесс продолжает жить на старом inode —
                # подмена через rename его не трогает.
                self.assertIsNone(victim.poll())
            finally:
                victim.terminate()
                victim.wait()

    def test_installs_into_fresh_dest(self):
        with tempfile.TemporaryDirectory(prefix="etxtbsy2-") as td:
            src = os.path.join(td, "newbin")
            payload = b"stub-not-executed-" + os.urandom(32)
            with open(src, "wb") as f:
                f.write(payload)
            dest = os.path.join(td, "sub", "geneva")
            self.assertTrue(ebi.install_binary(src, dest))
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), payload)
            self.assertTrue(os.access(dest, os.X_OK))
            # Временного файла от подмены не осталось
            self.assertEqual(
                sorted(os.listdir(os.path.dirname(dest))), ["geneva"])

    def test_missing_source_returns_false(self):
        with tempfile.TemporaryDirectory(prefix="etxtbsy3-") as td:
            self.assertFalse(
                ebi.install_binary(os.path.join(td, "nope"),
                                   os.path.join(td, "geneva")))
            # И мусора в каталоге не осталось
            self.assertEqual(os.listdir(td), [])


class TestDirectPathPrevBackup(unittest.TestCase):
    """Прямой путь установщика не оставляет роутер без движка.

    Регрессия, найденная ревью ETXTBSY-фикса: прямой путь (geneva и
    запасной источник opera/tgproto) при провале проверки запуска делал
    ``os.unlink(dest)`` — без бэкапа. До ETXTBSY-фикса «Авто» до этой
    строки не доходил (обновление отваливалось раньше, движок
    оставался живым), после — доходит, и битая сборка оставляла роутер
    без бинарника до перезагрузки. Схема та же, что у манифестного
    ``_install_binary_file``: прежний файл — в ``.prev``, откат при
    провале, флаг ``restored`` в ответе.
    """

    OLD = b"old-binary-" + b"x" * 32
    NEW = b"new-binary-" + b"y" * 32

    def _release(self):
        # Тег новее пина: у allow_unpinned-бинарника (geneva) сверка
        # идёт по SHA256SUMS релиза, то есть через замоканный
        # _verify_downloaded_file, — манифестный хэш не мешает.
        return {
            "tag_name": "v2.0.4",
            "assets": [
                {"name": "geneva-2.0.4-linux-aarch64.tar.gz",
                 "browser_download_url": "https://example.invalid/x"},
                {"name": "SHA256SUMS",
                 "browser_download_url": "https://example.invalid/s"},
            ],
        }

    def _install(self, dest, verify):
        """Прогнать прямой путь с реальным install_binary и файлами.

        Реальны: файловая система (dest, источник, .prev) и install_binary.
        Замоканы: сеть (github_release/download_file), сверка sha,
        распаковка (источник уже «распакован») и проверка запуска —
        её результат и есть параметр ``verify``.
        """
        with tempfile.TemporaryDirectory(prefix="prev-") as td:
            src = os.path.join(td, "newbin")
            with open(src, "wb") as f:
                f.write(self.NEW)
            cfg = dict(ebi.BINARIES["geneva"], dest=dest)
            with mock.patch("core.ext_binary_installer.github_release",
                            return_value=self._release()), \
                 mock.patch("core.ext_binary_installer."
                            "_verify_downloaded_file",
                            return_value={"ok": True}), \
                 mock.patch("core.ext_binary_installer.download_file",
                            return_value=True), \
                 mock.patch("core.ext_binary_installer._unpack_if_needed",
                            return_value=(src, None, "")), \
                 mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value=verify), \
                 mock.patch("core.ext_binary_installer._get_version",
                            return_value="2.0.1"), \
                 mock.patch("core.ext_binary_installer.detect_arch",
                            return_value="aarch64"), \
                 mock.patch("core.ext_binary_installer.tempfile."
                            "NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = src
                mtmp.return_value = tmp
                res = ebi.install_binary_by_name("geneva", _cfg=cfg)
        return res

    def test_verify_failure_restores_previous_binary(self):
        with tempfile.TemporaryDirectory(prefix="prev1-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            res = self._install(
                dest, verify={"ok": False, "error": "exit 1"})
            self.assertFalse(res["ok"])
            self.assertTrue(res["exec_error"])
            self.assertTrue(res["restored"])
            # На месте — прежняя версия, бэкап израсходован.
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertFalse(os.path.exists(dest + ".prev"))
            self.assertIn("не запускается", res["error"])
            # Пользователь видит, что прежняя версия вернулась на место,
            # а не «движок удалён» (как у манифестного пути).
            self.assertIn("Прежняя версия возвращена на место.",
                          res["error"])

    def test_verify_failure_without_previous_removes_new(self):
        with tempfile.TemporaryDirectory(prefix="prev2-") as td:
            dest = os.path.join(td, "geneva")
            res = self._install(
                dest, verify={"ok": False, "error": "exit 1"})
            self.assertFalse(res["ok"])
            self.assertFalse(res["restored"])
            # Прежнего не было — нового тоже не оставляем: он не работает.
            self.assertFalse(os.path.exists(dest))

    def test_success_cleans_backup(self):
        # Как у манифестного пути (test_good_binary_replaces_and_cleans_
        # backup): бэкап — страховка на случай провала verify, успех
        # её отработал — копии прежнего бинарника в PATH не остаётся.
        with tempfile.TemporaryDirectory(prefix="prev3-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            res = self._install(dest, verify={"ok": True})
            self.assertTrue(res["ok"], res)
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.NEW)
            self.assertFalse(os.path.exists(dest + ".prev"))

    def test_uninstall_removes_backup_too(self):
        with tempfile.TemporaryDirectory(prefix="prev5-") as td:
            dest = os.path.join(td, "geneva")
            for path, payload in ((dest, self.NEW),
                                  (dest + ".prev", self.OLD)):
                with open(path, "wb") as f:
                    f.write(payload)
            cfg = {"dest": dest, "install_kind": "binary"}
            with mock.patch.dict(ebi.BINARIES, {"testbin": cfg}):
                res = ebi.uninstall_binary("testbin")
            self.assertTrue(res["ok"], res)
            self.assertFalse(os.path.exists(dest))
            self.assertFalse(os.path.exists(dest + ".prev"))

    def test_not_a_binary_flag_surfaces(self):
        with tempfile.TemporaryDirectory(prefix="prev4-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            res = self._install(
                dest, verify={"ok": False, "not_a_binary": True,
                              "error": "shebang"})
            self.assertFalse(res["ok"])
            self.assertTrue(res["not_a_binary"])
            self.assertTrue(res["restored"])
            self.assertTrue(res["error"].startswith("Скачанный файл:"))
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.OLD)


class TestDirectPathRollbackResilience(TestDirectPathPrevBackup):
    """Провал отката не оставляет пользователя в темноте.

    LOW-2 ревью .prev-этапа: если os.replace(backup, dest) сам упал,
    прежняя версия оставалась единственной копией в ``.prev`` — без
    слов об этом в ответе и без второй попытки. Теперь: копия поверх
    не-исполняющегося файла как фолбэк, а при полном провале — честная
    подсказка, где лежит прежняя версия и как её вернуть.
    """

    def _install_with_broken_replace(self, dest, verify):
        """Прогон прямого пути, где ОТКАТ не может ни replace, ни copy."""
        events = []

        real_replace = os.replace
        real_copyfile = shutil.copyfile

        def replace(src, dst):
            if str(src).endswith(".prev"):
                events.append("replace-rollback-failed")
                raise OSError(28, "No space left on device")
            return real_replace(src, dst)

        def copyfile(src, dst, **kw):
            if str(src).endswith(".prev"):
                events.append("copy-rollback-failed")
                raise OSError(28, "No space left on device")
            return real_copyfile(src, dst, **kw)

        with tempfile.TemporaryDirectory(prefix="resil-") as td:
            src = os.path.join(td, "newbin")
            with open(src, "wb") as f:
                f.write(self.NEW)
            cfg = dict(ebi.BINARIES["geneva"], dest=dest)
            with mock.patch("core.ext_binary_installer.github_release",
                            return_value=self._release()), \
                 mock.patch("core.ext_binary_installer."
                            "_verify_downloaded_file",
                            return_value={"ok": True}), \
                 mock.patch("core.ext_binary_installer.download_file",
                            return_value=True), \
                 mock.patch("core.ext_binary_installer._unpack_if_needed",
                            return_value=(src, None, "")), \
                 mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value=verify), \
                 mock.patch("core.ext_binary_installer._get_version",
                            return_value="2.0.1"), \
                 mock.patch("core.ext_binary_installer.detect_arch",
                            return_value="aarch64"), \
                 mock.patch("core.ext_binary_installer.os.replace",
                            side_effect=replace), \
                 mock.patch("core.ext_binary_installer.shutil.copyfile",
                            side_effect=copyfile), \
                 mock.patch("core.ext_binary_installer.tempfile."
                            "NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = src
                mtmp.return_value = tmp
                res = ebi.install_binary_by_name("geneva", _cfg=cfg)
        return res, events

    def test_broken_rollback_keeps_prev_and_tells_where_it_is(self):
        with tempfile.TemporaryDirectory(prefix="resil1-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)

            res, events = self._install_with_broken_replace(
                dest, verify={"ok": False, "error": "exit 1"})

            self.assertFalse(res["ok"])
            self.assertFalse(res["restored"])
            # Обе попытки отката реально предприняты
            self.assertEqual(events, ["replace-rollback-failed",
                                      "copy-rollback-failed"])
            # Прежняя версия не потеряна и не замолчана
            self.assertTrue(os.path.isfile(dest + ".prev"))
            with open(dest + ".prev", "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertFalse(os.path.exists(dest))
            self.assertIn(dest + ".prev", res["error"])
            self.assertIn("mv %s %s" % (dest + ".prev", dest),
                          res["error"])

    def test_copy_fallback_restores_when_replace_fails(self):
        # os.replace упал, но copyfile над не-исполняющимся файлом
        # проходит: прежняя версия возвращается, бэкап почищен.
        with tempfile.TemporaryDirectory(prefix="resil2-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)

            real_replace = os.replace

            def replace(src, dst):
                if str(src).endswith(".prev"):
                    raise OSError(28, "No space left on device")
                return real_replace(src, dst)

            src = os.path.join(td, "newbin")
            with open(src, "wb") as f:
                f.write(self.NEW)
            cfg = dict(ebi.BINARIES["geneva"], dest=dest)
            with mock.patch("core.ext_binary_installer.github_release",
                            return_value=self._release()), \
                 mock.patch("core.ext_binary_installer."
                            "_verify_downloaded_file",
                            return_value={"ok": True}), \
                 mock.patch("core.ext_binary_installer.download_file",
                            return_value=True), \
                 mock.patch("core.ext_binary_installer._unpack_if_needed",
                            return_value=(src, None, "")), \
                 mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value={"ok": False,
                                          "error": "exit 1"}), \
                 mock.patch("core.ext_binary_installer._get_version",
                            return_value="2.0.1"), \
                 mock.patch("core.ext_binary_installer.detect_arch",
                            return_value="aarch64"), \
                 mock.patch("core.ext_binary_installer.os.replace",
                            side_effect=replace), \
                 mock.patch("core.ext_binary_installer.tempfile."
                            "NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = src
                mtmp.return_value = tmp
                res = ebi.install_binary_by_name("geneva", _cfg=cfg)

            self.assertFalse(res["ok"])
            self.assertTrue(res["restored"])
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertFalse(os.path.exists(dest + ".prev"))


class TestInstallLock(TestDirectPathPrevBackup):
    """MEDIUM-2 ревью: параллельные установки одного движка.

    Две установки наперегонки перепутывали бы пару dest/.prev: бэкап
    одного вызова становился откатом другого, os.replace на общем dest
    — гонкой последних записей. Теперь весь прямой путь (и удаление)
    сериализуется `_INSTALL_LOCK`; второй вызов, дождавшись, видит
    совпадающую версию и завершается noop-ом.
    """

    def _redownload(self, src):
        """Как живая загрузка: файл (пере)создаётся на каждый вызов.

        Хвост установки сносит tmp_path — в песочнице он же источник,
        поэтому «скачивание» обязано писать файл заново, иначе второй
        вызов в тесте получает ENOENT вместо своей копии.
        """
        def dl(*args, **kwargs):
            with open(src, "wb") as f:
                f.write(self.NEW)
            return True
        return dl

    def test_parallel_installs_serialize(self):
        windows = []          # (поток, вход, выход) одного выполнения

        def slow_unpack(path, member):
            # «Распаковка» — самая длинная стадия: по её окну видно,
            # перекрываются ли выполнения. Распаковывать нечего —
            # источник уже готов (tmp.name указывает на него).
            me = threading.current_thread()
            enter = time.time()
            time.sleep(0.2)
            windows.append((me, enter, time.time()))
            return path, None, ""

        with tempfile.TemporaryDirectory(prefix="locks-") as td:
            # Два ВЫЗОВА — один и тот же dest: до замка они крутили
            # lifecycle .prev друг друга.
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            src = os.path.join(td, "newbin")
            with open(src, "wb") as f:
                f.write(self.NEW)

            cfg = dict(ebi.BINARIES["geneva"], dest=dest)
            with mock.patch("core.ext_binary_installer.github_release",
                            return_value=self._release()), \
                 mock.patch("core.ext_binary_installer."
                            "_verify_downloaded_file",
                            return_value={"ok": True}), \
                 mock.patch("core.ext_binary_installer.download_file",
                            side_effect=self._redownload(src)), \
                 mock.patch("core.ext_binary_installer._unpack_if_needed",
                            side_effect=slow_unpack), \
                 mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value={"ok": True}), \
                 mock.patch("core.ext_binary_installer._get_version",
                            return_value="2.0.1"), \
                 mock.patch("core.ext_binary_installer.detect_arch",
                            return_value="aarch64"), \
                 mock.patch("core.ext_binary_installer.tempfile."
                            "NamedTemporaryFile") as mtmp:
                tmp = mock.Mock()
                tmp.__enter__ = mock.Mock(return_value=tmp)
                tmp.__exit__ = mock.Mock(return_value=False)
                tmp.name = src
                mtmp.return_value = tmp

                results = []

                def run():
                    results.append(ebi.install_binary_by_name(
                        "geneva", _cfg=cfg))

                threads = []
                for _ in range(2):
                    t = threading.Thread(target=run)
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join(30)
                    self.assertFalse(t.is_alive())

            # Оба вызова ДОСТАВИЛИ: без замка один из двух бился об
            # общий staged dest+".new" и возвращал «Не удалось
            # установить бинарник» — проверка результата, а не только
            # окон, ловит и это, и будущие регрессии замка.
            self.assertEqual(len(results), 2)
            for r in results:
                self.assertTrue(r.get("ok"), r)

            # Окна выполнений НЕ перекрываются: выход первого раньше
            # входа второго (пары полные, порядок любой).
            self.assertEqual(len(windows), 2)
            a, b = windows
            self.assertNotEqual(a[0], b[0])
            first, second = (a, b) if a[1] <= b[1] else (b, a)
            self.assertLessEqual(first[2], second[1] + 0.05)
            # Итог консистентен: dest — новая версия, мусора нет.
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.NEW)
            self.assertFalse(os.path.exists(dest + ".prev"))
            leftovers = [p for p in os.listdir(td)
                         if ".new-" in p or p.endswith(".prev")]
            self.assertEqual(leftovers, [])


class TestManifestPathRollback(TestDirectPathPrevBackup):
    """MEDIUM-3 ревью: лестница отката — и на манифестном пути.

    `_install_binary_file` — первичный путь usque/tgproto/opera (и
    локальные загрузки). До общей `_restore_prev` его откат был
    «replace или ничего»: неудача rename молча оставляла прежнюю
    версию единственной копией в .prev без фолбэка и подсказки.
    """

    def test_broken_rollback_keeps_prev_and_tells_where_it_is(self):
        import shutil

        real_replace = os.replace
        real_copyfile = shutil.copyfile

        def replace(src, dst):
            if str(src).endswith(".prev"):
                raise OSError(28, "No space left on device")
            return real_replace(src, dst)

        def copyfile(src, dst, **kw):
            if str(src).endswith(".prev"):
                raise OSError(28, "No space left on device")
            return real_copyfile(src, dst, **kw)

        with tempfile.TemporaryDirectory(prefix="manifest-rl-") as td:
            dest = os.path.join(td, "usque")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            src = os.path.join(td, "downloaded")
            with open(src, "wb") as f:
                f.write(self.NEW)

            cfg = {"dest": dest, "version_args": ["version"]}
            with mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value={"ok": False,
                                          "error": "exit 1"}), \
                 mock.patch("core.ext_binary_installer.os.replace",
                            side_effect=replace), \
                 mock.patch("core.ext_binary_installer.shutil.copyfile",
                            side_effect=copyfile):
                res = ebi._install_binary_file(cfg, src)

            self.assertFalse(res["ok"])
            self.assertFalse(res["restored"])
            # Прежняя версия уцелела в бэкапе, и ответ говорит, где
            # она и какой командой вернуть.
            self.assertTrue(os.path.exists(dest + ".prev"))
            with open(dest + ".prev", "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertFalse(os.path.exists(dest))
            self.assertIn("mv %s %s" % (dest + ".prev", dest),
                          res["error"])

    def test_copy_fallback_restores_when_replace_fails(self):
        import shutil

        real_replace = os.replace
        real_copyfile = shutil.copyfile

        def replace(src, dst):
            if str(src).endswith(".prev"):
                raise OSError(1, "Operation not permitted")
            return real_replace(src, dst)

        with tempfile.TemporaryDirectory(prefix="manifest-cf-") as td:
            dest = os.path.join(td, "usque")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            src = os.path.join(td, "downloaded")
            with open(src, "wb") as f:
                f.write(self.NEW)

            cfg = {"dest": dest, "version_args": ["version"]}
            with mock.patch("core.ext_binary_installer."
                            "verify_installed_binary",
                            return_value={"ok": False,
                                          "error": "exit 1"}), \
                 mock.patch("core.ext_binary_installer.os.replace",
                            side_effect=replace):
                res = ebi._install_binary_file(cfg, src)

            self.assertFalse(res["ok"])
            self.assertTrue(res["restored"])
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertFalse(os.path.exists(dest + ".prev"))


class TestPrevCleanupOnInstallFailure(TestDirectPathPrevBackup):
    """Провал install_binary не оставляет бесполезный .prev.

    dest не тронут (replace атомарен, staged прибран в самой
    install_binary): копия прежней версии рядом — 0755-мусор в PATH.
    """

    def test_prev_is_cleaned_and_dest_intact(self):
        # Провал install_binary: dest не тронут (replace атомарен,
        # staged прибран в самой install_binary), наш .prev — копия
        # того же, что лежит на месте, мусор прибираем.
        with tempfile.TemporaryDirectory(prefix="prev-clean-") as td:
            dest = os.path.join(td, "geneva")
            with open(dest, "wb") as f:
                f.write(self.OLD)
            with mock.patch("core.ext_binary_installer.install_binary",
                            return_value=False):
                res = self._install(
                    dest, verify={"ok": True, "version": "2.0.4"})

            self.assertFalse(res["ok"])
            self.assertEqual(res["error"], "Не удалось установить бинарник")
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), self.OLD)
            self.assertEqual(
                [p for p in os.listdir(td) if p.endswith(".prev")], [])
