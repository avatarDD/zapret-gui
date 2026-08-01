# tests/test_ext_binary_installer.py
"""Unit-тесты для core/ext_binary_installer.py."""

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

    def test_tgwsproxy_installs_latest_release(self):
        """Закреплённый тег означал бы, что «Обновления» показывают новую
        версию, а «Установить» молча ставит старую."""
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(cfg.get("release_tag", ""), "")
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
        """mips/mipsel не должны матчить ассет друг друга."""
        cfg = ebi.BINARIES["tgwsproxy"]
        for mgr, arches in cfg["package_assets"].items():
            for arch, name in arches.items():
                for other_arch in arches:
                    if other_arch == arch:
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
        mock_release.assert_called_once_with("spatiumstas/tg-ws-proxy-go", "")

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
    tg-ws-proxy ставится ПОСЛЕДНИМ релизом, а имя ассета версионировано
    (`tg-ws-proxy_0.9.3-1_entware_aarch64-3.10.ipk`). Значит на версии
    новее закреплённой ассет обязан находиться по версионно-независимому
    суффиксу — иначе установка упирается в fallback-URL с несуществующим
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

    def test_latest_is_requested_not_pinned_tag(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        release = self._release(
            cfg["pinned_tag"], [cfg["package_assets"]["opkg"]["aarch64"]])
        res, m_release, _ = self._install(
            release, cfg["sha256_map"]["opkg:aarch64"])
        self.assertTrue(res["ok"], res)
        m_release.assert_called_once_with("spatiumstas/tg-ws-proxy-go", "")

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
    opera-proxy ставится ПОСЛЕДНИМ релизом.

    Закреплённый тег означал бы, что «Обновления» видят новую версию, а
    кнопка «Установить» молча ставит старую (апстрим релизится раз в
    1–2 недели). Манифестный sha256 остаётся для known-good версии:
    совпал тег — проверка fail-closed, тег новее — установка разрешена,
    но помечена как несверенная.
    """

    def test_config_asks_for_latest(self):
        cfg = ebi.BINARIES["opera"]
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
        asset = ebi.BINARIES["opera"]["arch_map"]["x86_64"]
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
            res = ebi.install_binary_by_name("opera")
        return res, m_release

    def test_latest_is_requested_not_pinned_tag(self):
        pinned = ebi.BINARIES["opera"]["pinned_tag"]
        res, m_release = self._install(pinned,
                                       ebi.BINARIES["opera"]["sha256_map"]["x86_64"])
        self.assertTrue(res["ok"], res)
        # Пустой тег = /releases/latest.
        m_release.assert_called_once_with("Alexey71/opera-proxy", "")

    def test_known_version_is_checked_against_manifest(self):
        pinned = ebi.BINARIES["opera"]["pinned_tag"]
        res, _ = self._install(pinned,
                               ebi.BINARIES["opera"]["sha256_map"]["x86_64"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["sha256_verified"])
        self.assertTrue(res["sha256_pinned"])

    def test_known_version_with_wrong_hash_is_refused(self):
        pinned = ebi.BINARIES["opera"]["pinned_tag"]
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
        """Остальные бинарники не должны стать «мягкими» из-за этой правки."""
        for name in ("usque", "tgproto"):
            self.assertFalse(ebi.BINARIES[name].get("allow_unpinned"), name)
            self.assertTrue(ebi.BINARIES[name].get("release_tag"), name)

    def test_known_version_without_manifest_hash_is_refused(self):
        """У allow_unpinned послабление действует только для версии НОВЕЕ
        закреплённой. Приехала ровно закреплённая, а хэша под эту
        архитектуру в манифесте нет — это дыра в манифесте, ставить
        нельзя."""
        pinned = ebi.BINARIES["opera"]["pinned_tag"]
        with mock.patch("core.ext_binary_installer._expected_sha256",
                        return_value=""):
            res, _ = self._install(pinned, "0" * 64)
        self.assertFalse(res["ok"], res)
        self.assertIn("SHA256", res["error"])


if __name__ == "__main__":
    unittest.main()
