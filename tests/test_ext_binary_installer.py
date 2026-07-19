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

    def test_tgwsproxy_has_pinned_release_and_sha256(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(cfg.get("release_tag"), "0.9.2")
        self.assertIn("opkg:aarch64", cfg.get("sha256_map", {}))
        self.assertIn("apk:aarch64", cfg.get("sha256_map", {}))

    def test_tgwsproxy_asset_selection_for_package_manager(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(
            ebi._resolve_asset_name(cfg, "aarch64", "opkg"),
            "tg-ws-proxy_0.9.2-1_entware_aarch64-3.10.ipk",
        )
        self.assertEqual(
            ebi._resolve_asset_name(cfg, "aarch64", "apk"),
            "tg-ws-proxy_0.9.2-r1_openwrt_aarch64_generic.apk",
        )

    def test_expected_sha256_for_package_manager(self):
        cfg = ebi.BINARIES["tgwsproxy"]
        self.assertEqual(
            ebi._expected_sha256(cfg, "aarch64", "opkg"),
            "9e8737f43ec7114ba904179f54908dd1d21a7bb9151f7b10a38207fda2bd9f50",
        )
        self.assertEqual(
            ebi._expected_sha256(cfg, "aarch64", "apk"),
            "1516d79e73146a1886c2ad4348a54804fff2acc558fe2f4f2ab0e35500dc8925",
        )



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
    @mock.patch("core.ext_binary_installer._get_version")
    @mock.patch("os.path.isfile")
    @mock.patch("core.ext_binary_installer.detect_arch")
    def test_skips_download_if_versions_match(self, mock_arch, mock_isfile, mock_get_version, mock_release):
        mock_arch.return_value = "aarch64"
        mock_isfile.return_value = True
        mock_get_version.return_value = "v0.3.0"
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
            "tag_name": "0.9.2",
            "assets": [
                {
                    "name": "tg-ws-proxy_0.9.2-1_entware_aarch64-3.10.ipk",
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
                    h.hexdigest.return_value = "9e8737f43ec7114ba904179f54908dd1d21a7bb9151f7b10a38207fda2bd9f50"
                    mhash.return_value = h
                    res = ebi.install_binary_by_name("tgwsproxy")

        self.assertTrue(res["ok"])
        self.assertEqual(res["tag"], "0.9.2")


if __name__ == "__main__":
    unittest.main()
