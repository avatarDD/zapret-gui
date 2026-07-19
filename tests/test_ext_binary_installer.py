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

    @mock.patch("core.ext_binary_installer.github_latest_release")
    @mock.patch("core.ext_binary_installer._get_version")
    @mock.patch("os.path.isfile")
    @mock.patch("core.ext_binary_installer.detect_arch")
    def test_skips_download_if_versions_match(self, mock_arch, mock_isfile, mock_get_version, mock_release):
        mock_arch.return_value = "aarch64"
        mock_isfile.return_value = True
        mock_get_version.return_value = "v1.2.3"
        mock_release.return_value = {
            "tag_name": "v1.2.3",
            "assets": []
        }

        res = ebi.install_binary_by_name("usque")
        self.assertTrue(res["ok"])
        self.assertEqual(res.get("noop"), True)
        self.assertEqual(res["version"], "v1.2.3")


if __name__ == "__main__":
    unittest.main()
