# tests/test_installer_mirror.py
"""
Тесты миграции zapret/awg-инсталляторов на core/binary_installer:
загрузка делегируется общей утилите (→ зеркало/оффлайн работают),
GitHub API проходит через resolve_url.
"""

import unittest
from unittest import mock


class TestZapretDownloadDelegates(unittest.TestCase):

    def test_download_file_uses_binary_installer(self):
        from core.zapret_installer import ZapretInstaller
        inst = ZapretInstaller()
        with mock.patch("core.binary_installer.download_file",
                        return_value={"ok": True, "size": 123}) as df:
            ok = inst._download_file("https://github.com/o/r/x.tar.gz", "/tmp/x")
        self.assertTrue(ok)
        df.assert_called_once()
        self.assertEqual(df.call_args.args[0],
                         "https://github.com/o/r/x.tar.gz")

    def test_download_file_fallback_on_failure(self):
        from core.zapret_installer import ZapretInstaller
        inst = ZapretInstaller()
        with mock.patch("core.binary_installer.download_file",
                        return_value={"ok": False, "error": "net"}), \
             mock.patch("core.binary_installer.resolve_url",
                        return_value="https://mirror/u"), \
             mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="")
            with mock.patch("os.path.isfile", return_value=False):
                ok = inst._download_file("https://github.com/o/r/x", "/tmp/x")
        self.assertFalse(ok)
        # wget/curl получили зеркальный URL
        called_urls = [c.args[0] for c in run.call_args_list]
        self.assertTrue(all("https://mirror/u" in argv for argv in called_urls))


class TestAwgDownloadDelegates(unittest.TestCase):

    def test_download_uses_binary_installer(self):
        from core.awg_installer import AwgInstaller
        inst = AwgInstaller()
        with mock.patch("core.binary_installer.download_file",
                        return_value={"ok": True, "size": 5}) as df:
            inst._download("https://github.com/o/r/a.tar.gz", "/tmp/a",
                           0, 50, "awg")
        df.assert_called_once()

    def test_download_raises_on_failure(self):
        from core.awg_installer import AwgInstaller
        inst = AwgInstaller()
        with mock.patch("core.binary_installer.download_file",
                        return_value={"ok": False, "error": "boom"}):
            with self.assertRaises(RuntimeError):
                inst._download("https://github.com/o/r/a.tar.gz", "/tmp/a",
                               0, 50, "awg")


if __name__ == "__main__":
    unittest.main()
