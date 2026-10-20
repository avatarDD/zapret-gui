# tests/test_nfqws_asset_files.py
"""Регрессия issue #411: стратегия ссылается на blob, которого нет на диске.

Голая установка zapret2 кладёт в files/fake только апстрим-блобы; наши
tls_clienthello_1.bin, quic_5.bin и т.п. лежат в import/bin. Раньше nfqws2
падал «cannot access file … exit 1», а UI оставался в залипшем состоянии.

Менеджер обязан:
  - докладывать отсутствующий blob/lua из bundle import/;
  - чужие и существующие файлы не трогать;
  - если взять файл неоткуда — не запускать nfqws2 и объяснить, почему.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import asset_importer
from core.nfqws_manager import NFQWSManager


class TestAssetRefs(unittest.TestCase):

    def test_blob_and_lua_init_files(self):
        refs = NFQWSManager._asset_refs([
            "/usr/bin/nfqws2",
            "--blob=quic5:@/opt/zapret2/files/fake/quic_5.bin",
            "--blob=tls1:+2@/opt/zapret2/files/fake/tls_clienthello_1.bin",
            "--blob=hex:0x0102",
            "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
            "--lua-init=fake_default_tls = 1",
        ])
        self.assertEqual(refs, [
            ("/opt/zapret2/files/fake/quic_5.bin",
             asset_importer.IMPORT_BIN_DIR),
            ("/opt/zapret2/files/fake/tls_clienthello_1.bin",
             asset_importer.IMPORT_BIN_DIR),
            ("/opt/zapret2/lua/zapret-lib.lua",
             asset_importer.IMPORT_LUA_DIR),
        ])


class TestEnsureAssetFiles(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = os.path.join(self.tmp, "files", "fake")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_bundled_blob_is_copied(self):
        dst = os.path.join(self.fake, "quic_5.bin")
        missing = NFQWSManager._ensure_asset_files(
            ["--blob=quic5:@" + dst], bin_dir=self.fake)
        self.assertEqual(missing, [])
        with open(dst, "rb") as got, \
                open(os.path.join(asset_importer.IMPORT_BIN_DIR,
                                  "quic_5.bin"), "rb") as want:
            self.assertEqual(got.read(), want.read())

    def test_existing_file_is_not_overwritten(self):
        os.makedirs(self.fake)
        dst = os.path.join(self.fake, "quic_5.bin")
        with open(dst, "wb") as f:
            f.write(b"user")
        self.assertEqual(
            NFQWSManager._ensure_asset_files(["--blob=q:@" + dst],
                                             bin_dir=self.fake), [])
        with open(dst, "rb") as f:
            self.assertEqual(f.read(), b"user")

    def test_unknown_file_is_reported(self):
        dst = os.path.join(self.fake, "no_such_blob_411.bin")
        self.assertEqual(
            NFQWSManager._ensure_asset_files(["--blob=x:@" + dst],
                                             bin_dir=self.fake), [dst])
        self.assertFalse(os.path.exists(dst))

    def test_not_copied_outside_bin_dir(self):
        # Путь из стратегии, а пишем от root: в чужой каталог — никогда.
        dst = os.path.join(self.tmp, "etc", "quic_5.bin")
        self.assertEqual(
            NFQWSManager._ensure_asset_files(["--blob=q:@" + dst],
                                             bin_dir=self.fake), [dst])
        self.assertFalse(os.path.exists(dst))

    def test_missing_bundled_lua_is_copied(self):
        lua = os.path.join(self.tmp, "lua")
        dst = os.path.join(lua, "zapret-lib.lua")
        self.assertEqual(
            NFQWSManager._ensure_asset_files(["--lua-init=@" + dst],
                                             lua_dir=lua), [])
        self.assertTrue(os.path.isfile(dst))


class TestStartRefusesMissingAssets(unittest.TestCase):

    def test_start_fails_before_popen_with_reason(self):
        with mock.patch.object(NFQWSManager, "_recover_pid"):
            mgr = NFQWSManager()
        binary = shutil.which("true") or "/bin/true"
        cfg = mock.Mock()
        cfg.get.side_effect = lambda *a, **k: (
            binary if a[-1] == "nfqws_binary" else k.get("default"))
        argv = [binary, "--blob=x:@/nonexistent/411/none.bin"]
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch.object(NFQWSManager, "_is_running_locked",
                               return_value=False), \
             mock.patch.object(NFQWSManager, "_sweep_stray_processes"), \
             mock.patch.object(NFQWSManager, "compose_command",
                               return_value=argv), \
             mock.patch.object(NFQWSManager, "_write_roots",
                               return_value=[]), \
             mock.patch("core.nfqws_manager.subprocess.Popen") as popen:
            self.assertFalse(mgr.start(["--blob=x:@/nonexistent/411/none.bin"]))
        popen.assert_not_called()
        self.assertIn("/nonexistent/411/none.bin", mgr._last_error)


if __name__ == "__main__":
    unittest.main()
