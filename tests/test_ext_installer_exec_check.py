# tests/test_ext_installer_exec_check.py
"""Регрессия: «[Errno 8] Exec format error: '/opt/usr/bin/usque'».

Установщик клал файл на место бинарника и рапортовал успех, не проверив
НИЧЕГО, кроме факта записи. В результате на месте рабочего usque мог
оказаться файл, который ядро отказывается исполнять:

  * скачанный вручную ассет релиза (`usque-4.2.1-mipsel-softfloat.gz`) —
    форма «установить из файла» копировала его КАК ЕСТЬ;
  * тарбол: `.tar.gz` оканчивается на `.gz`, и ветка «просто gzip»
    срабатывала первой — на место бинарника ложился tar-архив;
  * сборка под другой порядок байт (`uname -m` на mips и mipsel
    одинаковый).

Проверяем: распаковку, определение «это не бинарник», откат к прежней
версии и то, что нерабочая сборка уводит установку на запасной источник.
"""

import gzip
import io
import os
import tarfile
import tempfile
import unittest
from unittest import mock

from core import ext_binary_installer as ebi


# Минимальные ELF-заголовки: 64 байта, дальше содержимое не важно —
# _elf_arch читает только e_ident/e_machine.
def _elf(machine: int, little: bool = True, bits: int = 0) -> bytes:
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2 if (bits or _host_bits()) == 64 else 1   # EI_CLASS
    head[5] = 1 if little else 2      # EI_DATA
    if little:
        head[18], head[19] = machine & 0xFF, machine >> 8
    else:
        head[18], head[19] = machine >> 8, machine & 0xFF
    return bytes(head) + b"\0" * 64


def _host_bits() -> int:
    import sys
    return 64 if sys.maxsize > 2 ** 32 else 32


ELF_MIPSEL = _elf(0x08, little=True)
ELF_MIPS_BE = _elf(0x08, little=False)
ELF_X86_64 = _elf(0x3E, little=True)


class TestElfArch(unittest.TestCase):

    def _write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_mipsel_and_mips_are_distinguished(self):
        self.assertEqual(ebi._elf_arch(self._write(ELF_MIPSEL))[0], "mipsel")
        self.assertEqual(ebi._elf_arch(self._write(ELF_MIPS_BE))[0], "mips")

    def test_gzip_is_reported_as_archive(self):
        arch, err = ebi._elf_arch(self._write(gzip.compress(ELF_MIPSEL)))
        self.assertEqual(arch, "")
        self.assertIn("gzip", err)

    def test_ipk_is_reported_as_package(self):
        arch, err = ebi._elf_arch(self._write(b"!<arch>\ndebian-binary"))
        self.assertEqual(arch, "")
        self.assertIn("ar-архив", err)

    def test_empty_file_is_reported(self):
        arch, err = ebi._elf_arch(self._write(b""))
        self.assertEqual(arch, "")
        self.assertIn("пустой", err)

    def test_html_error_page(self):
        arch, err = ebi._elf_arch(self._write(b"<!DOCTYPE html><html>404"))
        self.assertEqual(arch, "")
        self.assertIn("HTML", err)

    def test_wrong_bitness_is_reported(self):
        """64-битная сборка на 32-битном роутере — ровно случай
        пользователя: `od -c` показал `177 E L F 002` (EI_CLASS=2)."""
        other = 32 if _host_bits() == 64 else 64
        arch, err = ebi._elf_arch(self._write(_elf(0x08, bits=other)))
        self.assertEqual(arch, "")
        self.assertIn("битная", err)
        self.assertIn(str(other), err)

    def test_unknown_machine_with_wrong_bitness_still_caught(self):
        """Даже незнакомый e_machine не должен проскочить по разрядности."""
        other = 32 if _host_bits() == 64 else 64
        arch, err = ebi._elf_arch(self._write(_elf(0xF3, bits=other)))
        self.assertEqual(arch, "")
        self.assertTrue(err)


class TestVerifyInstalledBinary(unittest.TestCase):

    def _write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_foreign_endianness_rejected_without_exec(self):
        path = self._write(ELF_MIPS_BE)
        with mock.patch.object(ebi, "detect_arch", return_value="mipsel"):
            with mock.patch.object(ebi.subprocess, "run") as run:
                res = ebi.verify_installed_binary(path)
        self.assertFalse(res["ok"])
        self.assertIn("mipsel", res["error"])
        run.assert_not_called()

    def test_enoexec_from_kernel_is_failure(self):
        path = self._write(ELF_MIPSEL)
        with mock.patch.object(ebi, "detect_arch", return_value="mipsel"):
            with mock.patch.object(ebi.subprocess, "run",
                                   side_effect=OSError(8, "Exec format error")):
                res = ebi.verify_installed_binary(path)
        self.assertFalse(res["ok"])

    def test_nonzero_exit_code_is_not_a_failure(self):
        """Многие движки отвечают rc=1 на неизвестный аргумент."""
        path = self._write(ELF_MIPSEL)
        with mock.patch.object(ebi, "detect_arch", return_value="mipsel"):
            with mock.patch.object(ebi.subprocess, "run",
                                   return_value=mock.Mock(returncode=1)):
                res = ebi.verify_installed_binary(path)
        self.assertTrue(res["ok"])


class TestUnpack(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_tar_gz_is_untarred_not_gunzipped(self):
        """`.tar.gz` тоже оканчивается на `.gz` — раньше побеждала ветка gz."""
        path = os.path.join(self.dir, "engine.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("engine")
            info.size = len(ELF_MIPSEL)
            tar.addfile(info, io.BytesIO(ELF_MIPSEL))
        out, tmp, err = ebi._unpack_if_needed(path)
        self.assertEqual(err, "")
        self.assertTrue(tmp)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), ELF_MIPSEL)

    def test_plain_gz_is_gunzipped(self):
        path = os.path.join(self.dir, "usque-4.2.1-mipsel-softfloat.gz")
        with open(path, "wb") as f:
            f.write(gzip.compress(ELF_MIPSEL))
        out, tmp, err = ebi._unpack_if_needed(path)
        self.assertEqual(err, "")
        self.assertTrue(tmp)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), ELF_MIPSEL)


class TestInstallBinaryFileRollback(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dest = os.path.join(self.dir, "usque")
        self.cfg = {"dest": self.dest, "version_args": ("version",)}

    def _src(self, data: bytes, name="new.bin") -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_working_binary_survives_broken_update(self):
        with open(self.dest, "wb") as f:
            f.write(b"OLD-WORKING")
        os.chmod(self.dest, 0o755)

        with mock.patch.object(ebi, "verify_installed_binary",
                               return_value={"ok": False,
                                             "error": "не запускается"}):
            res = ebi._install_binary_file(self.cfg, self._src(b"BROKEN"))

        self.assertFalse(res["ok"])
        self.assertTrue(res["exec_error"])
        self.assertTrue(res["restored"])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"OLD-WORKING")
        self.assertFalse(os.path.exists(self.dest + ".prev"))

    def test_broken_first_install_leaves_no_file(self):
        with mock.patch.object(ebi, "verify_installed_binary",
                               return_value={"ok": False, "error": "x"}):
            res = ebi._install_binary_file(self.cfg, self._src(b"BROKEN"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.exists(self.dest))

    def test_good_binary_replaces_and_cleans_backup(self):
        with open(self.dest, "wb") as f:
            f.write(b"OLD")
        with mock.patch.object(ebi, "verify_installed_binary",
                               return_value={"ok": True, "error": ""}):
            res = ebi._install_binary_file(self.cfg, self._src(b"NEW"))
        self.assertTrue(res["ok"])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"NEW")
        self.assertFalse(os.path.exists(self.dest + ".prev"))


class TestLocalUploadOfReleaseAsset(unittest.TestCase):
    """Скачал ассет на телефоне → загрузил в GUI: .gz должен распаковаться."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dest = os.path.join(self.dir, "usque")

    def test_uploaded_gz_is_unpacked(self):
        upload = os.path.join(self.dir, "upload.bin")   # имя от формы
        with open(upload, "wb") as f:
            f.write(gzip.compress(ELF_MIPSEL))

        cfg = {"install_kind": "binary", "dest": self.dest}
        with mock.patch.dict(ebi.BINARIES, {"usque": cfg}):
            with mock.patch.object(ebi, "verify_installed_binary",
                                   return_value={"ok": True, "error": ""}):
                with mock.patch.object(ebi, "_get_version",
                                       return_value="4.2.1"):
                    res = ebi.install_local_file(
                        "usque", upload,
                        orig_name="usque-4.2.1-mipsel-softfloat.gz")

        self.assertTrue(res["ok"], res.get("error"))
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), ELF_MIPSEL)

    def test_uploaded_gz_does_not_land_as_is(self):
        """Без распаковки файл был бы gzip'ом с правом на исполнение."""
        upload = os.path.join(self.dir, "upload.bin")
        payload = gzip.compress(ELF_MIPSEL)
        with open(upload, "wb") as f:
            f.write(payload)
        cfg = {"install_kind": "binary", "dest": self.dest}
        with mock.patch.dict(ebi.BINARIES, {"usque": cfg}):
            with mock.patch.object(ebi, "verify_installed_binary",
                                   return_value={"ok": True, "error": ""}):
                with mock.patch.object(ebi, "_get_version", return_value=""):
                    ebi.install_local_file("usque", upload,
                                           orig_name="usque-4.2.1-mipsel.gz")
        with open(self.dest, "rb") as f:
            self.assertNotEqual(f.read(), payload)


class TestManifestFallsBackWhenBuildDoesNotRun(unittest.TestCase):
    """Нерабочая наша сборка → уходим на запасной источник, а не в тупик."""

    def test_exec_error_returns_none_for_legacy_fallback(self):
        cfg = {"repo": "avatarDD/zapret-gui", "release_prefix": "usque-bin-",
               "manifest_asset": "manifest.json", "manifest_section": "usque",
               "dest": "/nonexistent/usque"}
        release = {"tag_name": "usque-bin-v4.2.1", "assets": []}
        entry = {"url": "https://example/usque.gz", "sha256": "ab",
                 "filename": "usque-4.2.1-mipsel-softfloat.gz",
                 "version": "4.2.1"}
        with mock.patch.object(ebi, "github_release_by_prefix",
                               return_value=release), \
             mock.patch.object(ebi, "_manifest_entry", return_value=entry), \
             mock.patch.object(ebi, "download_file", return_value=True), \
             mock.patch.object(ebi, "_sha256_file", return_value="ab"), \
             mock.patch.object(ebi, "_install_binary_file",
                               return_value={"ok": False, "exec_error": True,
                                             "error": "не запускается"}):
            res = ebi._install_from_manifest("usque", cfg, "mipsel", None, "")
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
