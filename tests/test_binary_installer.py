# tests/test_binary_installer.py
"""
Unit-тесты для core/binary_installer.py.
"""

import hashlib
import os
import tarfile
import tempfile
import unittest
from unittest import mock

from core import binary_installer as bi


class TestSafePath(unittest.TestCase):

    def test_relative_ok(self):
        self.assertTrue(bi._is_safe_path("abc/def.txt"))
        self.assertTrue(bi._is_safe_path("nested/dir/file"))

    def test_absolute_blocked(self):
        self.assertFalse(bi._is_safe_path("/etc/passwd"))
        self.assertFalse(bi._is_safe_path("\\Windows\\System32"))

    def test_traversal_blocked(self):
        self.assertFalse(bi._is_safe_path("../etc/passwd"))
        self.assertFalse(bi._is_safe_path("abc/../../def"))


class TestSha256(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, "file.bin")
        with open(self.path, "wb") as f:
            f.write(b"hello world")
        self.expected = hashlib.sha256(b"hello world").hexdigest()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_compute(self):
        self.assertEqual(bi.sha256_of(self.path), self.expected)

    def test_verify_match(self):
        r = bi.verify_sha256(self.path, self.expected)
        self.assertTrue(r["ok"])

    def test_verify_mismatch(self):
        r = bi.verify_sha256(self.path, "wrong" + self.expected[5:])
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "sha256 mismatch")

    def test_verify_empty_expected_skipped(self):
        r = bi.verify_sha256(self.path, "")
        self.assertTrue(r["ok"])
        self.assertTrue(r["skipped"])

    def test_verify_case_insensitive(self):
        # Hex может приехать в верхнем регистре — проверка должна
        # быть case-insensitive.
        r = bi.verify_sha256(self.path, self.expected.upper())
        self.assertTrue(r["ok"])


class TestExtractTarball(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.archive = os.path.join(self.tmpdir, "test.tar.gz")
        # Создаём чистый архив
        with tarfile.open(self.archive, "w:gz") as tf:
            for name, body in (("bin/awg", b"binary"),
                               ("README", b"readme")):
                info = tarfile.TarInfo(name=name)
                info.size = len(body)
                import io
                tf.addfile(info, io.BytesIO(body))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extract_all(self):
        dest = os.path.join(self.tmpdir, "out")
        r = bi.extract_tarball(self.archive, dest)
        self.assertTrue(r["ok"])
        self.assertTrue(os.path.exists(os.path.join(dest, "bin", "awg")))
        self.assertTrue(os.path.exists(os.path.join(dest, "README")))

    def test_extract_filtered(self):
        dest = os.path.join(self.tmpdir, "out")
        r = bi.extract_tarball(
            self.archive, dest,
            members_filter=lambda m: m.name.startswith("bin/"))
        self.assertTrue(r["ok"])
        self.assertTrue(os.path.exists(os.path.join(dest, "bin", "awg")))
        self.assertFalse(os.path.exists(os.path.join(dest, "README")))

    def test_missing_archive(self):
        r = bi.extract_tarball("/nonexistent.tar.gz", self.tmpdir)
        self.assertFalse(r["ok"])

    def test_blocks_unsafe(self):
        evil_archive = os.path.join(self.tmpdir, "evil.tar.gz")
        with tarfile.open(evil_archive, "w:gz") as tf:
            info = tarfile.TarInfo(name="../../escape")
            info.size = 0
            import io
            tf.addfile(info, io.BytesIO(b""))
        r = bi.extract_tarball(evil_archive, self.tmpdir + "/out2")
        self.assertFalse(r["ok"])
        self.assertIn("небезопасн", r["error"])


class TestInstallBinary(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_install_fresh(self):
        src = os.path.join(self.tmpdir, "src", "awg")
        os.makedirs(os.path.dirname(src))
        with open(src, "wb") as f:
            f.write(b"fake-binary")
        dest = os.path.join(self.tmpdir, "dest", "awg")
        r = bi.install_binary(src, dest)
        self.assertTrue(r["ok"])
        self.assertTrue(os.access(dest, os.X_OK))

    def test_backup_old(self):
        src = os.path.join(self.tmpdir, "src", "awg")
        os.makedirs(os.path.dirname(src))
        with open(src, "wb") as f:
            f.write(b"new")
        dest = os.path.join(self.tmpdir, "dest", "awg")
        os.makedirs(os.path.dirname(dest))
        with open(dest, "wb") as f:
            f.write(b"old")
        r = bi.install_binary(src, dest, backup_old=True)
        self.assertTrue(r["ok"])
        self.assertTrue(os.path.exists(dest + ".bak"))
        with open(dest + ".bak", "rb") as f:
            self.assertEqual(f.read(), b"old")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b"new")

    def test_missing_src(self):
        r = bi.install_binary("/nonexistent",
                              os.path.join(self.tmpdir, "dest"))
        self.assertFalse(r["ok"])


class TestHumanSize(unittest.TestCase):

    def test_bytes(self):
        self.assertEqual(bi._human_size(500), "500 B")

    def test_kb(self):
        self.assertEqual(bi._human_size(1500), "1.5 KB")

    def test_mb(self):
        self.assertEqual(bi._human_size(5 * 1024 * 1024), "5.0 MB")


if __name__ == "__main__":
    unittest.main()


class TestResolveUrl(unittest.TestCase):
    GH = "https://github.com/owner/repo/releases/download/v1/asset.tar.gz"

    def test_no_mirror_passthrough(self):
        self.assertEqual(bi.resolve_url(self.GH, mirror=""), self.GH)

    def test_mirror_prefixes_github(self):
        out = bi.resolve_url(self.GH, mirror="https://mirror.example")
        self.assertEqual(out, "https://mirror.example/" + self.GH)

    def test_mirror_trailing_slash(self):
        out = bi.resolve_url(self.GH, mirror="https://mirror.example/")
        self.assertEqual(out, "https://mirror.example/" + self.GH)

    def test_non_github_untouched(self):
        url = "https://example.org/x.tar.gz"
        self.assertEqual(bi.resolve_url(url, mirror="https://mirror.example"),
                         url)

    def test_raw_githubusercontent_rewritten(self):
        url = "https://raw.githubusercontent.com/o/r/main/f"
        out = bi.resolve_url(url, mirror="https://m.example")
        self.assertTrue(out.startswith("https://m.example/https://raw."))

    def test_local_url_untouched(self):
        self.assertEqual(bi.resolve_url("file:///tmp/a.tar.gz",
                                        mirror="https://m"),
                         "file:///tmp/a.tar.gz")

    def test_env_mirror(self):
        with mock.patch.dict(os.environ,
                             {"ZAPRET_GUI_MIRROR": "https://envmirror"}):
            out = bi.resolve_url(self.GH)
        self.assertTrue(out.startswith("https://envmirror/"))


class TestIsLocalUrl(unittest.TestCase):

    def test_http_not_local(self):
        self.assertFalse(bi.is_local_url("https://x/y"))
        self.assertFalse(bi.is_local_url("http://x/y"))

    def test_file_scheme(self):
        self.assertTrue(bi.is_local_url("file:///tmp/a"))

    def test_plain_path(self):
        self.assertTrue(bi.is_local_url("/tmp/a.tar.gz"))

    def test_local_path_of(self):
        self.assertEqual(bi.local_path_of("file:///tmp/a"), "/tmp/a")
        self.assertEqual(bi.local_path_of("/tmp/b"), "/tmp/b")


class TestOfflineDownload(unittest.TestCase):

    def test_copy_local_file(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src.bin")
            with open(src, "wb") as f:
                f.write(b"hello-offline")
            dest = os.path.join(d, "out", "dest.bin")
            r = bi.download_file("file://" + src, dest)
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["size"], len(b"hello-offline"))
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"hello-offline")

    def test_copy_missing_local_file(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "dest.bin")
            r = bi.download_file("/nonexistent/path.bin", dest)
            self.assertFalse(r["ok"])


class TestWorkdir(unittest.TestCase):

    def test_disk_free_positive(self):
        # `/` на реальном роутере — read-only squashfs (f_bavail=0), поэтому
        # проверяем сам расчёт байт на замоканном statvfs, а не наличие места
        # на rootfs хоста (герметично на любой платформе).
        fake = mock.Mock(f_bavail=2048, f_frsize=4096)
        with mock.patch("os.statvfs", return_value=fake):
            self.assertEqual(bi.disk_free("/"), 2048 * 4096)

    def test_disk_free_nonexistent_walks_up(self):
        # Несуществующий путь → берём ближайшего существующего предка.
        self.assertGreaterEqual(bi.disk_free("/nonexistent/deep/path"), 0)

    def test_workbase_prefers_most_free(self):
        with tempfile.TemporaryDirectory() as big, \
             tempfile.TemporaryDirectory() as small:
            def fake_free(p):
                return 10_000 if os.path.abspath(p).startswith(
                    os.path.abspath(big)) else 10
            with mock.patch.dict(os.environ, {"ZAPRET_GUI_TMPDIR": big}), \
                 mock.patch.object(bi, "disk_free", fake_free):
                base = bi.workbase(near=small)
            self.assertEqual(os.path.abspath(base), os.path.abspath(big))

    def test_make_workdir_under_base(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(bi, "workbase", return_value=d):
                wd = bi.make_workdir(prefix="t-")
            self.assertTrue(os.path.isdir(wd))
            self.assertTrue(os.path.abspath(wd).startswith(os.path.abspath(d)))
            shutil.rmtree(wd, ignore_errors=True)
