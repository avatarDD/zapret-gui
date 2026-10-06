"""Проверка выпуска GUI (SHA256SUMS + Ed25519) и сторож отката (приём d2k)."""

import hashlib
import io
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from core import gui_updater, release_verify as rv


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestDecide(unittest.TestCase):

    SHA = "a" * 64

    def sums(self, sha=None):
        return {rv.ARCHIVE_NAME: sha or self.SHA}

    def test_parse_sums(self):
        text = "%s  zapret-gui-linux.tar.gz\n%s *dist/x.ipk\nмусор\n" % (
            "A" * 64, "b" * 64)
        self.assertEqual(rv.parse_sums(text),
                         {"zapret-gui-linux.tar.gz": "a" * 64,
                          "x.ipk": "b" * 64})

    def test_good_and_signed(self):
        res = rv.decide(self.SHA, self.sums(), (True, "ключ №1"))
        self.assertTrue(res["ok"] and res["integrity"] and res["authentic"])

    def test_hash_mismatch_refused(self):
        res = rv.decide("b" * 64, self.sums(), (True, "x"))
        self.assertFalse(res["ok"])
        self.assertIn("хеш", res["message"])

    def test_bad_signature_refused(self):
        res = rv.decide(self.SHA, self.sums(), (False, "не сходится"))
        self.assertFalse(res["ok"])
        self.assertTrue(res["integrity"])

    def test_unverifiable_signature_auto_vs_require(self):
        auto = rv.decide(self.SHA, self.sums(), (None, "нет ключа"))
        self.assertTrue(auto["ok"])
        self.assertFalse(auto["authentic"])
        self.assertTrue(auto["warnings"])
        req = rv.decide(self.SHA, self.sums(), (None, "нет ключа"),
                        rv.MODE_REQUIRE)
        self.assertFalse(req["ok"])

    def test_old_release_without_sums(self):
        self.assertTrue(rv.decide("", {}, (None, ""))["ok"])
        self.assertFalse(rv.decide("", {}, (None, ""),
                                   rv.MODE_REQUIRE)["ok"])

    def test_sums_without_our_archive(self):
        self.assertFalse(rv.decide(self.SHA, {"other": self.SHA},
                                   (None, ""))["ok"])

    def test_mode(self):
        cfg = mock.Mock()
        cfg.get.return_value = "require"
        self.assertEqual(rv.mode(cfg), rv.MODE_REQUIRE)
        cfg.get.return_value = "что-то"
        self.assertEqual(rv.mode(cfg), rv.MODE_AUTO)


def _openssl_ed25519():
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    r = subprocess.run([openssl, "genpkey", "-algorithm", "ed25519"],
                       capture_output=True)
    return r.returncode == 0


@unittest.skipUnless(_openssl_ed25519(), "нет openssl с Ed25519")
class TestSignature(unittest.TestCase):
    """Подпись проверяется тем же путём, что и на роутере (openssl)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sig-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.key = os.path.join(self.dir, "release.key")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                        "-out", self.key], check=True, capture_output=True)
        self.pub = subprocess.run(
            ["openssl", "pkey", "-in", self.key, "-pubout"],
            check=True, capture_output=True, text=True).stdout
        self.sums = os.path.join(self.dir, rv.SUMS_NAME)
        with open(self.sums, "w") as f:
            f.write("%s  %s\n" % ("c" * 64, rv.ARCHIVE_NAME))
        self.sig = os.path.join(self.dir, rv.SIG_NAME)
        # Так же подписывает release.yml.
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self.key,
                        "-rawin", "-in", self.sums, "-out", self.sig],
                       check=True, capture_output=True)

    def test_valid(self):
        ok, why = rv.verify_signature(self.sums, self.sig, [self.pub])
        self.assertTrue(ok, why)

    def test_tampered(self):
        with open(self.sums, "a") as f:
            f.write("%s  evil\n" % ("d" * 64))
        self.assertIs(rv.verify_signature(self.sums, self.sig,
                                          [self.pub])[0], False)

    def test_other_key(self):
        other = os.path.join(self.dir, "other.key")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                        "-out", other], check=True, capture_output=True)
        pub = subprocess.run(["openssl", "pkey", "-in", other, "-pubout"],
                             check=True, capture_output=True,
                             text=True).stdout
        self.assertIs(rv.verify_signature(self.sums, self.sig, [pub])[0],
                      False)
        # Ротация ключа: подходит любой из закреплённых.
        self.assertTrue(rv.verify_signature(self.sums, self.sig,
                                            [pub, self.pub])[0])

    def test_nothing_to_verify_with(self):
        self.assertIsNone(rv.verify_signature(self.sums, self.sig, [])[0])
        self.assertIsNone(rv.verify_signature(self.sums, "", [self.pub])[0])


def _archive_bytes(version="9.9.9"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = ('GUI_VERSION = "%s"\n' % version).encode()
        info = tarfile.TarInfo("zapret-gui/core/version.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestUpdaterUsesReleaseSums(unittest.TestCase):
    """Выпуск с SHA256SUMS ставится ЕГО архивом и только при совпадении."""

    def _run(self, archive, sums_text):
        up = gui_updater.GuiUpdater()
        fetched = []

        def fake_dl(url, dest, transport="", quiet=False):
            fetched.append(url)
            if url.endswith("/SHA256SUMS"):
                with open(dest, "w") as f:
                    f.write(sums_text)
                return True
            if url.endswith(".sig"):
                return False
            with open(dest, "wb") as f:
                f.write(archive)
            return True

        with mock.patch.object(up, "_download_file", side_effect=fake_dl), \
                mock.patch.object(up, "_resolve_latest_tag",
                                  return_value="v9.9.9"), \
                mock.patch.object(rv, "PUBLIC_KEYS", ()), \
                mock.patch.object(up, "_replace_dir",
                                  side_effect=AssertionError("ставит")):
            result = up._do_update()
        return result, fetched

    def test_mismatch_is_refused_before_install(self):
        result, fetched = self._run(
            _archive_bytes(), "%s  %s\n" % ("0" * 64, rv.ARCHIVE_NAME))
        self.assertFalse(result["ok"])
        self.assertIn("хеш", result["message"])
        self.assertTrue(any(u.endswith("/releases/download/v9.9.9/"
                                       + rv.ARCHIVE_NAME) for u in fetched))


class TestRollbackScript(unittest.TestCase):
    """Сгенерированный сторож: жив — копию убрать, мёртв — вернуть."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="rollback-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.app = os.path.join(self.root, "app")
        self.backup = os.path.join(self.root, "app.rollback-1")
        for base, tag in ((self.app, "new"), (self.backup, "old")):
            os.makedirs(os.path.join(base, "core"))
            with open(os.path.join(base, "core", "v.txt"), "w") as f:
                f.write(tag)
            with open(os.path.join(base, "app.py"), "w") as f:
                f.write(tag)
        self.restarted = os.path.join(self.root, "restarted")

    def _run(self, url):
        script = gui_updater.build_rollback_script(
            app_dir=self.app, backup=self.backup, dirs=["core", "api"],
            files=["app.py"], restart_cmd="touch %s" % self.restarted,
            url=url, python="python3", wait=0, from_version="1.0",
            to_version="1.1", retries=1, retry_pause=0)
        path = os.path.join(self.backup, "rollback.sh")
        with open(path, "w") as f:
            f.write(script)
        subprocess.run(["sh", path], check=True, timeout=60)

    def _read(self, *parts):
        with open(os.path.join(*parts)) as f:
            return f.read()

    @unittest.skipUnless(shutil.which("sh") and shutil.which("python3"),
                         "нет sh/python3")
    def test_dead_gui_is_rolled_back(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()                 # порт закрыт: GUI «не поднялся»
        self._run("http://127.0.0.1:%d/api/ping" % port)
        self.assertEqual(self._read(self.app, "core", "v.txt"), "old")
        self.assertEqual(self._read(self.app, "app.py"), "old")
        self.assertTrue(os.path.exists(self.restarted))
        self.assertFalse(os.path.exists(self.backup))
        mark = gui_updater.last_rollback(self.app)
        self.assertEqual(mark["from"], "1.1")
        self.assertEqual(mark["to"], "1.0")

    @unittest.skipUnless(shutil.which("sh") and shutil.which("python3"),
                         "нет sh/python3")
    def test_live_gui_keeps_new_version(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # 401 — это тоже «жив»: авторизация включена.
                self.send_response(401)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self._run("http://127.0.0.1:%d/api/ping" % server.server_port)
        self.assertEqual(self._read(self.app, "core", "v.txt"), "new")
        self.assertFalse(os.path.exists(self.restarted))
        self.assertFalse(os.path.exists(self.backup))
        self.assertEqual(gui_updater.last_rollback(self.app), {})


if __name__ == "__main__":
    unittest.main()
