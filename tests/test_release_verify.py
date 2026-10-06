"""Проверка выпуска GUI (SHA256SUMS) и сторож отката (приём d2k)."""

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

    def test_good(self):
        res = rv.decide(self.SHA, self.sums())
        self.assertTrue(res["ok"] and res["integrity"])

    def test_hash_mismatch_refused(self):
        res = rv.decide("b" * 64, self.sums())
        self.assertFalse(res["ok"])
        self.assertIn("хеш", res["message"])

    def test_old_release_without_sums(self):
        res = rv.decide("", {})
        self.assertTrue(res["ok"])
        self.assertFalse(res["integrity"])
        self.assertTrue(res["warnings"])

    def test_sums_without_our_archive(self):
        self.assertFalse(rv.decide(self.SHA, {"other": self.SHA})["ok"])


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
            with open(dest, "wb") as f:
                f.write(archive)
            return True

        with mock.patch.object(up, "_download_file", side_effect=fake_dl), \
                mock.patch.object(up, "_resolve_latest_tag",
                                  return_value="v9.9.9"), \
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
