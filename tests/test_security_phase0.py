# tests/test_security_phase0.py
"""Тесты security-фиксов Фазы 0.

Покрывают:
  - core.safe_io: атомарная запись + распаковка с защитой от path-traversal;
  - hosts_manager.restore: отказ на traversal/вне BACKUP_DIR;
  - subscription_importer: блок SSRF-редиректа на внутренние адреса;
  - app.create_app: HTTP Basic-аутентификация + CSRF/Origin-гейт;
  - autostart_manager: shell-квотирование значений в S99-скрипте.
"""

import base64
import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

import core.config_manager as cm_mod
from core import safe_io


# ════════════════════════════════════════════════════════════
# safe_io
# ════════════════════════════════════════════════════════════

class TestAtomicWrite(unittest.TestCase):

    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_json_roundtrip(self):
        import json
        p = os.path.join(self.d, "sub", "settings.json")
        safe_io.atomic_write_json(p, {"a": 1, "b": [2, 3]})
        with open(p, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"a": 1, "b": [2, 3]})

    def test_no_tmp_leftovers(self):
        p = os.path.join(self.d, "x.json")
        safe_io.atomic_write_json(p, {"k": "v"})
        # После успешной записи временных .tmp-*.swp в каталоге нет.
        leftovers = [n for n in os.listdir(self.d) if n.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_overwrite_replaces(self):
        p = os.path.join(self.d, "x.txt")
        safe_io.atomic_write_text(p, "first")
        safe_io.atomic_write_text(p, "second")
        with open(p, encoding="utf-8") as f:
            self.assertEqual(f.read(), "second")


class TestSafeExtract(unittest.TestCase):

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.dest = os.path.join(self.d, "dest")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _tar(self, name, members):
        path = os.path.join(self.d, name)
        with tarfile.open(path, "w:gz") as tf:
            for mname, data in members:
                info = tarfile.TarInfo(mname)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return path

    def test_benign_tar_extracts(self):
        arch = self._tar("ok.tar.gz", [("bin/nfqws", b"ELF")])
        ok, err = safe_io.safe_extract_archive(arch, self.dest)
        self.assertTrue(ok, err)
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "bin", "nfqws")))

    def test_tar_traversal_rejected(self):
        arch = self._tar("evil.tar.gz", [("../evil.txt", b"pwn")])
        ok, err = safe_io.safe_extract_archive(arch, self.dest)
        self.assertFalse(ok)
        # Файл НЕ должен появиться выше dest.
        self.assertFalse(os.path.exists(os.path.join(self.d, "evil.txt")))

    def test_tar_absolute_rejected(self):
        arch = self._tar("abs.tar.gz", [("/abs.txt", b"x")])
        ok, _ = safe_io.safe_extract_archive(arch, self.dest)
        self.assertFalse(ok)

    def test_tar_symlink_escape_rejected(self):
        path = os.path.join(self.d, "lnk.tar.gz")
        with tarfile.open(path, "w:gz") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            tf.addfile(info)
        ok, _ = safe_io.safe_extract_archive(path, self.dest)
        self.assertFalse(ok)

    def test_zip_traversal_rejected(self):
        z = os.path.join(self.d, "evil.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../evil.txt", "pwn")
        ok, _ = safe_io.safe_extract_archive(z, self.dest)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(os.path.join(self.d, "evil.txt")))

    def test_member_name_helper(self):
        self.assertTrue(safe_io.is_safe_member_name("a/b/c"))
        self.assertFalse(safe_io.is_safe_member_name("../x"))
        self.assertFalse(safe_io.is_safe_member_name("/x"))
        self.assertFalse(safe_io.is_safe_member_name(""))


# ════════════════════════════════════════════════════════════
# hosts_manager.restore — path traversal
# ════════════════════════════════════════════════════════════

class TestHostsRestoreTraversal(unittest.TestCase):

    def setUp(self):
        from core.hosts_manager import get_hosts_manager
        self.mgr = get_hosts_manager()

    def test_traversal_rejected_without_write(self):
        # /tmp/../etc/passwd проходил старую startswith("/tmp/")-проверку.
        with mock.patch.object(self.mgr, "_write_file") as wf, \
             mock.patch.object(self.mgr, "backup") as bk:
            # Файл существует (любой реальный), но путь уводит из BACKUP_DIR.
            self.assertFalse(self.mgr.restore("/tmp/../etc/hosts"))
            wf.assert_not_called()
            bk.assert_not_called()

    def test_outside_backup_dir_rejected(self):
        with mock.patch.object(self.mgr, "_write_file") as wf:
            self.assertFalse(self.mgr.restore("/etc/hosts"))
            wf.assert_not_called()

    def test_wrong_name_rejected(self):
        # Реальный файл в /tmp, но имя не hosts.bak.* → отказ.
        fd, p = tempfile.mkstemp(dir="/tmp", prefix="notabackup-")
        os.close(fd)
        try:
            with mock.patch.object(self.mgr, "_write_file") as wf:
                self.assertFalse(self.mgr.restore(p))
                wf.assert_not_called()
        finally:
            os.remove(p)


# ════════════════════════════════════════════════════════════
# subscription_importer — SSRF redirect
# ════════════════════════════════════════════════════════════

class TestSubscriptionSSRF(unittest.TestCase):

    def test_internal_hosts_flagged(self):
        from core.subscription_importer import _host_is_internal
        for h in ("169.254.169.254", "127.0.0.1", "10.0.0.1",
                  "192.168.1.1", "::1", "0.0.0.0"):
            self.assertTrue(_host_is_internal(h), h)

    def test_public_hosts_allowed(self):
        from core.subscription_importer import _host_is_internal
        for h in ("8.8.8.8", "example.com", "github.com", ""):
            self.assertFalse(_host_is_internal(h), h)

    def test_redirect_to_internal_blocked(self):
        import urllib.error
        import urllib.request
        from core.subscription_importer import _SafeRedirectHandler
        h = _SafeRedirectHandler()
        req = urllib.request.Request("https://sub.example/list")
        with self.assertRaises(urllib.error.URLError):
            h.redirect_request(req, None, 302, "Found", {},
                               "http://169.254.169.254/latest/meta-data/")

    def test_redirect_to_bad_scheme_blocked(self):
        import urllib.error
        import urllib.request
        from core.subscription_importer import _SafeRedirectHandler
        h = _SafeRedirectHandler()
        req = urllib.request.Request("https://sub.example/list")
        with self.assertRaises(urllib.error.URLError):
            h.redirect_request(req, None, 302, "Found", {},
                               "file:///etc/passwd")


# ════════════════════════════════════════════════════════════
# app.create_app — auth + CSRF
# ════════════════════════════════════════════════════════════

def _call(app, method, path, *, headers=None):
    """Прогнать запрос через WSGI-приложение, поддержать кастомные заголовки."""
    from tests._wsgi_client import make_environ
    env = make_environ(method, path)
    for k, v in (headers or {}).items():
        env["HTTP_" + k.upper().replace("-", "_")] = v
    captured = {}

    def start_response(status, hdrs, exc_info=None):
        captured["status"] = status
        return lambda s: None

    body = app(env, start_response)
    try:
        list(body)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    return int(captured["status"].split(" ", 1)[0])


class _AppTestBase(unittest.TestCase):
    AUTH = False

    def setUp(self):
        from app import create_app
        self._saved_cm = cm_mod._config_manager
        self._tmp = tempfile.mkdtemp()
        self.app = create_app(self._tmp)        # пере-инициализирует синглтон
        cfg = cm_mod.get_config_manager()
        if self.AUTH:
            cfg.set("gui", "auth_enabled", True)
            cfg.set("gui", "auth_user", "admin")
            cfg.set("gui", "auth_password", "s3cret")

    def tearDown(self):
        cm_mod._config_manager = self._saved_cm  # восстановить глобальный
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestAuth(_AppTestBase):
    AUTH = True

    def test_no_credentials_401(self):
        self.assertEqual(_call(self.app, "GET", "/"), 401)

    def test_wrong_credentials_401(self):
        tok = base64.b64encode(b"admin:wrong").decode()
        code = _call(self.app, "GET", "/",
                     headers={"Authorization": "Basic " + tok})
        self.assertEqual(code, 401)

    def test_correct_credentials_pass(self):
        tok = base64.b64encode(b"admin:s3cret").decode()
        code = _call(self.app, "GET", "/",
                     headers={"Authorization": "Basic " + tok})
        self.assertNotEqual(code, 401)


class TestCsrf(_AppTestBase):
    AUTH = False

    def test_cross_origin_mutation_blocked(self):
        code = _call(self.app, "POST", "/api/does-not-exist",
                     headers={"Origin": "http://evil.example"})
        self.assertEqual(code, 403)

    def test_same_origin_mutation_allowed(self):
        # Host в make_environ = localhost → same-origin проходит гейт (404).
        code = _call(self.app, "POST", "/api/does-not-exist",
                     headers={"Origin": "http://localhost"})
        self.assertNotEqual(code, 403)

    def test_no_origin_mutation_allowed(self):
        code = _call(self.app, "POST", "/api/does-not-exist")
        self.assertNotEqual(code, 403)


# ════════════════════════════════════════════════════════════
# autostart_manager — инъекция в S99-скрипт
# ════════════════════════════════════════════════════════════

class TestAutostartInjection(unittest.TestCase):

    def setUp(self):
        self._saved_cm = cm_mod._config_manager
        self._tmp = tempfile.mkdtemp()
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self._tmp)

    def tearDown(self):
        cm_mod._config_manager = self._saved_cm
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _script(self):
        from core.autostart_manager import get_autostart_manager
        return get_autostart_manager()._generate_script()

    def _sh_n_ok(self, script):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("sh недоступен")
        import subprocess
        p = subprocess.run([sh, "-n"], input=script,
                           text=True, capture_output=True)
        return p.returncode == 0, p.stderr

    def test_malicious_ports_contained(self):
        # ports_tcp читается из конфига и попадает в присваивание PORTS_TCP=.
        cfg = cm_mod.get_config_manager()
        cfg.set("strategy", "current_id", "")
        cfg.set("nfqws", "ports_tcp", '80"; reboot; "443')
        script = self._script()
        ok, err = self._sh_n_ok(script)
        self.assertTrue(ok, err)
        # Строка PORTS_TCP=... должна быть ОДНИМ shell-токеном (нет инъекции).
        import shlex
        line = next(ln for ln in script.splitlines()
                    if ln.startswith("PORTS_TCP="))
        self.assertEqual(len(shlex.split(line)), 1, line)

    def test_malicious_strategy_name_confined_to_comment(self):
        cfg = cm_mod.get_config_manager()
        cfg.set("strategy", "current_id", "")
        cfg.set("strategy", "current_name", "evil\nreboot\n")
        script = self._script()
        ok, err = self._sh_n_ok(script)
        self.assertTrue(ok, err)
        # Перевод строки из имени не должен породить отдельную строку `reboot`.
        self.assertNotIn("\nreboot\n", script)


if __name__ == "__main__":
    unittest.main()
