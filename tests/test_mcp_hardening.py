# tests/test_mcp_hardening.py
"""
Сторожа находок ревью MCP-сервера: каждое правило здесь — дыра, которая
была и закрыта. Ослаблять их нельзя, не перечитав причину.

* **сравнение секрета — по байтам.** ``hmac.compare_digest`` на str с
  не-ASCII бросает ``TypeError``: кириллический пароль GUI не пускал
  никогда, а мусор в ``Authorization`` давал 500 вместо 401;
* **ответ «слишком много» действительно короткий.** Длинная строка
  верхнего уровня (текст конфига, файла) оставалась в нём целиком, и
  лимит ``response_kb`` не значил ничего;
* **валидатор схем:** ``NaN`` проходил любой диапазон, ``True``
  проходил ``enum: [1]``, а ``default`` отдавался по ссылке;
* **маска понимает JSON и YAML.** ``cat settings.json`` под одним
  ``shell_readonly`` отдавал MCP-токен и пароль GUI открытым текстом;
* **маску нельзя записать обратно** — прочитав ``***`` и сохранив текст
  целиком, модель уничтожала ключи;
* **аргументы стратегии не распоряжаются движком.** ``--qnum``/
  ``--user``/``--debug=@файл``/``--writable=<каталог>`` в стратегии —
  это сломанный перехват или запись и ``chown`` от root по любому пути
  (в том числе в «проверке» ``strategy_validate``);
* **``file_write`` пишет туда, где проверил границу**, а ``file_read``
  не виснет на FIFO и устройствах;
* **``snapshot_id`` самоправки сверяется с форматом**: ``../`` делал
  чужой ``manifest.json`` снимком со своим ``root``;
* **DNS-rebinding:** чужое имя, перепривязанное на адрес роутера, делало
  любой запрос «same-origin» — страница злоумышленника читала MCP-токен
  с панели и раздавала себе разрешения. Имя в ``Host`` обязано быть IP,
  localhost или объявленным в ``gui.allowed_hosts``.
"""

import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from unittest import mock

from core import strategy_lint
from core.mcp import auth, redact, registry, schema
from tests._shell_sandbox import Sandbox


class TestSecretCompare(unittest.TestCase):

    def test_non_ascii_does_not_raise(self):
        self.assertTrue(auth.secret_equal("пароль", "пароль"))
        self.assertFalse(auth.secret_equal("пароль", "парол"))
        self.assertFalse(auth.secret_equal("��", "abc"))
        self.assertFalse(auth.secret_equal(None, "abc"))

    def test_gui_password_in_cyrillic_lets_in(self):
        class Cfg:
            def get(self, section, key=None, default=None):
                return {"auth_enabled": True, "auth_password": "секрет",
                        "auth_user": "админ"}.get(key, default)

        with mock.patch("core.config_manager.get_config_manager",
                        return_value=Cfg()):
            self.assertTrue(auth._gui_auth_ok(("админ", "секрет")))
            self.assertFalse(auth._gui_auth_ok(("админ", "не тот")))


class TestTruncatedAnswer(unittest.TestCase):

    def test_long_string_does_not_survive_truncation(self):
        with mock.patch.object(registry, "_response_limit_bytes",
                               return_value=4096):
            result = registry.tool_result({"ok": True, "path": "/a",
                                           "content": "x" * 100000})
        text = result["content"][0]["text"]
        self.assertLess(len(text.encode("utf-8")), 4096)
        payload = result["structuredContent"]
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["dropped_fields"], ["content"])
        self.assertEqual(payload["path"], "/a")

    def test_mutating_tools_are_not_declared_harmless(self):
        # destructiveHint=false по спеке — «только добавляет», и клиент
        # вправе не спрашивать подтверждения. Среди мутирующих —
        # перезагрузка и удаление пакета.
        for spec in registry.all_tools():
            with self.subTest(tool=spec.name):
                hints = spec.to_wire()["annotations"]
                self.assertEqual(hints["destructiveHint"], spec.mutating)

    def test_concurrent_first_load_sees_the_whole_registry(self):
        total = len(registry.all_tools())
        seen = []
        saved = registry._loaded
        registry._loaded = False
        try:
            threads = [threading.Thread(
                target=lambda: seen.append(len(registry.all_tools())))
                for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
        finally:
            registry._loaded = saved or registry._loaded
        self.assertEqual(seen, [total] * 4)


class TestSchema(unittest.TestCase):

    NUMBER = {"type": "object",
              "properties": {"a": {"type": "number", "minimum": 0,
                                   "maximum": 5}}}

    def test_nan_and_infinity_are_not_numbers(self):
        for text in ('{"a": NaN}', '{"a": Infinity}'):
            with self.subTest(value=text):
                with self.assertRaises(schema.SchemaError):
                    schema.validate(json.loads(text), self.NUMBER)

    def test_bool_is_not_an_enum_number(self):
        with self.assertRaises(schema.SchemaError):
            schema.validate(True, {"enum": [1, 2]})
        with self.assertRaises(schema.SchemaError):
            schema.validate(1, {"enum": [True]})
        self.assertEqual(schema.validate(1, {"enum": [1, 2]}), 1)

    def test_default_is_a_copy(self):
        spec = {"type": "object",
                "properties": {"items": {"type": "array", "default": []}}}
        first = schema.validate({}, spec)
        first["items"].append("мусор")
        self.assertEqual(spec["properties"]["items"]["default"], [])
        self.assertEqual(schema.validate({}, spec)["items"], [])


class TestTextMask(unittest.TestCase):

    def test_json_config_leaks_nothing(self):
        text = json.dumps({
            "mcp": {"token": "deadbeef" * 8, "enabled": True,
                    "confirm_token": "ярлык"},
            "gui": {"auth_password": "admin123", "auth_enabled": True,
                    "host": "192.168.1.1"},
            "outbounds": [{"uuid": "1111-2222", "server": "a.example",
                           "with_bypass": "ok"}],
        }, ensure_ascii=False)
        clean = redact.redact_text(text)
        for secret in ("deadbeef", "admin123", "1111-2222"):
            self.assertNotIn(secret, clean)
        # Рабочие данные и флаги целы, как у структурной маски.
        for kept in ("192.168.1.1", "a.example", "ярлык", '"with_bypass"'):
            self.assertIn(kept, clean)
        self.assertEqual(json.loads(clean)["gui"]["auth_enabled"], True)

    def test_yaml_config_leaks_nothing(self):
        text = ("proxies:\n"
                "  - name: n1\n"
                "    uuid: 1111-2222\n"
                "    password: \"p@ss w\"   # коммент\n"
                "    private-key: AAAA\n"
                "    auth: true\n"
                "    server: 1.2.3.4\n")
        clean = redact.redact_text(text)
        for secret in ("1111-2222", "p@ss w", "AAAA"):
            self.assertNotIn(secret, clean)
        for kept in ("auth: true", "server: 1.2.3.4", "name: n1"):
            self.assertIn(kept, clean)

    def test_proxy_links_lose_their_credentials(self):
        clean = redact.redact_text(
            "vless://1111-2222@h.example:443?sni=x trojan://pw@h:1")
        self.assertNotIn("1111-2222", clean)
        self.assertNotIn("pw@", clean)
        self.assertIn("h.example:443", clean)

    def test_strategy_args_are_untouched(self):
        args = "--lua-desync=fake:blob=tls_google:tcp_md5 --filter-tcp=443"
        self.assertEqual(redact.redact_text(args), args)

    def test_cat_settings_under_shell_readonly(self):
        box = Sandbox(self, {"shell_readonly": True})
        path = box.write("settings.json", json.dumps(
            {"mcp": {"token": "cafebabe" * 8},
             "gui": {"auth_password": "hunter2"}}))
        read = box.data("file_read", {"path": path},
                        {"shell_readonly": True})
        self.assertNotIn("cafebabe", read["content"])
        self.assertNotIn("hunter2", read["content"])


class TestMaskIsNotWrittenBack(unittest.TestCase):

    def test_rule(self):
        self.assertTrue(redact.mask_written_back("key = ***", "key = abc"))
        self.assertTrue(redact.mask_written_back("key = ***", None))
        # Маска была и раньше — это содержимое, а не наш след.
        self.assertFalse(redact.mask_written_back("a *** b", "a *** c"))
        self.assertFalse(redact.mask_written_back("key = abc", "key = x"))

    def test_file_write_refuses_the_mask(self):
        box = Sandbox(self, {"shell_full": True})
        path = box.write("wg.conf", "PrivateKey = REAL\n")
        answer = box.data("file_write",
                          {"path": path, "content": "PrivateKey = ***\n"},
                          {"shell_full": True})
        self.assertFalse(answer["ok"])
        self.assertIn("raw=true", answer["hint"])
        self.assertEqual(box.read(path), "PrivateKey = REAL\n")

    def test_tunnel_config_save_refuses_the_mask(self):
        from core import tunnels_control

        saved = []
        with mock.patch.object(tunnels_control, "config_get",
                               return_value={"text": "PrivateKey = REAL"}), \
             mock.patch.object(tunnels_control, "config_save",
                               side_effect=lambda *a: saved.append(a)):
            answer = registry.call("tunnel_config_save", {
                "engine": "awg", "name": "wg0",
                "text": "PrivateKey = ***"}, {"tunnels_write": True})
        self.assertTrue(answer["isError"])
        self.assertEqual(saved, [])


class TestStrategyCannotOwnTheEngine(unittest.TestCase):

    def setUp(self):
        self.lists = tempfile.mkdtemp(prefix="lists-")
        self.addCleanup(shutil.rmtree, self.lists, ignore_errors=True)

    def _compose(self, strategy):
        from core.nfqws_manager import NFQWSManager

        lists = self.lists

        class Cfg:
            def get(self, section, key=None, default=None):
                if (section, key) == ("zapret", "lists_path"):
                    return lists
                if (section, key) == ("interfaces", "wan"):
                    return "eth0"
                return default

        mgr = NFQWSManager.__new__(NFQWSManager)
        return mgr.compose_command(strategy, binary="/bin/nfqws2",
                                   cfg=Cfg())

    def test_owned_options_do_not_reach_the_engine(self):
        argv = self._compose([
            "--filter-tcp=443", "--qnum=1", "--user=root", "--uid=0:0",
            "--fwmark=0x1", "--pidfile=/etc/shadow", "--daemon",
            "--writable=/etc", "--debug=@/etc/passwd",
            "--lua-desync=fake:blob=x"])
        joined = " ".join(argv)
        for bad in ("--qnum=1", "--user=root", "--uid=0:0", "--fwmark=0x1",
                    "/etc/shadow", "--daemon", "--writable=/etc",
                    "/etc/passwd"):
            self.assertNotIn(bad, joined)
        # Базовые значения GUI на месте, приём — тоже.
        self.assertIn("--qnum=300", argv)
        self.assertIn("--user=nobody", argv)
        self.assertIn("--lua-desync=fake:blob=x", argv)

    def test_harmless_debug_stays(self):
        argv = self._compose(["--debug=syslog", "--lua-desync=fake"])
        self.assertIn("--debug=syslog", argv)

    def test_autohostlist_only_inside_list_dirs(self):
        argv = self._compose([
            "--hostlist-auto=/etc/shadow",
            "--hostlist-auto=%s/auto.txt" % self.lists,
            "--lua-desync=fake"])
        self.assertNotIn("--hostlist-auto=/etc/shadow", argv)
        self.assertIn("--hostlist-auto=%s/auto.txt" % self.lists, argv)

    def test_two_token_form_is_cut_with_its_value(self):
        # getopt_long nfqws2 принимает `--pidfile /путь` двумя токенами,
        # а стратегия из текста режется по пробелам.
        argv = self._compose([
            "--filter-tcp=443", "--qnum", "1", "--pidfile", "/etc/shadow",
            "--user", "root", "--lua-desync=fake"])
        for bad in ("1", "/etc/shadow", "root", "--pidfile"):
            self.assertNotIn(bad, argv)
        self.assertEqual(argv.count("--qnum=300"), 1)
        self.assertIn("--lua-desync=fake", argv)

    def test_two_token_autohostlist_is_checked_too(self):
        argv = self._compose([
            "--hostlist-auto", "/etc/nologin",
            "--hostlist-auto", "%s/auto.txt" % self.lists,
            "--lua-desync=fake"])
        self.assertNotIn("/etc/nologin", argv)
        i = argv.index("%s/auto.txt" % self.lists)
        self.assertEqual(argv[i - 1], "--hostlist-auto")

    def test_linter_names_it(self):
        found = strategy_lint.lint(["--filter-tcp=443", "--qnum=5",
                                    "--lua-desync=fake"])
        codes = [f["code"] for f in found]
        self.assertIn(strategy_lint.CODE_ENGINE_OPTION, codes)
        self.assertTrue(strategy_lint.summary(found)["blocking"])

    def test_missing_list_outside_roots_is_not_created(self):
        from core.nfqws_manager import NFQWSManager

        base = tempfile.mkdtemp(prefix="roots-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        inside = os.path.join(base, "in", "list.txt")
        outside = os.path.join(base, "out", "nologin")
        NFQWSManager._ensure_list_files(
            ["--hostlist=%s" % inside, "--hostlist=%s" % outside],
            [os.path.realpath(os.path.join(base, "in"))])
        self.assertTrue(os.path.exists(inside))
        self.assertFalse(os.path.exists(outside))


class TestFiles(unittest.TestCase):

    def test_write_lands_where_the_boundary_was_checked(self):
        box = Sandbox(self, {"shell_full": True})
        target = box.write("real.conf", "old\n")
        outside = tempfile.mkdtemp(prefix="outside-")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        # Ссылка ВНЕ разрешённых каталогов на файл ВНУТРИ них: граница
        # по realpath пройдена — и писать надо в цель, а не поверх
        # ссылки, которая лежит снаружи.
        link = os.path.join(outside, "link.conf")
        os.symlink(target, link)
        answer = box.data("file_write", {"path": link, "content": "new\n"},
                          {"shell_full": True})
        self.assertTrue(answer["ok"], answer)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(box.read(target), "new\n")

    def test_protected_name_behind_a_symlink(self):
        box = Sandbox(self, {"shell_full": True})
        settings = box.write("settings.json", "{}")
        link = box.path("harmless.txt")
        os.symlink(settings, link)
        answer = box.data("file_write", {"path": link, "content": "x"},
                          {"shell_full": True})
        self.assertFalse(answer["ok"])
        self.assertEqual(box.read(settings), "{}")

    def test_fifo_is_not_read(self):
        box = Sandbox(self, {"shell_readonly": True})
        fifo = box.path("pipe")
        os.mkfifo(fifo)
        self.assertTrue(stat.S_ISFIFO(os.stat(fifo).st_mode))
        answer = box.data("file_read", {"path": fifo},
                          {"shell_readonly": True})
        self.assertFalse(answer["ok"])
        self.assertIn("FIFO", answer["error"])


class TestSnapshotId(unittest.TestCase):

    def test_traversal_is_not_a_snapshot(self):
        from core import code_editor

        for bad in ("../../etc", "snap-20260101-000000/../../x", ""):
            with self.subTest(snapshot_id=bad):
                self.assertIsNone(code_editor.read_manifest(bad))
                self.assertIsNone(code_editor.snapshot_bytes(bad, "a.py"))
                with self.assertRaises(ValueError):
                    code_editor.snapshot_path(bad)
        self.assertTrue(code_editor.snapshot_path(
            "snap-20260101-000000-2").endswith("snap-20260101-000000-2"))


class TestHostGuard(unittest.TestCase):

    def test_ip_and_localhost_pass(self):
        from core.host_guard import host_allowed

        for host in ("192.168.1.1", "192.168.1.1:8080", "[::1]:8080",
                     "fe80::1", "localhost:8080", "gui.localhost", ""):
            with self.subTest(host=host):
                self.assertTrue(host_allowed(host))

    def test_foreign_name_is_refused(self):
        from core.host_guard import host_allowed

        for host in ("evil.example", "evil.example:8080",
                     "my.keenetic.net:8080", "localhost.evil.example"):
            with self.subTest(host=host):
                self.assertFalse(host_allowed(host))

    def test_declared_names_pass(self):
        from core.host_guard import host_allowed

        self.assertTrue(host_allowed("My.Keenetic.Net:8080",
                                     ["my.keenetic.net"]))
        self.assertTrue(host_allowed("dash.example",
                                     cors_origins=["https://dash.example"]))
        self.assertTrue(host_allowed("anything.example", ["*"]))


class TestHostGuardInTheApp(unittest.TestCase):
    """Гейт приложения целиком: rebinding не доходит ни до панели MCP."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        from tests._wsgi_client import WSGIClient

        cls.client = WSGIClient(app_module.create_app())

    def tearDown(self):
        from core.config_manager import get_config_manager
        get_config_manager().set("gui", "allowed_hosts", [])

    def test_rebound_name_cannot_read_the_panel(self):
        code, _, _ = self.client.request(
            "GET", "/api/mcp/ui/token",
            headers={"Host": "evil.example:8080"})
        self.assertEqual(code, 403)

    def test_ip_still_works(self):
        code, _, _ = self.client.request(
            "GET", "/api/status", headers={"Host": "192.168.1.1:8080"})
        self.assertEqual(code, 200)

    def test_declared_name_works(self):
        from core.config_manager import get_config_manager

        get_config_manager().set("gui", "allowed_hosts",
                                 ["my.keenetic.net"])
        code, _, _ = self.client.request(
            "GET", "/api/status", headers={"Host": "my.keenetic.net:8080"})
        self.assertEqual(code, 200)


if __name__ == "__main__":
    unittest.main()
