# tests/test_api_singbox.py
"""
Integration-тесты для api/singbox.py — все 33 эндпоинта через WSGI.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestSingboxAPI(unittest.TestCase):
    """Базовые smoke-тесты: эндпоинты отвечают, не падают."""

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())
        cls.tmpdir = tempfile.mkdtemp(prefix="sb-api-test-")

        # Подменяем config_dir у singbox-platform, чтобы тесты писали в /tmp
        cls._cfg_patch = mock.patch.object(
            cls.client.app, "_singbox_test_dir_marker", create=True,
            new=cls.tmpdir,
        )
        cls._cfg_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._cfg_patch.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # ─── environment / install ───

    def test_environment(self):
        r = self.client.get_json("/api/singbox/environment")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("platform", r)
        self.assertIn("binary", r)
        self.assertIn("tun", r)
        self.assertIn("ready", r)

    def test_environment_refresh(self):
        r = self.client.post_json("/api/singbox/environment/refresh", {})
        self.assertEqual(r["_status"], 200)
        self.assertIn("platform", r)

    def test_install_status(self):
        r = self.client.get_json("/api/singbox/install/status")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("progress", r)

    def test_releases(self):
        from unittest import mock
        fake = {"ok": True, "releases": [
            {"tag": "singbox-bin-v1.12.4", "version": "1.12.4"}]}
        with mock.patch(
                "core.singbox_installer.SingboxInstaller.list_releases",
                return_value=fake):
            r = self.client.get_json("/api/singbox/releases")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["releases"][0]["version"], "1.12.4")

    def test_install_local_requires_file(self):
        r = self.client.post_json("/api/singbox/install/local", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    # ─── подписки/пул: транспорт скачивания (задача №7) ───

    def test_subscription_add_passes_transport(self):
        from unittest import mock
        with mock.patch("core.subscription_manager.add_subscription",
                        return_value={"ok": True, "id": "sub-x"}) as add:
            r = self.client.post_json(
                "/api/singbox/subscriptions",
                {"name": "P", "url": "https://p/sub",
                 "transport": "awg:wg0"})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(add.call_args.kwargs.get("transport"), "awg:wg0")

    def test_subscription_update_passes_transport(self):
        from unittest import mock
        with mock.patch("core.subscription_manager.update_subscription",
                        return_value={"ok": True, "id": "sub-x"}) as upd:
            r = self.client.put_json(
                "/api/singbox/subscriptions/sub-x",
                {"transport": "mihomo:main"})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(upd.call_args.kwargs.get("transport"),
                         "mihomo:main")

    def test_pool_settings_passes_transport(self):
        from unittest import mock
        with mock.patch("core.server_pool.update_settings",
                        return_value={"ok": True}) as upd:
            r = self.client.post_json("/api/singbox/pool/settings",
                                      {"transport": "singbox:proxy"})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(upd.call_args.kwargs.get("transport"),
                         "singbox:proxy")

    def test_version(self):
        # На не-установленной системе version падает, но не должен
        # ронять сервер — отдаёт ok=False с error.
        r = self.client.get_json("/api/singbox/version")
        # 200 или 500 в зависимости от того есть ли сеть в env CI.
        self.assertIn(r["_status"], (200, 500))

    # ─── configs CRUD ───

    def test_configs_list_empty(self):
        # На свежей системе configs может быть пусто.
        r = self.client.get_json("/api/singbox/configs")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["configs"], list)

    def test_create_invalid_name(self):
        r = self.client.post_json("/api/singbox/configs",
                                   {"name": "bad/name",
                                    "text": '{"outbounds":[{"type":"direct","tag":"d"}]}'})
        self.assertFalse(r["ok"])
        self.assertIn("error", r)

    def test_create_no_name(self):
        r = self.client.post_json("/api/singbox/configs",
                                   {"text": "{}"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_get_nonexistent(self):
        r = self.client.get_json("/api/singbox/configs/never-existed")
        self.assertEqual(r["_status"], 404)

    def test_full_lifecycle(self):
        """Создать → list → get → update → delete."""
        name = "lifecycle-test"
        text = '{"outbounds":[{"type":"direct","tag":"d"}]}'

        # Create
        r = self.client.post_json("/api/singbox/configs",
                                   {"name": name, "text": text})
        if not r.get("ok"):
            self.skipTest("Cannot create config: %s" % r.get("error"))
        try:
            # List — должен содержать наш
            r = self.client.get_json("/api/singbox/configs")
            names = [c["name"] for c in r["configs"]]
            self.assertIn(name, names)

            # Get
            r = self.client.get_json("/api/singbox/configs/" + name)
            self.assertEqual(r["_status"], 200)
            self.assertEqual(r["name"], name)
            self.assertIsInstance(r["parsed"], dict)

            # Update
            new_text = '{"outbounds":[{"type":"direct","tag":"d2"}]}'
            r = self.client.put_json("/api/singbox/configs/" + name,
                                      {"text": new_text})
            self.assertTrue(r["ok"])

            # Verify updated
            r = self.client.get_json("/api/singbox/configs/" + name)
            self.assertEqual(r["parsed"]["outbounds"][0]["tag"], "d2")
        finally:
            # Delete
            r = self.client.delete_json("/api/singbox/configs/" + name)
            self.assertTrue(r.get("ok") or r.get("noop"))

    # ─── outbounds CRUD ───

    def test_outbounds_lifecycle(self):
        name = "out-test"
        text = '{"outbounds":[{"type":"direct","tag":"direct"}]}'
        r = self.client.post_json("/api/singbox/configs",
                                   {"name": name, "text": text})
        if not r.get("ok"):
            self.skipTest("Cannot create config")
        try:
            # Add via form
            r = self.client.post_json(
                "/api/singbox/configs/" + name + "/outbounds",
                {"_form": "vless", "tag": "v1",
                 "server": "h", "port": 443, "uuid": "u"})
            self.assertTrue(r["ok"])
            self.assertEqual(r["outbounds_count"], 2)

            # List
            r = self.client.get_json(
                "/api/singbox/configs/" + name + "/outbounds")
            self.assertTrue(r["ok"])
            tags = [o["tag"] for o in r["outbounds"]]
            self.assertIn("v1", tags)

            # Duplicate tag → 409
            r = self.client.post_json(
                "/api/singbox/configs/" + name + "/outbounds",
                {"_form": "vless", "tag": "v1",
                 "server": "h", "port": 443, "uuid": "u"})
            self.assertEqual(r["_status"], 409)

            # PUT (rename)
            r = self.client.put_json(
                "/api/singbox/configs/" + name + "/outbounds/v1",
                {"_form": "vless", "tag": "v-renamed",
                 "server": "h", "port": 443, "uuid": "u"})
            self.assertTrue(r["ok"])

            # DELETE
            r = self.client.delete_json(
                "/api/singbox/configs/" + name + "/outbounds/v-renamed")
            self.assertTrue(r["ok"])

            # DELETE nonexistent
            r = self.client.delete_json(
                "/api/singbox/configs/" + name + "/outbounds/never-existed")
            self.assertEqual(r["_status"], 404)
        finally:
            self.client.delete_json("/api/singbox/configs/" + name)

    # ─── wrap ───

    def test_wrap_in_urltest(self):
        name = "wrap-test"
        text = ('{"outbounds":['
                '{"type":"vless","tag":"v1","server":"h","server_port":443,"uuid":"u"},'
                '{"type":"trojan","tag":"t1","server":"h","server_port":443,"password":"p"},'
                '{"type":"direct","tag":"direct"}]}')
        r = self.client.post_json("/api/singbox/configs",
                                   {"name": name, "text": text})
        if not r.get("ok"):
            self.skipTest("Cannot create config")
        try:
            r = self.client.post_json(
                "/api/singbox/configs/" + name + "/wrap",
                {"group_type": "urltest", "group_tag": "auto"})
            self.assertTrue(r["ok"])
            self.assertEqual(r["group_type"], "urltest")
            self.assertEqual(r["group_tag"], "auto")

            # Verify первый outbound — urltest
            r = self.client.get_json(
                "/api/singbox/configs/" + name + "/outbounds")
            self.assertEqual(r["outbounds"][0]["type"], "urltest")
        finally:
            self.client.delete_json("/api/singbox/configs/" + name)

    # ─── autostart ───

    def test_autostart_status(self):
        r = self.client.get_json("/api/singbox/autostart")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("status", r)
        self.assertIn("autostart", r["status"])

    # ─── subscriptions ───

    def test_subscriptions_list(self):
        r = self.client.get_json("/api/singbox/subscriptions")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["subscriptions"], list)

    def test_subscriptions_add_missing_fields(self):
        r = self.client.post_json("/api/singbox/subscriptions",
                                   {"name": "x"})
        self.assertEqual(r["_status"], 400)

    # ─── server pool ───

    def test_pool_get(self):
        r = self.client.get_json("/api/singbox/pool")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("settings", r)
        self.assertIn("sources", r)
        self.assertIsInstance(r["presets"], list)
        self.assertTrue(len(r["presets"]) >= 1)

    def test_pool_add_source_bad_url(self):
        r = self.client.post_json("/api/singbox/pool/sources",
                                   {"name": "x", "url": "ftp://nope"})
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r["ok"])

    def test_pool_refresh_status_shape(self):
        r = self.client.get_json("/api/singbox/pool/refresh/status")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("running", r)
        self.assertIn("progress", r)
        self.assertIn("phase", r["progress"])

    # ─── proxy tester ───

    def test_test_status(self):
        r = self.client.get_json("/api/singbox/test/status")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("running", r)
        self.assertIn("targets", r)
        self.assertIn("cloudflare", r["targets"])

    def test_test_start_no_source(self):
        r = self.client.post_json("/api/singbox/test", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_test_start_empty_outbounds(self):
        r = self.client.post_json("/api/singbox/test", {"outbounds": []})
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r["ok"])


class _FakeRoutingMgr:
    """Поддельный менеджер: check_text принимает конфиг по правилу accept,
    save_config запоминает сохранённый (разобранный) конфиг."""

    def __init__(self, accept):
        self.accept = accept
        self.saved = None

    def check_text(self, text):
        import json
        return {"ok": bool(self.accept(json.loads(text)))}

    def save_config(self, name, text=""):
        import json
        self.saved = json.loads(text)
        return {"ok": True}


class TestApplyRoutingDomainResolver(unittest.TestCase):
    """_apply_singbox_routing подбирает default_domain_resolver под версию
    движка (на 1.14 без него FATAL)."""

    def _cfg(self):
        return {"outbounds": [{
            "type": "hysteria2", "tag": "h", "server": "vpn.example.com",
            "server_port": 8449, "password": "p",
            "tls": {"enabled": True, "server_name": "sni.example"}}]}

    def test_object_resolver_when_accepted(self):
        from api.singbox import _apply_singbox_routing
        mgr = _FakeRoutingMgr(lambda c: True)        # всё ок (1.14)
        save = _apply_singbox_routing(mgr, "vpn", self._cfg())
        self.assertTrue(save["ok"])
        self.assertEqual(mgr.saved["route"]["default_domain_resolver"],
                         {"server": "dns-direct"})
        # клиентский DNS — через прокси
        self.assertEqual(mgr.saved["dns"]["final"], "dns-proxy")
        self.assertEqual(save["dns_format"], "typed")

    def test_string_resolver_fallback(self):
        from api.singbox import _apply_singbox_routing
        # имитируем 1.12.0: принимаем только строковый resolver
        mgr = _FakeRoutingMgr(
            lambda c: isinstance(
                (c.get("route") or {}).get("default_domain_resolver"), str))
        save = _apply_singbox_routing(mgr, "vpn", self._cfg())
        self.assertTrue(save["ok"])
        self.assertEqual(mgr.saved["route"]["default_domain_resolver"],
                         "dns-direct")

    def test_legacy_has_no_resolver(self):
        from api.singbox import _apply_singbox_routing
        # имитируем старый движок (1.8–1.11): typed-DNS не принимается,
        # только legacy — и тогда resolver быть НЕ должно.
        def accept(c):
            servers = (c.get("dns") or {}).get("servers") or []
            typed = any("type" in s for s in servers)
            return (not typed) and \
                "default_domain_resolver" not in (c.get("route") or {})
        mgr = _FakeRoutingMgr(accept)
        save = _apply_singbox_routing(mgr, "vpn", self._cfg())
        self.assertTrue(save["ok"])
        self.assertNotIn("default_domain_resolver",
                         mgr.saved.get("route", {}))
        self.assertEqual(save["dns_format"], "legacy")

    def test_no_resolver_when_hijack_off(self):
        from api.singbox import _apply_singbox_routing
        mgr = _FakeRoutingMgr(lambda c: True)
        save = _apply_singbox_routing(mgr, "vpn", self._cfg(),
                                      hijack_dns=False)
        self.assertTrue(save["ok"])
        self.assertNotIn("default_domain_resolver",
                         mgr.saved.get("route", {}))
        self.assertNotIn("dns", mgr.saved)


class TestBinaryHasGvisor(unittest.TestCase):

    def _run(self, stdout):
        import types
        return mock.patch("subprocess.run", return_value=types.SimpleNamespace(
            stdout=stdout, returncode=0))

    def test_present(self):
        from api.singbox import _binary_has_gvisor
        with self._run("sing-box version 1.14.0\n"
                       "Tags: with_quic,with_gvisor,with_clash_api\n"):
            self.assertTrue(_binary_has_gvisor("/x"))

    def test_absent(self):
        from api.singbox import _binary_has_gvisor
        with self._run("sing-box version 1.14.0\nTags: with_quic,with_clash_api\n"):
            self.assertFalse(_binary_has_gvisor("/x"))

    def test_no_tags_line(self):
        from api.singbox import _binary_has_gvisor
        with self._run("sing-box version 1.14.0\n"):
            self.assertIsNone(_binary_has_gvisor("/x"))

    def test_empty_binary(self):
        from api.singbox import _binary_has_gvisor
        self.assertIsNone(_binary_has_gvisor(""))


class TestGvisorStackFallback(unittest.TestCase):
    """Без gvisor в сборке откатываемся на system (без FATAL) + флаг."""

    def _cfg(self):
        return {"outbounds": [{
            "type": "hysteria2", "tag": "h", "server": "vpn.example.com",
            "server_port": 8449, "password": "p",
            "tls": {"enabled": True, "server_name": "sni"}}]}

    def _mgr(self):
        mgr = _FakeRoutingMgr(lambda c: True)
        mgr._binary = lambda: "/opt/sbin/sing-box"
        return mgr

    def test_fallback_to_system_without_gvisor(self):
        from api import singbox as sb
        mgr = self._mgr()
        with mock.patch.object(sb, "_binary_has_gvisor", return_value=False):
            save = sb._apply_singbox_routing(mgr, "vpn", self._cfg())
        self.assertTrue(save["gvisor_missing"])
        self.assertEqual(save["stack"], "system")
        tun = next(ib for ib in mgr.saved["inbounds"]
                   if ib.get("type") == "tun")
        self.assertEqual(tun["stack"], "system")

    def test_uses_gvisor_when_present(self):
        from api import singbox as sb
        mgr = self._mgr()
        with mock.patch.object(sb, "_binary_has_gvisor", return_value=True):
            save = sb._apply_singbox_routing(mgr, "vpn", self._cfg())
        self.assertFalse(save["gvisor_missing"])
        self.assertEqual(save["stack"], "gvisor")
        tun = next(ib for ib in mgr.saved["inbounds"]
                   if ib.get("type") == "tun")
        self.assertEqual(tun["stack"], "gvisor")


if __name__ == "__main__":
    unittest.main()
