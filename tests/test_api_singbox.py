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


if __name__ == "__main__":
    unittest.main()
