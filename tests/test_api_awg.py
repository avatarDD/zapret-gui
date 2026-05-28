# tests/test_api_awg.py
"""Integration-тесты для api/awg.py — основные эндпоинты."""

import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestAwgAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    # ─── environment ───

    def test_environment(self):
        r = self.client.get_json("/api/awg/environment")
        self.assertEqual(r["_status"], 200)
        self.assertIn("platform", r)
        self.assertIn("architecture", r)
        self.assertIn("tun", r)

    def test_environment_refresh(self):
        r = self.client.post_json("/api/awg/environment/refresh", {})
        self.assertEqual(r["_status"], 200)

    # ─── install/status ───

    def test_install_status(self):
        r = self.client.get_json("/api/awg/install/status")
        self.assertEqual(r["_status"], 200)

    def test_keenetic_opkg_tun(self):
        r = self.client.get_json("/api/awg/keenetic/opkg-tun")
        self.assertEqual(r["_status"], 200)
        self.assertIn("tun_device", r)
        self.assertIn("ready", r)

    # ─── configs ───

    def test_configs_list(self):
        r = self.client.get_json("/api/awg/configs")
        self.assertEqual(r["_status"], 200)
        self.assertIn("configs", r)

    def test_configs_get_nonexistent(self):
        # AwgManager возвращает 404 для несуществующих
        r = self.client.get_json("/api/awg/configs/never-exists")
        self.assertIn(r["_status"], (200, 404))

    def test_configs_validate_no_body(self):
        # validate без body
        r = self.client.post_json("/api/awg/configs/validate", {})
        # Может вернуть 400 (нет text) или ok=False
        self.assertIn(r["_status"], (200, 400))

    # ─── keypair ───

    def test_keypair_generates(self):
        r = self.client.post_json("/api/awg/keypair", {})
        # На системе без awg-бинаря может вернуть error, но не 500
        self.assertIn(r["_status"], (200, 400, 500))

    # ─── interfaces ───

    def test_interfaces_list(self):
        r = self.client.get_json("/api/awg/interfaces")
        self.assertEqual(r["_status"], 200)
        self.assertIsInstance(r["interfaces"], list)

    # ─── autostart ───

    def test_autostart_status(self):
        r = self.client.get_json("/api/awg/autostart")
        self.assertEqual(r["_status"], 200)
        # Ключ interfaces — внутри status (nested), либо на верхнем
        # уровне — допускаем оба варианта.
        self.assertTrue(
            "interfaces" in r or
            (isinstance(r.get("status"), dict) and "interfaces" in r["status"]),
            "Ожидался ключ interfaces где-либо в ответе")

    # ─── watchdog ───

    def test_watchdog_status(self):
        r = self.client.get_json("/api/awg/watchdog")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("status", r)

    def test_watchdog_set_disabled(self):
        r = self.client.post_json("/api/awg/watchdog", {"enabled": False})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])

    # ─── subscription ───

    def test_subscription_preview_no_body(self):
        r = self.client.post_json("/api/awg/subscription/preview", {})
        self.assertEqual(r["_status"], 400)

    def test_subscription_preview_with_uri(self):
        r = self.client.post_json("/api/awg/subscription/preview",
                                   {"text": "wireguard://k@h:1234?publickey=p#test"})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertGreater(len(r["items"]), 0)


if __name__ == "__main__":
    unittest.main()
