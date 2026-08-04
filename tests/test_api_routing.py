# tests/test_api_routing.py
"""
Integration-тесты для api/routing.py — все эндпоинты дёргаются
через WSGI-клиент без сети/процессов.
"""

import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestRoutingAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    # ─── /api/routing/rules ───

    def test_list_rules_empty(self):
        with mock.patch("core.routing.storage.load_rules",
                        return_value=[]):
            r = self.client.get_json("/api/routing/rules")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertEqual(r["rules"], [])

    def test_create_rule_missing_type(self):
        r = self.client.post_json("/api/routing/rules", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])
        self.assertIn("type", r["error"])

    def test_create_rule_invalid_type(self):
        r = self.client.post_json("/api/routing/rules",
                                   {"type": "nonsense",
                                    "target_iface": "awg0"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_get_rule_missing(self):
        with mock.patch("core.routing.storage.get_rule",
                        return_value=None):
            r = self.client.get_json("/api/routing/rules/nonexistent")
        self.assertEqual(r["_status"], 404)
        self.assertFalse(r["ok"])

    def test_update_missing_rule(self):
        with mock.patch("core.routing.storage.get_rule",
                        return_value=None):
            r = self.client.put_json("/api/routing/rules/nonexistent",
                                     {"type": "cidr",
                                      "target_iface": "awg0",
                                      "cidrs": ["10.0.0.0/24"]})
        self.assertEqual(r["_status"], 404)

    # ─── /api/routing/ndms ───

    def test_ndms_status_not_keenetic(self):
        # Мокаем доступность: на реальном Keenetic RCI отвечает и available
        # был бы True — тест же проверяет именно не-Keenetic ветку.
        with mock.patch("core.ndms.is_ndms_available", return_value=False):
            r = self.client.get_json("/api/routing/ndms/status")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        # На не-Keenetic — available=False
        self.assertFalse(r["available"])

    def test_ndms_refresh(self):
        r = self.client.post_json("/api/routing/ndms/refresh", {})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)

    # ─── /api/routing/interfaces ───

    def test_interfaces_returns_list(self):
        r = self.client.get_json("/api/routing/interfaces")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertIn("interfaces", r)
        self.assertIsInstance(r["interfaces"], list)

    def test_interfaces_include_running_usque_tunnel(self):
        """Поднятый usque должен предлагаться как цель `warp:<iface>`.

        Без него в списке методов на странице маршрутизации был виден
        только AWG, хотя метод warp: бэкенд поддерживает.
        """
        configs = [{"name": "warp-default", "iface": "usque0",
                    "active": True, "path": "/tmp/warp-default.json"}]
        with mock.patch("core.usque_manager.UsqueManager.list_configs",
                        return_value=configs):
            r = self.client.get_json("/api/routing/interfaces")
        entry = next((i for i in r["interfaces"] if i["name"] == "usque0"), None)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["source"], "usque")
        self.assertTrue(entry["active"])

    def test_interfaces_include_mihomo_tun(self):
        """mihomo с включённым `tun` — цель `mihomo:<iface>`.

        Фронт умел раскладывать source=mihomo с самого начала, но сюда
        эти интерфейсы никто не клал.
        """
        configs = [{"name": "meta", "path": "/tmp/meta.yaml",
                    "running": True, "tun_iface": "mihomo-tun"}]
        with mock.patch("core.mihomo_manager.MihomoManager.list_configs",
                        return_value=configs):
            r = self.client.get_json("/api/routing/interfaces")
        entry = next((i for i in r["interfaces"]
                      if i["name"] == "mihomo-tun"), None)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["source"], "mihomo")

    def test_interfaces_skip_mihomo_without_tun(self):
        """Без `tun` у mihomo только локальный порт — заворачивать нечего.

        Но раз конфиг ЗАПУЩЕН, а цели нет — объясняем это в `notes`:
        иначе выглядит как пропажа mihomo из списка методов.
        """
        configs = [{"name": "meta", "path": "/tmp/meta.yaml",
                    "running": True, "tun_iface": ""}]
        with mock.patch("core.mihomo_manager.MihomoManager.list_configs",
                        return_value=configs):
            r = self.client.get_json("/api/routing/interfaces")
        self.assertEqual(
            [i for i in r["interfaces"] if i.get("source") == "mihomo"], [])
        notes = [n for n in r.get("notes", []) if n.get("source") == "mihomo"]
        self.assertEqual(len(notes), 1)
        self.assertIn("meta", notes[0]["text"])

    def test_no_note_for_stopped_mihomo_without_tun(self):
        """Остановленный конфиг без TUN — не повод шуметь в списке методов."""
        configs = [{"name": "meta", "path": "/tmp/meta.yaml",
                    "running": False, "tun_iface": ""}]
        with mock.patch("core.mihomo_manager.MihomoManager.list_configs",
                        return_value=configs):
            r = self.client.get_json("/api/routing/interfaces")
        self.assertEqual(
            [n for n in r.get("notes", []) if n.get("source") == "mihomo"], [])

    def test_interfaces_skip_usque_profile_without_iface(self):
        """У остановленного профиля имени интерфейса нет — маршрутизировать
        не во что, в списке целей его быть не должно."""
        configs = [{"name": "warp-default", "iface": "", "active": False,
                    "path": "/tmp/warp-default.json"}]
        with mock.patch("core.usque_manager.UsqueManager.list_configs",
                        return_value=configs):
            r = self.client.get_json("/api/routing/interfaces")
        self.assertEqual(
            [i for i in r["interfaces"] if i.get("source") == "usque"], [])

    # ─── /api/routing/aliases ───

    def test_aliases_list(self):
        r = self.client.get_json("/api/routing/aliases")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertIn("cached", r)
        self.assertIn("suggestions", r)

    def test_aliases_preview_no_items(self):
        r = self.client.post_json("/api/routing/aliases/preview", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_aliases_preview_with_items(self):
        r = self.client.post_json("/api/routing/aliases/preview",
                                   {"items": ["youtube.com", "10.0.0.0/24"]})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertEqual(r["result"]["domains"], ["youtube.com"])
        self.assertEqual(r["result"]["cidrs"], ["10.0.0.0/24"])

    # ─── /api/routing/doh ───

    def test_doh_get(self):
        r = self.client.get_json("/api/routing/doh")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertIn("settings", r)
        self.assertIn("known", r)

    def test_doh_test_missing_provider(self):
        r = self.client.post_json("/api/routing/doh/test",
                                   {"domain": "example.com"})
        self.assertEqual(r["_status"], 400)

    # ─── /api/routing/dnsmasq ───

    def test_dnsmasq_status(self):
        r = self.client.get_json("/api/routing/dnsmasq/status")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["ok"], True)
        self.assertIn("dnsmasq", r)
        self.assertIn("backends", r)


if __name__ == "__main__":
    unittest.main()
