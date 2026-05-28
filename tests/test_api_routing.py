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
