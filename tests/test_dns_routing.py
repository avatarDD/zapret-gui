# tests/test_dns_routing.py
"""Unit-тесты для core/dns_routing.py."""

import unittest
from unittest import mock

from core import dns_routing as dr


class FakeConfigManager:
    """Упрощённый мок ConfigManager для тестов dns_routing."""
    def __init__(self):
        self.data = {"dns_routing": {"rules": []}}
    def get(self, key1, key2, **kwargs):
        default = kwargs.get("default", None)
        return self.data.get(key1, {}).get(key2, default)
    def set(self, key1, key2, value):
        self.data.setdefault(key1, {})[key2] = value
    def save(self):
        return True


class TestDnsServers(unittest.TestCase):
    """Проверяем что все DNS-серверы определены корректно."""

    def test_has_required_servers(self):
        required = ["cloudflare", "google", "adguard", "quad9",
                     "yandex", "comss", "geohide"]
        for server_id in required:
            self.assertIn(server_id, dr.DNS_SERVERS,
                          "Missing server: %s" % server_id)

    def test_all_servers_have_ip(self):
        for sid, srv in dr.DNS_SERVERS.items():
            self.assertIn("ip", srv, "Server %s missing 'ip'" % sid)
            self.assertTrue(srv["ip"], "Server %s has empty ip" % sid)

    def test_geohide_has_doh(self):
        gh = dr.DNS_SERVERS["geohide"]
        self.assertIn("geohide.ru", gh.get("doh", ""))


class TestDnsRoutingManager(unittest.TestCase):
    """Тесты DnsRoutingManager."""

    def setUp(self):
        self.mgr = dr.DnsRoutingManager()
        self._rules_store = []
        self._patch = mock.patch("core.config_manager.get_config_manager")

        class FakeCM:
            def get(self_obj, *args, **kwargs):
                return list(self._rules_store)
            def set(self_obj, key1, key2, value):
                self._rules_store[:] = value
            def save(self_obj):
                return True
        self._cm = self._patch.start()
        self._cm.return_value = FakeCM()

    def tearDown(self):
        self._patch.stop()

    def test_add_rule(self):
        r = self.mgr.add_rule("youtube.com", "cloudflare")
        self.assertTrue(r["ok"])
        self.assertEqual(len(self._rules_store), 1)
        self.assertEqual(self._rules_store[0]["domain"], "youtube.com")
        self.assertEqual(self._rules_store[0]["dns"], "cloudflare")

    def test_add_rule_dedup(self):
        self._rules_store.append({"domain": "youtube.com", "dns": "cloudflare"})
        r = self.mgr.add_rule("youtube.com", "google")
        self.assertFalse(r["ok"])
        self.assertIn("уже существует", r["error"])

    def test_add_rule_invalid_dns(self):
        r = self.mgr.add_rule("test.com", "not-a-server")
        self.assertFalse(r["ok"])

    def test_add_rule_custom_ip(self):
        r = self.mgr.add_rule("test.com", "8.8.8.8")
        self.assertTrue(r["ok"])

    def test_remove_rule(self):
        self._rules_store.append({"domain": "youtube.com", "dns": "cloudflare"})
        r = self.mgr.remove_rule("youtube.com")
        self.assertTrue(r["ok"])
        self.assertEqual(len(self._rules_store), 0)

    def test_remove_rule_not_found(self):
        r = self.mgr.remove_rule("nonexistent.com")
        self.assertFalse(r["ok"])

    def test_get_rules(self):
        self._rules_store.append({"domain": "a.com", "dns": "cloudflare"})
        self._rules_store.append({"domain": "b.com", "dns": "google"})
        rules = self.mgr.get_rules()
        self.assertEqual(len(rules), 2)

    def test_resolve_server_known(self):
        self.assertEqual(self.mgr._resolve_server("cloudflare"), "1.1.1.1")
        self.assertEqual(self.mgr._resolve_server("geohide"), "45.155.204.190")

    def test_resolve_server_ip(self):
        self.assertEqual(self.mgr._resolve_server("8.8.8.8"), "8.8.8.8")

    def test_resolve_server_doh_url_known(self):
        self.assertEqual(self.mgr._resolve_server("https://dns.google/dns-query"), "8.8.8.8")
        self.assertEqual(self.mgr._resolve_server("https://1.1.1.1/dns-query"), "1.1.1.1")

    @mock.patch("socket.gethostbyname")
    def test_resolve_server_doh_url_custom(self, mock_gethost):
        mock_gethost.return_value = "9.9.9.9"
        self.assertEqual(self.mgr._resolve_server("https://dns.custom.com/dns-query"), "9.9.9.9")
        mock_gethost.assert_called_once_with("dns.custom.com")

    def test_resolve_server_doh_url_custom_ip_host(self):
        # Если хост в DoH URL уже является IP
        self.assertEqual(self.mgr._resolve_server("https://9.9.9.9/dns-query"), "9.9.9.9")

    def test_get_available_servers(self):
        servers = self.mgr.get_available_servers()
        self.assertGreater(len(servers), 0)
        ids = [s["id"] for s in servers]
        self.assertIn("cloudflare", ids)
        self.assertIn("geohide", ids)


if __name__ == "__main__":
    unittest.main()
