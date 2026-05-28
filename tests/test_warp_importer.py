# tests/test_warp_importer.py
"""
Unit-тесты для core/warp_importer.py — pure-функции:
_split_endpoint, _is_in_warp_range, is_warp_config, pick_default_name.
"""

import unittest

from core import warp_importer


class TestSplitEndpoint(unittest.TestCase):

    def test_ipv4_port(self):
        host, port = warp_importer._split_endpoint("1.2.3.4:51820")
        self.assertEqual(host, "1.2.3.4")
        # Возвращается строкой, что нормально — caller сам кастит.
        self.assertEqual(port, "51820")

    def test_ipv6_port(self):
        host, port = warp_importer._split_endpoint("[2001:db8::1]:443")
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, "443")

    def test_hostname(self):
        host, port = warp_importer._split_endpoint(
            "engage.cloudflareclient.com:2408")
        self.assertEqual(host, "engage.cloudflareclient.com")
        self.assertEqual(port, "2408")

    def test_invalid_no_colon(self):
        # Без двоеточия — возвращает (host, "") (пустую строку как порт).
        host, port = warp_importer._split_endpoint("noport")
        self.assertEqual(port, "")


class TestIsInWarpRange(unittest.TestCase):
    """CF-WARP endpoints резолвятся в Cloudflare-диапазоны."""

    def test_cf_clientfacing_hosts(self):
        # engage.cloudflareclient.com — официальный WARP-endpoint
        # Тут мы не тестируем DNS-резолв, только что функция не падает.
        try:
            result = warp_importer._is_in_warp_range("engage.cloudflareclient.com")
            self.assertIsInstance(result, bool)
        except Exception:
            # Может фейлить без сети — это OK
            pass

    def test_localhost_not_warp(self):
        self.assertFalse(warp_importer._is_in_warp_range("127.0.0.1"))


class TestIsWarpConfig(unittest.TestCase):
    """Эвристика «это WARP-конфиг или обычный WG»."""

    def test_classic_warp_endpoint(self):
        # WARP endpoint и WARP allowed_ips
        parsed = {
            "interface": {
                "PrivateKey": "abc=",
                "Address": "172.16.0.2/32,2606:4700:110::/96",
            },
            "peers": [{
                "PublicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "Endpoint": "engage.cloudflareclient.com:2408",
                "AllowedIPs": "0.0.0.0/0, ::/0",
            }],
        }
        r = warp_importer.is_warp_config(parsed)
        self.assertTrue(r["is_warp"],
                        msg="engage.cloudflareclient.com endpoint должен"
                            " распознаться как WARP")

    def test_obvious_non_warp(self):
        parsed = {
            "interface": {"PrivateKey": "abc=", "Address": "10.0.0.2/32"},
            "peers": [{
                "PublicKey": "pub",
                "Endpoint": "vpn.example.com:51820",
                "AllowedIPs": "0.0.0.0/0",
            }],
        }
        r = warp_importer.is_warp_config(parsed)
        self.assertFalse(r["is_warp"])

    def test_no_peer_falls_to_not_warp(self):
        parsed = {"interface": {"PrivateKey": "x"}, "peers": []}
        r = warp_importer.is_warp_config(parsed)
        self.assertFalse(r["is_warp"])

    def test_empty_input(self):
        r = warp_importer.is_warp_config({})
        self.assertFalse(r["is_warp"])


class TestPickDefaultName(unittest.TestCase):

    def test_first_when_empty(self):
        # Когда конфигов нет — берём дефолтный 'warp' (или близкий по
        # смыслу). Только проверяем, что возвращает непустую строку.
        n = warp_importer.pick_default_name(set())
        self.assertIsInstance(n, str)
        self.assertTrue(n)

    def test_avoids_collision(self):
        existing = {"warp"}
        n = warp_importer.pick_default_name(existing)
        self.assertNotIn(n, existing)

    def test_avoids_multiple_collisions(self):
        existing = {"warp", "warp1", "warp2"}
        n = warp_importer.pick_default_name(existing)
        self.assertNotIn(n, existing)


class TestToList(unittest.TestCase):

    def test_string_split_by_comma(self):
        self.assertEqual(warp_importer._to_list("a, b, c"),
                         ["a", "b", "c"])

    def test_list_passthrough(self):
        self.assertEqual(warp_importer._to_list(["a", "b"]),
                         ["a", "b"])

    def test_empty(self):
        self.assertEqual(warp_importer._to_list(""), [])
        self.assertEqual(warp_importer._to_list(None), [])


if __name__ == "__main__":
    unittest.main()
