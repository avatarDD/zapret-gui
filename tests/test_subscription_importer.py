# tests/test_subscription_importer.py
"""
Unit-тесты для core/subscription_importer.py.

HTTP-фетч не тестируется (это пройдено в e2e); проверяем парсеры
и URI→.conf конвертер.
"""

import base64
import unittest

from core.subscription_importer import (
    extract_items, wireguard_uri_to_conf, _maybe_decode_base64, _redact,
    _safe_conf_name,
)


class TestExtractItems(unittest.TestCase):

    def test_raw_conf_only(self):
        text = """[Interface]
PrivateKey = a

[Peer]
PublicKey = b
"""
        items = extract_items(text)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "conf")

    def test_multiple_uri_schemes(self):
        text = """wireguard://abc@host:1234?publickey=def#wg1
vless://uuid@host:8443#v1
ss://method:pass@host:8388#ss1
trojan://pass@host:1234#tr1
hysteria2://pass@host:443#h2
"""
        items = extract_items(text)
        schemes = sorted({i["scheme"] for i in items if i["type"] == "uri"})
        self.assertEqual(
            schemes, ["hysteria2", "ss", "trojan", "vless", "wireguard"])

    def test_base64_subscription(self):
        plain = "wireguard://k@h:1234?publickey=p#one\nvless://uuid@h:443"
        encoded = base64.b64encode(plain.encode()).decode()
        items = extract_items(encoded)
        schemes = sorted({i["scheme"] for i in items if i["type"] == "uri"})
        self.assertEqual(schemes, ["vless", "wireguard"])

    def test_dedup(self):
        text = "wireguard://k@h:1234?publickey=p#a\nwireguard://k@h:1234?publickey=p#a"
        items = extract_items(text)
        self.assertEqual(len(items), 1)


class TestMaybeDecodeBase64(unittest.TestCase):

    def test_plain_passes_through(self):
        text = "[Interface]\nPrivateKey=abc"
        self.assertEqual(_maybe_decode_base64(text), text)

    def test_too_short_passes_through(self):
        self.assertEqual(_maybe_decode_base64("short"), "short")

    def test_url_passes_through(self):
        # Содержит "://" → не пробуем декодить как base64
        self.assertEqual(_maybe_decode_base64("vless://uuid@host:443" * 5),
                         "vless://uuid@host:443" * 5)

    def test_real_b64(self):
        plain = "wireguard://k@h:1234?publickey=p#a"
        encoded = base64.b64encode(plain.encode()).decode()
        self.assertIn("://", _maybe_decode_base64(encoded))


class TestWireguardUriToConf(unittest.TestCase):

    def test_basic(self):
        uri = ("wireguard://PRIV@host.example.com:51820"
               "?publickey=PUB&address=10.0.0.2%2F32"
               "&allowedips=0.0.0.0%2F0&persistentkeepalive=25#MyVPN")
        r = wireguard_uri_to_conf(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["name"], "MyVPN")
        conf = r["conf"]
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = PRIV", conf)
        self.assertIn("Address = 10.0.0.2/32", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("PublicKey = PUB", conf)
        self.assertIn("Endpoint = host.example.com:51820", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_missing_publickey(self):
        uri = "wireguard://PRIV@host:1234"
        r = wireguard_uri_to_conf(uri)
        self.assertFalse(r["ok"])
        self.assertIn("PublicKey", r["error"])

    def test_no_endpoint(self):
        # Нет порта — должно отказать
        uri = "wireguard://PRIV@host?publickey=PUB"
        r = wireguard_uri_to_conf(uri)
        self.assertFalse(r["ok"])

    def test_wrong_scheme(self):
        r = wireguard_uri_to_conf("vless://uuid@host:443")
        self.assertFalse(r["ok"])

    def test_default_name(self):
        uri = "wireguard://PRIV@vpn.example.com:51820?publickey=PUB"
        r = wireguard_uri_to_conf(uri)
        self.assertTrue(r["ok"])
        self.assertEqual(r["name"], "wg-vpn-example-com")


class TestSafeConfName(unittest.TestCase):

    def test_strips_unsafe(self):
        self.assertEqual(_safe_conf_name("my vpn!"), "my-vpn")
        self.assertEqual(_safe_conf_name("a/b\\c"), "a-b-c")

    def test_max_length(self):
        self.assertLessEqual(len(_safe_conf_name("x" * 200)), 32)


class TestRedact(unittest.TestCase):

    def test_redacts_credentials(self):
        red = _redact("wireguard://SECRETKEY@host:1234")
        self.assertIn("***", red)
        self.assertNotIn("SECRETKEY", red)

    def test_no_creds_unchanged(self):
        self.assertEqual(_redact("https://example.com"),
                         "https://example.com")


if __name__ == "__main__":
    unittest.main()
