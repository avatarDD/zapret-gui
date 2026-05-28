# tests/test_singbox_subscription.py
"""Unit-тесты для core/singbox_subscription.py."""

import unittest

from core.singbox_subscription import (
    uri_to_outbound, vless_to_outbound, trojan_to_outbound,
    ss_to_outbound, hysteria2_to_outbound, tuic_to_outbound,
    _safe_tag,
)


class TestSafeTag(unittest.TestCase):

    def test_basic(self):
        self.assertEqual(_safe_tag("MyVPN"), "MyVPN")

    def test_unsafe_chars(self):
        self.assertEqual(_safe_tag("my vpn!"), "my-vpn")

    def test_empty_fallback(self):
        self.assertEqual(_safe_tag(""), "out")
        self.assertEqual(_safe_tag("", "custom"), "custom")

    def test_length_capped(self):
        self.assertLessEqual(len(_safe_tag("x" * 100)), 48)


class TestVless(unittest.TestCase):

    def test_reality(self):
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=PUB&sid=01"
               "&sni=cloudflare.com&fp=chrome"
               "&flow=xtls-rprx-vision&type=tcp#MyReality")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        ob = r["outbound"]
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["tag"], "MyReality")
        self.assertEqual(ob["uuid"], "uuid-1")
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PUB")
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")

    def test_ws_transport(self):
        uri = ("vless://uuid@host:443"
               "?security=tls&type=ws&path=%2Fws&host=ws.example#wsv")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["transport"]["type"], "ws")
        self.assertEqual(r["outbound"]["transport"]["path"], "/ws")
        self.assertEqual(
            r["outbound"]["transport"]["headers"]["Host"], "ws.example")

    def test_grpc_transport(self):
        uri = "vless://uuid@host:443?type=grpc&serviceName=svc1#g"
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["transport"]["type"], "grpc")
        self.assertEqual(r["outbound"]["transport"]["service_name"], "svc1")

    def test_missing_uuid(self):
        r = vless_to_outbound("vless://@host:443")
        self.assertFalse(r["ok"])

    def test_wrong_scheme(self):
        r = vless_to_outbound("trojan://x@host:443")
        self.assertFalse(r["ok"])


class TestTrojan(unittest.TestCase):

    def test_basic(self):
        r = trojan_to_outbound("trojan://pass@host:443?sni=h.com#t1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["type"], "trojan")
        self.assertEqual(r["outbound"]["password"], "pass")
        self.assertEqual(r["outbound"]["tls"]["server_name"], "h.com")

    def test_ws_transport(self):
        r = trojan_to_outbound(
            "trojan://pass@host:443?type=ws&path=/p&host=h#tw")
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["transport"]["type"], "ws")


class TestShadowsocks(unittest.TestCase):

    def test_base64_userinfo(self):
        # ss://base64(aes-128-gcm:pass)@host:8388
        # base64("aes-128-gcm:pass") == "YWVzLTEyOC1nY206cGFzcw=="
        r = ss_to_outbound("ss://YWVzLTEyOC1nY206cGFzcw==@host:8388#s1")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["method"], "aes-128-gcm")
        self.assertEqual(r["outbound"]["password"], "pass")

    def test_plain_userinfo(self):
        r = ss_to_outbound("ss://aes-128-gcm:pass@host:8388#s2")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server"], "host")
        self.assertEqual(r["outbound"]["server_port"], 8388)

    def test_full_base64(self):
        # ss://base64(method:pass@host:port)
        import base64
        plain = "aes-128-gcm:pass@host:8388"
        encoded = base64.b64encode(plain.encode()).decode()
        r = ss_to_outbound("ss://" + encoded + "#s3")
        self.assertTrue(r["ok"], msg=r.get("error"))

    def test_wrong_scheme(self):
        r = ss_to_outbound("vless://uuid@host:443")
        self.assertFalse(r["ok"])


class TestHysteria2(unittest.TestCase):

    def test_basic(self):
        r = hysteria2_to_outbound("hysteria2://pass@host:443?sni=h.com#h1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["password"], "pass")

    def test_hy2_alias(self):
        r = hysteria2_to_outbound("hy2://pass@host:443#h2")
        self.assertTrue(r["ok"])

    def test_insecure_flag(self):
        r = hysteria2_to_outbound("hy2://p@h:443?insecure=1#i")
        self.assertTrue(r["ok"])
        self.assertTrue(r["outbound"]["tls"]["insecure"])


class TestTuic(unittest.TestCase):

    def test_basic(self):
        r = tuic_to_outbound("tuic://uuid:pwd@host:443?sni=h.com#tu")
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["uuid"], "uuid")
        self.assertEqual(r["outbound"]["password"], "pwd")

    def test_no_password(self):
        r = tuic_to_outbound("tuic://uuid@host:443#tu")
        self.assertTrue(r["ok"])
        self.assertEqual(r["outbound"]["uuid"], "uuid")
        # password только если был

    def test_missing_uuid(self):
        r = tuic_to_outbound("tuic://@host:443")
        self.assertFalse(r["ok"])


class TestDispatcher(unittest.TestCase):

    def test_all_schemes_route(self):
        cases = [
            ("vless://u@h:1?", "vless"),
            ("trojan://p@h:1?", "trojan"),
            ("ss://aes-128-gcm:p@h:1", "shadowsocks"),
            ("hysteria2://p@h:1", "hysteria2"),
            ("hy2://p@h:1", "hysteria2"),
            ("tuic://uuid@h:1", "tuic"),
        ]
        for uri, expected_type in cases:
            r = uri_to_outbound(uri)
            # uuid в vless requires host:port парсинг —
            # некоторые могут не пройти, проверяем только что
            # диспетчер прорезолвил handler без 'scheme не поддержан'.
            if not r.get("ok"):
                self.assertNotIn("не поддержан", r.get("error", ""))
            else:
                self.assertEqual(r["outbound"]["type"], expected_type)

    def test_unknown_scheme(self):
        r = uri_to_outbound("magic://host:1")
        self.assertFalse(r["ok"])
        self.assertIn("не поддержан", r["error"])


if __name__ == "__main__":
    unittest.main()
