# tests/test_singbox_subscription.py
"""Unit-тесты для core/singbox_subscription.py."""

import base64
import json
import unittest

from core.singbox_subscription import (
    uri_to_outbound, vless_to_outbound, vmess_to_outbound,
    trojan_to_outbound, ss_to_outbound, hysteria2_to_outbound,
    tuic_to_outbound, _safe_tag,
)


def _vmess_uri(payload: dict) -> str:
    return "vmess://" + base64.b64encode(
        json.dumps(payload).encode("utf-8")).decode("ascii")


class TestVlessReality(unittest.TestCase):

    def test_reality_without_fp_defaults_utls_chrome(self):
        # sing-box требует utls для reality — даже без fp в URI.
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=PUB&sid=01&sni=cloudflare.com"
               "&flow=xtls-rprx-vision&type=tcp#NoFP")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        tls = r["outbound"]["tls"]
        self.assertTrue(tls["reality"]["enabled"])
        self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})

    def test_reality_with_fp_kept(self):
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=PUB&sid=01&fp=firefox#WithFP")
        r = vless_to_outbound(uri)
        self.assertEqual(r["outbound"]["tls"]["utls"]["fingerprint"], "firefox")


class TestVmess(unittest.TestCase):

    def test_ws_tls(self):
        uri = _vmess_uri({
            "v": "2", "ps": "Tokyo 01", "add": "1.2.3.4", "port": "443",
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
            "scy": "auto", "net": "ws", "host": "cdn.example.com",
            "path": "/vm", "tls": "tls", "sni": "cdn.example.com",
        })
        r = vmess_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        ob = r["outbound"]
        self.assertEqual(ob["type"], "vmess")
        self.assertEqual(ob["tag"], "Tokyo-01")
        self.assertEqual(ob["server"], "1.2.3.4")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["uuid"], "b831381d-6324-4d53-ad4f-8cda48b30811")
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/vm")
        self.assertEqual(ob["transport"]["headers"]["Host"], "cdn.example.com")
        self.assertTrue(ob["tls"]["enabled"])
        self.assertEqual(ob["tls"]["server_name"], "cdn.example.com")

    def test_plain_tcp(self):
        uri = _vmess_uri({
            "ps": "x", "add": "h.example", "port": "80",
            "id": "u", "net": "tcp",
        })
        r = vmess_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertNotIn("transport", r["outbound"])
        self.assertNotIn("tls", r["outbound"])

    def test_dispatch_via_uri_to_outbound(self):
        uri = _vmess_uri({"add": "h", "port": "443", "id": "u"})
        r = uri_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["type"], "vmess")

    def test_missing_fields(self):
        uri = _vmess_uri({"ps": "x", "net": "tcp"})  # нет add/port/id
        r = vmess_to_outbound(uri)
        self.assertFalse(r["ok"])

    def test_bad_base64(self):
        r = vmess_to_outbound("vmess://!!!not-base64!!!")
        self.assertFalse(r["ok"])


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
