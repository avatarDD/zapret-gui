# tests/test_singbox_subscription.py
"""Unit-тесты для core/singbox_subscription.py."""

import base64
import json
import unittest

from core.singbox_subscription import (
    uri_to_outbound, vless_to_outbound, vmess_to_outbound,
    trojan_to_outbound, ss_to_outbound, hysteria2_to_outbound,
    tuic_to_outbound, outbound_to_uri, _safe_tag,
)

# Валидный 32-байтный x25519 public key (reality-ссылки без него отвергаются,
# т.к. sing-box падает на старте с «invalid public_key»).
PUB = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def _vmess_uri(payload: dict) -> str:
    return "vmess://" + base64.b64encode(
        json.dumps(payload).encode("utf-8")).decode("ascii")


class TestVlessReality(unittest.TestCase):

    def test_reality_without_fp_defaults_utls_chrome(self):
        # sing-box требует utls для reality — даже без fp в URI.
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=" + PUB + "&sid=01&sni=cloudflare.com"
               "&flow=xtls-rprx-vision&type=tcp#NoFP")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        tls = r["outbound"]["tls"]
        self.assertTrue(tls["reality"]["enabled"])
        self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})

    def test_reality_with_fp_kept(self):
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=" + PUB + "&sid=01&fp=firefox#WithFP")
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

    def test_httpupgrade_transport(self):
        uri = _vmess_uri({"add": "h", "port": "443", "id": "u",
                          "net": "httpupgrade", "path": "/up", "host": "cdn.x"})
        r = vmess_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"]["type"], "httpupgrade")
        self.assertEqual(r["outbound"]["transport"]["host"], "cdn.x")

    def test_xhttp_rejected(self):
        uri = _vmess_uri({"add": "h", "port": "443", "id": "u", "net": "xhttp"})
        r = vmess_to_outbound(uri)
        self.assertFalse(r["ok"])
        self.assertIn("xhttp", r["error"])

    def test_skip_cert_verify(self):
        uri = _vmess_uri({"add": "h", "port": "443", "id": "u", "net": "tcp",
                          "tls": "tls", "skip-cert-verify": "true"})
        r = vmess_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertTrue(r["outbound"]["tls"]["insecure"])


class TestMalformedUri(unittest.TestCase):
    """Битая ссылка не должна ронять вызывающего (одна кривая ссылка в
    подписке иначе валит весь импорт mihomo/sing-box)."""

    def test_bad_port_returns_error_not_raises(self):
        # `.port` у urllib бросает ValueError на мусорном порту.
        r = uri_to_outbound("vless://uuid@host:2`bad?type=tcp#x")
        self.assertFalse(r["ok"])
        self.assertIn("error", r)

    def test_garbage_uri(self):
        r = uri_to_outbound("vmess://!!!not-base64!!!")
        self.assertFalse(r["ok"])

    def test_not_a_uri(self):
        self.assertFalse(uri_to_outbound("just text")["ok"])


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
               "?security=reality&pbk=" + PUB + "&sid=01"
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
        self.assertEqual(ob["tls"]["reality"]["public_key"], PUB)
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")

    def test_vision_udp443_flow_normalized(self):
        # Xray-вариант flow: sing-box знает только xtls-rprx-vision.
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=reality&pbk=" + PUB + "&sid=01"
               "&flow=xtls-rprx-vision-udp443&type=tcp#udp443")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["flow"], "xtls-rprx-vision")

    def test_legacy_flow_rejected(self):
        # Легаси xtls-flow роняет sing-box на старте («unsupported flow»)
        # — отсекаем при импорте, как reality без pbk.
        uri = ("vless://uuid-1@vpn.example:443"
               "?security=tls&flow=xtls-rprx-direct&type=tcp#legacy")
        r = vless_to_outbound(uri)
        self.assertFalse(r["ok"])
        self.assertIn("flow", r["error"])

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

    def test_httpupgrade_transport(self):
        # httpupgrade — sing-box-нативный транспорт (НЕ Xray xhttp); host —
        # отдельное поле, не headers.Host.
        uri = ("vless://uuid@host:443"
               "?type=httpupgrade&path=%2Fup&host=cdn.example#hu")
        r = vless_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        tr = r["outbound"]["transport"]
        self.assertEqual(tr["type"], "httpupgrade")
        self.assertEqual(tr["path"], "/up")
        self.assertEqual(tr["host"], "cdn.example")

    def test_xhttp_rejected(self):
        # xhttp — транспорт Xray, в sing-box его нет: отбраковываем, иначе
        # ссылка молча стала бы «голым TCP» и не подключилась.
        r = vless_to_outbound("vless://uuid@host:443?type=xhttp&path=/x#x")
        self.assertFalse(r["ok"])
        self.assertIn("xhttp", r["error"])

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

    def test_grpc_transport(self):
        r = trojan_to_outbound(
            "trojan://pass@host:443?type=grpc&serviceName=svc#tg")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"]["type"], "grpc")
        self.assertEqual(r["outbound"]["transport"]["service_name"], "svc")

    def test_httpupgrade_transport(self):
        r = trojan_to_outbound(
            "trojan://pass@host:443?type=httpupgrade&path=/up&host=h#thu")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"]["type"], "httpupgrade")

    def test_xhttp_rejected(self):
        r = trojan_to_outbound("trojan://pass@host:443?type=splithttp#x")
        self.assertFalse(r["ok"])

    def test_allow_insecure_and_fp_alpn(self):
        # allowInsecure=1 (self-signed) + uTLS fp + ALPN — иначе рукопожатие падает.
        r = trojan_to_outbound("trojan://pass@host:443"
                              "?sni=h.com&allowInsecure=1&fp=chrome&alpn=h2,http%2F1.1#ti")
        self.assertTrue(r["ok"], msg=r.get("error"))
        tls = r["outbound"]["tls"]
        self.assertTrue(tls["insecure"])
        self.assertEqual(tls["server_name"], "h.com")
        self.assertEqual(tls["utls"]["fingerprint"], "chrome")
        self.assertEqual(tls["alpn"], ["h2", "http/1.1"])

    def test_allow_insecure_zero_keeps_strict(self):
        r = trojan_to_outbound("trojan://pass@host:443?sni=h.com&allowInsecure=0#ts")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertNotIn("insecure", r["outbound"]["tls"])

    def test_trojan_go_ws_dialect(self):
        # Trojan-Go: ws=1&wspath=/p вместо type=ws&path=.
        r = trojan_to_outbound("trojan://pass@host:443?sni=h&ws=1&wspath=%2Fassign#tg")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"]["type"], "ws")
        self.assertEqual(r["outbound"]["transport"]["path"], "/assign")


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

    def test_chacha20_poly1305_normalized(self):
        # sing-box знает только chacha20-ietf-poly1305 — алиас нормализуем.
        r = ss_to_outbound("ss://chacha20-poly1305:pass@host:8388#x")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["method"], "chacha20-ietf-poly1305")

    def test_legacy_stream_cipher_rejected(self):
        # Легаси stream-шифр sing-box не поддерживает → сервер отбрасываем.
        r = ss_to_outbound("ss://aes-256-cfb:pass@host:8388#x")
        self.assertFalse(r["ok"])

    def test_plugin_obfs_local(self):
        # SIP002 plugin=<name>;<opts> — без него obfs-сервер не открывается.
        r = ss_to_outbound("ss://YWVzLTEyOC1nY206cGFzcw==@host:8388"
                           "?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com#p")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["plugin"], "obfs-local")
        self.assertEqual(r["outbound"]["plugin_opts"],
                         "obfs=tls;obfs-host=www.bing.com")

    def test_plugin_simple_obfs_aliased(self):
        # simple-obfs (Xray/ss-libev) → имя sing-box obfs-local.
        r = ss_to_outbound("ss://YWVzLTEyOC1nY206cGFzcw==@host:8388"
                           "?plugin=simple-obfs%3Bobfs%3Dhttp#p")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["plugin"], "obfs-local")

    def test_unknown_plugin_rejected(self):
        r = ss_to_outbound("ss://YWVzLTEyOC1nY206cGFzcw==@host:8388?plugin=kcptun#p")
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

    def test_obfs_salamander(self):
        # Сервер с obfs не отвечает без совпадающего obfs-пароля.
        r = hysteria2_to_outbound(
            "hy2://p@h:443?obfs=salamander&obfs-password=sec&sni=h#o")
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["obfs"],
                         {"type": "salamander", "password": "sec"})

    def test_obfs_unsupported_rejected(self):
        # sing-box умеет только salamander.
        r = hysteria2_to_outbound("hy2://p@h:443?obfs=weird&obfs-password=x#o")
        self.assertFalse(r["ok"])

    def test_no_obfs_no_field(self):
        r = hysteria2_to_outbound("hy2://p@h:443#n")
        self.assertTrue(r["ok"])
        self.assertNotIn("obfs", r["outbound"])


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

    def test_full_params(self):
        # alpn/insecure/congestion_control/udp_relay_mode должны попасть в outbound:
        # многие TUIC-серверы рвут рукопожатие без alpn h3 / self-signed → insecure.
        uri = ("tuic://87bc1693-8860-41d7-acf4-e6edf49abbbb:pwd@host:443"
               "?sni=h&alpn=h3&allow_insecure=1"
               "&congestion_control=bbr&udp_relay_mode=native#t")
        r = tuic_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        ob = r["outbound"]
        self.assertEqual(ob["congestion_control"], "bbr")
        self.assertEqual(ob["udp_relay_mode"], "native")
        self.assertTrue(ob["tls"]["insecure"])
        self.assertEqual(ob["tls"]["alpn"], ["h3"])

    def test_html_escaped_amp_params(self):
        # Часть подписок HTML-экранирует '&' → '&amp;'; параметры (insecure и
        # т.п.) не должны теряться, иначе TLS-рукопожатие к self-signed падает.
        uri = ("tuic://87bc1693-8860-41d7-acf4-e6edf49abbbb:pwd@host:443"
               "?congestion_control=bbr&amp;udp_relay_mode=native"
               "&amp;allow_insecure=1#t")
        r = tuic_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["udp_relay_mode"], "native")
        self.assertTrue(r["outbound"]["tls"]["insecure"])


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


class TestRoundTrip(unittest.TestCase):
    """outbound_to_uri → uri_to_outbound сохраняет ключевые поля новых вариантов
    (нужно для «копировать сервер как ссылку» в UI)."""

    def _rt(self, uri):
        r = uri_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        u2 = outbound_to_uri(r["outbound"])
        self.assertTrue(u2, "outbound_to_uri вернул пусто")
        r2 = uri_to_outbound(u2)
        self.assertTrue(r2["ok"], msg=r2.get("error"))
        return r2["outbound"]

    def test_httpupgrade_roundtrip(self):
        ob = self._rt("vless://u@h:443?type=httpupgrade&path=%2Fp&host=cdn&security=tls&sni=cdn#x")
        self.assertEqual(ob["transport"]["type"], "httpupgrade")
        self.assertEqual(ob["transport"]["host"], "cdn")

    def test_hysteria2_obfs_roundtrip(self):
        ob = self._rt("hy2://p@h:443?obfs=salamander&obfs-password=sec&sni=h#x")
        self.assertEqual(ob["obfs"]["password"], "sec")
        self.assertEqual(ob["obfs"]["type"], "salamander")

    def test_tuic_params_roundtrip(self):
        ob = self._rt("tuic://87bc1693-8860-41d7-acf4-e6edf49abbbb:pwd@h:443"
                      "?sni=h&alpn=h3&allow_insecure=1&congestion_control=bbr#x")
        self.assertEqual(ob["congestion_control"], "bbr")
        self.assertEqual(ob["tls"]["alpn"], ["h3"])
        self.assertTrue(ob["tls"]["insecure"])

    def test_ss_plugin_roundtrip(self):
        ob = self._rt("ss://YWVzLTEyOC1nY206cGFzcw==@h:8388"
                      "?plugin=obfs-local%3Bobfs%3Dtls#x")
        self.assertEqual(ob["plugin"], "obfs-local")
        self.assertEqual(ob["plugin_opts"], "obfs=tls")

    def test_trojan_insecure_fp_roundtrip(self):
        ob = self._rt("trojan://p@h:443?sni=h&allowInsecure=1&fp=chrome&alpn=h2#x")
        self.assertTrue(ob["tls"]["insecure"])
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")
        self.assertEqual(ob["tls"]["alpn"], ["h2"])


if __name__ == "__main__":
    unittest.main()
