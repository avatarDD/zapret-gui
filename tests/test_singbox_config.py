# tests/test_singbox_config.py
"""Unit-тесты для core/singbox_config.py."""

import unittest

from core.singbox_config import (
    parse_conf, validate, render_conf, make_minimal_config,
    make_vless_outbound, make_trojan_outbound,
    make_shadowsocks_outbound, make_hysteria2_outbound,
    make_tuic_outbound,
    KNOWN_OUTBOUND_TYPES,
)


class TestParseConf(unittest.TestCase):

    def test_valid_json(self):
        cfg = parse_conf('{"outbounds": [{"type": "direct"}]}')
        self.assertIn("outbounds", cfg)

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            parse_conf("not json")

    def test_empty(self):
        with self.assertRaises(ValueError):
            parse_conf("")

    def test_array_root(self):
        with self.assertRaises(ValueError):
            parse_conf('[]')


class TestValidate(unittest.TestCase):

    def test_minimal_valid(self):
        cfg = {"outbounds": [{"type": "direct", "tag": "out"}]}
        errors = validate(cfg)
        self.assertEqual(errors, [])

    def test_missing_outbounds(self):
        errors = validate({})
        self.assertTrue(any("outbounds" in e for e in errors))

    def test_outbounds_not_list(self):
        errors = validate({"outbounds": {}})
        self.assertTrue(any("массив" in e for e in errors))

    def test_outbound_without_type(self):
        errors = validate({"outbounds": [{"tag": "a"}]})
        self.assertTrue(any("type" in e for e in errors))

    def test_unknown_type_is_warning(self):
        # Неизвестный тип не блокирует — только сообщает
        errors = validate({"outbounds": [{"type": "made_up", "tag": "a"}]})
        # Errors не пустой, но это warning
        self.assertTrue(any("неизвестный тип" in e for e in errors))

    def test_duplicate_tags(self):
        cfg = {"outbounds": [
            {"type": "direct", "tag": "x"},
            {"type": "block",  "tag": "x"},
        ]}
        errors = validate(cfg)
        self.assertTrue(any("tag" in e and "встречается" in e for e in errors))


class TestRender(unittest.TestCase):

    def test_roundtrip(self):
        cfg = {"outbounds": [{"type": "direct", "tag": "out"}]}
        text = render_conf(cfg)
        cfg2 = parse_conf(text)
        self.assertEqual(cfg, cfg2)


class TestMakeMinimal(unittest.TestCase):

    def test_valid_structure(self):
        cfg = make_minimal_config()
        errors = validate(cfg)
        self.assertEqual(errors, [])
        self.assertIn("inbounds", cfg)
        self.assertIn("outbounds", cfg)
        self.assertIn("route", cfg)


class TestOutboundBuilders(unittest.TestCase):

    def test_vless_basic(self):
        ob = make_vless_outbound(
            tag="v1", server="h", port=443, uuid="u1")
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["tag"], "v1")
        self.assertEqual(ob["server"], "h")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["uuid"], "u1")
        self.assertNotIn("transport", ob)
        self.assertNotIn("tls", ob)

    def test_vless_with_tls(self):
        ob = make_vless_outbound(
            tag="v1", server="h", port=443, uuid="u1",
            tls={"enabled": True, "server_name": "h"})
        self.assertEqual(ob["tls"]["server_name"], "h")

    def test_trojan_with_sni(self):
        ob = make_trojan_outbound(
            tag="t", server="h", port=443, password="p", sni="h.example")
        self.assertEqual(ob["tls"]["server_name"], "h.example")

    def test_trojan_no_sni_marks_insecure(self):
        ob = make_trojan_outbound(
            tag="t", server="h", port=443, password="p")
        self.assertTrue(ob["tls"]["insecure"])

    def test_shadowsocks(self):
        ob = make_shadowsocks_outbound(
            tag="s", server="h", port=8388,
            method="aes-128-gcm", password="p")
        self.assertEqual(ob["type"], "shadowsocks")
        self.assertEqual(ob["method"], "aes-128-gcm")

    def test_hysteria2(self):
        ob = make_hysteria2_outbound(
            tag="h", server="srv", port=443,
            password="pw", sni="srv.example", insecure=True)
        self.assertEqual(ob["type"], "hysteria2")
        self.assertEqual(ob["tls"]["server_name"], "srv.example")
        self.assertTrue(ob["tls"]["insecure"])

    def test_tuic(self):
        ob = make_tuic_outbound(
            tag="t", server="h", port=443,
            uuid="u", password="p", sni="h.example")
        self.assertEqual(ob["type"], "tuic")
        self.assertEqual(ob["uuid"], "u")


class TestKnownTypes(unittest.TestCase):

    def test_includes_main_protocols(self):
        for t in ("direct", "block", "vless", "trojan",
                  "shadowsocks", "hysteria2", "tuic", "wireguard"):
            self.assertIn(t, KNOWN_OUTBOUND_TYPES)


if __name__ == "__main__":
    unittest.main()
