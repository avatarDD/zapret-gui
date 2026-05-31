# tests/test_singbox_config.py
"""Unit-тесты для core/singbox_config.py."""

import unittest

from core.singbox_config import (
    parse_conf, validate, render_conf, make_minimal_config,
    make_vless_outbound, make_trojan_outbound,
    make_shadowsocks_outbound, make_hysteria2_outbound,
    make_tuic_outbound, normalize_ss_method,
    make_selector_outbound, make_urltest_outbound,
    list_user_outbound_tags, wrap_in_group,
    KNOWN_OUTBOUND_TYPES,
)


class TestNormalizeSsMethod(unittest.TestCase):

    def test_alias_chacha20(self):
        self.assertEqual(normalize_ss_method("chacha20-poly1305"),
                         "chacha20-ietf-poly1305")
        self.assertEqual(normalize_ss_method("CHACHA20-POLY1305"),
                         "chacha20-ietf-poly1305")

    def test_supported_passthrough(self):
        self.assertEqual(normalize_ss_method("aes-256-gcm"), "aes-256-gcm")
        self.assertEqual(normalize_ss_method("2022-blake3-aes-256-gcm"),
                         "2022-blake3-aes-256-gcm")

    def test_unsupported_returns_empty(self):
        self.assertEqual(normalize_ss_method("aes-256-cfb"), "")
        self.assertEqual(normalize_ss_method("rc4-md5"), "")
        self.assertEqual(normalize_ss_method(""), "")

    def test_make_shadowsocks_normalizes(self):
        ob = make_shadowsocks_outbound("t", "h", 1, "chacha20-poly1305", "p")
        self.assertEqual(ob["method"], "chacha20-ietf-poly1305")


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


class TestSelectorAndUrltest(unittest.TestCase):

    def test_selector_default_first(self):
        ob = make_selector_outbound("sel", ["a", "b", "c"])
        self.assertEqual(ob["type"], "selector")
        self.assertEqual(ob["default"], "a")
        self.assertEqual(ob["outbounds"], ["a", "b", "c"])

    def test_selector_default_explicit(self):
        ob = make_selector_outbound("sel", ["a", "b"], default="b")
        self.assertEqual(ob["default"], "b")

    def test_selector_default_unknown_falls_back(self):
        # default не входит в outbounds → берём первый
        ob = make_selector_outbound("sel", ["a", "b"], default="xx")
        self.assertEqual(ob["default"], "a")

    def test_selector_requires_outbounds(self):
        with self.assertRaises(ValueError):
            make_selector_outbound("sel", [])
        with self.assertRaises(ValueError):
            make_selector_outbound("", ["a"])

    def test_urltest_basic(self):
        ob = make_urltest_outbound("auto", ["a", "b"])
        self.assertEqual(ob["type"], "urltest")
        self.assertIn("url", ob)
        self.assertIn("interval", ob)
        self.assertIn("tolerance", ob)

    def test_urltest_custom_params(self):
        ob = make_urltest_outbound(
            "auto", ["a"],
            url="https://example/health", interval="30s", tolerance=20)
        self.assertEqual(ob["url"], "https://example/health")
        self.assertEqual(ob["interval"], "30s")
        self.assertEqual(ob["tolerance"], 20)


class TestListUserOutboundTags(unittest.TestCase):

    def test_filters_service_outbounds(self):
        cfg = {"outbounds": [
            {"type": "direct",   "tag": "direct"},
            {"type": "block",    "tag": "block"},
            {"type": "selector", "tag": "auto"},
            {"type": "vless",    "tag": "v1"},
            {"type": "trojan",   "tag": "t1"},
        ]}
        self.assertEqual(list_user_outbound_tags(cfg), ["v1", "t1"])

    def test_empty(self):
        self.assertEqual(list_user_outbound_tags({}), [])
        self.assertEqual(list_user_outbound_tags(None), [])


class TestWrapInGroup(unittest.TestCase):

    def _sample(self):
        # Конфиг с 3 outbound'ами и route'ом, ведущим к одному из них.
        return {
            "inbounds": [{"type": "mixed", "tag": "in"}],
            "outbounds": [
                {"type": "vless",  "tag": "v1"},
                {"type": "trojan", "tag": "t1"},
                {"type": "direct", "tag": "direct"},
            ],
            "route": {
                "rules": [{"inbound": ["in"], "outbound": "v1"}],
                "final": "v1",
            },
        }

    def test_wrap_selector(self):
        cfg = wrap_in_group(self._sample(), "auto", "selector")
        # group первым в outbounds
        self.assertEqual(cfg["outbounds"][0]["type"], "selector")
        self.assertEqual(cfg["outbounds"][0]["tag"], "auto")
        self.assertEqual(cfg["outbounds"][0]["outbounds"], ["v1", "t1"])
        # route переехал на group
        self.assertEqual(cfg["route"]["rules"][0]["outbound"], "auto")
        self.assertEqual(cfg["route"]["final"], "auto")

    def test_wrap_urltest(self):
        cfg = wrap_in_group(self._sample(), "auto", "urltest")
        self.assertEqual(cfg["outbounds"][0]["type"], "urltest")
        self.assertIn("url", cfg["outbounds"][0])

    def test_wrap_no_outbounds(self):
        with self.assertRaises(ValueError):
            wrap_in_group({"outbounds": [{"type": "direct"}]},
                          "auto", "selector")

    def test_wrap_tag_collision(self):
        cfg = self._sample()
        with self.assertRaises(ValueError):
            wrap_in_group(cfg, "v1", "selector")   # v1 уже занят

    def test_wrap_invalid_type(self):
        with self.assertRaises(ValueError):
            wrap_in_group(self._sample(), "auto", "nonsense")


if __name__ == "__main__":
    unittest.main()
