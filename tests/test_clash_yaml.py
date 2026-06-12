# tests/test_clash_yaml.py
"""Unit-тесты для core/clash_yaml.py."""

import unittest

from core.clash_yaml import (
    parse_yaml, parse_clash_yaml, _parse_scalar,
)


SIMPLE_CLASH = """
proxies:
  - name: "My VLESS"
    type: vless
    server: vpn.example.com
    port: 443
    uuid: aaaa-bbbb-cccc
    network: tcp
    tls: true
    servername: cf.com
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: PUBKEY123
      short-id: 01

  - name: "Trojan-2"
    type: trojan
    server: trojan.host
    port: 443
    password: secret
    sni: t.example
    skip-cert-verify: true

  - name: SS-3
    type: ss
    server: ss.host
    port: 8388
    cipher: aes-128-gcm
    password: sspass

  - name: Hy2
    type: hysteria2
    server: hy2.host
    port: 443
    password: hypass
    sni: hy2.example

  - name: TuicX
    type: tuic
    server: tuic.host
    port: 443
    uuid: tu-uuid
    password: tupass
    sni: t.host
"""


WS_CLASH = """
proxies:
  - name: ws-vless
    type: vless
    server: h
    port: 443
    uuid: u
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: ws.example.com
    tls: true
"""


class TestParseScalar(unittest.TestCase):

    def test_quoted_string(self):
        self.assertEqual(_parse_scalar('"hello"'), 'hello')
        self.assertEqual(_parse_scalar("'world'"), 'world')

    def test_bool(self):
        self.assertTrue(_parse_scalar("true"))
        self.assertFalse(_parse_scalar("false"))
        self.assertTrue(_parse_scalar("yes"))

    def test_int(self):
        self.assertEqual(_parse_scalar("443"), 443)
        self.assertEqual(_parse_scalar("-7"), -7)

    def test_float(self):
        self.assertEqual(_parse_scalar("3.14"), 3.14)

    def test_null(self):
        self.assertIsNone(_parse_scalar("null"))

    def test_raw_string(self):
        self.assertEqual(_parse_scalar("foo-bar"), "foo-bar")


class TestParseYaml(unittest.TestCase):
    """Базовый YAML парсер должен правильно понять clash-структуру."""

    def test_simple_clash(self):
        data = parse_yaml(SIMPLE_CLASH)
        self.assertIn("proxies", data)
        self.assertEqual(len(data["proxies"]), 5)
        first = data["proxies"][0]
        self.assertEqual(first["name"], "My VLESS")
        self.assertEqual(first["type"], "vless")
        self.assertEqual(first["port"], 443)
        self.assertTrue(first["tls"])
        # reality-opts → nested dict
        self.assertIn("reality-opts", first)
        self.assertEqual(first["reality-opts"]["public-key"], "PUBKEY123")
        # YAML `01` без кавычек pyyaml парсит как int 1; самописный
        # parser оставит как "01". Тест толерантен к обоим.
        self.assertIn(first["reality-opts"]["short-id"], (1, "01"))

    def test_ws_opts(self):
        data = parse_yaml(WS_CLASH)
        p = data["proxies"][0]
        self.assertEqual(p["network"], "ws")
        # ws-opts nested + дальше headers
        self.assertIn("ws-opts", p)
        self.assertEqual(p["ws-opts"]["path"], "/ray")

    def test_empty(self):
        self.assertEqual(parse_yaml(""), {})
        self.assertEqual(parse_yaml("   "), {})


class TestParseClashYaml(unittest.TestCase):

    def test_all_protocols(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        self.assertTrue(r["ok"])
        types = sorted({o["type"] for o in r["outbounds"]})
        self.assertEqual(types, ["hysteria2", "shadowsocks",
                                  "trojan", "tuic", "vless"])
        # Все имеют tag
        for o in r["outbounds"]:
            self.assertTrue(o.get("tag"))
            self.assertTrue(o.get("server"))
            self.assertTrue(o.get("server_port"))

    def test_vless_reality(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        vless = [o for o in r["outbounds"] if o["type"] == "vless"][0]
        self.assertEqual(vless["uuid"], "aaaa-bbbb-cccc")
        self.assertEqual(vless["flow"], "xtls-rprx-vision")
        self.assertTrue(vless["tls"]["enabled"])
        self.assertEqual(vless["tls"]["server_name"], "cf.com")
        self.assertEqual(vless["tls"]["reality"]["public_key"], "PUBKEY123")
        # Тоже толерантно — см. test_simple_clash.
        self.assertIn(vless["tls"]["reality"]["short_id"], ("01", "1"))
        self.assertEqual(vless["tls"]["utls"]["fingerprint"], "chrome")

    def test_reality_without_fingerprint_defaults_chrome(self):
        # reality-opts без client-fingerprint → utls должен проставиться
        # по умолчанию (sing-box требует utls для reality).
        yaml = (
            "proxies:\n"
            "  - name: r1\n"
            "    type: vless\n"
            "    server: ex.com\n"
            "    port: 443\n"
            "    uuid: u-1\n"
            "    tls: true\n"
            "    reality-opts:\n"
            "      public-key: PK\n"
            "      short-id: \"ab\"\n"
        )
        r = parse_clash_yaml(yaml)
        self.assertTrue(r["ok"], msg=r.get("error"))
        v = [o for o in r["outbounds"] if o["type"] == "vless"][0]
        self.assertTrue(v["tls"]["reality"]["enabled"])
        self.assertEqual(v["tls"]["utls"],
                         {"enabled": True, "fingerprint": "chrome"})

    def test_vision_udp443_flow_normalized(self):
        # Xray-вариант flow → vision (sing-box иного не принимает).
        yaml = (
            "proxies:\n"
            "  - name: u443\n"
            "    type: vless\n"
            "    server: ex.com\n"
            "    port: 443\n"
            "    uuid: u-1\n"
            "    flow: xtls-rprx-vision-udp443\n"
        )
        r = parse_clash_yaml(yaml)
        self.assertTrue(r["ok"], msg=r.get("error"))
        v = [o for o in r["outbounds"] if o["type"] == "vless"][0]
        self.assertEqual(v["flow"], "xtls-rprx-vision")

    def test_legacy_flow_skipped(self):
        # Легаси xtls-flow sing-box не примет («unsupported flow») —
        # сервер пропускается, как ss с легаси stream-шифром.
        yaml = (
            "proxies:\n"
            "  - name: legacy\n"
            "    type: vless\n"
            "    server: ex.com\n"
            "    port: 443\n"
            "    uuid: u-1\n"
            "    flow: xtls-rprx-splice\n"
        )
        r = parse_clash_yaml(yaml)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(
            [o for o in r["outbounds"] if o["type"] == "vless"], [])
        self.assertEqual(len(r["skipped"]), 1)

    def test_trojan_skip_cert_verify(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        tr = [o for o in r["outbounds"] if o["type"] == "trojan"][0]
        self.assertEqual(tr["password"], "secret")
        self.assertTrue(tr["tls"]["insecure"])
        self.assertEqual(tr["tls"]["server_name"], "t.example")

    def test_ss(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        ss = [o for o in r["outbounds"] if o["type"] == "shadowsocks"][0]
        self.assertEqual(ss["method"], "aes-128-gcm")
        self.assertEqual(ss["password"], "sspass")

    def test_hysteria2(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        hy = [o for o in r["outbounds"] if o["type"] == "hysteria2"][0]
        self.assertEqual(hy["password"], "hypass")

    def test_tuic(self):
        r = parse_clash_yaml(SIMPLE_CLASH)
        tu = [o for o in r["outbounds"] if o["type"] == "tuic"][0]
        self.assertEqual(tu["uuid"], "tu-uuid")
        self.assertEqual(tu["password"], "tupass")

    def test_ws_transport(self):
        r = parse_clash_yaml(WS_CLASH)
        self.assertTrue(r["ok"])
        v = r["outbounds"][0]
        self.assertEqual(v["transport"]["type"], "ws")
        self.assertEqual(v["transport"]["path"], "/ray")

    def test_empty_yaml(self):
        r = parse_clash_yaml("")
        # Семантика: нет 'proxies' → ok=False с человекочитаемой ошибкой.
        self.assertFalse(r["ok"])
        self.assertIn("proxies", r["error"].lower())

    def test_no_proxies_section(self):
        r = parse_clash_yaml("hello: world\n")
        self.assertFalse(r["ok"])
        self.assertIn("proxies", r["error"].lower())

    def test_unknown_type_skipped(self):
        text = """
proxies:
  - name: Direct
    type: direct
    server: foo
    port: 1
"""
        r = parse_clash_yaml(text)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["outbounds"]), 0)
        self.assertEqual(len(r["skipped"]), 1)
        self.assertEqual(r["skipped"][0]["type"], "direct")

    def test_dedup_tags(self):
        text = """
proxies:
  - name: same
    type: ss
    server: a
    port: 1
    cipher: aes-128-gcm
    password: p
  - name: same
    type: ss
    server: b
    port: 2
    cipher: aes-128-gcm
    password: p
"""
        r = parse_clash_yaml(text)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["outbounds"]), 2)
        tags = [o["tag"] for o in r["outbounds"]]
        self.assertEqual(len(set(tags)), 2)


if __name__ == "__main__":
    unittest.main()
