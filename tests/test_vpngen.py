# tests/test_vpngen.py
"""Генератор конфигов WARP/Proton (core/vpngen): без сети, на подменах.

Что закреплено:
* тела запросов к Cloudflare такие же, как у usque (curve25519 → PATCH
  на secp256r1/masque), а наружу уходят только публичные ключи;
* Proton получает только публичный Ed25519, приватный ключ не покидает
  роутер;
* «авто»-транспорт переходит к следующему обходу только после СЕТЕВОЙ
  ошибки, а ответ API отдаётся сразу;
* у ванильного WireGuard-сервера S1..S4 = 0 и H1..H4 = 1..4 всегда;
* конфиги проходят парсеры своих движков;
* MCP не показывает приватные ключи, а откат удаляет созданное.
"""

import base64
import json
import unittest
from unittest import mock

from core.vpngen import generate as gen
from core.vpngen import keys, net, presets, proton, render, warp

PEER = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="


def _reg():
    return {"id": "dev1", "token": "tok1",
            "account": {"account_type": "free"},
            "config": {"client_id": "AQID",
                       "peers": [{"public_key": PEER, "endpoint": {
                           "v4": "162.159.192.1:0",
                           "v6": "[2606:4700:d0::a29f:c001]:0",
                           "host": "engage.cloudflareclient.com:2408"}}],
                       "interface": {"addresses": {
                           "v4": "172.16.0.2", "v6": "2606:4700:110::2"}}}}


def _masque_reg():
    pem = ("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n"
           % keys.p256_keypair()["public_der_b64"])
    return {"id": "dev1", "token": "tok1",
            "config": {"peers": [{"public_key": pem, "endpoint": {
                "v4": "162.159.198.1:0", "v6": "[2606:4700:103::1]:0"}}],
                "interface": {"addresses": {"v4": "172.16.0.2",
                                            "v6": "2606:4700:110::2"}}}}


class FakeCF:
    """Подмена request_json Cloudflare, записывающая запросы."""

    def __init__(self):
        self.calls = []

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if method == "PATCH":
            return _masque_reg()
        return _reg()


class TestWarpRequests(unittest.TestCase):

    def test_wireguard_registers_real_public_key(self):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf):
            prof = warp.wireguard_native("direct")
        method, url, kw = cf.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/v0a4471/reg"))
        body = kw["body"]
        self.assertEqual(body["key_type"], "curve25519")
        self.assertEqual(body["tunnel_type"], "wireguard")
        self.assertEqual(body["key"],
                         keys.wg_public_from_private(prof["private_key"]))
        self.assertNotIn(prof["private_key"], json.dumps(cf.calls))
        self.assertEqual(prof["endpoint_host"], "engage.cloudflareclient.com")
        self.assertEqual(prof["endpoint_port"], 2408)
        self.assertEqual(prof["reserved"], [1, 2, 3])

    def test_masque_switches_device_like_usque(self):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf):
            prof = warp.masque_native("direct", device_name="router")
        (m1, _u1, _k1), (m2, u2, k2) = cf.calls
        self.assertEqual((m1, m2), ("POST", "PATCH"))
        self.assertTrue(u2.endswith("/reg/dev1"))
        self.assertEqual(k2["body"]["key_type"], "secp256r1")
        self.assertEqual(k2["body"]["tunnel_type"], "masque")
        self.assertEqual(k2["body"]["name"], "router")
        self.assertEqual(k2["headers"]["Authorization"], "Bearer tok1")
        # SPKI публичного ключа уходит, SEC1 приватного — нет.
        self.assertNotIn(prof["private_key"], json.dumps(cf.calls))
        self.assertEqual(prof["endpoint_v4"], "162.159.198.1")
        self.assertEqual(prof["endpoint_v6"], "2606:4700:103::1")
        self.assertEqual(prof["access_token"], "tok1")

    def test_license_failure_is_a_warning(self):
        def fake(method, url, **kw):
            if method == "PUT":
                raise net.GenError("HTTP 400")
            return _reg()
        with mock.patch.object(warp, "request_json", side_effect=fake):
            prof = warp.wireguard_native("direct", license_key="bad")
        self.assertTrue(any("WARP+" in w for w in prof["warnings"]))

    def test_service_mode_marks_third_party_key(self):
        data = {"privKey": "k", "peer_pub": PEER, "client_ipv4": "172.16.0.2",
                "client_ipv6": "2606::2"}
        with mock.patch.object(warp, "request_json", return_value=data):
            prof = warp.wireguard_service("direct")
        self.assertEqual(prof["source"], "service")
        self.assertTrue(any("сервис-генератор" in w for w in prof["warnings"]))


class TestProton(unittest.TestCase):

    def setUp(self):
        proton.reset()

    def test_only_public_key_goes_to_service(self):
        calls = []

        def fake(path, body, transport):
            calls.append((path, body))
            if path.endswith("/session"):
                return {"ok": True, "session": {"uid": "u"}}
            if path.endswith("/servers"):
                return {"ok": True, "servers": [
                    {"id": "1", "name": "NL-FREE#1", "exitCountry": "NL",
                     "city": "Amsterdam", "load": 70,
                     "entryIp": "1.2.3.4", "publicKey": PEER},
                    {"id": "2", "name": "NL-FREE#2", "exitCountry": "NL",
                     "city": "Amsterdam", "load": 10,
                     "entryIp": "1.2.3.5", "publicKey": PEER}]}
            return {"ok": True}
        with mock.patch.object(proton, "_call", side_effect=fake):
            prof = proton.generate("direct", country="NL")
        self.assertEqual(prof["server"]["id"], "2")          # меньше нагрузка
        cert = calls[-1][1]
        self.assertIn("BEGIN PUBLIC KEY", cert["clientPublicKey"])
        self.assertNotIn(prof["private_key"], json.dumps(calls))
        self.assertEqual(prof["ipv4"], "10.2.0.2")

    def test_expired_session_is_reset(self):
        with mock.patch.object(proton, "request_json",
                               return_value={"ok": False,
                                             "error": "Invalid session"}):
            with self.assertRaises(net.GenError):
                proton._call("/api/proton/servers", {}, "direct")
        self.assertIsNone(proton._state["session"])


def _proton_conf(endpoint="185.107.56.1:51820"):
    priv, _ = keys.x25519_keypair()
    return ("[Interface]\n# Key for router\nPrivateKey = %s\n"
            "Address = 10.2.0.2/32, 2a07:b944::2:2/128\nDNS = 10.2.0.1\n\n"
            "[Peer]\n# NL-FREE#123\nPublicKey = %s\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\n"
            % (priv, PEER, endpoint)), priv


class TestProtonImport(unittest.TestCase):
    """Свой конфиг Proton — когда сервис закрыт (Cloudflare 1010)."""

    def test_from_config(self):
        text, priv = _proton_conf()
        prof = proton.from_config(text)
        self.assertEqual((prof["private_key"], prof["peer_public_key"]),
                         (priv, PEER))
        self.assertEqual((prof["endpoint_host"], prof["endpoint_port"]),
                         ("185.107.56.1", 51820))
        self.assertEqual(prof["ipv4"], "10.2.0.2")
        self.assertEqual(prof["server"]["country"], "NL")
        self.assertEqual(prof["source"], "import")
        self.assertEqual(proton.from_config(text, port=443)["endpoint_port"],
                         443)

    def test_rejects_psk_and_many_peers(self):
        text, _ = _proton_conf()
        psk = text.replace("AllowedIPs", "PresharedKey = %s\nAllowedIPs" % PEER)
        two = text + "\n[Peer]\nPublicKey = %s\nEndpoint = 1.1.1.1:51820\n" % PEER
        for bad in (psk, two):
            with self.assertRaises(net.GenError):
                proton.from_config(bad)

    def test_interface_comment_is_not_server(self):
        text, _ = _proton_conf()
        text = text.replace("# Key for router", "# ROUTER").replace(
            "# NL-FREE#123\n", "")
        self.assertEqual(proton.from_config(text)["server"]["name"], "")

    def test_ipv6_endpoint(self):
        text, _ = _proton_conf("[2a07:b944::1]:51820")
        self.assertEqual(proton.from_config(text)["endpoint_host"],
                         "2a07:b944::1")

    def test_bad_configs(self):
        text, _ = _proton_conf()
        for bad in ("", text.replace("[Peer]", "[Nope]"),
                    text.replace("PublicKey = ", "PublicKey = zz"),
                    text.replace("185.107.56.1:51820", "185.107.56.1"),
                    text.replace("10.2.0.2/32, ", "")):
            with self.subTest(bad=bad[-60:]):
                with self.assertRaises(net.GenError):
                    proton.from_config(bad)

    def test_generate_without_network(self):
        text, priv = _proton_conf()
        with mock.patch.object(net, "request_json",
                               side_effect=AssertionError("сеть")), \
             mock.patch.object(gen, "_existing_names", return_value=set()):
            res = gen.generate({"provider": "proton", "source": "import",
                                "config": text, "targets": ["awg", "mihomo"],
                                "transport": "direct",
                                "options": {"mask": "quic"}})
        self.assertIn("PrivateKey = %s" % priv, res["results"]["awg"]["text"])
        self.assertIn("I1 = ", res["results"]["awg"]["text"])
        self.assertIn("185.107.56.1", res["results"]["mihomo"]["text"])


class TestCheckOutput(unittest.TestCase):
    """Кнопка «Проверить»: синтаксис без сохранения."""

    def _gen(self, target, provider="warp", protocol="wireguard"):
        prof = _wg_profile()
        opts = gen.normalize_options(provider, protocol, {"mask": "quic"})
        opts["label"] = "WARP"
        opts["listen_port"] = 1080
        return gen.render_target(target, prof, opts)

    def test_generated_configs_pass(self):
        nobin = mock.Mock()
        nobin.check_text.return_value = {"ok": False, "no_binary": True}
        nobin._binary.return_value = ""
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=nobin), \
             mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=nobin):
            for target in ("awg", "singbox", "mihomo"):
                with self.subTest(target=target):
                    r = gen.check_output(target, self._gen(target))
                    self.assertTrue(r["ok"], r)
                    self.assertTrue(r["checked_by"])
            # движок не установлен — честное предупреждение
            r = gen.check_output("singbox", self._gen("singbox"))
            self.assertIn("не установлен", r["warnings"][0])

    def test_usque_config_passes(self):
        with mock.patch.object(warp, "request_json", FakeCF()):
            prof = warp.masque_native("direct", device_name="router")
        opts = gen.normalize_options("warp", "masque", {})
        r = gen.check_output("usque", gen.render_target("usque", prof, opts))
        self.assertTrue(r["ok"], r)

    def test_mihomo_with_geo_rules_not_run(self):
        mgr = mock.Mock()
        mgr._binary.return_value = "/opt/bin/mihomo"
        text = self._gen("mihomo").replace("- MATCH,", "- GEOIP,CN,DIRECT\n- MATCH,")
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr):
            r = gen.check_output("mihomo", text)
        self.assertTrue(r["ok"], r)
        mgr.validate_via_binary.assert_not_called()
        self.assertIn("внешние базы", r["warnings"][0])

    def test_singbox_check_uses_unique_private_tmp(self):
        # Параллельные проверки не должны писать в один файл, а сам файл
        # (в нём приватный ключ) — быть читаемым всеми.
        import os
        import stat
        import tempfile
        from core import singbox_manager as sm
        seen = []

        def fake_run(args, timeout=15, input_text=None):
            path = args[-1]
            seen.append((path, stat.S_IMODE(os.stat(path).st_mode),
                         open(path).read()))
            return 0, "", ""
        with tempfile.TemporaryDirectory() as d:
            mgr = sm.SingboxManager.__new__(sm.SingboxManager)
            plat = mock.Mock(run_dir=d)
            with mock.patch.object(sm.SingboxManager, "_binary",
                                   return_value="/bin/sing-box"), \
                 mock.patch.object(sm.SingboxManager, "_platform",
                                   return_value=plat), \
                 mock.patch.object(sm, "_run", side_effect=fake_run):
                self.assertTrue(mgr.check_text("{\"a\":1}")["ok"])
                self.assertTrue(mgr.check_text("{\"b\":2}")["ok"])
            self.assertEqual(os.listdir(d), [])            # убраны
        self.assertNotEqual(seen[0][0], seen[1][0])
        self.assertEqual([m for _p, m, _t in seen], [0o600, 0o600])
        self.assertEqual([t for _p, _m, t in seen], ['{"a":1}', '{"b":2}'])

    def test_engine_error_is_readable(self):
        self.assertEqual(gen._engine_error(
            'time="t" level=info msg="Start"\n'
            'time="t" level=error msg="proxy 0: unsupport proxy type: x"'),
            "proxy 0: unsupport proxy type: x")
        self.assertEqual(gen._engine_error(
            "\x1b[31mFATAL\x1b[0m[0000] decode config at "
            "/var/run/sing-box/_zg-check-ab.json: inbounds[0].x: unknown"),
            "decode config inbounds[0].x: unknown")

    def test_binary_verdict_wins(self):
        mgr = mock.Mock()
        mgr.check_text.return_value = {"ok": False, "error": "unknown field"}
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr):
            r = gen.check_output("singbox", self._gen("singbox"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["errors"], ["unknown field"])
        self.assertIn("sing-box check", r["checked_by"])

    def test_broken_configs_fail(self):
        cases = {
            "awg": "[Interface]\nPrivateKey = нет\n",
            "usque": "{\"private_key\": \"x\"}",
            "singbox": "{not json",
            "mihomo": "mode: rule\n",
            "proton-import": "[Interface]\n",
        }
        for target, text in cases.items():
            with self.subTest(target=target):
                r = gen.check_output(target, text)
                self.assertFalse(r["ok"])
                self.assertTrue(r["errors"])
        self.assertFalse(gen.check_output("evil", "x")["ok"])
        self.assertFalse(gen.check_output("awg", "  ")["ok"])

    def test_proton_import_summary(self):
        text, _ = _proton_conf()
        r = gen.check_output("proton-import", text)
        self.assertTrue(r["ok"], r)
        self.assertIn("185.107.56.1:51820", r["summary"])

    def test_api_check_saved_by_name(self):
        from tests._wsgi_client import WSGIClient, build_test_app
        client = WSGIClient(build_test_app())
        text = self._gen("awg")
        with mock.patch("core.tunnels_control.config_get",
                        return_value={"ok": True, "text": text}) as cg:
            r = client.post_json("/api/vpngen/check",
                                 {"target": "awg", "name": "warp"})
        self.assertTrue(r["ok"], r)
        cg.assert_called_once_with("awg", "warp")
        # Чужое имя (обход каталога) — отказ до чтения файла.
        r = client.post_json("/api/vpngen/check",
                             {"target": "awg", "name": "../../etc/passwd"})
        self.assertFalse(r["ok"])

    def test_load_saved_usque(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "warp.json")
            with open(path, "w") as f:
                f.write('{"a": 1}')
            mgr = mock.Mock()
            mgr.list_configs.return_value = [{"name": "warp", "path": path}]
            with mock.patch("core.usque_manager.get_usque_manager",
                            return_value=mgr):
                self.assertEqual(gen.load_saved("usque", "warp"), '{"a": 1}')
                with self.assertRaises(net.GenError):
                    gen.load_saved("usque", "nope")

    def test_api_check(self):
        from tests._wsgi_client import WSGIClient, build_test_app
        client = WSGIClient(build_test_app())
        r = client.post_json("/api/vpngen/check",
                             {"target": "awg", "text": self._gen("awg")})
        self.assertTrue(r["ok"], r)


class TestCloudflareBlocked(unittest.TestCase):

    def _http_error(self, body):
        import io
        import urllib.error
        return urllib.error.HTTPError("https://x", 403, "Forbidden", {},
                                      io.BytesIO(body.encode()))

    def test_1010_is_blocked_not_network(self):
        body = ('{"type":"…error-1010/","title":"Error 1010: Access denied",'
                '"status":403,"error_code":1010,'
                '"error_name":"browser_signature_banned"}')
        opener = mock.Mock()
        opener.open.side_effect = self._http_error(body)
        with mock.patch.object(net, "_opener", return_value=opener):
            with self.assertRaises(net.GenError) as cm:
                net.request_json("POST", "https://www.api-proton.workers.dev/x",
                                 body={})
        e = cm.exception
        self.assertTrue(e.blocked)
        self.assertFalse(e.network)                 # «Авто» не перебирает
        self.assertIn("1010", str(e))
        self.assertNotIn("browser_signature", str(e))

    def test_ip_ban_tries_next_transport(self):
        # 1009 (страна) — от адреса зависит: «Авто» должно пробовать обход.
        opener = mock.Mock()
        opener.open.side_effect = self._http_error('{"error_code":1009}')
        with mock.patch.object(net, "_opener", return_value=opener):
            with self.assertRaises(net.GenError) as cm:
                net.request_json("GET", "https://x.example/a")
        self.assertTrue(cm.exception.network)
        self.assertFalse(cm.exception.blocked)

    def test_plain_403_is_not_blocked(self):
        self.assertEqual(net._cf_access_denied('{"error":"nope"}'), "")
        self.assertEqual(net._cf_access_denied("error code: 1020"), "1020")


class TestTransport(unittest.TestCase):

    def test_auto_falls_through_on_network_errors_only(self):
        tried = []

        def fn(t):
            tried.append(t)
            if t == "direct":
                raise net.GenError("timeout", network=True)
            return "ok"
        with mock.patch.object(net, "transports_for",
                               return_value=["direct", "awg:awg0"]):
            res, used, failed = net.run_with_transport("auto", fn)
        self.assertEqual((res, used), ("ok", "awg:awg0"))
        self.assertEqual(len(failed), 1)

    def test_api_error_is_not_retried_elsewhere(self):
        tried = []

        def fn(t):
            tried.append(t)
            raise net.GenError("HTTP 400", status=400)
        with mock.patch.object(net, "transports_for",
                               return_value=["direct", "awg:awg0"]):
            with self.assertRaises(net.GenError):
                net.run_with_transport("auto", fn)
        self.assertEqual(tried, ["direct"])


class TestPresets(unittest.TestCase):

    def test_public_allowed_ips_exclude_lan(self):
        import ipaddress
        nets = [ipaddress.ip_network(n)
                for n in presets.allowed_ips("public", ipv6=False)]
        lan = ipaddress.ip_address("192.168.1.10")
        self.assertFalse(any(lan in n for n in nets))
        self.assertTrue(any(ipaddress.ip_address("8.8.8.8") in n
                            for n in nets))

    def test_dns_without_ipv6(self):
        self.assertEqual(presets.dns_servers("google", ipv6=False),
                         ["8.8.8.8", "8.8.4.4"])
        self.assertEqual(presets.dns_servers("provider", ipv6=True,
                                             provider="proton"),
                         ["10.2.0.1", "2a07:b944::2:1"])

    def test_masks(self):
        q = presets.masks("quic", sni="ozon.ru")["I1"]
        self.assertTrue(q.startswith("<b 0xc"))            # long header
        self.assertGreaterEqual(len(q), 2 * 1200)
        self.assertEqual(set(presets.masks("sip")), {"I1", "I2"})
        self.assertEqual(presets.masks("none"), {})
        self.assertEqual(presets.masks("custom", custom="<r 32>"),
                         {"I1": "<r 32>"})
        with self.assertRaises(ValueError):
            presets.masks("custom", custom="0xdeadbeef")

    def test_dns_mask_encodes_name(self):
        raw = bytes.fromhex(presets.dns_mask("vk.com")[5:-1])
        self.assertIn(b"\x02vk\x03com\x00", raw)


class TestNormalize(unittest.TestCase):

    def test_bad_values_rejected(self):
        for raw in ({"mtu": 900}, {"keepalive": "x"},
                    {"endpoint_mode": "custom", "endpoint": "nohost"},
                    {"junk": {"Jc": 4, "Jmin": 100, "Jmax": 50}},
                    {"awg3": {"RekeyTimeout": "1;rm"}}):
            with self.subTest(raw=raw):
                with self.assertRaises(net.GenError):
                    gen.normalize_options("warp", "wireguard", raw)

    def test_masque_forces_mtu_1280(self):
        with mock.patch.object(gen, "default_sni", return_value="ozon.ru"):
            o = gen.normalize_options("warp", "masque", {"mtu": 1400})
        self.assertEqual(o["mtu"], 1280)
        self.assertEqual(o["sni"], "ozon.ru")


def _wg_profile():
    priv, _ = keys.x25519_keypair()
    return {"provider": "warp", "protocol": "wireguard",
            "private_key": priv, "peer_public_key": PEER,
            "ipv4": "172.16.0.2", "ipv6": "2606:4700:110::2",
            "endpoint_host": "engage.cloudflareclient.com",
            "endpoint_port": 2408, "reserved": [1, 2, 3]}


class TestRender(unittest.TestCase):

    def setUp(self):
        self.opts = gen.normalize_options(
            "warp", "wireguard", {"mask": "sip", "junk": "light"})
        self.opts["label"] = "WARP"

    def test_awg_keeps_vanilla_wireguard_fields(self):
        from core.awg_config import parse_conf, validate
        text = render.awg_conf(_wg_profile(), self.opts)
        cfg = parse_conf(text)
        iface = cfg["interface"]
        self.assertEqual([str(iface[k]) for k in ("S1", "S2")], ["0", "0"])
        self.assertEqual([str(iface["H%d" % i]) for i in range(1, 5)],
                         ["1", "2", "3", "4"])
        self.assertIn("I2", iface)
        self.assertEqual(validate(cfg), [])

    def test_awg_without_obfuscation_is_plain_wireguard(self):
        # «Jc»/«H1» ищем в полях распарсенного конфига, а не в тексте:
        # PrivateKey — случайный base64 и с шансом ~1% за прогон содержит
        # «Jc» (и «H1») просто как пару букв (поймано прогоном CI).
        from core.awg_config import parse_conf
        opts = gen.normalize_options("warp", "wireguard",
                                     {"mask": "none", "junk": "off"})
        cfg = parse_conf(render.awg_conf(_wg_profile(), opts))
        iface = cfg["interface"]
        self.assertNotIn("Jc", iface)
        self.assertNotIn("H1", iface)

    def test_singbox_uses_endpoints(self):
        from core.singbox_config import parse_conf, validate
        cfg = json.loads(render.singbox_json(_wg_profile(), self.opts))
        self.assertEqual(cfg["endpoints"][0]["type"], "wireguard")
        self.assertFalse(any(o["type"] == "wireguard"
                             for o in cfg["outbounds"]))
        self.assertEqual(cfg["endpoints"][0]["peers"][0]["reserved"],
                         [1, 2, 3])
        self.assertEqual(validate(parse_conf(json.dumps(cfg))), [])

    def test_mihomo_wireguard_with_amnezia_options(self):
        from core.clash_yaml import parse_yaml
        y = parse_yaml(render.mihomo_yaml(_wg_profile(), self.opts))
        p = y["proxies"][0]
        self.assertEqual(p["type"], "wireguard")
        self.assertEqual(p["amnezia-wg-option"]["jc"], 4)
        self.assertIn("i1", p["amnezia-wg-option"])
        self.assertEqual(y["rules"], ["MATCH,WARP-group"])

    def test_mihomo_masque_public_key_is_bare_spki(self):
        from core.clash_yaml import parse_yaml
        with mock.patch.object(warp, "request_json", FakeCF()):
            prof = warp.masque_native("direct")
        y = parse_yaml(render.mihomo_yaml(prof, {"label": "M", "dns": []}))
        self.assertEqual([p.get("network") for p in y["proxies"]],
                         [None, "h2"])
        self.assertNotIn("BEGIN", y["proxies"][0]["public-key"])
        base64.b64decode(y["proxies"][0]["public-key"])
        self.assertEqual(y["proxy-groups"][0]["type"], "fallback")

    def test_usque_json_fields(self):
        with mock.patch.object(warp, "request_json", FakeCF()):
            prof = warp.masque_native("direct")
        data = json.loads(render.usque_json(prof, {}))
        from core.usque_manager import UsqueManager
        self.assertEqual(set(data), set(UsqueManager._USQUE_KNOWN) - {"license"})


class TestGenerate(unittest.TestCase):

    def _run(self, req, saved=True):
        cf = FakeCF()
        with mock.patch.object(warp, "request_json", cf), \
             mock.patch.object(gen, "_existing_names", return_value=set()), \
             mock.patch.object(gen, "_ports_in_configs", return_value=set()), \
             mock.patch.object(gen, "save_output",
                               return_value={"ok": saved, "name": "x"}) as so:
            return gen.generate(req), so

    def test_incompatible_target_rejected(self):
        with self.assertRaises(net.GenError):
            gen.generate({"provider": "warp", "protocol": "masque",
                          "targets": ["singbox"], "transport": "direct"})
        with self.assertRaises(net.GenError):
            gen.generate({"provider": "proton", "targets": ["usque"],
                          "transport": "direct"})

    def test_one_registration_many_targets(self):
        res, so = self._run({"provider": "warp", "protocol": "wireguard",
                             "targets": ["awg", "singbox", "mihomo"],
                             "transport": "direct", "save": True})
        self.assertEqual(set(res["results"]), {"awg", "singbox", "mihomo"})
        self.assertEqual(so.call_count, 3)
        self.assertTrue(res["ok"])
        self.assertTrue(any("одно и то же устройство" in w
                            for w in res["warnings"]))
        ports = {res["results"][t]["listen_port"]
                 for t in ("singbox", "mihomo")}
        self.assertEqual(len(ports), 2)

    def test_save_failure_reported(self):
        res, _ = self._run({"provider": "warp", "targets": ["awg"],
                            "transport": "direct", "save": True},
                           saved=False)
        self.assertFalse(res["ok"])

    def test_mask_hides_keys(self):
        res, _ = self._run({"provider": "warp", "targets": ["awg"],
                            "transport": "direct"})
        text = gen.mask(res["results"]["awg"]["text"], res["secrets"])
        self.assertNotIn(res["secrets"][0], text)
        self.assertIn("«скрыто»", text)


class TestNames(unittest.TestCase):

    def test_unique_and_valid(self):
        self.assertEqual(gen.unique_name("awg", "warp", taken={"warp"}),
                         "warp-2")
        name = gen.unique_name("awg", "proton-very-long-country",
                               taken=set())
        self.assertLessEqual(len(name), 15)
        self.assertTrue(gen.valid_name("awg", name))
        self.assertFalse(gen.valid_name("usque", "a.b"))

    def test_save_output_refuses_existing(self):
        with mock.patch.object(gen, "_existing_names",
                               return_value={"warp"}):
            res = gen.save_output("awg", "warp", "[Interface]\n")
        self.assertFalse(res["ok"])
        self.assertIn("уже есть", res["error"])


    def test_save_output_fails_closed(self):
        # Список не прочитан — не сохраняем (иначе перезапись чужого).
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        side_effect=OSError("нет доступа")):
            res = gen.save_output("mihomo", "warp", "proxies: []\n")
        self.assertFalse(res["ok"])
        self.assertIn("не получен", res["error"])

    def test_save_output_reports_os_error(self):
        mgr = mock.Mock()
        mgr.save_config.side_effect = OSError("Read-only file system")
        with mock.patch.object(gen, "_existing_names", return_value=set()), \
             mock.patch("core.awg_manager.get_awg_manager", return_value=mgr):
            res = gen.save_output("awg", "warp", "[Interface]\n")
        self.assertFalse(res["ok"])
        self.assertIn("Read-only", res["error"])


class TestRobustness(unittest.TestCase):

    def test_proton_requires_explicit_ok(self):
        with mock.patch.object(proton, "request_json",
                               return_value={"error": "bad key"}):
            with self.assertRaises(net.GenError):
                proton._call("/api/proton/certificate", {}, "direct")

    def test_proton_load_tolerant(self):
        self.assertEqual(proton._normalize({"load": "12.5"})["load"], 12)
        self.assertEqual(proton._normalize({"load": "N/A"})["load"], 0)

    def test_mihomo_label_with_comma(self):
        opts = gen.normalize_options("warp", "wireguard", {})
        opts["label"] = "My, VPN"
        text = render.mihomo_yaml(_wg_profile(), opts)
        # Имя прокси с запятой допустимо; в правило попадает группа.
        self.assertIn("- MATCH,My VPN\n", text)

    def test_missing_bypass_is_network_error(self):
        with mock.patch("core.download_transport.build_opener",
                        side_effect=RuntimeError("интерфейс не найден")):
            with self.assertRaises(net.GenError) as cm:
                net._opener("awg:gone")
        self.assertTrue(cm.exception.network)

    def test_post_not_retried(self):
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("timed out")
        with mock.patch.object(net, "_opener", return_value=opener), \
             mock.patch.object(net.time, "sleep"):
            with self.assertRaises(net.GenError):
                net.request_json("POST", "https://x.example/reg", body={})
        self.assertEqual(opener.open.call_count, 1)


class TestMcpTool(unittest.TestCase):

    def test_generate_masks_keys_and_records_undo(self):
        from core.mcp.tools import vpngen as tool
        fake = {"ok": True, "results": {"awg": {
                    "name": "warp", "saved": True,
                    "text": "PrivateKey = SECRET\n"}},
                "secrets": ["SECRET"], "warnings": []}
        with mock.patch.object(gen, "generate", return_value=fake), \
             mock.patch.object(tool.audit, "snapshot",
                               return_value={"id": "s1"}) as snap:
            out = tool.vpngen_generate({"provider": "warp"})
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(snap.call_args.args[3],
                         [{"target": "awg", "name": "warp"}])

    def test_undo_deletes_created(self):
        from core.mcp.tools import vpngen as tool
        with mock.patch.object(gen, "delete_output",
                               return_value={"ok": True}) as d:
            out = tool._undo_generated(
                {"after": [{"target": "awg", "name": "warp"}]})
        self.assertTrue(out["ok"])
        d.assert_called_once_with("awg", "warp")


class TestApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_options(self):
        r = self.client.get_json("/api/vpngen/options")
        self.assertTrue(r["ok"])
        self.assertEqual({t["id"] for t in r["targets"]},
                         {"awg", "usque", "singbox", "mihomo"})

    def test_bad_transport_rejected(self):
        r = self.client.post_json("/api/vpngen/generate",
                                  {"provider": "warp", "transport": "ftp:x"})
        self.assertFalse(r["ok"])

    def test_generate_hides_secret_list(self):
        fake = {"ok": True, "results": {}, "secrets": ["S"]}
        with mock.patch("core.vpngen.generate.generate", return_value=fake):
            r = self.client.post_json("/api/vpngen/generate",
                                      {"provider": "warp"})
        self.assertNotIn("secrets", r)

    def test_proton_servers_reports_blocked(self):
        err = net.GenError("закрыто", status=403, blocked=True)
        with mock.patch("core.vpngen.proton.servers", side_effect=err):
            r = self.client.post_json("/api/vpngen/proton/servers",
                                      {"transport": "direct"})
        self.assertFalse(r["ok"])
        self.assertTrue(r["blocked"])

    def test_save_validates_target(self):
        r = self.client.post_json("/api/vpngen/save",
                                  {"target": "evil", "name": "x", "text": "y"})
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
