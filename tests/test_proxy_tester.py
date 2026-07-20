# tests/test_proxy_tester.py
"""Unit-тесты для core/proxy_tester.py (чистые помощники, без бинаря)."""

import types
import unittest
from unittest import mock

from core import proxy_tester as pt
from core.proxy_tester import build_test_config, parse_delay


class TestResolveTarget(unittest.TestCase):

    def test_presets(self):
        self.assertIn("cloudflare", pt.resolve_target("cloudflare"))
        self.assertIn("aws", pt.resolve_target("amazon"))
        self.assertIn("gstatic", pt.resolve_target("google"))

    def test_custom_url(self):
        self.assertEqual(pt.resolve_target("https://x.example/204"),
                         "https://x.example/204")

    def test_empty_defaults_cloudflare(self):
        self.assertIn("cloudflare", pt.resolve_target(""))

    def test_unknown_defaults(self):
        self.assertEqual(pt.resolve_target("nonsense"),
                         pt.TARGET_PRESETS[pt.DEFAULT_TARGET])


class TestBuildTestConfig(unittest.TestCase):

    def _obs(self):
        return [
            {"type": "vless", "tag": "a", "server": "1.1.1.1",
             "server_port": 443, "uuid": "u"},
            {"type": "trojan", "tag": "b", "server": "2.2.2.2",
             "server_port": 443, "password": "p"},
        ]

    def test_structure(self):
        cfg = build_test_config(self._obs(), clash_port=9090,
                                clash_secret="s3cr3t", mixed_port=1080)
        # clash_api присутствует
        self.assertEqual(
            cfg["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9090")
        self.assertEqual(cfg["experimental"]["clash_api"]["secret"], "s3cr3t")
        # selector над обоими серверами
        sel = [o for o in cfg["outbounds"] if o.get("type") == "selector"][0]
        self.assertEqual(sel["tag"], "test-select")
        self.assertEqual(sel["outbounds"], ["a", "b"])
        # route на селектор
        self.assertEqual(cfg["route"]["rules"][0]["outbound"], "test-select")
        # реальные серверы сохранены
        tags = {o.get("tag") for o in cfg["outbounds"]}
        self.assertTrue({"a", "b", "test-select", "direct"} <= tags)
        # block-outbound удалён в sing-box 1.13 — на новых бинарях он
        # валил бы каждый батч; в тестовом конфиге его быть не должно.
        self.assertNotIn("block", tags)

    def test_empty_outbounds_falls_back_direct(self):
        cfg = build_test_config([], clash_port=1, clash_secret="",
                                mixed_port=2)
        sel = [o for o in cfg["outbounds"] if o.get("type") == "selector"][0]
        self.assertEqual(sel["outbounds"], ["direct"])

    def test_vless_flow_udp443_normalized(self):
        # Xray-flow '…-vision-udp443' встречается в сохранённых конфигах;
        # sing-box на нём падает целиком («unsupported flow») — тестовый
        # конфиг обязан нормализовать его до vision, не мутируя исходник.
        obs = [{"type": "vless", "tag": "v", "server": "1.1.1.1",
                "server_port": 443, "uuid": "u",
                "flow": "xtls-rprx-vision-udp443"}]
        cfg = build_test_config(obs, clash_port=1, clash_secret="",
                                mixed_port=2)
        v = [o for o in cfg["outbounds"] if o.get("tag") == "v"][0]
        self.assertEqual(v["flow"], "xtls-rprx-vision")
        self.assertEqual(obs[0]["flow"], "xtls-rprx-vision-udp443")


class TestParseDelay(unittest.TestCase):

    def test_ok(self):
        r = parse_delay(200, '{"delay": 137}')
        self.assertTrue(r["ok"])
        self.assertEqual(r["latency_ms"], 137)

    def test_timeout_error(self):
        r = parse_delay(408, '{"message": "An error occurred in the delay test"}')
        self.assertFalse(r["ok"])
        self.assertIn("delay", r["error"].lower())

    def test_non_json(self):
        r = parse_delay(0, "connection refused")
        self.assertFalse(r["ok"])

    def test_200_without_delay_field(self):
        r = parse_delay(200, "{}")
        self.assertFalse(r["ok"])


class TestTestOutboundsNoBinary(unittest.TestCase):
    """Без бинаря фаза 2 пропускается; результат строится из TCP-фазы."""

    def test_no_binary_no_prefilter(self):
        obs = [{"type": "vless", "tag": "a", "server": "1.1.1.1",
                "server_port": 443, "uuid": "u"}]
        res = pt.run_outbound_tests(obs, tcp_prefilter_enabled=False, binary="")
        self.assertTrue(res["ok"])
        self.assertFalse(res["engine_used"])
        self.assertEqual(res["summary"]["total"], 1)
        # без prefilter и без движка считаем «живым» по TCP-предположению
        self.assertEqual(res["results"][0]["stage"], "tcp")

    def test_empty(self):
        res = pt.run_outbound_tests([], binary="")
        self.assertTrue(res["ok"])
        self.assertEqual(res["summary"]["total"], 0)

    def test_progress_cb_invoked(self):
        # Недостижимые адреса → TCP-проба быстро падает; нас интересует,
        # что progress_cb вызывается с (phase, done, total).
        obs = [{"type": "vless", "tag": "a", "server": "192.0.2.1",
                "server_port": 1, "uuid": "u"},
               {"type": "vless", "tag": "b", "server": "192.0.2.2",
                "server_port": 1, "uuid": "u"}]
        calls = []
        pt.run_outbound_tests(obs, binary="",
                          progress_cb=lambda ph, d, t: calls.append((ph, d, t)))
        self.assertTrue(calls)
        # последний tcp-колбэк — done == total == 2
        tcp = [c for c in calls if c[0] == "tcp"]
        self.assertEqual(tcp[-1][1], 2)
        self.assertEqual(tcp[-1][2], 2)


class TestUdpProtoPrefilter(unittest.TestCase):
    """UDP/QUIC-протоколы (hysteria2/tuic/wireguard) не должны убиваться
    TCP-отсевом — их сервер не слушает TCP."""

    def test_hysteria2_bypasses_tcp_prefilter(self):
        # Сразу (True, None), без TCP-пробы к недостижимому адресу.
        obs = [{"type": "hysteria2", "tag": "h", "server": "192.0.2.1",
                "server_port": 8449}]
        res = pt.tcp_prefilter(obs)
        self.assertEqual(res.get("h"), (True, None))

    def test_tuic_and_wireguard_bypass(self):
        obs = [{"type": "tuic", "tag": "t", "server": "192.0.2.1",
                "server_port": 443},
               {"type": "wireguard", "tag": "w", "server": "192.0.2.2",
                "server_port": 51820}]
        res = pt.tcp_prefilter(obs)
        self.assertEqual(res.get("t"), (True, None))
        self.assertEqual(res.get("w"), (True, None))

    def test_tcp_proto_still_probed(self):
        # Не-UDP тип по-прежнему проходит TCP-пробу.
        obs = [{"type": "vless", "tag": "v", "server": "192.0.2.1",
                "server_port": 443}]
        with mock.patch.object(pt, "_tcp_connect_ok",
                               return_value=(False, None)) as m:
            res = pt.tcp_prefilter(obs)
        m.assert_called_once()
        self.assertEqual(res.get("v"), (False, None))

    def test_hysteria2_not_dead_in_run_outbound_tests(self):
        # Регресс: hysteria2 не помечается «мёртвым» TCP-фазой (была причина
        # ложного «дохлая» у hysteria2/tuic).
        obs = [{"type": "hysteria2", "tag": "h", "server": "192.0.2.1",
                "server_port": 8449, "password": "p",
                "tls": {"enabled": True, "server_name": "sni.example"}}]
        res = pt.run_outbound_tests(obs, binary="")   # без движка → только фаза 1
        self.assertTrue(res["ok"])
        row = res["results"][0]
        self.assertTrue(row["alive"])
        self.assertNotIn("TCP", row.get("error") or "")


class TestStripAnsi(unittest.TestCase):

    def test_removes_color_codes(self):
        raw = "\x1b[31mFATAL\x1b[0m[0000] create clash-server: clash api is not included"
        self.assertEqual(
            pt._strip_ansi(raw),
            "FATAL[0000] create clash-server: clash api is not included")

    def test_plain_unchanged(self):
        self.assertEqual(pt._strip_ansi("plain text"), "plain text")


class TestBinaryHasClashApi(unittest.TestCase):

    def _run(self, stdout):
        return mock.patch.object(
            pt.subprocess, "run",
            return_value=types.SimpleNamespace(stdout=stdout, returncode=0))

    def test_present(self):
        with self._run("sing-box version 1.12.0\n"
                       "Tags: with_quic,with_clash_api\nCGO: disabled"):
            self.assertIs(pt.binary_has_clash_api("/opt/sing-box"), True)

    def test_absent(self):
        with self._run("sing-box version 1.12.0\n"
                       "Tags: with_quic,with_utls\nCGO: disabled"):
            self.assertIs(pt.binary_has_clash_api("/opt/sing-box"), False)

    def test_unknown_when_no_tags_line(self):
        with self._run("sing-box version 1.12.0\nCGO: disabled"):
            self.assertIsNone(pt.binary_has_clash_api("/opt/sing-box"))

    def test_empty_binary_is_unknown(self):
        self.assertIsNone(pt.binary_has_clash_api(""))


class TestSkipE2EWithoutClashApi(unittest.TestCase):
    """Фаза 2 не запускается, если бинарь заведомо без clash_api."""

    def test_no_clash_api_skips_engine(self):
        obs = [{"type": "vless", "tag": "a", "server": "1.1.1.1",
                "server_port": 443, "uuid": "u"}]
        with mock.patch.object(pt, "tcp_prefilter",
                               return_value={"a": (True, 12)}), \
             mock.patch.object(pt, "binary_has_clash_api",
                               return_value=False), \
             mock.patch.object(pt, "_e2e_delays") as e2e:
            res = pt.run_outbound_tests(obs, binary="/opt/sing-box")
        e2e.assert_not_called()              # движок не поднимали
        self.assertFalse(res["engine_used"])
        self.assertTrue(res["ok"])
        self.assertEqual(res["results"][0]["stage"], "tcp")
        self.assertTrue(res["results"][0]["alive"])

    def test_clash_api_present_runs_engine(self):
        obs = [{"type": "vless", "tag": "a", "server": "1.1.1.1",
                "server_port": 443, "uuid": "u"}]
        with mock.patch.object(pt, "tcp_prefilter",
                               return_value={"a": (True, 12)}), \
             mock.patch.object(pt, "binary_has_clash_api",
                               return_value=True), \
             mock.patch.object(pt, "_e2e_delays",
                               return_value={"a": {"ok": True,
                                                   "latency_ms": 99}}) as e2e:
            res = pt.run_outbound_tests(obs, binary="/opt/sing-box")
        e2e.assert_called_once()
        self.assertTrue(res["engine_used"])
        self.assertEqual(res["results"][0]["stage"], "e2e")


if __name__ == "__main__":
    unittest.main()
