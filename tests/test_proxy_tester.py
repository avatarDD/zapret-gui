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
        # Английский текст движка непрозрачен («что-то пошло не так») —
        # отдаём формулировку, из которой понятно, что проверять.
        r = parse_delay(408, '{"message": "An error occurred in the delay test"}')
        self.assertFalse(r["ok"])
        self.assertIn("проверочный URL", r["error"])

    def test_known_delay_errors_are_translated(self):
        cases = {
            '{"message": "Request timeout"}': "таймаут",
            '{"message": "context deadline exceeded"}': "таймаут",
            '{"message": "response status is inconsistent with the expected"}':
                "не тем кодом",
        }
        for body, needle in cases.items():
            self.assertIn(needle, parse_delay(504, body)["error"], msg=body)

    def test_unknown_error_is_passed_through(self):
        r = parse_delay(404, '{"message": "Proxy does not exist"}')
        self.assertEqual(r["error"], "Proxy does not exist")

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
        self.assertEqual(res.get("h"), (True, None, ""))

    def test_tuic_and_wireguard_bypass(self):
        obs = [{"type": "tuic", "tag": "t", "server": "192.0.2.1",
                "server_port": 443},
               {"type": "wireguard", "tag": "w", "server": "192.0.2.2",
                "server_port": 51820}]
        res = pt.tcp_prefilter(obs)
        self.assertEqual(res.get("t"), (True, None, ""))
        self.assertEqual(res.get("w"), (True, None, ""))

    def test_tcp_proto_still_probed(self):
        # Не-UDP тип по-прежнему проходит TCP-пробу.
        obs = [{"type": "vless", "tag": "v", "server": "192.0.2.1",
                "server_port": 443}]
        with mock.patch.object(pt, "_tcp_connect_ok",
                               return_value=(False, None, "таймаут TCP")) as m:
            res = pt.tcp_prefilter(obs)
        m.assert_called_once()
        self.assertEqual(res.get("v"), (False, None, "таймаут TCP"))

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


class TestTargetsAreHttps(unittest.TestCase):
    """Цели замера — только https.

    По http движок шлёт HEAD, а провайдеры/узлы перехватывают известные
    captive-portal адреса и на повторный HEAD (его делает `unified-delay`,
    который включён в наших конфигах) отвечают мусором. Апстрим mihomo
    предупреждает об этом прямо в URLTest. Симптом был ровно такой: живой
    узел с реальным трафиком → «An error occurred in the delay test».
    """

    def test_no_plain_http_presets(self):
        for name, url in pt.TARGET_PRESETS.items():
            self.assertTrue(url.startswith("https://"),
                            "%s = %s" % (name, url))

    def test_default_target_is_https(self):
        self.assertTrue(pt.resolve_target("").startswith("https://"))
        self.assertTrue(pt.resolve_target("cloudflare").startswith("https://"))

    def test_explicit_user_url_is_respected(self):
        # Свой URL пользователь вправе задать любой — не подменяем.
        self.assertEqual(pt.resolve_target("http://example.com/x"),
                         "http://example.com/x")


class TestTcpFailureReasons(unittest.TestCase):
    """Причина отказа TCP-пробы: раньше всё сводилось к одной строке.

    По вердикту «сервер не отвечает (TCP)» нельзя отличить дохлый сервер
    от сломанного резолвера роутера или от трафика, завёрнутого в
    неработающий туннель, — а лечатся они по-разному.
    """

    def test_dns_failure_is_named(self):
        with mock.patch.object(pt.socket, "create_connection",
                               side_effect=pt.socket.gaierror(-2, "no name")):
            ok, ms, reason = pt._tcp_connect_ok("nope.invalid", 443, 1.0)
        self.assertFalse(ok)
        self.assertEqual(reason, pt.TCP_FAIL_DNS)

    def test_refused_timeout_and_unreachable(self):
        import errno as _errno
        cases = [
            (ConnectionRefusedError(), pt.TCP_FAIL_REFUSED),
            (pt.socket.timeout(), pt.TCP_FAIL_TIMEOUT),
            (OSError(_errno.ENETUNREACH, "unreach"), pt.TCP_FAIL_UNREACH),
            (OSError(_errno.EHOSTUNREACH, "unreach"), pt.TCP_FAIL_UNREACH),
        ]
        for exc, expected in cases:
            with mock.patch.object(pt.socket, "create_connection",
                                   side_effect=exc):
                _ok, _ms, reason = pt._tcp_connect_ok("1.2.3.4", 443, 1.0)
            self.assertEqual(reason, expected, repr(exc))

    def test_bad_port_is_named(self):
        _ok, _ms, reason = pt._tcp_connect_ok("1.2.3.4", "abc", 1.0)
        self.assertEqual(reason, pt.TCP_FAIL_BAD_ADDR)

    def test_reason_reaches_the_result_row(self):
        obs = [{"type": "vless", "tag": "a", "server": "h.invalid",
                "server_port": 443, "uuid": "u"}]
        with mock.patch.object(pt, "_tcp_connect_ok",
                               return_value=(False, None, pt.TCP_FAIL_DNS)):
            res = pt.run_outbound_tests(obs, binary="")
        self.assertEqual(res["results"][0]["error"], pt.TCP_FAIL_DNS)

    def test_unpack_tolerates_legacy_two_tuple(self):
        self.assertEqual(pt.unpack_tcp_entry((True, 12)), (True, 12, ""))
        ok, ms, reason = pt.unpack_tcp_entry((False, None))
        self.assertFalse(ok)
        self.assertTrue(reason)


class TestCommonFailureHint(unittest.TestCase):
    """«Умерли все и по одной причине» — это про роутер, а не про ключи."""

    def _rows(self, error, n=3, alive=False):
        return [{"tag": "t%d" % i, "alive": alive, "error": error}
                for i in range(n)]

    def test_dns_hint(self):
        hint = pt.common_failure_hint(self._rows(pt.TCP_FAIL_DNS))
        self.assertIn("DNS", hint)
        self.assertIn("не про серверы", hint)

    def test_unreachable_hint_mentions_tunnel(self):
        hint = pt.common_failure_hint(self._rows(pt.TCP_FAIL_UNREACH))
        self.assertIn("туннель", hint)

    def test_no_hint_when_something_is_alive(self):
        rows = self._rows(pt.TCP_FAIL_DNS)
        rows.append({"tag": "ok", "alive": True, "error": ""})
        self.assertEqual(pt.common_failure_hint(rows), "")

    def test_no_hint_when_reasons_differ(self):
        rows = self._rows(pt.TCP_FAIL_DNS, n=1)
        rows += self._rows(pt.TCP_FAIL_TIMEOUT, n=1)
        self.assertEqual(pt.common_failure_hint(rows), "")

    def test_no_hint_for_single_server(self):
        self.assertEqual(pt.common_failure_hint(self._rows(pt.TCP_FAIL_DNS, 1)),
                         "")
