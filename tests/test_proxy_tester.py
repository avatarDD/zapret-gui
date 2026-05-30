# tests/test_proxy_tester.py
"""Unit-тесты для core/proxy_tester.py (чистые помощники, без бинаря)."""

import unittest

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
        self.assertTrue({"a", "b", "test-select", "direct", "block"} <= tags)

    def test_empty_outbounds_falls_back_direct(self):
        cfg = build_test_config([], clash_port=1, clash_secret="",
                                mixed_port=2)
        sel = [o for o in cfg["outbounds"] if o.get("type") == "selector"][0]
        self.assertEqual(sel["outbounds"], ["direct"])


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
        res = pt.test_outbounds(obs, tcp_prefilter_enabled=False, binary="")
        self.assertTrue(res["ok"])
        self.assertFalse(res["engine_used"])
        self.assertEqual(res["summary"]["total"], 1)
        # без prefilter и без движка считаем «живым» по TCP-предположению
        self.assertEqual(res["results"][0]["stage"], "tcp")

    def test_empty(self):
        res = pt.test_outbounds([], binary="")
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
        pt.test_outbounds(obs, binary="",
                          progress_cb=lambda ph, d, t: calls.append((ph, d, t)))
        self.assertTrue(calls)
        # последний tcp-колбэк — done == total == 2
        tcp = [c for c in calls if c[0] == "tcp"]
        self.assertEqual(tcp[-1][1], 2)
        self.assertEqual(tcp[-1][2], 2)


if __name__ == "__main__":
    unittest.main()
