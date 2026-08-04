# tests/test_api_mihomo_routing.py
"""
Integration-тесты api/mihomo.py для эндпоинтов маршрутизации и watchdog'а
(через WSGI, с моками core-функций — без бинаря mihomo).
"""

import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestMihomoRoutingAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_routing_options(self):
        fake = {"ok": True, "installed": True, "has_gvisor": True,
                "hostlists": [], "lists": [], "configs": []}
        with mock.patch("core.mihomo_routing.build_options",
                        return_value=fake):
            r = self.client.get_json("/api/mihomo/routing/options")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("has_gvisor", r)

    def test_domain_build_passes_params(self):
        captured = {}

        def _fake(**kw):
            captured.update(kw)
            return {"ok": True, "name": kw["name"], "mode": "domain"}

        with mock.patch("core.mihomo_routing.build_domain_route_and_save",
                        side_effect=_fake):
            r = self.client.post_json("/api/mihomo/routing/domain/build", {
                "name": "d1", "proxy_link": "vless://x",
                "hostlists": ["other"], "ipsets": ["ipset-base"],
                "geosite": "youtube, telegram", "geoip": "ru",
                "domains": "a.com, b.com",
                "route_all": False, "reject_quic": True})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(captured["name"], "d1")
        self.assertEqual(captured["hostlists"], ["other"])
        self.assertEqual(captured["ipsets"], ["ipset-base"])
        self.assertEqual(captured["geosite"], ["youtube", "telegram"])  # str→list
        self.assertEqual(captured["geoip"], ["ru"])
        self.assertEqual(captured["domains"], ["a.com", "b.com"])  # строка → list
        self.assertTrue(captured["reject_quic"])

    def test_domain_build_error_is_400(self):
        with mock.patch("core.mihomo_routing.build_domain_route_and_save",
                        return_value={"ok": False, "error": "no proxy"}):
            r = self.client.post_json("/api/mihomo/routing/domain/build",
                                      {"name": "d"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_source_build_passes_params(self):
        captured = {}

        def _fake(**kw):
            captured.update(kw)
            return {"ok": True, "name": kw["name"], "mode": "source"}

        with mock.patch("core.mihomo_routing.build_source_route_and_save",
                        side_effect=_fake):
            r = self.client.post_json("/api/mihomo/routing/source/build", {
                "name": "s1", "proxy_config": "cfg",
                "source_ips": ["192.168.1.5"], "route_all": True})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(captured["source_ips"], ["192.168.1.5"])
        self.assertTrue(captured["route_all"])

    def test_watchdog_get(self):
        wd = mock.MagicMock()
        wd.get_status.return_value = {"enabled": False, "running": False,
                                      "settings": {}, "restarts_last_hour": {}}
        with mock.patch("core.mihomo_watchdog.get_watchdog", return_value=wd):
            r = self.client.get_json("/api/mihomo/watchdog")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("status", r)

    def test_watchdog_set(self):
        wd = mock.MagicMock()
        wd.get_status.return_value = {"enabled": True}
        with mock.patch("core.mihomo_watchdog.set_settings",
                        return_value={"enabled": True}) as ss, \
             mock.patch("core.mihomo_watchdog.get_watchdog", return_value=wd):
            r = self.client.post_json("/api/mihomo/watchdog",
                                      {"enabled": True, "check_interval_sec": 30})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        ss.assert_called_once()
        self.assertEqual(ss.call_args.kwargs.get("enabled"), True)
        self.assertEqual(ss.call_args.kwargs.get("check_interval_sec"), 30)


if __name__ == "__main__":
    unittest.main()


class TestMihomoProxiesAPI(unittest.TestCase):
    """/api/mihomo/configs/<name>/proxies — «в редакторе есть, в таблице нет».

    Конфиг с якорями (`<<:`-merge) наш YAML-парсер разбирает не целиком.
    Раньше это молча давало пустой список и надпись «в конфиге нет прокси»
    при полном конфиге на диске.
    """

    ANCHOR_CFG = (
        "defaults: &d\n"
        "  udp: true\n"
        "proxies:\n"
        "  - <<: *d\n"
        "    name: A\n"
        "    type: hysteria2\n"
        "    server: h.example.com\n"
        "    port: 443\n"
        "rules:\n"
        "  - MATCH,DIRECT\n"
    )

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def _get(self, text, running=False):
        with mock.patch("core.mihomo_manager.MihomoManager.get_config",
                        return_value={"ok": True, "name": "meta",
                                      "text": text}), \
             mock.patch("core.mihomo_manager.MihomoManager.is_running",
                        return_value=running):
            return self.client.get_json("/api/mihomo/configs/meta/proxies")

    def test_text_fallback_when_structured_parse_is_empty(self):
        import builtins
        real = builtins.__import__

        def _no_yaml(name, *a, **k):
            if name == "yaml":
                raise ImportError("no yaml")
            return real(name, *a, **k)

        builtins.__import__ = _no_yaml
        try:
            r = self._get(self.ANCHOR_CFG)
        finally:
            builtins.__import__ = real
        self.assertTrue(r["ok"])
        self.assertEqual([p["name"] for p in r["proxies"]], ["A"])
        self.assertTrue(r["text_fallback"])

    def test_normal_config_uses_structured_path(self):
        text = ("proxies:\n"
                "  - name: A\n    type: ss\n    server: 1.2.3.4\n"
                "    port: 8388\n")
        r = self._get(text)
        self.assertEqual([p["name"] for p in r["proxies"]], ["A"])
        self.assertFalse(r["text_fallback"])
        self.assertEqual(r["parse_error"], "")
