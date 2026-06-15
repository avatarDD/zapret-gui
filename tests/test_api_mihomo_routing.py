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
                "hostlists": ["other"], "domains": "a.com, b.com",
                "route_all": False, "reject_quic": True})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(captured["name"], "d1")
        self.assertEqual(captured["hostlists"], ["other"])
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
