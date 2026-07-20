# tests/test_api_tgproxy.py
"""
Integration-тесты для Telegram Proxy API (/api/tgproxy/*).

Проверяем:
  1. GET  /status                 — статус обоих движков
  2. GET  /detect                 — обнаружение установленных пакетов
  3. GET  /tgwsproxy/config       — чтение конфига
  4. PUT  /tgwsproxy/config       — запись конфига (с валидацией)
  5. GET  /tgwsproxy/connect-info — connect-info без запуска
  6. POST /tgwsproxy/down         — остановка (идемпотентность)
  7. POST /mtproto/down           — остановка mtproto (идемпотентность)
  8. GET  /tgwsproxy/tunnels      — список WARP-туннелей
  9. POST /tgwsproxy/route-via-tunnel — валидация kind/iface
"""

import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestTgproxyStatusDetect(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_status(self):
        """GET /api/tgproxy/status — структура."""
        r = self.client.get_json("/api/tgproxy/status")
        self.assertEqual(r["_status"], 200)
        self.assertIn("tgwsproxy", r)
        self.assertIn("mtproto", r)
        self.assertIn("any_running", r)
        # без запуска — false
        self.assertIs(r["any_running"], False)

    def test_detect(self):
        """GET /api/tgproxy/detect — структура."""
        r = self.client.get_json("/api/tgproxy/detect")
        self.assertEqual(r["_status"], 200)
        self.assertIn("tgwsproxy", r)
        self.assertIn("mtproto", r)
        self.assertIn("installed", r["tgwsproxy"])
        self.assertIn("installed", r["mtproto"])

    def test_tgwsproxy_config_get(self):
        """GET /api/tgproxy/tgwsproxy/config — структура."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/config")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))
        self.assertIn("config", r)
        cfg = r["config"]
        self.assertIn("host", cfg)
        self.assertIn("port", cfg)
        self.assertIn("fake_tls_domain", cfg)
        self.assertIn("cf_domain", cfg)

    def test_tgwsproxy_connect_info(self):
        """GET /api/tgproxy/tgwsproxy/connect-info — 200."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/connect-info")
        self.assertEqual(r["_status"], 200)

    def test_tgwsproxy_down(self):
        """POST /api/tgproxy/tgwsproxy/down — идемпотентность."""
        r = self.client.post_json("/api/tgproxy/tgwsproxy/down")
        self.assertEqual(r["_status"], 200)

    def test_mtproto_down(self):
        """POST /api/tgproxy/mtproto/down — идемпотентность."""
        r = self.client.post_json("/api/tgproxy/mtproto/down")
        self.assertEqual(r["_status"], 200)

    def test_mtproto_connect_info_not_running(self):
        """GET /api/tgproxy/mtproto/connect-info — без запуска."""
        r = self.client.get_json("/api/tgproxy/mtproto/connect-info")
        self.assertEqual(r["_status"], 200)
        self.assertIn("link", r)

    def test_tunnels_list(self):
        """GET /api/tgproxy/tgwsproxy/tunnels — 200."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/tunnels")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))
        self.assertIsInstance(r.get("tunnels"), list)


class TestTgproxyConfigPut(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_put_config_valid(self):
        """PUT /api/tgproxy/tgwsproxy/config — корректные параметры."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "host": "0.0.0.0",
            "port": 1443,
            "log_level": "0",
        })
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    def test_put_config_with_domain(self):
        """PUT с валидным cf_domain."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "cf_domain": "example.com",
        })
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    def test_put_config_invalid_port_low(self):
        """PUT с портом 0 — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": 0,
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_port_high(self):
        """PUT с портом 99999 — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": 99999,
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_port_string(self):
        """PUT с портом-строкой — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": "not-a-number",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_cf_domain(self):
        """PUT с невалидным cf_domain — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "cf_domain": "not a domain!@#",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_fake_tls_domain(self):
        """PUT с невалидным fake_tls_domain — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "fake_tls_domain": "spaces in domain",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)


class TestTgproxyRouteViaTunnel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_route_via_tunnel_missing_kind(self):
        """POST /route-via-tunnel без kind — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"iface": "awg0"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)
        self.assertIn("error", r)

    def test_route_via_tunnel_invalid_kind(self):
        """POST /route-via-tunnel с kind=invalid — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"kind": "invalid", "iface": "tun0"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_route_via_tunnel_missing_iface(self):
        """POST /route-via-tunnel без iface — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"kind": "warp"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_unroute_via_tunnel(self):
        """DELETE /route-via-tunnel — идемпотентность."""
        r = self.client.delete_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel")
        self.assertEqual(r["_status"], 200)


class TestMtprotoUpAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    @mock.patch("core.tgproxy_manager.get_mtproxy_client_manager")
    def test_mtproto_up_without_relay(self, mock_get_mgr):
        mgr = mock.Mock()
        mgr.start.return_value = {"ok": False, "error": "relay обязателен для mtproto-режима"}
        mock_get_mgr.return_value = mgr
        r = self.client.post_json("/api/tgproxy/mtproto/up", {"port": 1443})
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r["ok"])
        mgr.start.assert_called_once()
        self.assertEqual(mgr.start.call_args.kwargs["relay"], "")
