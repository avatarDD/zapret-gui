# tests/test_api_warp_in_warp.py
"""
Integration-тесты для WARP-in-WARP API (/api/warp-in-warp/*).

Проверяем:
  1. GET  /detect  — определение доступных компонентов
  2. GET  /status  — статус (без запущенного туннеля)
  3. POST /down    — остановка без запущенного туннеля
  4. POST /up      — запуск с некорректными параметрами
"""

import unittest

from tests._wsgi_client import WSGIClient, build_test_app


class TestWarpInWarpApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    # ── detect ─────────────────────────────────────────────────

    def test_detect_endpoint(self):
        """GET /api/warp-in-warp/detect — 200 + ключи."""
        r = self.client.get_json("/api/warp-in-warp/detect")
        self.assertEqual(r["_status"], 200)
        self.assertIn("usque_installed", r)
        self.assertIn("awg_available", r)
        self.assertIn("arch", r)

    # ── status ─────────────────────────────────────────────────

    def test_status_endpoint(self):
        """GET /api/warp-in-warp/status — 200 + структура."""
        r = self.client.get_json("/api/warp-in-warp/status")
        self.assertEqual(r["_status"], 200)
        self.assertIn("active", r)
        self.assertIn("mode", r)
        self.assertIn("outer_running", r)
        self.assertIn("inner_running", r)

    def test_status_default_inactive(self):
        """Без запуска статус должен быть inactive."""
        r = self.client.get_json("/api/warp-in-warp/status")
        self.assertIs(r["active"], False)

    # ── down ───────────────────────────────────────────────────

    def test_down_returns_ok_when_stopped(self):
        """POST /api/warp-in-warp/down — должен вернуть ok даже без
        запущенного туннеля (идемпотентность)."""
        r = self.client.post_json("/api/warp-in-warp/down")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    # ── up ─────────────────────────────────────────────────────

    def test_up_rejects_empty_body(self):
        """POST /api/warp-in-warp/up без параметров — должен вернуть
        ошибку, не 500."""
        r = self.client.post_json("/api/warp-in-warp/up", {})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)
        self.assertIn("error", r)

    def test_up_rejects_unknown_mode(self):
        """POST /api/warp-in-warp/up с неизвестным mode — ошибка."""
        r = self.client.post_json("/api/warp-in-warp/up",
                                   {"mode": "nonexistent"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_up_masque_masque_missing_configs(self):
        """POST /api/warp-in-warp/up с mode=masque_masque без configs
        — ожидаемая ошибка (не 500)."""
        r = self.client.post_json("/api/warp-in-warp/up",
                                   {"mode": "masque_masque"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)
        self.assertIn("error", r)

    def test_up_masque_awg_missing_configs(self):
        """POST /api/warp-in-warp/up с mode=masque_awg без конфигов — ошибка."""
        r = self.client.post_json("/api/warp-in-warp/up",
                                   {"mode": "masque_awg"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_up_awg_masque_missing_configs(self):
        """POST /api/warp-in-warp/up с mode=awg_masque без конфигов — ошибка."""
        r = self.client.post_json("/api/warp-in-warp/up",
                                   {"mode": "awg_masque"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)
