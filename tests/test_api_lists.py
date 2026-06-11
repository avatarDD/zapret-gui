# tests/test_api_lists.py
"""Integration-тесты для api/lists.py — курируемые списки."""

import unittest

from tests._wsgi_client import WSGIClient, build_test_app


class TestListsCuratedAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_lists_all(self):
        r = self.client.get_json("/api/lists")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["lists"], list)

    def test_curated_presets(self):
        r = self.client.get_json("/api/lists/curated")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["presets"], list)
        self.assertTrue(len(r["presets"]) >= 1)
        self.assertIn("url", r["presets"][0])
        self.assertIn("added", r["presets"][0])

    def test_curated_add_missing_url(self):
        r = self.client.post_json("/api/lists/curated", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_curated_add_bad_url(self):
        r = self.client.post_json("/api/lists/curated", {"url": "ftp://nope"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_curated_route_not_shadowed(self):
        # /api/lists/curated не должен трактоваться как /api/lists/<id>.
        r = self.client.get_json("/api/lists/curated")
        self.assertIn("presets", r)

    # ─── транспорт скачивания (задача №7) ───

    def test_curated_returns_transport(self):
        from unittest import mock
        with mock.patch("core.list_updater.get_transport",
                        return_value="awg:wg0"):
            r = self.client.get_json("/api/lists/curated")
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["transport"], "awg:wg0")

    def test_curated_settings_saves_transport(self):
        from unittest import mock
        with mock.patch("core.list_updater.set_transport",
                        return_value={"ok": True,
                                      "transport": "singbox:p"}) as st:
            r = self.client.post_json("/api/lists/curated/settings",
                                      {"transport": "singbox:p"})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        st.assert_called_once_with("singbox:p")

    def test_curated_settings_rejects_unknown(self):
        # Невалидная спека отклоняется ДО записи в settings (реальный
        # set_transport: валидация раньше сохранения).
        r = self.client.post_json("/api/lists/curated/settings",
                                  {"transport": "tor:9050"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
