# tests/test_unified_manager.py
"""Unit-тесты для core/unified/manager.py (CRUD + apply оркестрация)."""

import unittest
from unittest import mock

from core.unified import manager


class FakeConfigManager:
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def save(self):
        return True


class TestManager(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.unified.storage.get_config_manager",
                             return_value=self.fake)
        self._p.start()
        # applier — no-op, чтобы не трогать движки
        self._pa = mock.patch("core.unified.applier.apply_route",
                              return_value={"ok": True})
        self._pa.start()
        self._pr = mock.patch("core.unified.applier.remove_route",
                              return_value={"ok": True})
        self._pr.start()

    def tearDown(self):
        for p in (self._p, self._pa, self._pr):
            p.stop()

    def test_save_valid(self):
        r = manager.save_route({
            "name": "YT", "method": "awg:awg0",
            "destination": {"domains": ["youtube.com"]},
        })
        self.assertTrue(r["ok"])
        self.assertEqual(len(manager.list_routes()), 1)

    def test_save_empty_destination_rejected(self):
        r = manager.save_route({"name": "x", "method": "direct",
                                "destination": {}})
        self.assertFalse(r["ok"])
        self.assertIn("Назначение пустое", r["error"])

    def test_save_bad_method(self):
        r = manager.save_route({"name": "x", "method": "bogus",
                                "destination": {"domains": ["a.com"]}})
        self.assertFalse(r["ok"])

    def test_update_keeps_single(self):
        r = manager.save_route({"name": "a", "method": "direct",
                                "destination": {"domains": ["a.com"]}})
        rid = r["route"]["id"]
        manager.save_route({"id": rid, "name": "a2", "method": "nfqws2",
                            "destination": {"domains": ["a.com"]}})
        routes = manager.list_routes()
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["name"], "a2")

    def test_delete(self):
        rid = manager.save_route({"name": "a", "method": "direct",
                                  "destination": {"domains": ["a.com"]}})["route"]["id"]
        self.assertTrue(manager.delete_route(rid)["ok"])
        self.assertEqual(manager.list_routes(), [])
        self.assertFalse(manager.delete_route(rid)["ok"])

    def test_disabled_route_removed_not_applied(self):
        manager.save_route({"name": "a", "method": "awg:awg0", "enabled": False,
                            "destination": {"domains": ["a.com"]}})
        # apply_route не должен вызываться для disabled
        from core.unified import applier
        applier.apply_route.assert_not_called()
        applier.remove_route.assert_called()


if __name__ == "__main__":
    unittest.main()
