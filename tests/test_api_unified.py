# tests/test_api_unified.py
"""
Интеграционные тесты единого слоя через реальный WSGI-app:
/api/lists + /api/unified/* сквозным сценарием.

ConfigManager работает с временным config_dir; движки (routing/
hostlist) применять не пытаемся (метод direct), чтобы не трогать сеть.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestUnifiedApiFlow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="uni-api-")
        from core.config_manager import init_config
        init_config(cls.tmp)
        cls.client = WSGIClient(build_test_app())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_lists_crud(self):
        r = self.client.post_json('/api/lists',
                                  {"name": "L1", "entries": "youtube.com 1.2.3.0/24"})
        self.assertTrue(r["ok"], r)
        lid = r["list"]["id"]
        got = self.client.get_json('/api/lists')
        self.assertTrue(any(x["id"] == lid for x in got["lists"]))
        one = self.client.get_json('/api/lists/' + lid)
        self.assertEqual(one["list"]["domains"], ["youtube.com"])
        self.assertEqual(one["list"]["cidrs"], ["1.2.3.0/24"])
        self.__class__.list_id = lid

    def test_02_create_route_direct(self):
        r = self.client.post_json('/api/unified/routes', {
            "name": "R-direct", "method": "direct",
            "destination": {"domains": ["example.com"]},
        })
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["applied"]["method"], "direct")
        self.__class__.route_id = r["route"]["id"]

    def test_03_route_uses_list(self):
        r = self.client.post_json('/api/unified/routes', {
            "name": "R-list", "method": "direct",
            "destination": {"list_ids": [self.list_id]},
        })
        self.assertTrue(r["ok"], r)

    def test_04_empty_destination_rejected(self):
        status, _b = self.client.post('/api/unified/routes',
                                      {"name": "bad", "method": "direct",
                                       "destination": {}})
        self.assertTrue(status.startswith("400"))

    def test_05_bad_method_rejected(self):
        status, _b = self.client.post('/api/unified/routes',
                                      {"name": "bad2", "method": "wat",
                                       "destination": {"domains": ["a.com"]}})
        self.assertTrue(status.startswith("400"))

    def test_06_status_lists_routes(self):
        s = self.client.get_json('/api/unified/status')
        self.assertTrue(s["ok"])
        self.assertGreaterEqual(len(s["routes"]), 2)

    def test_07_apply_and_delete(self):
        rid = self.route_id
        ap = self.client.post_json('/api/unified/routes/%s/apply' % rid)
        self.assertTrue(ap["ok"])
        d = self.client.delete_json('/api/unified/routes/' + rid)
        self.assertTrue(d["ok"])
        status, _b = self.client.delete('/api/unified/routes/' + rid)
        self.assertTrue(status.startswith("404"))

    def test_08_monitor_toggle(self):
        r = self.client.post_json('/api/unified/monitor',
                                  {"enabled": True, "interval": 30})
        self.assertTrue(r["ok"])
        self.assertTrue(r["running"])
        r2 = self.client.post_json('/api/unified/monitor', {"enabled": False})
        self.assertFalse(r2["running"])


if __name__ == "__main__":
    unittest.main()
