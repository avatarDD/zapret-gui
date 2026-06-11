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

    def test_09_route_with_devices_and_dscp(self):
        r = self.client.post_json('/api/unified/routes', {
            "name": "R-dev", "method": "direct",
            "destination": {},
            "devices": [{"ip": "192.168.1.50", "hostname": "tv"}],
            "dscp": 46, "dscp_self": True,
        })
        self.assertTrue(r["ok"], r)
        rid = r["route"]["id"]
        # для direct устройства/DSCP честно помечаются пропущенными
        self.assertTrue(any("устройства/DSCP" in s for s in
                            (r["applied"].get("skipped_selectors") or [])))
        got = self.client.get_json('/api/unified/routes/' + rid)
        self.assertEqual(got["route"]["devices"][0]["ip"], "192.168.1.50")
        self.assertEqual(got["route"]["dscp"], 46)
        self.assertTrue(got["route"]["dscp_self"])
        d = self.client.delete_json('/api/unified/routes/' + rid)
        self.assertTrue(d["ok"])

    def test_10_legacy_and_migrate(self):
        # Кладём legacy-правило прямо в routing.rules (старый формат).
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("routing", {"rules": [{
            "id": "cidr-test1234", "type": "cidr", "target_iface": "awg0",
            "cidrs": ["10.10.0.0/16"], "ip_version": "auto",
            "description": "legacy cidr", "enabled": False,
            "priority": 0, "created_at": 1700000000,
        }]})
        cm.save()
        leg = self.client.get_json('/api/unified/legacy')
        self.assertTrue(leg["ok"])
        self.assertEqual(leg["count"], 1)
        m = self.client.post_json('/api/unified/migrate')
        self.assertTrue(m["ok"], m)
        self.assertEqual(len(m["migrated"]), 1)
        self.assertEqual(m["migrated"][0]["route_id"], "mig-cidr-test1234")
        # legacy-хранилище опустело, маршрут появился в едином слое
        leg2 = self.client.get_json('/api/unified/legacy')
        self.assertEqual(leg2["count"], 0)
        got = self.client.get_json('/api/unified/routes/mig-cidr-test1234')
        self.assertTrue(got["ok"])
        self.assertEqual(got["route"]["method"], "awg:awg0")
        self.assertEqual(got["route"]["destination"]["cidrs"],
                         ["10.10.0.0/16"])
        # повторная миграция — идемпотентный no-op
        m2 = self.client.post_json('/api/unified/migrate')
        self.assertTrue(m2["ok"])
        self.assertEqual(m2["migrated"], [])
        d = self.client.delete_json('/api/unified/routes/mig-cidr-test1234')
        self.assertTrue(d["ok"])


if __name__ == "__main__":
    unittest.main()
