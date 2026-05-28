# tests/test_api_connectivity.py
"""Integration-тесты для api/connectivity.py."""

import unittest

from tests._wsgi_client import WSGIClient, build_test_app


class TestConnectivityAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_matrix_empty_when_no_probe(self):
        r = self.client.get_json("/api/connectivity/matrix")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("snapshot", r)
        # До первого probe snapshot пустой.
        self.assertEqual(r["snapshot"]["cells"], [])

    def test_targets_get(self):
        r = self.client.get_json("/api/connectivity/targets")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertGreater(len(r["targets"]), 0)
        self.assertGreater(len(r["defaults"]), 0)

    def test_targets_set_custom(self):
        r = self.client.post_json("/api/connectivity/targets",
                                   {"targets": [
                                       {"name": "Custom", "host": "1.2.3.4"},
                                   ]})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["targets"]), 1)
        self.assertEqual(r["targets"][0]["host"], "1.2.3.4")
        # Возвращаем дефолты для следующих тестов.
        self.client.post_json("/api/connectivity/targets",
                               {"targets": []})

    def test_targets_set_invalid(self):
        r = self.client.post_json("/api/connectivity/targets",
                                   {"targets": "not-a-list"})
        self.assertEqual(r["_status"], 400)

    def test_traffic_index(self):
        r = self.client.get_json("/api/connectivity/traffic")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("ifaces", r)
        self.assertIn("sample_interval", r)

    def test_traffic_iface_no_data(self):
        r = self.client.get_json("/api/connectivity/traffic/awg0")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        # Без данных серии пустые.
        s = r["series"]
        self.assertEqual(s["iface"], "awg0")
        self.assertEqual(s["1h"], [])

    def test_peers_no_data(self):
        r = self.client.get_json("/api/connectivity/peers/awg0")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(r["peers"]["iface"], "awg0")
        self.assertEqual(r["peers"]["peers"], [])


if __name__ == "__main__":
    unittest.main()
