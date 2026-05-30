# tests/test_devices_discovery.py
"""Тесты извлечения hostname из NDM-структуры (RCI/CLI)."""

import unittest

from core.devices_discovery import _extract_ndm_hosts


class TestExtractNdmHosts(unittest.TestCase):

    def test_host_list_with_names(self):
        data = {"host": [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10",
             "name": "Galaxy-S21"},
            {"mac": "11:22:33:44:55:66", "ip": "192.168.1.11",
             "hostname": "macbook"},
        ]}
        out = _extract_ndm_hosts(data)
        self.assertEqual(len(out), 2)
        names = {h["ip"]: h["hostname"] for h in out}
        self.assertEqual(names["192.168.1.10"], "Galaxy-S21")
        self.assertEqual(names["192.168.1.11"], "macbook")
        self.assertTrue(all(h["source"] == "ndm" for h in out))

    def test_name_preferred_over_hostname(self):
        data = {"host": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1",
                          "name": "AdminName", "hostname": "client-sent"}]}
        self.assertEqual(_extract_ndm_hosts(data)[0]["hostname"], "AdminName")

    def test_single_host_dict(self):
        data = {"host": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.2",
                         "name": "solo"}}
        out = _extract_ndm_hosts(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["hostname"], "solo")

    def test_bare_array(self):
        data = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.3", "name": "x"}]
        self.assertEqual(len(_extract_ndm_hosts(data)), 1)

    def test_skips_without_ip_or_mac(self):
        data = {"host": [{"name": "nothing"}]}
        self.assertEqual(_extract_ndm_hosts(data), [])

    def test_empty_and_garbage(self):
        self.assertEqual(_extract_ndm_hosts({}), [])
        self.assertEqual(_extract_ndm_hosts({"host": None}), [])
        self.assertEqual(_extract_ndm_hosts("not a dict"), [])
        self.assertEqual(_extract_ndm_hosts(None), [])


if __name__ == "__main__":
    unittest.main()
