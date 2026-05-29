# tests/test_unified_model.py
"""Unit-тесты для core/unified/model.py и storage.py."""

import unittest
from unittest import mock

from core.unified import model
from core.unified.model import Destination, UnifiedRoute, parse_method


class FakeConfigManager:
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def save(self):
        return True


class TestParseMethod(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(parse_method("direct"), ("direct", ""))
        self.assertEqual(parse_method("nfqws2"), ("nfqws2", ""))

    def test_tunnel(self):
        self.assertEqual(parse_method("awg:awg0"), ("awg", "awg0"))
        self.assertEqual(parse_method("singbox:tun0"), ("singbox", "tun0"))
        self.assertEqual(parse_method("mihomo:utun"), ("mihomo", "utun"))

    def test_tunnel_requires_iface(self):
        with self.assertRaises(ValueError):
            parse_method("awg")
        with self.assertRaises(ValueError):
            parse_method("singbox:")

    def test_unknown(self):
        with self.assertRaises(ValueError):
            parse_method("magic")
        with self.assertRaises(ValueError):
            parse_method("")

    def test_helpers(self):
        self.assertTrue(model.is_tunnel_method("awg:awg0"))
        self.assertFalse(model.is_tunnel_method("nfqws2"))
        self.assertEqual(model.method_iface("singbox:tun0"), "tun0")
        self.assertEqual(model.method_iface("direct"), "")


class TestDestination(unittest.TestCase):

    def test_resolve_inline(self):
        d = Destination(domains=["A.com", "a.com"], cidrs=["1.2.3.0/24"])
        r = d.resolve()
        self.assertEqual(r["domains"], ["a.com"])
        self.assertEqual(r["cidrs"], ["1.2.3.0/24"])

    def test_resolve_with_list(self):
        with mock.patch("core.named_lists.resolve",
                        return_value={"domains": ["x.com"], "cidrs": ["9.9.9.9/32"]}):
            d = Destination(domains=["a.com"], list_ids=["list-1"])
            r = d.resolve()
        self.assertIn("a.com", r["domains"])
        self.assertIn("x.com", r["domains"])
        self.assertIn("9.9.9.9/32", r["cidrs"])

    def test_empty(self):
        self.assertTrue(Destination().is_empty())
        self.assertFalse(Destination(domains=["a.com"]).is_empty())

    def test_roundtrip(self):
        d = Destination(domains=["a.com"], geosite=["google"], geoip=["ru"])
        d2 = Destination.from_dict(d.to_dict())
        self.assertEqual(d2.domains, ["a.com"])
        self.assertEqual(d2.geosite, ["google"])
        self.assertEqual(d2.geoip, ["ru"])


class TestUnifiedRoute(unittest.TestCase):

    def test_method_chain_dedup(self):
        r = UnifiedRoute(name="r", method="nfqws2",
                         fallbacks=["awg:awg0", "nfqws2", "direct"])
        self.assertEqual(r.method_chain(), ["nfqws2", "awg:awg0", "direct"])

    def test_invalid_method_rejected(self):
        with self.assertRaises(ValueError):
            UnifiedRoute(name="r", method="bogus")

    def test_roundtrip(self):
        r = UnifiedRoute(
            name="YT", destination=Destination(domains=["youtube.com"]),
            method="awg:awg0", fallbacks=["nfqws2"], priority=5,
            monitor_enabled=True, failover_enabled=True, probe_domain="youtube.com")
        r2 = UnifiedRoute.from_dict(r.to_dict())
        self.assertEqual(r2.method, "awg:awg0")
        self.assertEqual(r2.fallbacks, ["nfqws2"])
        self.assertTrue(r2.monitor_enabled)
        self.assertEqual(r2.destination.domains, ["youtube.com"])


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.unified.storage.get_config_manager",
                             return_value=self.fake)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_add_get_remove(self):
        from core.unified import storage
        r = UnifiedRoute(name="r1", method="direct")
        storage.add_route(r)
        got = storage.get_route(r.id)
        self.assertIsNotNone(got)
        self.assertEqual(got.name, "r1")
        self.assertEqual(len(storage.load_routes()), 1)
        self.assertTrue(storage.remove_route(r.id))
        self.assertFalse(storage.remove_route(r.id))

    def test_update_replaces(self):
        from core.unified import storage
        r = UnifiedRoute(name="r1", method="direct")
        storage.add_route(r)
        r2 = UnifiedRoute(route_id=r.id, name="renamed", method="nfqws2")
        storage.update_route(r2)
        self.assertEqual(len(storage.load_routes()), 1)
        self.assertEqual(storage.get_route(r.id).name, "renamed")


if __name__ == "__main__":
    unittest.main()
