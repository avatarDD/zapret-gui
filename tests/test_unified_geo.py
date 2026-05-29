# tests/test_unified_geo.py
"""Тесты geo-инъекции: singbox_config-хелперы + geo_engine."""

import unittest
from unittest import mock

from core import singbox_config as sc
from core.unified import geo_engine
from core.unified.model import UnifiedRoute, Destination


class TestGeoRouteHelpers(unittest.TestCase):

    def test_build_rule(self):
        r = sc.build_geo_route_rule("PROXY", domains=["a.com"],
                                    geosite=["google"], geoip=["ru"])
        self.assertEqual(r["outbound"], "PROXY")
        self.assertEqual(r["domain_suffix"], ["a.com"])
        self.assertEqual(r["geosite"], ["google"])
        self.assertEqual(r["geoip"], ["ru"])

    def test_build_rule_only_geosite(self):
        r = sc.build_geo_route_rule("P", geosite=["youtube"])
        self.assertNotIn("domain_suffix", r)
        self.assertNotIn("geoip", r)
        self.assertEqual(r["geosite"], ["youtube"])

    def test_add_remove_rule(self):
        cfg = {"outbounds": []}
        rule = sc.build_geo_route_rule("P", geosite=["google"])
        sc.add_route_rule(cfg, rule)
        self.assertEqual(cfg["route"]["rules"][0], rule)
        self.assertTrue(sc.remove_route_rule(cfg, rule))
        self.assertEqual(cfg["route"]["rules"], [])
        self.assertFalse(sc.remove_route_rule(cfg, rule))

    def test_pick_outbound_prefers_group(self):
        cfg = {"outbounds": [
            {"type": "vless", "tag": "v1"},
            {"type": "selector", "tag": "PROXY", "outbounds": ["v1"]},
        ]}
        self.assertEqual(sc.pick_proxy_outbound(cfg), "PROXY")

    def test_pick_outbound_first_real(self):
        cfg = {"outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "trojan", "tag": "t1"},
        ]}
        self.assertEqual(sc.pick_proxy_outbound(cfg), "t1")

    def test_pick_outbound_none(self):
        cfg = {"outbounds": [{"type": "direct", "tag": "direct"}]}
        self.assertEqual(sc.pick_proxy_outbound(cfg), "")

    def test_find_tun_interface(self):
        cfg = {"inbounds": [{"type": "tun", "interface_name": "sb-tun"}]}
        self.assertEqual(sc.find_tun_interface(cfg), "sb-tun")
        self.assertEqual(sc.find_tun_interface({"inbounds": []}), "")


class TestLocateConfig(unittest.TestCase):

    def test_locate_by_interface_name(self):
        mgr = mock.Mock()
        mgr.list_configs.return_value = [{"name": "home"}, {"name": "work"}]
        def _get(name):
            cfgs = {
                "home": {"inbounds": [{"type": "tun", "interface_name": "tun9"}]},
                "work": {"inbounds": [{"type": "tun", "interface_name": "tunX"}]},
            }
            return {"ok": True, "parsed": cfgs[name]}
        mgr.get_config.side_effect = _get
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr):
            self.assertEqual(geo_engine.locate_singbox_config("tun9"), "home")

    def test_locate_by_name_fallback(self):
        mgr = mock.Mock()
        mgr.list_configs.return_value = [{"name": "tun0"}]
        mgr.get_config.return_value = {"ok": True, "parsed": {"inbounds": []}}
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr):
            self.assertEqual(geo_engine.locate_singbox_config("tun0"), "tun0")

    def test_locate_not_found(self):
        mgr = mock.Mock()
        mgr.list_configs.return_value = [{"name": "home"}]
        mgr.get_config.return_value = {"ok": True, "parsed": {"inbounds": []}}
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr):
            self.assertEqual(geo_engine.locate_singbox_config("nope"), "")


class TestApplyGeo(unittest.TestCase):

    def _route(self, **kw):
        return UnifiedRoute(name="t", method=kw.get("method", "singbox:tun0"),
                            destination=Destination(**kw.get("dest", {})))

    def test_no_geo_noop(self):
        r = self._route(dest={"domains": ["a.com"]})
        with mock.patch("core.unified.geo_engine.remove_geo") as rm:
            res = geo_engine.apply_geo(r, "singbox:tun0")
        self.assertTrue(res.get("noop"))

    def test_mihomo_skipped(self):
        r = self._route(dest={"geosite": ["google"]}, method="mihomo:utun")
        res = geo_engine.apply_geo(r, "mihomo:utun")
        self.assertTrue(res["skipped"])
        self.assertIn("mihomo", res["reason"])

    def test_awg_skipped(self):
        r = self._route(dest={"geosite": ["google"]}, method="awg:awg0")
        res = geo_engine.apply_geo(r, "awg:awg0")
        self.assertTrue(res["skipped"])

    def test_singbox_config_not_found(self):
        r = self._route(dest={"geosite": ["google"]}, method="singbox:tun0")
        with mock.patch("core.unified.geo_engine.locate_singbox_config",
                        return_value=""):
            res = geo_engine.apply_geo(r, "singbox:tun0")
        self.assertTrue(res["skipped"])
        self.assertIn("не найден", res["reason"])


if __name__ == "__main__":
    unittest.main()
