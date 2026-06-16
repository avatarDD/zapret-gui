# tests/test_unified_geo.py
"""Тесты geo-инъекции: singbox_config-хелперы + geo_engine."""

import unittest
from unittest import mock

from core import singbox_config as sc
from core.unified import geo_engine
from core.unified.model import UnifiedRoute, Destination


class TestGeoRouteHelpers(unittest.TestCase):

    def test_build_rule(self):
        # geosite/geoip-матчеры удалены в sing-box 1.12 → хелпер принимает уже
        # развёрнутые домены/CIDR и эмитит ТОЛЬКО domain_suffix/ip_cidr.
        r = sc.build_geo_route_rule("PROXY", domains=["a.com"],
                                    cidrs=["1.2.3.0/24"])
        self.assertEqual(r["outbound"], "PROXY")
        self.assertEqual(r["domain_suffix"], ["a.com"])
        self.assertEqual(r["ip_cidr"], ["1.2.3.0/24"])
        # ключи удалённых матчеров не должны появляться никогда.
        self.assertNotIn("geosite", r)
        self.assertNotIn("geoip", r)

    def test_build_rule_only_cidr(self):
        r = sc.build_geo_route_rule("P", cidrs=["10.0.0.0/8"])
        self.assertNotIn("domain_suffix", r)
        self.assertEqual(r["ip_cidr"], ["10.0.0.0/8"])

    def test_add_remove_rule(self):
        cfg = {"outbounds": []}
        rule = sc.build_geo_route_rule("P", domains=["google.com"])
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

    def test_singbox_inject_resolves_geo_to_domain_ip(self):
        # geosite/geoip разворачиваются в domain_suffix/ip_cidr; удалённых в
        # sing-box 1.12 матчеров в сохранённом конфиге быть не должно.
        r = self._route(dest={"geosite": ["google"], "geoip": ["ru"]},
                        method="singbox:tun0")
        cfg = {"outbounds": [{"type": "vless", "tag": "PROXY"}],
               "route": {"rules": []}}
        mgr = mock.Mock()
        mgr.get_config.return_value = {"ok": True, "parsed": cfg}
        saved = {}
        mgr.save_config.side_effect = lambda name, text=None: (
            saved.update(text=text) or {"ok": True})
        mgr.is_running.return_value = False
        with mock.patch("core.unified.geo_engine.locate_singbox_config",
                        return_value="tun0"), \
             mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr), \
             mock.patch("core.routing.alias_resolver.expand_domains",
                        return_value={"domains": ["google.com"],
                                      "cidrs": ["1.0.0.0/8"],
                                      "aliases_resolved": [],
                                      "aliases_failed": []}):
            res = geo_engine.apply_geo(r, "singbox:tun0")
        self.assertTrue(res.get("applied"), msg=res)
        self.assertIn("google.com", saved["text"])
        self.assertIn("1.0.0.0/8", saved["text"])
        self.assertNotIn("geosite", saved["text"])
        self.assertNotIn('"geoip"', saved["text"])

    def test_singbox_inject_skips_when_resolution_empty(self):
        # Сеть недоступна / пустой результат → не добавляем правило-«ловушку»
        # без матчеров (иначе завернули бы ВЕСЬ трафик).
        r = self._route(dest={"geosite": ["google"]}, method="singbox:tun0")
        cfg = {"outbounds": [{"type": "vless", "tag": "PROXY"}],
               "route": {"rules": []}}
        mgr = mock.Mock()
        mgr.get_config.return_value = {"ok": True, "parsed": cfg}
        with mock.patch("core.unified.geo_engine.locate_singbox_config",
                        return_value="tun0"), \
             mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr), \
             mock.patch("core.routing.alias_resolver.expand_domains",
                        return_value={"domains": [], "cidrs": [],
                                      "aliases_resolved": [],
                                      "aliases_failed": [{"kind": "geosite",
                                                          "name": "google"}]}):
            res = geo_engine.apply_geo(r, "singbox:tun0")
        self.assertTrue(res.get("skipped"))
        mgr.save_config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
