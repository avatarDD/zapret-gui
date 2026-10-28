"""Находки прогона точечной маршрутизации через MCP на OpenWrt.

Интерфейс-опечатка, несуществующий список, устройство только по MAC,
URL вместо домена, перекрытия маршрутов, nfqws2 без флага, правка
списка без переприменения маршрутов, раздутый ответ save и
противоречивая подсказка hostlist_edit.
"""

import unittest
from unittest import mock

from core.unified import bulk, manager
from core.unified.model import UnifiedRoute, Destination


def _save(data, previous=None, **patches):
    """save_route(validate=True) без диска, ядра и монитора."""
    with mock.patch("core.unified.storage.get_route",
                    return_value=previous), \
            mock.patch("core.unified.storage.add_route"), \
            mock.patch("core.unified.storage.update_route"), \
            mock.patch("core.unified.applier.apply_route",
                       return_value={"ok": True}), \
            mock.patch.object(manager, "_sync_monitor"), \
            mock.patch.object(manager, "_router_devices", return_value=[]):
        return manager.save_route(data, validate=True)


class TestNormalizeDomains(unittest.TestCase):

    def test_urls_become_hosts(self):
        self.assertEqual(
            bulk.normalize_domains([
                "https://www.Example.com/some/path?q=1",
                "example.org/some/path", "http://user@host.net:8080/",
                "10.0.0.0/8", "1.2.3.4", "*.wild.example.org",
                "geosite:youtube", "plain.com", "www.keep.com"]),
            ["example.com", "example.org", "host.net", "10.0.0.0/8",
             "1.2.3.4", "*.wild.example.org", "geosite:youtube",
             "plain.com", "www.keep.com"])

    def test_path_error_speaks_of_domain(self):
        errs = bulk.validate_destination({"domains": ["example.com/x"]})
        self.assertEqual(len(errs), 1)
        self.assertIn("домен с путём", errs[0])
        self.assertNotIn("IP", errs[0])

    def test_save_accepts_url(self):
        res = _save({"method": "direct",
                     "destination": {"domains": ["https://example.com/a"]}})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["route"]["destination"]["domains"],
                         ["example.com"])


class TestUnknownIface(unittest.TestCase):

    def setUp(self):
        p = mock.patch.object(manager, "CHECK_IFACES", True)
        p.start()
        self.addCleanup(p.stop)

    def _data(self, method, fallbacks=()):
        return {"method": method, "fallbacks": list(fallbacks),
                "destination": {"domains": ["example.com"]}}

    def test_typo_is_refused(self):
        with mock.patch("core.unified.model.iface_present",
                        return_value=False), \
                mock.patch.object(manager, "_engine_ifaces",
                                  return_value={"awg_warp", "proton"}):
            res = _save(self._data("awg:nosuchiface"))
            fb = _save(self._data("awg:awg_warp", ["warp:usque0"]))
        self.assertFalse(res["ok"])
        self.assertIn("nosuchiface", res["error"])
        self.assertIn("awg_warp", res["error"])
        self.assertFalse(fb["ok"])
        self.assertIn("usque0", fb["error"])

    def test_configured_but_down_is_accepted(self):
        with mock.patch("core.unified.model.iface_present",
                        return_value=False), \
                mock.patch.object(manager, "_engine_ifaces",
                                  return_value={"awg_warp"}):
            self.assertTrue(_save(self._data("awg:awg_warp"))["ok"])

    def test_live_iface_and_unreadable_configs_pass(self):
        with mock.patch("core.unified.model.iface_present",
                        return_value=True):
            self.assertTrue(_save(self._data("singbox:tun0"))["ok"])
        with mock.patch("core.unified.model.iface_present",
                        return_value=False), \
                mock.patch.object(manager, "_engine_ifaces",
                                  return_value=None):
            self.assertTrue(_save(self._data("mihomo:mt0"))["ok"])

    def test_old_route_stays_editable(self):
        prev = UnifiedRoute(route_id="r1", method="awg:gone",
                            destination=Destination(domains=["a.com"]))
        data = dict(self._data("awg:gone"), id="r1", enabled=False)
        with mock.patch("core.unified.model.iface_present",
                        return_value=False), \
                mock.patch.object(manager, "_engine_ifaces",
                                  return_value=set()), \
                mock.patch("core.unified.applier.remove_route"), \
                mock.patch.object(manager, "_sweep_dnsmasq"):
            self.assertTrue(_save(data, previous=prev)["ok"])


class TestUnknownList(unittest.TestCase):

    def test_typo_is_refused_with_available(self):
        hm = mock.Mock()
        hm.list_names.return_value = ["other", "other2", "unified_nfqws"]
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm):
            res = _save({"method": "direct",
                         "destination": {"list_ids": ["hl:nosuchlist"]}})
            ok = _save({"method": "direct",
                        "destination": {"list_ids": ["hl:other2"]}})
        self.assertFalse(res["ok"])
        self.assertIn("hl:nosuchlist", res["error"])
        self.assertIn("hl:other2", res["error"])
        self.assertNotIn("unified_nfqws", res["error"])
        self.assertTrue(ok["ok"], ok)

    def test_ipset_and_named(self):
        im = mock.Mock()
        im.list_names.return_value = ["ipset-base"]
        with mock.patch("core.ipset_manager.get_ipset_manager",
                        return_value=im), \
                mock.patch("core.named_lists.get", return_value=None), \
                mock.patch("core.named_lists.list_all", return_value=[]):
            missing = bulk.unknown_list_ids(["ipl:nosuch", "ipl:ipset-base",
                                             "nl-123"])
        self.assertEqual([m["id"] for m in missing], ["ipl:nosuch", "nl-123"])


class TestDevicesByMac(unittest.TestCase):

    def test_mac_resolves_to_ip(self):
        with mock.patch("core.devices_discovery.mac_ip_map",
                        return_value={"aa:bb:cc:dd:ee:ff": "192.168.1.50"}):
            res = _save({"method": "awg:awg0",
                         "devices": [{"mac": "AA:BB:CC:DD:EE:FF"}]})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["route"]["devices"][0]["ip"], "192.168.1.50")

    def test_unknown_mac_is_an_error_not_whole_network(self):
        with mock.patch("core.devices_discovery.mac_ip_map",
                        return_value={}):
            res = _save({"method": "direct",
                         "destination": {"domains": ["example.com"]},
                         "devices": [{"mac": "aa:bb:cc:dd:ee:ff"}]})
        self.assertFalse(res["ok"])
        self.assertIn("aa:bb:cc:dd:ee:ff", res["error"])


class TestReleaseTables(unittest.TestCase):

    def test_dead_iface_number_is_returned(self):
        route = UnifiedRoute(route_id="r1", method="awg:nosuchiface",
                             fallbacks=["awg:awg_warp"],
                             destination=Destination(domains=["a.com"]))
        with mock.patch("core.routing.storage.load_rules", return_value=[]), \
                mock.patch("core.unified.storage.load_routes",
                           return_value=[]), \
                mock.patch("core.unified.model.iface_present",
                           side_effect=lambda i: i == "awg_warp"), \
                mock.patch("core.routing.manager.release_table") as rel:
            manager._release_tables(route)
        rel.assert_called_once_with("nosuchiface")


class TestProbeDeadIface(unittest.TestCase):

    def test_missing_iface_is_a_failure(self):
        from core.unified import monitor
        route = UnifiedRoute(method="awg:nosuchiface",
                             destination=Destination(domains=["a.com"]))
        with mock.patch("core.unified.model.iface_present",
                        return_value=False), \
                mock.patch.object(monitor, "probe_host",
                                  return_value=True) as ph, \
                mock.patch("core.unified.failover.current_method",
                           return_value=None):
            self.assertFalse(monitor.probe_route(route))
        ph.assert_not_called()


class TestNfqwsNote(unittest.TestCase):

    def test_flag_off_is_not_claimed_effective(self):
        from core.unified import applier
        route = UnifiedRoute(method="nfqws2",
                             destination=Destination(domains=["a.com"]))
        hm = mock.Mock()
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm), \
                mock.patch("core.unified.nfqws_hostlist.rebuild",
                           return_value={"ok": True}), \
                mock.patch("core.unified.nfqws_hostlist.enabled",
                           return_value=False), \
                mock.patch.object(applier, "_remove_routing_rules"):
            res = applier._apply_nfqws(route, ["a.com"])
        self.assertIs(res["effective"], False)
        self.assertIn("nfqws.unified_hostlist", res["note"])

    def test_setting_is_known(self):
        from core.config_manager import DEFAULT_CONFIG
        self.assertIn("unified_hostlist", DEFAULT_CONFIG["nfqws"])


class TestSaveResponse(unittest.TestCase):

    def test_long_lists_are_compacted(self):
        from core.mcp.tools.routing import _compact
        out = _compact({"applied": [{"prepop": list(range(300))}]})
        item = out["applied"][0]
        self.assertEqual(len(item["prepop"]), 10)
        self.assertEqual(item["prepop_total"], 300)

    def test_overlap_warning(self):
        from core.mcp.tools import routing
        routes = [
            {"id": "a", "enabled": True, "method": "awg:awg_warp",
             "destination": {"list_ids": ["hl:other2"]}},
            {"id": "b", "enabled": True, "method": "awg:proton",
             "destination": {"list_ids": ["hl:other2"]}},
        ]
        with mock.patch("core.unified.manager.list_routes",
                        return_value=routes):
            found = routing._overlaps_with(routes[1])
        self.assertEqual(found[0]["routes"], ["a", "b"])


class TestListEditHint(unittest.TestCase):

    def _result(self, pids):
        from core.mcp.tools import lists
        with mock.patch("core.nfqws_reload.find_nfqws_pids",
                        return_value=pids), \
                mock.patch("core.mcp.audit.snapshot", return_value="u1"), \
                mock.patch.object(lists, "_reapply_routes",
                                  return_value=[{"id": "r1", "ok": True}]):
            return lists._list_result("hostlist", "hostlist_edit", "other2",
                                      "add", ["a.com"], ["a.com", "b.com"],
                                      [], what="доменов",
                                      route_ref="hl:other2")

    def test_no_engine_no_sighup_claim(self):
        res = self._result([])
        self.assertIn("не запущен", res["hint"])
        self.assertNotIn("уведомлён по SIGHUP", res["hint"])

    def test_running_engine(self):
        res = self._result([123])
        self.assertIn("уведомлён по SIGHUP", res["hint"])
        self.assertNotIn("не запущен", res["hint"])
        self.assertEqual(res["routes_reapplied"], [{"id": "r1", "ok": True}])

    def test_reapply_now_runs_synchronously(self):
        route = UnifiedRoute(route_id="r1", method="awg:awg0",
                             destination=Destination(list_ids=["hl:other2"]))
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
                mock.patch("core.unified.applier.apply_route",
                           return_value={"ok": True}) as ap:
            res = manager.reapply_now(["hl:other2"])
        ap.assert_called_once()
        self.assertEqual(res["applied"][0]["id"], "r1")


class TestSiteTracePending(unittest.TestCase):

    def test_domain_not_in_kernel_is_flagged(self):
        from core import site_trace
        from core.routing.rules import DomainRoutingRule
        route = UnifiedRoute(route_id="r1", name="warp",
                             method="awg:awg_warp",
                             destination=Destination(domains=["new.com",
                                                              "old.com"]))
        rule = DomainRoutingRule(target_iface="awg_warp",
                                 domains=["old.com"], rule_id="uni-r1-dom")
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
                mock.patch("core.routing.storage.get_rule",
                           return_value=rule), \
                mock.patch("core.unified.failover.current_method",
                           return_value=None):
            new = site_trace._unified_layer("new.com")
            old = site_trace._unified_layer("old.com")
        self.assertTrue(new[0]["pending"])
        self.assertFalse(old[0]["pending"])
        lines = site_trace.summarize({"routes": new})
        self.assertIn("НЕ разложен", " ".join(lines))
        self.assertFalse(any("уходит в туннель" in x for x in lines))


if __name__ == "__main__":
    unittest.main()
