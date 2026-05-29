# tests/test_unified_applier.py
"""
Unit-тесты для core/unified/applier.py.

RoutingManager и HostlistManager мокаем — проверяем, что applier
раскладывает маршрут в правильные производные артефакты и снимает
неактуальные при смене метода.
"""

import unittest
from unittest import mock

from core.unified.applier import (
    apply_route, remove_route, _dom_rule_id, _cidr_rule_id, _hostlist_name,
)
from core.unified.model import UnifiedRoute, Destination


def _route(method, domains=None, cidrs=None):
    return UnifiedRoute(
        name="t", method=method,
        destination=Destination(domains=domains or [], cidrs=cidrs or []))


class TestApplyTunnel(unittest.TestCase):

    def setUp(self):
        self.mgr = mock.Mock()
        self.mgr.add_rule.return_value = {"ok": True}
        self.mgr.update_rule.return_value = {"ok": True}
        self._pm = mock.patch("core.routing.get_routing_manager",
                              return_value=self.mgr)
        self._pm.start()
        # storage.get_rule → None (правил ещё нет) — чтобы upsert делал add.
        self._ps = mock.patch("core.routing.storage.get_rule",
                              return_value=None)
        self._ps.start()
        # без активного failover-метода
        self._pf = mock.patch("core.unified.failover.current_method",
                              return_value=None)
        self._pf.start()
        # hostlist cleanup — no-op
        self._ph = mock.patch("core.unified.applier._remove_hostlist")
        self._ph.start()

    def tearDown(self):
        for p in (self._pm, self._ps, self._pf, self._ph):
            p.stop()

    def test_tunnel_creates_domain_and_cidr_rules(self):
        r = _route("awg:awg0", domains=["youtube.com"], cidrs=["1.2.3.0/24"])
        res = apply_route(r)
        self.assertTrue(res["ok"])
        self.assertEqual(res["iface"], "awg0")
        # добавлены два правила (domain + cidr)
        self.assertEqual(self.mgr.add_rule.call_count, 2)
        added_ids = [c.args[0].id for c in self.mgr.add_rule.call_args_list]
        self.assertIn(_dom_rule_id(r.id), added_ids)
        self.assertIn(_cidr_rule_id(r.id), added_ids)
        # верный target_iface
        for c in self.mgr.add_rule.call_args_list:
            self.assertEqual(c.args[0].target_iface, "awg0")

    def test_tunnel_only_domains(self):
        r = _route("singbox:tun0", domains=["a.com"])
        res = apply_route(r)
        self.assertTrue(res["ok"])
        self.assertEqual(self.mgr.add_rule.call_count, 1)
        # cidr-правило не создаётся, а возможный старый — снимается (get_rule None → no remove)
        self.mgr.remove_rule.assert_not_called()

    def test_geosite_skipped(self):
        r = UnifiedRoute(name="g", method="awg:awg0",
                         destination=Destination(domains=["a.com"],
                                                  geosite=["google"]))
        res = apply_route(r)
        self.assertTrue(res["skipped_selectors"])


class TestApplyNfqwsAndDirect(unittest.TestCase):

    def setUp(self):
        self._pf = mock.patch("core.unified.failover.current_method",
                              return_value=None)
        self._pf.start()
        self._prr = mock.patch("core.unified.applier._remove_routing_rules")
        self._prr.start()

    def tearDown(self):
        self._pf.stop()
        self._prr.stop()

    def test_nfqws_saves_hostlist(self):
        hm = mock.Mock()
        hm.save_hostlist.return_value = {"ok": True}
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm):
            r = _route("nfqws2", domains=["x.com", "y.com"])
            res = apply_route(r)
        self.assertTrue(res["ok"])
        # Вызывается per-route save + пересборка агрегата unified_nfqws.
        per_route = [c for c in hm.save_hostlist.call_args_list
                     if c.args[0] == _hostlist_name(r.id)]
        self.assertEqual(len(per_route), 1)
        self.assertEqual(per_route[0].args[1], ["x.com", "y.com"])

    def test_direct_cleans_up(self):
        with mock.patch("core.unified.applier._remove_hostlist") as rh:
            r = _route("direct", domains=["a.com"])
            res = apply_route(r)
        self.assertTrue(res["ok"])
        self.assertEqual(res["method"], "direct")
        rh.assert_called_once()


class TestRemoveRoute(unittest.TestCase):

    def test_remove_calls_both(self):
        with mock.patch("core.unified.applier._remove_routing_rules") as rr, \
             mock.patch("core.unified.applier._remove_hostlist") as rh:
            r = _route("awg:awg0", domains=["a.com"])
            res = remove_route(r)
        self.assertTrue(res["ok"])
        rr.assert_called_once()
        rh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
