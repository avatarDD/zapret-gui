# tests/test_routing_domain_sets.py
"""
Set-based доменная маршрутизация БЕЗ dnsmasq (Keenetic: 53-й порт занят
ndnsproxy, но ipset/iptables есть) + фоновый рефрешер IP
(core/routing/domain_refresh).

Причина появления: с одними destination-доменами (hostlist'ами) маршрут
«не работал без выбора устройства» — iproute-фолбэк резолвил домены один
раз при применении, IP протухали, большие hostlist'ы резолвились
минутами. Теперь set + fwmark + собственный резолв + периодическое
обновление.
"""

import unittest
from unittest import mock

from core.routing import domain_refresh, domain_rule, ipset_backend
from core.routing.rules import DomainRoutingRule


def _rule(rule_id="uni-s", domains=None):
    return DomainRoutingRule(target_iface="awg0",
                             domains=domains or ["example.com"],
                             rule_id=rule_id)


class TestApplyDomainViaSets(unittest.TestCase):

    def _apply(self, rule, state=None):
        saved = {}

        def fake_save(st):
            saved.update(st)

        with mock.patch.object(domain_rule, "_backend_for",
                               return_value=ipset_backend), \
             mock.patch.object(domain_rule, "_iface_exists",
                               return_value=True), \
             mock.patch.object(domain_rule, "_ensure_table_default",
                               return_value=True), \
             mock.patch.object(ipset_backend, "create_set",
                               side_effect=lambda n, family: {
                                   "ok": True, "name": n}) as create, \
             mock.patch.object(ipset_backend, "setup_mark_rule",
                               return_value={"ok": True}) as mark, \
             mock.patch.object(ipset_backend, "add_ip_rule_fwmark",
                               return_value={"ok": True}) as fwm, \
             mock.patch.object(domain_rule, "_prepopulate_domains",
                               return_value=[{"ok": True, "added": 2}]) \
                as prepop, \
             mock.patch.object(domain_rule, "_sets_state_load",
                               return_value=dict(state or {})), \
             mock.patch.object(domain_rule, "_sets_state_save",
                               side_effect=fake_save), \
             mock.patch.object(domain_rule, "_start_refresher") as ref, \
             mock.patch("core.routing.masquerade.ensure_for_iface",
                        return_value={"ok": True}):
            res = domain_rule._apply_domain_via_sets(rule)
        return res, saved, create, mark, fwm, prepop, ref

    def test_applies_sets_marks_and_prepopulates(self):
        rule = _rule()
        res, saved, create, mark, fwm, prepop, ref = self._apply(rule)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["backend"], "ipset")
        # v4 + v6: set, mark-правило, fwmark ip rule
        self.assertEqual(create.call_count, 2)
        self.assertEqual(mark.call_count, 2)
        self.assertEqual(fwm.call_count, 2)
        prepop.assert_called_once()
        # правило учтено в состоянии — рефрешер будет его пополнять
        self.assertEqual(saved.get(rule.id), "ipset")
        ref.assert_called_once()
        self.assertIn("note", res)

    def test_deferred_when_iface_down(self):
        rule = _rule()
        with mock.patch.object(domain_rule, "_backend_for",
                               return_value=ipset_backend), \
             mock.patch.object(domain_rule, "_iface_exists",
                               return_value=False):
            res = domain_rule._apply_domain_via_sets(rule)
        self.assertTrue(res["ok"])
        self.assertTrue(res["deferred"])

    def test_error_without_backend(self):
        with mock.patch.object(domain_rule, "_backend_for",
                               return_value=None):
            res = domain_rule._apply_domain_via_sets(_rule())
        self.assertFalse(res["ok"])


class TestRemoveDomainViaSets(unittest.TestCase):

    def test_teardown_and_state_cleanup(self):
        rule = _rule()
        saved = {}
        with mock.patch.object(domain_rule, "_sets_state_load",
                               return_value={rule.id: "ipset"}), \
             mock.patch.object(domain_rule, "_sets_state_save",
                               side_effect=saved.update), \
             mock.patch.object(ipset_backend, "del_ip_rule_fwmark",
                               return_value={"ok": True}) as delr, \
             mock.patch.object(ipset_backend, "teardown_mark_rule",
                               return_value={"ok": True}) as tear, \
             mock.patch.object(ipset_backend, "destroy_set",
                               return_value={"ok": True}) as destr, \
             mock.patch("core.routing.masquerade.remove_if_unused"):
            res = domain_rule._remove_domain_via_sets(rule)
        self.assertTrue(res["ok"])
        self.assertEqual(delr.call_count, 2)
        self.assertEqual(tear.call_count, 2)
        self.assertEqual(destr.call_count, 2)
        self.assertNotIn(rule.id, saved)

    def test_remove_domain_rule_dispatches_to_sets(self):
        rule = _rule()
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=False), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_sets_state_load",
                               return_value={rule.id: "ipset"}), \
             mock.patch.object(domain_rule, "_remove_domain_via_sets",
                               return_value={"ok": True,
                                             "backend": "ipset"}) as f:
            res = domain_rule.remove_domain_rule(rule)
        f.assert_called_once()
        self.assertEqual(res.get("backend"), "ipset")


class TestDomainRefresh(unittest.TestCase):

    def test_refresh_once_tops_up_sets_rules(self):
        rule = _rule(rule_id="uni-r")
        with mock.patch("core.routing.storage.load_rules",
                        return_value=[rule]), \
             mock.patch.object(domain_rule, "_sets_state_load",
                               return_value={rule.id: "ipset"}), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_iface_exists",
                               return_value=True), \
             mock.patch.object(domain_rule, "_prepopulate_domains",
                               return_value=[{"ok": True, "added": 3}]) \
                as prepop:
            stats = domain_refresh.refresh_once()
        prepop.assert_called_once()
        self.assertEqual(stats["sets"], 1)
        self.assertEqual(stats["ips_added"], 3)

    def test_refresh_once_adds_new_iproute_ips(self):
        rule = _rule(rule_id="uni-i")
        runs = []

        def fake_run(args, **kw):
            runs.append(list(args))
            return mock.Mock(returncode=0, stderr="", stdout="")

        # 1.2.3.4 уже в state, 5.6.7.8 — новый: добавиться должен только он.
        state = {rule.id: [["1.2.3.4/32", "-4"]]}
        with mock.patch("core.routing.storage.load_rules",
                        return_value=[rule]), \
             mock.patch.object(domain_rule, "_sets_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               side_effect=lambda: {k: list(v) for k, v
                                                    in state.items()}), \
             mock.patch.object(domain_rule, "_iproute_state_save") as save, \
             mock.patch.object(domain_rule, "_iface_exists",
                               return_value=True), \
             mock.patch.object(domain_rule, "_resolve_ips",
                               side_effect=lambda d, f: (
                                   ["1.2.3.4", "5.6.7.8"]
                                   if f == "v4" else [])), \
             mock.patch("subprocess.run", side_effect=fake_run):
            stats = domain_refresh.refresh_once()

        self.assertEqual(stats["iproute"], 1)
        self.assertEqual(stats["ips_added"], 1)
        adds = [" ".join(a) for a in runs if "add" in a]
        self.assertTrue(any("5.6.7.8/32" in a for a in adds))
        self.assertFalse(any("1.2.3.4/32" in a for a in adds))
        save.assert_called_once()

    def test_refresh_skips_dnsmasq_managed_rules(self):
        # Правило не числится ни в sets-, ни в iproute-state
        # (им занимается dnsmasq/NDMS) — рефрешер его не трогает.
        rule = _rule(rule_id="uni-d")
        with mock.patch("core.routing.storage.load_rules",
                        return_value=[rule]), \
             mock.patch.object(domain_rule, "_sets_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_prepopulate_domains") as pp:
            stats = domain_refresh.refresh_once()
        pp.assert_not_called()
        self.assertEqual(stats, {"sets": 0, "iproute": 0, "ips_added": 0})

    def test_interval_and_enabled_defaults(self):
        with mock.patch.object(domain_refresh, "_settings",
                               return_value={}):
            self.assertTrue(domain_refresh.is_enabled())
            self.assertEqual(domain_refresh.interval_sec(), 600)
        with mock.patch.object(domain_refresh, "_settings",
                               return_value={"enabled": False,
                                             "interval_min": 1}):
            self.assertFalse(domain_refresh.is_enabled())
            self.assertEqual(domain_refresh.interval_sec(), 60)


if __name__ == "__main__":
    unittest.main()
