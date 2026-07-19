# tests/test_routing_domain_iproute.py
"""
Доменная маршрутизация через ip-route для userspace-туннелей
(singbox-tun / amneziawg / WARP), где NDMS dns-proxy route не работает
(привязывает домены только к нативным NDMS-интерфейсам), а dnsmasq на
Keenetic не поднять.
"""

import unittest
from unittest import mock

from core.routing import domain_rule
from core.routing.rules import DomainRoutingRule


def _rule():
    return DomainRoutingRule(target_iface="singbox-tun",
                             domains=["example.com"], rule_id="uni-x")


class TestApplyDomainViaIproute(unittest.TestCase):

    def test_resolves_and_adds_ip_rules(self):
        rule = _rule()
        runs = []

        def fake_run(args, **kw):
            runs.append(list(args))
            return mock.Mock(returncode=0, stderr="", stdout="")

        with mock.patch.object(domain_rule, "_iface_exists",
                               return_value=True), \
             mock.patch.object(domain_rule, "_resolve_ips",
                               side_effect=lambda d, f: (["1.2.3.4"]
                                                         if f == "v4" else [])), \
             mock.patch.object(domain_rule, "_ensure_table_default",
                               return_value=True), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value={}), \
             mock.patch.object(domain_rule, "_iproute_state_save") as save, \
             mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch("core.routing.masquerade.ensure_for_iface",
                        return_value={"ok": True}):
            res = domain_rule._apply_domain_via_iproute(rule)

        self.assertTrue(res["ok"])
        self.assertEqual(res["backend"], "iproute")
        self.assertGreaterEqual(res["ips_added"], 1)
        # есть `ip -4 rule add to 1.2.3.4/32 lookup <table>`
        self.assertTrue(any("add" in a and "1.2.3.4/32" in a for a in runs))
        save.assert_called()

    def test_deferred_when_iface_down(self):
        with mock.patch.object(domain_rule, "_iface_exists",
                               return_value=False):
            res = domain_rule._apply_domain_via_iproute(_rule())
        self.assertTrue(res["ok"])
        self.assertTrue(res["deferred"])


class TestApplyDomainRuleRouting(unittest.TestCase):
    """apply_domain_rule выбирает ip-route путь для userspace-туннеля
    без dnsmasq (а не падает с ошибкой про dnsmasq)."""

    def test_userspace_no_dnsmasq_no_sets_goes_iproute(self):
        # Без dnsmasq И без ipset/nft — прежний iproute-фолбэк.
        rule = _rule()
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=False), \
             mock.patch.object(domain_rule, "_backend_for",
                               return_value=None), \
             mock.patch.object(domain_rule, "_apply_domain_via_iproute",
                               return_value={"ok": True,
                                             "backend": "iproute"}) as f, \
             mock.patch("core.routing.dnsmasq_integration.DnsmasqIntegration") \
                as Dn:
            Dn.return_value.status.return_value = {"available": False,
                                                   "running": False}
            res = domain_rule.apply_domain_rule(rule)
        f.assert_called_once()
        self.assertEqual(res.get("backend"), "iproute")

    def test_userspace_no_dnsmasq_with_sets_goes_sets(self):
        # Без dnsmasq, но с ipset/nft — set-based путь (масштабируется
        # и обновляется рефрешером), а не iproute.
        from core.routing import ipset_backend
        rule = _rule()
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=False), \
             mock.patch.object(domain_rule, "_backend_for",
                               return_value=ipset_backend), \
             mock.patch.object(domain_rule, "_apply_domain_via_sets",
                               return_value={"ok": True,
                                             "backend": "ipset"}) as f, \
             mock.patch("core.routing.dnsmasq_integration.DnsmasqIntegration") \
                as Dn:
            Dn.return_value.status.return_value = {"available": False,
                                                   "running": False}
            res = domain_rule.apply_domain_rule(rule)
        f.assert_called_once()
        self.assertEqual(res.get("backend"), "ipset")

    def test_native_ndms_iface_uses_ndms(self):
        rule = DomainRoutingRule(target_iface="Wireguard0",
                                 domains=["example.com"], rule_id="uni-y")
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=True), \
             mock.patch.object(domain_rule, "_is_native_ndms_iface",
                               return_value=True), \
             mock.patch("core.routing.ndms_backend.apply_domain_rule",
                        return_value={"ok": True, "backend": "ndms"}) as f:
            res = domain_rule.apply_domain_rule(rule)
        f.assert_called_once()
        self.assertEqual(res.get("backend"), "ndms")


class TestRemoveDomainViaIproute(unittest.TestCase):

    def test_removes_tracked_rules(self):
        rule = _rule()
        runs = []

        def fake_run(args, **kw):
            runs.append(list(args))
            return mock.Mock(returncode=0, stderr="", stdout="")

        state = {"uni-x": [["1.2.3.4/32", "-4"]]}
        with mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value=dict(state)), \
             mock.patch.object(domain_rule, "_iproute_state_save") as save, \
             mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch("core.routing.masquerade.remove_if_unused"):
            res = domain_rule._remove_domain_via_iproute(rule)

        self.assertTrue(res["ok"])
        self.assertEqual(res["removed"], 1)
        self.assertTrue(any("del" in a and "1.2.3.4/32" in a for a in runs))
        save.assert_called()


class TestGeoExpansionAndStaticCidrs(unittest.TestCase):
    """
    geosite → домены, geoip → CIDR в interval-set (nft). Проверяем
    разбор алиасов и раскладку geoip-CIDR по семействам одним набором
    (без тысяч `ip rule`).
    """

    def test_expand_rule_splits_domains_and_cidrs(self):
        rule = DomainRoutingRule(target_iface="awg0",
                                 domains=["a.com", "geosite:x", "geoip:y"],
                                 rule_id="u")
        with mock.patch(
            "core.routing.alias_resolver.expand_domains",
            return_value={"domains": ["a.com", "z.com"],
                          "cidrs": ["1.2.3.0/24", "2001:db8::/32"]}):
            domains, cidrs = domain_rule._expand_rule(rule)
        self.assertEqual(domains, ["a.com", "z.com"])
        self.assertEqual(cidrs, ["1.2.3.0/24", "2001:db8::/32"])

    def test_static_cidrs_go_to_nftset_by_family(self):
        from core.routing import nftset_backend
        cmds = []

        def fake_run(args, **kw):
            cmds.append(list(args))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            added = domain_rule._add_static_cidrs_to_sets(
                ["1.2.3.0/24", "2001:db8::/32", "10.0.0.0/8"],
                "set4", "set6", nftset_backend)
        self.assertEqual(added, 3)
        adds = [" ".join(c) for c in cmds if "add" in c and "element" in c]
        v4 = [a for a in adds if "set4" in a][0]
        v6 = [a for a in adds if "set6" in a][0]
        self.assertIn("1.2.3.0/24", v4)
        self.assertIn("10.0.0.0/8", v4)
        self.assertIn("2001:db8::/32", v6)

    def test_static_cidrs_skipped_on_ipset_backend(self):
        from core.routing import ipset_backend
        # ipset hash:ip не хранит сети — geoip-CIDR пропускаются (0 added).
        with mock.patch("subprocess.run") as run:
            added = domain_rule._add_static_cidrs_to_sets(
                ["1.2.3.0/24"], "s4", "s6", ipset_backend)
        self.assertEqual(added, 0)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
