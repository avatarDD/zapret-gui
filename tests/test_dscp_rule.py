# tests/test_dscp_rule.py
"""
Unit-тесты для DSCP-routing: модель DscpRoutingRule (rules.py) и
чистый builder в core/routing/dscp_rule.py.
"""

import unittest

from core.routing.rules import DscpRoutingRule, rule_from_dict
from core.routing import dscp_rule


class TestDscpRule(unittest.TestCase):

    def test_basic(self):
        r = DscpRoutingRule(target_iface="awg0", dscp=46)
        self.assertEqual(r.dscp, 46)
        self.assertEqual(r.type_name, "dscp")
        self.assertFalse(r.proxy_self)

    def test_proxy_self(self):
        r = DscpRoutingRule(target_iface="awg0", dscp=10, proxy_self=True)
        self.assertTrue(r.proxy_self)

    def test_dscp_out_of_range(self):
        with self.assertRaises(ValueError):
            DscpRoutingRule(target_iface="awg0", dscp=64)
        with self.assertRaises(ValueError):
            DscpRoutingRule(target_iface="awg0", dscp=-1)

    def test_dscp_non_numeric(self):
        with self.assertRaises(ValueError):
            DscpRoutingRule(target_iface="awg0", dscp="ef")

    def test_roundtrip_dict(self):
        r = DscpRoutingRule(target_iface="warp1", dscp=26, proxy_self=True,
                            description="streaming")
        d = r.to_dict()
        self.assertEqual(d["type"], "dscp")
        self.assertEqual(d["dscp"], 26)
        self.assertTrue(d["proxy_self"])
        r2 = rule_from_dict(d)
        self.assertIsInstance(r2, DscpRoutingRule)
        self.assertEqual(r2.dscp, 26)
        self.assertEqual(r2.target_iface, "warp1")
        self.assertTrue(r2.proxy_self)


class TestDscpBuilder(unittest.TestCase):

    def test_build_mark_rules(self):
        rules = dscp_rule.build_mark_rules("DSCP_ROUTING_PRE", 46, 123)
        self.assertEqual(len(rules), 1)
        argv = rules[0]
        joined = " ".join(argv)
        self.assertIn("-m dscp --dscp 46", joined)
        self.assertIn("-j MARK --set-mark 123", joined)
        self.assertIn("DSCP_ROUTING_PRE", joined)
        self.assertEqual(argv[0], "iptables")
        # позиция операции -A — индекс 3 (используется для -D в remove)
        self.assertEqual(argv[3], "-A")


if __name__ == "__main__":
    unittest.main()


class TestNftDscpFragment(unittest.TestCase):

    def test_fragment(self):
        frag = dscp_rule.build_nft_dscp_fragment(46, 123)
        self.assertEqual(frag, "ip dscp 0x2e meta mark set 123")

    def test_fragment_zero(self):
        self.assertEqual(dscp_rule.build_nft_dscp_fragment(0, 5),
                         "ip dscp 0x00 meta mark set 5")
