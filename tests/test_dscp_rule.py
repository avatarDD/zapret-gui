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


class TestNftDscpMatch(unittest.TestCase):
    """
    Регрессия идемпотентности nft-DSCP: nft нормализует и DSCP (0x2e→ef),
    и метку (917→0x00000395), поэтому сравнение нашего текста фрагмента с
    выводом nft НИКОГДА не совпадало → дубликаты копились на каждом apply,
    а remove не находил правило. Сопоставление теперь семантическое.
    """

    def test_parse_nft_dscp_symbolic(self):
        self.assertEqual(dscp_rule._parse_nft_dscp("ef"), 46)
        self.assertEqual(dscp_rule._parse_nft_dscp("cs0"), 0)
        self.assertEqual(dscp_rule._parse_nft_dscp("af41"), 34)

    def test_parse_nft_dscp_numeric(self):
        self.assertEqual(dscp_rule._parse_nft_dscp("0x2e"), 46)
        self.assertEqual(dscp_rule._parse_nft_dscp("46"), 46)
        self.assertIsNone(dscp_rule._parse_nft_dscp("garbage"))

    def test_find_handles_matches_nft_canonical_form(self):
        # как nft реально печатает наше правило (ef + hex-метка)
        canned = (
            "table inet awg_routing {\n"
            "\tchain prerouting { # handle 1\n"
            "\t\ttype filter hook prerouting priority mangle; policy accept;\n"
            "\t\tip dscp ef meta mark set 0x00000395 # handle 11\n"
            "\t\tip dscp cs1 meta mark set 0x00000395 # handle 12\n"
            "\t}\n}\n"
        )
        orig = dscp_rule._run
        dscp_rule._run = lambda *a, **k: (0, canned, "")
        try:
            # dscp=46 (ef), mark=917 (0x395) → находим handle 11, НЕ 12
            handles = dscp_rule._find_nft_dscp_handles(
                "awg_routing", "prerouting", 46, 917)
            self.assertEqual(handles, ["11"])
            # cs1 = dscp 8 → handle 12
            self.assertEqual(
                dscp_rule._find_nft_dscp_handles(
                    "awg_routing", "prerouting", 8, 917),
                ["12"])
            # несуществующая метка → ничего
            self.assertEqual(
                dscp_rule._find_nft_dscp_handles(
                    "awg_routing", "prerouting", 46, 100),
                [])
        finally:
            dscp_rule._run = orig


if __name__ == "__main__":
    unittest.main()
