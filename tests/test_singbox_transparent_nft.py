# tests/test_singbox_transparent_nft.py
"""Unit-тесты для nft-builder'ов прозрачного проксирования."""

import unittest

from core import singbox_transparent_nft as nft


class TestRedirectFragments(unittest.TestCase):

    def test_basic(self):
        f = nft.build_redirect_fragments(family="v4", tcp_port=1100)
        pre = f["prerouting"]
        self.assertTrue(any("redirect to :1100" in r for r in pre))
        self.assertTrue(any("ip daddr {" in r and "return" in r for r in pre))
        self.assertEqual(f["output"], [])

    def test_lan_ifaces(self):
        f = nft.build_redirect_fragments(
            family="v4", tcp_port=1100, lan_ifaces=["br0"])
        self.assertTrue(any('iifname "br0" meta l4proto tcp redirect to :1100' in r
                            for r in f["prerouting"]))

    def test_proxy_self_output(self):
        f = nft.build_redirect_fragments(
            family="v4", tcp_port=1100, proxy_self=True)
        self.assertTrue(f["output"])
        self.assertTrue(any("meta mark 1 return" in r for r in f["output"]))

    def test_v6_daddr(self):
        f = nft.build_redirect_fragments(family="v6", tcp_port=1100)
        self.assertTrue(any("ip6 daddr" in r for r in f["prerouting"]))


class TestTproxyFragments(unittest.TestCase):

    def test_tcp_udp(self):
        f = nft.build_tproxy_fragments(family="v4", port=1100)
        pre = f["prerouting"]
        self.assertTrue(any("tproxy ip to :1100" in r for r in pre))
        self.assertTrue(any("{ tcp, udp }" in r for r in pre))
        self.assertTrue(any("meta mark set 1" in r for r in pre))

    def test_udp_only_hybrid(self):
        f = nft.build_tproxy_fragments(
            family="v4", port=1102, protocols=("udp",))
        self.assertTrue(any("{ udp }" in r for r in f["prerouting"]))

    def test_v6_tproxy_ip6(self):
        f = nft.build_tproxy_fragments(family="v6", port=1100)
        self.assertTrue(any("tproxy ip6 to :1100" in r for r in f["prerouting"]))

    def test_proxy_self_marks(self):
        f = nft.build_tproxy_fragments(
            family="v4", port=1100, proxy_self=True)
        self.assertTrue(any("meta mark set 1" in r for r in f["output"]))
        self.assertTrue(any("meta mark 1 return" in r for r in f["output"]))

    def test_custom_mark(self):
        f = nft.build_tproxy_fragments(family="v4", port=1100, mark=7)
        self.assertTrue(any("meta mark set 7" in r for r in f["prerouting"]))

    def test_server_bypass(self):
        f = nft.build_tproxy_fragments(
            family="v4", port=1100, server_ips=["1.2.3.4"])
        self.assertTrue(any("ip daddr 1.2.3.4 return" in r
                            for r in f["prerouting"]))


class TestNftAddRule(unittest.TestCase):

    def test_prefix(self):
        argv = nft._nft_add_rule("pretp", "meta mark set 1")
        self.assertEqual(argv[:6],
                         ["nft", "add", "rule", "inet", "sbtproxy", "pretp"])


if __name__ == "__main__":
    unittest.main()
