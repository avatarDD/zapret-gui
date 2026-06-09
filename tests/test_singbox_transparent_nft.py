# tests/test_singbox_transparent_nft.py
"""Unit-тесты для nft-builder'ов прозрачного проксирования."""

import unittest
from unittest import mock

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


class TestDnsHijackFragments(unittest.TestCase):

    def test_via_tproxy(self):
        frags = nft.build_dns_hijack_fragments(
            family="v4", dns_port=1053, via="tproxy")
        self.assertTrue(any("th dport 53" in f for f in frags))
        self.assertTrue(any("tproxy ip to :1053" in f for f in frags))
        self.assertTrue(any("{ tcp, udp }" in f for f in frags))

    def test_via_redirect(self):
        frags = nft.build_dns_hijack_fragments(
            family="v4", dns_port=1053, via="redirect")
        self.assertTrue(any("redirect to :1053" in f for f in frags))
        self.assertTrue(all("tproxy" not in f for f in frags))

    def test_lan_ifaces_per_iface(self):
        frags = nft.build_dns_hijack_fragments(
            family="v4", dns_port=1053, lan_ifaces=["br0", "br1"])
        self.assertEqual(len(frags), 2)
        self.assertTrue(all(f.startswith('iifname "br') for f in frags))

    def test_v6_uses_ip6(self):
        frags = nft.build_dns_hijack_fragments(
            family="v6", dns_port=1053, via="tproxy")
        self.assertTrue(any("tproxy ip6 to :1053" in f for f in frags))


class TestIpv6BlockFragment(unittest.TestCase):

    def test_fragment(self):
        self.assertEqual(nft.build_ipv6_block_fragment(),
                         "meta nfproto ipv6 drop")


class TestNftApplyWiring(unittest.TestCase):
    """apply() через мок _run (без рута): DNS-hijack и IPv6-drop должны
    доезжать до нужных цепочек."""

    def _run_apply(self, **kw):
        cmds = []

        def fake(args, timeout=10):
            cmds.append(" ".join(args))
            return (0, "", "")

        with mock.patch.object(nft, "_run", fake), \
             mock.patch.object(nft, "available", lambda: True):
            res = nft.apply(**kw)
        return res, cmds

    def test_dns_redirect_goes_to_nat_chain(self):
        res, cmds = self._run_apply(mode="redirect", tcp_port=1100,
                                    dns_hijack_port=1053, families=("v4",))
        self.assertTrue(res["ok"])
        self.assertTrue(any("rule inet sbtproxy predr" in c
                            and "th dport 53" in c
                            and "redirect to :1053" in c for c in cmds))

    def test_dns_tproxy_goes_to_mangle_chain(self):
        res, cmds = self._run_apply(mode="tproxy", tcp_port=1100,
                                    dns_hijack_port=1053, families=("v4",))
        self.assertTrue(any("rule inet sbtproxy pretp" in c
                            and "th dport 53" in c and "tproxy" in c
                            for c in cmds))

    def test_ipv6_drop_created_when_policy_drop(self):
        res, cmds = self._run_apply(mode="tproxy", tcp_port=1100,
                                    families=("v4",), ipv6_policy="drop")
        self.assertTrue(any("chain inet sbtproxy fwd6" in c for c in cmds))
        self.assertTrue(any("rule inet sbtproxy fwd6" in c
                            and "meta nfproto ipv6 drop" in c for c in cmds))

    def test_no_ipv6_drop_when_allow(self):
        _res, cmds = self._run_apply(mode="tproxy", tcp_port=1100,
                                     families=("v4",), ipv6_policy="allow")
        self.assertFalse(any("fwd6" in c for c in cmds))

    def test_no_ipv6_drop_when_v6_proxied(self):
        _res, cmds = self._run_apply(mode="tproxy", tcp_port=1100,
                                     families=("v4", "v6"), ipv6_policy="drop")
        self.assertFalse(any("fwd6" in c for c in cmds))


if __name__ == "__main__":
    unittest.main()
