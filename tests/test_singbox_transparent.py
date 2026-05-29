# tests/test_singbox_transparent.py
"""
Unit-тесты для core/singbox_transparent.py (чистые builder'ы) и
генератора прозрачных inbound'ов в core/singbox_config.py.

Проверяем только чистую логику построения argv — без запуска
iptables (его нет в CI и он требует рута).
"""

import unittest

from core import singbox_transparent as tp
from core.singbox_config import (
    make_transparent_inbounds, set_transparent_inbounds,
)


def _flat(rules):
    """Список argv → список строк-команд для удобного поиска подстрок."""
    return [" ".join(r) for r in rules]


class TestRedirectBuilder(unittest.TestCase):

    def test_basic_tcp_redirect(self):
        rules = tp.build_redirect_rules(family="v4", tcp_port=1100)
        flat = _flat(rules)
        # есть REDIRECT на нужный порт
        self.assertTrue(any("REDIRECT --to-ports 1100" in r for r in flat))
        # bypass приватных сетей присутствует
        self.assertTrue(any("192.168.0.0/16 -j RETURN" in r for r in flat))
        # всё через iptables (v4)
        self.assertTrue(all(r.startswith("iptables") for r in flat))

    def test_server_ip_excluded(self):
        rules = tp.build_redirect_rules(
            family="v4", tcp_port=1100, server_ips=["1.2.3.4"])
        flat = _flat(rules)
        self.assertTrue(any("-d 1.2.3.4 -j RETURN" in r for r in flat))

    def test_lan_ifaces_scope(self):
        rules = tp.build_redirect_rules(
            family="v4", tcp_port=1100, lan_ifaces=["br0", "br-lan"])
        flat = _flat(rules)
        self.assertTrue(any("-i br0 -p tcp" in r for r in flat))
        self.assertTrue(any("-i br-lan -p tcp" in r for r in flat))

    def test_proxy_self_adds_output(self):
        rules = tp.build_redirect_rules(
            family="v4", tcp_port=1100, proxy_self=True)
        flat = _flat(rules)
        self.assertTrue(any(tp.NAT_OUT in r for r in flat))
        # mark-RETURN чтобы не зациклить движок
        self.assertTrue(any("--mark 1 -j RETURN" in r for r in flat))

    def test_v6_uses_ip6tables(self):
        rules = tp.build_redirect_rules(family="v6", tcp_port=1100)
        flat = _flat(rules)
        self.assertTrue(all(r.startswith("ip6tables") for r in flat))
        self.assertTrue(any("::1/128 -j RETURN" in r for r in flat))


class TestTproxyBuilder(unittest.TestCase):

    def test_tcp_and_udp(self):
        rules = tp.build_tproxy_rules(family="v4", port=1100)
        flat = _flat(rules)
        self.assertTrue(any("-p tcp -j TPROXY --on-port 1100" in r
                            for r in flat))
        self.assertTrue(any("-p udp -j TPROXY --on-port 1100" in r
                            for r in flat))
        self.assertTrue(any("--tproxy-mark 1" in r for r in flat))

    def test_protocols_filter(self):
        rules = tp.build_tproxy_rules(
            family="v4", port=1100, protocols=("udp",))
        flat = _flat(rules)
        self.assertFalse(any("-p tcp -j TPROXY" in r for r in flat))
        self.assertTrue(any("-p udp -j TPROXY" in r for r in flat))

    def test_proxy_self_marks_output(self):
        rules = tp.build_tproxy_rules(
            family="v4", port=1100, proxy_self=True)
        flat = _flat(rules)
        self.assertTrue(any(tp.MANGLE_OUT in r and "MARK --set-mark 1" in r
                            for r in flat))

    def test_custom_mark(self):
        rules = tp.build_tproxy_rules(family="v4", port=1100, mark=99)
        flat = _flat(rules)
        self.assertTrue(any("--tproxy-mark 99" in r for r in flat))


class TestDnsHijackBuilder(unittest.TestCase):

    def test_tproxy_dns(self):
        rules = tp.build_dns_hijack_rules(
            family="v4", dns_port=1053, via="tproxy")
        flat = _flat(rules)
        self.assertTrue(any("--dport 53 -j TPROXY --on-port 1053" in r
                            for r in flat))
        # и udp и tcp
        self.assertTrue(any("-p udp --dport 53" in r for r in flat))
        self.assertTrue(any("-p tcp --dport 53" in r for r in flat))

    def test_redirect_dns(self):
        rules = tp.build_dns_hijack_rules(
            family="v4", dns_port=1053, via="redirect")
        flat = _flat(rules)
        self.assertTrue(any("--dport 53 -j REDIRECT --to-ports 1053" in r
                            for r in flat))


class TestIpv6Block(unittest.TestCase):

    def test_block_forward(self):
        rules = tp.build_ipv6_block_rules()
        flat = _flat(rules)
        self.assertTrue(all(r.startswith("ip6tables") for r in flat))
        self.assertTrue(any("FORWARD -j DROP" in r for r in flat))


class TestTransparentInbounds(unittest.TestCase):

    def test_redirect_mode(self):
        ibs = make_transparent_inbounds(mode="redirect", tcp_port=1100)
        self.assertEqual(len(ibs), 1)
        self.assertEqual(ibs[0]["type"], "redirect")
        self.assertEqual(ibs[0]["listen_port"], 1100)

    def test_tproxy_mode(self):
        ibs = make_transparent_inbounds(mode="tproxy", tcp_port=1100)
        self.assertEqual(len(ibs), 1)
        self.assertEqual(ibs[0]["type"], "tproxy")

    def test_hybrid_mode_two_inbounds(self):
        ibs = make_transparent_inbounds(
            mode="hybrid", tcp_port=1100, udp_port=1102)
        types = {ib["type"] for ib in ibs}
        self.assertEqual(types, {"redirect", "tproxy"})
        tproxy = [ib for ib in ibs if ib["type"] == "tproxy"][0]
        self.assertEqual(tproxy["listen_port"], 1102)
        self.assertEqual(tproxy["network"], "udp")

    def test_dns_inbound(self):
        ibs = make_transparent_inbounds(
            mode="tproxy", tcp_port=1100, dns_port=1053)
        dns = [ib for ib in ibs if ib["tag"] == "dns-in"]
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]["listen_port"], 1053)

    def test_sniff_toggle(self):
        with_sniff = make_transparent_inbounds(mode="tproxy", sniff=True)
        without = make_transparent_inbounds(mode="tproxy", sniff=False)
        self.assertIn("sniff", with_sniff[0])
        self.assertNotIn("sniff", without[0])


class TestSetTransparentInbounds(unittest.TestCase):

    def test_adds_and_preserves_user_inbounds(self):
        cfg = {"inbounds": [{"type": "mixed", "tag": "user-mixed"}],
               "outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", tcp_port=1100)
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertIn("tproxy-in", tags)
        self.assertIn("user-mixed", tags)

    def test_replaces_previous_transparent(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="redirect", tcp_port=1100)
        set_transparent_inbounds(cfg, mode="tproxy", tcp_port=1100)
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        # старый redirect-in должен быть вытеснен, не дублироваться
        self.assertEqual(tags.count("redirect-in"), 0)
        self.assertEqual(tags.count("tproxy-in"), 1)

    def test_hybrid_adds_both(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="hybrid",
                                 tcp_port=1100, udp_port=1102)
        tags = {ib["tag"] for ib in cfg["inbounds"]}
        self.assertIn("redirect-in", tags)
        self.assertIn("tproxy-in", tags)


if __name__ == "__main__":
    unittest.main()
