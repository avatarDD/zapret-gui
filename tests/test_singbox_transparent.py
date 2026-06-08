# tests/test_singbox_transparent.py
"""
Unit-тесты для core/singbox_transparent.py (чистые builder'ы) и
генератора прозрачных inbound'ов в core/singbox_config.py.

Проверяем только чистую логику построения argv — без запуска
iptables (его нет в CI и он требует рута).
"""

import unittest
from unittest import mock

from core import singbox_transparent as tp
from core.singbox_config import (
    make_transparent_inbounds, set_transparent_inbounds, make_sniff_rule,
    make_hijack_dns_rule,
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
        # КАЖДОЕ правило идёт в таблицу nat (иначе -A уходит в filter, где
        # нашей цепочки нет → «No chain/target/match by that name»).
        self.assertTrue(all("-t nat -A " in r for r in flat), flat)

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
        # КАЖДОЕ правило идёт в таблицу mangle (TPROXY живёт только там,
        # и цепочка SBT_TP_PRE создаётся именно в mangle).
        self.assertTrue(all("-t mangle -A " in r for r in flat), flat)

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
        self.assertTrue(all("-t mangle -A " in r for r in flat), flat)

    def test_redirect_dns(self):
        rules = tp.build_dns_hijack_rules(
            family="v4", dns_port=1053, via="redirect")
        flat = _flat(rules)
        self.assertTrue(any("--dport 53 -j REDIRECT --to-ports 1053" in r
                            for r in flat))
        self.assertTrue(all("-t nat -A " in r for r in flat), flat)


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

    def test_inbounds_carry_no_legacy_sniff(self):
        # sing-box 1.13 удалил legacy inbound-поля; sniff не должен
        # оказаться в inbound'е ни при каком значении флага.
        for s in (True, False):
            ibs = make_transparent_inbounds(mode="tproxy", sniff=s)
            for ib in ibs:
                self.assertNotIn("sniff", ib)
                self.assertNotIn("sniff_override_destination", ib)
                self.assertNotIn("domain_strategy", ib)


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

    def test_sniff_added_as_route_action(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", tcp_port=1100,
                                 sniff=True)
        rules = cfg["route"]["rules"]
        self.assertEqual(rules[0], make_sniff_rule())
        # и в самих inbound'ах никаких legacy-полей sniff
        for ib in cfg["inbounds"]:
            self.assertNotIn("sniff", ib)

    def test_sniff_route_action_idempotent(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", sniff=True)
        set_transparent_inbounds(cfg, mode="tproxy", sniff=True)
        sniffs = [r for r in cfg["route"]["rules"]
                  if r.get("action") == "sniff"]
        self.assertEqual(len(sniffs), 1)        # не дублируется

    def test_sniff_false_removes_route_action(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", sniff=True)
        set_transparent_inbounds(cfg, mode="tproxy", sniff=False)
        sniffs = [r for r in cfg["route"].get("rules", [])
                  if r.get("action") == "sniff"]
        self.assertEqual(len(sniffs), 0)

    def test_sniff_preserves_user_route_rules(self):
        cfg = {"outbounds": [],
               "route": {"rules": [{"domain": ["x.com"], "outbound": "o"}]}}
        set_transparent_inbounds(cfg, mode="tproxy", sniff=True)
        actions = [r.get("action") for r in cfg["route"]["rules"]]
        self.assertIn("sniff", actions)
        # пользовательское правило не потеряно
        self.assertTrue(any(r.get("domain") == ["x.com"]
                            for r in cfg["route"]["rules"]))

    def test_dns_hijack_adds_route_action_after_sniff(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", tcp_port=1100,
                                 dns_port=1053, sniff=True)
        rules = cfg["route"]["rules"]
        self.assertIn(make_hijack_dns_rule(), rules)
        # порядок: sniff раньше hijack-dns (иначе протокол DNS не распознан)
        self.assertLess(rules.index(make_sniff_rule()),
                        rules.index(make_hijack_dns_rule()))

    def test_dns_hijack_forces_sniff(self):
        # hijack-dns требует sniff — даже если sniff=False, он появится.
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", dns_port=1053,
                                 sniff=False)
        self.assertIn(make_sniff_rule(), cfg["route"]["rules"])
        self.assertIn(make_hijack_dns_rule(), cfg["route"]["rules"])

    def test_no_dns_hijack_no_rule(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", dns_port=0, sniff=True)
        self.assertNotIn(make_hijack_dns_rule(), cfg["route"]["rules"])

    def test_dns_hijack_idempotent_and_removable(self):
        cfg = {"outbounds": []}
        set_transparent_inbounds(cfg, mode="tproxy", dns_port=1053)
        set_transparent_inbounds(cfg, mode="tproxy", dns_port=1053)
        hits = [r for r in cfg["route"]["rules"]
                if r == make_hijack_dns_rule()]
        self.assertEqual(len(hits), 1)                 # не дублируется
        # выключение DNS-hijack снимает правило
        set_transparent_inbounds(cfg, mode="tproxy", dns_port=0)
        self.assertNotIn(make_hijack_dns_rule(), cfg["route"]["rules"])


class TestReapplySaved(unittest.TestCase):

    def test_noop_when_no_settings(self):
        fake_cfg = mock.Mock()
        fake_cfg.get.return_value = {}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=fake_cfg):
            r = tp.reapply_saved()
        self.assertTrue(r["ok"])
        self.assertTrue(r.get("noop"))

    def test_calls_apply_with_saved(self):
        fake_cfg = mock.Mock()
        fake_cfg.get.return_value = {
            "mode": "tproxy", "tcp_port": 1100, "families": ["v4"],
            "bogus_key": "ignored",
        }
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=fake_cfg), \
             mock.patch.object(tp, "apply",
                               return_value={"ok": True}) as m:
            r = tp.reapply_saved()
        self.assertTrue(r["ok"])
        m.assert_called_once()
        kwargs = m.call_args.kwargs
        self.assertEqual(kwargs["mode"], "tproxy")
        self.assertEqual(kwargs["families"], ("v4",))
        self.assertNotIn("bogus_key", kwargs)


if __name__ == "__main__":
    unittest.main()
