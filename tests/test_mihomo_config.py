# tests/test_mihomo_config.py
"""
Тесты чистых билдеров clash-YAML для маршрутизации mihomo
(core/mihomo_config.py): структура tun/dns/rules/external-controller, режимы
(домены/source-IP/весь трафик), fake-ip-filter, QUIC, round-trip через
dump_yaml/parse_yaml.
"""

import unittest

from core import mihomo_config as mc
from core.clash_yaml import dump_yaml, parse_yaml


def _vless():
    return {"name": "srv-1", "type": "vless", "server": "vpn.example.com",
            "port": 443, "uuid": "u-1", "tls": True,
            "servername": "vpn.example.com"}


def _ss_ip():
    return {"name": "ss-2", "type": "ss", "server": "1.2.3.4", "port": 8388,
            "cipher": "aes-128-gcm", "password": "p"}


class TestHelpers(unittest.TestCase):

    def test_norm_suffix(self):
        out = mc._norm_suffix_domains(
            ["WWW.YouTube.com", "*.youtube.com", "+.youtube.com",
             "https://x.org/path", "youtube.com", "127.0.0.1", "localhost", ""])
        self.assertIn("youtube.com", out)
        self.assertIn("x.org", out)
        self.assertNotIn("localhost", out)
        self.assertNotIn("127.0.0.1", out)
        self.assertEqual(out.count("youtube.com"), 1)

    def test_norm_src_cidr(self):
        self.assertEqual(mc._norm_src_cidr("192.168.1.5"), "192.168.1.5/32")
        self.assertEqual(mc._norm_src_cidr("10.0.0.0/8"), "10.0.0.0/8")
        self.assertEqual(mc._norm_src_cidr("fe80::1"), "fe80::1/128")

    def test_collect_proxy_domains(self):
        doms = mc.collect_proxy_server_domains([_vless(), _ss_ip()])
        self.assertEqual(doms, ["vpn.example.com"])     # IP-сервер отброшен


class TestTun(unittest.TestCase):

    def test_defaults(self):
        tun = mc.make_tun()
        self.assertTrue(tun["enable"])
        self.assertEqual(tun["mtu"], 1500)              # не 9000
        self.assertTrue(tun["auto-route"])
        self.assertFalse(tun["strict-route"])           # не лочим роутер
        self.assertEqual(tun["dns-hijack"], ["any:53"])
        self.assertNotIn("auto-redirect", tun)

    def test_auto_redirect_only_with_auto_route(self):
        self.assertIn("auto-redirect",
                      mc.make_tun(auto_route=True, auto_redirect=True))
        self.assertNotIn("auto-redirect",
                         mc.make_tun(auto_route=False, auto_redirect=True))

    def test_device_clamped(self):
        self.assertEqual(len(mc.make_tun(device="x" * 40)["device"]), 15)


class TestFakeipDns(unittest.TestCase):

    def test_structure(self):
        dns = mc.make_fakeip_dns(proxy_server_domains=[_vless()])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")
        self.assertEqual(dns["fake-ip-range"], mc.FAKEIP_RANGE)
        self.assertFalse(dns["ipv6"])
        # домен прокси-сервера исключён из fake-ip (резолв напрямую, без петли)
        self.assertIn("vpn.example.com", dns["fake-ip-filter"])
        # DoH — ПО ИМЕНИ ХОСТА (IP-литерал валит проверку TLS-сертификата),
        # с обычным UDP-бутстрапом в default-nameserver.
        self.assertEqual(dns["nameserver"], mc.DEFAULT_DOH_SERVERS)
        self.assertEqual(dns["proxy-server-nameserver"], mc.DEFAULT_DOH_SERVERS)
        self.assertTrue(all(s.startswith("https://") for s in dns["nameserver"]))
        self.assertFalse(any("//1.1.1.1/" in s or "//8.8.8.8/" in s
                             for s in dns["nameserver"]))   # не IP-литерал
        self.assertEqual(dns["default-nameserver"], mc.DEFAULT_BOOTSTRAP)


class TestDomainConfig(unittest.TestCase):

    def test_selective_ruleset(self):
        cfg = mc.build_domain_config(
            proxies=[_vless()], proxied_domains=["youtube.com", "x.com"],
            proxied_cidrs=["203.0.113.0/24"], controller_port=9090,
            controller_secret="sek")
        # round-trip YAML
        self.assertEqual(parse_yaml(dump_yaml(cfg)), cfg)
        # external-controller + secret
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9090")
        self.assertEqual(cfg["secret"], "sek")
        # tun gvisor (доменный режим)
        self.assertEqual(cfg["tun"]["stack"], "gvisor")
        # rule-provider inline c доменами и RULE-SET-правилом
        rp = cfg["rule-providers"][mc.DEFAULT_RULESET]
        self.assertEqual(rp["type"], "inline")
        self.assertEqual(rp["behavior"], "domain")
        self.assertIn("+.youtube.com", rp["payload"])
        rules = cfg["rules"]
        self.assertIn("RULE-SET,proxied,PROXY", rules)
        # подсети — через ipcidr rule-provider (RULE-SET ... no-resolve)
        ipp = cfg["rule-providers"][mc.DEFAULT_IP_RULESET]
        self.assertEqual(ipp["behavior"], "ipcidr")
        self.assertIn("203.0.113.0/24", ipp["payload"])
        self.assertIn("RULE-SET,proxied-ip,PROXY,no-resolve", rules)
        self.assertEqual(rules[-1], "MATCH,DIRECT")
        # приватные подсети — направлены в DIRECT и ДО проксирующих правил
        self.assertTrue(any(r.startswith("IP-CIDR,192.168.0.0/16,DIRECT")
                            for r in rules))
        # proxy-group select со ссылкой на узел
        grp = cfg["proxy-groups"][0]
        self.assertEqual(grp["name"], "PROXY")
        self.assertEqual(grp["type"], "select")
        self.assertEqual(grp["proxies"], ["srv-1"])

    def test_use_ruleset_false_inlines_domain_suffix(self):
        cfg = mc.build_domain_config(
            proxies=[_vless()], proxied_domains=["youtube.com"],
            proxied_cidrs=["203.0.113.0/24"], use_ruleset=False)
        self.assertNotIn("rule-providers", cfg)
        self.assertIn("DOMAIN-SUFFIX,youtube.com,PROXY", cfg["rules"])
        self.assertIn("IP-CIDR,203.0.113.0/24,PROXY,no-resolve", cfg["rules"])

    def test_cidr_normalized_to_mask(self):
        # голый IP → /32 в ipcidr-провайдере
        cfg = mc.build_domain_config(proxies=[_vless()],
                                     proxied_cidrs=["8.8.8.8", "2001:db8::1"])
        payload = cfg["rule-providers"][mc.DEFAULT_IP_RULESET]["payload"]
        self.assertIn("8.8.8.8/32", payload)
        self.assertIn("2001:db8::1/128", payload)

    def test_ipcidr_only_no_domains(self):
        # только подсети (напр. geoip/ipset), без доменов
        cfg = mc.build_domain_config(proxies=[_vless()],
                                     proxied_cidrs=["203.0.113.0/24"])
        self.assertIn(mc.DEFAULT_IP_RULESET, cfg["rule-providers"])
        self.assertNotIn(mc.DEFAULT_RULESET, cfg["rule-providers"])
        self.assertIn("RULE-SET,proxied-ip,PROXY,no-resolve", cfg["rules"])

    def test_route_all(self):
        cfg = mc.build_domain_config(proxies=[_vless()], route_all=True)
        self.assertNotIn("rule-providers", cfg)
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")
        # приватное всё равно остаётся DIRECT
        self.assertTrue(any("DIRECT" in r for r in cfg["rules"][:-1]))

    def test_reject_quic_opt_in(self):
        off = mc.build_domain_config(proxies=[_vless()], route_all=True)
        self.assertFalse(any("REJECT" in r for r in off["rules"]))
        on = mc.build_domain_config(proxies=[_vless()], route_all=True,
                                    reject_quic=True)
        self.assertIn(mc.quic_reject_rule(), on["rules"])

    def test_requires_proxy(self):
        with self.assertRaises(ValueError):
            mc.build_domain_config(proxies=[], proxied_domains=["x.com"])


class TestSourceConfig(unittest.TestCase):

    def test_selective_source(self):
        cfg = mc.build_source_config(
            proxies=[_vless()], source_ips=["192.168.1.117", "192.168.1.84"],
            controller_port=9091)
        self.assertEqual(parse_yaml(dump_yaml(cfg)), cfg)
        self.assertEqual(cfg["tun"]["stack"], "system")       # kernel, low-CPU
        rules = cfg["rules"]
        self.assertIn("SRC-IP-CIDR,192.168.1.117/32,PROXY", rules)
        self.assertIn("SRC-IP-CIDR,192.168.1.84/32,PROXY", rules)
        self.assertEqual(rules[-1], "MATCH,DIRECT")

    def test_route_all_source(self):
        cfg = mc.build_source_config(proxies=[_vless()], route_all=True)
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")


class TestIntrospection(unittest.TestCase):

    def test_active_group_and_device(self):
        cfg = mc.build_domain_config(proxies=[_vless()], route_all=True,
                                     device="mihomo-tun")
        self.assertEqual(mc.active_proxy_group(cfg), "PROXY")
        self.assertEqual(mc.find_tun_device(cfg), "mihomo-tun")

    def test_no_group_no_tun(self):
        self.assertEqual(mc.active_proxy_group({}), "")
        self.assertEqual(mc.find_tun_device({}), "")


if __name__ == "__main__":
    unittest.main()
