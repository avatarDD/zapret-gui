# tests/test_singbox_fakeip.py
"""FakeIP-роутинг: сборка конфига (core/singbox_config.build_fakeip_config).

Проверяем структуру (TUN auto_route, DNS с FakeIP, hijack-dns, domain/cidr
route-правила, cache_file), оба формата DNS (legacy/typed) и режим «весь
трафик», а также нормализацию доменов под domain_suffix.
"""

import json
import unittest

from core.singbox_config import (
    build_fakeip_config, make_fakeip_dns, _norm_suffix_domains,
    render_conf, parse_conf, validate, FAKEIP_INET4,
)


def _vless():
    return {"type": "vless", "tag": "myserver", "server": "1.2.3.4",
            "server_port": 443, "uuid": "u-1",
            "tls": {"enabled": True, "server_name": "ex.com"}}


class TestNormalizeSuffix(unittest.TestCase):
    def test_strips_and_dedups(self):
        out = _norm_suffix_domains(
            ["WWW.YouTube.com", "*.youtube.com", "https://x.org/path",
             "youtube.com", "localhost", "127.0.0.1", ""])
        self.assertIn("youtube.com", out)
        self.assertIn("x.org", out)
        self.assertNotIn("localhost", out)
        self.assertNotIn("127.0.0.1", out)
        # www.youtube.com / *.youtube.com / youtube.com → один youtube.com
        self.assertEqual(out.count("youtube.com"), 1)


class TestFakeipDns(unittest.TestCase):
    def test_legacy_has_toplevel_fakeip(self):
        dns = make_fakeip_dns(proxied_domains=["youtube.com"],
                              direct_dns="local", typed=False, fakeip=True)
        self.assertIn("fakeip", dns)
        self.assertEqual(dns["fakeip"]["inet4_range"], FAKEIP_INET4)
        tags = {s["tag"]: s for s in dns["servers"]}
        self.assertEqual(tags["dns-fakeip"]["address"], "fakeip")
        self.assertEqual(tags["dns-direct"]["address"], "local")
        self.assertEqual(dns["rules"][0]["server"], "dns-fakeip")

    def test_typed_uses_type_field(self):
        dns = make_fakeip_dns(proxied_domains=["youtube.com"],
                              direct_dns="local", typed=True, fakeip=True)
        self.assertNotIn("fakeip", dns)        # нет top-level в typed
        tags = {s["tag"]: s for s in dns["servers"]}
        self.assertEqual(tags["dns-fakeip"]["type"], "fakeip")
        self.assertEqual(tags["dns-direct"]["type"], "local")

    def test_direct_ip_gets_udp_detour(self):
        dns = make_fakeip_dns(proxied_domains=["a.com"], direct_dns="8.8.8.8",
                              typed=False, fakeip=True)
        d = {s["tag"]: s for s in dns["servers"]}["dns-direct"]
        self.assertEqual(d["address"], "8.8.8.8")
        self.assertEqual(d["detour"], "direct")


class TestBuildFakeipConfig(unittest.TestCase):
    def test_selective_structure(self):
        cfg = build_fakeip_config(
            proxy_outbound=_vless(), proxied_domains=["youtube.com", "x.com"],
            proxied_cidrs=["203.0.113.0/24"], route_all=False)
        # JSON-валидно и проходит наш структурный валидатор
        self.assertEqual(parse_conf(render_conf(cfg)), cfg)
        self.assertEqual(validate(cfg), [])
        # TUN auto_route + strict_route
        tun = cfg["inbounds"][0]
        self.assertEqual(tun["type"], "tun")
        self.assertTrue(tun["auto_route"] and tun["strict_route"])
        # прокси-outbound переименован
        self.assertEqual(cfg["outbounds"][0]["tag"], "proxy-out")
        self.assertEqual(cfg["outbounds"][0]["type"], "vless")
        self.assertEqual(cfg["outbounds"][1], {"type": "direct",
                                               "tag": "direct"})
        # route: sniff, hijack-dns, private→direct, domain→proxy, cidr→proxy
        rules = cfg["route"]["rules"]
        self.assertEqual(rules[0], {"action": "sniff"})
        self.assertEqual(rules[1], {"protocol": "dns",
                                    "action": "hijack-dns"})
        self.assertTrue(any(r.get("ip_is_private") for r in rules))
        self.assertTrue(any(r.get("domain_suffix") and
                            r.get("outbound") == "proxy-out" for r in rules))
        self.assertTrue(any(r.get("ip_cidr") and
                            r.get("outbound") == "proxy-out" for r in rules))
        self.assertEqual(cfg["route"]["final"], "direct")
        # FakeIP включён + cache.store_fakeip
        self.assertIn("fakeip", cfg["dns"])
        self.assertTrue(cfg["experimental"]["cache_file"]["store_fakeip"])

    def test_route_all_disables_fakeip_and_routes_everything(self):
        cfg = build_fakeip_config(proxy_outbound=_vless(), route_all=True)
        self.assertEqual(cfg["route"]["final"], "proxy-out")
        self.assertNotIn("fakeip", cfg["dns"])      # FakeIP не нужен
        self.assertFalse(cfg["experimental"]["cache_file"]["store_fakeip"])
        # нет domain/cidr правил «в прокси» (всё идёт через final)
        for r in cfg["route"]["rules"]:
            if r.get("outbound") == "proxy-out":
                self.fail("в route_all не должно быть точечных proxy-правил")

    def test_auto_redirect_only_when_requested(self):
        off = build_fakeip_config(proxy_outbound=_vless(),
                                  proxied_domains=["a.com"])
        self.assertNotIn("auto_redirect", off["inbounds"][0])
        on = build_fakeip_config(proxy_outbound=_vless(),
                                 proxied_domains=["a.com"], auto_redirect=True)
        self.assertTrue(on["inbounds"][0]["auto_redirect"])

    def test_typed_dns_variant_valid_json(self):
        cfg = build_fakeip_config(proxy_outbound=_vless(),
                                  proxied_domains=["a.com"], typed_dns=True)
        self.assertEqual(parse_conf(render_conf(cfg)), cfg)
        tags = {s["tag"]: s for s in cfg["dns"]["servers"]}
        self.assertEqual(tags["dns-fakeip"]["type"], "fakeip")

    def test_bad_proxy_raises(self):
        with self.assertRaises(ValueError):
            build_fakeip_config(proxy_outbound={"no": "type"})


class _FakeMgr:
    def __init__(self, check_results):
        self._cr = list(check_results)
        self.saved = None

    def check_text(self, text):
        return self._cr.pop(0) if self._cr else {"ok": True}

    def save_config(self, name, text=""):
        self.saved = (name, text)
        return {"ok": True, "warnings": []}

    def list_configs(self):
        return []


class _FakeHM:
    def get_hostlist(self, name):
        return {"svc": ["youtube.com", "*.youtube.com"]}.get(name, [])

    def get_stats(self):
        return {"svc": {"count": 2}}

    def list_names(self):
        return ["svc"]


class _FakePlat:
    def supports_nftables(self):
        return False


class _FakeDet:
    def __init__(self, ver="1.13.0", installed=True):
        self._v, self._i = ver, installed

    def detect_binary(self):
        return {"version": self._v, "installed": self._i}


def _patch(fakeip_mgr, ver="1.13.0", installed=True):
    """Контекст: подменить зависимости build_and_save."""
    from unittest import mock
    return [
        mock.patch("core.singbox_manager.get_singbox_manager",
                   return_value=fakeip_mgr),
        mock.patch("core.singbox_platform.detect_singbox_platform",
                   return_value=_FakePlat()),
        mock.patch("core.singbox_detector.get_singbox_detector",
                   return_value=_FakeDet(ver, installed)),
        mock.patch("core.hostlist_manager.get_hostlist_manager",
                   return_value=_FakeHM()),
        mock.patch("core.singbox_subscription.uri_to_outbound",
                   return_value={"ok": True, "tag": "s",
                                 "outbound": _vless()}),
    ]


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        from core import singbox_fakeip
        self.sf = singbox_fakeip

    def _run(self, mgr, ver="1.13.0", installed=True, **kw):
        patches = _patch(mgr, ver, installed)
        for p in patches:
            p.start()
        try:
            return self.sf.build_and_save(**kw)
        finally:
            for p in patches:
                p.stop()

    def test_link_proxy_legacy_saved_and_validated(self):
        mgr = _FakeMgr([{"ok": True}])               # legacy прошёл check
        res = self._run(mgr, name="fi", proxy_link="vless://u@h:443",
                        domains="youtube.com")
        self.assertTrue(res["ok"])
        self.assertEqual(res["dns_format"], "legacy")
        self.assertTrue(res["fakeip"])
        self.assertEqual(mgr.saved[0], "fi")
        self.assertIn("fakeip", mgr.saved[1])         # FakeIP в сохранённом

    def test_falls_back_to_typed_when_legacy_rejected(self):
        # legacy отвергнут, typed принят → формат typed.
        mgr = _FakeMgr([{"ok": False, "error": "legacy removed"},
                        {"ok": True}])
        res = self._run(mgr, proxy_link="vless://u@h:443", domains="a.com")
        self.assertTrue(res["ok"])
        self.assertEqual(res["dns_format"], "typed")

    def test_no_binary_saves_without_check(self):
        mgr = _FakeMgr([{"ok": False, "no_binary": True}])
        res = self._run(mgr, installed=False, proxy_link="vless://u@h:443",
                        domains="a.com")
        self.assertTrue(res["ok"])
        self.assertTrue(res["warning"])

    def test_guard_requires_proxy(self):
        mgr = _FakeMgr([{"ok": True}])
        res = self._run(mgr, domains="a.com")        # без ссылки/конфига
        self.assertFalse(res["ok"])

    def test_guard_requires_targets_when_not_route_all(self):
        mgr = _FakeMgr([{"ok": True}])
        res = self._run(mgr, proxy_link="vless://u@h:443")  # нет доменов/cidr
        self.assertFalse(res["ok"])

    def test_route_all_needs_no_targets(self):
        mgr = _FakeMgr([{"ok": True}])
        res = self._run(mgr, proxy_link="vless://u@h:443", route_all=True)
        self.assertTrue(res["ok"])
        self.assertTrue(res["route_all"])

    def test_hostlist_domains_collected(self):
        mgr = _FakeMgr([{"ok": True}])
        res = self._run(mgr, proxy_link="vless://u@h:443", hostlists=["svc"])
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["domains"], 1)   # youtube.com из svc


if __name__ == "__main__":
    unittest.main()
