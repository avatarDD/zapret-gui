# tests/test_mihomo_routing.py
"""
Тесты оркестраторов маршрутизации mihomo (core/mihomo_routing.py): резолв
прокси (ссылка/конфиг), сборка+сохранение без бинаря (graceful), фолбэк стека
gvisor→system и rule-provider→DOMAIN-SUFFIX через мок `mihomo -t`.
"""

import unittest
from unittest import mock

from core import mihomo_routing as mr
from core.clash_yaml import parse_yaml


def _vless_proxy():
    return {"name": "srv", "type": "vless", "server": "vpn.example.com",
            "port": 443, "uuid": "u-1", "tls": True}


def _detector(installed=True, has_gvisor=True):
    det = mock.MagicMock()
    det.detect_binary.return_value = {"installed": installed,
                                      "has_gvisor": has_gvisor,
                                      "version": "1.18.0"}
    return det


class _FakeManager:
    """Менеджер-заглушка: validate_via_binary решает по содержимому text."""

    def __init__(self, accept=lambda cfg: True):
        self.accept = accept
        self.saved = None

    def validate_via_binary(self, name, text=None):
        cfg = parse_yaml(text or "")
        ok = self.accept(cfg)
        return {"ok": ok, "stderr": "" if ok else "rejected", "returncode":
                0 if ok else 1}

    def save_config(self, name, text=""):
        self.saved = (name, text)
        return {"ok": True, "name": name, "warnings": []}


class TestResolveProxies(unittest.TestCase):

    def test_from_link(self):
        items = [{"type": "uri", "value": "vless://x"},
                 {"type": "uri", "value": "ss://y"}]
        with mock.patch("core.subscription_importer.extract_items",
                        return_value=items), \
             mock.patch("core.clash_yaml.uri_to_clash_proxy",
                        side_effect=[{"ok": True, "proxy": _vless_proxy()},
                                     {"ok": False, "error": "bad"}]):
            r = mr._resolve_proxies(proxy_link="vless://x\nss://y")
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["proxies"]), 1)

    def test_link_no_valid(self):
        with mock.patch("core.subscription_importer.extract_items",
                        return_value=[]):
            r = mr._resolve_proxies(proxy_link="garbage")
        self.assertFalse(r["ok"])

    def test_from_config(self):
        cfg_text = ("proxies:\n  - {name: a, type: ss, server: 1.1.1.1, "
                    "port: 1, cipher: aes-128-gcm, password: p}\n")
        mgr = mock.MagicMock()
        mgr.get_config.return_value = {"ok": True, "text": cfg_text}
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr):
            r = mr._resolve_proxies(proxy_config="cfg")
        self.assertTrue(r["ok"])
        self.assertEqual(r["proxies"][0]["name"], "a")

    def test_none(self):
        self.assertFalse(mr._resolve_proxies()["ok"])

    def test_dedup_names(self):
        out = mr._dedup_names([{"name": "x", "type": "ss"},
                               {"name": "x", "type": "ss"},
                               {"type": "vless"}])
        names = [p["name"] for p in out]
        self.assertEqual(names, ["x", "x-2", "vless"])


class TestCollectLists(unittest.TestCase):

    def test_hostlists_and_named(self):
        hm = mock.MagicMock()
        hm.get_hostlist.return_value = ["a.com", "b.com"]
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm), \
             mock.patch("core.named_lists.resolve",
                        return_value={"domains": ["c.com"],
                                      "cidrs": ["9.9.9.0/24"]}):
            doms, cidrs = mr._collect_lists(hostlists=["other"], lists=["id1"])
        self.assertEqual(set(doms), {"a.com", "b.com", "c.com"})
        self.assertEqual(cidrs, ["9.9.9.0/24"])


class TestBuildDomainRoute(unittest.TestCase):

    def _patches(self, mgr, installed=True, has_gvisor=True, nft=False):
        plat = mock.MagicMock()
        plat.get_firewall_backend.return_value = "nftables" if nft else "iptables"
        return [
            mock.patch("core.mihomo_detector.get_mihomo_detector",
                       return_value=_detector(installed, has_gvisor)),
            mock.patch("core.mihomo_manager.get_mihomo_manager",
                       return_value=mgr),
            mock.patch("core.proxy_tester._free_port", return_value=9099),
            mock.patch("core.mihomo_platform.detect_mihomo_platform",
                       return_value=plat),
            mock.patch.object(mr, "_resolve_proxies",
                              return_value={"ok": True,
                                            "proxies": [_vless_proxy()]}),
        ]

    def _run(self, mgr, **kw):
        ps = self._patches(mgr, **kw.pop("_env", {}))
        for p in ps:
            p.start()
        try:
            return mr.build_domain_route_and_save(**kw)
        finally:
            for p in ps:
                p.stop()

    def test_no_binary_graceful(self):
        mgr = _FakeManager()
        with mock.patch("core.mihomo_detector.get_mihomo_detector",
                        return_value=_detector(installed=False)), \
             mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch("core.proxy_tester._free_port", return_value=9099), \
             mock.patch("core.mihomo_platform.detect_mihomo_platform"), \
             mock.patch.object(mr, "_resolve_proxies",
                               return_value={"ok": True,
                                             "proxies": [_vless_proxy()]}):
            r = mr.build_domain_route_and_save(
                name="d", proxy_link="vless://x", domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertIn("не установлен", r["warning"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertEqual(cfg["tun"]["stack"], "gvisor")
        self.assertIn("RULE-SET,proxied,PROXY", cfg["rules"])
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9099")

    def test_gvisor_fallback_to_system(self):
        # mihomo -t отвергает gvisor, принимает system.
        mgr = _FakeManager(accept=lambda c: c.get("tun", {}).get("stack")
                           != "gvisor")
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "system")

    def test_ruleset_fallback_to_domain_suffix(self):
        # Отвергаем любой конфиг с rule-providers (старая сборка).
        mgr = _FakeManager(accept=lambda c: "rule-providers" not in c)
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertFalse(r["ruleset"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertIn("DOMAIN-SUFFIX,youtube.com,PROXY", cfg["rules"])

    def test_reject_all_fails(self):
        mgr = _FakeManager(accept=lambda c: False)
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertFalse(r["ok"])
        self.assertIn("отверг", r["error"])

    def test_requires_domains_or_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x")
        self.assertFalse(r["ok"])

    def test_nft_enables_auto_redirect(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"], _env={"nft": True})
        self.assertTrue(r["ok"])
        self.assertTrue(r["auto_redirect"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertTrue(cfg["tun"]["auto-redirect"])


class TestBuildSourceRoute(unittest.TestCase):

    def _run(self, mgr, **kw):
        plat = mock.MagicMock()
        plat.get_firewall_backend.return_value = "iptables"
        with mock.patch("core.mihomo_detector.get_mihomo_detector",
                        return_value=_detector()), \
             mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch("core.proxy_tester._free_port", return_value=9099), \
             mock.patch("core.mihomo_platform.detect_mihomo_platform",
                        return_value=plat), \
             mock.patch.object(mr, "_resolve_proxies",
                               return_value={"ok": True,
                                             "proxies": [_vless_proxy()]}):
            return mr.build_source_route_and_save(**kw)

    def test_source_default_system_stack(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x",
                      source_ips=["192.168.1.10"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "system")
        cfg = parse_yaml(mgr.saved[1])
        self.assertIn("SRC-IP-CIDR,192.168.1.10/32,PROXY", cfg["rules"])

    def test_requires_source_or_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x")
        self.assertFalse(r["ok"])

    def test_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x", route_all=True)
        self.assertTrue(r["ok"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")


if __name__ == "__main__":
    unittest.main()
