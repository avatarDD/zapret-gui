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
    make_hijack_dns_rule, make_tun_inbound, set_tun_inbound,
    find_tun_interface,
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


class TestTunInbound(unittest.TestCase):

    def _cfg(self):
        return {"inbounds": [{"type": "mixed", "tag": "user"}], "outbounds": [
            {"type": "selector", "tag": "PROXY",
             "outbounds": ["s1"], "default": "s1"},
            {"type": "vless", "tag": "s1", "server": "x",
             "server_port": 443, "uuid": "u"}]}

    def test_make_tun_uses_modern_fields_only(self):
        ib = make_tun_inbound(interface_name="singbox-tun")
        self.assertEqual(ib["type"], "tun")
        self.assertEqual(ib["interface_name"], "singbox-tun")
        self.assertIsInstance(ib["address"], list)        # не inet4_address
        for legacy in ("inet4_address", "inet6_address",
                       "inet4_route_address", "gso"):
            self.assertNotIn(legacy, ib)

    def test_make_tun_auto_route_off_by_default(self):
        # для выборочной маршрутизации sing-box не должен забирать
        # маршрут по умолчанию.
        self.assertFalse(make_tun_inbound()["auto_route"])
        self.assertTrue(make_tun_inbound(auto_route=True)["auto_route"])

    def test_set_tun_inbound_creates_interface(self):
        cfg = self._cfg()
        set_tun_inbound(cfg, interface_name="singbox-tun")
        self.assertEqual(find_tun_interface(cfg), "singbox-tun")
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertIn("tun-in", tags)
        self.assertIn("user", tags)                       # чужой inbound цел

    def test_set_tun_routes_to_proxy_and_sniffs(self):
        cfg = self._cfg()
        set_tun_inbound(cfg, route_to_proxy=True, sniff=True)
        self.assertEqual(cfg["route"]["final"], "PROXY")  # первый selector
        self.assertIn(make_sniff_rule(), cfg["route"]["rules"])

    def test_set_tun_idempotent(self):
        cfg = self._cfg()
        set_tun_inbound(cfg, interface_name="t0")
        set_tun_inbound(cfg, interface_name="t1")
        tun = [ib for ib in cfg["inbounds"] if ib["tag"] == "tun-in"]
        self.assertEqual(len(tun), 1)                     # заменён, не дубль
        self.assertEqual(tun[0]["interface_name"], "t1")


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


class TestTproxyCapability(unittest.TestCase):
    """Префлайт TPROXY (issue #149): когда цели TPROXY нет на роутере,
    apply() для tproxy/hybrid должен отдать ОДНУ понятную подсказку и не
    ставить правила; redirect — не трогать проверку вовсе."""

    def setUp(self):
        # Подменяем I/O: iptables «есть», все команды «успешны».
        self._patchers = [
            mock.patch.object(tp, "_run", lambda *a, **k: (0, "", "")),
            mock.patch.object(tp, "available", lambda family="v4": True),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()

    def test_tproxy_missing_blocks_with_actionable_error(self):
        with mock.patch.object(tp, "tproxy_available",
                               lambda family="v4": False):
            r = tp.apply(mode="tproxy", tcp_port=1100,
                         families=("v4",), backend="iptables")
        self.assertFalse(r["ok"])
        self.assertEqual(r.get("need"), "tproxy")
        self.assertEqual(r.get("rule_count"), 0)
        joined = " ".join(r["errors"]).lower()
        for hint in ("tproxy", "iptables-mod-tproxy", "redirect", "tun"):
            self.assertIn(hint, joined)        # подсказка самодостаточна

    def test_hybrid_missing_tproxy_also_blocks(self):
        with mock.patch.object(tp, "tproxy_available",
                               lambda family="v4": False):
            r = tp.apply(mode="hybrid", tcp_port=1100, udp_port=1102,
                         families=("v4",), backend="iptables")
        self.assertFalse(r["ok"])
        self.assertEqual(r.get("need"), "tproxy")

    def test_tproxy_present_proceeds(self):
        with mock.patch.object(tp, "tproxy_available",
                               lambda family="v4": True):
            r = tp.apply(mode="tproxy", tcp_port=1100,
                         families=("v4",), backend="iptables")
        self.assertTrue(r["ok"])               # _run всё «успешно»
        self.assertNotIn("need", r)

    def test_redirect_skips_tproxy_probe(self):
        # redirect не требует TPROXY — проверку даже не запускаем.
        calls = {"n": 0}

        def _probe(family="v4"):
            calls["n"] += 1
            return False

        with mock.patch.object(tp, "tproxy_available", _probe):
            r = tp.apply(mode="redirect", tcp_port=1100,
                         families=("v4",), backend="iptables")
        self.assertTrue(r["ok"])
        self.assertEqual(calls["n"], 0)

    def test_probe_detects_missing_target(self):
        # tproxy_available → False, когда вставка падает с «No chain/...».
        def _fake_run(args, timeout=10):
            if "-A" in args and "TPROXY" in args:
                return (1, "", "iptables: No chain/target/match by that name.")
            return (0, "", "")
        with mock.patch.object(tp, "_run", _fake_run):
            self.assertFalse(tp.tproxy_available("v4"))

    def test_probe_ok_when_insert_succeeds(self):
        with mock.patch.object(tp, "_run", lambda *a, **k: (0, "", "")):
            self.assertTrue(tp.tproxy_available("v4"))


class TestTproxyCache(unittest.TestCase):
    """issue #149: /transparent/status поллится каждые 5с, поэтому доступность
    TPROXY кэшируется (живой iptables-зонд на каждый poll недопустим), а
    apply()-префлайт держит кэш свежим, чтобы UI сразу убрал/показал
    предупреждение."""

    def setUp(self):
        tp.reset_tproxy_cache()

    def tearDown(self):
        tp.reset_tproxy_cache()

    def test_cached_probes_once_until_force(self):
        calls = {"n": 0}

        def _probe(family="v4"):
            calls["n"] += 1
            return True

        with mock.patch.object(tp, "tproxy_available", _probe):
            self.assertTrue(tp.tproxy_supported_cached("v4"))
            self.assertTrue(tp.tproxy_supported_cached("v4"))
            self.assertEqual(calls["n"], 1)          # второй раз — из кэша
            self.assertTrue(tp.tproxy_supported_cached("v4", force=True))
            self.assertEqual(calls["n"], 2)          # force → перепроверка

    def test_apply_preflight_populates_cache(self):
        # TPROXY недоступна → apply пишет False в кэш; status потом отдаёт его
        # БЕЗ повторного зонда.
        with mock.patch.object(tp, "_run", lambda *a, **k: (0, "", "")), \
                mock.patch.object(tp, "available", lambda family="v4": True), \
                mock.patch.object(tp, "tproxy_available",
                                  lambda family="v4": False):
            r = tp.apply(mode="tproxy", tcp_port=1100,
                         families=("v4",), backend="iptables")
        self.assertEqual(r.get("need"), "tproxy")

        # Теперь кэш уже False — зонд дёргаться не должен.
        def _boom(family="v4"):
            raise AssertionError("tproxy_available не должен вызываться — кэш")

        with mock.patch.object(tp, "tproxy_available", _boom):
            self.assertFalse(tp.tproxy_supported_cached("v4"))


class TestSbinPath(unittest.TestCase):
    """PATH без /sbin (systemd/обычный юзер) не должен прятать iptables —
    available() ложно показывал «iptables недоступен» на Debian."""

    def test_sbin_dirs_added_when_present(self):
        import os
        orig = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = os.pathsep.join(["/usr/bin", "/bin"])
            tp._ensure_sbin_in_path()
            parts = os.environ["PATH"].split(os.pathsep)
            for d in ("/usr/local/sbin", "/usr/sbin", "/sbin"):
                if os.path.isdir(d):              # только реально существующие
                    self.assertIn(d, parts)
        finally:
            os.environ["PATH"] = orig

    def test_existing_path_preserved(self):
        import os
        orig = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = "/opt/custom/bin"
            tp._ensure_sbin_in_path()
            self.assertIn("/opt/custom/bin",
                          os.environ["PATH"].split(os.pathsep))
        finally:
            os.environ["PATH"] = orig


if __name__ == "__main__":
    unittest.main()
