# tests/test_phase1_fixes.py
"""Тесты функциональных HIGH-фиксов Фазы 1."""

import os
import tempfile
import time
import unittest
from unittest import mock


# ════════════════════════════════════════════════════════════
# #10 — per-peer sparkline больше не всегда пустой
# ════════════════════════════════════════════════════════════

class TestTrafficPeerSeries(unittest.TestCase):

    def test_peer_points_give_bucket_ge_two_samples(self):
        from core.connectivity import traffic
        # bucket_sec = window // points должен вмещать ≥2 сэмпла.
        window = traffic.PEER_HISTORY_MINUTES * 60
        bucket_sec = window // traffic.PEER_SERIES_POINTS
        self.assertGreaterEqual(bucket_sec, 2 * traffic.SAMPLE_INTERVAL_SEC)

    def test_series_nonempty_with_peer_points(self):
        from core.connectivity import traffic
        now = int(time.time())
        window = traffic.PEER_HISTORY_MINUTES * 60
        # Сэмплы каждые SAMPLE_INTERVAL_SEC за всё окно, rx/tx растут.
        raw = []
        rx = 0
        for k in range(window // traffic.SAMPLE_INTERVAL_SEC + 1):
            ts = now - window + k * traffic.SAMPLE_INTERVAL_SEC
            rx += 1000
            raw.append((ts, rx, rx * 2))
        series = traffic._series_from_samples(
            raw, window, traffic.PEER_SERIES_POINTS)
        self.assertTrue(series, "peer-серия не должна быть пустой")
        # Регрессия-маркер: со старым points=PEER_BUFFER_SIZE серия пуста.
        self.assertEqual(
            traffic._series_from_samples(raw, window,
                                         traffic.PEER_BUFFER_SIZE), [])


# ════════════════════════════════════════════════════════════
# #13 — NDMS static-route: dotted-маска вместо префикса
# ════════════════════════════════════════════════════════════

class TestNdmsNetmask(unittest.TestCase):

    def test_cidr_to_dotted(self):
        from core.routing.ndms_backend import _split_cidr
        self.assertEqual(_split_cidr("10.0.0.0/24"),
                         ("10.0.0.0", "255.255.255.0"))
        self.assertEqual(_split_cidr("192.168.1.0/16"),
                         ("192.168.0.0", "255.255.0.0"))

    def test_bare_ip_is_host_mask(self):
        from core.routing.ndms_backend import _split_cidr
        self.assertEqual(_split_cidr("1.2.3.4"),
                         ("1.2.3.4", "255.255.255.255"))

    def test_ipv6_passthrough(self):
        from core.routing.ndms_backend import _split_cidr
        net, mask = _split_cidr("2001:db8::/32")
        self.assertEqual(net, "2001:db8::")
        self.assertEqual(mask, "32")


# ════════════════════════════════════════════════════════════
# #12 — clash YAML fallback-эмиттер: пустой контейнер в первом ключе
# ════════════════════════════════════════════════════════════

class TestClashYamlEmptyContainer(unittest.TestCase):

    def test_empty_container_first_key(self):
        from core import clash_yaml
        seq = [{"smux": {}, "name": "srv", "alpn": []}]
        out = []
        clash_yaml._emit_seq(seq, 0, out)
        text = "\n".join(out) + "\n"
        self.assertIn("- smux: {}", text)
        # Должно парситься корректно и сохранять типы (dict/list, не строки).
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml недоступен")
        parsed = yaml.safe_load(text)
        self.assertEqual(parsed, seq)
        self.assertIsInstance(parsed[0]["smux"], dict)
        self.assertIsInstance(parsed[0]["alpn"], list)


# ════════════════════════════════════════════════════════════
# #9 — nft exclude использует ct mark, processed — meta mark
# ════════════════════════════════════════════════════════════

class TestFirewallNftMark(unittest.TestCase):

    def test_exclude_uses_ct_mark(self):
        from core.firewall import FirewallManager
        fw = FirewallManager()
        excl = fw._extra.get("mark_exclude", "0x20000000")
        proc = "0x40000000"
        with mock.patch.object(fw, "_run_cmd", return_value=True):
            fw._apply_nftables(qnum=300, ports_tcp="443", ports_udp="443",
                               fwmark=proc, tcp_pkt=20, udp_pkt=5,
                               wan4_ifaces=[], wan6_ifaces=[])
        rules = fw._rules_info
        self.assertTrue(rules)
        excl_rules = [r for r in rules if ("and %s ==" % excl) in r]
        proc_rules = [r for r in rules if ("and %s ==" % proc) in r]
        self.assertTrue(excl_rules, "нет exclude-правил")
        for r in excl_rules:
            self.assertIn("ct mark and", r)
            self.assertNotIn("meta mark and", r)
        # PROCESSED-маска остаётся пакетной (meta mark), как в iptables.
        for r in proc_rules:
            self.assertIn("meta mark and", r)


# ════════════════════════════════════════════════════════════
# #7 — AwgManager.restart принимает имя интерфейса (резолв в конфиг)
# ════════════════════════════════════════════════════════════

class TestAwgConfigForName(unittest.TestCase):

    def _mgr(self):
        from core.awg_manager import AwgManager
        return AwgManager()

    def test_iface_name_resolves_to_config(self):
        mgr = self._mgr()
        with mock.patch.object(mgr, "_config_path",
                               return_value="/nonexistent/opkgtun0.conf"), \
             mock.patch.object(mgr, "_all_config_names",
                               return_value={"awg0-opkgtun0"}), \
             mock.patch.object(mgr, "_iface_for_name",
                               return_value="opkgtun0"):
            self.assertEqual(mgr._config_for_name("opkgtun0"),
                             "awg0-opkgtun0")

    def test_existing_config_name_passthrough(self):
        mgr = self._mgr()
        with tempfile.NamedTemporaryFile(suffix=".conf") as tf:
            with mock.patch.object(mgr, "_config_path",
                                   return_value=tf.name):
                self.assertEqual(mgr._config_for_name("whatever"), "whatever")


# ════════════════════════════════════════════════════════════
# #11 — pre-population: fan-out v4+v6 ограниченным пулом
# ════════════════════════════════════════════════════════════

class TestPrepopulateDomains(unittest.TestCase):

    def test_fanout_v4_v6(self):
        from core.routing import domain_rule
        calls = []

        def fake_prepop(set_name, domain, family, backend):
            calls.append((set_name, domain, family))
            return {"ok": True, "added": 1, "domain": domain}

        with mock.patch.object(domain_rule, "_prepopulate_set",
                               side_effect=fake_prepop):
            res = domain_rule._prepopulate_domains(
                ["a.com", "b.com"], "set4", "set6", backend=None)
        self.assertEqual(len(res), 4)          # 2 домена × 2 семейства
        fams = sorted({f for _, _, f in calls})
        self.assertEqual(fams, ["v4", "v6"])
        v4 = {d for s, d, f in calls if f == "v4"}
        self.assertEqual(v4, {"a.com", "b.com"})

    def test_empty_domains(self):
        from core.routing import domain_rule
        self.assertEqual(
            domain_rule._prepopulate_domains([], "s4", "s6", None), [])


if __name__ == "__main__":
    unittest.main()
