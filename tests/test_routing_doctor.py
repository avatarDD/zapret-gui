# tests/test_routing_doctor.py
"""
Routing doctor — пошаговая диагностика «правило есть, а трафик мимо
туннеля» (core/routing/doctor). Проверяем разбор вывода утилит и сборку
отчёта по здоровой/сломанной цепочке.
"""

import unittest
from unittest import mock

from core.routing import doctor
from core.routing.rules import DomainRoutingRule


class TestParsers(unittest.TestCase):

    def test_ipset_count_parses_header(self):
        out = ("Name: awgr_x\nType: hash:ip\nNumber of entries: 42\n"
               "Members:\n1.2.3.4\n")
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            self.assertEqual(doctor._ipset_count("awgr_x"), 42)

    def test_ipset_count_missing_set(self):
        with mock.patch.object(doctor, "_run",
                               return_value=(1, "", "does not exist")):
            self.assertIsNone(doctor._ipset_count("nope"))

    def test_has_fwmark_rule_hex(self):
        lines = ["0:\tfrom all lookup local",
                 "10100:\tfrom all fwmark 0x1abcd lookup 361",
                 "32766:\tfrom all lookup main"]
        with mock.patch.object(doctor, "_ip_rule_lines",
                               return_value=lines):
            self.assertTrue(doctor._has_fwmark_rule(0x1abcd, 361))
            self.assertFalse(doctor._has_fwmark_rule(0x1abcd, 999))

    def test_mangle_counters(self):
        out = ("Chain AWG_ROUTING_PRE (1 references)\n"
               "    pkts      bytes target     prot opt in     out\n"
               "     123     4567 MARK       all  --  *      *       "
               "0.0.0.0/0  0.0.0.0/0  match-set awgr_x dst MARK set 0x1abcd\n")
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            found, pkts = doctor._mangle_mark_counters("awgr_x")
        self.assertTrue(found)
        # обе цепочки (PRE и OUT) вернули одинаковый мок → 123*2
        self.assertEqual(pkts, 246)

    def test_route_get_dev(self):
        out = "1.2.3.4 dev WARPv1_61 table 361 src 172.16.0.2\n"
        with mock.patch.object(doctor, "_run",
                               return_value=(0, out, "")):
            self.assertEqual(doctor._route_get_dev("1.2.3.4", mark=7),
                             "WARPv1_61")


class TestDiagnose(unittest.TestCase):

    def _rule(self):
        return DomainRoutingRule(target_iface="awg0",
                                 domains=["example.com"],
                                 rule_id="uni-doc")

    def _patch_chain(self, healthy=True):
        from core.routing import domain_rule
        return [
            mock.patch("core.routing.storage.load_rules",
                       return_value=[self._rule()]),
            mock.patch.object(domain_rule, "_sets_state_load",
                              return_value={"uni-doc": "ipset"}),
            mock.patch.object(domain_rule, "_iproute_state_load",
                              return_value={}),
            mock.patch.object(domain_rule, "_iface_exists",
                              return_value=True),
            mock.patch.object(domain_rule, "_resolve_ips",
                              return_value=["1.2.3.4"]),
            mock.patch.object(doctor, "_ipset_count", return_value=10),
            mock.patch.object(doctor, "_mangle_mark_counters",
                              return_value=(True, 5 if healthy else 0)),
            mock.patch.object(doctor, "_has_fwmark_rule",
                              return_value=True),
            mock.patch.object(doctor, "_table_default_iface",
                              return_value="awg0"),
            mock.patch.object(doctor, "_masquerade_present",
                              return_value=True),
            mock.patch.object(doctor, "_ipset_test", return_value=True),
            mock.patch.object(doctor, "_route_get_dev",
                              return_value="awg0" if healthy else "eth0"),
            mock.patch.object(doctor, "_run",
                              return_value=(0, "", "")),
        ]

    def _run_diag(self, healthy):
        patches = self._patch_chain(healthy)
        for p in patches:
            p.start()
        try:
            return doctor.diagnose()
        finally:
            for p in patches:
                p.stop()

    def test_healthy_chain_all_ok(self):
        report = self._run_diag(healthy=True)
        self.assertTrue(report["ok"], doctor.render_text(report))
        self.assertEqual(len(report["rules"]), 1)

    def test_broken_chain_flags_failures(self):
        report = self._run_diag(healthy=False)
        self.assertFalse(report["ok"])
        bad = [c["name"] for c in report["rules"][0]["checks"]
               if not c["ok"]]
        # 0 пакетов на mark-правиле и route get мимо туннеля — оба видны
        self.assertTrue(any("маркировка" in n for n in bad), bad)
        self.assertTrue(any("route get" in n for n in bad), bad)

    def test_render_text_smoke(self):
        report = self._run_diag(healthy=True)
        text = doctor.render_text(report)
        self.assertIn("uni-doc", text)
        self.assertIn("✓", text)


if __name__ == "__main__":
    unittest.main()
