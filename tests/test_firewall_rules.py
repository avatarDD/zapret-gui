# tests/test_firewall_rules.py
"""Тесты состава правил FirewallManager (iptables / nftables).

Не выполняем реальные iptables-команды — перехватываем _run_cmd и проверяем,
что после портирования из nfqws2-keenetic появились правила обоих направлений,
NAT MASQUERADE и обработка TCP-флагов.
"""

import unittest
from unittest import mock

from core.firewall import FirewallManager


def _capture_iptables(fw):
    """Запустить _apply_ipt_family для iptables, вернуть список команд (списки)."""
    captured = []

    def fake_run(cmd):
        captured.append(cmd)
        return True

    with mock.patch.object(fw, "_run_cmd", side_effect=fake_run), \
            mock.patch("core.firewall.shutil.which", return_value="/sbin/iptables"):
        rules = []
        fw._apply_ipt_family(
            "iptables", 300, "80,443", "443",
            "0x40000000", 20, 5, ["eth0"], rules,
        )
    return captured


class TestIptablesRules(unittest.TestCase):

    def setUp(self):
        self.fw = FirewallManager()
        self.cmds = _capture_iptables(self.fw)
        self.flat = [" ".join(c) for c in self.cmds]

    def test_has_postrouting_and_prerouting(self):
        self.assertTrue(any("POSTROUTING" in c for c in self.flat))
        self.assertTrue(any("PREROUTING" in c for c in self.flat))

    def test_has_nat_masquerade(self):
        nat = [c for c in self.flat if "nat" in c and "MASQUERADE" in c]
        self.assertTrue(nat, "ожидалось NAT MASQUERADE правило")

    def test_has_tcp_flag_rules(self):
        self.assertTrue(any("--tcp-flags syn,ack syn,ack" in c for c in self.flat))
        self.assertTrue(any("--tcp-flags fin fin" in c for c in self.flat))
        self.assertTrue(any("--tcp-flags rst rst" in c for c in self.flat))

    def test_has_mark_exclude_return(self):
        ret = [c for c in self.flat if "connmark" in c and "RETURN" in c]
        self.assertTrue(ret, "ожидался RETURN для MARK_EXCLUDE")

    def test_reply_connbytes_in_prerouting(self):
        pre_reply = [c for c in self.flat
                     if "PREROUTING" in c and "connbytes-dir=reply" in c]
        self.assertTrue(pre_reply)

    def test_outgoing_uses_dports_incoming_uses_sports(self):
        post = [c for c in self.flat if "POSTROUTING" in c and "multiport" in c]
        pre = [c for c in self.flat if "PREROUTING" in c and "multiport" in c]
        self.assertTrue(all("--dports" in c for c in post))
        self.assertTrue(all("--sports" in c for c in pre))


class TestNftablesRules(unittest.TestCase):

    def setUp(self):
        self.fw = FirewallManager()
        captured = []

        def fake_run(cmd):
            captured.append(" ".join(cmd))
            return True

        with mock.patch.object(self.fw, "_run_cmd", side_effect=fake_run):
            self.fw._apply_nftables(
                300, "80,443", "443", "0x40000000", 20, 5,
                ["eth0"], None,
            )
        self.flat = captured

    def test_three_chains_created(self):
        joined = "\n".join(self.flat)
        self.assertIn("postrouting", joined)
        self.assertIn("prerouting", joined)
        self.assertIn("natpost", joined)

    def test_has_masquerade(self):
        self.assertTrue(any("masquerade" in c for c in self.flat))

    def test_has_tcp_flags(self):
        joined = "\n".join(self.flat)
        self.assertIn("tcp flags syn,ack", joined)


if __name__ == "__main__":
    unittest.main()
