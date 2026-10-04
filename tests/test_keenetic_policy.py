"""Политика доступа Keenetic для перехвата nfqws2 (POLICY_NAME/POLICY_EXCLUDE
из nfqws2-keenetic): разбор метки и состав iptables-правил."""

import unittest
from unittest import mock

from core import keenetic_policy as kp
from core.firewall import FirewallManager
from core.firewall_persistence import FIREWALL_SH_FUNCTIONS, render_run_conf


SHOW_IP_POLICY = """\
   policy, name = Policy0, description = nfqws:
       mark: ffffaaa
       permit, interface = ISP
   policy, name = Policy1, description = Гостевая:
       mark: ffffaab
"""


class TestParse(unittest.TestCase):

    def test_found(self):
        self.assertEqual(kp.parse_policy_mark(SHOW_IP_POLICY, "nfqws"),
                         "0xffffaaa/0x0fffffff")

    def test_case_insensitive_and_unicode(self):
        self.assertEqual(kp.parse_policy_mark(SHOW_IP_POLICY, "NFQWS"),
                         "0xffffaaa/0x0fffffff")
        self.assertEqual(kp.parse_policy_mark(SHOW_IP_POLICY, "Гостевая"),
                         "0xffffaab/0x0fffffff")

    def test_missing(self):
        self.assertEqual(kp.parse_policy_mark(SHOW_IP_POLICY, "vpn"), "")
        self.assertEqual(kp.parse_policy_mark("", "nfqws"), "")
        self.assertEqual(kp.parse_policy_mark(SHOW_IP_POLICY, ""), "")

    def test_garbage_mark(self):
        txt = "policy, description = x:\n   mark: $(reboot)\n"
        self.assertEqual(kp.parse_policy_mark(txt, "x"), "")

    def test_clean_name(self):
        self.assertEqual(kp.clean_name('nfqws"; reboot; #'), "nfqws reboot")
        self.assertEqual(kp.clean_name(" Гостевая-1 "), "Гостевая-1")


def _capture(policy_mark, exclude):
    fw = FirewallManager()
    fw._extra.update({"policy_mark": policy_mark, "policy_exclude": exclude})
    captured = []

    def fake_run(cmd):
        captured.append(cmd)
        return True

    with mock.patch.object(fw, "_run_cmd", side_effect=fake_run), \
            mock.patch.object(fw, "_comment_supported", return_value=True), \
            mock.patch.object(fw, "_multiport_supported", return_value=True), \
            mock.patch.object(fw, "_connbytes_supported", return_value=True), \
            mock.patch.object(fw, "_nfqueue_supported", return_value=True), \
            mock.patch("core.firewall.shutil.which",
                       return_value="/sbin/iptables"):
        fw._apply_ipt_family("iptables", 300, "80,443", "443",
                             "0x40000000", 20, 5, ["eth0"], [])
    return [" ".join(c) for c in captured]


class TestRules(unittest.TestCase):

    MARK = "0xffffaaa/0x0fffffff"

    def _first_nfq(self, cmds, chain):
        return next(i for i, c in enumerate(cmds)
                    if " %s " % chain in c and "NFQUEUE" in c)

    def test_no_policy_no_rules(self):
        cmds = _capture("", False)
        self.assertFalse([c for c in cmds if "0x0fffffff" in c])

    def test_include_mode_marks_others_excluded(self):
        cmds = _capture(self.MARK, False)
        pol = [i for i, c in enumerate(cmds)
               if "! --mark %s" % self.MARK in c]
        self.assertEqual(len(pol), 1)
        self.assertIn("CONNMARK --set-xmark 0x20000000/0x20000000",
                      cmds[pol[0]])
        # Метка — до любых NFQUEUE-правил исходящего направления.
        self.assertLess(pol[0], self._first_nfq(cmds, "POSTROUTING"))

    def test_exclude_mode_returns_policy_both_ways(self):
        cmds = _capture(self.MARK, True)
        ret = [c for c in cmds
               if "--mark %s" % self.MARK in c and c.endswith("RETURN")
               and "!" not in c]
        self.assertEqual(len(ret), 2)  # POSTROUTING + PREROUTING
        self.assertTrue(any("POSTROUTING" in c for c in ret))
        self.assertTrue(any("PREROUTING" in c for c in ret))
        self.assertFalse([c for c in cmds if "CONNMARK" in c])


class TestShell(unittest.TestCase):

    def test_run_conf_has_policy(self):
        txt = render_run_conf({"policy_mark": "0x1/0x0fffffff",
                               "policy_exclude": "1",
                               "policy_name": ""})
        self.assertIn('POLICY_MARK="0x1/0x0fffffff"', txt)
        self.assertIn('POLICY_EXCLUDE="1"', txt)

    def test_shell_functions_resolve_and_apply(self):
        self.assertIn("_policy_resolve() {", FIREWALL_SH_FUNCTIONS)
        self.assertIn("-m mark ! --mark $POLICY_MARK -j CONNMARK",
                      FIREWALL_SH_FUNCTIONS)
        self.assertIn('show ip policy', FIREWALL_SH_FUNCTIONS)


if __name__ == "__main__":
    unittest.main()
