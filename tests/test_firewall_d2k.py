"""Приёмы firewall, перенесённые из d2k (necronicle/d2k).

* разгрузка аппаратного ускорителя Keenetic (`-j PPE -m connskip`);
* метка собственных проб GUI — мимо очереди в обе стороны;
* клиенты, уведённые `ip rule` мимо WAN, — мимо очереди, когда WAN
  неизвестен (core/route_marks.py).

Python-путь и shell-путь (автозапуск + reapply-хук) проверяются вместе:
у них один источник правды по смыслу, и разойтись молча им нельзя.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from core import firewall as fwmod
from core import firewall_persistence as fp
from core import route_marks
from core.firewall import FirewallManager


IP_RULES = """\
0:\tfrom all lookup local
900:\tfrom all fwmark 0xffffaab lookup 4097
1000:\tfrom all fwmark 0xffffaaa lookup 4096
1100:\tnot from all fwmark 0x5 lookup 7
1200:\tfrom all fwmark 0x10000/0x1ffff lookup 100
1300:\tfrom all fwmark 0x7 blackhole
1400:\tfrom all fwmark 0x8 lookup main
32766:\tfrom all lookup main
32767:\tfrom all lookup default
"""

MAIN_ROUTES = "default via 10.0.0.1 dev eth3 proto static\n" \
              "10.0.0.0/24 dev eth3 scope link\n"


class TestRouteMarksParse(unittest.TestCase):

    def test_parse_rules(self):
        rules = route_marks.parse_rules(IP_RULES)
        marks = [(r["mark"], r["mask"], r["table"], r["action"])
                 for r in rules]
        self.assertIn((0xffffaaa, 0xffffffff, "4096", "lookup"), marks)
        self.assertIn((0x10000, 0x1ffff, "100", "lookup"), marks)
        self.assertIn((0x7, 0xffffffff, "", "blackhole"), marks)
        # `not ... fwmark` — «все, кроме метки», не про клиента с меткой.
        self.assertNotIn(5, [r["mark"] for r in rules])

    def test_default_devs(self):
        self.assertEqual(route_marks.parse_default_devs(MAIN_ROUTES),
                         ["eth3"])
        self.assertEqual(route_marks.parse_default_devs(
            "10.0.0.0/24 dev br0\n"), [])

    def test_routed_only_other_exit(self):
        rules = route_marks.parse_rules(IP_RULES)
        tables = {
            "4096": ["nwg0"],          # VPN Keenetic — уведён
            "4097": ["eth3"],          # политика в того же провайдера
            # 100 — без default: ядро идёт к следующему правилу
        }
        marks = route_marks.routed_marks(rules, ["eth3"], tables)
        self.assertIn("0xffffaaa/0xffffffff", marks)
        self.assertIn("0x7/0xffffffff", marks)            # blackhole
        self.assertNotIn("0xffffaab/0xffffffff", marks)   # тот же выход
        self.assertNotIn("0x10000/0x1ffff", marks)        # нет default
        self.assertNotIn("0x8/0xffffffff", marks)         # lookup main

    def test_garbage(self):
        self.assertEqual(route_marks.parse_rules(
            "1: from all fwmark zzz lookup 5\n"), [])
        self.assertEqual(route_marks.routed_marks([], [], {}), [])


class TestHelpers(unittest.TestCase):

    def test_normalize_mark(self):
        self.assertEqual(fwmod.normalize_mark("0x10000000"), "0x10000000")
        self.assertEqual(fwmod.normalize_mark("268435456"), "0x10000000")
        for empty in ("", "0", None, "junk", "-1", "0x1ffffffff"):
            self.assertEqual(fwmod.normalize_mark(empty), "")

    def test_connskip_covers_window(self):
        self.assertEqual(fwmod.ppe_connskip(20, 10, 5, 3), 40)
        self.assertEqual(fwmod.ppe_connskip(1, 1, 1, 1), 30)
        self.assertEqual(fwmod.ppe_connskip(60, 40, 5, 3), 110)

    def test_ppe_mode(self):
        cfg = mock.Mock()
        cfg.get.return_value = "off"
        self.assertEqual(fwmod.ppe_mode(cfg), "off")
        cfg.get.return_value = "auto"
        self.assertEqual(fwmod.ppe_mode(cfg), "auto")
        cfg.get.return_value = "что-то"
        self.assertEqual(fwmod.ppe_mode(cfg), "auto")

    def test_ppe_available_reads_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ip_tables_targets")
            with open(path, "w") as handle:
                handle.write("CONNMARK\nPPE\nNFQUEUE\n")
            with mock.patch.dict(fwmod.PPE_TARGETS_FILES,
                                 {"iptables": path}):
                self.assertTrue(fwmod.ppe_available("iptables"))
            with open(path, "w") as handle:
                handle.write("CONNMARK\nPPEX\n")
            with mock.patch.dict(fwmod.PPE_TARGETS_FILES,
                                 {"iptables": path}):
                self.assertFalse(fwmod.ppe_available("iptables"))
        self.assertFalse(fwmod.ppe_available("nope"))


def _capture(extra, wan=("eth0",), ppe=False):
    fw = FirewallManager()
    fw._extra.update(extra)
    captured = []

    def fake_run(cmd):
        captured.append(" ".join(cmd))
        return True

    with mock.patch.object(fw, "_run_cmd", side_effect=fake_run), \
            mock.patch.object(fw, "_comment_supported", return_value=True), \
            mock.patch.object(fw, "_multiport_supported", return_value=True), \
            mock.patch.object(fw, "_connbytes_supported", return_value=True), \
            mock.patch.object(fw, "_nfqueue_supported", return_value=True), \
            mock.patch.object(fw, "_ensure_named_chain"), \
            mock.patch("core.firewall.ppe_available", return_value=ppe), \
            mock.patch("core.firewall.shutil.which",
                       return_value="/sbin/iptables"):
        fw._apply_ipt_family("iptables", 300, "80,443", "443",
                             "0x40000000", 20, 5, list(wan), [])
    return captured


class TestIptablesPython(unittest.TestCase):

    def _first(self, cmds, needle):
        return next(i for i, c in enumerate(cmds) if needle in c)

    def test_probe_mark_excluded_before_queue(self):
        cmds = _capture({"probe_mark": "0x10000000"})
        rule = self._first(cmds, "--mark 0x10000000/0x10000000")
        self.assertIn("CONNMARK --set-xmark 0x20000000/0x20000000",
                      cmds[rule])
        self.assertLess(rule, self._first(cmds, "NFQUEUE"))

    def test_no_probe_mark_when_disabled(self):
        cmds = _capture({"probe_mark": ""})
        self.assertFalse(any("0x10000000" in c for c in cmds))

    def test_routed_marks_only_without_wan(self):
        extra = {"routed_marks": {"4": ["0xffffaaa/0xffffffff"], "6": []}}
        with_wan = _capture(extra, wan=("eth0",))
        self.assertFalse(any("0xffffaaa" in c for c in with_wan))
        all_ifaces = _capture(extra, wan=())
        rule = self._first(all_ifaces, "--mark 0xffffaaa/0xffffffff")
        self.assertIn("CONNMARK --set-xmark", all_ifaces[rule])
        self.assertLess(rule, self._first(all_ifaces, "NFQUEUE"))

    def test_ppe_rules(self):
        cmds = _capture({"ppe": "auto", "ppe_connskip": 40}, ppe=True)
        ppe = [c for c in cmds if "-j PPE" in c]
        self.assertTrue(ppe)
        self.assertTrue(all("-m connskip --connskip 40" in c for c in ppe))
        pre = [c for c in ppe if " nfqws_ppe_pre " in c]
        fwd = [c for c in ppe if " nfqws_ppe_fwd " in c]
        # Исходящее — в PREROUTING и FORWARD, ответ — только в FORWARD.
        self.assertTrue(all("--dports" in c for c in pre))
        self.assertTrue(any("--sports" in c for c in fwd))
        self.assertTrue(any("-p udp" in c for c in fwd))

    def test_ppe_off_or_missing(self):
        self.assertFalse(any("-j PPE" in c for c in _capture(
            {"ppe": "off"}, ppe=True)))
        self.assertFalse(any("-j PPE" in c for c in _capture(
            {"ppe": "auto"}, ppe=False)))


class TestNftPython(unittest.TestCase):

    def _cmds(self, extra, wan4=("eth0",)):
        fw = FirewallManager()
        fw._extra.update(extra)
        captured = []
        with mock.patch.object(fw, "_run_cmd",
                               side_effect=lambda c: captured.append(
                                   " ".join(c)) or True):
            fw._apply_nftables(300, "80,443", "443", "0x40000000", 20, 5,
                               list(wan4), None)
        return captured

    def test_probe_and_routed(self):
        extra = {"probe_mark": "0x10000000",
                 "routed_marks": {"4": ["0xffffaaa/0xffffffff"], "6": []}}
        cmds = self._cmds(extra, wan4=())
        probe = [c for c in cmds if "0x10000000" in c]
        self.assertEqual(len(probe), 1)
        self.assertIn("ct mark set ct mark or 0x20000000", probe[0])
        routed = [c for c in cmds if "0xffffaaa" in c]
        self.assertEqual(len(routed), 1)
        self.assertIn("meta nfproto ipv4", routed[0])
        # С WAN — уведённые клиенты в очередь и так не попадают.
        self.assertFalse(any("0xffffaaa" in c for c in self._cmds(extra)))


# ─────────────────────────── shell-путь ────────────────────────────

_FAKE = r"""
iptables() {
    case " $* " in
      *" -A ZGUI_PROBE "*|*" -N "*|*" -F "*|*" -X "*) return 0 ;;
      *" -C "*) return 1 ;;
      *) echo "RULE: $*"; return 0 ;;
    esac
}
ip6tables() { iptables "$@"; }
nft() { echo "NFT: $*"; return 0; }
ip() {
    case "$*" in
      "-4 rule show") printf '%s' "$FAKE_IP_RULES" ;;
      "-4 route show table main") printf '%s' "$FAKE_MAIN" ;;
      "-4 route show table 4096") echo "default dev nwg0 scope link" ;;
      "-4 route show table 4097") echo "default via 10.0.0.1 dev eth3" ;;
      *) return 0 ;;
    esac
}
"""

_PRELUDE = (
    'QUEUE_NUM=300\nPORTS_TCP="80,443"\nPORTS_UDP="443"\n'
    'MAX_PKT_OUT=20\nMAX_PKT_OUT_UDP=5\nMAX_PKT_IN=10\n'
    'MARK_PROCESSED="0x40000000/0x40000000"\n'
    'MARK_EXCLUDE="0x20000000/0x20000000"\n'
    'IPV6_ENABLED=0\n'
)


def _shell(wan="eth3", probe="0x10000000/0x10000000", ppe="1",
           ppe_proc=None, skip_routed="1", command="firewall_iptables"):
    sh = shutil.which("sh")
    env = dict(os.environ, FAKE_IP_RULES=IP_RULES, FAKE_MAIN=MAIN_ROUTES)
    if ppe_proc:
        env["PPE_PROC_NET"] = ppe_proc
    script = (_PRELUDE
              + 'WAN_IFACES="%s"\nPROBE_MARK="%s"\nPPE_DEOFFLOAD="%s"\n'
                'PPE_CONNSKIP=40\nSKIP_ROUTED_MARKS="%s"\n'
              % (wan, probe, ppe, skip_routed)
              + _FAKE + fp.FIREWALL_SH_FUNCTIONS + "\n%s\n" % command)
    r = subprocess.run([sh], input=script, text=True, capture_output=True,
                       env=env)
    out = r.stdout.splitlines()
    return ([ln[6:] for ln in out if ln.startswith("RULE: ")],
            [ln[5:] for ln in out if ln.startswith("NFT: ")])


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"),
                     "нет sh/awk")
class TestShell(unittest.TestCase):

    def test_probe_mark_rule(self):
        rules, _ = _shell()
        probe = [r for r in rules if "0x10000000/0x10000000" in r]
        self.assertEqual(len(probe), 1)
        self.assertIn("CONNMARK --set-xmark 0x20000000/0x20000000",
                      probe[0])

    def test_routed_marks_shell_matches_python(self):
        rules, _ = _shell(wan="")
        routed = [r for r in rules if "-m mark --mark 0xffff" in r
                  and "CONNMARK" in r]
        # 4096 (VPN) — да, 4097 (тот же провайдер) — нет.
        self.assertEqual(len(routed), 1, routed)
        joined = "\n".join(routed)
        self.assertIn("0xffffaaa/0xffffffff", joined)
        self.assertNotIn("0xffffaab", joined)
        # blackhole-правило — отдельной строкой
        self.assertTrue(any("0x7/0xffffffff" in r for r in rules))

    def test_routed_marks_need_all_ifaces_and_switch(self):
        rules, _ = _shell(wan="eth3")
        self.assertFalse(any("0xffffaaa" in r for r in rules))
        rules, _ = _shell(wan="", skip_routed="0")
        self.assertFalse(any("0xffffaaa" in r for r in rules))

    def test_ppe_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "ip_tables_targets"), "w") as f:
                f.write("PPE\n")
            rules, _ = _shell(ppe_proc=tmp)
            off, _ = _shell(ppe_proc=tmp, ppe="0")
        ppe = [r for r in rules if "-j PPE" in r]
        self.assertTrue(ppe)
        self.assertTrue(all("--connskip 40" in r for r in ppe))
        self.assertTrue(any("-I PREROUTING -j nfqws_ppe_pre" in r
                            for r in rules))
        self.assertTrue(any("-I FORWARD -j nfqws_ppe_fwd" in r
                            for r in rules))
        self.assertFalse(any("PPE" in r for r in off))

    def test_ppe_absent_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, _ = _shell(ppe_proc=tmp)
        self.assertFalse(any("PPE" in r for r in rules))

    def test_nft_shell(self):
        _, nft = _shell(wan="", command="firewall_nftables")
        text = "\n".join(nft)
        self.assertIn("meta mark and 0x10000000 == 0x10000000 ct mark set "
                      "ct mark or 0x20000000", text)
        self.assertIn("meta nfproto ipv4 meta mark and 0xffffffff == "
                      "0xffffaaa ct mark set ct mark or 0x20000000", text)

    def test_stop_removes_ppe_chains(self):
        rules, _ = _shell(command="firewall_stop")
        # -F/-X глушит фейк; видно снятие переходов не будет (нет -C),
        # главное — команда не падает и не ставит правил.
        self.assertFalse(any("-j PPE" in r for r in rules))


class TestRunConf(unittest.TestCase):

    def test_run_conf_carries_new_vars(self):
        txt = fp.render_run_conf({"probe_mark": "0x10000000/0x10000000",
                                  "ppe_deoffload": "1", "ppe_connskip": 40,
                                  "skip_routed_marks": "0"})
        self.assertIn('PROBE_MARK="0x10000000/0x10000000"', txt)
        self.assertIn('PPE_DEOFFLOAD="1"', txt)
        self.assertIn('PPE_CONNSKIP="40"', txt)
        self.assertIn('SKIP_ROUTED_MARKS="0"', txt)


if __name__ == "__main__":
    unittest.main()
