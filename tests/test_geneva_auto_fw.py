# tests/test_geneva_auto_fw.py
"""
Применение групп режима «Авто» geneva: правила firewall
(core/geneva_auto_fw.py — golden-тексты nft и iptables), распределение
очередей и Applier (core/geneva_auto_apply.py), процессы групп в
GenevaManager против заглушки geneva.

Golden-текст nft проверен настоящим ``nft -c -f`` (с ``accept`` вместо
``queue``: в ядре контейнера CI нет nft_queue), команды iptables —
настоящим iptables в отдельном сетевом namespace.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from core import geneva_auto as ga
from core import geneva_auto_apply as ap
from core import geneva_auto_fw as fw
from tests.test_geneva_manager import _StubCase, wait_for

S1 = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"
S2 = "[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \\/"


def groups():
    g1 = ga.Group(S1, ["web:site.example", "dns:93.184.216.53"], [
        ga.Target(addresses=["93.184.216.7", "2a00:1450::1"],
                  tcp_ports="443-444,8443"),
        ga.Target(addresses=["93.184.216.53"], tcp_ports="53",
                  udp_ports="53")])
    g2 = ga.Group(S2, ["port:udp:192.168.1.10:6881"], [
        ga.Target(by_local_port=True, client="192.168.1.10",
                  udp_ports="6881")])
    return {340: g1, 341: g2}


NFT_GOLDEN = """\
table inet zapret_geneva_auto
delete table inet zapret_geneva_auto
table inet zapret_geneva_auto {
\tset geneva_auto_340_0_v4 {
\t\ttype ipv4_addr
\t\tflags timeout
\t\ttimeout 7d
\t\telements = { 93.184.216.7 }
\t}
\tset geneva_auto_340_0_v6 {
\t\ttype ipv6_addr
\t\tflags timeout
\t\ttimeout 7d
\t\telements = { 2a00:1450::1 }
\t}
\tset geneva_auto_340_1_v4 {
\t\ttype ipv4_addr
\t\tflags timeout
\t\ttimeout 7d
\t\telements = { 93.184.216.53 }
\t}
\tchain post {
\t\ttype filter hook postrouting priority 151; policy accept;
\t\tmeta mark & 0x20000000 == 0x20000000 return
\t\ttcp sport 30000-30543 return
\t\tudp sport 30000-30543 return
\t\tip daddr @geneva_auto_340_0_v4 tcp dport { 443-444, 8443 } ct original packets 1-12 queue num 340 bypass
\t\tip6 daddr @geneva_auto_340_0_v6 tcp dport { 443-444, 8443 } ct original packets 1-12 queue num 340 bypass
\t\tip daddr @geneva_auto_340_1_v4 tcp dport { 53 } ct original packets 1-12 queue num 340 bypass
\t\tip daddr @geneva_auto_340_1_v4 udp dport { 53 } ct original packets 1-12 queue num 340 bypass
\t\tmeta l4proto udp ct original ip saddr 192.168.1.10 ct original proto-src 6881 ct direction original ct original packets 1-12 queue num 341 bypass
\t}
\tchain pre {
\t\ttype filter hook prerouting priority -149; policy accept;
\t\tmeta mark & 0x20000000 == 0x20000000 return
\t\ttcp dport 30000-30543 return
\t\tudp dport 30000-30543 return
\t\tip saddr @geneva_auto_340_0_v4 tcp sport { 443-444, 8443 } ct reply packets 1-6 queue num 340 bypass
\t\tip6 saddr @geneva_auto_340_0_v6 tcp sport { 443-444, 8443 } ct reply packets 1-6 queue num 340 bypass
\t\tip saddr @geneva_auto_340_1_v4 tcp sport { 53 } ct reply packets 1-6 queue num 340 bypass
\t\tip saddr @geneva_auto_340_1_v4 udp sport { 53 } ct reply packets 1-6 queue num 340 bypass
\t\tmeta l4proto udp ct original ip saddr 192.168.1.10 ct original proto-src 6881 ct direction reply ct reply packets 1-6 queue num 341 bypass
\t}
}
"""


class TestNftRules(unittest.TestCase):

    def test_golden(self):
        self.assertEqual(fw.build_auto_rules(groups(), "nft"), NFT_GOLDEN)

    def test_no_addresses_means_no_catch_all(self):
        """Цель без адресов не даёт правила «все порты в geneva»."""
        g = ga.Group(S1, ["web:x"], [ga.Target(addresses=[],
                                               tcp_ports="443")])
        text = fw.build_auto_rules({340: g}, "nft")
        self.assertNotIn("queue", text)
        self.assertNotIn("1-65535", text)

    def test_ipv6_client_by_local_port(self):
        g = ga.Group(S2, ["port:udp:2a02:6b8::5:6881"], [
            ga.Target(by_local_port=True, client="2a02:6b8::5",
                      udp_ports="6881")])
        self.assertIn("ct original ip6 saddr 2a02:6b8::5",
                      fw.build_auto_rules({340: g}, "nft"))

    @unittest.skipUnless(shutil.which("nft"), "нет nft")
    def test_real_nft_accepts_syntax(self):
        text = fw.build_auto_rules(groups(), "nft")
        for q in (340, 341):
            text = text.replace("queue num %d bypass" % q, "accept")
        with tempfile.NamedTemporaryFile("w", suffix=".nft",
                                         delete=False) as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        r = subprocess.run(["nft", "-c", "-f", f.name], capture_output=True,
                           text=True)
        if r.returncode != 0 and "Operation not permitted" in r.stderr:
            self.skipTest("nft -c без прав")
        self.assertEqual(r.returncode, 0, r.stderr)


class TestIptablesRules(unittest.TestCase):

    def test_sets_swapped_atomically(self):
        cmds = [" ".join(c) for c, _ in fw.ipt_commands(groups())]
        i = cmds.index("ipset create geneva_auto_340_0_v4 hash:ip family "
                       "inet timeout 604800 -exist")
        self.assertEqual(cmds[i + 2], "ipset flush geneva_auto_340_0_v4_t")
        self.assertEqual(cmds[i + 3],
                         "ipset add geneva_auto_340_0_v4_t 93.184.216.7 "
                         "-exist")
        self.assertEqual(cmds[i + 4], "ipset swap geneva_auto_340_0_v4_t "
                                      "geneva_auto_340_0_v4")

    def test_golden_rules(self):
        text = fw.build_auto_rules(groups(), "iptables")
        expected = [
            "iptables -t mangle -I POSTROUTING 1 -j ZGGA_POST",
            "iptables -t mangle -A ZGGA_POST -m mark --mark "
            "0x20000000/0x20000000 -j RETURN",
            "iptables -t mangle -A ZGGA_POST -p tcp --sport 30000:30543 "
            "-j RETURN",
            "iptables -t mangle -A ZGGA_POST -p tcp -m set --match-set "
            "geneva_auto_340_0_v4 dst --dport 443:444 -m connbytes "
            "--connbytes-dir original --connbytes-mode packets --connbytes "
            "1:12 -j NFQUEUE --queue-num 340 --queue-bypass",
            "iptables -t mangle -A ZGGA_POST -p tcp -m set --match-set "
            "geneva_auto_340_0_v4 dst --dport 8443 -m connbytes "
            "--connbytes-dir original --connbytes-mode packets --connbytes "
            "1:12 -j NFQUEUE --queue-num 340 --queue-bypass",
            "iptables -t mangle -A ZGGA_PRE -p udp -m set --match-set "
            "geneva_auto_340_1_v4 src --sport 53 -m connbytes "
            "--connbytes-dir reply --connbytes-mode packets --connbytes 1:6 "
            "-j NFQUEUE --queue-num 340 --queue-bypass",
            "iptables -t mangle -A ZGGA_POST -p udp -m conntrack "
            "--ctorigsrc 192.168.1.10 --ctorigsrcport 6881 --ctdir ORIGINAL "
            "-m connbytes --connbytes-dir original --connbytes-mode packets "
            "--connbytes 1:12 -j NFQUEUE --queue-num 341 --queue-bypass",
            "iptables -t mangle -A ZGGA_PRE -p udp -m conntrack "
            "--ctorigsrc 192.168.1.10 --ctorigsrcport 6881 --ctdir REPLY "
            "-m connbytes --connbytes-dir reply --connbytes-mode packets "
            "--connbytes 1:6 -j NFQUEUE --queue-num 341 --queue-bypass",
            "ip6tables -t mangle -A ZGGA_POST -p tcp -m set --match-set "
            "geneva_auto_340_0_v6 dst --dport 443:444 -m connbytes "
            "--connbytes-dir original --connbytes-mode packets --connbytes "
            "1:12 -j NFQUEUE --queue-num 340 --queue-bypass",
        ]
        lines = text.splitlines()
        for line in expected:
            self.assertIn(line, lines)
        # IPv4-клиент DHT — только в iptables, набора v6 у DNS нет
        self.assertFalse(any(l.startswith("ip6tables") and
                             ("192.168.1.10" in l or "_340_1_v6" in l)
                             for l in lines))
        # пропуск метки — до первой очереди в каждой цепочке
        post = [l for l in lines if l.startswith("iptables -t mangle -A "
                                                 "ZGGA_POST")]
        self.assertIn("--mark", post[0])

    def test_teardown(self):
        cmds = [" ".join(c) for c, _ in fw.teardown_commands(
            "iptables", ["geneva_auto_340_0_v4", "other_set",
                         "geneva_auto_341_0_v6"])]
        self.assertIn("iptables -t mangle -D POSTROUTING -j ZGGA_POST", cmds)
        self.assertIn("ip6tables -t mangle -X ZGGA_PRE", cmds)
        self.assertIn("ipset destroy geneva_auto_340_0_v4", cmds)
        self.assertNotIn("ipset destroy other_set", cmds)
        self.assertEqual(fw.teardown_commands("nft"), [
            (["nft", "delete", "table", "inet", "zapret_geneva_auto"],
             False)])
        self.assertTrue(all(not must for _c, must in
                            fw.teardown_commands("iptables", ["x"])))


class TestFwApply(unittest.TestCase):

    def setUp(self):
        self.calls = []

        def run(argv, stdin=None):
            self.calls.append((argv, stdin))
            return True, ""

        p = mock.patch.object(fw, "_run", run)
        p.start()
        self.addCleanup(p.stop)

    def test_nft_one_atomic_script(self):
        with mock.patch.object(fw.shutil, "which", return_value="/x"):
            r = fw.apply(groups(), backend="nft")
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], ["nft", "-f", "-"])
        self.assertEqual(self.calls[0][1], NFT_GOLDEN)

    def test_empty_plan_removes(self):
        r = fw.apply({}, backend="nft")
        self.assertTrue(r["ok"])
        self.assertEqual(self.calls[0][0][:3], ["nft", "delete", "table"])

    def test_iptables_without_ipset_is_clear_error(self):
        fwm = mock.Mock()
        fwm._connbytes_supported.return_value = True
        with mock.patch("core.firewall.get_firewall_manager",
                        return_value=fwm), \
                mock.patch.object(fw.shutil, "which",
                                  side_effect=lambda n: None
                                  if n == "ipset" else "/x"):
            r = fw.apply(groups(), backend="iptables")
        self.assertFalse(r["ok"])
        self.assertIn("ipset", r["error"])
        self.assertIn("opkg install ipset", r["hint"])
        self.assertEqual(self.calls, [])

    def test_iptables_without_connbytes_is_clear_error(self):
        fwm = mock.Mock()
        fwm._connbytes_supported.return_value = False
        with mock.patch("core.firewall.get_firewall_manager",
                        return_value=fwm), \
                mock.patch.object(fw.shutil, "which", return_value="/x"):
            r = fw.apply(groups(), backend="iptables")
        self.assertFalse(r["ok"])
        self.assertIn("connbytes", r["error"])
        self.assertIn("conntrack-extra", r["hint"])

    def test_iptables_failure_rolls_back(self):
        fwm = mock.Mock()
        fwm._connbytes_supported.return_value = True

        def run(argv, stdin=None):
            self.calls.append((argv, stdin))
            if argv[:2] == ["iptables", "-t"] and "NFQUEUE" in argv:
                return False, "No chain/target/match by that name"
            return True, ""

        with mock.patch("core.firewall.get_firewall_manager",
                        return_value=fwm), \
                mock.patch.object(fw.shutil, "which", return_value="/x"), \
                mock.patch.object(fw, "_run", run):
            r = fw.apply(groups(), backend="iptables")
        self.assertFalse(r["ok"])
        # после ошибки — снятие всего
        self.assertIn(["iptables", "-t", "mangle", "-X", "ZGGA_POST"],
                      [c[0] for c in self.calls])


class TestAssignQueues(unittest.TestCase):

    def g(self, strat):
        return ga.Group(strat, [strat], [ga.Target(addresses=["1.1.1.1"],
                                                   tcp_ports="443")])

    def test_running_strategy_keeps_its_queue(self):
        out = ap.assign_queues([self.g("B"), self.g("A")],
                               {341: "A", 342: "OLD"}, max_groups=4)
        self.assertEqual(out[341].strategy, "A")
        self.assertEqual(out[340].strategy, "B")
        self.assertNotIn(342, out)

    def test_stale_queue_reused_only_after_free(self):
        out = ap.assign_queues([self.g("N1"), self.g("N2")],
                               {340: "OLD"}, max_groups=2)
        self.assertEqual(out[341].strategy, "N1")
        self.assertEqual(out[340].strategy, "N2")

    def test_max_groups(self):
        out = ap.assign_queues([self.g(x) for x in "ABCDE"], {},
                               max_groups=2)
        self.assertEqual(sorted(out), [340, 341])
        self.assertEqual(ap.assign_queues([self.g("A")], {}, max_groups=99),
                         {340: out[340]})

    def test_rates(self):
        self.assertEqual(ap.rates({"pkts_out": 10, "pkts_in": 5},
                                  {"pkts_out": 30, "pkts_in": 5}, 5.0),
                         {"pkts_out": 4.0, "pkts_in": 0.0})
        self.assertEqual(ap.rates({}, {"pkts_out": 1}, 0), {})


class FakeGM:
    def __init__(self, fail=()):
        self.groups = {}
        self.fail = set(fail)
        self.stopped_all = False

    def auto_groups(self):
        return {q: {"pid": 100 + q, "strategy": s}
                for q, s in self.groups.items()}

    def auto_apply(self, plan):
        out = {}
        for q in list(self.groups):
            if q not in plan:
                del self.groups[q]
        for q, s in plan.items():
            if s in self.fail:
                out[q] = {"pid": None, "action": "error", "error": "exit 4"}
                continue
            action = "kept" if self.groups.get(q) == s else "started"
            self.groups[q] = s
            out[q] = {"pid": 100 + q, "action": action}
        return {"ok": not any(r["action"] == "error" for r in out.values()),
                "queues": out}

    def auto_stop_all(self):
        self.groups = {}
        self.stopped_all = True

    def auto_stats(self, q):
        return {"ok": True, "pkts_out": 50, "pkts_in": 20}


class FakeFW:
    def __init__(self, ok=True):
        self.ok = ok
        self.applied = []
        self.removed = 0

    def apply(self, queues):
        self.applied.append(dict(queues))
        if not self.ok:
            return {"ok": False, "error": "нет ipset", "hint": "opkg"}
        return {"ok": True, "backend": "nft"}

    def remove(self):
        self.removed += 1


def svc(key, strategy, ip, kind=ga.WEB, status=ga.APPLIED):
    return ga.Service(key=key, kind=kind, name=key, status=status,
                      strategy=strategy,
                      addresses=[{"ip": ip, "seen": 1}], ports=[443])


class TestApplier(unittest.TestCase):

    def test_trial_group_only_on_its_service(self):
        gmf, fwf = FakeGM(), FakeFW()
        a = ap.Applier(geneva=gmf, fw=fwf, max_groups=4)
        books = [svc("web:a", S1, "93.184.216.1"),
                 svc("dns:b", None, "93.184.216.53", kind=ga.DNS,
                     status=ga.SEARCHING)]
        r = a.apply_services(books, trial=(books[1], S2))
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["trial_ok"])
        # пробная стратегия — первой, на первой очереди
        self.assertEqual(gmf.groups[340], S2)
        trial_group = fwf.applied[-1][340]
        self.assertEqual(trial_group.services, ["dns:b"])
        self.assertEqual(trial_group.targets[0].addresses,
                         ["93.184.216.53"])

    def test_trial_not_ok_when_process_failed(self):
        gmf, fwf = FakeGM(fail={S2}), FakeFW()
        a = ap.Applier(geneva=gmf, fw=fwf)
        s = svc("dns:b", None, "93.184.216.53", kind=ga.DNS,
                status=ga.SEARCHING)
        r = a.apply_services([s], trial=(s, S2))
        self.assertFalse(r["trial_ok"])
        self.assertEqual(fwf.applied[-1], {})       # правил на мёртвую нет

    def test_firewall_error_means_nothing_live(self):
        a = ap.Applier(geneva=FakeGM(), fw=FakeFW(ok=False))
        s = svc("web:a", None, "93.184.216.1", status=ga.SEARCHING)
        r = a.apply_services([s], trial=(s, S1))
        self.assertFalse(r["ok"])
        self.assertFalse(r["trial_ok"])
        self.assertEqual(r["hint"], "opkg")

    def test_kept_process_on_address_change(self):
        gmf, fwf = FakeGM(), FakeFW()
        a = ap.Applier(geneva=gmf, fw=fwf)
        s = svc("web:a", S1, "93.184.216.1")
        a.apply_services([s])
        s.addresses.append({"ip": "93.184.216.2", "seen": 2})
        r = a.apply_services([s])
        self.assertEqual(r["queues"][340]["action"], "kept")
        self.assertEqual(fwf.applied[-1][340].targets[0].addresses,
                         ["93.184.216.1", "93.184.216.2"])

    def test_clear_and_stats(self):
        gmf, fwf = FakeGM(), FakeFW()
        t = [100.0]
        a = ap.Applier(geneva=gmf, fw=fwf, clock=lambda: t[0])
        a.apply_services([svc("web:a", S1, "93.184.216.1")])
        first = a.stats()[340]
        self.assertTrue(first["ok"])
        self.assertNotIn("rate", first)
        t[0] = 105.0
        self.assertEqual(a.stats()[340]["rate"]["pkts_out"], 0.0)
        a.clear()
        self.assertEqual(fwf.removed, 1)
        self.assertTrue(gmf.stopped_all)
        self.assertEqual(a.queues, {})


class TestManagerGroups(_StubCase):

    def test_lifecycle(self):
        r = self.mgr.auto_apply({340: S1, 341: S2})
        self.assertTrue(r["ok"], r)
        self.assertEqual({q: v["action"] for q, v in r["queues"].items()},
                         {340: "started", 341: "started"})
        self.assertEqual({q: v["strategy"] for q, v in
                          self.mgr.auto_groups().items()}, {340: S1, 341: S2})
        call = [c for c in self.calls() if c.startswith("run")][0]
        for part in ("-q 340", "--firewall none", "-p 1-65535",
                     "--proto tcp,udp", "--stats-interval 5"):
            self.assertIn(part, call)
        # одиночный geneva run — не эти процессы
        self.assertFalse(self.mgr.is_running())

        # та же стратегия — процесс не трогается; другая — на лету
        pid340 = self.mgr.auto_group_pid(340)
        r = self.mgr.auto_apply({340: S1, 341: S1.replace("-1", "8")})
        self.assertEqual(r["queues"][340]["action"], "kept")
        self.assertEqual(r["queues"][341]["action"], "switched")
        self.assertEqual(self.mgr.auto_group_pid(340), pid340)

        stats = self.mgr.auto_stats(340)
        self.assertTrue(stats["ok"])
        self.assertEqual(stats["pkts_out"], 120)

        # упавший поднимается, лишний останавливается
        os.kill(pid340, 9)
        self.assertTrue(wait_for(lambda: not self.mgr.auto_group_pid(340)))
        r = self.mgr.auto_apply({340: S1})
        self.assertEqual(r["queues"][340]["action"], "started")
        self.assertEqual(r["queues"][341]["action"], "stopped")
        self.assertEqual(list(self.mgr.auto_groups()), [340])

        self.mgr.auto_stop_all()
        self.assertEqual(self.mgr.auto_groups(), {})

    def test_bad_queue_and_crash_on_start(self):
        r = self.mgr.auto_apply({310: S1})
        self.assertFalse(r["ok"])
        with mock.patch.dict(os.environ, {"GENEVA_STUB_RUN_FAIL": "4"}):
            r = self.mgr.auto_apply({340: S1})
        self.assertFalse(r["ok"])
        self.assertIn("нет прав", r["queues"][340]["error"])
        self.assertEqual(self.mgr.auto_groups(), {})


if __name__ == "__main__":
    unittest.main()
