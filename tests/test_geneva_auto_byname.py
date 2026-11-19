# tests/test_geneva_auto_byname.py
"""
Применение по имени (geneva_c 2.0: ext_profile, ext_lists, очередь 348)
и детектор geneva (ext_auto, очередь 349) в режиме «Авто» — как
AutoPlan.HostProfiles и GenevaManager.ApplyHostAsync Zapret2_AutoTuner.
"""

import json
import os
import unittest
from unittest import mock

from core import geneva_auto as ga
from core import geneva_auto_apply as ap
from core import geneva_auto_fw as fw
from core import geneva_manager as gm
from core import geneva_rate as gr
from tests.test_geneva_auto_fw import FakeFW, FakeGM
from tests.test_geneva_auto_manager import _Base
from tests.test_geneva_manager import _StubCase, wait_for

S1 = r"[TCP:flags:PA]-fragment{tcp:-1:True}-| \/"
S2 = r"[TCP:flags:PA]-fragment{tcp:8:True}-| \/"


def svc(key, status=ga.APPLIED, strategy=S1, kind=ga.WEB, ports=(443,),
        ips=("203.0.113.5",)):
    s = ga.Service(key=key, kind=kind,
                   transport="udp" if kind == ga.QUIC else "tcp",
                   status=status, strategy=strategy, ports=list(ports),
                   addresses=[{"ip": ip, "seen": 1.0} for ip in ips])
    s.name = key.split(":", 1)[1]
    return s


class TestHostProfiles(unittest.TestCase):

    def test_group_by_strategy_most_sites_first(self):
        a, b = svc("web:a.example"), svc("web:b.example")
        c = svc("web:c.example", strategy=S2)
        profs = ga.host_profiles([c, b, a])
        self.assertEqual([p["strategy"] for p in profs], [S1, S2])
        self.assertEqual(profs[0]["domains"], ["a.example", "b.example"])
        self.assertEqual(profs[0]["services"], ["web:b.example",
                                                "web:a.example"])

    def test_family_domains_unless_busy(self):
        yt = svc("web:youtube.com")
        own = svc("web:googlevideo.com", status=ga.SEARCHING, strategy=None)
        doms = ga.host_profiles([yt, own])[0]["domains"]
        self.assertEqual(doms[0], "youtube.com")
        self.assertIn("ytimg.com", doms)
        self.assertNotIn("googlevideo.com", doms)
        self.assertEqual(ga.host_profiles([yt], families=False)[0]
                         ["domains"], ["youtube.com"])

    def test_trial_quic_and_limits(self):
        a = svc("web:a.example")
        q = svc("quic:a.example", kind=ga.QUIC)
        self.assertEqual(ga.host_profiles([a], trial_keys=["web:a.example"]),
                         [])
        self.assertEqual(len(ga.host_profiles([a, q])), 1)
        profs = ga.host_profiles([a, q], quic=True)
        self.assertEqual(sorted(p["udp"] for p in profs), [False, True])
        many = [svc("web:s%d.example" % i, strategy=S1.replace(
            "-1", str(i))) for i in range(30)]
        self.assertEqual(len(ga.host_profiles(many)), ga.MAX_HOST_PROFILES)

    def test_covers_only_80_443_sites(self):
        a, b = svc("web:a.example"), svc("web:b.example", ports=(8443,))
        profs = ga.host_profiles([a, b])
        self.assertEqual(ga.by_name_covers([a, b], profs), {"web:a.example"})


class TestHostRule(unittest.TestCase):

    def test_after_groups_and_counted(self):
        g = ga.plan_groups([svc("web:a.example")])[0]
        rules = {340: g, 348: fw.HostRule(udp=True)}
        nft = fw.build_auto_rules(rules)
        post = nft.split("chain post")[1].split("}")[1:]
        text = nft.split("chain post")[1]
        self.assertLess(text.index("queue num 340"),
                        text.index("queue num 348"))
        self.assertIn("udp dport { 443 } ct original packets 1-12 "
                      "queue num 348 bypass", nft)
        self.assertTrue(post)
        want = fw.expected({348: fw.HostRule()})["rules"]
        # tcp 80 и 443 в обе стороны
        self.assertEqual(want[("iptables", fw.CHAIN_POST)], 3 + 2)
        self.assertEqual(want[("iptables", fw.CHAIN_PRE)], 3 + 2)


class HostGM(FakeGM):
    def __init__(self):
        super().__init__()
        self.host_calls = []
        self.host_pid = None

    def auto_host_apply(self, profiles, exclude_ips, exclude_domains):
        self.host_calls.append((profiles, exclude_ips, exclude_domains))
        self.host_pid = 4800
        r = {"ok": True, "pid": 4800, "action": "started",
             "udp": any(p["udp"] for p in profiles)}
        if hasattr(self, "loaded"):
            r["services"] = self.loaded
        return r

    def auto_host_pid(self):
        return self.host_pid

    def auto_host_stop(self):
        self.host_pid = None


class TestApplierHost(unittest.TestCase):

    def test_host_rule_and_group_addresses_excluded(self):
        gmf, fwf = HostGM(), FakeFW()
        a = ap.Applier(geneva=gmf, fw=fwf)
        a.fwm = fw
        fwf.HostRule = fw.HostRule
        s = svc("web:a.example")
        profs = ga.host_profiles([s])
        res = a.apply_services([s], hosts={"profiles": profs,
                                           "exclude_ips": ["10.0.0.0/8"],
                                           "exclude_domains": ["bank.ru"]})
        self.assertTrue(res["ok"])
        self.assertEqual(res["host"]["pid"], 4800)
        _, ips, doms = gmf.host_calls[-1]
        self.assertEqual(ips, ["10.0.0.0/8", "203.0.113.5"])
        self.assertEqual(doms, ["bank.ru"])
        self.assertEqual(fwf.applied[-1][348], fw.HostRule(False))
        # выключено — процесс стоп, правила без 348
        a.apply_services([s], hosts=None)
        self.assertIsNone(gmf.host_pid)
        self.assertNotIn(348, fwf.applied[-1])


class TestManagerByNameAndDetector(_Base):

    def setUp(self):
        super().setUp()
        self.hgm = HostGM()
        self.fwf.HostRule = fw.HostRule
        self.applier = ap.Applier(geneva=self.hgm, fw=self.fwf)

    def test_by_name_profiles_and_covers(self):
        m = self.manager()
        m.load()
        m.book._services["web:a.example"] = svc("web:a.example")
        m._apply(101.0)
        self.assertEqual(self.hgm.host_calls[-1][0][0]["domains"],
                         ["a.example"])
        self.assertEqual(m.book.by_name, {"web:a.example"})
        self.assertEqual(m.status()["by_name"], True)
        # процесс не загрузил профиль сайта — сайт не покрыт
        self.hgm.loaded = []
        m._applied_sig = None
        m._apply(102.0)
        self.assertEqual(m.book.by_name, set())
        del self.hgm.loaded
        m._applied_sig = None
        m._apply(102.5)
        self.cfg.set("geneva", "auto", {"by_name": False})
        m._apply(102.0)
        self.assertEqual(m.book.by_name, set())
        self.assertIsNone(self.hgm.host_pid)

    def test_detector_marks_and_capacity(self):
        m = self.manager()
        m.load()
        s = svc("web:slow.example", status=ga.WATCHING, strategy=None)
        m.book._services[s.key] = s
        self.gm.auto_observer_ensure.return_value = {"ok": True, "pid": 77}
        self.gm.auto_observer_status.return_value = {
            "ok": True, "capacity": 5_000_000, "impaired": [
                {"key": "slow.example", "level": "host", "impaired": True,
                 "class": "THROTTLE"},
                {"key": "slow.example", "level": "host", "impaired": True,
                 "class": "DNS_POISON"},
                {"key": "evil.example", "level": "host", "impaired": True,
                 "class": "DNS_POISON"},      # не наш сервис — молчим
                {"key": "tcp/443", "level": "port", "impaired": True,
                 "class": "RETRANS"}]}
        cap = gr.LinkCapacity(clock=lambda: 101.0)
        with mock.patch.object(gr, "SHARED", cap):
            m._detector(101.0)
        self.assertEqual(cap.current(101.0), 5_000_000)
        self.assertEqual(m.book.find(s.key).detected, [101.0])
        text = " ".join(j.get("text", "") for j in m.journal)
        self.assertIn("DoH", text)
        self.assertNotIn("evil.example", text)
        self.assertIn("slow.example", text)
        # DoH — раз в час на имя
        with mock.patch.object(gr, "SHARED", cap):
            m._detector(160.0)
        text = [j.get("text", "") for j in m.journal]
        self.assertEqual(sum("DoH" in x for x in text), 1)

    def test_detector_unsupported_is_quiet(self):
        m = self.manager()
        m.load()
        self.gm.auto_observer_ensure.return_value = {
            "ok": True, "pid": None, "action": "unsupported"}
        m._detector(101.0)
        self.assertEqual(m.detector["supported"], False)
        self.gm.auto_observer_status.assert_not_called()


class TestHostProcess(_StubCase):
    """Процесс «по имени» и детектор на заглушке geneva."""

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"GENEVA_STUB_EXT": "1",
                                         "GENEVA_STUB_LISTS": "1"})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.mgr.auto_host_stop)
        self.addCleanup(self.mgr.auto_observer_stop)

    def profs(self, strategy=S1, domains=("a.example",)):
        return [{"strategy": strategy, "udp": False,
                 "domains": list(domains), "services": ["web:a.example"]}]

    def test_start_reload_restart_stop(self):
        r = self.mgr.auto_host_apply(self.profs(), ["203.0.113.5"],
                                     ["bank.example"])
        self.assertEqual(r["action"], "started", r)
        hp = gm.auto_host_paths()
        ini = open(hp["profiles"]).read()
        self.assertIn("[profile p0]", ini)
        self.assertIn("filter-l7 = tls,http", ini)
        run = [c for c in self.calls() if c.startswith("run ")][-1]
        self.assertIn("--ext-profile", run)
        self.assertIn("-q 348", run)
        self.assertIn("--ext-ipcache-hostname", run)
        self.assertIn("203.0.113.5", open(hp["exclude_ip"]).read())
        # новые имена — reload_lists без перезапуска
        r2 = self.mgr.auto_host_apply(self.profs(domains=("a.example",
                                                           "b.example")))
        self.assertEqual((r2["action"], r2["pid"]), ("reloaded", r["pid"]))
        self.assertIn("b.example", open(os.path.join(hp["dir"],
                                                     "hosts-0.txt")).read())
        # другая стратегия — перезапуск
        r3 = self.mgr.auto_host_apply(self.profs(strategy=S2))
        self.assertEqual(r3["action"], "started")
        self.assertNotEqual(r3["pid"], r["pid"])
        # пусто — стоп
        self.assertEqual(self.mgr.auto_host_apply([])["action"], "stopped")
        self.assertIsNone(self.mgr.auto_host_pid())

    def test_needs_ext_profile(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_LISTS": "0"}):
            self.mgr._version_cache = {}
            r = self.mgr.auto_host_apply(self.profs())
        self.assertEqual(r["action"], "unsupported")

    def test_observer(self):
        imp = [{"key": "x.example", "level": "host", "impaired": True,
                "class": "THROTTLE"}]
        with mock.patch.dict(os.environ, {
                "GENEVA_STUB_IMPAIRED": json.dumps(imp),
                "GENEVA_STUB_CAPACITY": "1000000"}):
            r = self.mgr.auto_observer_ensure()
            self.assertEqual(r["action"], "started", r)
            self.assertEqual(self.mgr.auto_observer_ensure()["action"],
                             "kept")
            wait_for(lambda: self.mgr.auto_observer_status().get("ok"), 5)
            st = self.mgr.auto_observer_status()
        self.assertEqual(st["impaired"], imp)
        self.assertEqual(st["capacity"], 1000000)
        run = [c for c in self.calls() if "--ext-auto" in c][-1]
        self.assertIn("-q 349", run)
        self.assertIn("-p 9", run)
        self.mgr.auto_observer_stop()
        self.assertIsNone(self.mgr.auto_observer_pid())


if __name__ == "__main__":
    unittest.main()
