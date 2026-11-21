# tests/test_geneva_related.py
"""
Перенос AutoTuner 1.5 в «Авто» и ручной подбор geneva:

* связанные ресурсы сайта (core/geneva_related.py) и их проверка в
  подборе «Авто» (AutoSearch._check_related, менеджер — пробная
  стратегия по имени и на семейство);
* семейство по самому хосту (geneva_auto_lists.service_family);
* итоговая проверка ручного подбора (core/geneva_final_check.py,
  GenevaManager._start_final, «Найденные»);
* сколько проверяется сейчас (ExternalAnswerer.counters, строки подбора).

Без root и сети: фейки geneva, проб и менеджера.
"""

import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from core import geneva_auto as ga
from core import geneva_auto_lists as gal
from core import geneva_auto_probes as pr
from core import geneva_auto_search as gs
from core import geneva_final_check as gfc
from core import geneva_manager as gm
from core import geneva_related as grel
from tests.test_geneva_auto_search import (FakeGeneva, FakeProbes, _FakeProc,
                                           web_service)
from tests.test_geneva_manager import wait_for


def yt_service(**kw):
    base = dict(key="web:youtube.com", kind=ga.WEB, transport="tcp",
                name="youtube.com", host="www.youtube.com",
                addresses=[{"ip": "93.184.216.9", "seen": 1}], ports=[443],
                status=ga.BLOCKED)
    base.update(kw)
    return ga.Service(**base)


class TestFamilyByHost(unittest.TestCase):

    def test_host_decides(self):
        s = web_service(key="web:googleapis.com", name="googleapis.com",
                        host="youtubei.googleapis.com")
        self.assertEqual(gal.service_family(s), "YouTube")
        # другой хост того же домена — не YouTube
        s.host = "storage.googleapis.com"
        self.assertIsNone(gal.service_family(s))

    def test_without_host_by_site_and_address_has_none(self):
        s = yt_service(host="")
        self.assertEqual(gal.service_family(s), "YouTube")
        s = web_service(key="web:93.184.216.7", name="93.184.216.7",
                        host="93.184.216.7")
        self.assertIsNone(gal.service_family(s))

    def test_family_host_is_sticky(self):
        # хост с семейством не уступает хосту без него: семейство
        # googleapis.com не мигает от наблюдения к наблюдению
        self.assertTrue(ga._family_kept("youtubei.googleapis.com",
                                        "fonts.googleapis.com"))
        self.assertFalse(ga._family_kept("fonts.googleapis.com",
                                         "youtubei.googleapis.com"))
        self.assertFalse(ga._family_kept("", "fonts.googleapis.com"))
        self.assertFalse(ga._family_kept("www.youtube.com", "m.youtube.com"))


class TestPure(unittest.TestCase):

    def test_site_and_family(self):
        doms = grel.site_and_family("www.youtube.com")
        self.assertEqual(doms[0], "youtube.com")
        self.assertIn("googlevideo.com", doms)
        # хост семейства без всего домена: сам хост, не googleapis.com
        doms = grel.site_and_family("youtubei.googleapis.com")
        self.assertEqual(doms[0], "youtubei.googleapis.com")
        self.assertNotIn("googleapis.com", doms)
        self.assertEqual(grel.site_and_family("rutracker.org"),
                         ["rutracker.org"])
        self.assertEqual(grel.site_and_family("93.184.216.7"), [])
        self.assertEqual(grel.registrable("a.b.example.co.uk"),
                         "example.co.uk")

    def test_hosts_to_check(self):
        doms = grel.site_and_family("www.youtube.com")
        seen = [("rr3---sn-abc.googlevideo.com", "1.2.3.4"),
                ("www.youtube.com", "5.6.7.8")]
        got = grel.hosts_to_check(doms, seen, own="www.youtube.com")
        names = [h for h, _ in got]
        # сам сайт не проверяется, увиденное устройствами — первым
        self.assertNotIn("www.youtube.com", names)
        self.assertNotIn("youtube.com", names)
        self.assertEqual(got[0], ("rr3---sn-abc.googlevideo.com", "1.2.3.4"))
        self.assertIn(("i.ytimg.com", ""), got)
        self.assertLessEqual(len(got), grel.MAX_HOSTS)
        self.assertEqual(grel.hosts_to_check(["rutracker.org"], (),
                                             own="rutracker.org"), [])

    def test_judge_and_summary(self):
        ok = pr.PageResult(connect_ok=True, tls_ok=True, status=404)
        reset = pr.PageResult(connect_ok=True, error=pr.P_TLS_RESET)
        alien = pr.PageResult(connect_ok=True, tls_ok=True,
                              cert_valid=False)
        national = pr.PageResult(connect_ok=True, tls_ok=True,
                                 cert_valid=False, untrusted_root=True)
        down = pr.PageResult(error=pr.P_CONNECT_TIMEOUT)
        self.assertEqual(grel.judge(ok), grel.OK)
        self.assertEqual(grel.judge(reset), grel.FAILED)
        self.assertEqual(grel.judge(alien), grel.FAILED)
        self.assertEqual(grel.judge(national), grel.NO_VERDICT)
        self.assertEqual(grel.judge(down), grel.NO_VERDICT)
        self.assertEqual(grel.summary([]), (None, ""))
        self.assertEqual(grel.summary([("a", grel.OK, "x"),
                                       ("b", grel.NO_VERDICT, "y")]),
                         (True, "a"))
        self.assertEqual(grel.summary([("a", grel.OK, "x"),
                                       ("b", grel.FAILED, "сброс")]),
                         (False, "b: сброс"))

    def test_trial_families(self):
        yt = yt_service()
        own = web_service(key="web:ytimg.com", name="ytimg.com",
                          host="i.ytimg.com", status=ga.APPLIED,
                          strategy="[TCP:flags:PA]-drop-| \\/")
        other = web_service()
        taken = [{"strategy": "S", "udp": False,
                  "domains": ["ggpht.com"], "services": []}]
        out = grel.trial_families([yt, own, other],
                                  [(yt, "T"), (other, "U")], taken)
        keys = [k for k, _ in out]
        self.assertEqual(keys, ["web:youtube.com", "web:blocked.example"])
        doms = out[0][1]["domains"]
        self.assertEqual(doms[0], "youtube.com")
        self.assertIn("googlevideo.com", doms)
        # своя жизнь в книге и уже названное профилем — не трогаются
        self.assertNotIn("ytimg.com", doms)
        self.assertNotIn("ggpht.com", doms)
        self.assertEqual(out[0][1]["services"], [])
        self.assertEqual(out[1][1]["domains"], ["blocked.example"])

    def test_trial_families_part_of_site(self):
        # семейство не берёт весь googleapis.com: по имени — только хост
        s = web_service(key="web:googleapis.com", name="googleapis.com",
                        host="youtubei.googleapis.com")
        out = grel.trial_families([s], [(s, "T")])
        doms = out[0][1]["domains"]
        self.assertEqual(doms[0], "youtubei.googleapis.com")
        self.assertNotIn("googleapis.com", doms)
        self.assertIn("youtube.com", doms)


class RelatedProbes(FakeProbes):
    """Связанные ресурсы не грузятся со стратегиями из ``broken``."""

    def __init__(self, works=(), broken=()):
        super().__init__(works)
        self.broken = set(broken)
        self.related = []

    def check_related(self, hosts, exclude=None, **kw):
        self.related.append((self.applied, list(hosts)))
        v = grel.FAILED if self.applied in self.broken else grel.OK
        return [(h, v, "сброс" if v == grel.FAILED else "HTTP 200")
                for h, _ in hosts]


class TestSearchRelated(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.paths = {"auto": os.path.join(self.tmp, "auto"),
                      "auto_runtime": os.path.join(self.tmp, "rt")}
        for target, v in (("JOB_POLL", 0.05), ("TRIAL_SETTLE", 0.05)):
            p = mock.patch.object(gs, target, v)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(grel, "SETTLE", 0.01)
        p.start()
        self.addCleanup(p.stop)

    def run_search(self, probes, related, s=None):
        a, b = ("[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/",
                "[TCP:flags:PA]-tamper{TCP:window:replace:2}-| \\/")
        g = FakeGeneva(eval_results=[{"strategy": a, "avg_fitness": 396},
                                     {"strategy": b, "avg_fitness": 390}])

        def trial(svc, strat):
            probes.applied = strat
            return True

        x = gs.AutoSearch(geneva=g, probes=probes, trial=trial,
                          related=related, workers=4,
                          python="/usr/bin/python3", script="/app/p.py",
                          paths=self.paths)
        self.assertTrue(x.start(s or yt_service()))
        self.assertTrue(wait_for(lambda: not x.busy, 10))
        return x, x.result(), a, b

    def test_broken_related_tries_next(self):
        calls = []

        def related(svc, strat):
            calls.append(strat)
            if strat:
                return {"pid": 7, "hosts": [("i.ytimg.com", "")]}
            return {"pid": 7}

        probes = RelatedProbes(broken={
            "[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/"},
            works={"[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/",
                   "[TCP:flags:PA]-tamper{TCP:window:replace:2}-| \\/"})
        _, res, a, b = self.run_search(probes, related)
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, b))
        self.assertEqual(calls, [a, None, b, None])
        self.assertEqual([x for x, _ in probes.related], [a, b])

    def test_restart_of_name_process_is_not_blamed(self):
        gens = iter([2, 3])

        def related(svc, strat):
            # pid тот же (повтор pid), номер запуска — другой
            return {"pid": 7, "gen": 1, "hosts": [("i.ytimg.com", "")]} \
                if strat else {"pid": 7, "gen": next(gens)}

        a = "[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/"
        probes = RelatedProbes(works={a}, broken={a})
        _, res, a, _ = self.run_search(probes, related)
        # запуск до снятия другой — перезапуск: провал не в счёт
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, a))

    def test_stop_during_related_is_not_applied(self):
        holder = []
        orig = gs.AutoSearch.start

        def start(x, s):
            holder.append(x)
            return orig(x, s)

        def related(svc, strat):
            if strat:
                holder[0]._stop.set()   # отмена во время ожидания
                return {"pid": 7, "gen": 1, "hosts": [("i.ytimg.com", "")]}
            return {"pid": 7, "gen": 1}

        a = "[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/"
        probes = RelatedProbes(works={a})
        with mock.patch.object(gs.AutoSearch, "start", start):
            _, res, _, _ = self.run_search(probes, related)
        self.assertNotEqual(getattr(res, "outcome", None), gs.APPLIED)

    def test_switched_off_or_not_a_site(self):
        a = "[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/"
        called = []

        def related(svc, strat):
            called.append(strat)
            return {"pid": 7, "hosts": [("i.ytimg.com", "")]}

        probes = RelatedProbes(works={a}, broken={a})
        x = gs.AutoSearch(related=related)
        x.final_check = False
        self.assertEqual(x._check_related(yt_service(), a), (None, ""))
        self.assertEqual(x._check_related(
            yt_service(ports=[80]), a), (None, ""))
        self.assertEqual(called, [])
        # нет процесса «по имени» — нечего проверять, стратегия принята
        _, res, a, _ = self.run_search(
            probes, lambda svc, strat: None if strat else {"pid": None})
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, a))


class _Cfg:
    def __init__(self, data=None):
        self.data = data or {}

    def get(self, section, key, default=None):
        return self.data.get(section, {}).get(key, default)

    def set(self, section, key, value):
        self.data.setdefault(section, {})[key] = value

    def save(self):
        pass


class TestManagerRelated(unittest.TestCase):

    def test_trial_family_goes_by_name_only_while_checked(self):
        from core import geneva_auto_manager as gam
        cfg = _Cfg({"geneva": {"auto": {"by_name": True}}})
        m = gam.GenevaAutoManager(cfg=cfg, path=os.path.join(
            tempfile.mkdtemp(), "auto.json"))
        yt = yt_service()
        trials = [(yt, "T")]
        self.assertIsNone(m._hosts([yt], trials))
        m._related.add(yt.key)
        hosts = m._hosts([yt], trials)
        self.assertEqual(hosts["related"][yt.key][0], "youtube.com")
        prof = hosts["profiles"][-1]
        self.assertEqual((prof["strategy"], prof["services"]), ("T", []))
        self.assertTrue(gam.auto_settings(cfg)["final_check"])
        cfg.set("geneva", "final_check", False)
        self.assertFalse(gam.auto_settings(cfg)["final_check"])

    def test_related_only_what_process_loaded(self):
        from core import geneva_auto_manager as gam
        cfg = _Cfg({"geneva": {"auto": {"by_name": True}}})
        m = gam.GenevaAutoManager(cfg=cfg, path=os.path.join(
            tempfile.mkdtemp(), "auto.json"))
        yt = yt_service()
        m._related.add(yt.key)
        host = {"pid": 5, "domains": ["youtube.com", "ytimg.com"]}
        fake = mock.Mock(max_groups=4)
        fake.apply_services.return_value = {"host": host}
        with mock.patch.object(m, "applier", return_value=fake):
            m._apply_plan([yt], [(yt, "T")], 1.0)
            self.assertEqual(m._related_sent[yt.key],
                             ["youtube.com", "ytimg.com"])
            host["domains"] = []        # профиль пробы отброшен
            m._apply_plan([yt], [(yt, "T")], 2.0)
            self.assertEqual(m._related_sent, {})


class TestCounters(unittest.TestCase):

    def test_probing_and_checked(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        events = os.path.join(tmp, "e.jsonl")
        proc = _FakeProc()
        self.addCleanup(proc.out.close)
        gate = threading.Event()
        seen = []

        def probe(lports, strategy):
            seen.append(strategy)
            gate.wait(5)
            return 400, "ok"

        a = gm.ExternalAnswerer(proc, events, probe, workers=2,
                                with_strategy=True).start()
        with open(events, "a") as f:
            for i in (1, 2):
                f.write(json.dumps({"ev": "eval_request", "id": i,
                                    "strategy": "S%d" % i, "run": 0,
                                    "lports": "30000-30063"}) + "\n")
        self.assertTrue(wait_for(lambda: a.counters()["probing"] == 2, 5))
        self.assertEqual(a.counters()["workers"], 2)
        gate.set()
        proc.out.readline()
        proc.out.readline()
        self.assertTrue(wait_for(lambda: a.counters()["checked"] == 2, 5))
        self.assertEqual(sorted(seen), ["S1", "S2"])
        proc.code = 0
        self.assertEqual(a.counters()["probing"], 0)

    def test_status_view(self):
        class A:
            def counters(self):
                return {"probing": 3, "workers": 4, "checked": 9}
        v = gm.job_status_view({"status": "running"}, True, A())
        self.assertEqual((v["probing"], v["workers"], v["checked"]),
                         (3, 4, 9))
        v = gm.job_status_view({"status": "done"}, False, A())
        self.assertEqual(v["probing"], 0)


class TestFinalCheck(unittest.TestCase):

    def test_pick_and_target(self):
        res = [{"strategy": "A", "avg_fitness": 300},
               {"strategy": "B", "avg_fitness": 398},
               {"strategy": "C", "avg_fitness": -400},
               {"strategy": "D", "avg_fitness": 100},
               {"strategy": "E", "avg_fitness": 50}]
        self.assertEqual(gfc.pick(res), ["B", "A", "D"])
        self.assertEqual(gfc.pick([{"strategy": "X", "avg_fitness": "?"},
                                   {"strategy": "Y", "avg_fitness": 1}]),
                         ["Y"])
        self.assertEqual(gfc.target_of({"host": "x.org", "probe": "http"}),
                         ("x.org", 80, False))
        self.assertEqual(gfc.target_of({"host": "x.org", "probe": "tls",
                                        "port": 8443}),
                         ("x.org", 8443, True))

    def test_measure(self):
        good = pr.PageResult(connect_ok=True, tls_ok=True, status=200,
                             body=40000, complete=True)
        bad = pr.PageResult(connect_ok=True, error=pr.P_TLS_RESET)

        def page_ok(*a, **kw):
            return good

        def page_bad(*a, **kw):
            return bad

        rel = [("i.ytimg.com", "1.2.3.4")]
        ok = gfc.measure("www.youtube.com", 443, True, "5.6.7.8",
                         (30128, 30191), rel, page=page_ok,
                         related_check=lambda h: [(h[0][0], grel.OK, "")])
        self.assertTrue(ok[0])
        no = gfc.measure("www.youtube.com", 443, True, "5.6.7.8",
                         (30128, 30191), rel, page=page_ok,
                         related_check=lambda h: [(h[0][0], grel.FAILED,
                                                   "сброс")])
        self.assertIs(no[0], False)
        self.assertIn("i.ytimg.com", no[1])
        self.assertIs(gfc.measure("x.org", 443, True, "1.1.1.1", (1, 2),
                                  page=page_bad)[0], False)

    def test_measure_keeps_exclude(self):
        good = pr.PageResult(connect_ok=True, tls_ok=True, status=200,
                             body=40000, complete=True)
        probes = mock.Mock()
        probes.check_related.return_value = [("i.ytimg.com", grel.OK, "")]
        excl = object()
        with mock.patch.object(pr, "get_auto_probes", return_value=probes):
            ok, _ = gfc.measure("www.youtube.com", 443, True, "5.6.7.8",
                                (1, 2), [("i.ytimg.com", "")],
                                page=lambda *a, **kw: good, exclude=excl)
        self.assertTrue(ok)
        self.assertIs(probes.check_related.call_args.kwargs["exclude"], excl)

    def test_finish_survives_final_error(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        restored = []
        m._start_final = mock.Mock(side_effect=RuntimeError("boom"))
        m._restore_paused = lambda st: restored.append(st)
        m._save_search_state = lambda st: None
        m._job_answerer = None
        m._job_proc = object()
        m._pump_job = lambda: None
        st = {"kind": "evolve", "status": "running"}
        m._job_state = st
        with mock.patch.object(gm, "paths", return_value={
                "job_pid": os.devnull + ".none", "job_log": os.devnull,
                "result": os.devnull + ".none"}):
            try:
                m._finish_job(1)
            except Exception as e:          # noqa: BLE001
                self.fail("_finish_job: %r" % e)
        self.assertEqual(len(restored), 1)
        self.assertIsNone(m._job_proc)

    def test_probe_records_verdict(self):
        fc = gfc.FinalCheck(None, ["S"], {"host": "x.org", "probe": "tls"},
                            lambda v: None, address="1.1.1.1")
        with mock.patch.object(gfc, "measure",
                               return_value=(False, "сайт не открылся")):
            self.assertEqual(fc._probe("30128-30191", "S")[0], -400)
        with mock.patch.object(gfc, "measure", return_value=(None, "корень")):
            self.assertEqual(fc._probe("30128-30191", "T")[0], 400)
        self.assertEqual(fc.verdicts["S"]["ok"], False)
        self.assertIsNone(fc.verdicts["T"]["ok"])

    def test_verdicts_reach_found(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        with mock.patch.object(gm, "state_dir", return_value=tmp):
            gm.remember_verdicts({"S": {"ok": True, "detail": "открылся"}},
                                 "https:x.org")
            self.assertTrue(gm.final_verdicts()["S"]["ok"])

    def test_start_final_only_after_manual_evolve(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._final = None
        st = {"kind": "evolve", "status": "done",
              "params": {"host": "x.org", "probe": "tls"},
              "results": [{"strategy": "S", "avg_fitness": 398}]}
        started = []
        with mock.patch("core.geneva_auto_manager.final_check_enabled",
                        return_value=True), \
                mock.patch.object(gm, "_cfg", return_value=_Cfg()), \
                mock.patch.object(gfc.FinalCheck, "start",
                                  lambda self: started.append(self)):
            m._ready_binary = lambda: ("/bin/geneva", "")
            m.features = lambda b="": ["external_workers"]
            self.assertTrue(m._start_final(dict(st)))
            self.assertEqual(started[-1].strategies, ["S"])
            self.assertFalse(m._start_final(dict(st, owner="auto")))
            self.assertFalse(m._start_final(dict(st, kind="eval")))
            self.assertFalse(m._start_final(dict(st, status="stopped")))
            m._final = None
            m.features = lambda b="": []
            self.assertFalse(m._start_final(dict(st)))


class TestLibraryExt(unittest.TestCase):

    def test_ext_first_then_without(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._library_cache = None
        m._ready_binary = lambda: ("/bin/geneva", "")
        m.features = lambda b="": ["ext"]
        calls = []

        class R:
            def __init__(self, code, out):
                self.returncode, self.stdout = code, out

        def run(argv, timeout=10):
            calls.append(argv[2:])
            if "--ext" in argv:
                return R(2, "")
            return R(0, json.dumps([{"strategy": "\\/"}, {"strategy": "X"}]))

        m._run_cmd = run
        res = m._geneva_library(True)
        self.assertEqual([i["strategy"] for i in res["items"]], ["X"])
        self.assertEqual(calls, [["--json", "--ext"], ["--json"]])


if __name__ == "__main__":
    unittest.main()


class TestWorkersUpTo32(unittest.TestCase):

    def test_search_takes_up_to_32(self):
        for n in (16, 32):
            self.assertEqual(gm.validate_search(
                {"host": "x.org", "workers": n}, {})["workers"], n)
        for n in (0, 33):
            with self.assertRaises(ValueError):
                gm.validate_search({"host": "x.org", "workers": n}, {})
        # старое значение из настроек не уронит запуск geneva
        self.assertEqual(gm.geneva_workers(100), "32")
        args = gm.build_evolve_args("/bin/geneva", dict(
            gm.SEARCH_DEFAULTS, host="x.org", workers=16), {
                "checkpoint": "c", "db": "d", "job_events": "e",
                "job_log": "l"})
        self.assertEqual(args[args.index("--workers") + 1], "16")


class TestHostFamilyDoesNotTakeFamilyDomains(unittest.TestCase):

    def test_applied_profile_takes_site_family_only(self):
        g = web_service(key="web:googleapis.com", name="googleapis.com",
                        host="youtubei.googleapis.com", status=ga.APPLIED,
                        strategy="[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/")
        self.assertEqual(gal.service_family(g), "YouTube")
        self.assertIsNone(gal.site_family(g))
        profs = ga.host_profiles([g], [], families=True)
        doms = [d for p in profs for d in p["domains"]]
        self.assertIn("googleapis.com", doms)
        self.assertNotIn("googlevideo.com", doms)


class TestFinalCancel(unittest.TestCase):

    def test_cancelled_before_start_does_not_start(self):
        g = mock.Mock()
        done = []
        fc = gfc.FinalCheck(g, ["S"], {"host": "x.org", "probe": "tls"},
                            done.append, address="1.1.1.1",
                            related=[("a.org", "")])
        fc.cancel()
        with mock.patch("core.geneva_auto_manager.get_geneva_auto_manager",
                        side_effect=RuntimeError):
            fc._main()
        g.start_final_job.assert_not_called()
        self.assertEqual(done, [{}])
