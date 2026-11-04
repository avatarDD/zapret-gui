# tests/test_geneva_auto_search.py
"""
Подбор режима «Авто» geneva (core/geneva_auto_search.py), задания «Авто»
в GenevaManager и проба для ``--probe exec``
(core/geneva_auto_probe_cli.py).

Без root и сети: GenevaManager гоняется против заглушки tests/geneva_stub
(как в test_geneva_manager), AutoSearch — с фейками geneva, проб и
пробной группы, проба exec — против серверов на 127.0.0.1.
"""

import io
import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

from core import geneva_auto as ga
from core import geneva_auto_probes as pr
from core import geneva_auto_search as gs
from core import geneva_manager as gm
from core import geneva_auto_probe_cli as cli
from tests.test_geneva_manager import _StubCase, wait_for


def web_service(**kw):
    base = dict(key="web:blocked.example", kind=ga.WEB, transport="tcp",
                name="blocked.example", host="www.blocked.example",
                addresses=[{"ip": "93.184.216.7", "seen": 1}], ports=[443],
                status=ga.BLOCKED)
    base.update(kw)
    return ga.Service(**base)


def wg_service():
    return ga.Service(key="ep:wireguard:udp:93.184.216.20:51820",
                      kind=ga.ENDPOINT, transport="udp", app="wireguard",
                      name="WireGuard 93.184.216.20:51820",
                      addresses=[{"ip": "93.184.216.20", "seen": 1}],
                      ports=[51820], status=ga.BLOCKED)


class TestPure(unittest.TestCase):

    def test_probe_argv_web(self):
        argv = gs.probe_argv(web_service(), python="/usr/bin/python3",
                             script="/app/core/p.py")
        self.assertEqual(argv[:2], ["/usr/bin/python3", "/app/core/p.py"])
        self.assertIn("{lports}", argv)
        i = argv.index("--host")
        self.assertEqual(argv[i + 1], "www.blocked.example")
        self.assertEqual(argv[argv.index("--tls") + 1], "1")
        self.assertEqual(argv[argv.index("--ip") + 1], "93.184.216.7")

    def test_probe_argv_replay_and_fresh(self):
        s = ga.Service(key="ep:openvpn:udp:x", kind=ga.ENDPOINT,
                       transport="udp", app="openvpn",
                       replay=ga.to_base64([b"\x38abc"]),
                       addresses=[{"ip": "93.184.216.40", "seen": 1}],
                       ports=[1194])
        self.assertIsNone(gs.probe_argv(s, python="p", script="s"))
        argv = gs.probe_argv(s, python="p", script="s",
                             replay_file="/tmp/r.b64")
        self.assertIn("--udp", argv)
        self.assertEqual(argv[argv.index("--replay-file") + 1], "/tmp/r.b64")
        dns = ga.Service(key="dns:93.184.216.53", kind=ga.DNS,
                         transport="udp",
                         addresses=[{"ip": "93.184.216.53", "seen": 1}])
        argv = gs.probe_argv(dns, python="p", script="s")
        self.assertEqual(argv[argv.index("--fresh") + 1], "dns")
        self.assertEqual(argv[argv.index("--port") + 1], "53")
        self.assertIsNone(gs.probe_argv(wg_service(), python="p",
                                        script="s"))

    def test_hostile_host_is_refused(self):
        s = web_service(host="x.org'; rm -rf / #")
        self.assertIsNone(gs.probe_argv(s, python="p", script="s"))

    def test_command_text_keeps_placeholder_one_word(self):
        cmd = gs.command_text(["/usr/bin/python3", "/a b/p.py",
                               "--lports", "{lports}"])
        self.assertIn("'/a b/p.py'", cmd)
        self.assertIn("{lports}", cmd)

    def test_probe_spec(self):
        self.assertEqual(gs.probe_spec(web_service()),
                         {"ip": "93.184.216.7", "port": 443, "kind": "web",
                          "host": "www.blocked.example", "tls": True})
        s = ga.Service(key="ep:openvpn:udp:x", kind=ga.ENDPOINT,
                       transport="udp", app="openvpn",
                       replay=ga.to_base64([b"\x38abc"]),
                       addresses=[{"ip": "93.184.216.40", "seen": 1}],
                       ports=[1194])
        spec = gs.probe_spec(s)
        # первые пакеты — в самой пробе, файл для external не нужен
        self.assertEqual((spec["kind"], spec["udp"], spec["fresh"],
                          spec["payloads"]),
                         ("replay", True, "", [b"\x38abc"]))
        self.assertIsNone(gs.probe_spec(wg_service()))
        self.assertIsNone(gs.probe_spec(web_service(host="a b")))

    def test_external_probe(self):
        seen = []

        def measure(spec, ports):
            seen.append((spec["host"], ports))
            return -480, "timeout", "tls: no answer"

        probe = gs.external_probe(gs.probe_spec(web_service()), measure)
        self.assertEqual(probe("30064-30127"),
                         (-480, "timeout: tls: no answer"))
        self.assertEqual(seen, [("www.blocked.example", (30064, 30127))])
        with self.assertRaises(ValueError):
            probe("80-90")

    def test_passing(self):
        res = [{"strategy": "A", "avg_fitness": 395},
               {"strategy": "B", "avg_fitness": -400},
               {"strategy": "C", "avg_fitness": 398},
               {"strategy": "A", "avg_fitness": 390},
               {"strategy": "D", "fitness": 380},
               {"strategy": "E", "avg_fitness": 370}]
        self.assertEqual(gs.passing(res), [("C", 398), ("A", 395),
                                           ("D", 380)])
        self.assertEqual(gs.passing(res, skip=("C", "A")),
                         [("D", 380), ("E", 370)])
        self.assertEqual(gs.passing([]), [])

    def test_next_generations(self):
        self.assertEqual(gs.next_generations({}, False), (10, False))
        self.assertEqual(gs.next_generations({"generations": 10}, False),
                         (10, False))
        self.assertEqual(gs.next_generations({"generations": 10}, True),
                         (15, True))

    def test_job_params(self):
        p = gs.job_params(web_service(), cmd="c", workers=20)
        self.assertEqual((p["protos"], p["population"], p["generations"],
                          p["workers"], p["target"]),
                         ("TCP", 20, 10, 8, "https:www.blocked.example"))
        dns = ga.Service(key="dns:93.184.216.53", kind=ga.DNS,
                         transport="udp",
                         addresses=[{"ip": "93.184.216.53", "seen": 1}])
        p = gs.job_params(dns, cmd="c", workers=2)
        self.assertEqual((p["protos"], p["target"]),
                         ("UDP,IP,DNS,DNSQR", "replay:93.184.216.53:53"))
        self.assertEqual(p["timeout"], gs.EXEC_TIMEOUT_REPLAY)


class TestAutoJobArgs(unittest.TestCase):

    def setUp(self):
        self.p = {"auto_candidates": "/st/auto/c.txt", "db": "/st/db.jsonl",
                  "job_events": "/rt/e.jsonl", "job_log": "/rt/j.log"}
        self.params = gm.validate_auto_job({
            "cmd": "python3 x --lports {lports}", "target": "replay:1.2.3.4:53",
            "protos": "UDP,IP", "workers": 4, "checkpoint": "/st/auto/a.ckpt",
            "generations": 15})

    def test_eval(self):
        a = gm.build_auto_eval_args("/bin/geneva", self.params, self.p)
        self.assertEqual(a[:4], ["/bin/geneva", "eval", "--probe", "exec"])
        self.assertEqual(a[a.index("--workers") + 1], "4")
        self.assertEqual(a[a.index("-f") + 1], "/st/auto/c.txt")
        self.assertEqual(a[a.index("--injected-contains") + 1], "INJECTED")
        self.assertEqual(a[a.index("-q") + 1], "311")

    def test_evolve(self):
        a = gm.build_auto_evolve_args("/bin/geneva", self.params, self.p,
                                      resume=True)
        self.assertEqual(a[a.index("--protos") + 1], "UDP,IP")
        self.assertEqual(a[a.index("--generations") + 1], "15")
        self.assertEqual(a[a.index("--population") + 1], "20")
        self.assertEqual(a[a.index("--checkpoint") + 1], "/st/auto/a.ckpt")
        self.assertEqual(a[a.index("--target") + 1], "replay:1.2.3.4:53")
        self.assertEqual(a[-1], "--resume")

    def test_external(self):
        params = gm.validate_auto_job({
            "probe": "external", "cmd": "ignored", "target": "https:x.org",
            "workers": 4, "checkpoint": "/st/auto/a.ckpt"})
        self.assertEqual((params["probe"], params["cmd"]), ("external", ""))
        for a in (gm.build_auto_eval_args("/bin/geneva", params, self.p),
                  gm.build_auto_evolve_args("/bin/geneva", params, self.p)):
            self.assertEqual(a[2:4], ["--probe", "external"])
            # фитнес ставит zapret-gui: ни команды, ни таймаута exec
            for opt in ("--cmd", "--injected-contains", "--timeout"):
                self.assertNotIn(opt, a)
            self.assertEqual(a[a.index("--workers") + 1], "4")
            self.assertEqual(a[a.index("-e") + 1], "/rt/e.jsonl")
        self.assertEqual(self.params["probe"], "exec")

    def test_validation(self):
        for bad in ({"cmd": "", "target": "x"},
                    {"cmd": "a\nb", "target": "x"},
                    {"cmd": "a", "target": "x; rm"},
                    {"cmd": "a", "target": "x", "protos": "tcp;"},
                    {"cmd": "a", "target": "x", "workers": 99},
                    {"probe": "tls", "cmd": "a", "target": "x"}):
            with self.assertRaises(ValueError):
                gm.validate_auto_job(bad)


class _FakeProc:
    def __init__(self):
        r, w = os.pipe()
        self.stdin = os.fdopen(w, "wb")
        self.out = os.fdopen(r, "rb")
        self.code = None

    def poll(self):
        return self.code


class TestExternalAnswerer(unittest.TestCase):

    def test_answers_by_id_in_finish_order(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        events = os.path.join(tmp, "e.jsonl")
        proc = _FakeProc()
        self.addCleanup(proc.out.close)
        slow = threading.Event()

        def probe(lports):
            if lports == "30000-30063":
                slow.wait(5)
                return 400, "ok"
            return -360, "reset"

        a = gm.ExternalAnswerer(proc, events, probe, workers=2).start()
        with open(events, "a") as f:
            f.write(json.dumps({"ev": "start", "mode": "eval"}) + "\n")
            for i, lp in ((1, "30000-30063"), (2, "30064-30127")):
                f.write(json.dumps({"ev": "eval_request", "id": i,
                                    "strategy": "x", "run": 0,
                                    "lports": lp}) + "\n")
        first = json.loads(proc.out.readline())
        self.assertEqual(first, {"id": 2, "fitness": -360.0,
                                 "detail": "reset"})
        slow.set()
        self.assertEqual(json.loads(proc.out.readline())["id"], 1)
        proc.code = 0                      # процесс вышел — stdin закрыт
        a._thread.join(5)
        self.assertFalse(a._thread.is_alive())
        self.assertTrue(proc.stdin.closed)

    def test_answer_line(self):
        self.assertEqual(json.loads(gm.external_answer(3, True)),
                         {"id": 3, "ok": True})
        self.assertEqual(json.loads(gm.external_answer(4, (-480, "x" * 300)))
                         ["detail"], "x" * 200)


class TestManagerAutoJobs(_StubCase):

    def params(self, **kw):
        base = {"cmd": "true {lports}", "target": "https:blocked.example",
                "protos": "TCP", "workers": 2, "key": "web:blocked.example"}
        base.update(kw)
        return base

    def wait_auto(self):
        self.assertTrue(wait_for(lambda: not self.mgr.job_running(), 15))
        return self.mgr.auto_job_status()

    def test_eval_keeps_manual_search_state(self):
        manual = {"kind": "evolve", "status": "stopped", "params": {"x": 1}}
        gm._write_atomic(gm.paths()["search"], json.dumps(manual))
        with mock.patch("core.bypass_engine.pause_for_search") as pause:
            r = self.mgr.start_auto_job("eval", self.params(),
                                        strategies=["[TCP:flags:PA]-drop-| \\/",
                                                    "[TCP:flags:S]-drop-| \\/"])
            self.assertTrue(r["ok"], r)
            pause.assert_not_called()          # группы «Авто» работают
        self.assertTrue(self.mgr.auto_job_running())
        st = self.wait_auto()
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["key"], "web:blocked.example")
        self.assertEqual([x["avg_fitness"] for x in st["results"]],
                         [380, -400])
        # ручной поиск не тронут, страница снова показывает его
        self.assertEqual(self.mgr.search_state(), manual)
        self.assertEqual(self.mgr.search_status()["owner"], "manual")
        auto = gm._read_json(gm.paths()["auto_search"])
        self.assertEqual(auto["owner"], "auto")
        call = [c for c in self.calls() if c.startswith("eval")][-1]
        self.assertIn("--probe exec", call)
        self.assertIn("--workers 2", call)

    def test_evolve_with_own_checkpoint_and_resume(self):
        ckpt = os.path.join(gm.paths()["auto"], "s.ckpt")
        r = self.mgr.start_auto_job("evolve", self.params(
            checkpoint=ckpt, generations=2))
        self.assertTrue(r["ok"], r)
        st = self.wait_auto()
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["results"][0]["avg_fitness"], 380)
        self.assertTrue(os.path.isfile(ckpt))
        self.assertFalse(os.path.isfile(gm.paths()["checkpoint"]))
        r = self.mgr.start_auto_job("evolve", self.params(
            checkpoint=ckpt, generations=4), resume=True)
        self.assertTrue(r["ok"], r)
        self.wait_auto()
        self.assertIn("--resume", [c for c in self.calls()
                                   if c.startswith("evolve")][-1])

    def test_external_eval_answers_every_worker(self):
        """geneva_c 1.2: запросы воркеров разом, у каждого свой блок
        портов; фитнес — из ответа zapret-gui."""
        asked = []
        both = threading.Barrier(2, timeout=5)

        def answer(lports):
            asked.append(lports)
            both.wait()                       # оба запроса в полёте разом
            return (400, "ok") if lports.startswith("30000") \
                else (-480, "timeout")

        r = self.mgr.start_auto_job(
            "eval", self.params(cmd=""), answer=answer,
            strategies=["[TCP:flags:PA]-drop-| \\/",
                        "[TCP:flags:S]-drop-| \\/"])
        self.assertTrue(r["ok"], r)
        st = self.wait_auto()
        self.assertEqual(st["status"], "done")
        self.assertEqual(sorted(asked), ["30000-30063", "30064-30127"])
        self.assertEqual([x["avg_fitness"] for x in st["results"]],
                         [398, -480])
        call = [c for c in self.calls() if c.startswith("eval")][-1]
        self.assertIn("--probe external", call)
        self.assertNotIn("--cmd", call)

    def test_external_evolve_baseline_open(self):
        ckpt = os.path.join(gm.paths()["auto"], "s.ckpt")
        r = self.mgr.start_auto_job("evolve", self.params(
            checkpoint=ckpt, generations=2), answer=lambda lp: (400, "ok"))
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.wait_auto()["status"], "not_blocked")

    def test_external_probe_error_is_failed(self):
        def answer(lports):
            raise OSError("no route")

        r = self.mgr.start_auto_job("eval", self.params(), answer=answer,
                                    strategies=["[TCP:flags:PA]-drop-| \\/"])
        self.assertTrue(r["ok"], r)
        st = self.wait_auto()
        self.assertEqual([x["avg_fitness"] for x in st["results"]], [-400])

    def test_external_without_answer_refused(self):
        r = self.mgr.start_auto_job("eval", self.params(probe="external"),
                                    strategies=["[TCP:flags:PA]-drop-| \\/"])
        self.assertFalse(r["ok"])

    def test_busy_while_manual_search(self):
        with mock.patch("core.bypass_engine.pause_for_search",
                        return_value=""), \
                mock.patch.dict(os.environ, {"GENEVA_STUB_GEN_DELAY": "0.4"}):
            self.assertTrue(self.mgr.start_search(
                {"host": "blocked.example", "population": 4,
                 "generations": 5})["ok"])
            r = self.mgr.start_auto_job("eval", self.params(),
                                        strategies=["[TCP:flags:PA]-drop-| \\/"])
        self.assertFalse(r["ok"])
        self.assertTrue(r["busy"])
        self.assertFalse(self.mgr.auto_job_running())

    def test_interrupted_auto_job_on_boot(self):
        gm._write_atomic(gm.paths()["auto_search"], json.dumps(
            {"kind": "evolve", "owner": "auto", "status": "running"}))
        self.mgr.recover_on_boot()
        self.assertEqual(self.mgr.auto_job_status()["status"], "interrupted")


class FakeGeneva:
    """Задания завершаются сразу с заданными итогами."""

    def __init__(self, eval_results=(), evolve_results=(),
                 evolve_status="done", busy=False):
        self.eval_results = list(eval_results)
        self.evolve_results = list(evolve_results)
        self.evolve_status = evolve_status
        self.busy = busy
        self.jobs = []
        self.answers = []
        self.last = {}

    def db_top(self, target, limit):
        return {"ok": True, "items": [
            {"strategy": "[TCP:flags:PA]-duplicate-| \\/", "ok": 2},
            {"strategy": "[TCP:flags:PA]-drop-| \\/", "ok": 0}]}

    def start_auto_job(self, kind, params, strategies=None, resume=False,
                       answer=None):
        if self.busy:
            return {"ok": False, "busy": True, "error": "подбор уже идёт"}
        self.jobs.append((kind, dict(params), list(strategies or []),
                          resume))
        self.answers.append(answer)
        if kind == "eval":
            self.last = {"running": False, "status": "done",
                         "results": self.eval_results}
        else:
            if params.get("checkpoint"):
                os.makedirs(os.path.dirname(params["checkpoint"]),
                            exist_ok=True)
                open(params["checkpoint"], "w").close()
            self.last = {"running": False, "status": self.evolve_status,
                         "results": self.evolve_results}
        return {"ok": True}

    def auto_job_status(self):
        return dict(self.last)

    def auto_job_running(self):
        return False

    def stop_search(self):
        return {"ok": True}


class FakeProbes:

    def __init__(self, works=()):
        self.works = set(works)
        self.applied = None
        self.checks = []

    def judge(self, s):
        return pr.AutoProbes().judge(s)

    def check(self, s, through_bypass=False):
        self.checks.append((self.applied, through_bypass))
        if self.applied in self.works:
            return ga.C_NOT_BLOCKED, "ok"
        return ga.C_BLOCKED, "сброс"


class TestAutoSearch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.paths = {"auto": os.path.join(self.tmp, "auto"),
                      "auto_runtime": os.path.join(self.tmp, "rt")}
        for target in ("JOB_POLL", "TRIAL_SETTLE", "UNPROBED_WAIT"):
            p = mock.patch.object(gs, target, 0.05)
            p.start()
            self.addCleanup(p.stop)

    def search(self, geneva, probes, trial=True, ok_since=None, **kw):
        self.trials = []

        def apply(s, strat):
            self.trials.append(strat)
            probes.applied = strat
            return True

        return gs.AutoSearch(geneva=geneva, probes=probes,
                             trial=apply if trial else None,
                             ok_since=ok_since, workers=4,
                             python="/usr/bin/python3",
                             script="/app/core/p.py", paths=self.paths,
                             **kw)

    def run_search(self, search, s, running=()):
        self.assertTrue(search.start(s, running))
        self.assertTrue(wait_for(lambda: not search.busy, 10))
        return search.result()

    def test_quick_candidate_wins_without_evolve(self):
        good = "[TCP:flags:PA]-fragment{tcp:8:True}-| \\/"
        g = FakeGeneva(eval_results=[{"strategy": good, "avg_fitness": 396}])
        p = FakeProbes(works={good})
        res = self.run_search(self.search(g, p), web_service(),
                              running=["[TCP:flags:A]-drop-| \\/"])
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, good))
        self.assertEqual([j[0] for j in g.jobs], ["eval"])
        kind, params, cands, _ = g.jobs[0]
        # стратегии групп, затем найденные с успехом, затем шаблоны
        self.assertEqual(cands[0], "[TCP:flags:A]-drop-| \\/")
        self.assertEqual(cands[1], "[TCP:flags:PA]-duplicate-| \\/")
        self.assertNotIn("[TCP:flags:PA]-drop-| \\/", cands)
        self.assertLessEqual(len(cands), ga.MAX_QUICK_CANDIDATES)
        self.assertEqual(params["workers"], 4)
        self.assertIn("{lports}", params["cmd"])
        self.assertEqual(p.checks, [(good, True)])  # проба через обход

    def test_external_probe_when_geneva_has_feature(self):
        good = "[TCP:flags:PA]-fragment{tcp:8:True}-| \\/"
        g = FakeGeneva(eval_results=[{"strategy": good, "avg_fitness": 396}])
        g.detect = lambda: {"features": ["nfqueue", gs.EXTERNAL_FEATURE]}
        measured = []

        def measure(spec, ports):
            measured.append(ports)
            return 400, "ok", "page"

        res = self.run_search(self.search(g, FakeProbes(works={good}),
                                          measure=measure), web_service())
        self.assertEqual(res.outcome, gs.APPLIED)
        params = g.jobs[0][1]
        self.assertEqual((params["probe"], params["cmd"]), ("external", ""))
        self.assertEqual(g.answers[0]("30128-30191"), (400, "ok: page"))
        self.assertEqual(measured, [(30128, 30191)])
        # без повтора в файле: для external он не нужен
        self.assertFalse(os.path.isdir(self.paths["auto_runtime"]))

    def test_exec_probe_without_feature(self):
        g = FakeGeneva(eval_results=[])
        g.detect = lambda: {"features": ["nfqueue"]}
        self.run_search(self.search(g, FakeProbes()), web_service())
        self.assertEqual(g.jobs[0][1]["probe"], "exec")
        self.assertIn("{lports}", g.jobs[0][1]["cmd"])
        self.assertIsNone(g.answers[0])

    def test_evolve_when_quick_fails_then_second_verified(self):
        a, b = ("[TCP:flags:PA]-tamper{TCP:window:replace:1}-| \\/",
                "[TCP:flags:PA]-tamper{TCP:window:replace:2}-| \\/")
        g = FakeGeneva(eval_results=[{"strategy": "X", "avg_fitness": -400}],
                       evolve_results=[{"strategy": a, "avg_fitness": 395},
                                       {"strategy": b, "avg_fitness": 390}])
        p = FakeProbes(works={b})
        res = self.run_search(self.search(g, p), web_service())
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, b))
        # круг проверенных, круг всех остальных, затем evolve
        self.assertEqual([j[0] for j in g.jobs], ["eval", "eval", "evolve"])
        evo = g.jobs[2][1]
        self.assertEqual((evo["generations"], evo["protos"]), (10, "TCP"))
        self.assertTrue(evo["checkpoint"].startswith(self.paths["auto"]))
        self.assertEqual(self.trials, [a, b])

    def test_proven_first_then_whole_catalog(self):
        lib = ["[TCP:flags:PA]-tamper{TCP:window:replace:7}-| \\/",
               "[UDP:sport:*]-drop-| \\/"]
        g = FakeGeneva(eval_results=[{"strategy": "X", "avg_fitness": -400}])
        g.library = lambda: {"ok": True,
                             "items": [{"strategy": x} for x in lib]}
        proven = ["[TCP:flags:PA]-tamper{TCP:window:replace:5}-| \\/",
                  "[TCP:flags:PA]-tamper{TCP:window:replace:6}-| \\/"]
        search = self.search(g, FakeProbes())
        self.assertTrue(search.start(web_service(), (), proven))
        self.assertTrue(wait_for(lambda: not search.busy, 10))
        evals = [j[2] for j in g.jobs if j[0] == "eval"]
        self.assertEqual(len(evals), 2)
        first, rest = evals
        # найденные для цели, затем проверенные у других; круг добран до
        # кратного числа воркеров
        self.assertEqual(first[:3], ["[TCP:flags:PA]-duplicate-| \\/"]
                         + proven)
        self.assertEqual(len(first) % 4, 0)
        # библиотека исследований — во втором круге, чужой транспорт — нет
        self.assertIn(lib[0], rest)
        self.assertNotIn(lib[1], rest + first)
        self.assertFalse(set(first) & set(rest))

    def test_not_found_and_resume_next_time(self):
        g = FakeGeneva(evolve_results=[])
        p = FakeProbes()
        s = web_service()
        res = self.run_search(self.search(g, p), s)
        self.assertEqual(res.outcome, gs.NOT_FOUND)
        res = self.run_search(self.search(g, p), s)
        evo = [j for j in g.jobs if j[0] == "evolve"]
        self.assertEqual((evo[-1][1]["generations"], evo[-1][3]), (15, True))
        self.assertEqual(res.outcome, gs.NOT_FOUND)

    def test_failed_verification_removes_trial(self):
        good = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"
        g = FakeGeneva(eval_results=[{"strategy": good, "avg_fitness": 396}])
        res = self.run_search(self.search(g, FakeProbes()), web_service())
        self.assertEqual(res.outcome, gs.NOT_FOUND)
        self.assertIsNone(self.trials[-1])

    def test_stopped_from_page_is_not_not_found(self):
        g = FakeGeneva(eval_results=[], evolve_status="stopped")
        res = self.run_search(self.search(g, FakeProbes()), web_service())
        self.assertEqual(res.outcome, gs.BUSY)
        # прерванный evolve следующий подбор продолжает
        res = self.run_search(self.search(g, FakeProbes()), web_service())
        evo = [j for j in g.jobs if j[0] == "evolve"]
        self.assertEqual((evo[-1][1]["generations"], evo[-1][3]), (15, True))

    def test_busy_and_not_blocked(self):
        res = self.run_search(self.search(FakeGeneva(busy=True),
                                          FakeProbes()), web_service())
        self.assertEqual(res.outcome, gs.BUSY)
        g = FakeGeneva(evolve_status="not_blocked")
        res = self.run_search(self.search(g, FakeProbes()), web_service())
        self.assertEqual(res.outcome, gs.NOT_BLOCKED)

    def test_without_trial_eval_result_accepted(self):
        good = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"
        g = FakeGeneva(eval_results=[{"strategy": good, "avg_fitness": 396}])
        res = self.run_search(self.search(g, FakeProbes(), trial=False),
                              web_service())
        self.assertEqual((res.outcome, res.strategy), (gs.APPLIED, good))

    def test_candidates_checked_by_geneva(self):
        """Неразбираемый кандидат не уходит в eval (иначе код 3 уронил
        бы весь быстрый круг); канонический вид — от geneva."""
        g = FakeGeneva(eval_results=[])
        bad = ga.AUTO_PRESETS_TCP[0]

        def check(c):
            if c == bad:
                return {"ok": False, "error": "parse error"}
            return {"ok": True, "strategy": c + " "}

        g.check_strategy = check
        self.run_search(self.search(g, FakeProbes()), web_service())
        cands = g.jobs[0][2]
        self.assertNotIn(bad, cands)
        self.assertNotIn(bad + " ", cands)
        self.assertTrue(all(c.endswith(" ") for c in cands))

    def test_replay_file_for_replayable_service(self):
        s = ga.Service(key="ep:openvpn:udp:93.184.216.40:1194",
                       kind=ga.ENDPOINT, transport="udp", app="openvpn",
                       name="OpenVPN", replay=ga.to_base64([b"\x38abc"]),
                       addresses=[{"ip": "93.184.216.40", "seen": 1}],
                       ports=[1194], status=ga.BLOCKED)
        g = FakeGeneva(eval_results=[])
        self.run_search(self.search(g, FakeProbes()), s)
        cmd = g.jobs[0][1]["cmd"]
        path = os.path.join(self.paths["auto_runtime"],
                            gs.slug(s.key) + ".b64")
        self.assertIn(path, cmd)
        self.assertEqual(open(path).read(), s.replay)
        self.assertEqual(g.jobs[1][1]["protos"], "UDP,IP")

    def test_unprobed_service_by_client_traffic(self):
        g = FakeGeneva()
        seen = {"n": 0}

        def ok_since(key, t):
            seen["n"] += 1
            return len(self.trials) >= 2       # прошёл со второй

        res = self.run_search(self.search(g, FakeProbes(),
                                          ok_since=ok_since), wg_service())
        self.assertEqual(res.outcome, gs.APPLIED)
        self.assertEqual(res.strategy, self.trials[1])
        self.assertEqual(g.jobs, [])            # ни eval, ни evolve
        # второй кандидат: вторая предустановленная UDP-стратегия
        self.assertEqual(res.strategy, ga.candidates_for(wg_service())[1])
        self.assertEqual(res.strategy, ga.AUTO_PRESETS_UDP[1])

    def test_unprobed_without_traffic_source(self):
        res = self.run_search(self.search(FakeGeneva(), FakeProbes()),
                              wg_service())
        self.assertEqual(res.outcome, gs.NOT_FOUND)

    def test_cancel(self):
        g = FakeGeneva()
        started = threading.Event()

        def ok_since(key, t):
            started.set()
            return False

        search = self.search(g, FakeProbes(), ok_since=ok_since)
        self.assertTrue(search.start(wg_service()))
        self.assertTrue(started.wait(5))
        self.assertFalse(search.start(wg_service()))   # уже идёт
        search.cancel()
        self.assertEqual(search.result().outcome, gs.CANCELLED)
        self.assertIsNone(self.trials[-1])


class _Http:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.peers = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, addr = self.sock.accept()
            except OSError:
                return
            self.peers.append(addr[1])
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
            c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
            c.close()


class TestProbeCli(unittest.TestCase):

    def test_verdict(self):
        self.assertEqual(cli.verdict(396, "ok"), (0, "ok"))
        self.assertEqual(cli.verdict(-360, "reset"), (1, "reset"))
        self.assertEqual(cli.verdict(-360, "injected"), (1, "INJECTED"))
        self.assertEqual(cli.verdict(-400, "timeout: no answer"),
                         (1, "timeout: no answer"))
        self.assertEqual(cli.parse_lports("30064-30127"), (30064, 30127))
        with self.assertRaises(ValueError):
            cli.parse_lports("80-90")

    def test_web_from_worker_ports(self):
        srv = _Http()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.run(["--kind", "web", "--ip", "127.0.0.1",
                                "--port", str(srv.port), "--host", "x.org",
                                "--tls", "0", "--lports", "39200-39263"])
        finally:
            srv.sock.close()
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(39200 <= srv.peers[0] <= 39263)

    def test_replay_no_connection(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(ga.to_base64([b"\x16\x03\x01hello"]))
        self.addCleanup(os.unlink, f.name)
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.run(["--kind", "replay", "--ip", "127.0.0.1",
                            "--port", str(port), "--replay-file", f.name,
                            "--lports", "39300-39363"])
        self.assertEqual(code, 1)
        self.assertIn("connect_timeout", out.getvalue())

    def test_script_runs_standalone(self):
        """geneva зовёт файл скриптом из чужого каталога."""
        import subprocess
        import sys
        r = subprocess.run([sys.executable, gs.probe_script(), "--help"],
                           capture_output=True, text=True, cwd="/",
                           timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
