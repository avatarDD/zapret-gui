# tests/test_geneva_manager.py
"""
Тесты движка geneva_c: чистые функции, события, сокет, жизненный цикл.

Жизненный цикл гоняется НАСТОЯЩИМ менеджером против заглушки
tests/geneva_stub.py, которая повторяет CLI geneva_c v1.0.0 (run с
управляющим сокетом, evolve с checkpoint'ом, eval, check, library, db).
Так ловится то, что не видно в моках:

  * стратегия меняется у живого движка через сокет, без перезапуска;
  * остановленный подбор продолжается с checkpoint'а, а законченный —
    продлевается (more_generations);
  * итог подбора переживает перезапуск GUI (search.json в каталоге
    конфига, а не в ОЗУ);
  * geneva не поднимается, пока активный движок — nfqws2;
  * после SIGKILL правила снимаются `geneva fw down` с теми же
    очередью и портами.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import geneva_manager as gm


STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "geneva_stub.py")


def _cmdline_without_interpreter(pid):
    """Заглушка — python-скрипт: в cmdline первым идёт интерпретатор."""
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            words = f.read().split(b"\0")
    except OSError:
        return ""
    words = [w.decode("utf-8", "replace") for w in words if w]
    if words and os.path.basename(words[0]).startswith("python"):
        words = words[1:]
    return " ".join(words)


def wait_for(cond, timeout=10.0, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


# ─────────────────────────── чистые функции ──────────────────────────

class TestValidation(unittest.TestCase):

    def test_ports_normalized(self):
        self.assertEqual(gm.normalize_ports(" 80, 443 "), "80,443")
        self.assertEqual(gm.normalize_ports("1000-2000"), "1000-2000")
        for bad in ("", "abc", "0", "70000", "443,", "10-5"):
            with self.assertRaises(ValueError, msg=bad):
                gm.normalize_ports(bad)

    def test_strategy_text(self):
        # Библиотека Geneva часто пишет стратегии без «\/».
        self.assertEqual(gm.check_strategy_text(
            "  [TCP:flags:PA]-drop-|  "), "[TCP:flags:PA]-drop-|")
        self.assertEqual(gm.check_strategy_text("\\/ [TCP:flags:R]-|"),
                         "\\/ [TCP:flags:R]-|")
        for bad in ("", "drop", "[a]\n[b]", "[" + "x" * 5000):
            with self.assertRaises(ValueError, msg=bad[:20]):
                gm.check_strategy_text(bad)

    def test_settings(self):
        clean = gm.validate_settings({"ports": "443", "proto": "tcp,udp",
                                      "firewall": "nft", "autostart": "1",
                                      "log_level": "DEBUG", "first": 3})
        self.assertEqual(clean["ports"], "443")
        self.assertEqual(clean["proto"], "tcp,udp")
        self.assertIs(clean["autostart"], True)
        self.assertEqual(clean["log_level"], "debug")
        # Путь к программе, запускаемой от root, по HTTP не меняется.
        self.assertNotIn("binary", gm.validate_settings(
            {"binary": "/tmp/evil"}))
        for bad in ({"proto": "icmp"}, {"firewall": "pf"},
                    {"iface": "eth0; rm -rf /"}, {"log_level": "loud"}):
            with self.assertRaises(ValueError, msg=bad):
                gm.validate_settings(bad)

    def test_search_defaults_and_limits(self):
        p = gm.validate_search({"host": "blocked.example"})
        self.assertEqual(p["probe"], "tls")
        self.assertEqual(p["population"], gm.SEARCH_DEFAULTS["population"])
        self.assertTrue(p["pause_bypass"])
        with self.assertRaises(ValueError):
            gm.validate_search({})                      # нет сайта
        with self.assertRaises(ValueError):
            gm.validate_search({"host": "a b"})
        with self.assertRaises(ValueError):
            gm.validate_search({"host": "x.example", "probe": "dns"})
        with self.assertRaises(ValueError):
            gm.validate_search({"host": "x.example", "population": 10000})
        # Сохранённые параметры — основа, явные — поверх.
        p = gm.validate_search({"host": "y.example"},
                               {"probe": "http", "population": 12})
        self.assertEqual((p["probe"], p["population"]), ("http", 12))


class TestArgs(unittest.TestCase):

    def setUp(self):
        self.p = {k: "/x/" + k for k in (
            "strategy", "socket", "run_events", "run_log", "checkpoint",
            "db", "job_events", "job_log", "candidates")}

    def test_run_args(self):
        args = gm.build_run_args("/bin/geneva", {
            "ports": "443", "proto": "tcp", "queue": 310, "firewall": "auto",
            "log_level": "info", "iface": "eth3", "first": 5}, self.p)
        self.assertEqual(args[:2], ["/bin/geneva", "run"])
        joined = " ".join(args)
        for part in ("-f /x/strategy", "-p 443", "-q 310",
                     "--mark 0x20000000", "-c unix:/x/socket",
                     "-e /x/run_events", "-i eth3", "--first 5"):
            self.assertIn(part, joined)

    def test_fw_down_mirrors_run(self):
        run = gm.build_run_args("/bin/geneva", {
            "ports": "80,443", "proto": "tcp", "queue": 312,
            "firewall": "nft", "iface": "ppp0"}, self.p)
        down = gm.fw_down_args("/bin/geneva", run)
        self.assertEqual(down[:3], ["/bin/geneva", "fw", "down"])
        joined = " ".join(down)
        for part in ("-p 80,443", "-q 312", "--firewall nft", "-i ppp0",
                     "--mark 0x20000000", "--proto tcp"):
            self.assertIn(part, joined)
        self.assertNotIn("-c", down)
        self.assertNotIn("-f", down)

    def test_evolve_args(self):
        params = gm.validate_search({"host": "b.example"})
        args = gm.build_evolve_args("/g", params, self.p)
        self.assertIn("--checkpoint", args)
        self.assertIn("--db", args)
        self.assertNotIn("--resume", args)
        self.assertEqual(args[args.index("-q") + 1], str(gm.EVAL_QUEUE))
        self.assertIn("--resume",
                      gm.build_evolve_args("/g", params, self.p, True))

    def test_https_probe_uses_curl_with_fail(self):
        params = gm.validate_search({"host": "b.example", "probe": "https"})
        args = gm.build_evolve_args("/g", params, self.p)
        cmd = args[args.index("--cmd") + 1]
        self.assertEqual(args[args.index("--probe") + 1], "exec")
        # curl без -f засчитывает HTTP-ошибку как успех (Pitfalls geneva_c).
        self.assertIn("curl -sf", cmd)
        self.assertIn("--local-port {lports}", cmd)
        self.assertIn("https://b.example/", cmd)

    def test_eval_args(self):
        params = gm.validate_search({"host": "b.example"})
        args = gm.build_eval_args("/g", params, self.p)
        self.assertEqual(args[1], "eval")
        self.assertEqual(args[args.index("-f") + 1], "/x/candidates")


class TestEvents(unittest.TestCase):

    def test_parse_event(self):
        self.assertEqual(gm.parse_event('{"ts":1,"ev":"ready"}')["ev"],
                         "ready")
        for bad in ("", "garbage", "[1,2]", '{"ts":1}'):
            self.assertIsNone(gm.parse_event(bad), bad)

    def test_describe_is_russian_and_levelled(self):
        level, text = gm.describe_event({"ev": "ready", "firewall": "nft"})
        self.assertEqual(level, "ok")
        self.assertIn("nft", text)
        level, text = gm.describe_event(
            {"ev": "generation", "gen": 2, "best_fitness": 380}, 10)
        self.assertEqual(level, "ok")
        self.assertIn("Поколение 3 из 10", text)
        level, _ = gm.describe_event({"ev": "exit", "code": 5,
                                      "reason": "error"})
        self.assertEqual(level, "warn")
        self.assertIsNone(gm.describe_event({"ev": "stats"}))
        self.assertIsNone(gm.describe_event({"ev": "future_event"}))

    def test_reader_is_incremental_and_survives_truncation(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "ev.jsonl")
        r = gm.EventReader(path)
        self.assertEqual(r.read_new(), [])
        with open(path, "a") as f:
            f.write('{"ts":1,"ev":"start"}\n{"ts":2,"ev":"rea')
        self.assertEqual([e["ev"] for e in r.read_new()], ["start"])
        with open(path, "a") as f:
            f.write('dy"}\n')
        self.assertEqual([e["ev"] for e in r.read_new()], ["ready"])
        self.assertTrue(gm.trim_file(path, 0))
        with open(path, "a") as f:
            f.write('{"ts":3,"ev":"exit"}\n')
        self.assertEqual([e["ev"] for e in r.read_new()], ["exit"])

    def test_summarize_stats_verdict(self):
        self.assertEqual(gm.summarize_stats({})["verdict"], "no_traffic")
        self.assertEqual(gm.summarize_stats(
            {"pkts_out": 5, "triggered": 0})["verdict"], "not_firing")
        out = gm.summarize_stats({"pkts_out": 5, "triggered": 2,
                                  "send_errors": 1, "parse_errors": 2,
                                  "out_trees": [{"tree": "[x]", "fired": 2}]})
        self.assertEqual(out["verdict"], "working")
        self.assertEqual(out["errors"], 3)
        self.assertEqual(out["trees"], [{"dir": "out", "tree": "[x]",
                                         "fired": 2}])

    def test_parse_db_lines(self):
        text = ('{"s":"[A]-|","t":"tls:x","runs":4,"ok":3,"fit_sum":800,'
                '"fit_best":390}\nnoise\n{"t":"no strategy"}\n')
        items = gm.parse_db_lines(text)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["success_rate"], 0.75)
        self.assertEqual(items[0]["avg_fitness"], 200.0)


# ───────────────────── жизненный цикл на заглушке ────────────────────

@unittest.skipUnless(sys.platform.startswith("linux"),
                     "нужны /proc и unix-сокеты")
class _StubCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="geneva-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Путь к unix-сокету ограничен ~108 байтами: держим его коротким.
        self.rt = tempfile.mkdtemp(prefix="gv-")
        self.addCleanup(shutil.rmtree, self.rt, ignore_errors=True)

        self.calls_path = os.path.join(self.tmp, "calls.log")
        env = {"GENEVA_STUB_CALLS": self.calls_path,
               "ZAPRET_GUI_GENEVA_RUNTIME": self.rt}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.binary = os.path.join(self.tmp, "geneva")
        with open(STUB) as src, open(self.binary, "w") as dst:
            dst.write(src.read().replace("#!/usr/bin/env python3",
                                         "#!" + sys.executable, 1))
        os.chmod(self.binary, os.stat(self.binary).st_mode | stat.S_IEXEC)

        self._saved_cm = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self.tmp)
        cm_mod._config_manager.load()
        self.addCleanup(setattr, cm_mod, "_config_manager", self._saved_cm)
        self.cfg = cm_mod._config_manager
        self.cfg.set("geneva", "binary", self.binary)
        self.cfg.set("bypass", "engine", "geneva")
        self.cfg.save()

        for target, new in (("_pid_cmdline", _cmdline_without_interpreter),
                            ("rules_present", lambda q: None)):
            p = mock.patch.object(gm, target, new)
            p.start()
            self.addCleanup(p.stop)

        self.mgr = gm.GenevaManager()
        p = mock.patch.object(gm, "_instance", self.mgr)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._cleanup_processes)

    def _cleanup_processes(self):
        self.mgr._monitor_stop.set()
        try:
            self.mgr.stop_search()
        except Exception:
            pass
        try:
            self.mgr.stop()
        except Exception:
            pass

    def calls(self):
        try:
            with open(self.calls_path) as f:
                return [line.strip() for line in f if line.strip()]
        except OSError:
            return []


class TestDetectAndTools(_StubCase):

    def test_detect(self):
        d = self.mgr.detect()
        self.assertTrue(d["installed"])
        self.assertTrue(d["proto_ok"])
        self.assertEqual(d["version"], "1.0.0")

    def test_wrong_proto_is_refused(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_PROTO": "2"}):
            self.mgr._version_cache = {}
            d = self.mgr.detect()
            self.assertFalse(d["proto_ok"])
            res = self.mgr.start("[TCP:flags:PA]-drop-|")
            self.assertFalse(res["ok"])
            self.assertIn("протокола", res["error"])

    def test_check_and_library(self):
        res = self.mgr.check_strategy("[TCP:flags:PA]-drop-|")
        self.assertTrue(res["ok"])
        self.assertEqual(res["strategy"], "[TCP:flags:PA]-drop-| \\/")
        bad = self.mgr.check_strategy("[TCP:flags:PA]-bogus-|")
        self.assertFalse(bad["ok"])
        self.assertIn("не разбирается", bad["error"])
        lib = self.mgr.library()
        self.assertTrue(lib["ok"])
        # Эталон «без стратегии» (\/) применять нечего — его не показываем.
        self.assertEqual(len(lib["items"]), 2)
        self.assertNotIn("\\/", [i["strategy"] for i in lib["items"]])


class TestRunLifecycle(_StubCase):

    def test_refuses_while_nfqws2_is_active(self):
        self.cfg.set("bypass", "engine", "nfqws2")
        res = self.mgr.start("[TCP:flags:PA]-drop-|")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "engine_nfqws2")
        self.assertFalse(any(c.startswith("run ") for c in self.calls()))

    def test_no_strategy(self):
        res = self.mgr.start()
        self.assertFalse(res["ok"])
        self.assertIn("стратегия", res["error"])

    def test_start_status_live_strategy_pause_stop(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|", source="test")
        res = self.mgr.start()
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["ready"])
        # Перед запуском всегда fw down: после краха могли остаться правила.
        calls = self.calls()
        fw = [i for i, c in enumerate(calls) if c.startswith("fw down")]
        run = [i for i, c in enumerate(calls) if c.startswith("run ")]
        self.assertTrue(fw and run and fw[0] < run[0], calls)

        st = self.mgr.status()
        self.assertTrue(st["running"])
        self.assertEqual(st["state"], "running")
        self.assertEqual(st["stats"]["verdict"], "working")
        self.assertTrue(any("Перехват включён" in e["text"]
                            for e in st["events"]))

        res = self.mgr.set_strategy("[TCP:flags:S]-drop-|", source="lib")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["applied_live"])
        self.assertEqual(self.mgr.status()["live_strategy"],
                         "[TCP:flags:S]-drop-| \\/")
        self.assertEqual(self.cfg.get("geneva", "strategy"),
                         "[TCP:flags:S]-drop-| \\/")
        with open(gm.paths()["strategy"]) as f:
            self.assertEqual(f.read().strip(), "[TCP:flags:S]-drop-| \\/")

        self.assertTrue(self.mgr.control("pause")["ok"])
        self.assertEqual(self.mgr.status()["state"], "paused")
        self.mgr.control("resume")

        res = self.mgr.stop()
        self.assertTrue(res["ok"])
        self.assertFalse(res["forced"])
        self.assertFalse(self.mgr.is_running())

    def test_bad_strategy_is_not_saved_over_working_one(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.assertTrue(self.mgr.start()["ok"])
        res = self.mgr.set_strategy("[TCP:flags:PA]-bogus-|")
        self.assertFalse(res["ok"])
        self.assertEqual(self.cfg.get("geneva", "strategy"),
                         "[TCP:flags:PA]-duplicate-| \\/")

    def test_start_failure_reports_exit_code(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        with mock.patch.dict(os.environ, {"GENEVA_STUB_RUN_FAIL": "4"}):
            res = self.mgr.start()
        self.assertFalse(res["ok"])
        self.assertIn("нет прав или модулей ядра", res["error"])
        self.assertFalse(self.mgr.is_running())

    def test_sigkill_fallback_runs_fw_down(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.cfg.set("geneva", "ports", "8443")
        with mock.patch.dict(os.environ, {"GENEVA_STUB_IGNORE_TERM": "1"}):
            self.assertTrue(self.mgr.start()["ok"])
        before = len([c for c in self.calls() if c.startswith("fw down")])
        real = gm._terminate
        with mock.patch.object(gm, "_terminate",
                               lambda pid, sub, wait=10.0:
                               real(pid, sub, wait=0.5)):
            res = self.mgr.stop()
        self.assertTrue(res["forced"])
        downs = [c for c in self.calls() if c.startswith("fw down")]
        self.assertEqual(len(downs), before + 1)
        self.assertIn("-p 8443", downs[-1])

    def test_firewall_loss_restarts_only_after_rules_were_seen(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.assertTrue(self.mgr.start()["ok"])
        with mock.patch.object(self.mgr, "stop") as stop, \
                mock.patch.object(self.mgr, "start") as start:
            # Проверить нельзя или ни разу не видели — не трогаем.
            with mock.patch.object(gm, "rules_present", lambda q: False):
                self.mgr._fw_checked = 0
                self.mgr._check_firewall()
            stop.assert_not_called()
            with mock.patch.object(gm, "rules_present", lambda q: True):
                self.mgr._fw_checked = 0
                self.mgr._check_firewall()
            with mock.patch.object(gm, "rules_present", lambda q: False):
                self.mgr._fw_checked = 0
                self.mgr._check_firewall()
            stop.assert_called_once()
            start.assert_called_once()


class TestSearch(_StubCase):

    def setUp(self):
        super().setUp()
        # Подбор останавливает обход: здесь обхода нет, проверяем лишь
        # передачу параметров, а саму паузу — в test_bypass_engine.
        p = mock.patch("core.bypass_engine.pause_for_search",
                       return_value="")
        p.start()
        self.addCleanup(p.stop)

    def _wait_done(self, timeout=15):
        ok = wait_for(lambda: not self.mgr.job_running(), timeout)
        self.assertTrue(ok, "подбор не закончился")
        return self.mgr.search_status()

    def test_full_search_then_extend(self):
        res = self.mgr.start_search({"host": "blocked.example",
                                     "population": 4, "generations": 3})
        self.assertTrue(res["ok"], res)
        st = self._wait_done()
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["generation"], 3)
        self.assertEqual(st["percent"], 100)
        self.assertTrue(st["baseline"]["blocked"])
        self.assertEqual(st["results"][0]["avg_fitness"], 380)
        self.assertTrue(st["evals"])
        self.assertFalse(st["can_resume"])
        self.assertTrue(st["can_extend"])
        # Параметры стали сохранёнными: форма их подставит.
        self.assertEqual(self.cfg.get("geneva", "search")["host"],
                         "blocked.example")
        # База оценок пополнилась.
        top = self.mgr.db_top()
        self.assertTrue(top["ok"])
        self.assertEqual(top["items"][0]["strategy"],
                         "[TCP:flags:PA]-duplicate-| \\/")

        # Без more_generations законченный поиск продолжать нечего.
        self.assertFalse(self.mgr.start_search(resume=True)["ok"])
        res = self.mgr.start_search(resume=True, more_generations=2)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["params"]["generations"], 5)
        self.assertTrue(wait_for(lambda: any(
            c.startswith("evolve") and "--resume" in c
            for c in self.calls())))
        st = self._wait_done()
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["generation"], 5)

    def test_stop_then_resume_and_survive_gui_restart(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_GEN_DELAY": "0.4"}):
            res = self.mgr.start_search({"host": "blocked.example",
                                         "population": 4,
                                         "generations": 50})
            self.assertTrue(res["ok"], res)
            self.assertTrue(wait_for(
                lambda: self.mgr.search_status()["generation"] >= 1))
            res = self.mgr.stop_search()
            self.assertTrue(res["ok"])
        st = self.mgr.search_status()
        self.assertEqual(st["status"], "stopped")
        self.assertTrue(st["can_resume"])

        # «Перезапуск GUI»: новый менеджер видит то же из каталога конфига.
        fresh = gm.GenevaManager()
        with mock.patch.object(gm, "_instance", fresh):
            fresh.recover_on_boot()
            st2 = fresh.search_status()
            self.assertEqual(st2["status"], "stopped")
            self.assertTrue(st2["can_resume"])
            self.assertEqual(st2["target"], st["target"])
            res = fresh.start_search(resume=True)
            self.assertTrue(res["ok"], res)
            self.assertTrue(wait_for(lambda: any(
                c.startswith("evolve") and "--resume" in c
                for c in self.calls())))
            self.assertTrue(wait_for(lambda: not fresh.job_running(), 40))
            self.assertEqual(fresh.search_status()["status"], "done")

    def test_interrupted_when_process_vanished(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_GEN_DELAY": "0.4"}):
            self.assertTrue(self.mgr.start_search(
                {"host": "blocked.example", "generations": 50})["ok"])
            self.assertTrue(wait_for(
                lambda: self.mgr.search_status()["generation"] >= 1))
        pid = self.mgr._job_pid()
        os.kill(pid, 9)
        fresh = gm.GenevaManager()
        self.assertTrue(wait_for(lambda: not fresh.job_running()))
        fresh.recover_on_boot()
        st = fresh.search_status()
        self.assertEqual(st["status"], "interrupted")
        self.assertTrue(st["can_resume"])

    def test_not_blocked(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_BASELINE": "open"}):
            self.assertTrue(self.mgr.start_search(
                {"host": "open.example"})["ok"])
            st = self._wait_done()
        self.assertEqual(st["status"], "not_blocked")
        self.assertFalse(st["baseline"]["blocked"])

    def test_error_carries_reason_from_log(self):
        res = self.mgr.start_search({"host": "blocked.example"})
        self.assertTrue(res["ok"], res)
        with mock.patch.object(gm, "tail_lines",
                               return_value=["geneva evolve: cannot resolve "
                                             "blocked.example"]):
            self._wait_done()
            self.mgr._job_state["exit_code"] = 2
            self.mgr._job_state["status"] = "running"
            self.mgr._finish_job(2)
        st = self.mgr.search_status()
        self.assertEqual(st["status"], "error")
        self.assertIn("неверные аргументы — geneva evolve: cannot resolve",
                      st["error"])

    def test_one_job_at_a_time_and_no_run_meanwhile(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_GEN_DELAY": "0.4"}):
            self.assertTrue(self.mgr.start_search(
                {"host": "blocked.example", "generations": 50})["ok"])
            self.assertFalse(self.mgr.start_search(
                {"host": "blocked.example"})["ok"])
            self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
            self.assertFalse(self.mgr.start()["ok"])

    def test_eval_list(self):
        res = self.mgr.start_eval(["[TCP:flags:PA]-duplicate-|",
                                   "not a strategy",
                                   "[TCP:flags:S]-drop-|"],
                                  {"host": "blocked.example"})
        self.assertTrue(res["ok"], res)
        with open(gm.paths()["candidates"]) as f:
            self.assertEqual(len(f.read().split("\n")), 3)  # 2 + конец
        st = self._wait_done()
        self.assertEqual(st["kind"], "eval")
        self.assertEqual(st["status"], "done")
        self.assertEqual(st["done"], 2)
        self.assertEqual(st["percent"], 100)

    def test_forget(self):
        self.assertTrue(self.mgr.start_search(
            {"host": "blocked.example", "generations": 2})["ok"])
        self._wait_done()
        self.assertTrue(self.mgr.forget_search()["ok"])
        st = self.mgr.search_status()
        self.assertEqual(st["status"], "idle")
        self.assertFalse(os.path.exists(gm.paths()["checkpoint"]))
        # База оценок остаётся: это найденные стратегии.
        self.assertTrue(os.path.exists(gm.paths()["db"]))

    def test_state_lives_in_config_dir(self):
        p = gm.paths()
        self.assertTrue(p["checkpoint"].startswith(self.tmp))
        self.assertTrue(p["search"].startswith(self.tmp))
        self.assertTrue(p["socket"].startswith(self.rt))


if __name__ == "__main__":
    unittest.main()
