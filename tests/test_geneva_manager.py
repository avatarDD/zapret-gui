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
import threading
import time
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import geneva_auto as ga
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
        self.assertNotIn("--ext", args)
        ext = ["--ext", "--ext-blob", "z2_a:@/f/a.bin"]
        a = gm.build_evolve_args("/g", params, self.p, ext=ext)
        self.assertEqual(a[:5], ["/g", "evolve"] + ext)

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


class TestNflogRefused(unittest.TestCase):
    """Отказ NFLOG в логе geneva — признак «в ядре нет nfnetlink_log».

    Ядро отвечает EINVAL, когда подсистемы нет вовсе (request_module не
    нашёл модуль), и EBUSY, когда группу уже читает другая программа.
    Путать эти случаи нельзя: второй — временный и к нашему модулю не
    относится.
    """

    LINE = ("2026-11-21 17:25:13.768 error engine: cannot bind NFLOG group "
            "349: Invalid argument")

    def test_einval_is_our_case(self):
        self.assertTrue(gm.nflog_refused(self.LINE))

    def test_busy_is_not(self):
        self.assertFalse(gm.nflog_refused(
            "error engine: cannot bind NFLOG group 349: Device or resource "
            "busy (another program reads this group)"))

    def test_other_errors_are_not(self):
        self.assertFalse(gm.nflog_refused("error engine: netlink socket: "
                                          "Operation not permitted"))
        self.assertFalse(gm.nflog_refused(""))
        self.assertFalse(gm.nflog_refused(None))

    def test_warns_about_mark_are_not_nflog(self):
        self.assertFalse(gm.nflog_refused(
            "warn run: --mark 0x20000000 shares bit 0x20000000 with "
            "zapret2's DESYNC_MARK_POSTNAT"))


class TestObserverDisabled(unittest.TestCase):
    """Детектор с отказом NFLOG не перезапускается до сброса."""

    def _mgr(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        m._obs_disabled = ""
        # modprobe в тестах не дёргаем: это отдельный тест ниже
        m._nflog_load_tried = True
        return m

    def test_refusal_disables_until_reset(self):
        m = self._mgr()
        proc = mock.Mock()
        proc.pid = 4242
        proc.poll.return_value = 1          # сразу умер
        proc.returncode = 1
        hp = {"obs_pid": "/tmp/x.pid", "obs_events": "/tmp/x.ev",
              "obs_log": "/tmp/x.log", "obs_socket": "/tmp/x.sock"}
        calls = []

        def spawn(args, log_path):
            calls.append(args)
            return proc

        with mock.patch.object(m, "auto_observer_pid", return_value=None), \
             mock.patch.object(m, "_ready_binary",
                               return_value=("/opt/usr/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_auto"}), \
             mock.patch.object(gm, "auto_host_paths", return_value=hp), \
             mock.patch.object(m, "_stop_aux"), \
             mock.patch.object(gm, "_spawn", side_effect=spawn), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_remove"), \
             mock.patch.object(gm, "_wait_ready_events"), \
             mock.patch.object(gm, "tail_lines",
                               return_value=[TestNflogRefused.LINE]):
            r = m.auto_observer_ensure()
            self.assertEqual(r["action"], "disabled")
            self.assertEqual(r["reason"], "no_nflog")
            # второй вызов процесс не запускает
            r2 = m.auto_observer_ensure()
            self.assertEqual(r2["action"], "disabled")
            self.assertEqual(len(calls), 1)
            m.auto_observer_reset()
            m.auto_observer_ensure()
            self.assertEqual(len(calls), 2)

    def test_crash_is_not_persistent(self):
        m = self._mgr()
        proc = mock.Mock()
        proc.pid = 4343
        proc.poll.return_value = 1
        proc.returncode = 1
        hp = {"obs_pid": "/tmp/x.pid", "obs_events": "/tmp/x.ev",
              "obs_log": "/tmp/x.log", "obs_socket": "/tmp/x.sock"}
        with mock.patch.object(m, "auto_observer_pid", return_value=None), \
             mock.patch.object(m, "_ready_binary",
                               return_value=("/opt/usr/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_auto"}), \
             mock.patch.object(gm, "auto_host_paths", return_value=hp), \
             mock.patch.object(m, "_stop_aux"), \
             mock.patch.object(gm, "_spawn", return_value=proc), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_remove"), \
             mock.patch.object(gm, "_wait_ready_events"), \
             mock.patch.object(gm, "tail_lines",
                               return_value=["error engine: exit 4"]):
            r = m.auto_observer_ensure()
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "crash")
        self.assertEqual(m._obs_disabled, "")

    def test_unsupported_engine_is_silent(self):
        m = self._mgr()
        with mock.patch.object(m, "auto_observer_pid", return_value=None), \
             mock.patch.object(m, "_ready_binary",
                               return_value=("/opt/usr/bin/geneva", "")), \
             mock.patch.object(m, "features", return_value={"nfqueue"}):
            r = m.auto_observer_ensure()
        self.assertEqual(r["action"], "unsupported")
        self.assertEqual(m._obs_disabled, "")

    def test_module_is_loaded_once_per_session(self):        # Linux/Keenetic: модуль есть, но не загружен — пробуем modprobe
        # один раз, а не на каждом срезе.
        m = self._mgr()
        m._nflog_load_tried = False
        with mock.patch("core.kmod_manager.nflog_ensure_module") as ens:
            m._ensure_nflog_module()
            m._ensure_nflog_module()
        self.assertEqual(ens.call_count, 1)
        m.auto_observer_reset()
        with mock.patch("core.kmod_manager.nflog_ensure_module") as ens:
            m._ensure_nflog_module()
        self.assertEqual(ens.call_count, 1)

    def test_disabled_detector_revives_when_module_appears(self):
        # Модуль поставили кнопкой, режим не перезапускали: запрет снимается
        # на следующем срезе, не дожидаясь auto_observer_reset().
        m = self._mgr()
        m._obs_disabled = "no_nflog"
        proc = mock.Mock()
        proc.pid = 5151
        proc.poll.return_value = None       # живёт
        hp = {"obs_pid": "/tmp/x.pid", "obs_events": "/tmp/x.ev",
              "obs_log": "/tmp/x.log", "obs_socket": "/tmp/x.sock"}
        with mock.patch.object(m, "auto_observer_pid", return_value=None), \
             mock.patch.object(m, "_ready_binary",
                               return_value=("/opt/usr/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_auto"}), \
             mock.patch.object(gm, "auto_host_paths", return_value=hp), \
             mock.patch.object(m, "_stop_aux"), \
             mock.patch.object(gm, "_spawn", return_value=proc), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_wait_ready_events"), \
             mock.patch.object(gm, "nflog_available", return_value=True):
            r = m.auto_observer_ensure()
        self.assertEqual(r["action"], "started")
        self.assertEqual(r["pid"], 5151)
        self.assertEqual(m._obs_disabled, "")


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

    def test_broken_binary_hint_names_script(self):
        """На месте бинарника init-скрипт (случай geneva_c 2.0.1):
        подсказка обязана звать переустановить, а не «не отвечает»."""
        script = os.path.join(self.tmp, "geneva-init")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncase \"$1\" in start) ;; esac\n")
        self.assertIn("Переустановить", self.mgr._broken_binary_hint(script))
        self.assertIn("скрипт", self.mgr._broken_binary_hint(script))
        elf = os.path.join(self.tmp, "geneva-elf")
        with open(elf, "wb") as f:
            f.write(b"\x7fELF" + b"\0" * 60)
        self.assertIn("не отвечает", self.mgr._broken_binary_hint(elf))

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


class TestExtStrategies(_StubCase):
    """x-стратегии geneva_c 2.0: --ext и фейки zapret2 (core/geneva_ext)."""

    X = "[TCP:flags:PA]-xfake{blob=z2_tls_clienthello_vk_com;ttl=3}-|"

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"GENEVA_STUB_EXT": "1"})
        p.start()
        self.addCleanup(p.stop)
        base = os.path.join(self.tmp, "zapret2")
        self.fake = os.path.join(base, "files", "fake")
        os.makedirs(self.fake)
        for name in ("tls_clienthello_vk_com.bin", "tls_alert.bin"):
            with open(os.path.join(self.fake, name), "wb") as f:
                f.write(b"\x16\x03\x01")
        self.cfg.set("zapret", "bin_path",
                     os.path.join(base, "files", "fake"))

    def runs(self):
        return [c for c in self.calls() if c.startswith("run ")]

    def test_detect_reports_ext(self):
        self.assertTrue(self.mgr.detect()["ext"])

    def test_x_strategy_runs_with_ext_and_fakes(self):
        res = self.mgr.set_strategy(self.X)
        self.assertTrue(res["ok"], res)
        self.assertTrue(any(c.startswith("check --ext ")
                            for c in self.calls()))
        res = self.mgr.start()
        self.assertTrue(res["ok"], res)
        run = self.runs()[-1]
        self.assertTrue(run.startswith("run --ext --ext-blob "), run)
        self.assertIn("z2_tls_alert:@%s" % os.path.join(
            self.fake, "tls_alert.bin"), run)
        self.assertIn("z2_tls_clienthello_vk_com:@", run)

    def _search_args(self):
        with mock.patch("core.bypass_engine.pause_for_search",
                        return_value=""):
            res = self.mgr.start_search({"host": "blocked.example",
                                         "population": 4, "generations": 1})
            self.assertTrue(res["ok"], res)
            wait_for(lambda: not self.mgr.job_running(), 15)
        return [c for c in self.calls() if c.startswith("evolve ")][-1]

    def test_search_without_xgen_has_no_ext(self):
        # geneva_c 2.0.0: подбор только скрещивает x-действия — как раньше
        self.assertTrue(self._search_args().startswith("evolve --probe "))

    def test_search_with_xgen_runs_with_ext_and_fakes(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_XGEN": "1"}):
            args = self._search_args()
        self.assertTrue(args.startswith("evolve --ext --ext-blob "), args)
        self.assertIn("z2_tls_alert:@%s" % os.path.join(
            self.fake, "tls_alert.bin"), args)

    def test_plain_strategy_runs_without_ext(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.assertTrue(self.mgr.start()["ok"])
        self.assertNotIn("--ext", self.runs()[-1])

    def test_live_switch_to_x_restarts_with_ext(self):
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.assertTrue(self.mgr.start()["ok"])
        res = self.mgr.set_strategy(self.X)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["restarted"])
        self.assertTrue(self.mgr.is_running())
        self.assertTrue(self.runs()[-1].startswith("run --ext "))
        # дальше x-стратегии меняются через сокет, без перезапуска
        res = self.mgr.set_strategy(
            "[TCP:flags:PA]-xfake{blob=z2_tls_alert;ttl=2}-|")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["applied_live"])
        self.assertEqual(len(self.runs()), 2)

    def test_new_fake_needs_restart_not_socket(self):
        """Фейки geneva читает при запуске: стратегия с фейком, которого
        процесс не получил, ставится перезапуском, а не через сокет."""
        self.assertTrue(self.mgr.set_strategy(self.X)["ok"])
        self.assertTrue(self.mgr.start()["ok"])
        with open(os.path.join(self.fake, "stun.bin"), "wb") as f:
            f.write(b"\x00\x01")
        res = self.mgr.set_strategy("[UDP:dport:3478]-xfake{blob=z2_stun}-|")
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["restarted"])
        self.assertIn("z2_stun:@", self.runs()[-1])

    def test_failed_restart_keeps_old_strategy(self):
        plain = "[TCP:flags:PA]-duplicate-|"
        self.mgr.set_strategy(plain)
        self.assertTrue(self.mgr.start()["ok"])
        with mock.patch.dict(os.environ, {"GENEVA_STUB_RUN_FAIL": "4"}):
            res = self.mgr.set_strategy(self.X)
        self.assertFalse(res["ok"])
        self.assertEqual(self.cfg.get("geneva", "strategy"), plain + " \\/")

    def test_missing_fake_is_refused(self):
        res = self.mgr.check_strategy(
            "[TCP:flags:PA]-xfake{blob=z2_tls_clienthello_nope;ttl=3}-|")
        self.assertFalse(res["ok"])
        self.assertIn("z2_tls_clienthello_nope", res["error"])

    def test_old_geneva_refuses_x_strategy(self):
        with mock.patch.dict(os.environ, {"GENEVA_STUB_EXT": "0"}):
            self.mgr._version_cache = {}
            self.assertFalse(self.mgr.detect()["ext"])
            res = self.mgr.check_strategy(self.X)
            self.assertFalse(res["ok"])
            self.assertIn("geneva_c 2.0", res["error"])
            good, bad = self.mgr.runnable(
                [self.X, "[TCP:flags:PA]-drop-|"])
            self.assertEqual(good, ["[TCP:flags:PA]-drop-|"])
            self.assertEqual(len(bad), 1)


class TestZapret2Manual(TestExtStrategies):
    """Ручной подбор с методами zapret2, «Библиотека» с ними и «Не
    трогать» для ручного run (AutoTuner 1.4)."""

    def test_search_seeds_zapret2_methods(self):
        self.cfg.set("geneva", "search", {"zapret2": True})
        args = self._search_args()
        self.assertTrue(args.startswith("evolve --ext "), args)
        self.assertIn("--load-from ", args)
        with open(gm.paths()["seeds"]) as f:
            seeds = f.read().split("\n")
        from core import geneva_auto as ga
        self.assertEqual(seeds[0], ga.X_TCP[0])

    def test_http_probe_seeds_http_methods(self):
        from core import geneva_auto as ga
        self.assertEqual(gm.zapret2_seeds({"probe": "http"}),
                         list(ga.X_HTTP))
        self.assertEqual(gm.zapret2_seeds({"probe": "tls", "port": 80}),
                         list(ga.X_HTTP))
        self.assertEqual(gm.zapret2_seeds({"probe": "tls"}), list(ga.X_TCP))

    def test_library_lists_zapret2_methods(self):
        items = self.mgr.library(zapret2=True)["items"]
        z2 = [i for i in items if i.get("zapret2")]
        self.assertEqual({i["test"] for i in z2}, {"TLS", "HTTP", "TCP"})
        self.assertFalse(any(i.get("zapret2")
                             for i in self.mgr.library()["items"]))

    def test_exclude_goes_to_manual_run(self):
        self.cfg.set("geneva", "auto", {"exclude": [
            "bank.example", "10.0.0.0/8", "192.0.2.7"]})
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        with mock.patch.dict(os.environ, {"GENEVA_STUB_LISTS": "1"}):
            self.mgr._version_cache = {}
            self.assertTrue(self.mgr.start()["ok"])
        run = self.runs()[-1]
        self.assertTrue(run.startswith("run --ext "), run)
        self.assertIn("--ipset-exclude-ip 10.0.0.0/8,192.0.2.7/32", run)
        self.assertIn("--hostlist-exclude-domains bank.example", run)

    def test_exclude_without_ext_lists_only_warns(self):
        self.cfg.set("geneva", "auto", {"exclude": ["bank.example"]})
        self.mgr.set_strategy("[TCP:flags:PA]-duplicate-|")
        self.assertTrue(self.mgr.start()["ok"])
        self.assertNotIn("exclude", self.runs()[-1])


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

    def test_stop_waits_without_lock_and_keeps_stopped(self):
        """Ожидание выхода — без замка; итог, дописанный монитором за это
        время, второй раз не переписывается."""
        import threading
        with mock.patch.dict(os.environ, {"GENEVA_STUB_GEN_DELAY": "0.4"}):
            self.assertTrue(self.mgr.start_search(
                {"host": "blocked.example", "generations": 50})["ok"])
            self.assertTrue(wait_for(
                lambda: self.mgr.search_status()["generation"] >= 1))
        real = gm._terminate
        seen = {}

        def terminate(pid, sub, wait=0.0):
            clean = real(pid, sub, wait=wait)
            # «Монитор» из другого потока: замок свободен, он дописывает
            # итог раньше stop_search.
            def monitor():
                seen["free"] = self.mgr._lock.acquire(timeout=2)
                if seen["free"]:
                    try:
                        self.mgr._finish_job(None)
                    finally:
                        self.mgr._lock.release()
            t = threading.Thread(target=monitor)
            t.start()
            t.join(5)
            return clean

        with mock.patch.object(gm, "_terminate", side_effect=terminate):
            res = self.mgr.stop_search()
        self.assertTrue(res["ok"])
        self.assertTrue(seen.get("free"), "stop_search держал замок")
        st = self.mgr.search_status()
        self.assertEqual(st["status"], "stopped")
        self.assertTrue(st["can_resume"])

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


class TestAutoEngineProfiles(unittest.TestCase):
    """Один процесс на все стратегии: файл профилей, argv и запуск."""

    S1 = "[TCP:flags:PA]-fragment{tcp:34:True:17}-| \\/"
    S2 = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ep = {k: os.path.join(self.tmp, "engine", k)
                   for k in ("profiles", "signature", "args", "log",
                             "events", "pid", "socket", "strategies")}
        self.ep["dir"] = os.path.join(self.tmp, "engine")

    def _profile(self, name, strategy, ips, tcp="443", udp=""):
        strategy = self.S1 if strategy == "S1" else strategy
        return ga.Profile(strategy=strategy, services=[name], targets=[
            ga.Target(addresses=list(ips), tcp_ports=tcp, udp_ports=udp)],
            name=name)

    def test_ini_has_ports_ipset_and_strategy_file(self):
        profs = [self._profile("p1", "S1", ["1.1.1.1"]),
                 self._profile("p2", "S2", [], tcp="", udp="6881")]
        text = gm.auto_profiles_ini(profs, self.ep)
        self.assertIn("[profile p1]", text)
        self.assertIn("filter-tcp = 443", text)
        self.assertIn("ipset = %s/ips-0.txt" % self.ep["dir"], text)
        self.assertIn("strategy-file = %s/strategy-0.txt" % self.ep["dir"],
                      text)
        # профиль без адресов сервера tcp не назвал: geneva сама
        # запретит tcp (defaults дописывает пропущенный протокол)
        self.assertIn("[profile p2]\nfilter-udp = 6881", text)
        self.assertNotIn("1-65535", text)
        self.assertNotIn("ips-1.txt", text)

    def test_ini_never_takes_every_port_with_explicit_ports(self):
        # geneva отвергает профиль «все порты» при -p: «все» называем
        # только для tcp, udp остаётся запрещённым (defaults в geneva)
        text = gm.auto_profiles_ini([self._profile("p1", "S", [], tcp="")],
                                    self.ep)
        self.assertIn("filter-tcp = 1-65535", text)
        self.assertNotIn("filter-udp", text)

    def test_args_ask_for_workers_and_profile_file(self):
        args = gm.build_auto_engine_args("/bin/geneva", self.ep, 6,
                                         ["--ext"])
        self.assertEqual(args[:3], ["/bin/geneva", "run", "--ext"])
        self.assertEqual(args[args.index("--ext-workers") + 1], "6")
        self.assertEqual(args[args.index("--ext-profile") + 1],
                         self.ep["profiles"])
        self.assertEqual(args[args.index("-q") + 1],
                         str(ga.QUEUE_BASE))
        self.assertEqual(args[args.index("--firewall") + 1], "none")
        self.assertEqual(args[args.index("--proto") + 1], "tcp,udp")

    def test_workers_never_reach_the_host_queue(self):
        """Диапазон 340..340+N-1 не должен дойти до очереди «по имени» и
        детектора: они получат чужие пакеты. Предел — только у движка."""
        args = gm.build_auto_engine_args("/bin/geneva", self.ep, 1000,
                                         ["--ext"])
        n = int(args[args.index("--ext-workers") + 1])
        self.assertEqual(n, ga.ENGINE_WORKERS_MAX)
        self.assertLess(ga.QUEUE_BASE + n - 1, ga.HOST_QUEUE)
        self.assertLess(ga.HOST_QUEUE, ga.OBSERVE_QUEUE)

    def test_workers_limit_is_the_engine_limit(self):
        """Потоков не меньше, чем умеет сам geneva_c (--ext-workers 1–64):
        наши числа не должны вводить свой предел."""
        self.assertEqual(ga.ENGINE_WORKERS_MAX, 64)
        self.assertEqual(ga.ENGINE_QUEUES_MAX, ga.ENGINE_WORKERS_MAX)
        args = gm.build_auto_engine_args("/bin/geneva", self.ep, 64,
                                         ["--ext"])
        self.assertEqual(args[args.index("--ext-workers") + 1], "64")

    def test_queue_matches_reads_argv(self):
        """Живой процесс «по имени»/детектора сверяется по фактической
        ``-q``: подпись от номера очереди не зависит, и процесс пережил бы
        её смену."""
        def argv(words):
            data = b"\0".join(w.encode() for w in words) + b"\0"

            class F:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return data

            return F()

        with mock.patch("builtins.open", lambda *a, **k: argv(
                ["/opt/usr/bin/geneva", "run", "-q", "404", "--ext"])):
            self.assertTrue(gm._queue_matches(4242, ga.HOST_QUEUE))
            self.assertFalse(gm._queue_matches(4242, ga.OBSERVE_QUEUE))
        # нет /proc — верим подписи (как pid_alive)
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertTrue(gm._queue_matches(4242, ga.HOST_QUEUE))
        self.assertFalse(gm._queue_matches(None, ga.HOST_QUEUE))

    def test_apply_writes_files_and_spawns(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        proc = mock.Mock()
        proc.pid = 7001
        proc.poll.return_value = None
        calls = []

        def spawn(args, log_path):
            calls.append(args)
            return proc

        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_profile"}), \
             mock.patch.object(m, "ext_problem", return_value=""), \
             mock.patch.object(m, "auto_engine_pid", return_value=None), \
             mock.patch.object(m, "auto_engine_stop"), \
             mock.patch.object(gm, "auto_engine_paths", return_value=self.ep), \
             mock.patch.object(gm, "_spawn", side_effect=spawn), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_wait_ready_events"), \
             mock.patch.object(gm, "trim_file"):
            r = m.auto_engine_apply(
                [self._profile("p1", "S1", ["1.1.1.1"])], 3)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["action"], "started")
        self.assertEqual(len(calls), 1)
        with open(os.path.join(self.ep["dir"], "ips-0.txt")) as f:
            self.assertEqual(f.read().strip().split("\n")[-1], "1.1.1.1")
        with open(os.path.join(self.ep["dir"], "strategy-0.txt")) as f:
            self.assertEqual(f.read().strip(), self.S1)
        with open(self.ep["profiles"]) as f:
            self.assertIn("[profile p1]", f.read())

    def test_apply_x_strategy_passes_blob_pairs_not_names(self):
        """Регрессия 0.26.06: с geneva_c 2.0.2 (ext_xgen) поиск находит
        x-стратегии, и argv() дорос до блобов — ему нужны ПАРЫ
        (имя, путь), а ему передавали имена. Тик «Авто» и пробы в поиске
        падали «too many values to unpack (expected 2)»."""
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        proc = mock.Mock()
        proc.pid = 7001
        proc.poll.return_value = None
        calls = []

        def spawn(args, log_path):
            calls.append(args)
            return proc

        xstrat = "[TCP:flags:PA]-xfake{blob=z2_fake_default_tls}-| \\/"
        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features",
                              return_value={"ext_xact", "ext_profile"}), \
             mock.patch.object(gm.geneva_ext, "blob_files",
                               return_value=[("z2_fake_default_tls",
                                              "/tmp/fake.bin")]), \
             mock.patch.object(m, "auto_engine_pid", return_value=None), \
             mock.patch.object(m, "auto_engine_stop"), \
             mock.patch.object(gm, "auto_engine_paths",
                               return_value=self.ep), \
             mock.patch.object(gm, "_spawn", side_effect=spawn), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_wait_ready_events",
                               return_value=True), \
             mock.patch.object(gm, "trim_file"):
            r = m.auto_engine_apply(
                [self._profile("p1", xstrat, ["1.1.1.1"])], 3)
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(calls), 1)
        self.assertIn("--ext", calls[0])
        self.assertIn("--ext-blob", calls[0])
        self.assertEqual(
            calls[0][calls[0].index("--ext-blob") + 1],
            "z2_fake_default_tls:@/tmp/fake.bin")

    def _live(self, feats=("ext", "ext_profile"), strategies=None):
        """Менеджер с живым процессом профилей под ``p1`` стратегии S1."""
        os.makedirs(self.ep["dir"], exist_ok=True)
        with open(self.ep["signature"], "w") as f:
            f.write("workers 3\np1")
        self._save_strategies(strategies or {"p1": self.S1})
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        return m, list(feats)

    def _save_strategies(self, strat_of, ports=None):
        with open(self.ep["strategies"], "w") as f:
            json.dump({"workers": 3, "profiles": strat_of,
                       "ports": ports or {"p1": ["443", ""]}}, f)

    def _apply(self, m, feats, profiles):
        calls = []
        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features", return_value=feats), \
             mock.patch.object(m, "ext_problem", return_value=""), \
             mock.patch.object(m, "auto_engine_pid", return_value=7001), \
             mock.patch.object(m, "auto_engine_stop") as stop, \
             mock.patch.object(gm, "control_request",
                               side_effect=lambda *a, **k:
                               calls.append((a, k)) or {"ok": True}), \
             mock.patch.object(gm, "auto_engine_paths", return_value=self.ep):
            r = m.auto_engine_apply(profiles, 3)
        return r, stop, calls

    def test_apply_keeps_live_process_with_same_signature(self):
        """Та же подпись, те же стратегии: только списки и адреса."""
        m, feats = self._live()
        r, stop, calls = self._apply(m, feats,
                                     [self._profile("p1", "S1", ["2.2.2.2"])])
        self.assertEqual(r["action"], "reloaded")
        self.assertEqual(r["pid"], 7001)
        stop.assert_not_called()
        # адреса CDN могли смениться: файл переписан, списки перечитаны
        with open(os.path.join(self.ep["dir"], "ips-0.txt")) as f:
            self.assertIn("2.2.2.2", f.read())
        self.assertEqual([c[0][1] for c in calls], ["reload_lists"])

    def test_strategy_changes_without_restart_when_the_engine_allows(self):
        """X6d: стратегия профиля меняется на ходу, процесс тот же."""
        s2 = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"
        m, feats = self._live(feats=("ext", "ext_profile",
                                     "ext_profile_runtime"))
        r, stop, calls = self._apply(m, feats,
                                     [self._profile("p1", "S1", [])])
        self.assertEqual(r["action"], "reloaded")   # стратегия та же
        r, stop, calls = self._apply(
            m, feats, [self._profile("p1", s2, [])])
        self.assertEqual(r["action"], "updated")
        self.assertEqual(r["pid"], 7001)
        stop.assert_not_called()
        # одна команда: reload перечитывает и стратегии, и списки
        self.assertEqual([c[0][1] for c in calls], ["reload"])
        # запомнили: следующий срез не станет менять её заново
        self.assertEqual(m._engine_strategies(self.ep)["profiles"],
                         {"p1": s2})

    def test_port_change_restarts_even_with_runtime(self):
        """Порты профиля повторяют правила firewall — только перезапуск."""
        m, feats = self._live(feats=("ext", "ext_profile",
                                     "ext_profile_runtime"))
        prof = self._profile("p1", "S1", [], tcp="80")
        with mock.patch.object(gm, "_spawn") as spawn, \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_wait_ready_events", return_value=True):
            proc = mock.Mock(pid=8123, returncode=None)
            proc.poll.return_value = None
            spawn.return_value = proc
            r, stop, calls = self._apply(m, feats, [prof])
        self.assertEqual(r["action"], "started")
        stop.assert_called()
        self.assertNotIn("set_strategy", [c[0][1] for c in calls])

    def test_strategy_change_restarts_an_old_engine(self):
        """geneva_c 2.0.1 (без X6d): смена стратегии — перезапуск."""
        s2 = "[TCP:flags:PA]-fragment{tcp:-1:True}-| \\/"
        m, feats = self._live()
        with mock.patch.object(gm, "_spawn") as spawn, \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_wait_ready_events", return_value=True):
            proc = mock.Mock(pid=8123, returncode=None)
            proc.poll.return_value = None
            spawn.return_value = proc
            r, stop, calls = self._apply(
                m, feats, [self._profile("p1", s2, [])])
        self.assertEqual(r["action"], "started")
        stop.assert_called()
        self.assertNotIn("set_strategy", [c[0][1] for c in calls])

    def test_apply_without_profile_feature_is_unsupported(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features", return_value={"ext"}):
            r = m.auto_engine_apply([self._profile("p1", "S", [])], 2)
        self.assertEqual(r["action"], "unsupported")
        self.assertFalse(r["ok"])

    def test_apply_empty_stops(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_profile"}), \
             mock.patch.object(m, "auto_engine_stop") as stop:
            r = m.auto_engine_apply([], 2)
        self.assertEqual(r["action"], "stopped")
        stop.assert_called_once()

    def test_apply_crash_reports_log_tail(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        proc = mock.Mock()
        proc.pid = 7002
        proc.poll.return_value = 1
        proc.returncode = 1
        with mock.patch.object(m, "_ready_binary",
                               return_value=("/bin/geneva", "")), \
             mock.patch.object(m, "features",
                               return_value={"ext", "ext_profile"}), \
             mock.patch.object(m, "ext_problem", return_value=""), \
             mock.patch.object(m, "auto_engine_pid", return_value=None), \
             mock.patch.object(m, "auto_engine_stop"), \
             mock.patch.object(gm, "auto_engine_paths", return_value=self.ep), \
             mock.patch.object(gm, "_spawn", return_value=proc), \
             mock.patch.object(gm, "_write_pid"), \
             mock.patch.object(gm, "_remove"), \
             mock.patch.object(gm, "_wait_ready_events"), \
             mock.patch.object(gm, "trim_file"), \
             mock.patch.object(gm, "tail_lines",
                               return_value=["error: profile p2: bad"]):
            r = m.auto_engine_apply(
                [self._profile("p1", "S1", ["1.1.1.1"])], 2)
        self.assertFalse(r["ok"])
        self.assertIn("profile p2", r["error"])

    def test_status_reads_workers_and_names(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        os.makedirs(self.ep["dir"], exist_ok=True)
        with open(self.ep["profiles"], "w") as f:
            f.write("[profile p1]\nfilter-tcp = 443\n\n[profile p2]\n")
        with open(self.ep["args"], "w") as f:
            json.dump(["geneva", "run", "--ext-workers", "5"], f)
        with mock.patch.object(gm, "auto_engine_paths", return_value=self.ep), \
             mock.patch.object(m, "auto_engine_pid", return_value=7003):
            st = m.auto_engine_status()
        self.assertEqual(st["workers"], 5)
        self.assertEqual(st["profiles"], ["p1", "p2"])
        self.assertTrue(st["running"])
        self.assertEqual(st["queues"], [340, 341, 342, 343, 344])


class TestAutoGroupQueueGuard(unittest.TestCase):
    """Граница очередей групп «Авто» — одна константа с валидатором.

    Регрессия: ``AUTO_QUEUE_MAX`` в geneva_manager отстал от
    ``MAX_GROUPS_LIMIT`` (8 против 64) — auto_apply отвергал сохранённые
    настройки ошибкой «очередь вне 340–347», хотя карточка их приняла.
    """

    STRAT = "[TCP:flags:PA]-duplicate-| \\/"

    def _mgr(self):
        m = gm.GenevaManager.__new__(gm.GenevaManager)
        m._lock = threading.RLock()
        m._auto_procs = {}
        return m

    def test_limit_synced_with_validator(self):
        self.assertEqual(gm.AUTO_QUEUE_MAX, ga.MAX_GROUPS_LIMIT)

    def test_apply_accepts_last_queue(self):
        m = self._mgr()
        q = gm.AUTO_QUEUE_BASE + gm.AUTO_QUEUE_MAX - 1
        with mock.patch.object(m, "auto_groups", return_value={}), \
             mock.patch.object(m, "auto_group_pid", return_value=None), \
             mock.patch.object(m, "ext_problem", return_value=None), \
             mock.patch.object(m, "_ready_binary",
                               return_value=("/opt/usr/bin/geneva", "")), \
             mock.patch.object(m, "_auto_spawn",
                               return_value={"pid": 7, "action": "started"}) as sp:
            res = m.auto_apply({q: self.STRAT})
        self.assertEqual(res["queues"][q]["action"], "started")
        self.assertTrue(res["ok"])
        sp.assert_called_once()

    def test_apply_rejects_queue_beyond_limit(self):
        m = self._mgr()
        q = gm.AUTO_QUEUE_BASE + gm.AUTO_QUEUE_MAX
        with mock.patch.object(m, "auto_groups", return_value={}), \
             mock.patch.object(m, "_auto_spawn") as sp:
            res = m.auto_apply({q: self.STRAT})
        self.assertIn("вне", res["queues"][q]["error"])
        self.assertFalse(res["ok"])
        sp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
