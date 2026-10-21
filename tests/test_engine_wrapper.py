# tests/test_engine_wrapper.py
"""Общая обвязка AWG / sing-box / mihomo (core/engine_common.py).

Паритет трёх движков: лимит памяти Go, режим отладки и лог демона AWG,
проверка связи через туннель AWG, диагностика sing-box/mihomo, init-
скрипт автозапуска через app.py и одинаковые роуты для всех трёх.
"""

import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from core import engine_common


class FakeCM:
    """Заменитель config_manager: get(section, key, default) / set / save."""

    def __init__(self, data=None):
        self.data = data or {}
        self.saved = 0

    def get(self, section, key=None, default=None):
        sec = self.data.get(section, {})
        if key is None:
            return sec or default
        return sec.get(key, default)

    def set(self, section, key, value):
        self.data.setdefault(section, {})[key] = value

    def save(self):
        self.saved += 1


class _CMCase(unittest.TestCase):
    def setUp(self):
        self.cm = FakeCM()
        p = mock.patch.object(engine_common, "_cm", return_value=self.cm)
        p.start()
        self.addCleanup(p.stop)


# ─────────────────────────── лимит памяти Go ────────────────────────

class TestGoMemory(_CMCase):

    def test_defaults_for_every_engine(self):
        for engine in engine_common.ENGINES:
            self.assertEqual(engine_common.go_memory_get(engine),
                             {"enabled": False, "gogc": 50,
                              "memlimit_mb": 64})

    def test_awg_keys_are_kept(self):
        # Старые настройки AWG (go_mem_*) читаются как есть — пользователи
        # не теряют включённый лимит после обновления.
        self.cm.data["awg"] = {"go_mem_enabled": True, "go_gogc": 30,
                               "go_memlimit_mb": 48}
        self.assertEqual(engine_common.go_memory_get("awg"),
                         {"enabled": True, "gogc": 30, "memlimit_mb": 48})

    def test_set_and_env(self):
        engine_common.go_memory_set("singbox", enabled=True, gogc=40,
                                    memlimit_mb=96)
        self.assertEqual(self.cm.data["singbox"]["go_gogc"], 40)
        self.assertEqual(engine_common.go_memory_vars("singbox"),
                         {"GOGC": "40", "GOMEMLIMIT": "96MiB"})
        env = engine_common.launch_env("singbox")
        self.assertEqual(env["GOMEMLIMIT"], "96MiB")
        self.assertIn("PATH", env)      # окружение GUI унаследовано
        # Другой движок не задет.
        self.assertIsNone(engine_common.launch_env("mihomo"))

    def test_zero_means_unset(self):
        engine_common.go_memory_set("mihomo", enabled=True, gogc=0,
                                    memlimit_mb=128)
        self.assertEqual(engine_common.go_memory_vars("mihomo"),
                         {"GOMEMLIMIT": "128MiB"})

    def test_disabled_inherits_env(self):
        engine_common.go_memory_set("awg", enabled=False, gogc=10)
        self.assertIsNone(engine_common.launch_env("awg"))
        self.assertEqual(engine_common.launch_env("awg", {"X": "1"})["X"],
                         "1")

    def test_set_persists_all_fields(self):
        # Что видно в GUI (умолчания), то и применяется при запуске.
        engine_common.go_memory_set("mihomo", enabled=True)
        self.assertEqual(self.cm.data["mihomo"],
                         {"go_mem_enabled": True, "go_gogc": 50,
                          "go_memlimit_mb": 64})

    def test_invalid_values_write_nothing(self):
        with self.assertRaises(engine_common.SettingsError):
            engine_common.go_memory_set("awg", enabled=True, gogc="abc")
        with self.assertRaises(engine_common.SettingsError):
            engine_common.go_memory_set("awg", memlimit_mb=-1)
        self.assertEqual(self.cm.data, {})
        self.assertEqual(self.cm.saved, 0)

    def test_unknown_engine(self):
        with self.assertRaises(engine_common.SettingsError):
            engine_common.go_memory_get("usque")


class TestDebugFlag(_CMCase):

    def test_roundtrip(self):
        self.assertFalse(engine_common.debug_enabled("awg"))
        self.assertTrue(engine_common.set_debug("awg", True)["ok"])
        self.assertTrue(engine_common.debug_enabled("awg"))
        self.assertTrue(self.cm.data["awg"]["debug_log"])


# ─────────────────────────── /proc и лог ────────────────────────────

class TestProcessInfo(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="zg-proc-")
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(os.path.join(self.root, "42"))
        with open(os.path.join(self.root, "42", "status"), "w") as f:
            f.write("Name:\tsing-box\nVmHWM:\t  20480 kB\n"
                    "VmRSS:\t  10240 kB\nThreads:\t9\n")
        # Имя с пробелом и скобкой — режем по последней «)».
        fields = ["S"] + ["0"] * 18 + ["1000"] + ["0"] * 10
        with open(os.path.join(self.root, "42", "stat"), "w") as f:
            f.write("42 (sing box) %s\n" % " ".join(fields))
        with open(os.path.join(self.root, "uptime"), "w") as f:
            f.write("110.00 50.00\n")

    def test_reads_status_and_uptime(self):
        with mock.patch.object(engine_common, "_clock_ticks",
                               return_value=100):
            info = engine_common.process_info(42, proc_root=self.root)
        self.assertEqual(info["rss_kb"], 10240)
        self.assertEqual(info["rss_peak_kb"], 20480)
        self.assertEqual(info["threads"], 9)
        self.assertEqual(info["uptime_sec"], 100)

    def test_missing_process(self):
        self.assertEqual(engine_common.process_info(7, proc_root=self.root),
                         {})
        self.assertEqual(engine_common.process_info(None), {})

    def test_tail_file(self):
        path = os.path.join(self.root, "x.log")
        with open(path, "w") as f:
            f.write("\n".join("line %d" % i for i in range(100)))
        self.assertEqual(engine_common.tail_file(path, 2),
                         "line 98\nline 99")
        self.assertEqual(engine_common.tail_file(path + ".none"), "")


# ─────────────────────────── init-скрипт ────────────────────────────

class TestAutostartScript(unittest.TestCase):

    def test_entware_calls_app_py(self):
        text = engine_common.render_autostart_script(
            "singbox", "sing-box", "sh", log_path="/tmp/a.log",
            python="/opt/bin/python3", app_py="/opt/zg/app.py")
        self.assertIn('"$PYTHON" "$APP_PY" --apply-singbox-autostart', text)
        self.assertIn("--stop-singbox-autostart", text)
        # Бинарь движка скрипт больше не зовёт сам.
        self.assertNotIn("setsid", text)
        self.assertTrue(text.startswith("#!/bin/sh"))

    def test_systemd_starts_all_configs(self):
        text = engine_common.render_autostart_script(
            "mihomo", "mihomo", "systemd", log_path="/tmp/a.log",
            python="/usr/bin/python3", app_py="/srv/app.py")
        # «-»: частичный отказ не делает юнит failed (иначе systemd убил
        # бы cgroup вместе с поднявшимися инстансами).
        self.assertIn("ExecStart=-/usr/bin/python3 /srv/app.py "
                      "--apply-mihomo-autostart", text)
        self.assertIn("Type=oneshot", text)
        # Раньше юнит поднимал ровно один конфиг: «-f <dir>/<first>.yaml».
        self.assertNotIn(".yaml", text)

    def test_openwrt_is_rc_common(self):
        text = engine_common.render_autostart_script(
            "singbox", "sing-box", "procd", log_path="/var/log/a.log",
            python="/usr/bin/python3", app_py="/srv/app.py")
        self.assertTrue(text.startswith("#!/bin/sh /etc/rc.common"))
        self.assertIn("START=96", text)
        self.assertEqual(engine_common.script_flavor("openwrt"), "procd")
        self.assertEqual(engine_common.script_flavor("linux"), "systemd")
        self.assertEqual(engine_common.script_flavor("keenetic"), "sh")

    def test_flags_exist_in_app_cli(self):
        with open(engine_common.APP_PY, "r", encoding="utf-8") as f:
            app_src = f.read()
        self.assertIn('"--apply-%s-autostart" % _engine', app_src)
        self.assertIn('"--stop-%s-autostart" % _engine', app_src)


class _FakeInitPlatform:
    def __init__(self, base, name="entware"):
        self.name = name
        self.log_dir = base
        self._path = os.path.join(base, "S99engine")

    def init_script_path(self):
        return self._path

    def install_init_script(self, content):
        with open(self._path, "w") as f:
            f.write(content)
        return self._path

    def remove_init_script(self):
        if os.path.exists(self._path):
            os.remove(self._path)


class TestAutostartModules(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="zg-auto-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _check(self, mod, platform_attr, detector):
        plat = _FakeInitPlatform(self.tmp)
        with mock.patch.object(mod, platform_attr, return_value=plat), \
                mock.patch.object(mod, "list_autostart",
                                  return_value={"a": True, "b": True}), \
                mock.patch(detector + ".detect_binary",
                           return_value={"installed": True, "path": "/x"}):
            st = mod.status()
            self.assertFalse(st["script_installed"])
            self.assertIsNone(st["up_to_date"])
            # Старый формат — помечается как устаревший.
            plat.install_init_script("#!/bin/sh\nsetsid /x run\n")
            self.assertFalse(mod.status()["up_to_date"])
            r = mod.regenerate()
            self.assertTrue(r["ok"])
            st = mod.status()
            self.assertTrue(st["script_installed"])
            self.assertTrue(st["up_to_date"])
            self.assertEqual(st["script_path"], plat.init_script_path())
            # Другой путь интерпретатора — скрипт всё равно рабочий, не
            # переписываем его на каждом старте.
            with open(plat.init_script_path()) as f:
                text = f.read()
            plat.install_init_script(text.replace(mod.PYTHON_BIN,
                                                  "/other/python3"))
            self.assertTrue(mod.status()["up_to_date"])

    def test_singbox(self):
        from core import singbox_autostart
        self._check(singbox_autostart, "detect_singbox_platform",
                    "core.singbox_detector.SingboxDetector")

    def test_mihomo(self):
        from core import mihomo_autostart
        self._check(mihomo_autostart, "detect_mihomo_platform",
                    "core.mihomo_detector.MihomoDetector")

    def test_apply_and_stop_report_failures(self):
        from core import mihomo_autostart
        mgr = mock.Mock()
        mgr.list_configs.return_value = [{"name": "a"}, {"name": "b"}]
        mgr.up.side_effect = [{"ok": True}, {"ok": False, "error": "x"}]
        mgr.down.return_value = {"ok": True}
        with mock.patch.object(mihomo_autostart, "list_autostart",
                               return_value={"a": True, "b": True,
                                             "c": False}), \
                mock.patch("core.mihomo_manager.get_mihomo_manager",
                           return_value=mgr):
            r = mihomo_autostart.apply_now()
            self.assertFalse(r["ok"])
            self.assertEqual([x["name"] for x in r["applied"]], ["a", "b"])
            r = mihomo_autostart.stop_now()
            self.assertEqual(mgr.down.call_count, 2)

    def test_missing_config_is_skipped_not_failed(self):
        mgr = mock.Mock()
        mgr.list_configs.return_value = [{"name": "a"}]
        mgr.up.return_value = {"ok": True}
        r = engine_common.autostart_apply("singbox", mgr,
                                          {"a": True, "gone": True})
        self.assertTrue(r["ok"])
        mgr.up.assert_called_once_with("a")
        self.assertTrue(r["applied"][1]["skipped"])


class TestInitScriptEnabled(unittest.TestCase):
    """Записанный скрипт ещё и включён: иначе при загрузке он не идёт."""

    def test_systemd_and_openwrt_enable(self):
        from core import awg_platform, mihomo_platform, singbox_platform
        tmp = tempfile.mkdtemp(prefix="zg-init-")
        self.addCleanup(shutil.rmtree, tmp, True)
        cases = (
            (singbox_platform, "GenericLinuxSingbox", "OpenWrtSingbox"),
            (mihomo_platform, "GenericLinuxMihomo", "OpenWrtMihomo"),
            (awg_platform, "GenericLinuxPlatform", "OpenWrtPlatform"),
        )
        for mod, linux_cls, owrt_cls in cases:
            for cls_name, expect in ((linux_cls, "systemctl"),
                                     (owrt_cls, "enable")):
                plat = getattr(mod, cls_name)()
                plat.init_dir = tmp
                with mock.patch.object(mod, "_cmd_ok",
                                       return_value=True) as cmd:
                    path = plat.install_init_script("x")
                calls = [c.args[0] for c in cmd.call_args_list]
                if expect == "systemctl":
                    self.assertIn(["systemctl", "enable", plat.init_name],
                                  calls, cls_name)
                else:
                    self.assertIn([path, "enable"], calls, cls_name)


class TestLogGuard(unittest.TestCase):

    def test_trim_keeps_tail_from_line_start(self):
        tmp = tempfile.mkdtemp(prefix="zg-trim-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "singbox-x.log")
        with open(path, "w") as f:
            for i in range(2000):
                f.write("line %05d\n" % i)
        self.assertFalse(engine_common.trim_log(path, max_bytes=10 ** 6))
        self.assertTrue(engine_common.trim_log(path, max_bytes=1000,
                                               keep_bytes=100))
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertIn("dropped", lines[0])
        self.assertEqual(lines[-1], "line 01999")
        self.assertTrue(all(l.startswith("line ") for l in lines[1:]))
        self.assertFalse(engine_common.trim_log(path + ".none"))


# ─────────────────────────── запуск с env ───────────────────────────

class _FakeProxyPlatform:
    def __init__(self, base, ext):
        self.run_dir = os.path.join(base, "run")
        self.config_dir = os.path.join(base, "cfg")
        self.log_dir = base
        self.ext = ext
        os.makedirs(self.run_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)

    def config_path(self, name):
        return os.path.join(self.config_dir, name + self.ext)

    def pid_path(self, name):
        return os.path.join(self.run_dir, "%s.pid" % name)

    def log_path(self, name):
        return os.path.join(self.run_dir, "%s.log" % name)

    def tun_available(self):
        return True


class TestLaunchEnvPassed(unittest.TestCase):
    """Лимит памяти доходит до Popen у sing-box и mihomo."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="zg-env-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run(self, mgr, ext, text):
        plat = _FakeProxyPlatform(self.tmp, ext)
        with open(plat.config_path("c"), "w") as f:
            f.write(text)
        popen = mock.Mock(pid=4242)
        popen.poll.return_value = None
        env = {"GOMEMLIMIT": "64MiB"}
        with mock.patch.object(mgr, "_platform", return_value=plat), \
                mock.patch.object(mgr, "_binary", return_value="/bin/true"), \
                mock.patch.object(mgr, "is_running", return_value=False), \
                mock.patch.object(engine_common, "launch_env",
                                  return_value=env) as le, \
                mock.patch("subprocess.Popen", return_value=popen) as po, \
                mock.patch("time.sleep"):
            if hasattr(mgr, "_debug_enabled"):
                with mock.patch.object(mgr, "_debug_enabled",
                                       return_value=False):
                    res = mgr._do_up("c")
            else:
                res = mgr._do_up("c")
        self.assertTrue(res["ok"], res)
        self.assertIs(po.call_args.kwargs["env"], env)
        return le

    def test_singbox(self):
        from core.singbox_manager import SingboxManager
        mgr = SingboxManager()
        with mock.patch("core.singbox_manager._run",
                        return_value=(0, "", "")):
            le = self._run(mgr, ".json", '{"inbounds": []}')
        le.assert_called_with("singbox")

    def test_mihomo(self):
        from core.mihomo_manager import MihomoManager
        mgr = MihomoManager()
        with mock.patch("core.mihomo_manager._run",
                        return_value=(0, "", "")):
            le = self._run(mgr, ".yaml", "mixed-port: 7890\n")
        le.assert_called_with("mihomo")


# ─────────────────────────── AWG: отладка, лог, проба ───────────────

class TestAwgDebugAndLog(unittest.TestCase):

    def setUp(self):
        from core.awg_manager import AwgManager
        self.tmp = tempfile.mkdtemp(prefix="zg-awg-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.mgr = AwgManager()
        plat = mock.Mock(log_dir=self.tmp)
        p = mock.patch.object(self.mgr, "_platform", return_value=plat)
        p.start()
        self.addCleanup(p.stop)
        self.bin = os.path.join(self.tmp, "fake-go")

    def _fake_bin(self, body):
        with open(self.bin, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(self.bin, os.stat(self.bin).st_mode | stat.S_IEXEC)

    def test_no_debug_uses_plain_run(self):
        with mock.patch.object(self.mgr, "_amneziawg_go_env",
                               return_value=None), \
                mock.patch("core.awg_manager._run",
                           return_value=(0, "", "")) as run:
            self.assertEqual(self.mgr._spawn_go("/x/amneziawg-go", "awg0"),
                             (0, ""))
        run.assert_called_once_with(["/x/amneziawg-go", "awg0"], timeout=15,
                                    env=None)
        self.assertFalse(os.path.exists(self.mgr._log_path("awg0")))

    def test_debug_writes_daemon_output_to_log(self):
        self._fake_bin('echo "INFO: device started"\nexit 0\n')
        env = dict(os.environ, LOG_LEVEL="verbose")
        with mock.patch.object(self.mgr, "_amneziawg_go_env",
                               return_value=env):
            rc, err = self.mgr._spawn_go(self.bin, "awg0")
        self.assertEqual((rc, err), (0, ""))
        with mock.patch("core.engine_common.debug_enabled",
                        return_value=True):
            r = self.mgr.read_log("awg0")
        self.assertTrue(r["exists"])
        self.assertIn("device started", r["log"])
        self.assertIn("LOG_LEVEL=verbose", r["log"])
        self.assertTrue(r["debug"])

    def test_debug_failure_returns_new_output_only(self):
        with open(self.mgr._log_path("awg0"), "w") as f:
            f.write("old run noise\n")
        self._fake_bin('echo "ERROR: tun busy" >&2\nexit 1\n')
        env = dict(os.environ, LOG_LEVEL="verbose")
        with mock.patch.object(self.mgr, "_amneziawg_go_env",
                               return_value=env):
            rc, err = self.mgr._spawn_go(self.bin, "awg0")
        self.assertEqual(rc, 1)
        self.assertIn("tun busy", err)
        self.assertNotIn("old run noise", err)
        self.assertNotIn("LOG_LEVEL", err)

    def test_big_log_starts_over(self):
        with open(self.mgr._log_path("awg0"), "wb") as f:
            f.write(b"x" * (self.mgr.LOG_MAX_BYTES + 10))
        self._fake_bin("exit 0\n")
        env = dict(os.environ, LOG_LEVEL="verbose")
        with mock.patch.object(self.mgr, "_amneziawg_go_env",
                               return_value=env):
            self.mgr._spawn_go(self.bin, "awg0")
        self.assertLess(os.path.getsize(self.mgr._log_path("awg0")), 1000)

    def test_env_gets_log_level_only_in_debug(self):
        with mock.patch("core.engine_common.debug_enabled",
                        return_value=True), \
                mock.patch("core.engine_common.go_memory_vars",
                           return_value={}):
            self.assertEqual(self.mgr._amneziawg_go_env()["LOG_LEVEL"],
                             "verbose")
        with mock.patch("core.engine_common.debug_enabled",
                        return_value=False), \
                mock.patch("core.engine_common.go_memory_vars",
                           return_value={}):
            self.assertIsNone(self.mgr._amneziawg_go_env())

    def test_read_log_bad_name(self):
        self.assertFalse(self.mgr.read_log("../etc")["ok"])


class TestAwgProbe(unittest.TestCase):

    def setUp(self):
        from core.awg_manager import AwgManager
        self.mgr = AwgManager()
        self.settings = mock.patch(
            "core.awg_watchdog._get_settings",
            return_value={"probe_host": "9.9.9.9", "probe_port": 443})
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def _probe(self, verdict, running=True):
        with mock.patch.object(self.mgr, "is_running",
                               return_value=running), \
                mock.patch.object(self.mgr, "_iface_for_name",
                                  return_value="awg0"), \
                mock.patch("core.awg_watchdog.probe_via_iface",
                           return_value=verdict) as pv:
            return self.mgr.probe("awg0"), pv

    def test_ok(self):
        r, pv = self._probe(True)
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"], "ok")
        self.assertIn("delay_ms", r)
        self.assertEqual(r["target"], "9.9.9.9:443")
        pv.assert_called_once_with("9.9.9.9", 443, "awg0", 4.0)

    def test_fail_and_cant_bind(self):
        r, _ = self._probe(False)
        self.assertEqual((r["ok"], r["result"]), (False, "fail"))
        r, _ = self._probe(None)
        self.assertEqual((r["ok"], r["result"]), (False, "cant_bind"))

    def test_not_running(self):
        r, pv = self._probe(True, running=False)
        self.assertTrue(r["needs_running"])
        pv.assert_not_called()


# ─────────────────────────── диагностика ────────────────────────────

class TestProxyDiagnostics(_CMCase):

    def test_no_secrets_and_wrapper_fields(self):
        tmp = tempfile.mkdtemp(prefix="zg-diag-")
        self.addCleanup(shutil.rmtree, tmp, True)
        log_path = os.path.join(tmp, "x.log")
        with open(log_path, "w") as f:
            f.write("started\n")
        info = engine_common.proxy_diagnostics(
            "singbox", "x", pid=None, active=False,
            binary={"installed": True, "path": "/b", "version": "1.11"},
            config_path=os.path.join(tmp, "x.json"),
            config_check={"ok": True, "output": ""}, log_path=log_path,
            autostart=True,
            controller={"host": "127.0.0.1", "port": 9090,
                        "secret": "TOPSECRET"})
        self.assertNotIn("TOPSECRET", repr(info))
        self.assertEqual(info["wrapper"]["autostart"], True)
        self.assertEqual(info["wrapper"]["go_memory"]["gogc"], 50)
        self.assertEqual(info["log_tail"], "started")
        self.assertFalse(info["config"]["exists"])
        # Инстанс не запущен — контроллер не опрашиваем.
        self.assertIsNone(info["controller"]["reachable"])

    def test_controller_unreachable(self):
        r = engine_common.controller_check(
            {"host": "127.0.0.1", "port": 9, "secret": ""}, timeout=0.5)
        self.assertTrue(r["configured"])
        self.assertFalse(r["reachable"])
        self.assertEqual(engine_common.controller_check(None),
                         {"configured": False})


# ─────────────────────────── роуты ──────────────────────────────────

class TestRoutes(_CMCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_go_memory_same_for_three_engines(self):
        for engine in ("awg", "singbox", "mihomo"):
            r = self.client.post_json("/api/%s/go-memory" % engine,
                                      {"enabled": True, "gogc": 25,
                                       "memlimit_mb": 32})
            self.assertEqual(r["_status"], 200, engine)
            self.assertTrue(r["enabled"])
            g = self.client.get_json("/api/%s/go-memory" % engine)
            self.assertEqual((g["gogc"], g["memlimit_mb"]), (25, 32))

    def test_go_memory_bad_input_400(self):
        r = self.client.post_json("/api/mihomo/go-memory", {"gogc": "x"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])

    def test_awg_debug_toggle(self):
        r = self.client.post_json("/api/awg/debug", {"enabled": True})
        self.assertTrue(r["enabled"])
        self.assertTrue(self.client.get_json("/api/awg/debug")["enabled"])

    def test_diagnostics_missing_config_404(self):
        for engine in ("singbox", "mihomo"):
            r = self.client.get_json(
                "/api/%s/configs/never-exists/diagnostics" % engine)
            self.assertEqual(r["_status"], 404, engine)

    def test_awg_log_and_test_routes(self):
        r = self.client.get_json("/api/awg/configs/never-exists/log")
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r["exists"])
        with mock.patch("core.awg_manager.AwgManager.is_running",
                        return_value=False):
            r = self.client.post_json("/api/awg/configs/never-exists/test",
                                      {})
        self.assertTrue(r["needs_running"])

    def test_mihomo_traffic_reset(self):
        tracker = mock.Mock()
        with mock.patch("core.proxy_traffic.get_mihomo_traffic_tracker",
                        return_value=tracker):
            r = self.client.post_json("/api/mihomo/traffic/reset",
                                      {"names": ["a"]})
        self.assertTrue(r["ok"])
        tracker.reset.assert_called_once_with(["a"])


if __name__ == "__main__":
    unittest.main()
