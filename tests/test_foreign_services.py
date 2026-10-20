# tests/test_foreign_services.py
"""Сторонние экземпляры туннелей (core/foreign_services).

Что сторожим:
* свои скрипты (`*-gui`, маркер zapret-gui, S99zapret*, скрипт пакета
  tg-ws-proxy) никогда не попадают в «чужие»;
* `S51usque` и `S52awg-opkgtun0` на одном `opkgtun0` — это конфликт;
* отключение на Entware — снятие бита исполнения с запоминанием режима,
  «Вернуть» восстанавливает его, а обновление пакета (бит вернулся) —
  повод отключить снова;
* «передать GUI», который не поднял туннель, возвращает чужой скрипт;
* установка через GUI отключает скрипт пакета, который GUI сам поставил
  (usque-keenetic), но не трогает скрипт tg-ws-proxy.
"""

import os
import stat
import tempfile
import unittest
from unittest import mock

from core import foreign_services as fs


class TestClassify(unittest.TestCase):

    def test_engine_by_name(self):
        cases = {
            "S51usque": "usque",
            "S99sing-box": "singbox",
            "S99mihomo": "mihomo",
            "S99amneziawg": "awg",
            "S52awg-opkgtun0": "awg",
            "S99opera-proxy": "opera",
            "S98tg-tunnel": "tgproxy",
        }
        for name, engine in cases.items():
            with self.subTest(name=name):
                self.assertEqual(fs.classify_script(name, ""), engine)

    def test_own_scripts_are_never_foreign(self):
        for name in ("S51amneziawg-gui", "S52sing-box-gui",
                     "S53mihomo-gui", "S99zapret", "S99zapret-gui"):
            with self.subTest(name=name):
                self.assertEqual(fs.classify_script(name, "sing-box run"), "")
        body = "#!/bin/sh\n# zapret-gui: sing-box autostart\nsing-box run\n"
        self.assertEqual(fs.classify_script("S52whatever", body), "")
        # Путь с «zapret-gui» внутри — ещё не наш маркер.
        body = "#!/bin/sh\nsing-box run -c /opt/zapret-gui/x.json\n"
        self.assertEqual(fs.classify_script("S99sing-box", body), "singbox")

    def test_engine_by_body(self):
        body = "#!/bin/sh\n/opt/usr/bin/usque nativetun -n opkgtun1\n"
        self.assertEqual(fs.classify_script("S51z2k-warp", body), "usque")
        self.assertEqual(fs.classify_script("S10cron", "crond -b"), "")


class TestIfacesAndConflicts(unittest.TestCase):

    def test_script_ifaces(self):
        body = ('ARGS="nativetun -n opkgtun0 -c /opt/etc/usque/config.json"\n'
                '# wg9 в комментарии не считается\n')
        self.assertEqual(fs.script_ifaces("S51usque", body), ["opkgtun0"])
        self.assertEqual(fs.script_ifaces("S52awg-opkgtun0", ""),
                         ["opkgtun0"])
        self.assertEqual(fs.script_ifaces("S99x", "IFACE=$1\n"), [])
        body = "awg-quick up /opt/etc/amneziawg/awg0-opkgtun0.conf\n"
        self.assertEqual(fs.script_ifaces("S52awg-opkgtun0", body),
                         ["opkgtun0"])

    def test_usque_and_awg_scripts_on_one_name(self):
        scripts = [
            {"path": "/opt/etc/init.d/S51usque", "name": "S51usque",
             "engine": "usque", "enabled": True, "ifaces": ["opkgtun0"],
             "configs": ["/opt/etc/usque/config.json"]},
            {"path": "/opt/etc/init.d/S52awg-opkgtun0",
             "name": "S52awg-opkgtun0", "engine": "awg", "enabled": True,
             "ifaces": ["opkgtun0"],
             "configs": ["/opt/etc/amneziawg/awg0-opkgtun0.conf"]},
        ]
        gui = [("opkgtun0", "конфиг AWG «awg0-opkgtun0»", "awg",
                "/opt/etc/amneziawg/awg0-opkgtun0.conf")]
        out = fs.find_conflicts(scripts, [], gui)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["iface"], "opkgtun0")
        labels = [c["label"] for c in out[0]["claimants"]]
        # Конфиг AWG — тот же туннель, что S52awg-opkgtun0, не третий.
        self.assertEqual(labels, ["S51usque", "S52awg-opkgtun0"])
        self.assertIn("opkgtun0", out[0]["hint"])

    def test_process_of_script_is_same_owner(self):
        scripts = [{"path": "/s/S51usque", "name": "S51usque",
                    "engine": "usque", "enabled": True,
                    "ifaces": ["opkgtun0"], "configs": []}]
        procs = [{"pid": 7, "engine": "usque", "iface": "opkgtun0",
                  "script": "/s/S51usque", "binary": "usque"}]
        self.assertEqual(fs.find_conflicts(scripts, procs, []), [])

    def test_gui_profile_vs_foreign_process(self):
        procs = [{"pid": 7, "engine": "usque", "iface": "usque0",
                  "script": "", "binary": "/opt/bin/usque"}]
        gui = [("usque0", "профиль usque «warp»", "usque", "/c/warp.json")]
        out = fs.find_conflicts([], procs, gui)
        self.assertEqual([c["kind"] for c in out[0]["claimants"]],
                         ["process", "gui"])


class TestParse(unittest.TestCase):

    def test_parse_process(self):
        p = fs.parse_process("mihomo", ["mihomo", "-d", "/opt/etc/mihomo"])
        self.assertEqual(p["config"], "/opt/etc/mihomo/config.yaml")
        p = fs.parse_process("singbox", ["sing-box", "run", "-c",
                                         "/opt/etc/sing-box/config.json"])
        self.assertEqual(p["config"], "/opt/etc/sing-box/config.json")
        p = fs.parse_process("awg", ["amneziawg-go", "-f", "opkgtun0"])
        self.assertEqual(p["iface"], "opkgtun0")
        p = fs.parse_process("usque", ["usque", "nativetun",
                                       "--interface-name=opkgtun0",
                                       "-c", "/opt/etc/usque/config.json"])
        self.assertEqual((p["iface"], p["config"]),
                         ("opkgtun0", "/opt/etc/usque/config.json"))

    def test_parse_opera_args(self):
        argv = ["opera-proxy", "-country", "AS", "-bind-address",
                "0.0.0.0:18080", "-socks-mode", "-verbosity=30"]
        self.assertEqual(fs.parse_opera_args(argv),
                         {"country": "AS", "bind": "0.0.0.0:18080",
                          "socks_mode": True, "verbosity": "30"})


class _FsCase(unittest.TestCase):
    """Каталог init.d и каталог настроек во временной папке."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.init_dir = os.path.join(root, "init.d")
        self.cfg_dir = os.path.join(root, "cfg")
        os.makedirs(self.init_dir)
        os.makedirs(self.cfg_dir)
        self.patches = [
            mock.patch.object(fs, "INIT_DIRS", (self.init_dir,)),
            mock.patch.object(fs, "RC_D_DIR", os.path.join(root, "rc.d")),
            mock.patch.dict(os.environ, {"ZAPRET_GUI_CONFIG_DIR":
                                         self.cfg_dir}),
            mock.patch.object(fs, "find_processes", return_value=[]),
            mock.patch.object(fs, "_gui_claims", return_value=[]),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def script(self, name, body="", mode=0o755):
        path = os.path.join(self.init_dir, name)
        marker = os.path.join(self.tmp.name, name + ".log")
        with open(path, "w") as f:
            f.write('#!/bin/sh\n%s\necho "$1" >> %s\n' % (body, marker))
        os.chmod(path, mode)
        return path, marker


class TestDisableEnable(_FsCase):

    def test_disable_drops_exec_bit_and_enable_restores(self):
        path, marker = self.script("S51usque", "usque nativetun -n opkgtun0")
        own, _ = self.script("S52sing-box-gui", "sing-box run")
        found = fs.find_scripts()
        self.assertEqual([s["path"] for s in found], [path])
        self.assertTrue(found[0]["enabled"])

        res = fs.disable_script(path)
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.stat(path).st_mode & stat.S_IXUSR)
        with open(marker) as f:
            self.assertIn("stop", f.read())
        self.assertFalse(fs.find_scripts()[0]["enabled"])
        self.assertTrue(fs.find_scripts()[0]["gui_disabled"])

        self.assertTrue(fs.enable_script(path)["ok"])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)
        self.assertEqual(fs.load_state()["disabled"], {})

    def test_unknown_path_is_refused(self):
        own, _ = self.script("S52sing-box-gui", "sing-box run")
        self.assertFalse(fs.disable_script(own)["ok"])
        self.assertFalse(fs.disable_script("/etc/passwd")["ok"])
        self.assertTrue(os.stat(own).st_mode & stat.S_IXUSR)

    def test_enforce_redisables_after_package_upgrade(self):
        path, _ = self.script("S99sing-box", "sing-box run -c /x.json")
        fs.disable_script(path)
        os.chmod(path, 0o755)               # opkg upgrade вернул бит
        res = fs.enforce()
        self.assertEqual(res["redisabled"], [path])
        self.assertFalse(os.stat(path).st_mode & stat.S_IXUSR)

    def test_enforce_kills_only_clearly_owned_processes(self):
        path, _ = self.script("S51usque",
                              "usque nativetun -n opkgtun0 "
                              "-c /opt/etc/usque/config.json")
        fs.disable_script(path, kill_leftovers=False)
        os.chmod(path, 0o644)
        procs = [
            {"pid": 11, "engine": "usque", "binary": "usque", "cmdline": "",
             "iface": "opkgtun0", "config": "/opt/etc/usque/config.json"},
            # Руками, на другом имени и с другим конфигом: только догадка.
            {"pid": 12, "engine": "usque", "binary": "usque", "cmdline": "",
             "iface": "opkgtun7", "config": "/root/u.json"},
        ]
        with mock.patch.object(fs, "find_processes", return_value=procs), \
             mock.patch.object(fs, "_kill", return_value=True) as kill:
            res = fs.enforce()
        self.assertEqual(res["killed"], [11])
        kill.assert_called_once_with(11)

    def test_enforce_is_noop_without_state(self):
        path, marker = self.script("S99mihomo", "mihomo -d /opt/etc/mihomo")
        self.assertEqual(fs.enforce(), {"redisabled": [], "killed": []})
        self.assertFalse(os.path.exists(marker))
        self.assertTrue(os.stat(path).st_mode & stat.S_IXUSR)

    def test_exclusive_disables_everything_foreign(self):
        a, _ = self.script("S99sing-box", "sing-box run")
        b, _ = self.script("S99mihomo", "mihomo")
        with mock.patch.object(fs, "get_guard"):
            fs.set_exclusive(True)
        for p in (a, b):
            self.assertFalse(os.stat(p).st_mode & stat.S_IXUSR)

    def test_entware_enabled_flag(self):
        path, _ = self.script("S99opera-proxy", "ENABLED=no\nopera-proxy")
        self.assertFalse(fs.find_scripts()[0]["enabled"])

    def test_neutralize_package_scripts(self):
        path, _ = self.script("S51usque", "usque nativetun")
        with mock.patch.object(fs, "package_init_scripts",
                               return_value=[path]):
            done = fs.neutralize_package_scripts("usque-keenetic", "usque")
        self.assertEqual(done, [path])
        self.assertFalse(os.stat(path).st_mode & stat.S_IXUSR)
        entry = fs.load_state()["disabled"][path]
        self.assertEqual(entry["reason"], "installed-by-gui:usque-keenetic")


class TestAdoptRollback(_FsCase):

    def test_failed_start_restores_foreign_script(self):
        path, marker = self.script("S99sing-box",
                                   "sing-box run -c /opt/etc/sb.json")
        proc = {"pid": 4242, "engine": "singbox", "binary": "sing-box",
                "cmdline": "sing-box run -c /opt/etc/sb.json",
                "iface": "", "config": "/opt/etc/sb.json"}
        adopters = {"singbox": {
            "prepare": lambda p: {"name": "sb"},
            "start": lambda prep: {"ok": False, "error": "check failed"},
            "autostart": lambda prep: None}}
        with mock.patch.object(fs, "find_processes", return_value=[proc]), \
             mock.patch.object(fs, "_adoptable", return_value=(True, "")), \
             mock.patch.object(fs, "_kill", return_value=True), \
             mock.patch.object(fs, "_alive", return_value=True), \
             mock.patch.dict(fs._ADOPTERS, adopters):
            res = fs.adopt("singbox", 4242)
        self.assertFalse(res["ok"])
        self.assertTrue(res["rollback"]["ok"], res)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)
        with open(marker) as f:
            self.assertEqual(f.read().split(), ["stop", "start"])

    def test_success_enables_gui_autostart(self):
        path, _ = self.script("S99sing-box", "sing-box run -c /opt/etc/sb.json")
        proc = {"pid": 4242, "engine": "singbox", "binary": "sing-box",
                "cmdline": "", "iface": "", "config": "/opt/etc/sb.json"}
        calls = []
        adopters = {"singbox": {
            "prepare": lambda p: {"name": "sb"},
            "start": lambda prep: {"ok": True},
            "autostart": lambda prep: calls.append(prep["name"])}}
        with mock.patch.object(fs, "find_processes", return_value=[proc]), \
             mock.patch.object(fs, "_adoptable", return_value=(True, "")), \
             mock.patch.object(fs, "_kill", return_value=True), \
             mock.patch.object(fs, "_alive", return_value=False), \
             mock.patch.dict(fs._ADOPTERS, adopters):
            res = fs.adopt("singbox", 4242)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["script_disabled"], path)
        self.assertEqual(calls, ["sb"])
        self.assertFalse(os.stat(path).st_mode & stat.S_IXUSR)

    def test_unknown_pid_is_refused(self):
        self.assertFalse(fs.adopt("singbox", 1)["ok"])
        self.assertFalse(fs.stop_process(1)["ok"])


class TestInstallerHook(unittest.TestCase):

    def _install(self, name, res):
        from core import ext_binary_installer as ebi
        with mock.patch.object(ebi, "_install_binary_by_name",
                               return_value=res), \
             mock.patch.object(fs, "neutralize_package_scripts",
                               return_value=["/opt/etc/init.d/S51usque"]
                               ) as neu, \
             mock.patch.object(fs, "engine_foreign",
                               return_value={"scripts": [],
                                             "processes": []}):
            out = ebi.install_binary_by_name(name)
        return out, neu

    def test_gui_installed_package_loses_its_autostart(self):
        out, neu = self._install("usque", {"ok": True,
                                           "package": "usque-keenetic"})
        neu.assert_called_once_with("usque-keenetic", "usque")
        self.assertEqual(out["disabled_package_scripts"],
                         ["/opt/etc/init.d/S51usque"])

    def test_tgwsproxy_keeps_its_script(self):
        _out, neu = self._install("tgwsproxy", {"ok": True,
                                                "package": "tg-ws-proxy"})
        neu.assert_not_called()

    def test_binary_install_touches_nothing(self):
        _out, neu = self._install("usque", {"ok": True,
                                            "binary": "/opt/usr/bin/usque"})
        neu.assert_not_called()


class TestApi(_FsCase):
    """/api/foreign/*: чтение и отказ на путь, который не наш случай."""

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_status_and_disable_roundtrip(self):
        path, _ = self.script("S51usque", "usque nativetun -n opkgtun0")
        with mock.patch.object(fs, "get_guard"):
            r = self.client.get_json("/api/foreign/status")
            self.assertEqual([x["name"] for x in r["scripts"]], ["S51usque"])
            r = self.client.post_json("/api/foreign/script/disable",
                                      {"path": "/etc/shadow"})
            self.assertFalse(r["ok"])
            r = self.client.post_json("/api/foreign/script/disable",
                                      {"path": path})
            self.assertTrue(r["ok"], r)
            r = self.client.post_json("/api/foreign/script/enable",
                                      {"path": path})
            self.assertTrue(r["ok"], r)
            r = self.client.post_json("/api/foreign/adopt",
                                      {"engine": "usque", "pid": "x"})
            self.assertFalse(r["ok"])


class TestBrief(unittest.TestCase):

    def test_foreign_is_a_warning_on_dashboard(self):
        from core.dashboard_brief import brief
        out = brief({"foreign": {"engines": {"usque": {"processes": 1}},
                                 "conflicts": 1}})
        pages = [p["page"] for p in out["problems"] if p["block"] == "vpn"]
        self.assertEqual(pages, ["foreign-services", "foreign-services"])
        self.assertEqual(out["blocks"]["vpn"]["level"], "warn")


if __name__ == "__main__":
    unittest.main()
