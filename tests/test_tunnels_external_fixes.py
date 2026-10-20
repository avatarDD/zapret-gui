# tests/test_tunnels_external_fixes.py
"""Сторожа по разбору роутера с 256 МБ ОЗУ (zapret-gui 0.25.21).

Другой агент через наш MCP нашёл на роутере вечный `amneziawg-go -v`,
невидимый внешний usque, «молчащий» монитор у маршрута устройств и
мёртвое поле awg.autostart.enabled. Здесь — то, что подтвердилось и
исправлено.
"""

import subprocess
import unittest
from unittest import mock


class TestAwgVersionProbe(unittest.TestCase):

    def setUp(self):
        from core import awg_installer as ai
        ai._ext_version_cache.clear()

    def test_only_long_version_flag(self):
        """`-v` у amneziawg-go — имя интерфейса: его звать нельзя."""
        from core import awg_installer as ai
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            raise subprocess.TimeoutExpired(argv, 4)

        with mock.patch.object(ai.os.path, "isfile", return_value=True), \
             mock.patch.object(ai.subprocess, "run", side_effect=run):
            self.assertEqual(ai._detect_binary_version("/x/amneziawg-go"), "")
        self.assertEqual(calls, [["/x/amneziawg-go", "--version"]])

    def test_external_version_cached(self):
        from core import awg_installer as ai
        with mock.patch.object(ai, "_opkg_pkg_version",
                               return_value="0.2.16-1") as opkg, \
             mock.patch.object(ai, "_file_stamp", return_value=(1, 2)):
            self.assertEqual(ai._resolve_external_version("amneziawg-go", "/b"),
                             ("0.2.16-1", "opkg"))
            self.assertEqual(ai._resolve_external_version("amneziawg-go", "/b"),
                             ("0.2.16-1", "opkg"))
        self.assertEqual(opkg.call_count, 1)

    def test_cache_invalidated_by_new_binary(self):
        from core import awg_installer as ai
        stamps = iter([(1, 2), (5, 6)])
        with mock.patch.object(ai, "_opkg_pkg_version",
                               return_value="0.2.16") as opkg, \
             mock.patch.object(ai, "_file_stamp",
                               side_effect=lambda p: next(stamps)):
            ai._resolve_external_version("amneziawg-go", "/b")
            ai._resolve_external_version("amneziawg-go", "/b")
        self.assertEqual(opkg.call_count, 2)


class TestExtGetVersion(unittest.TestCase):

    def test_no_short_v_and_rc_checked(self):
        from core import ext_binary_installer as ebi
        seen = []

        def run(argv, **kw):
            seen.append(argv[1])
            if argv[1] == "--version":
                return mock.Mock(returncode=1, stdout="unknown flag", stderr="")
            return mock.Mock(returncode=0, stdout="opera-proxy 1.30.0\n",
                             stderr="")

        with mock.patch.object(ebi.subprocess, "run", side_effect=run):
            v = ebi._get_version("/fake/opera-proxy")
        self.assertEqual(v, "opera-proxy 1.30.0")
        self.assertNotIn("-v", seen)

    def test_short_output_without_number_is_not_a_version(self):
        from core import ext_binary_installer as ebi
        with mock.patch.object(ebi.subprocess, "run",
                               return_value=mock.Mock(returncode=0,
                                                      stdout="listening",
                                                      stderr="")):
            self.assertEqual(ebi._get_version("/fake/bin"), "")

    def test_usque_uses_subcommand(self):
        from core import ext_binary_installer as ebi
        self.assertEqual(ebi._version_args(ebi.BINARIES["usque"]["dest"]),
                         ("version",))


class TestUsqueVersionParse(unittest.TestCase):

    def test_variants(self):
        from core.usque_manager import _parse_usque_version as p
        self.assertEqual(p("usque version: 4.2.0\nCommit: x\n", False), "4.2.0")
        self.assertEqual(p("usque version: dev\n", False), "dev")
        self.assertEqual(p("v4.2.1\n", False), "4.2.1")
        self.assertEqual(p("failed to load config: /opt/etc/usque/"
                           "config.json version 2\n", True), "")
        self.assertEqual(p("Version: 4.2.1\n", True), "4.2.1")

    def test_falls_back_to_package(self):
        from core.usque_manager import UsqueManager
        with mock.patch("core.usque_manager.subprocess.run",
                        return_value=mock.Mock(stdout="", stderr="")), \
             mock.patch("core.ext_binary_installer._pkg_version",
                        side_effect=lambda pkg: "4.2.1-1"
                        if pkg == "usque-keenetic" else ""):
            self.assertEqual(UsqueManager._probe_version("/opt/usr/bin/usque"),
                             "4.2.1-1")


class TestUsqueExternal(unittest.TestCase):

    def test_foreign_nativetun_found(self):
        from core import usque_manager as um
        mgr = um.UsqueManager()
        cmdlines = {
            "1720": b"/opt/usr/bin/usque\0nativetun\0--config\0"
                    b"/opt/etc/usque/session.conf\0--interface-name\0"
                    b"opkgtun0\0--no-iproute2\0",
            "20225": b"/opt/usr/sbin/amneziawg-go\0WARPv1_30\0",
        }

        def fake_open(path, mode="r"):
            pid = path.split("/")[2]
            return mock.mock_open(read_data=cmdlines[pid])()

        with mock.patch.object(um.os, "listdir",
                               return_value=list(cmdlines) + ["self"]), \
             mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(mgr, "_read_pid", return_value=0):
            ext = mgr.find_external()
        self.assertEqual(len(ext), 1)
        self.assertEqual(ext[0]["pid"], 1720)
        self.assertEqual(ext[0]["iface"], "opkgtun0")
        self.assertEqual(ext[0]["config"], "/opt/etc/usque/session.conf")


class TestStrayAwgDaemon(unittest.TestCase):

    def test_iface_name_cannot_start_with_dash(self):
        from core.awg_manager import _valid_iface_name
        self.assertFalse(_valid_iface_name("-v"))
        self.assertTrue(_valid_iface_name("WARPv1_30"))

    def test_reap(self):
        from core import awg_manager as am
        alive = {15804}

        def listdir(path):
            if path == "/proc":
                return ["15804", "20225", "self"]
            if path == "/var/run/amneziawg":
                return ["-v.sock", "WARPv1_30.sock"]
            raise OSError

        argvs = {15804: ["/opt/usr/sbin/amneziawg-go", "-v"],
                 20225: ["/opt/usr/sbin/amneziawg-go", "WARPv1_30"]}

        def kill(pid, sig):
            alive.discard(pid)

        with mock.patch.object(am.os, "listdir", side_effect=listdir), \
             mock.patch.object(am, "_pid_argv",
                               side_effect=lambda p: argvs.get(p, [])), \
             mock.patch.object(am.os, "kill", side_effect=kill) as k, \
             mock.patch.object(am, "_pid_alive",
                               side_effect=lambda p: p in alive), \
             mock.patch.object(am, "_run",
                               return_value=(0, "", "")) as run, \
             mock.patch.object(am.os, "unlink") as unlink:
            self.assertEqual(am.reap_stray_daemons(), ["-v"])
        k.assert_called_once()
        self.assertEqual(k.call_args[0][0], 15804)
        run.assert_called_once_with(["ip", "link", "del", "dev", "-v"],
                                    timeout=5)
        unlink.assert_any_call("/var/run/amneziawg/-v.sock")


class TestSourceOnlyRouteProbe(unittest.TestCase):

    def _route(self, **kw):
        from core.unified.model import UnifiedRoute
        return UnifiedRoute(name="dev", method="awg:WARPv1_30",
                            devices=[{"ip": "192.168.1.84",
                                      "mac": "aa:bb:cc:dd:ee:ff"}],
                            monitor_enabled=True, **kw)

    def test_probes_through_tunnel_iface(self):
        from core.unified import monitor
        with mock.patch.object(monitor, "probe_host",
                               return_value=True) as ph:
            self.assertTrue(monitor.probe_route(self._route()))
        self.assertEqual(ph.call_args.kwargs["device"], "WARPv1_30")
        self.assertEqual(ph.call_args.args[0], monitor.SOURCE_PROBE_DEFAULT)

    def test_can_probe(self):
        from core.unified import monitor
        from core.unified.model import UnifiedRoute, Destination
        self.assertTrue(monitor.can_probe(self._route()))
        geo = UnifiedRoute(name="g", method="awg:x",
                           destination=Destination(geosite=["youtube"]))
        self.assertFalse(monitor.can_probe(geo))

    def test_device_drift(self):
        from core.unified.manager import _device_drift
        r = self._route()
        self.assertEqual(_device_drift(r, {"aa:bb:cc:dd:ee:ff":
                                           "192.168.1.84"}), [])
        drift = _device_drift(r, {"aa:bb:cc:dd:ee:ff": "192.168.1.90"})
        self.assertEqual(drift[0]["now_ip"], "192.168.1.90")
        self.assertEqual(_device_drift(r, {}), [])


class TestAwgAutostartNoPhantomFlag(unittest.TestCase):

    def test_save_drops_enabled(self):
        from core.awg_autostart_manager import AwgAutostartManager
        cm = mock.Mock()
        cm.get.return_value = {"interfaces": {"WARPv1_30": True}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm):
            m = AwgAutostartManager()
            sec = m._section()
            self.assertNotIn("enabled", sec)  # не дописываем сами
            m._save_section({"enabled": False, "interfaces": {}})
        saved = cm.set.call_args[0][2]
        self.assertNotIn("enabled", saved)


if __name__ == "__main__":
    unittest.main()
