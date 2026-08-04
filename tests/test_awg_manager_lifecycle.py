# tests/test_awg_manager_lifecycle.py
"""
Lifecycle-тесты для core/awg_manager.py.

Используем временный config_dir, мокаем subprocess (`_run`) чтобы
не вызывать реальные awg/ip/wg команды. Lifecycle: save_config →
get_config → list_configs → is_running → delete_config.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import awg_manager


SAMPLE_CONF = """[Interface]
PrivateKey = qK4xn2cV7g7H4ICm3w4f5G9k2vRl0pZ8H8Y0OqWQS3w=
Address = 10.0.0.2/32

[Peer]
PublicKey = B5dN1RoG3Jp1A7vWcDjI5xqRsX9cQYTuVE2KAFAVqXk=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""


class FakePlatform:
    """Lightweight stand-in для AwgPlatform с временными путями."""

    def __init__(self, tmpdir):
        self.binary_dir = os.path.join(tmpdir, "bin")
        self.config_dir = os.path.join(tmpdir, "config")
        self.run_dir    = os.path.join(tmpdir, "run")
        # UAPI-сокеты кладём во временный каталог: teardown интерфейса их
        # удаляет, и трогать настоящий /var/run тесты не должны.
        self.uapi_dir   = os.path.join(tmpdir, "uapi")
        os.makedirs(self.binary_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.run_dir, exist_ok=True)
        os.makedirs(self.uapi_dir, exist_ok=True)

    def binary_path(self, name="amneziawg-go"):
        return os.path.join(self.binary_dir, name)

    def awg_path(self):
        return os.path.join(self.binary_dir, "awg")

    def uapi_dirs(self):
        return (self.uapi_dir,)

    def uapi_paths(self, iface):
        return [os.path.join(d, "%s.sock" % iface) for d in self.uapi_dirs()]

    def uapi_path(self, iface):
        return self.uapi_paths(iface)[0]


class TestAwgManagerCRUD(unittest.TestCase):
    """CRUD конфигов — без обращения к процессам."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="awg-mgr-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = awg_manager.AwgManager()

        # Подмена платформы — все пути ведут во временный каталог.
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_config_dir",
                              return_value=self.platform.config_dir),
            mock.patch.object(self.mgr, "_run_dir",
                              return_value=self.platform.run_dir),
            mock.patch.object(self.mgr, "_scan_dirs",
                              return_value=[self.platform.config_dir]),
            mock.patch.object(self.mgr, "_awg_bin",
                              return_value="/fake/awg"),
            mock.patch.object(self.mgr, "_amneziawg_go",
                              return_value="/fake/amneziawg-go"),
            # is_running по умолчанию — False (нет процесса, нет в wg show).
            mock.patch.object(self.mgr, "_wg_interfaces",
                              return_value=[]),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_config_creates_file(self):
        result = self.mgr.save_config("awg0", text=SAMPLE_CONF)
        self.assertEqual(result["name"], "awg0")
        self.assertTrue(os.path.isfile(
            os.path.join(self.platform.config_dir, "awg0.conf")))

    def test_save_config_injects_keepalive(self):
        # SAMPLE_CONF без PersistentKeepalive → save проставляет 25.
        self.assertNotIn("PersistentKeepalive", SAMPLE_CONF)
        self.mgr.save_config("awg0", text=SAMPLE_CONF)
        saved = open(os.path.join(self.platform.config_dir,
                                  "awg0.conf")).read()
        self.assertIn("PersistentKeepalive = 25", saved)

    def test_save_config_preserves_existing_keepalive(self):
        conf = SAMPLE_CONF.rstrip() + "\nPersistentKeepalive = 15\n"
        self.mgr.save_config("awg0", text=conf)
        cfg = self.mgr.get_config("awg0")
        self.assertEqual(
            str(cfg["parsed"]["peers"][0].get("PersistentKeepalive")), "15")
        self.assertNotIn("PersistentKeepalive = 25", cfg["text"])

    def test_save_invalid_name_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.save_config("bad/name", text=SAMPLE_CONF)

    def test_save_needs_text_or_parsed(self):
        with self.assertRaises(ValueError):
            self.mgr.save_config("awg0")

    def test_save_invalid_conf_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.save_config("awg0", text="not a valid conf")

    def test_get_config_after_save(self):
        self.mgr.save_config("awg0", text=SAMPLE_CONF)
        cfg = self.mgr.get_config("awg0")
        self.assertEqual(cfg["name"], "awg0")
        self.assertIn("[Interface]", cfg["text"])
        self.assertIn("PrivateKey", cfg["parsed"]["interface"])

    def test_get_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.mgr.get_config("never-saved")

    def test_get_invalid_name_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.get_config("bad/name")

    def test_list_configs_empty(self):
        # Без сохранённых
        self.assertEqual(self.mgr.list_configs(), [])

    def test_list_configs_after_save(self):
        self.mgr.save_config("awg0", text=SAMPLE_CONF)
        self.mgr.save_config("awg1", text=SAMPLE_CONF)
        cfgs = self.mgr.list_configs()
        names = sorted(c["name"] for c in cfgs)
        self.assertEqual(names, ["awg0", "awg1"])

    def test_delete_config(self):
        self.mgr.save_config("awg0", text=SAMPLE_CONF)
        r = self.mgr.delete_config("awg0")
        self.assertTrue(r["ok"])
        self.assertFalse(os.path.isfile(
            os.path.join(self.platform.config_dir, "awg0.conf")))

    def test_delete_nonexistent_is_ok(self):
        # delete должен быть идемпотентным
        r = self.mgr.delete_config("never-existed")
        self.assertTrue(r["ok"])


class TestAwgManagerIsRunning(unittest.TestCase):
    """is_running проверка через pid-file и wg show."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="awg-running-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = awg_manager.AwgManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_run_dir",
                              return_value=self.platform.run_dir),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_not_running_no_pid_no_wg(self):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                                return_value=[]):
            self.assertFalse(self.mgr.is_running("awg0"))

    def test_running_via_wg_show(self):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                                return_value=["awg0", "wg1"]):
            self.assertTrue(self.mgr.is_running("awg0"))

    def _write_pid(self, iface, pid):
        pid_file = self.mgr._pid_path(iface)
        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
        with open(pid_file, "w") as f:
            f.write(str(pid))

    def test_running_via_pid_file(self):
        # Живой PID, чей cmdline — наш демон.
        self._write_pid("awg0", os.getpid())
        with mock.patch.object(awg_manager, "_pid_cmdline",
                               return_value="/opt/usr/sbin/amneziawg-go awg0"):
            with mock.patch.object(self.mgr, "_wg_interfaces",
                                    return_value=[]):
                self.assertTrue(self.mgr.is_running("awg0"))

    def test_stale_pid_of_foreign_process_is_not_running(self):
        # На Keenetic run_dir лежит в /opt (переживает перезагрузку): после
        # ребута тот же PID занят посторонним процессом. Он не должен
        # выдавать туннель за поднятый — иначе автозапуск молча
        # не поднимает интерфейс («уже поднят»).
        self._write_pid("awg0", os.getpid())
        with mock.patch.object(awg_manager, "_pid_cmdline",
                               return_value="/usr/sbin/ndnproxy -c /etc/ndn.conf"):
            with mock.patch.object(self.mgr, "_wg_interfaces",
                                    return_value=[]):
                self.assertFalse(self.mgr.is_running("awg0"))

    def test_cleanup_does_not_kill_foreign_pid(self):
        # _cleanup_iface не должен слать сигналы чужому процессу.
        self._write_pid("awg0", os.getpid())
        with mock.patch.object(awg_manager, "_pid_cmdline",
                               return_value="/usr/sbin/ndnproxy"):
            with mock.patch("os.kill") as mkill:
                self.mgr._cleanup_iface("awg0")
                # Сигнал 0 — это лишь проба «жив ли PID», она безобидна.
                # Настоящих сигналов (SIGTERM/SIGKILL) быть не должно.
                sent = [c.args[1] for c in mkill.call_args_list
                        if len(c.args) > 1 and c.args[1] != 0]
                self.assertEqual(sent, [])


class TestWgInterfacesParser(unittest.TestCase):
    """_wg_interfaces — парсер вывода `wg show interfaces` и `ip link`."""

    def test_parses_wg_show_output(self):
        mgr = awg_manager.AwgManager()
        with mock.patch.object(mgr, "_awg_bin", return_value="/fake/awg"):
            with mock.patch.object(awg_manager, "_run",
                                    return_value=(0, "awg0 wg1 opkgtun0", "")):
                ifs = mgr._wg_interfaces()
        self.assertEqual(sorted(ifs), ["awg0", "opkgtun0", "wg1"])

    def test_fallback_to_ip_link(self):
        mgr = awg_manager.AwgManager()
        with mock.patch.object(mgr, "_awg_bin", return_value="/fake/awg"):
            # awg show — пусто, fallback на ip link
            runs = [
                (0, "", ""),    # wg show
                (0, "2: awg0: <BROADCAST,...>\n3: wg1: <...>", ""),  # ip link
            ]
            with mock.patch.object(awg_manager, "_run", side_effect=runs):
                ifs = mgr._wg_interfaces()
        self.assertIn("awg0", ifs)
        self.assertIn("wg1", ifs)


class TestIfaceForName(unittest.TestCase):
    """_iface_for_name — резолв `awg0-opkgtun0.conf` → `opkgtun0`."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="awg-resolv-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = awg_manager.AwgManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_config_dir",
                              return_value=self.platform.config_dir),
            mock.patch.object(self.mgr, "_scan_dirs",
                              return_value=[self.platform.config_dir]),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_direct_match(self):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                                return_value=["awg0"]):
            self.assertEqual(self.mgr._iface_for_name("awg0"), "awg0")

    def test_fallback_to_name_when_no_match(self):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                                return_value=[]):
            # Нет активного интерфейса и нет файла → возвращает name
            self.assertEqual(self.mgr._iface_for_name("never-existed"),
                             "never-existed")


class TestAwgManagerDiagnosticsBinaries(unittest.TestCase):
    """
    Регрессия: diagnostics()["binaries"] должен отдавать ПО КАЖДОМУ
    бинарю объект {path, exists, broken, version}, а не плоскую строку-путь.

    Раньше второй блок в diagnostics() перезаписывал структурированный dict
    плоскими путями + sibling-полями *_version, из-за чего фронт
    (awg_dashboard.fmtBin) видел info.exists === undefined и ВСЕГДА печатал
    «не найден ✗» с версией «?», даже когда бинарь на месте. Этот баг
    маскировал реальную причину в баг-репортах.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="awg-diag-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = awg_manager.AwgManager()

        # Реальные файлы-бинари, чтобы os.path.isfile → True (exists).
        self.awg_file = os.path.join(self.platform.binary_dir, "awg")
        self.go_file  = os.path.join(self.platform.binary_dir, "amneziawg-go")
        for f in (self.awg_file, self.go_file):
            with open(f, "w") as fh:
                fh.write("#!/bin/true\n")

        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_config_dir",
                              return_value=self.platform.config_dir),
            mock.patch.object(self.mgr, "_run_dir",
                              return_value=self.platform.run_dir),
            mock.patch.object(self.mgr, "_scan_dirs",
                              return_value=[self.platform.config_dir]),
            mock.patch.object(self.mgr, "_awg_bin",
                              return_value=self.awg_file),
            mock.patch.object(self.mgr, "_amneziawg_go",
                              return_value=self.go_file),
            mock.patch.object(self.mgr, "_wg_interfaces",
                              return_value=[]),
        ]
        for p in self._patches:
            p.start()

        # Сохраняем конфиг, чтобы get_config/render_setconf отработали.
        self.mgr.save_config("awg0", text=SAMPLE_CONF)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @staticmethod
    def _fake_run(args, timeout=15, input_text=None, env=None):
        # Любой `--version` → распознаваемая строка; всё прочее (ip/awg show
        # и т.п.) — безобидный успех. Маркеров «битости» нет → broken=False.
        if "--version" in args:
            return 0, "TESTVER 1.2.3", ""
        return 0, "", ""

    def test_binaries_are_structured_objects_with_version(self):
        with mock.patch.object(awg_manager, "_run", self._fake_run):
            diag = self.mgr.diagnostics("awg0")

        bins = diag["binaries"]
        for key in ("awg", "amneziawg_go"):
            entry = bins[key]
            # Контракт фронта: объект, а не строка-путь.
            self.assertIsInstance(entry, dict, "%s должен быть объектом" % key)
            self.assertTrue(entry["exists"], "%s.exists должен быть True" % key)
            self.assertFalse(entry["broken"])
            self.assertEqual(entry["version"], "TESTVER 1.2.3")
            self.assertTrue(entry["path"])

        # Плоские sibling-поля версий не должны возвращаться (старый формат,
        # который ломал фронт).
        self.assertNotIn("awg_version", bins)
        self.assertNotIn("amneziawg_go_version", bins)


class TestResolveEndpointIp(unittest.TestCase):
    """`_resolve_endpoint_ip` — bounded-резолв Endpoint перед setconf.

    `awg setconf` резолвит хостнейм синхронно; если DNS роутера лежит
    (resolv.conf → 127.0.0.1, dnsmasq down), setconf висит. Резолвим сами
    с жёстким таймаутом: IP-литерал — мимо, имя — через getaddrinfo в
    потоке, зависший резолвер — отдаём timed_out вместо вечного ожидания."""

    def test_ipv4_literal_passthrough(self):
        ip, timed_out = awg_manager._resolve_endpoint_ip("162.159.192.4")
        self.assertEqual(ip, "162.159.192.4")
        self.assertFalse(timed_out)

    def test_ipv6_literal_passthrough(self):
        ip, timed_out = awg_manager._resolve_endpoint_ip("2606:4700:d0::a29f:c004")
        self.assertEqual(ip, "2606:4700:d0::a29f:c004")
        self.assertFalse(timed_out)

    def test_prefers_ipv4(self):
        import socket
        fake = [
            (socket.AF_INET6, socket.SOCK_DGRAM, 0, "", ("2606::1", 0, 0, 0)),
            (socket.AF_INET,  socket.SOCK_DGRAM, 0, "", ("162.159.192.4", 0)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            ip, timed_out = awg_manager._resolve_endpoint_ip("engage.example.com")
        self.assertEqual(ip, "162.159.192.4")
        self.assertFalse(timed_out)

    def test_hard_timeout_on_stuck_resolver(self):
        import socket, time
        def _hang(*a, **k):
            time.sleep(5)
            return []
        with mock.patch("socket.getaddrinfo", side_effect=_hang):
            ip, timed_out = awg_manager._resolve_endpoint_ip(
                "stuck.example.com", timeout=0.3)
        self.assertIsNone(ip)
        self.assertTrue(timed_out)

    def test_unresolvable_name(self):
        import socket
        with mock.patch("socket.getaddrinfo",
                        side_effect=socket.gaierror("nope")):
            ip, timed_out = awg_manager._resolve_endpoint_ip(
                "nope.invalid", timeout=2)
        self.assertIsNone(ip)
        self.assertFalse(timed_out)


if __name__ == "__main__":
    unittest.main()


class TestUapiSocketDirs(unittest.TestCase):
    """Каталог UAPI-сокета зависит от ветки движка.

    amneziawg-go v3.x создаёт сокет в /var/run/amneziawg
    (`ipc/uapi_unix.go`), туда же ходит `awg` из tools v3
    (`src/ipc-uapi-unix.h`); сборки на базе wireguard-go — в
    /var/run/wireguard. Раньше мы знали только второй путь: после SIGKILL
    сокет v3 оставался, а поиск интерфейсов по сокетам не находил ничего.
    """

    def test_platform_lists_both_dirs_v3_first(self):
        from core.awg_platform import GenericLinuxPlatform, UAPI_SOCKET_DIRS
        self.assertEqual(UAPI_SOCKET_DIRS,
                         ("/var/run/amneziawg", "/var/run/wireguard"))
        paths = GenericLinuxPlatform().uapi_paths("awg0")
        self.assertEqual(paths, ["/var/run/amneziawg/awg0.sock",
                                 "/var/run/wireguard/awg0.sock"])

    def test_uapi_path_prefers_the_socket_that_exists(self):
        from core.awg_platform import GenericLinuxPlatform
        plat = GenericLinuxPlatform()
        legacy = "/var/run/wireguard/awg0.sock"
        with mock.patch("os.path.exists", side_effect=lambda p: p == legacy):
            self.assertEqual(plat.uapi_path("awg0"), legacy)

    def test_uapi_path_falls_back_to_current_branch(self):
        from core.awg_platform import GenericLinuxPlatform
        with mock.patch("os.path.exists", return_value=False):
            self.assertEqual(GenericLinuxPlatform().uapi_path("awg0"),
                             "/var/run/amneziawg/awg0.sock")

    def test_cleanup_removes_socket_from_every_dir(self):
        tmpdir = tempfile.mkdtemp(prefix="awg-uapi-test-")
        self.addCleanup(shutil.rmtree, tmpdir, True)
        platform = FakePlatform(tmpdir)
        # Два каталога, как на реальной системе со сменившейся веткой.
        second = os.path.join(tmpdir, "uapi-legacy")
        os.makedirs(second, exist_ok=True)
        platform.uapi_dirs = lambda: (platform.uapi_dir, second)
        socks = platform.uapi_paths("awg0")
        for s in socks:
            with open(s, "w") as f:
                f.write("")

        mgr = awg_manager.AwgManager()
        with mock.patch.object(awg_manager.AwgManager, "_platform",
                               return_value=platform):
            mgr._cleanup_iface("awg0")

        for s in socks:
            self.assertFalse(os.path.exists(s),
                             "не удалён мёртвый сокет %s" % s)


