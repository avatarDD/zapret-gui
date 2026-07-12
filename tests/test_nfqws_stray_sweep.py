# tests/test_nfqws_stray_sweep.py
"""Регрессия issue #123: при переключении стратегий стакаются процессы nfqws2.

Менеджер обязан:
  - «усыновлять» живой PID из PID-файла, даже если потерял Popen (другой
    воркер/перезапуск GUI), чтобы не плодить дубли;
  - перед стартом и на стопе зачищать любые посторонние nfqws/nfqws2.
"""

import unittest
from unittest import mock

from core.nfqws_manager import NFQWSManager


class TestStraySweep(unittest.TestCase):

    def setUp(self):
        # Свежий менеджер без восстановления PID из реального файла.
        with mock.patch.object(NFQWSManager, "_recover_pid"):
            self.mgr = NFQWSManager()

    def test_sweep_kills_strays_except_excluded(self):
        killed = []

        def fake_kill(pid, sig):
            killed.append((pid, sig))

        with mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[111, 222, 333]), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=False), \
             mock.patch("core.nfqws_manager.os.kill", side_effect=fake_kill), \
             mock.patch("builtins.open", side_effect=IOError):
            self.mgr._sweep_stray_processes(exclude_pid=222)

        sent_pids = {pid for pid, _ in killed}
        self.assertIn(111, sent_pids)
        self.assertIn(333, sent_pids)
        self.assertNotIn(222, sent_pids)  # исключённый не трогаем

    def test_sweep_noop_when_no_strays(self):
        with mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[]), \
             mock.patch("core.nfqws_manager.os.kill") as k:
            self.mgr._sweep_stray_processes()
        k.assert_not_called()

    def test_sweep_sigkills_survivors(self):
        # Процесс пережил SIGTERM → должен получить SIGKILL.
        import signal as _sig
        killed = []
        with mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[999]), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True), \
             mock.patch("core.nfqws_manager.time.time",
                        side_effect=[0.0, 0.0, 5.0, 5.0]), \
             mock.patch("core.nfqws_manager.time.sleep"), \
             mock.patch("core.nfqws_manager.os.kill",
                        side_effect=lambda p, s: killed.append((p, s))), \
             mock.patch("builtins.open", side_effect=IOError):
            self.mgr._sweep_stray_processes()
        self.assertIn((999, _sig.SIGTERM), killed)
        self.assertIn((999, _sig.SIGKILL), killed)

    def test_is_running_adopts_pid_from_file(self):
        # Popen потерян (None), но PID-файл указывает на живой nfqws2 →
        # менеджер должен считать его запущенным, а не плодить дубль.
        self.mgr._process = None
        self.mgr._pid = None
        with mock.patch.object(NFQWSManager, "_read_pid_file",
                               return_value=4242), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True), \
             mock.patch("core.nfqws_manager.os.stat") as st:
            st.return_value = mock.Mock(st_mtime=100.0)
            self.assertTrue(self.mgr._is_running_locked())
        self.assertEqual(self.mgr._pid, 4242)

    def test_is_running_drops_dead_pid_from_file(self):
        self.mgr._process = None
        self.mgr._pid = None
        with mock.patch.object(NFQWSManager, "_read_pid_file",
                               return_value=4242), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=False), \
             mock.patch.object(NFQWSManager, "_remove_pid_file"):
            self.assertFalse(self.mgr._is_running_locked())
        self.assertIsNone(self.mgr._pid)

    def test_stop_sweeps_even_when_not_running(self):
        # /api/stop должен зачищать сирот, даже если свой процесс не отслеживается.
        with mock.patch.object(NFQWSManager, "_is_running_locked",
                               return_value=False), \
             mock.patch.object(self.mgr, "_sweep_stray_processes") as sweep, \
             mock.patch.object(self.mgr, "_cleanup"):
            self.assertTrue(self.mgr.stop())
        sweep.assert_called_once()


class TestOrchestratorBundle(unittest.TestCase):
    """circular-стратегия подтягивает companion-скрипты, обычная — нет."""

    def test_circular_loads_orchestrator_bundle(self):
        with mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True):
            args = NFQWSManager._build_lua_init_args(
                ["--lua-desync=circular:detector=combined_failure_detector"],
                "/opt/zapret2/lua")
        joined = " ".join(args)
        from core import nfqws_manager as nm
        for lf in nm._ORCHESTRATOR_LUA_FILES:
            self.assertIn(lf, joined,
                          "circular не подтянул %s" % lf)

    def test_non_circular_does_not_load_orchestrator(self):
        with mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True):
            args = NFQWSManager._build_lua_init_args(
                ["--lua-desync=multisplit:pos=1"], "/opt/zapret2/lua")
        joined = " ".join(args)
        self.assertNotIn("strategy-lock-manager.lua", joined)
        self.assertNotIn("combined-detector.lua", joined)
        # core при этом загружается
        self.assertIn("zapret-lib.lua", joined)


class TestDryRun(unittest.TestCase):

    def setUp(self):
        with mock.patch.object(NFQWSManager, "_recover_pid"):
            self.mgr = NFQWSManager()

    def test_unavailable_when_binary_missing(self):
        cfg = mock.Mock()
        cfg.get.return_value = "/no/such/nfqws2"
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=False):
            res = self.mgr.dry_run(["--filter-tcp=443"])
        self.assertFalse(res["ok"])
        self.assertFalse(res["available"])

    def _patched_run(self, returncode, output=b""):
        completed = mock.Mock(returncode=returncode, stdout=output)
        cfg = mock.Mock()
        cfg.get.return_value = "/opt/zapret2/nfq2/nfqws2"
        return cfg, completed

    def test_appends_intercept0_and_strips_user(self):
        cfg, completed = self._patched_run(0, b"all ok")
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            return completed

        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True), \
             mock.patch("core.nfqws_manager.os.access", return_value=True), \
             mock.patch.object(self.mgr, "compose_command",
                               return_value=["/opt/zapret2/nfq2/nfqws2",
                                             "--user=nobody", "--qnum=300",
                                             "--filter-tcp=443"]), \
             mock.patch("core.nfqws_manager.subprocess.run",
                        side_effect=fake_run):
            res = self.mgr.dry_run(["--filter-tcp=443"])

        self.assertTrue(res["ok"])
        self.assertEqual(res["returncode"], 0)
        # Валидация через --intercept=0 (грузит lua-init), без --dry-run.
        self.assertIn("--intercept=0", seen["argv"])
        self.assertNotIn("--dry-run", seen["argv"])
        self.assertNotIn("--user=nobody", seen["argv"])  # setuid не нужен

    def test_strips_existing_intercept_and_dry_run(self):
        cfg, completed = self._patched_run(0, b"ok")
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = argv
            return completed

        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True), \
             mock.patch("core.nfqws_manager.os.access", return_value=True), \
             mock.patch.object(self.mgr, "compose_command",
                               return_value=["/opt/zapret2/nfq2/nfqws2",
                                             "--intercept=1", "--dry-run",
                                             "--filter-tcp=443"]), \
             mock.patch("core.nfqws_manager.subprocess.run",
                        side_effect=fake_run):
            self.mgr.dry_run(["--filter-tcp=443"])

        # Ровно один --intercept=0, никакого --intercept=1 / --dry-run.
        self.assertEqual(
            [a for a in seen["argv"] if a.startswith("--intercept")],
            ["--intercept=0"])
        self.assertNotIn("--dry-run", seen["argv"])

    def test_nonzero_returncode_is_failure(self):
        cfg, completed = self._patched_run(1, b"lua error: function 'foo' nil")
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True), \
             mock.patch("core.nfqws_manager.os.access", return_value=True), \
             mock.patch.object(self.mgr, "compose_command",
                               return_value=["/opt/zapret2/nfq2/nfqws2",
                                             "--lua-desync=foo"]), \
             mock.patch("core.nfqws_manager.subprocess.run",
                        return_value=completed):
            res = self.mgr.dry_run(["--lua-desync=foo"])
        self.assertFalse(res["ok"])
        self.assertEqual(res["returncode"], 1)
        self.assertIn("lua error", res["output"])


class TestEnsureListFiles(unittest.TestCase):
    """Отсутствующие --hostlist*/--ipset* файлы создаются пустыми.

    Регрессия «Ошибка при добавлении стратегии»: zapret2 (в отличие от v1)
    stat()-ит файлы-списки на этапе разбора опций и падает «failed to register
    hostlist» с exit 1, если файла нет. Одна битая ссылка (ipset/
    zapret-hosts-user.txt из чужого пресета, lists/netrogat.txt при
    несовпадении base_path со старой установкой nfqws2) роняла всю стратегию,
    а уже накатанные NFQUEUE-правила «чёрной дырой» рвали связь → «Сервер
    недоступен». Файлы-списки должны молча дозаявляться пустыми.
    """

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def _p(self, *parts):
        import os
        return os.path.join(self.d, *parts)

    def test_creates_missing_list_files_empty(self):
        import os
        hostlist = self._p("ipset", "zapret-hosts-user.txt")  # нет каталога
        exclude = self._p("lists", "netrogat.txt")
        auto = self._p("lists", "auto.txt")
        ipset = self._p("ipset", "ip.txt")
        argv = [
            "/opt/zapret2/nfq2/nfqws2", "--qnum=300", "--filter-tcp=443",
            "--hostlist=%s" % hostlist,
            "--hostlist-exclude=%s" % exclude,
            "--hostlist-auto=%s" % auto,
            "--ipset=%s" % ipset,
        ]
        NFQWSManager._ensure_list_files(argv)
        for p in (hostlist, exclude, auto, ipset):
            self.assertTrue(os.path.isfile(p), "не создан: %s" % p)
            self.assertEqual(os.path.getsize(p), 0, "не пустой: %s" % p)

    def test_inline_and_debug_flags_are_not_files(self):
        import os
        debug_log = self._p("auto-debug.log")
        argv = [
            "/opt/zapret2/nfq2/nfqws2",
            # inline-домены/ip — НЕ пути к файлам, трогать нельзя
            "--hostlist-domains=youtube.com,google.com",
            "--hostlist-exclude-domains=vk.com",
            "--ipset-ip=1.2.3.4",
            # debug-лог nfqws2 создаёт сам (LOG_APPEND) — не наша забота
            "--hostlist-auto-debug=%s" % debug_log,
        ]
        NFQWSManager._ensure_list_files(argv)
        self.assertFalse(os.path.exists(debug_log))
        # каталог не засорён никакими файлами
        self.assertEqual(os.listdir(self.d), [])

    def test_existing_file_not_overwritten(self):
        import os
        exclude = self._p("netrogat.txt")
        with open(exclude, "w") as f:
            f.write("bank.example\n")
        NFQWSManager._ensure_list_files(
            ["/opt/zapret2/nfq2/nfqws2", "--hostlist-exclude=%s" % exclude])
        with open(exclude) as f:
            self.assertEqual(f.read(), "bank.example\n")

    def test_create_failure_does_not_raise(self):
        # read-only/битый путь: best-effort, исключение наружу не летит.
        argv = ["/opt/zapret2/nfq2/nfqws2",
                "--hostlist=%s" % self._p("netrogat.txt")]
        with mock.patch("core.nfqws_manager.open",
                        side_effect=OSError("read-only fs")):
            NFQWSManager._ensure_list_files(argv)  # не должно бросить

    def test_epoch_mtime_healed_content_kept(self):
        # Регрессия «cannot access hostlist file '<file>' при живом файле»:
        # file_mod_time() nfqws2 трактует st_mtime == 0 (Jan 1 1970) как
        # ошибку stat() → exit 1. Такой файл надо touch'нуть, не трогая
        # содержимое.
        import os
        exclude = self._p("netrogat.txt")
        with open(exclude, "w") as f:
            f.write("bank.example\n")
        os.utime(exclude, (0, 0))
        NFQWSManager._ensure_list_files(
            ["/opt/zapret2/nfq2/nfqws2", "--hostlist-exclude=%s" % exclude])
        self.assertGreater(os.stat(exclude).st_mtime, 0)
        with open(exclude) as f:
            self.assertEqual(f.read(), "bank.example\n")

    def test_normal_mtime_untouched(self):
        import os
        exclude = self._p("netrogat.txt")
        with open(exclude, "w") as f:
            f.write("x\n")
        os.utime(exclude, (1234567890, 1234567890))
        NFQWSManager._ensure_list_files(
            ["/opt/zapret2/nfq2/nfqws2", "--hostlist-exclude=%s" % exclude])
        self.assertEqual(int(os.stat(exclude).st_mtime), 1234567890)

    def test_epoch_mtime_fix_failure_does_not_raise(self):
        # utime может упасть (read-only FS) — best-effort, не роняем запуск.
        import os
        exclude = self._p("netrogat.txt")
        open(exclude, "w").close()
        os.utime(exclude, (0, 0))
        with mock.patch("core.nfqws_manager.os.utime",
                        side_effect=OSError("read-only fs")):
            NFQWSManager._ensure_list_files(
                ["/opt/zapret2/nfq2/nfqws2",
                 "--hostlist-exclude=%s" % exclude])

    def test_dry_run_creates_files_before_validation(self):
        import os
        missing = self._p("ipset", "zapret-hosts-user.txt")
        cfg = mock.Mock()
        cfg.get.return_value = "/opt/zapret2/nfq2/nfqws2"
        completed = mock.Mock(returncode=0, stdout=b"ok")
        with mock.patch.object(NFQWSManager, "_recover_pid"):
            mgr = NFQWSManager()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch("core.nfqws_manager.os.path.isfile",
                        return_value=True), \
             mock.patch("core.nfqws_manager.os.access", return_value=True), \
             mock.patch.object(mgr, "compose_command",
                               return_value=["/opt/zapret2/nfq2/nfqws2",
                                             "--user=nobody",
                                             "--hostlist=%s" % missing]), \
             mock.patch("core.nfqws_manager.subprocess.run",
                        return_value=completed):
            res = mgr.dry_run(["--hostlist=%s" % missing])
        self.assertTrue(res["ok"])
        self.assertTrue(os.path.isfile(missing),
                        "dry_run не создал недостающий hostlist")


if __name__ == "__main__":
    unittest.main()
