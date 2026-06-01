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


if __name__ == "__main__":
    unittest.main()
