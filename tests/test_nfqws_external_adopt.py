# tests/test_nfqws_external_adopt.py
"""Регрессия discussion #102: после перезагрузки роутера GUI врал про nfqws2.

Автозапуск S99zapret поднимает nfqws2 сам (`--daemon --pidfile=`), а
`/var/run` — tmpfs, так что нашего PID-файла после ребута нет в принципе.
Менеджер обязан подобрать такой процесс, иначе «Главная» и «Управление»
показывают «не работает» при живом обходе.

Подхватывать при этом можно только демонов: blockcheck2.sh во время
подбора стратегии крутит свои короткоживущие nfqws2, и они не должны
превращаться в «обход запущен».
"""

import unittest
from unittest import mock

from core.nfqws_manager import AUTOSTART_PID_FILE, NFQWSManager


class TestExternalAdopt(unittest.TestCase):

    def setUp(self):
        with mock.patch.object(NFQWSManager, "_recover_pid"):
            self.mgr = NFQWSManager()
        self.mgr._process = None
        self.mgr._pid = None

    def _no_pid_files(self, autostart_pid=None):
        """Подменить чтение PID-файлов: свой пуст, автозапуска — по вкусу."""
        def fake_read(path=None):
            if path == AUTOSTART_PID_FILE:
                return autostart_pid
            return None
        return mock.patch.object(NFQWSManager, "_read_pid_file",
                                 side_effect=fake_read)

    def test_adopts_daemon_from_autostart_pid_file(self):
        with self._no_pid_files(autostart_pid=4242), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True):
            self.assertTrue(self.mgr.is_running())

        self.assertEqual(self.mgr._pid, 4242)
        self.assertTrue(self.mgr._external)

    def test_status_marks_adopted_process_as_external(self):
        with self._no_pid_files(autostart_pid=4242), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True):
            status = self.mgr.get_status()

        self.assertTrue(status["running"])
        self.assertEqual(status["pid"], 4242)
        self.assertTrue(status["external"])

    def test_stale_autostart_pid_file_is_not_adopted(self):
        # PID-файл остался от прошлой загрузки, процесса уже нет.
        with self._no_pid_files(autostart_pid=4242), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=False), \
             mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[]):
            self.assertFalse(self.mgr.is_running())

    def test_scan_adopts_only_daemonized_process(self):
        cmdlines = {
            777: ["/opt/zapret2/nfq2/nfqws2", "--qnum=200",
                  "--lua-desync=fake"],                       # проба blockcheck
            888: ["/opt/zapret2/nfq2/nfqws2", "--qnum=200", "--daemon",
                  "--pidfile=/var/run/zapret-nfqws.pid"],      # автозапуск
        }
        with self._no_pid_files(), \
             mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[777, 888]), \
             mock.patch.object(NFQWSManager, "_proc_cmdline",
                               side_effect=lambda p: cmdlines[p]), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True):
            self.assertTrue(self.mgr.is_running())

        self.assertEqual(self.mgr._pid, 888)

    def test_probe_processes_do_not_count_as_running(self):
        # Только чужие непрямые nfqws2 (без --daemon/--pidfile) — «не запущен».
        with self._no_pid_files(), \
             mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               return_value=[777]), \
             mock.patch.object(NFQWSManager, "_proc_cmdline",
                               return_value=["nfqws2", "--qnum=200"]), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True):
            self.assertFalse(self.mgr.is_running())

    def test_proc_scan_is_throttled(self):
        calls = []

        def counting_scan():
            calls.append(1)
            return []

        with self._no_pid_files(), \
             mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                               side_effect=counting_scan):
            for _ in range(5):
                self.assertFalse(self.mgr.is_running())

        # Пять опросов подряд — один скан /proc.
        self.assertEqual(len(calls), 1)

    def test_own_process_is_not_external(self):
        with mock.patch.object(NFQWSManager, "_read_pid_file",
                               return_value=1234), \
             mock.patch.object(NFQWSManager, "_check_pid_alive",
                               return_value=True):
            self.assertTrue(self.mgr.is_running())

        self.assertFalse(self.mgr._external)
        self.assertFalse(self.mgr.get_status()["external"])


if __name__ == "__main__":
    unittest.main()
