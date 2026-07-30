# tests/test_nfqws_reload_lists.py
"""issue #265: правка списков должна доезжать до живого nfqws2 (SIGHUP).

nfqws2 читает хостлисты/ipset-ы один раз при старте и перечитывает их только
по SIGHUP. Без сигнала «добавил домен в Exclude» не действовало до
перезапуска обхода — сайт продолжал ломаться десинком.
"""

import os
import signal
import tempfile
import unittest
from unittest import mock

from core.config_manager import get_config_manager
from core.hostlist_manager import get_hostlist_manager
from core.ipset_manager import get_ipset_manager


class TestReloadOnListWrite(unittest.TestCase):

    def setUp(self):
        self.cfg = get_config_manager()
        self.cfg.load()
        self.lists_dir = tempfile.mkdtemp()
        self.ipset_dir = tempfile.mkdtemp()
        self.cfg.set("zapret", "lists_path", self.lists_dir)
        self.cfg.set("zapret", "ipset_path", self.ipset_dir)

    # ── hostlists ──
    def test_save_hostlist_signals_running_nfqws(self):
        hm = get_hostlist_manager()
        with mock.patch("core.nfqws_reload.find_nfqws_pids",
                        return_value=[4242]), \
             mock.patch("core.nfqws_reload.os.kill") as kill:
            self.assertTrue(hm.save_hostlist("netrogat", ["aliexpress.ru"]))

        kill.assert_called_once_with(4242, signal.SIGHUP)
        with open(os.path.join(self.lists_dir, "netrogat.txt")) as f:
            self.assertIn("aliexpress.ru", f.read())

    def test_add_domains_signals_running_nfqws(self):
        # Путь из GUI: «Добавить домен» в список исключений.
        hm = get_hostlist_manager()
        hm.save_hostlist("netrogat", [])
        with mock.patch("core.nfqws_reload.find_nfqws_pids",
                        return_value=[7]), \
             mock.patch("core.nfqws_reload.os.kill") as kill:
            self.assertEqual(hm.add_domains("netrogat", ["deepseek.com"]), 1)
        kill.assert_called_once_with(7, signal.SIGHUP)

    def test_save_hostlist_ok_when_nfqws_not_running(self):
        # Обход выключен — запись обязана пройти без ошибок.
        hm = get_hostlist_manager()
        with mock.patch("core.nfqws_reload.find_nfqws_pids", return_value=[]):
            self.assertTrue(hm.save_hostlist("other2", ["example.com"]))

    def test_dead_pid_does_not_break_save(self):
        hm = get_hostlist_manager()
        with mock.patch("core.nfqws_reload.find_nfqws_pids",
                        return_value=[999999]), \
             mock.patch("core.nfqws_reload.os.kill",
                        side_effect=ProcessLookupError()):
            self.assertTrue(hm.save_hostlist("other2", ["example.com"]))

    # ── ipsets ──
    def test_save_ipset_signals_running_nfqws(self):
        im = get_ipset_manager()
        with mock.patch("core.nfqws_reload.find_nfqws_pids",
                        return_value=[11]), \
             mock.patch("core.nfqws_reload.os.kill") as kill:
            self.assertTrue(im.save_ipset("my-ipset", ["1.2.3.4"]))
        kill.assert_called_once_with(11, signal.SIGHUP)


class TestFindNfqwsPids(unittest.TestCase):

    def test_pidfile_and_proc_scan_are_merged_without_dupes(self):
        from core import nfqws_reload

        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("100\n")
            pidfile = f.name
        self.addCleanup(os.unlink, pidfile)

        with mock.patch.object(nfqws_reload, "PID_FILES", (pidfile,)), \
             mock.patch("core.nfqws_manager.NFQWSManager._find_nfqws_pids",
                        return_value=[100, 200]):
            self.assertEqual(nfqws_reload.find_nfqws_pids(), [100, 200])

    def test_proc_scan_finds_pid_without_pidfile(self):
        """GUI поднимает nfqws2 без --daemon — PID-файла может не быть."""
        from core import nfqws_reload

        with mock.patch.object(nfqws_reload, "PID_FILES", ()), \
             mock.patch("core.nfqws_manager.NFQWSManager._find_nfqws_pids",
                        return_value=[321]):
            self.assertEqual(nfqws_reload.find_nfqws_pids(), [321])

    def test_reload_reports_not_running(self):
        from core import nfqws_reload

        with mock.patch.object(nfqws_reload, "find_nfqws_pids",
                               return_value=[]):
            result = nfqws_reload.reload_lists("netrogat.txt")
        self.assertFalse(result["ok"])
        self.assertEqual(result["pids"], [])


if __name__ == "__main__":
    unittest.main()
