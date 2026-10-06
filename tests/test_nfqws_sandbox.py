"""Песочница сканера: второй nfqws2 на своей очереди (core/nfqws_sandbox.py).

Сторожит главное обещание: пока идёт подбор, обход сети не трогается —
ни процесс основного движка, ни его правила. И обратное: основной
менеджер не принимает песочницу за дубль и не убивает её.
"""

import socket
import unittest
from unittest import mock

from core import nfqws_sandbox, probe_mark
from core.firewall import FirewallManager, SANDBOX_CHAINS
from core.nfqws_manager import NFQWSManager, SANDBOX_PID_FILE
from core.strategy_scanner import StrategyScanner


class FakeCfg:
    def __init__(self, **values):
        self.values = values

    def get(self, section, key, default=None):
        return self.values.get("%s.%s" % (section, key), default)


class TestQueueAndMark(unittest.TestCase):

    def test_default_is_main_plus_one(self):
        self.assertEqual(nfqws_sandbox.queue_num(
            FakeCfg(**{"nfqws.queue_num": 300})), 301)

    def test_never_equals_main(self):
        cfg = FakeCfg(**{"nfqws.queue_num": 300,
                         "scan.sandbox_queue_num": 300})
        self.assertEqual(nfqws_sandbox.queue_num(cfg), 301)
        cfg = FakeCfg(**{"nfqws.queue_num": 65535})
        self.assertEqual(nfqws_sandbox.queue_num(cfg), 65534)

    def test_explicit(self):
        cfg = FakeCfg(**{"nfqws.queue_num": 300,
                         "scan.sandbox_queue_num": 777})
        self.assertEqual(nfqws_sandbox.queue_num(cfg), 777)

    def test_mark(self):
        self.assertEqual(nfqws_sandbox.mark(FakeCfg()), 0x80000000)
        self.assertEqual(nfqws_sandbox.mark(
            FakeCfg(**{"nfqws.desync_mark_sandbox": ""})), 0)

    def test_available_reasons(self):
        off = nfqws_sandbox.available(FakeCfg(**{"scan.isolated": "off"}))
        self.assertFalse(off["ok"])
        with mock.patch.object(probe_mark, "supported", return_value=False):
            self.assertIn("SO_MARK", nfqws_sandbox.available(
                FakeCfg())["reason"])


class TestProcesses(unittest.TestCase):

    def test_base_args_use_own_queue(self):
        with mock.patch.object(nfqws_sandbox.NFQWSSandbox, "_recover_pid"):
            sandbox = nfqws_sandbox.NFQWSSandbox(301)
        cfg = FakeCfg(**{"nfqws.queue_num": 300, "nfqws.user": "nobody"})
        with mock.patch.object(NFQWSManager, "_detect_wan_interfaces",
                               return_value=[]):
            args = sandbox._build_base_args(cfg)
        self.assertIn("--qnum=301", args)
        self.assertNotIn("--qnum=300", args)

    def test_own_pidfile_state_and_log(self):
        self.assertEqual(nfqws_sandbox.NFQWSSandbox.PID_PATH,
                         SANDBOX_PID_FILE)
        self.assertNotEqual(NFQWSManager.PID_PATH, SANDBOX_PID_FILE)
        self.assertEqual(nfqws_sandbox.NFQWSSandbox.LOG_SOURCE,
                         "nfqws-sandbox")
        self.assertNotEqual(nfqws_sandbox.NFQWSSandbox._state_dir(),
                            NFQWSManager._state_dir())

    def test_main_manager_does_not_see_sandbox(self):
        # Зачистка «дублей» основного менеджера не должна убить песочницу.
        with mock.patch("core.nfqws_manager._sandbox_pid",
                        return_value=4242), \
                mock.patch("core.nfqws_manager.os.listdir",
                           return_value=["4242", "100"]), \
                mock.patch("builtins.open",
                           mock.mock_open(read_data=b"/opt/nfqws2\x00-x")):
            pids = NFQWSManager._find_nfqws_pids()
        self.assertEqual(pids, [100])

    def test_sandbox_sweep_never_touches_main(self):
        with mock.patch.object(nfqws_sandbox.NFQWSSandbox, "_recover_pid"):
            sandbox = nfqws_sandbox.NFQWSSandbox(301)
        with mock.patch("core.nfqws_sandbox._sandbox_pid",
                        return_value=None), \
                mock.patch("core.nfqws_sandbox.os.kill") as kill, \
                mock.patch.object(NFQWSManager, "_find_nfqws_pids",
                                  return_value=[100, 200]):
            sandbox._sweep_stray_processes()
        kill.assert_not_called()

    def test_stale_sandbox_is_killed(self):
        with mock.patch.object(nfqws_sandbox.NFQWSSandbox, "_recover_pid"):
            sandbox = nfqws_sandbox.NFQWSSandbox(301)
        with mock.patch("core.nfqws_sandbox._sandbox_pid",
                        return_value=555), \
                mock.patch("core.nfqws_sandbox.os.kill") as kill, \
                mock.patch.object(NFQWSManager, "_check_pid_alive",
                                  return_value=False), \
                mock.patch.object(nfqws_sandbox.NFQWSSandbox,
                                  "_remove_pid_file"):
            sandbox._sweep_stray_processes()
        self.assertEqual(kill.call_args_list[0][0][0], 555)


def _capture_ipt(fw_type="iptables", **cfg_values):
    fw = FirewallManager()
    fw._fw_type = fw_type
    captured, chains = [], []
    cfg = FakeCfg(**dict({"nfqws.ports_tcp": "80,443",
                          "nfqws.ports_udp": "443",
                          "nfqws.desync_mark": "0x40000000",
                          "nfqws.desync_mark_postnat": "0x20000000",
                          "nfqws.tcp_pkt_out": 20, "nfqws.tcp_pkt_in": 10,
                          "nfqws.udp_pkt_out": 5, "nfqws.udp_pkt_in": 3,
                          "gui.port": 8080}, **cfg_values))
    with mock.patch("core.config_manager.get_config_manager",
                    return_value=cfg), \
            mock.patch.object(fw, "_run_cmd",
                              side_effect=lambda c: captured.append(
                                  " ".join(c)) or True), \
            mock.patch.object(fw, "_ensure_named_chain",
                              side_effect=lambda *a: chains.append(a)), \
            mock.patch.object(fw, "_nfqueue_supported", return_value=True), \
            mock.patch.object(fw, "_multiport_supported", return_value=True), \
            mock.patch.object(fw, "_connbytes_supported", return_value=True), \
            mock.patch("core.firewall.subprocess.run"):
        ok = fw.apply_sandbox_rules(301, 0x80000000)
    return ok, captured, chains


class TestFirewall(unittest.TestCase):

    def test_iptables_only_marked_connections_to_own_queue(self):
        ok, cmds, chains = _capture_ipt()
        self.assertTrue(ok)
        self.assertEqual({c[3] for c in chains},
                         {name for _, _, name in SANDBOX_CHAINS})
        queue = [c for c in cmds if "NFQUEUE" in c]
        self.assertTrue(queue)
        self.assertTrue(all("--queue-num 301" in c for c in queue))
        # Метка → connmark «песочница + EXCLUDE»: основные правила
        # пропустят такое соединение целиком.
        self.assertTrue(any("--mark 0x80000000/0x80000000 -j CONNMARK "
                            "--set-xmark 0xa0000000/0xa0000000" in c
                            for c in cmds))
        # Чужие соединения — RETURN до любой очереди.
        first_queue = next(i for i, c in enumerate(cmds)
                           if "NFQUEUE" in c and "nfqws_sbx_post" in c)
        ret = next(i for i, c in enumerate(cmds)
                   if "nfqws_sbx_post" in c and "! --mark 0x80000000" in c)
        self.assertLess(ret, first_queue)
        # Основные цепочки не трогаются.
        self.assertFalse(any("nfqws_post " in c or " POSTROUTING " in c
                             for c in cmds))

    def test_nft_separate_table_before_main(self):
        ok, cmds, _ = _capture_ipt(fw_type="nftables")
        self.assertTrue(ok)
        self.assertTrue(all("zapret_gui_sbx" in c for c in cmds))
        self.assertTrue(any("priority 149" in c for c in cmds))
        self.assertTrue(any("ct mark set ct mark or 0xa0000000" in c
                            for c in cmds))
        self.assertTrue(any("queue num 301 bypass" in c for c in cmds))


class TestScanner(unittest.TestCase):

    def _scanner(self):
        scanner = StrategyScanner()
        scanner._target = "example.com"
        scanner._protocol = "tcp"
        return scanner

    def test_decide_isolated_with_running_engine(self):
        scanner = self._scanner()
        engine = mock.Mock(is_running=mock.Mock(return_value=True))
        with mock.patch.object(nfqws_sandbox, "available",
                               return_value={"ok": True, "reason": "ок"}), \
                mock.patch("core.nfqws_manager.get_nfqws_manager",
                           return_value=engine), \
                mock.patch.object(probe_mark, "baseline_mode",
                                  return_value={"marked": True,
                                                "mark": 0x10000000,
                                                "reason": "ок"}), \
                mock.patch.object(nfqws_sandbox, "NFQWSSandbox"):
            scanner._decide_isolation()
        self.assertTrue(scanner._isolated)
        self.assertEqual(scanner._baseline_mark, 0x10000000)
        self.assertEqual(scanner._sandbox_mark, 0x80000000)

    def test_no_baseline_mark_means_old_path(self):
        scanner = self._scanner()
        engine = mock.Mock(is_running=mock.Mock(return_value=True))
        with mock.patch.object(nfqws_sandbox, "available",
                               return_value={"ok": True, "reason": "ок"}), \
                mock.patch("core.nfqws_manager.get_nfqws_manager",
                           return_value=engine), \
                mock.patch.object(probe_mark, "baseline_mode",
                                  return_value={"marked": False, "mark": 0,
                                                "reason": "старые правила"}):
            scanner._decide_isolation()
        self.assertFalse(scanner._isolated)
        self.assertIn("старые правила", scanner._isolation_note)

    def test_isolated_cleanup_leaves_network_engine(self):
        scanner = self._scanner()
        scanner._isolated = True
        scanner._sandbox = mock.Mock()
        main = mock.Mock()
        fw = mock.Mock()
        with mock.patch("core.nfqws_manager.get_nfqws_manager",
                        return_value=main), \
                mock.patch("core.firewall.get_firewall_manager",
                           return_value=fw):
            scanner._ensure_cleanup()
            scanner._saved_nfqws_running = True
            with mock.patch("core.nfqws_session.get_nfqws_session") as ses:
                scanner._restore_previous_state()
        scanner._sandbox.stop.assert_called_once()
        fw.remove_sandbox_rules.assert_called_once()
        fw.remove_rules.assert_not_called()
        main.stop.assert_not_called()
        ses.assert_not_called()

    def test_isolated_probe_uses_sandbox_and_mark(self):
        scanner = self._scanner()
        scanner._isolated = True
        scanner._sandbox_mark = 0x80000000
        scanner._sandbox = mock.Mock(start=mock.Mock(return_value=True),
                                     is_running=mock.Mock(return_value=True))
        main = mock.Mock()

        def deep_probe():
            socket.socket().close()
            return {"success": True, "latency_ms": 10.0, "error": "",
                    "http_code": 200, "kbps": 100.0, "body_passed": True,
                    "success_rate": 1.0, "score": 1.0, "test_type": "tls",
                    "details": "", "per_host": []}

        entry = mock.Mock(section_id="s1", source_file="f", level="l",
                          label="", get_args_list=mock.Mock(return_value=[]))
        entry.name = "s1"
        fw = mock.Mock(sandbox_rules_applied=mock.Mock(return_value=True))
        with mock.patch("core.nfqws_manager.get_nfqws_manager",
                        return_value=main), \
                mock.patch("core.firewall.get_firewall_manager",
                           return_value=fw), \
                mock.patch.object(scanner, "_build_strategy_args",
                                  return_value=["--filter-tcp=443"]), \
                mock.patch.object(scanner, "_get_stabilization_delay",
                                  return_value=0), \
                mock.patch.object(scanner, "_deep_probe",
                                  side_effect=deep_probe), \
                mock.patch.object(probe_mark, "apply",
                                  return_value=True) as apply:
            result = scanner._probe_one_strategy(entry, 0)
        # Сокет пробы получил метку песочницы.
        self.assertEqual(apply.call_args[0][1], 0x80000000)
        self.assertTrue(result.success, result.error)
        scanner._sandbox.start.assert_called_once()
        scanner._sandbox.stop.assert_called_once()
        main.start.assert_not_called()
        fw.is_applied.assert_not_called()


class TestMarkingContext(unittest.TestCase):

    def test_marks_only_inside_and_only_this_thread(self):
        import threading
        if not probe_mark.supported(0x80000000):
            self.skipTest("нет прав на SO_MARK")

        def read():
            sock = socket.socket()
            try:
                return sock.getsockopt(socket.SOL_SOCKET,
                                       probe_mark.SO_MARK) & 0xFFFFFFFF
            finally:
                sock.close()

        other = {}
        with probe_mark.marking(0x80000000):
            inside = read()
            thread = threading.Thread(target=lambda: other.update(v=read()))
            thread.start()
            thread.join()
        self.assertEqual(inside, 0x80000000)
        self.assertEqual(other["v"], 0)
        self.assertEqual(read(), 0)

    def test_failed_mark_refuses_socket(self):
        with mock.patch.object(probe_mark, "apply", return_value=False):
            with probe_mark.marking(0x80000000):
                with self.assertRaises(probe_mark.MarkError):
                    socket.socket()


if __name__ == "__main__":
    unittest.main()
