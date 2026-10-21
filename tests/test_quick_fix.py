# tests/test_quick_fix.py
"""Быстрый ремонт (core/quick_fix): оценки часов, DNS, маршрута и ремонт."""

import time
import unittest
from unittest import mock

from core import quick_fix as qf


NOW = 1_790_000_000.0          # 2026 год


class TestClock(unittest.TestCase):

    def test_parse_http_date(self):
        ts = qf.parse_http_date("Wed, 21 Oct 2026 07:41:46 GMT")
        self.assertEqual(time.gmtime(ts)[:6], (2026, 10, 21, 7, 41, 46))
        self.assertIsNone(qf.parse_http_date(""))
        self.assertIsNone(qf.parse_http_date("мусор"))

    def test_in_sync(self):
        f = qf.evaluate_clock(NOW, NOW + 3)
        self.assertEqual(f["status"], "ok")
        self.assertIsNone(f["fix"])

    def test_small_skew_warns(self):
        f = qf.evaluate_clock(NOW, NOW + 90)
        self.assertEqual(f["status"], "warning")
        self.assertEqual(f["fix"], "clock_sync")

    def test_big_skew_is_error_in_both_directions(self):
        for delta in (-3 * 86400, 600):
            with self.subTest(delta=delta):
                f = qf.evaluate_clock(NOW, NOW + delta)
                self.assertEqual(f["status"], "error")
                self.assertEqual(f["fix"], "clock_sync")
                self.assertAlmostEqual(f["offset_sec"], delta, delta=1)

    def test_offline_1970_is_error(self):
        f = qf.evaluate_clock(0.0, None)
        self.assertEqual(f["status"], "error")
        self.assertIn("1970", f["title"])

    def test_offline_sane_year_is_unknown(self):
        self.assertEqual(qf.evaluate_clock(NOW, None)["status"], "unknown")


class TestDnsAndRoutes(unittest.TestCase):

    def test_dns_ok(self):
        self.assertEqual(qf.evaluate_dns({"ya.ru": True, "google.com": True},
                                         None)["status"], "ok")

    def test_one_domain_is_a_block_not_a_breakage(self):
        f = qf.evaluate_dns({"ya.ru": True, "google.com": False}, True)
        self.assertEqual(f["status"], "warning")
        self.assertIsNone(f["fix"])

    def test_dead_resolver_with_live_doh_offers_restart(self):
        f = qf.evaluate_dns({"ya.ru": False, "google.com": False}, True)
        self.assertEqual(f["status"], "error")
        self.assertEqual(f["fix"], "dns_restart")

    def test_nothing_works_is_wan_not_dns(self):
        f = qf.evaluate_dns({"ya.ru": False, "google.com": False}, False)
        self.assertEqual(f["status"], "error")
        self.assertIsNone(f["fix"])

    def test_default_route(self):
        head = "Iface\tDestination\tGateway\n"
        ok = qf.evaluate_default_route(
            [head, "eth0\t00000000\t0101A8C0\n", "br0\t0001A8C0\t00000000\n"])
        self.assertEqual(ok["status"], "ok")
        self.assertIn("eth0", ok["detail"])
        bad = qf.evaluate_default_route([head, "br0\t0001A8C0\t00000000\n"])
        self.assertEqual(bad["status"], "error")

    def test_resolv_conf(self):
        self.assertEqual(qf.evaluate_resolv_conf(
            "# x\nnameserver 127.0.0.1\n")["status"], "ok")
        self.assertEqual(qf.evaluate_resolv_conf("search lan\n")["status"],
                         "warning")
        self.assertEqual(qf.evaluate_resolv_conf(None)["status"], "warning")


class TestCheckAndFix(unittest.TestCase):

    def setUp(self):
        qf.invalidate()

    def test_offline_check_sends_nothing(self):
        with mock.patch.object(qf, "network_time") as nt, \
                mock.patch.object(qf, "_resolve") as res:
            report = qf.check(network=False)
        nt.assert_not_called()
        res.assert_not_called()
        ids = [f["id"] for f in report["findings"]]
        self.assertNotIn("dns", ids)
        self.assertIn("clock", ids)

    def test_network_report_is_cached(self):
        with mock.patch.object(qf, "network_time",
                               return_value=time.time()) as nt, \
                mock.patch.object(qf, "_resolve", return_value=True):
            qf.check(network=True)
            qf.check(network=True)
            self.assertEqual(nt.call_count, 1)
            qf.check(network=True, fresh=True)
            self.assertEqual(nt.call_count, 2)

    def test_clock_problem_only_on_error(self):
        with mock.patch.object(qf, "network_time",
                               return_value=time.time() + 86400), \
                mock.patch.object(qf, "_resolve", return_value=True):
            self.assertEqual(qf.clock_problem()["fix"], "clock_sync")
        qf.invalidate()
        with mock.patch.object(qf, "network_time", return_value=time.time()), \
                mock.patch.object(qf, "_resolve", return_value=True):
            self.assertIsNone(qf.clock_problem())

    def test_sync_prefers_busybox_ntpd(self):
        with mock.patch.object(qf, "_busybox_ntpd",
                               return_value="/usr/sbin/ntpd"), \
                mock.patch.object(qf, "_run", return_value=(0, "")) as run:
            r = qf.sync_clock()
        self.assertTrue(r["ok"])
        self.assertEqual(r["method"], "ntpd")
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/sbin/ntpd", "-q", "-n", "-p"])
        # Все серверы — одним вызовом с общим таймаутом.
        self.assertEqual(argv.count("-p"), len(qf.NTP_SERVERS))
        self.assertEqual(run.call_count, 1)
        # Время попыток — не сдвиг часов.
        self.assertLess(abs(r["shift_sec"]), 1)

    def test_foreign_ntpd_is_not_called_with_busybox_flags(self):
        with mock.patch.object(qf.shutil, "which",
                               return_value="/usr/sbin/ntpd"), \
                mock.patch.object(qf.os.path, "realpath",
                                  return_value="/usr/sbin/ntpd"), \
                mock.patch.object(qf, "_run",
                                  return_value=(0, "ntpd 4.2.8p15")):
            self.assertIsNone(qf._busybox_ntpd())

    def test_sync_falls_back_to_http_date(self):
        calls = []

        def fake_run(argv, timeout=20):
            calls.append(argv)
            return 0, ""

        with mock.patch.object(qf.shutil, "which", return_value=None), \
                mock.patch.object(qf, "_busybox_ntpd", return_value=None), \
                mock.patch.object(qf, "network_time", return_value=NOW), \
                mock.patch.object(qf, "_run", side_effect=fake_run):
            r = qf.sync_clock()
        self.assertTrue(r["ok"])
        self.assertEqual(r["method"], "http-date")
        self.assertEqual(calls[-1][:3], ["date", "-u", "-s"])
        self.assertTrue(calls[-1][3].startswith("2026-"))

    def test_sync_without_network_fails_cleanly(self):
        with mock.patch.object(qf.shutil, "which", return_value=None), \
                mock.patch.object(qf, "_busybox_ntpd", return_value=None), \
                mock.patch.object(qf, "network_time", return_value=None):
            r = qf.sync_clock()
        self.assertFalse(r["ok"])

    def test_dns_restart_starts_a_dead_dnsmasq(self):
        dn = mock.Mock()
        dn.get_pid.return_value = 0
        dn._has_dnsmasq_service.return_value = False
        dn._find_init_script.return_value = "/etc/init.d/dnsmasq"
        dn._step_start_init_script.return_value = {"ok": True}
        with mock.patch("core.routing.dnsmasq_integration."
                        "DnsmasqIntegration", return_value=dn):
            r = qf.restart_dns()
        self.assertTrue(r["ok"])
        dn.restart.assert_not_called()
        dn._step_start_init_script.assert_called_once()

    def test_dns_restart_running_uses_integration(self):
        dn = mock.Mock()
        dn.get_pid.return_value = 42
        dn.restart.return_value = {"ok": True, "how": "/etc/init.d/dnsmasq"}
        with mock.patch("core.routing.dnsmasq_integration."
                        "DnsmasqIntegration", return_value=dn):
            self.assertTrue(qf.restart_dns()["ok"])
        dn.restart.assert_called_once()

    def test_dns_restart_without_dnsmasq(self):
        dn = mock.Mock()
        dn.get_pid.return_value = 0
        dn._has_dnsmasq_service.return_value = False
        dn._find_init_script.return_value = ""
        with mock.patch("core.routing.dnsmasq_integration."
                        "DnsmasqIntegration", return_value=dn):
            self.assertFalse(qf.restart_dns()["ok"])

    def test_second_fix_while_running_is_refused(self):
        self.assertTrue(qf._fix_lock.acquire(blocking=False))
        try:
            r = qf.apply_fix("clock_sync")
        finally:
            qf._fix_lock.release()
        self.assertTrue(r.get("busy"))

    def test_dns_query_roundtrip(self):
        q = qf.build_dns_query("ya.ru", 0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x02ya\x02ru\x00", q)
        # Настоящий ответ: вопрос и A-запись со сжатым именем.
        reply = (b"\x12\x34" + b"\x81\x80" + b"\x00\x01\x00\x01"
                 + b"\x00\x00\x00\x00" + q[12:]
                 + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                 + bytes([87, 250, 250, 242]))
        self.assertTrue(qf.dns_reply_ok(reply, 0x1234))
        self.assertFalse(qf.dns_reply_ok(reply, 0x9999))
        nx = reply[:2] + b"\x81\x83" + reply[4:]
        self.assertFalse(qf.dns_reply_ok(nx, 0x1234))

    def test_clock_problem_is_one_probe(self):
        with mock.patch.object(qf, "network_time",
                               return_value=time.time() + 86400), \
                mock.patch.object(qf, "_resolve") as res:
            self.assertIsNotNone(qf.clock_problem())
        res.assert_not_called()

    def test_unknown_fix(self):
        r = qf.apply_fix("rm_rf")
        self.assertFalse(r["ok"])
        self.assertEqual(r["known"], list(qf.FIXES))


class TestPrerequisitesSeeClock(unittest.TestCase):

    def test_1970_is_a_prerequisite_error(self):
        from core import diagnostics as diag
        with mock.patch.object(diag.time, "time", return_value=0.0):
            report = diag.check_strategy_prerequisites()
        ids = [i["id"] for i in report["issues"]]
        self.assertIn("clock_wrong", ids)
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()


class TestMcpTools(unittest.TestCase):

    def test_clock_sync_needs_probes(self):
        from core.mcp.tools import diagnostics as tools
        with mock.patch.object(tools.perms_mod, "granted",
                               side_effect=lambda name: name == "control"), \
                mock.patch.object(qf, "apply_fix") as fix:
            r = tools.quick_fix_apply({"fix": "clock_sync"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["permission"], "probes")
        fix.assert_not_called()

    def test_check_without_probes_is_offline(self):
        from core.mcp.tools import diagnostics as tools
        with mock.patch.object(tools.perms_mod, "granted",
                               return_value=False), \
                mock.patch.object(qf, "check",
                                  return_value={"ok": True,
                                                "findings": []}) as chk:
            r = tools.quick_fix_check({})
        self.assertFalse(chk.call_args.kwargs["network"])
        self.assertEqual(r["probes"]["permission"], "probes")
