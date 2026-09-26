# tests/test_body_probe_family.py
"""
Body-проба по одному семейству адресов.

Сканер пробует стратегию по тем AF, что были заблокированы на baseline.
TLS-тестер умеет «только IPv6», а body-проба раньше шла через
``http.client`` — тот при неудаче IPv6 сам уходит на IPv4. Итог: при
открытом IPv4 и заблокированном IPv6 любая стратегия «проходила» тело
по IPv4 и получала ложный успех.

Сервер здесь настоящий (только 127.0.0.1), двойной стек имитирует
подменённый ``getaddrinfo``: у имени есть ``::1`` (там никто не слушает)
и ``127.0.0.1``.
"""

import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from core.models import SingleTestResult
from core.models import TestStatus as Status
from core.testers import body_tester

_REAL_GETADDRINFO = socket.getaddrinfo


class _Big(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"x" * 70_000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestProbeBodyFamily(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Big)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _resolve(self, host, port, family=0, type=0, proto=0, flags=0):
        if host not in ("dual.test", "v4only.test"):
            return _REAL_GETADDRINFO(host, port, family, type, proto, flags)
        entries = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                    ("127.0.0.1", port))]
        if host == "dual.test":
            entries.insert(0, (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                               ("::1", port, 0, 0)))
        if family:
            entries = [e for e in entries if e[0] == family]
        if not entries:
            raise socket.gaierror(socket.EAI_NONAME, "no such family")
        return entries

    def _probe(self, host, family):
        url = "http://%s:%d/" % (host, self.port)
        with mock.patch("socket.getaddrinfo", side_effect=self._resolve):
            return body_tester.probe_body(url, min_bytes=65_536,
                                          timeout=3.0, ip_family=family)

    def test_ipv4_passes(self):
        self.assertEqual(self._probe("dual.test", "ipv4").status,
                         Status.SUCCESS.value)

    def test_ipv6_does_not_fall_back_to_ipv4(self):
        # На ::1 никто не слушает: проба «по IPv6» обязана упасть, а не
        # скачать тело по 127.0.0.1.
        self.assertNotEqual(self._probe("dual.test", "ipv6").status,
                            Status.SUCCESS.value)

    def test_missing_family_is_skipped(self):
        r = self._probe("v4only.test", "ipv6")
        self.assertEqual(r.status, Status.SKIPPED.value)
        self.assertEqual(r.error, "NO_ADDR_FAMILY")


class TestScannerPassesFamily(unittest.TestCase):
    """Сканер качает тело по тому же AF, что и TLS."""

    def _run(self, body_side_effect):
        from core.scan_targets import detect_target
        from core.strategy_scanner import StrategyScanner

        scanner = StrategyScanner()
        scanner._target = "example.org"
        scanner._protocol = "tcp"
        scanner._mode = "quick"
        scanner._scan_profile = detect_target("example.org")
        # IPv4 открыт без обхода, IPv6 — нет: пробуется только ipv6.
        scanner._baseline_by_af = {"ipv4": True, "ipv6": False}

        tls = SingleTestResult(target="example.org", test_type="tls",
                               status=Status.SUCCESS.value,
                               raw_data={"connected_ip": "2001:db8::1"})
        calls = []

        def fake_body(**kw):
            calls.append(kw)
            return body_side_effect(kw)

        with mock.patch("core.testers.tls_tester.test_tls",
                        return_value=tls), \
                mock.patch("core.testers.body_tester.probe_body",
                           side_effect=fake_body):
            probe = scanner._deep_probe()
        return probe, calls

    def test_body_uses_the_probed_family(self):
        def ok(kw):
            return SingleTestResult(
                target=kw["url"], test_type="http",
                status=Status.SUCCESS.value,
                raw_data={"kbps": 100.0, "bytes_received": 70_000,
                          "status_code": 200})
        probe, calls = self._run(ok)
        self.assertTrue(calls)
        self.assertTrue(all(c.get("ip_family") == "ipv6" for c in calls))
        self.assertTrue(probe["success"])

    def test_probe_url_without_family_falls_back_to_tls_host(self):
        def skipped_then_ok(kw):
            if kw["url"] != "https://example.org/":
                return SingleTestResult(target=kw["url"], test_type="http",
                                        status=Status.SKIPPED.value,
                                        error="NO_ADDR_FAMILY")
            return SingleTestResult(
                target=kw["url"], test_type="http",
                status=Status.SUCCESS.value,
                raw_data={"kbps": 50.0, "bytes_received": 70_000,
                          "status_code": 200})

        with mock.patch("core.scan_targets.ScanTarget.get_probe_url",
                        return_value="https://cdn.example.net/x"):
            probe, calls = self._run(skipped_then_ok)
        self.assertEqual(calls[0]["url"], "https://cdn.example.net/x")
        self.assertEqual(calls[1]["url"], "https://example.org/")
        self.assertTrue(probe["success"])


class TestBaselineUsesTheSameCriterion(unittest.TestCase):
    """Baseline «открыт» — только если прошло и тело, как у стратегии.

    TLS-тестер читает ≤2 КБ ответа: при обрыве на 16-20 КБ handshake
    проходит и без обхода. Раньше baseline считал такую цель открытой,
    и КАЖДАЯ стратегия получала BASELINE_OPEN.
    """

    def _baseline(self, body_result):
        from core.scan_targets import detect_target
        from core.strategy_scanner import StrategyScanner

        scanner = StrategyScanner()
        scanner._target = "example.org"
        scanner._protocol = "tcp"
        scanner._scan_profile = detect_target("example.org")

        def tls(host, port, timeout, ip_family):
            if ip_family == "ipv6":
                return SingleTestResult(target=host, test_type="tls",
                                        status=Status.SKIPPED.value)
            return SingleTestResult(target=host, test_type="tls",
                                    status=Status.SUCCESS.value)

        with mock.patch("core.testers.tls_tester.test_tls",
                        side_effect=tls), \
                mock.patch("core.testers.body_tester.probe_body",
                           return_value=body_result):
            opened = scanner._run_baseline_test()
        return opened, scanner._baseline_by_af

    def test_16_20_cut_is_blocked_not_open(self):
        cut = SingleTestResult(target="u", test_type="tcp_16_20",
                               status=Status.FAILED.value,
                               error="TCP_16_20")
        opened, per_af = self._baseline(cut)
        self.assertFalse(opened)
        self.assertEqual(per_af, {"ipv4": False})

    def test_full_body_is_open(self):
        ok = SingleTestResult(target="u", test_type="http",
                              status=Status.SUCCESS.value)
        opened, per_af = self._baseline(ok)
        self.assertTrue(opened)
        self.assertEqual(per_af, {"ipv4": True})

    def test_no_body_to_check_keeps_tls_verdict(self):
        skipped = SingleTestResult(target="u", test_type="http",
                                   status=Status.SKIPPED.value,
                                   error="NO_ADDR_FAMILY")
        opened, _ = self._baseline(skipped)
        self.assertTrue(opened)


if __name__ == "__main__":
    unittest.main()
