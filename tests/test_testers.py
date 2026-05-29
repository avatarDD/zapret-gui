# tests/test_testers.py
"""
Unit-тесты для core/testers/ — DPI-классификатор, STUN-парсер,
body_tester, isp_detector.

Сетевые вызовы (socket.connect, ssl.wrap_socket) мокаем.
"""

import errno
import socket
import ssl
import struct
import unittest
from unittest import mock

from core.testers import dpi_classifier, stun_tester, body_tester


# ─────── DPI classifier ───────

class TestClassifySslError(unittest.TestCase):
    """classify_ssl_error по тексту ошибки и bytes_read."""

    def test_connection_reset(self):
        e = ssl.SSLError("connection reset by peer")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_RESET")

    def test_eof_early(self):
        e = ssl.SSLError("EOF occurred in violation of protocol")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_EOF_EARLY")

    def test_eof_after_data(self):
        e = ssl.SSLError("EOF occurred")
        label, _, n = dpi_classifier.classify_ssl_error(e, 1024)
        self.assertEqual(label, "TLS_EOF_DATA")
        self.assertEqual(n, 1024)

    def test_certificate_self_signed(self):
        e = ssl.SSLError("certificate verify failed: self signed certificate")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_MITM_SELF")

    def test_unknown_ca(self):
        e = ssl.SSLError("certificate verify failed: unable to get local issuer certificate")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_MITM_UNKNOWN_CA")

    def test_certificate_other(self):
        e = ssl.SSLError("certificate verify failed: expired")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_CERT_ERR")

    def test_unsupported(self):
        e = ssl.SSLError("no protocols available")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_UNSUPPORTED")

    def test_handshake_failure(self):
        e = ssl.SSLError("sslv3 alert handshake failure")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_HANDSHAKE")

    def test_sni_reject(self):
        e = ssl.SSLError("alert unrecognized_name")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_SNI_REJECT")

    def test_timeout(self):
        e = ssl.SSLError("timed out")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_TIMEOUT")

    def test_unknown_returns_generic(self):
        e = ssl.SSLError("some weird new error")
        label, _, _ = dpi_classifier.classify_ssl_error(e, 0)
        self.assertEqual(label, "TLS_ERR")


class TestClassifyConnectError(unittest.TestCase):

    def test_connection_reset(self):
        e = ConnectionResetError("reset")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "TCP_RESET")

    def test_connection_refused(self):
        e = ConnectionRefusedError("refused")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "TCP_REFUSED")

    def test_timeout(self):
        e = OSError(errno.ETIMEDOUT, "timed out")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "TCP_TIMEOUT")

    def test_host_unreach(self):
        e = OSError(errno.EHOSTUNREACH, "host unreachable")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "HOST_UNREACH")

    def test_net_unreach(self):
        e = OSError(errno.ENETUNREACH, "net unreachable")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "NET_UNREACH")

    def test_generic(self):
        e = OSError(999, "unknown")
        label, _, _ = dpi_classifier.classify_connect_error(e)
        self.assertEqual(label, "CONNECT_ERR")


class TestClassifyReadError(unittest.TestCase):

    def test_reset_mid_stream(self):
        e = OSError("Connection reset")
        label, _, n = dpi_classifier.classify_read_error(e, 5000)
        self.assertEqual(label, "READ_RESET")
        self.assertEqual(n, 5000)

    def test_timeout(self):
        e = socket.timeout("timed out")
        label, _, _ = dpi_classifier.classify_read_error(e, 0)
        self.assertEqual(label, "READ_TIMEOUT")

    def test_broken_pipe(self):
        e = BrokenPipeError("broken pipe")
        label, _, _ = dpi_classifier.classify_read_error(e, 0)
        self.assertEqual(label, "READ_BROKEN")

    def test_generic(self):
        e = Exception("some other error")
        label, _, _ = dpi_classifier.classify_read_error(e, 0)
        self.assertEqual(label, "READ_ERR")


# ─────── STUN parser ───────

class TestBuildStunRequest(unittest.TestCase):

    def test_header_format(self):
        req = stun_tester.build_stun_request()
        # 20 байт: 2 type + 2 length + 4 magic + 12 transaction
        self.assertEqual(len(req), 20)
        # Magic cookie
        magic = struct.unpack(">I", req[4:8])[0]
        self.assertEqual(magic, 0x2112A442)
        # Message type — Binding Request
        msg_type = struct.unpack(">H", req[0:2])[0]
        self.assertEqual(msg_type, 0x0001)

    def test_transaction_id_random(self):
        # Два подряд build_stun_request должны отличаться TID
        a = stun_tester.build_stun_request()
        b = stun_tester.build_stun_request()
        self.assertNotEqual(a[8:20], b[8:20])


class TestParseStunResponse(unittest.TestCase):

    def test_garbage_returns_none(self):
        self.assertIsNone(stun_tester.parse_stun_response(b"\x00" * 5))
        self.assertIsNone(stun_tester.parse_stun_response(b""))

    def test_wrong_magic_returns_none(self):
        # Build header с неправильным magic cookie
        bad = struct.pack(">HHI", 0x0101, 0, 0xDEADBEEF) + b"\x00" * 12
        self.assertIsNone(stun_tester.parse_stun_response(bad))

    def test_valid_xor_mapped_ipv4(self):
        # Сконструируем валидный STUN-ответ с XOR-MAPPED-ADDRESS
        # IPv4: 203.0.113.5 порт 8080
        magic = 0x2112A442
        tid = b"\x01" * 12
        # Calc XOR-encoded IPv4 + port
        port = 8080
        xor_port = port ^ (magic >> 16)
        ip_int = (203 << 24) | (0 << 16) | (113 << 8) | 5
        xor_ip = ip_int ^ magic
        attr_value = struct.pack(">BBHI", 0, 0x01, xor_port, xor_ip)
        # XOR-MAPPED-ADDRESS attribute type = 0x0020, length = 8
        attr = struct.pack(">HH", 0x0020, 8) + attr_value
        # Response header: type=0x0101 (Binding Success), length=12
        header = struct.pack(">HHI", 0x0101, len(attr), magic) + tid
        full = header + attr
        result = stun_tester.parse_stun_response(full)
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "203.0.113.5")
        self.assertEqual(result["port"], 8080)
        self.assertEqual(result["family"], "IPv4")


# ─────── body tester ───────

class TestDetectIspMarker(unittest.TestCase):

    def test_no_marker(self):
        body = b"<html><body>Hello</body></html>"
        self.assertEqual(body_tester._detect_isp_marker(body), "")

    def test_rkn_marker(self):
        body = b"<html>The site is blocked by Roskomnadzor (rkn.gov.ru)</html>"
        self.assertNotEqual(body_tester._detect_isp_marker(body), "")

    def test_blocked_phrase(self):
        body = b"<html>blocked by federal law</html>"
        self.assertNotEqual(body_tester._detect_isp_marker(body), "")

    def test_garbage_body(self):
        # Не должен падать на бинарном/нечитаемом теле
        body = b"\x00\xff\x80\x01\x02"
        result = body_tester._detect_isp_marker(body)
        self.assertEqual(result, "")


# ─────── off-domain redirect (заимствовано из blockcheckw) ───────


class TestOffDomainRedirect(unittest.TestCase):
    """Мягкий сигнал ISP-заглушки: редирект на чужой регистрируемый домен."""

    def test_same_domain_not_off(self):
        from core.testers.isp_detector import is_off_domain_redirect
        # m.youtube.com → youtube.com — норма, не off-domain
        self.assertFalse(is_off_domain_redirect(
            "m.youtube.com", "https://youtube.com/"))
        # Тот же хост
        self.assertFalse(is_off_domain_redirect(
            "example.com", "https://example.com/login"))

    def test_relative_not_off(self):
        from core.testers.isp_detector import is_off_domain_redirect
        self.assertFalse(is_off_domain_redirect("example.com", "/login"))
        self.assertFalse(is_off_domain_redirect("example.com", "#frag"))
        self.assertFalse(is_off_domain_redirect("example.com", ""))

    def test_different_etld_is_off(self):
        from core.testers.isp_detector import is_off_domain_redirect
        # youtube.com → rkn.gov.ru — сильно отличающиеся регистрируемые домены
        self.assertTrue(is_off_domain_redirect(
            "youtube.com", "https://warning.rt.ru/?id=1"))
        self.assertTrue(is_off_domain_redirect(
            "discord.com", "http://blackhole.example.net/blocked"))

    def test_subdomain_of_different_etld_is_off(self):
        from core.testers.isp_detector import is_off_domain_redirect
        self.assertTrue(is_off_domain_redirect(
            "discord.com", "https://login.facebook.com/oauth"))


# ─────── FAKE_LEAK: HTTP 400 = десинк не сработал (blockcheckw) ───────


class TestFakeLeakDetection(unittest.TestCase):
    """body_tester должен помечать HTTP 400 как FAKE_LEAK."""

    def test_priority_includes_fake_leak(self):
        # FAKE_LEAK имеет более высокий приоритет, чем TCP_16_20
        from core.strategy_scanner import StrategyScanner
        s = StrategyScanner()
        # Симулируем выбор лучшей ошибки: FAKE_LEAK выигрывает у TCP_16_20
        # (важно для корректной отметки «стратегия точно не помогает»)
        err = s._pick_best_error({"FAKE_LEAK", "TCP_16_20"}, 0, 0)
        self.assertEqual(err, "FAKE_LEAK")

    def test_status_400_classified_as_fake_leak(self):
        # Прямо: status_code=400 в body_tester ветке после успешного чтения
        # классифицируется как FAILED + FAKE_LEAK.
        # Используем mock для http.client, чтобы не лезть в сеть.
        from core.testers import body_tester
        with mock.patch("core.testers.body_tester.http.client.HTTPSConnection") \
                as M:
            resp = mock.Mock()
            resp.status = 400
            resp.read = mock.Mock(side_effect=[b"bad", b""])
            conn = mock.Mock()
            conn.getresponse.return_value = resp
            M.return_value = conn

            r = body_tester.probe_body("https://example.com/", min_bytes=100,
                                       timeout=2.0)
            self.assertEqual(r.error, "FAKE_LEAK")
            self.assertEqual(r.raw_data.get("status_code"), 400)


# ─────── Widened TCP block range (10..25 KB, blockcheckw) ───────


class TestWideTcpBlockRange(unittest.TestCase):
    """Расширенное окно DPI data-limit ловит вариации 16-20KB-блока."""

    def test_wide_range_constants(self):
        from core.testers.config import (
            TCP_BLOCK_RANGE_MAX, TCP_BLOCK_RANGE_MIN,
            TCP_BLOCK_RANGE_WIDE_MAX, TCP_BLOCK_RANGE_WIDE_MIN,
        )
        self.assertLess(TCP_BLOCK_RANGE_WIDE_MIN, TCP_BLOCK_RANGE_MIN)
        self.assertGreater(TCP_BLOCK_RANGE_WIDE_MAX, TCP_BLOCK_RANGE_MAX)
        # Окно из blockcheckw
        self.assertEqual(TCP_BLOCK_RANGE_WIDE_MIN, 10_240)
        self.assertEqual(TCP_BLOCK_RANGE_WIDE_MAX, 25_600)


# ─────── IP-block vs DPI-block (заимствовано из blockcheckw) ───────

class TestIpVsDpiClassification(unittest.TestCase):
    """Разделение IP-блока (нужен туннель) и DPI-блока (поможет zapret)."""

    def _target(self, *results):
        from core.models import TargetResult, SingleTestResult
        tr = TargetResult(domain="example.com")
        tr.results = list(results)
        return tr

    def _r(self, test_type, status, error=""):
        from core.models import SingleTestResult, TestType, TestStatus
        tt = getattr(TestType, test_type).value
        st = getattr(TestStatus, status).value
        return SingleTestResult(target="example.com", test_type=tt,
                                status=st, error=error)

    def test_ip_block_on_connect_refused(self):
        from core.models import DPIClassification
        tr = self._target(
            self._r("DNS", "SUCCESS"),
            self._r("TLS_13", "FAILED", "TCP_REFUSED"),
            self._r("TLS_12", "FAILED", "HOST_UNREACH"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.IP_BLOCK)

    def test_rst_during_handshake_is_dpi_not_ip(self):
        from core.models import DPIClassification
        tr = self._target(
            self._r("DNS", "SUCCESS"),
            self._r("TLS_13", "FAILED", "TLS_RESET"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.TLS_DPI)

    def test_dns_failed_not_ip_block(self):
        # Если DNS не резолвится — это не IP-блок (другая причина).
        from core.models import DPIClassification
        tr = self._target(
            self._r("DNS", "FAILED", "DNS_ERR"),
            self._r("TLS_13", "FAILED", "HOST_UNREACH"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertNotEqual(c, DPIClassification.IP_BLOCK)


class TestRemediation(unittest.TestCase):
    """Машиночитаемая рекомендация по типу блокировки."""

    def test_map(self):
        from core.models import remediation_for
        self.assertEqual(remediation_for("tls_dpi"), "zapret")
        self.assertEqual(remediation_for("tcp_16_20"), "zapret")
        self.assertEqual(remediation_for("ip_block"), "tunnel")
        self.assertEqual(remediation_for("full_block"), "tunnel")
        self.assertEqual(remediation_for("dns_fake"), "dns")
        self.assertEqual(remediation_for("none"), "none")

    def test_target_dict_includes_remediation(self):
        from core.models import TargetResult, DPIClassification
        tr = TargetResult(domain="x.com")
        tr.dpi_classification = DPIClassification.IP_BLOCK.value
        self.assertEqual(tr.to_dict()["remediation"], "tunnel")


if __name__ == "__main__":
    unittest.main()
