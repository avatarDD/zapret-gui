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


if __name__ == "__main__":
    unittest.main()
