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


# ─────── THROTTLED / CLIENTHELLO_DPI / QUIC_BLOCK (заимствовано из YT-DPI) ───────

class TestNewClassifications(unittest.TestCase):
    """Новые вердикты: троттлинг, size-based DPI на ClientHello, QUIC-блок."""

    def _target(self, *results):
        from core.models import TargetResult
        tr = TargetResult(domain="example.com")
        tr.results = list(results)
        return tr

    def _r(self, test_type, status, error=""):
        from core.models import SingleTestResult, TestType, TestStatus
        tt = getattr(TestType, test_type).value
        st = getattr(TestStatus, status).value
        return SingleTestResult(target="example.com", test_type=tt,
                                status=st, error=error)

    def test_throttled_on_tls_version_mix(self):
        # TLS 1.2 работает, TLS 1.3 обрывается → троттлинг, не полный DPI.
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_12", "SUCCESS"),
            self._r("TLS_13", "FAILED", "TLS_RESET"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.THROTTLED)

    def test_all_tls_fail_is_not_throttled(self):
        # Если ВСЕ версии падают — это TLS_DPI, а не троттлинг.
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_12", "FAILED", "TLS_RESET"),
            self._r("TLS_13", "FAILED", "TLS_RESET"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.TLS_DPI)

    def test_throttled_on_slow_throughput(self):
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_13", "SUCCESS"),
            self._r("HTTP", "FAILED", "THROTTLE_SLOW"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.THROTTLED)

    def test_clienthello_dpi(self):
        # Обычный TLS ок, большой/PQ ClientHello рвётся → size-based DPI.
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_13", "SUCCESS"),
            self._r("TLS_BIGHELLO", "FAILED", "TLS_EOF_EARLY"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.CLIENTHELLO_DPI)

    def test_quic_block_while_https_works(self):
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_13", "SUCCESS"),
            self._r("QUIC", "TIMEOUT", "TIMEOUT"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertEqual(c, DPIClassification.QUIC_BLOCK)

    def test_quic_fail_without_https_not_quic_block(self):
        # QUIC падает, но и TLS падает → это не специфичный QUIC-блок.
        from core.models import DPIClassification
        tr = self._target(
            self._r("TLS_13", "FAILED", "TLS_RESET"),
            self._r("QUIC", "TIMEOUT", "TIMEOUT"),
        )
        c, _ = dpi_classifier.DPIClassifier.classify(tr)
        self.assertNotEqual(c, DPIClassification.QUIC_BLOCK)

    def test_remediation_for_new_types(self):
        from core.models import remediation_for
        self.assertEqual(remediation_for("throttled"), "zapret")
        self.assertEqual(remediation_for("quic_block"), "zapret")
        self.assertEqual(remediation_for("clienthello_dpi"), "zapret")


# ─────── QUIC probe builder ───────

class TestQuicProbe(unittest.TestCase):

    def test_packet_is_long_header_and_padded(self):
        from core.testers import quic_tester
        pkt, dcid, scid = quic_tester.build_quic_vn_probe()
        self.assertGreaterEqual(len(pkt), 1200)         # anti-amplification
        self.assertTrue(pkt[0] & 0x80)                  # long header form
        self.assertTrue(pkt[0] & 0x40)                  # fixed bit
        self.assertEqual(len(dcid), 8)
        self.assertEqual(len(scid), 8)

    def test_version_is_force_vn(self):
        import struct
        from core.testers import quic_tester
        pkt, _, _ = quic_tester.build_quic_vn_probe()
        version = struct.unpack(">I", pkt[1:5])[0]
        # «greasing»-версия (?a?a?a?a) форсирует Version Negotiation.
        self.assertEqual(version & 0x0F0F0F0F, 0x0A0A0A0A)

    def test_response_detection(self):
        import struct
        from core.testers import quic_tester
        # Version Negotiation: version == 0.
        vn = b"\xc0" + struct.pack(">I", 0) + b"\x00" * 8
        self.assertTrue(quic_tester._looks_like_quic_response(vn, b"", b""))
        self.assertFalse(quic_tester._looks_like_quic_response(b"\x00\x01", b"", b""))


# ─────── Большой / PQ ClientHello ───────

class TestClientHelloBuilder(unittest.TestCase):

    def test_record_and_handshake_lengths(self):
        import struct
        from core.testers import tls_tester
        ch = tls_tester.build_client_hello("youtube.com", with_pq=True)
        self.assertEqual(ch[0], 0x16)                   # handshake record
        rec_len = struct.unpack(">H", ch[3:5])[0]
        self.assertEqual(rec_len, len(ch) - 5)
        self.assertEqual(ch[5], 0x01)                   # client_hello
        hs_len = struct.unpack(">I", b"\x00" + ch[6:9])[0]
        self.assertEqual(hs_len, len(ch) - 9)

    def test_pq_group_present_and_big(self):
        from core.testers import tls_tester
        ch = tls_tester.build_client_hello("youtube.com", with_pq=True)
        # X25519MLKEM768 codepoint 0x11ec должен присутствовать.
        self.assertIn(b"\x11\xec", ch)
        # PQ key_share (1216 B) делает ClientHello > одного сегмента.
        self.assertGreater(len(ch), 1460)

    def test_sni_present(self):
        from core.testers import tls_tester
        ch = tls_tester.build_client_hello("example.com", with_pq=False)
        self.assertIn(b"example.com", ch)

    def test_pad_to_reached(self):
        from core.testers import tls_tester
        ch = tls_tester.build_client_hello("a.com", with_pq=False, pad_to=1700)
        self.assertEqual(len(ch), 1700)


# ─────── CDN shard regex / proxy parse ───────

class TestCdnAndProxy(unittest.TestCase):

    def test_shard_regex(self):
        from core.testers.youtube_cdn import _SHARD_RE
        body = (
            "redirector => rr5---sn-c0q7lnz7.googlevideo.com, "
            "r2---sn-jvhnu5g-c35k.googlevideo.com\n"
            "noise example.com not-a-shard.com"
        )
        hosts = [m.group(1) for m in _SHARD_RE.finditer(body)]
        self.assertIn("rr5---sn-c0q7lnz7.googlevideo.com", hosts)
        self.assertIn("r2---sn-jvhnu5g-c35k.googlevideo.com", hosts)
        self.assertEqual(len(hosts), 2)

    def test_proxy_parse_socks5(self):
        from core.testers.proxy import parse_proxy, proxy_label
        p = parse_proxy({"type": "socks5h", "host": "h", "port": "1080",
                         "user": "u", "pass": "p"})
        self.assertEqual(p["type"], "socks5")
        self.assertEqual(p["port"], 1080)
        self.assertIn("socks5://", proxy_label(p))

    def test_proxy_parse_http_and_invalid(self):
        from core.testers.proxy import parse_proxy
        self.assertEqual(parse_proxy({"type": "http", "host": "h",
                                      "port": 8080})["type"], "http")
        self.assertIsNone(parse_proxy({"type": "ftp", "host": "h", "port": 1}))
        self.assertIsNone(parse_proxy({"host": "", "port": 1}))
        self.assertIsNone(parse_proxy(None))


# ─────── Traceroute parser ───────

class TestTracerouteParser(unittest.TestCase):

    def test_parse_hops(self):
        from core.diagnostics import _parse_traceroute
        out = (
            " 1  192.168.1.1  1.234 ms\n"
            " 2  * \n"
            " 3  10.0.0.1  5.6 ms !X\n"
        )
        hops = _parse_traceroute(out)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0]["ip"], "192.168.1.1")
        self.assertAlmostEqual(hops[0]["rtt_ms"], 1.234)
        self.assertTrue(hops[1]["timeout"])
        self.assertIsNone(hops[1]["ip"])
        self.assertEqual(hops[2]["annotation"], "!X")


if __name__ == "__main__":
    unittest.main()
