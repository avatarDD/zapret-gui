# tests/test_probe.py
"""
Unit-тесты общей пробы core/testers/probe.py и её потребителей.

Проба — единственное место, где домен превращается в вердикт: её словарь
кодов и таксономия DPIClassification общие для «Теста доступности» и
«Мониторинга DNS», поэтому здесь же проверяется, что оба потребителя видят
одинаковые названия и одинаковый remediation.

Сеть мокаем: socket.getaddrinfo / socket.create_connection / ssl.
"""

import socket
import ssl
import unittest
from unittest import mock

from core.models import DPIClassification, remediation_for
from core.testers import probe
from core.testers.config import (
    KNOWN_BLOCK_IPS,
    TCP_BLOCK_RANGE_MIN,
)


# ─────── словарь кодов ───────

class TestCodeTables(unittest.TestCase):
    """Подписи и таксономия описаны для одних и тех же кодов."""

    def test_tables_cover_same_codes(self):
        self.assertEqual(set(probe.PROBE_CODES), set(probe.DPI_BY_PROBE_CODE))

    def test_dpi_values_are_valid_classifications(self):
        valid = {c.value for c in DPIClassification}
        for code, dpi in probe.DPI_BY_PROBE_CODE.items():
            self.assertIn(dpi, valid, f"код {code} ссылается на несуществующий DPI")

    def test_remediation_resolves_for_every_code(self):
        allowed = {"zapret", "tunnel", "dns", "none", "unknown"}
        for code in probe.PROBE_CODES:
            self.assertIn(remediation_for(probe.dpi_for_code(code)), allowed)

    def test_ip_block_asks_for_tunnel_not_zapret(self):
        # TCP не устанавливается → обход DPI бесполезен, нужен туннель.
        self.assertEqual(remediation_for(probe.dpi_for_code("tcp_refused")), "tunnel")
        # Таймаут неоднозначен (silent-drop DPI выглядит так же) → zapret.
        self.assertEqual(remediation_for(probe.dpi_for_code("tcp_timeout")), "zapret")

    def test_unclassified_tls_error_is_not_actionable(self):
        # Просроченный серт/отказ по SNI не должны уезжать в авто-списки.
        self.assertEqual(remediation_for(probe.dpi_for_code("tls_garbage")), "unknown")

    def test_describe_code_falls_back(self):
        self.assertEqual(probe.describe_code("нет-такого"),
                         probe.PROBE_CODES["unknown"])


# ─────── признаки DNS-подмены ───────

class TestHijackHeuristics(unittest.TestCase):

    def test_known_block_ip(self):
        ip = sorted(KNOWN_BLOCK_IPS)[0]
        flag, reason = probe.looks_hijacked([ip])
        self.assertTrue(flag)
        self.assertIn(ip, reason)

    def test_all_loopback_is_stub(self):
        flag, _ = probe.looks_hijacked(["127.0.0.1"])
        self.assertTrue(flag)

    def test_public_ip_is_clean(self):
        flag, _ = probe.looks_hijacked(["142.250.185.78"])
        self.assertFalse(flag)

    def test_lan_ip_is_not_flagged(self):
        # split-horizon DNS (nas.lan) — не блокировка; иначе монитор
        # завалил бы список внутренними именами.
        flag, _ = probe.looks_hijacked(["192.168.1.10"])
        self.assertFalse(flag)

    def test_empty_is_clean(self):
        self.assertEqual(probe.looks_hijacked([]), (False, ""))

    def test_has_non_public_ip(self):
        self.assertTrue(probe.has_non_public_ip(["10.0.0.1"]))
        self.assertFalse(probe.has_non_public_ip(["8.8.8.8"]))
        self.assertFalse(probe.has_non_public_ip(["не-ip"]))

    def test_known_block_ip_returns_match(self):
        self.assertEqual(probe.known_block_ip(["8.8.8.8", "0.0.0.0"]), "0.0.0.0")
        self.assertEqual(probe.known_block_ip(["8.8.8.8"]), "")


# ─────── стадии пробы ───────

def _fake_tls(response: bytes = b"", error: Exception | None = None):
    """TLS-сокет-заглушка: отдаёт response порциями, затем error или EOF."""
    sock = mock.MagicMock()
    chunks = [response[i:i + 8192] for i in range(0, len(response), 8192)]
    seq: list = list(chunks)

    def _recv(_n):
        if seq:
            return seq.pop(0)
        if error is not None:
            raise error
        return b""

    sock.recv.side_effect = _recv
    sock.version.return_value = "TLSv1.3"
    return sock


class TestProbeStages(unittest.TestCase):
    """Каждая стадия даёт свой код и свой способ обхода."""

    def _run(self, response=b"", error=None, addrs=("93.184.216.34",)):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
                 for ip in addrs]
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = _fake_tls(response, error)
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               return_value=mock.MagicMock()), \
             mock.patch.object(ssl, "create_default_context", return_value=ctx):
            return probe.probe_domain("example.com", timeout=1)

    def test_dns_failure(self):
        with mock.patch.object(socket, "getaddrinfo",
                               side_effect=socket.gaierror("nope")):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "dns_block")
        self.assertEqual(res.remediation, "dns")
        self.assertFalse(res.ok)

    def test_dns_hijack_short_circuits_before_connect(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection") as conn:
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "dns_hijack")
        self.assertEqual(res.remediation, "dns")
        # До TCP дело не дошло — заодно это защита от сканирования локалки.
        conn.assert_not_called()

    def test_tcp_refused_means_ip_block(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               side_effect=ConnectionRefusedError(111, "refused")):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "tcp_refused")
        self.assertEqual(res.dpi, DPIClassification.IP_BLOCK.value)
        self.assertEqual(res.remediation, "tunnel")

    def test_tcp_timeout_is_not_ip_block(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               side_effect=socket.timeout("timed out")):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "tcp_timeout")
        self.assertEqual(res.remediation, "zapret")

    def test_second_address_tried_after_failure(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 443))]
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = _fake_tls(b"HTTP/1.1 200 OK\r\n\r\nhi")
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               side_effect=[socket.timeout("timed out"),
                                            mock.MagicMock()]), \
             mock.patch.object(ssl, "create_default_context", return_value=ctx):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "ok")
        self.assertEqual(res.connected_ip, "5.6.7.8")

    def test_tls_reset_is_dpi(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        ctx = mock.MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLError("connection reset by peer")
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               return_value=mock.MagicMock()), \
             mock.patch.object(ssl, "create_default_context", return_value=ctx):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "tls_rst")
        self.assertEqual(res.dpi, DPIClassification.TLS_DPI.value)
        self.assertEqual(res.remediation, "zapret")

    def test_tls_mitm_detected(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        ctx = mock.MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLError(
            "certificate verify failed: self signed certificate")
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               return_value=mock.MagicMock()), \
             mock.patch.object(ssl, "create_default_context", return_value=ctx):
            res = probe.probe_domain("example.com", timeout=1)
        self.assertEqual(res.code, "tls_mitm")
        self.assertEqual(res.dpi, DPIClassification.TLS_MITM.value)

    def test_cert_verification_enabled_by_default(self):
        # Без проверки сертификата MITM неотличим от рабочего соединения.
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = _fake_tls(b"HTTP/1.1 200 OK\r\n\r\nhi")
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(socket, "create_connection",
                               return_value=mock.MagicMock()), \
             mock.patch.object(ssl, "create_default_context", return_value=ctx):
            probe.probe_domain("example.com", timeout=1)
        self.assertNotEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_ok_response(self):
        res = self._run(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<html>")
        self.assertEqual(res.code, "ok")
        self.assertTrue(res.ok)
        self.assertEqual(res.remediation, "none")
        self.assertIn("200", res.detail)

    def test_non_2xx_is_still_reachable(self):
        # 403/451 — политика сервера, а не блокировка провайдером: раньше
        # такой ответ помечался как http_cutoff и тянул домен в списки.
        res = self._run(b"HTTP/1.1 403 Forbidden\r\n\r\nno")
        self.assertEqual(res.code, "ok")

    def test_isp_block_page(self):
        body = (b"HTTP/1.1 200 OK\r\n\r\n"
                b"<html>doc blocked by eais.rkn.gov.ru registry</html>")
        res = self._run(body)
        self.assertEqual(res.code, "isp_page")
        self.assertEqual(res.dpi, DPIClassification.ISP_PAGE.value)
        self.assertEqual(res.remediation, "zapret")

    def test_reset_in_16_20kb_window(self):
        body = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * (TCP_BLOCK_RANGE_MIN + 500)
        res = self._run(body, error=ConnectionResetError("connection reset"))
        self.assertEqual(res.code, "tcp_16_20")
        self.assertEqual(res.dpi, DPIClassification.TCP_16_20.value)

    def test_reset_right_after_handshake(self):
        res = self._run(b"", error=ConnectionResetError("connection reset"))
        self.assertEqual(res.code, "http_cutoff")
        self.assertEqual(res.remediation, "zapret")

    def test_read_timeout(self):
        res = self._run(b"HTTP/1.1 200 OK\r\n\r\nxx",
                        error=socket.timeout("timed out"))
        self.assertEqual(res.code, "http_timeout")

    def test_empty_response(self):
        res = self._run(b"")
        self.assertEqual(res.code, "http_cutoff")

    def test_empty_domain(self):
        res = probe.probe_domain("  ", timeout=1)
        self.assertEqual(res.code, "unknown")

    def test_to_dict_keeps_legacy_field(self):
        res = self._run(b"HTTP/1.1 200 OK\r\n\r\nhi")
        d = res.to_dict()
        # block_code — историческое имя, на нём завязан фронтенд.
        self.assertEqual(d["block_code"], d["code"])
        for key in ("domain", "block_desc", "dpi", "remediation", "detail"):
            self.assertIn(key, d)


# ─────── потребитель: block_detector ───────

class TestDetectorUsesSharedProbe(unittest.TestCase):

    def setUp(self):
        from core.block_detector import BlockDetector
        self.det = BlockDetector()

    def test_block_codes_alias_shared_table(self):
        from core import block_detector
        self.assertIs(block_detector.BLOCK_CODES, probe.PROBE_CODES)

    def test_probe_returns_plain_code(self):
        # Строковый контракт нужен core/auto_remediation.py.
        with mock.patch("core.block_detector.probe_domain",
                        return_value=probe.ProbeResult(
                            domain="x.com", code="tls_rst")) as p:
            self.assertEqual(self.det._probe("x.com", 3), "tls_rst")
        p.assert_called_once_with("x.com", timeout=3)

    def test_probe_failure_is_contained(self):
        with mock.patch("core.block_detector.probe_domain",
                        side_effect=RuntimeError("boom")):
            self.assertEqual(self.det._probe("x.com"), "unknown")

    def test_record_stores_verdict(self):
        self.det._record("x.com", probe.ProbeResult(domain="x.com",
                                                    code="tls_rst",
                                                    detail="RST"))
        row = self.det.get_results()[0]
        self.assertEqual(row["domain"], "x.com")
        self.assertEqual(row["block_code"], "tls_rst")
        self.assertEqual(row["dpi"], DPIClassification.TLS_DPI.value)
        self.assertEqual(row["remediation"], "zapret")
        self.assertEqual(row["block_desc"], probe.PROBE_CODES["tls_rst"])

    def test_status_counts_actionable_separately(self):
        self.det._record("a.com", probe.ProbeResult(domain="a.com", code="tls_rst"))
        self.det._record("b.com", probe.ProbeResult(domain="b.com", code="tls_garbage"))
        self.det._record("c.com", probe.ProbeResult(domain="c.com", code="ok"))
        st = self.det.get_status()
        self.assertEqual(st["monitored_count"], 3)
        self.assertEqual(st["blocked_count"], 2)
        self.assertEqual(st["actionable_count"], 1)

    def test_auto_add_skips_non_actionable(self):
        from core import named_lists

        cfg = mock.MagicMock()
        cfg.get.side_effect = lambda *a, **kw: (
            True if a[1] == "auto_add_enabled" else "my-list")
        with mock.patch("core.config_manager.get_config_manager", return_value=cfg), \
             mock.patch.object(named_lists, "get", return_value={"domains": []}), \
             mock.patch.object(named_lists, "update_fields") as upd:
            # Способ обхода неясен — в список не добавляем.
            self.det._maybe_auto_add(
                "x.com", probe.ProbeResult(domain="x.com", code="tls_garbage"))
            upd.assert_not_called()

            self.det._maybe_auto_add(
                "y.com", probe.ProbeResult(domain="y.com", code="tls_rst"))
            upd.assert_called_once_with("my-list", {"domains": ["y.com"]})

    def test_rate_limit_has_its_own_code(self):
        # Раньше служебный отказ выдавался кодом throttled и выглядел как
        # вердикт «провайдер режет скорость».
        with mock.patch.object(self.det, "_is_rate_limited", return_value=True):
            out = self.det.probe_now("x.com", client_ip="10.0.0.5")
        self.assertEqual(out["block_code"], "rate_limited")
        self.assertNotEqual(out["block_code"], "throttled")

    def test_manual_probe_is_recorded(self):
        with mock.patch.object(self.det, "_probe_full",
                               return_value=probe.ProbeResult(domain="x.com",
                                                              code="ok")):
            self.det.probe_now("x.com")
        self.assertEqual([r["domain"] for r in self.det.get_results()], ["x.com"])

    def test_trim_keeps_newest(self):
        for i in range(2100):
            self.det._monitored["d%d.com" % i] = {
                "first_seen": i, "last_checked": 0, "block_code": "unknown",
                "dpi": "unknown", "remediation": "unknown", "detail": "",
            }
        with self.det._lock:
            self.det._trim_locked()
        self.assertEqual(len(self.det._monitored), 2000)
        self.assertNotIn("d0.com", self.det._monitored)
        self.assertIn("d2099.com", self.det._monitored)


# ─────── потребитель: blockcheck ───────

class TestBlockcheckUsesSharedHeuristics(unittest.TestCase):

    def test_dns_phase_imports_shared_helpers(self):
        # Дублирующая копия _has_non_public_ip внутри blockcheck удалена.
        import inspect
        from core import blockcheck
        src = inspect.getsource(blockcheck.BlockcheckRunner._run_dns_phase)
        self.assertIn("from core.testers.probe import", src)
        self.assertNotIn("def _has_non_public_ip", src)


if __name__ == "__main__":
    unittest.main()
