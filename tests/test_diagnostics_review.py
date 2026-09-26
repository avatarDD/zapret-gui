# tests/test_diagnostics_review.py
"""
Сторожа к ревью кода диагностики (backend).

  - тест «TCP 16-20 КБ» не видел обрыв посреди тела (число байт терялось
    в исключении) — самый частый блок ТСПУ уходил в «ошибку теста»;
  - blockcheck не выносил в итог блок 16-20 КБ и закрытый STUN;
  - QUIC-фаза blockcheck пробовала пакетом без SNI и пропускала блок
    QUIC по имени сайта;
  - «Network unreachable» по IPv6 перекрывал RST от DPI по IPv4 и
    превращал «поможет обход» в «нужен туннель»;
  - «Access denied» Cloudflare/Akamai считался заглушкой провайдера;
  - проверка предпосылок пробовала iptables на системах с nftables;
  - healthcheck: два демона после reload(), плановый и ручной прогоны
    одновременно.
"""

import errno
import socket
import threading
import unittest
from unittest import mock

from core import models
from core.models import BlockcheckReport, SingleTestResult, TargetResult

# Короткие имена: под именами Test* pytest пытался бы собрать Enum'ы
# как классы тестов.
ST = models.TestStatus
TT = models.TestType


class TestTcp1620MidBody(unittest.TestCase):

    def _run(self, exc, got):
        from core.testers import tcp_test

        def fake_get(url, timeout, max_bytes=25_000, progress=None):
            progress["bytes"] = got
            raise exc

        with mock.patch.object(tcp_test, "_stream_get", side_effect=fake_get):
            return tcp_test.check_tcp_16_20_single("https://x/file")

    def test_reset_in_window_is_block(self):
        r = self._run(ConnectionResetError(errno.ECONNRESET, "reset"), 17_000)
        self.assertEqual(r.error, "TCP_16_20")
        self.assertEqual(r.status, ST.FAILED.value)

    def test_stall_in_window_is_block(self):
        r = self._run(socket.timeout("timed out"), 18_432)
        self.assertEqual(r.error, "TCP_16_20")

    def test_error_before_body_is_not_block(self):
        r = self._run(ConnectionResetError(errno.ECONNRESET, "reset"), 0)
        self.assertEqual(r.error, "TCP_ERR")


class TestBlockcheckServiceTargets(unittest.TestCase):

    def _report(self, tcp_error="TCP_16_20", stun_status=ST.TIMEOUT.value):
        r = BlockcheckReport(mode="full", started_at=0)
        yt = TargetResult(domain="youtube.com")
        yt.results = [SingleTestResult(target="youtube.com",
                                       test_type=TT.TLS_13.value,
                                       status=ST.SUCCESS.value)]
        tcp = TargetResult(domain="TCP 16-20KB")
        tcp.results = [SingleTestResult(
            target="https://x", test_type=TT.TCP_16_20.value,
            status=(ST.FAILED.value if tcp_error
                    else ST.SUCCESS.value),
            error=tcp_error)]
        r.targets = [yt, tcp]
        for name in ("Google STUN", "Cloudflare STUN"):
            st = TargetResult(domain=name)
            st.results = [SingleTestResult(target=name,
                                           test_type=TT.STUN.value,
                                           status=stun_status,
                                           error="TIMEOUT")]
            r.targets.append(st)
        return r

    def test_tcp_block_reaches_verdict(self):
        from core.blockcheck import BlockcheckRunner
        r = self._report(stun_status=ST.SUCCESS.value)
        b = BlockcheckRunner()
        b._run_classification(r)
        self.assertEqual(b._aggregate_dpi(r), "tcp_16_20")

    def test_stun_block_needs_all_servers_silent(self):
        from core.blockcheck import BlockcheckRunner
        b = BlockcheckRunner()
        r = self._report(tcp_error="")
        b._run_classification(r)
        self.assertEqual(b._aggregate_dpi(r), "stun_block")
        # Один сервер жив — это не блокировка UDP.
        r = self._report(tcp_error="")
        r.targets[-1].results[0].status = ST.SUCCESS.value
        b._run_classification(r)
        self.assertEqual(b._aggregate_dpi(r), "none")


class TestQuicDpiProbe(unittest.TestCase):

    def _res(self, status, error=""):
        return SingleTestResult(target="h:443/udp", test_type=TT.QUIC.value,
                                status=status, error=error)

    def test_sni_block_detected(self):
        from core.testers import quic_tester as q
        with mock.patch.object(q, "test_quic_handshake",
                               return_value=self._res(ST.TIMEOUT.value,
                                                      "QUIC_TIMEOUT")), \
             mock.patch.object(q, "test_quic",
                               return_value=self._res(ST.SUCCESS.value)):
            r = q.test_quic_dpi("youtube.com")
        self.assertEqual(r.error, "QUIC_SNI_BLOCK")
        self.assertEqual(r.status, ST.TIMEOUT.value)

    def test_handshake_ok_skips_control(self):
        from core.testers import quic_tester as q
        with mock.patch.object(q, "test_quic_handshake",
                               return_value=self._res(ST.SUCCESS.value)), \
             mock.patch.object(q, "test_quic") as vn:
            r = q.test_quic_dpi("youtube.com")
        vn.assert_not_called()
        self.assertEqual(r.status, ST.SUCCESS.value)

    def test_blockcheck_uses_sni_probe(self):
        import inspect
        from core import blockcheck
        src = inspect.getsource(blockcheck.BlockcheckRunner._run_quic_phase)
        self.assertIn("test_quic_dpi", src)


class TestNoRouteDoesNotHideDpi(unittest.TestCase):

    def test_pick_error(self):
        from core.testers.tls_tester import pick_error
        rst = ConnectionResetError(errno.ECONNRESET, "reset")
        unreach = OSError(errno.ENETUNREACH, "Network is unreachable")
        self.assertIs(pick_error(rst, unreach), rst)
        self.assertIs(pick_error(unreach, rst), rst)
        self.assertIs(pick_error(None, unreach), unreach)

    def test_probe_keeps_connect_error_of_reachable_family(self):
        from core.testers import probe
        refused = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        unreach = OSError(errno.ENETUNREACH, "Network is unreachable")
        with mock.patch.object(probe, "_resolve",
                               return_value=["1.2.3.4", "2001:db8::1"]), \
             mock.patch("socket.create_connection",
                        side_effect=[refused, unreach]):
            res = probe.probe_domain("x.example", timeout=1)
        self.assertEqual(res.code, "tcp_refused")


class TestIspMarkers(unittest.TestCase):

    def test_cdn_access_denied_is_not_isp(self):
        from core.testers.isp_detector import find_isp_marker
        akamai = ("<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>"
                  "You don't have permission. Reference #18.abc "
                  "https://errors.edgesuite.net/18.abc</BODY></HTML>")
        cf = ("<title>Attention Required! | Cloudflare</title>Sorry, you "
              "have been blocked. Cloudflare Ray ID: 8a1b")
        self.assertEqual(find_isp_marker(akamai), "")
        self.assertEqual(find_isp_marker(cf), "")

    def test_isp_stub_detected(self):
        from core.testers.isp_detector import find_isp_marker
        self.assertNotEqual(find_isp_marker(
            "<html>Доступ к ресурсу ограничен. Сайт заблокирован</html>"), "")
        self.assertNotEqual(find_isp_marker(
            "<html>" + "x" * 20_000 + " eais.rkn.gov.ru</html>"), "")

    def test_weak_marker_on_big_page_ignored(self):
        from core.testers.isp_detector import find_isp_marker
        page = "<html>" + "новости " * 2000 + "аккаунт заблокирован</html>"
        self.assertEqual(find_isp_marker(page), "")


class TestPrerequisitesNft(unittest.TestCase):

    def test_iptables_not_probed_on_nftables(self):
        from core import diagnostics
        fw = mock.MagicMock()
        fw.detect_fw_type.return_value = "nftables"
        with mock.patch("core.firewall.get_firewall_manager", return_value=fw), \
             mock.patch.object(diagnostics, "_find_binary",
                               return_value="/usr/sbin/iptables"), \
             mock.patch("core.firewall.FirewallManager._ipt_probe_rule") as probe:
            res = diagnostics.check_strategy_prerequisites()
        probe.assert_not_called()
        self.assertNotIn("iptables_caps", res["checks"])
        self.assertFalse(any(i["id"] == "ipt_nfqueue_target_missing"
                             for i in res["issues"]))


class TestHealthcheckThreads(unittest.TestCase):

    def test_restart_gets_new_stop_event(self):
        from core.healthcheck import HealthcheckDaemon
        d = HealthcheckDaemon()
        cfg = mock.MagicMock()
        cfg.get.return_value = True
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg), \
             mock.patch.object(HealthcheckDaemon, "_loop",
                               side_effect=lambda evt: evt.wait(5)):
            d.start()
            first = d._stop_evt
            d.stop()
            d.start()
            self.assertIsNot(first, d._stop_evt)
            self.assertTrue(first.is_set())
            self.assertFalse(d._stop_evt.is_set())
            d.stop()

    def test_scheduled_tick_skips_while_manual_runs(self):
        from core.healthcheck import HealthcheckDaemon
        d = HealthcheckDaemon()
        d._checking = True
        with mock.patch.object(d, "_tick") as tick:
            self.assertIsNone(d._tick_exclusive())
        tick.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class TestMcpDiskFull(unittest.TestCase):

    def test_disk_full_finding_uses_real_keys(self):
        # _get_disk_usage отдаёт used_percent/path — раньше MCP читал
        # несуществующие percent/mount, и находка не срабатывала никогда.
        from core.mcp.tools import diagnostics as d
        disk = {"label": "/opt", "path": "/opt", "total_mb": 100,
                "free_mb": 4, "used_percent": 96}
        self.assertTrue(d._disk_is_full(disk))
        self.assertFalse(d._disk_is_full(dict(disk, used_percent=40)))
