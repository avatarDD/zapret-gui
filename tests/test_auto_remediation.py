# tests/test_auto_remediation.py
"""Unit-тесты для core/auto_remediation.py."""

import unittest

from core import auto_remediation as ar


class TestRemediationActions(unittest.TestCase):
    """Тесты маппинга DPI-типов на действия."""

    def test_tls_dpi_maps_to_zapret(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("tls_dpi"), "zapret_scan")

    def test_ip_block_maps_to_tunnel(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("ip_block"), "tunnel")

    def test_dns_fake_maps_to_dns(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("dns_fake"), "dns_fix")

    def test_full_block_maps_to_tunnel(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("full_block"), "tunnel")

    def test_none_maps_to_skip(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("none"), "skip")

    def test_all_dpi_types_have_actions(self):
        """Все 13 типов DPI должны иметь action."""
        dpi_types = [
            "none", "dns_fake", "http_inject", "isp_page", "tls_dpi",
            "tls_mitm", "clienthello_dpi", "tcp_reset", "tcp_16_20",
            "stun_block", "quic_block", "throttled", "ip_block",
            "full_block", "timeout_drop", "unknown"
        ]
        for dt in dpi_types:
            self.assertIn(dt, ar.REMEDIATION_ACTIONS,
                          "Missing action for DPI type: %s" % dt)


class TestAutoRemediation(unittest.TestCase):
    """Тесты AutoRemediation."""

    def setUp(self):
        self.remediation = ar.AutoRemediation()

    def test_find_best_tunnel_empty(self):
        """Без конфигов — нет туннелей."""
        result = self.remediation._find_best_tunnel()
        self.assertEqual(result, "")

    def test_get_results_empty(self):
        results = self.remediation.get_results()
        self.assertEqual(results, [])

    @unittest.mock.patch("core.config_manager.get_config_manager")
    def test_get_remediation_actions_custom(self, mock_get_cfg):
        mock_cfg = unittest.mock.MagicMock()
        mock_cfg.get.return_value = {"tls_dpi": "custom_tunnel_action"}
        mock_get_cfg.return_value = mock_cfg

        actions = ar._get_remediation_actions()
        self.assertEqual(actions.get("tls_dpi"), "custom_tunnel_action")
        # Другие действия должны быть из дефолтного маппинга
        self.assertEqual(actions.get("ip_block"), "tunnel")

    @unittest.mock.patch("core.hosts_manager.get_hosts_manager")
    @unittest.mock.patch("urllib.request.urlopen")
    def test_apply_dns_fix_success(self, mock_urlopen, mock_get_hm):
        # Мокаем DoH ответ
        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = b'{"Answer": [{"type": 1, "data": "93.184.216.34"}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Мокаем hosts_manager
        mock_hm = unittest.mock.MagicMock()
        mock_hm.add_entry.return_value = True
        mock_get_hm.return_value = mock_hm

        success, msg = self.remediation._apply_dns_fix("example.com")
        self.assertTrue(success)
        self.assertIn("Добавлен в hosts", msg)
        mock_hm.add_entry.assert_called_once_with("93.184.216.34", "example.com")

    @unittest.mock.patch("core.hosts_manager.get_hosts_manager")
    @unittest.mock.patch("urllib.request.urlopen")
    def test_apply_dns_fix_not_found(self, mock_urlopen, mock_get_hm):
        # Мокаем DoH ответ без Answer
        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = b'{"Answer": []}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        success, msg = self.remediation._apply_dns_fix("example.com")
        self.assertFalse(success)
        self.assertIn("DNS IP не найден", msg)

    @unittest.mock.patch("core.strategy_scanner.get_strategy_scanner")
    def test_apply_zapret_success(self, mock_get_scanner):
        mock_scanner = unittest.mock.MagicMock()
        mock_scanner.start.return_value = True
        mock_get_scanner.return_value = mock_scanner

        success, msg = self.remediation._apply_zapret("example.com", "tls_dpi")
        self.assertTrue(success)
        self.assertIn("Strategy scan запущен", msg)
        mock_scanner.start.assert_called_once()

    @unittest.mock.patch("core.strategy_scanner.get_strategy_scanner")
    def test_apply_zapret_busy(self, mock_get_scanner):
        mock_scanner = unittest.mock.MagicMock()
        mock_scanner.start.return_value = False
        mock_get_scanner.return_value = mock_scanner

        success, msg = self.remediation._apply_zapret("example.com", "tls_dpi")
        self.assertFalse(success)
        self.assertIn("Не удалось запустить сканирование", msg)

    @unittest.mock.patch("core.auto_remediation.AutoRemediation._find_best_tunnel")
    @unittest.mock.patch("core.unified.storage.add_route")
    @unittest.mock.patch("core.unified.applier.apply_route")
    @unittest.mock.patch("core.block_detector.get_block_detector")
    def test_apply_tunnel_success(self, mock_get_bd, mock_apply_route, mock_add_route, mock_find_best):
        mock_find_best.return_value = "warp:wg0"
        mock_apply_route.return_value = {"ok": True}

        mock_bd = unittest.mock.MagicMock()
        mock_bd._probe.return_value = "ok"
        mock_get_bd.return_value = mock_bd

        success, msg = self.remediation._apply_tunnel("example.com")
        self.assertTrue(success)
        self.assertIn("Route создан и проверен", msg)
        mock_add_route.assert_called_once()
        mock_bd._probe.assert_called_once_with("example.com")

    @unittest.mock.patch("core.auto_remediation.AutoRemediation._find_best_tunnel")
    @unittest.mock.patch("core.unified.storage.add_route")
    @unittest.mock.patch("core.unified.applier.apply_route")
    @unittest.mock.patch("core.block_detector.get_block_detector")
    def test_apply_tunnel_fail(self, mock_get_bd, mock_apply_route, mock_add_route, mock_find_best):
        mock_find_best.return_value = "warp:wg0"
        mock_apply_route.return_value = {"ok": True}

        mock_bd = unittest.mock.MagicMock()
        mock_bd._probe.return_value = "timeout_drop"
        mock_get_bd.return_value = mock_bd

        success, msg = self.remediation._apply_tunnel("example.com")
        self.assertFalse(success)
        self.assertIn("проверка туннеля не удалась", msg)
        self.assertIn("timeout_drop", msg)


if __name__ == "__main__":
    unittest.main()
