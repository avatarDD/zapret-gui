# tests/test_teardown.py
"""MR-121: Тесты для core/teardown.py — проверка очистки при удалении."""

import unittest
from unittest.mock import patch, MagicMock


class TestTeardown(unittest.TestCase):
    """Тесты функций очистки teardown."""

    @patch("subprocess.run")
    def test_flush_ipset_nftset_removes_awg_routing_table(self, mock_run):
        """_flush_ipset_nftset удаляет nft таблицу awg_routing."""
        from core.teardown import _flush_ipset_nftset
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _flush_ipset_nftset()
        nft_calls = [c for c in mock_run.call_args_list
                     if c[0][0][0] == "nft"]
        self.assertTrue(any("awg_routing" in str(c) for c in nft_calls))

    @patch("subprocess.run")
    def test_flush_ipset_nftset_destroys_awgr_sets(self, mock_run):
        """_flush_ipset_nftset уничтожает ipset множества awgr_*."""
        from core.teardown import _flush_ipset_nftset
        def side_effect(cmd, **kwargs):
            if cmd[0] == "ipset" and cmd[1] == "list":
                return MagicMock(returncode=0, stdout="awgr_youtube\nawgr_discord\nother_set\n", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        mock_run.side_effect = side_effect
        _flush_ipset_nftset()
        destroy_calls = [c for c in mock_run.call_args_list
                         if c[0][0][0] == "ipset" and "destroy" in c[0][0]]
        self.assertEqual(len(destroy_calls), 2)

    @patch("subprocess.run")
    def test_flush_ipset_nftset_removes_iptables_chains(self, mock_run):
        """_flush_ipset_nftset удаляет iptables цепочки AWG_ROUTING_*."""
        from core.teardown import _flush_ipset_nftset
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _flush_ipset_nftset()
        ipt_calls = [c for c in mock_run.call_args_list
                     if c[0][0][0] in ("iptables", "ip6tables")]
        chain_names = [str(c) for c in ipt_calls]
        self.assertTrue(any("AWG_ROUTING_PRE" in c for c in chain_names))

    @patch("subprocess.run")
    def test_flush_ipset_nftset_handles_errors(self, mock_run):
        """_flush_ipset_nftset не падает при ошибках (best-effort)."""
        from core.teardown import _flush_ipset_nftset
        mock_run.side_effect = OSError("not found")
        _flush_ipset_nftset()

    @patch("core.teardown._flush_ipset_nftset")
    @patch("core.teardown._remove_routing_rules")
    @patch("core.teardown._remove_dnsmasq_integration")
    @patch("core.teardown._flush_ndms_backend")
    @patch("core.teardown._flush_dnsmasq_backend")
    @patch("core.teardown._remove_transparent")
    @patch("core.teardown._stop_engines")
    @patch("core.teardown._remove_persistence")
    @patch("core.teardown._remove_firewall")
    @patch("core.teardown._stop_nfqws")
    @patch("core.teardown._disable_autostart")
    @patch("core.teardown._reset_block_detector")
    def test_run_calls_all_cleanup_functions(self, mock_reset, mock_disable,
            mock_stop, mock_firewall, mock_persistence, mock_engines,
            mock_transparent, mock_flush_dns, mock_flush_ndms,
            mock_remove_routing, mock_remove_dnsmasq, mock_flush_ipset):
        """run() вызывает все функции очистки."""
        from core.teardown import run
        result = run()
        self.assertEqual(result, 0)
        mock_disable.assert_called_once()
        mock_stop.assert_called_once()
        mock_firewall.assert_called_once()
        mock_flush_ipset.assert_called_once()

    @patch("subprocess.run")
    def test_flush_ipset_nftset_idempotent(self, mock_run):
        """_flush_ipset_nftset можно вызывать несколько раз без ошибок."""
        from core.teardown import _flush_ipset_nftset
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _flush_ipset_nftset()
        _flush_ipset_nftset()


if __name__ == "__main__":
    unittest.main()
