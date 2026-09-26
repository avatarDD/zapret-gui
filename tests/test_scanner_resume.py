# tests/test_scanner_resume.py
"""
Resume подбора — только для того же прогона.

Позиция resume — это индекс в отсортированном списке стратегий, а список
задают цель, протокол, режим и тип DPI. Раньше сохранённый индекс
отдавался любому следующему прогону: отменили youtube/tcp/standard на
50-й стратегии, запустили discord/udp/quick «с продолжением» — и первые
50 стратегий нового списка молча пропускались.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from core.strategy_scanner import StrategyScanner


class TestResumeMatchesRun(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="scan-resume-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "resume.json")
        self.scanner = StrategyScanner()
        patcher = mock.patch.object(StrategyScanner, "_resume_file_path",
                                    return_value=self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _save(self, target="youtube.com", protocol="tcp", mode="standard",
              dpi_type="", next_index=50):
        self.scanner._target = target
        self.scanner._protocol = protocol
        self.scanner._mode = mode
        self.scanner._dpi_type = dpi_type
        self.scanner._save_resume_state(next_index)

    def test_same_run_resumes(self):
        self._save()
        self.assertEqual(self.scanner.get_resume_index(
            target="youtube.com", protocol="tcp", mode="standard",
            dpi_type=""), 50)

    def test_other_target_starts_from_zero(self):
        self._save()
        self.assertEqual(self.scanner.get_resume_index(
            target="discord.com", protocol="tcp", mode="standard",
            dpi_type=""), 0)

    def test_other_mode_or_protocol_or_dpi_starts_from_zero(self):
        self._save(dpi_type="tls_dpi")
        for run in ({"protocol": "udp"}, {"mode": "quick"},
                    {"dpi_type": ""}):
            with self.subTest(**run):
                want = {"target": "youtube.com", "protocol": "tcp",
                        "mode": "standard", "dpi_type": "tls_dpi"}
                want.update(run)
                self.assertEqual(self.scanner.get_resume_index(**want), 0)

    def test_dpi_type_is_saved(self):
        self._save(dpi_type="tcp_16_20")
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["dpi_type"], "tcp_16_20")

    def test_file_from_older_version_without_dpi_type(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"target": "youtube.com", "protocol": "tcp",
                       "mode": "quick", "next_index": 7}, f)
        self.assertEqual(self.scanner.get_resume_index(
            target="youtube.com", protocol="tcp", mode="quick",
            dpi_type=""), 7)

    def test_broken_file_is_zero(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("[1, 2")
        self.assertEqual(self.scanner.get_resume_index(target="x"), 0)


class TestStartRejectsBadInputBeforeRunning(unittest.TestCase):
    """Кривой вход — исключение, но не «вечно запущенный» сканер."""

    def test_bad_start_index_leaves_scanner_idle(self):
        scanner = StrategyScanner()
        with self.assertRaises(ValueError):
            scanner.start(target="youtube.com", start_index="abc")
        self.assertEqual(scanner.get_status()["status"], "idle")


class TestApplyGoesThroughControl(unittest.TestCase):
    """Найденная стратегия применяется тем же путём, что кнопка и MCP.

    Раньше сканер сам гасил nfqws2, ставил правила и поднимал движок:
    без общего мьютекса (поверх идущего скана/эксперимента) и без
    пересборки автозапуска — после ребута поднималась прежняя стратегия.
    """

    def _apply(self, control_result):
        from core import nfqws_control
        from core.models import StrategyProbeResult

        scanner = StrategyScanner()
        entry = mock.Mock(section_id="s1", source_file="basic.txt")
        entry.name = "fake"
        cm = mock.Mock()
        cm.get_entry_by_id.return_value = entry
        sm = mock.Mock()
        sm.save_user_strategy.return_value = {"id": "scan_s1",
                                              "name": "[Scan] fake"}
        probe = StrategyProbeResult(strategy_id="s1", strategy_name="fake",
                                    target="youtube.com", success=True,
                                    latency_ms=10.0)
        with mock.patch("core.catalog_loader.get_catalog_manager",
                        return_value=cm), \
                mock.patch("core.strategy_builder.get_strategy_manager",
                           return_value=sm), \
                mock.patch.object(scanner, "_build_strategy_args",
                                  return_value=["--lua-desync=fake"]), \
                mock.patch.object(nfqws_control, "apply_strategy",
                                  return_value=control_result) as apply, \
                mock.patch("core.nfqws_manager.get_nfqws_manager",
                           side_effect=AssertionError("мимо nfqws_control")):
            ok = scanner._apply_probe_result(probe)
        return ok, apply

    def test_uses_nfqws_control(self):
        ok, apply = self._apply({"ok": True})
        self.assertTrue(ok)
        apply.assert_called_once_with("scan_s1", source="scanner")

    def test_busy_engine_is_a_refusal(self):
        ok, _apply = self._apply({"ok": False, "error_code": "busy",
                                  "error": "движок занят: подбор"})
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
