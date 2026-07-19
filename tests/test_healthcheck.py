# tests/test_healthcheck.py
"""Демон healthcheck: фоновый watchdog для autocircular state.

Тестируем без реальных curl'ов — мокаем core.diagnostics.check_http
и core.strategy_state.clear_host, чтобы видеть, КАК демон реагирует на
провалы и когда триггерит сброс state.tsv.
"""

import os
import threading
import time
import unittest
from unittest.mock import patch


def _fake_check_http_factory(map_url_to_ok):
    """Возвращает фейковый check_http, который читает map_url_to_ok[url]."""
    def _fake(url, timeout=5):
        ok = bool(map_url_to_ok.get(url, False))
        return {
            "url": url,
            "ok": ok,
            "status_code": 200 if ok else 0,
            "response_time": 50 if ok else None,
            "error": None if ok else "fake-timeout",
            "tls_version": None,
            "redirect_url": None,
        }
    return _fake


class TestHealthcheckTick(unittest.TestCase):

    def setUp(self):
        from core.healthcheck import HealthcheckDaemon
        self.hc = HealthcheckDaemon()
        # Чистим singleton конфига между тестами — берём config_manager и
        # подменяем секцию healthcheck.
        from core.config_manager import get_config_manager
        self.cfg = get_config_manager()
        self._saved_hc = dict(self.cfg._config.get("healthcheck") or {})
        self.cfg._config["healthcheck"] = {
            "enabled": True,
            "interval_min": 5,
            "consecutive_failures": 2,
            "auto_reset": True,
            "services": ["youtube", "discord"],
            "history_size": 50,
        }

    def tearDown(self):
        self.cfg._config["healthcheck"] = self._saved_hc

    def test_tick_records_results_for_each_service(self):
        urls = {
            "https://www.youtube.com": True,
            "https://discord.com": True,
        }
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host") as mock_clear:
                result = self.hc.run_now()
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["ok"], 2)
        self.assertEqual(result["failed"], 0)
        services_in_result = {r["service"] for r in result["results"]}
        self.assertEqual(services_in_result, {"youtube", "discord"})
        # Все OK → reset не вызывался
        mock_clear.assert_not_called()

    def test_consecutive_failures_under_threshold_no_reset(self):
        """Первый провал НЕ должен триггерить сброс при threshold=2."""
        urls = {"https://www.youtube.com": False, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host") as mock_clear:
                self.hc.run_now()
        mock_clear.assert_not_called()
        self.assertEqual(self.hc._fail_streak["youtube"], 1)

    def test_consecutive_failures_at_threshold_triggers_reset(self):
        """Второй провал YouTube (threshold=2) ⇒ clear_host для всех его hosts."""
        urls = {"https://www.youtube.com": False, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host",
                       return_value={"ok": True, "removed": 3}) as mock_clear:
                with patch("core.strategy_state.reload_nfqws",
                           return_value={"ok": True}):
                    self.hc.run_now()  # streak = 1
                    self.hc.run_now()  # streak = 2 → reset
        # YouTube hosts: youtube.com, www.youtube.com, i.ytimg.com (3 шт.)
        self.assertEqual(mock_clear.call_count, 3)
        # После reset streak сбрасывается, чтобы не зацикливать
        self.assertEqual(self.hc._fail_streak["youtube"], 0)

    def test_success_resets_failure_streak(self):
        urls = {"https://www.youtube.com": False, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host",
                       return_value={"ok": True, "removed": 0}):
                self.hc.run_now()
                self.assertEqual(self.hc._fail_streak["youtube"], 1)
        # YouTube снова работает — streak → 0
        urls["https://www.youtube.com"] = True
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            self.hc.run_now()
        self.assertEqual(self.hc._fail_streak["youtube"], 0)

    def test_auto_reset_off_does_not_clear_state(self):
        self.cfg._config["healthcheck"]["auto_reset"] = False
        urls = {"https://www.youtube.com": False, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host") as mock_clear:
                self.hc.run_now()
                self.hc.run_now()  # обычно triggers reset
        mock_clear.assert_not_called()

    def test_unknown_service_in_config_is_skipped(self):
        self.cfg._config["healthcheck"]["services"] = ["youtube", "nonexistent"]
        urls = {"https://www.youtube.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            result = self.hc.run_now()
        # nonexistent тихо пропущен — только 1 результат
        self.assertEqual(result["total"], 1)

    def test_global_outage_skips_reset(self):
        """Если упали ВСЕ сервисы — это общий обвал (нет связи/nfqws),
        сброс state НЕ должен происходить даже при повторных провалах."""
        urls = {"https://www.youtube.com": False, "https://discord.com": False}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host") as mock_clear:
                r1 = self.hc.run_now()  # обвал
                r2 = self.hc.run_now()  # обвал снова — обычно был бы reset
        self.assertTrue(r1["global_outage"])
        self.assertTrue(r2["global_outage"])
        mock_clear.assert_not_called()

    def test_global_outage_holds_streak(self):
        """При обвале streak НЕ растёт (не виним конкретную стратегию)."""
        urls = {"https://www.youtube.com": False, "https://discord.com": False}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            self.hc.run_now()
            self.hc.run_now()
        # streak должен остаться 0 (не накопился), т.к. это обвал
        self.assertEqual(self.hc._fail_streak.get("youtube", 0), 0)

    def test_partial_failure_is_not_global_outage(self):
        """1 из 2 упал — это НЕ обвал, нормальная логика сброса работает."""
        urls = {"https://www.youtube.com": False, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            r = self.hc.run_now()
        self.assertFalse(r["global_outage"])

    def test_control_domain_up_means_not_outage_and_resets(self):
        """Все цели упали, НО контрольный сайт открылся → это DPI, не обвал:
        сброс ВЫПОЛНЯЕТСЯ (кейс юзера: все сайты реально заблокированы)."""
        self.cfg._config["healthcheck"]["control_domain"] = "ya.ru"
        self.cfg._config["healthcheck"]["consecutive_failures"] = 1
        urls = {
            "https://www.youtube.com": False,
            "https://discord.com": False,
            "https://ya.ru": True,   # контрольный — открывается
        }
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host",
                       return_value={"ok": True, "removed": 1}) as mock_clear:
                with patch("core.strategy_state.reload_nfqws",
                           return_value={"ok": True}):
                    r = self.hc.run_now()
        self.assertFalse(r["global_outage"])
        self.assertTrue(r["control_ok"])
        mock_clear.assert_called()   # сброс произошёл

    def test_control_domain_down_means_outage_no_reset(self):
        """Все цели И контрольный упали → реальный обвал, сброс пропущен."""
        self.cfg._config["healthcheck"]["control_domain"] = "ya.ru"
        self.cfg._config["healthcheck"]["consecutive_failures"] = 1
        urls = {
            "https://www.youtube.com": False,
            "https://discord.com": False,
            "https://ya.ru": False,  # связи нет вообще
        }
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host") as mock_clear:
                r = self.hc.run_now()
        self.assertTrue(r["global_outage"])
        self.assertFalse(r["control_ok"])
        mock_clear.assert_not_called()

    def test_outage_guard_off_always_resets(self):
        """outage_guard=False → даже при падении всех целей сброс выполняется."""
        self.cfg._config["healthcheck"]["outage_guard"] = False
        self.cfg._config["healthcheck"]["consecutive_failures"] = 1
        urls = {"https://www.youtube.com": False, "https://discord.com": False}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host",
                       return_value={"ok": True, "removed": 1}) as mock_clear:
                with patch("core.strategy_state.reload_nfqws",
                           return_value={"ok": True}):
                    r = self.hc.run_now()
        self.assertFalse(r["global_outage"])
        mock_clear.assert_called()

    def test_custom_domains_become_targets(self):
        """Кастомные домены добавляются как цели проверки."""
        self.cfg._config["healthcheck"]["services"] = []
        self.cfg._config["healthcheck"]["custom_domains"] = [
            "rutracker.org", "https://example.com/path"]
        urls = {
            "https://rutracker.org": True,
            "https://example.com/path": True,
        }
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            r = self.hc.run_now()
        self.assertEqual(r["total"], 2)
        keys = {x["service"] for x in r["results"]}
        self.assertEqual(keys, {"custom:rutracker.org", "custom:example.com"})

    def test_custom_domain_failure_resets_its_host(self):
        """Провал кастомного домена сбрасывает state именно его хоста."""
        self.cfg._config["healthcheck"]["services"] = []
        self.cfg._config["healthcheck"]["custom_domains"] = ["rutracker.org"]
        self.cfg._config["healthcheck"]["consecutive_failures"] = 1
        self.cfg._config["healthcheck"]["outage_guard"] = False
        urls = {"https://rutracker.org": False}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            with patch("core.strategy_state.clear_host",
                       return_value={"ok": True, "removed": 2}) as mock_clear:
                with patch("core.strategy_state.reload_nfqws",
                           return_value={"ok": True}):
                    self.hc.run_now()
        mock_clear.assert_called_once_with("rutracker.org", flush=False)

    def test_run_now_nonblocking_returns_started(self):
        """run_now(blocking=False) запускает фон и сразу возвращает started."""
        urls = {"https://www.youtube.com": True, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            res = self.hc.run_now(blocking=False)
            self.assertTrue(res["started"])
            # дождёмся фонового потока
            t = self.hc._check_thread
            if t:
                t.join(timeout=5)
        # После завершения флаг checking снят
        self.assertFalse(self.hc._checking)

    def test_history_appends_each_tick(self):
        urls = {"https://www.youtube.com": True, "https://discord.com": True}
        with patch("core.diagnostics.check_http",
                   side_effect=_fake_check_http_factory(urls)):
            for _ in range(3):
                self.hc.run_now()
        with self.hc._lock:
            self.assertEqual(len(self.hc._history), 3)
            # newest right
            self.assertGreaterEqual(
                self.hc._history[-1]["ts"], self.hc._history[0]["ts"])


class TestHealthcheckDaemonControl(unittest.TestCase):

    def setUp(self):
        from core.healthcheck import HealthcheckDaemon
        self.hc = HealthcheckDaemon()
        from core.config_manager import get_config_manager
        self.cfg = get_config_manager()
        self._saved_hc = dict(self.cfg._config.get("healthcheck") or {})

    def tearDown(self):
        self.hc.stop()
        self.cfg._config["healthcheck"] = self._saved_hc

    def test_start_no_op_when_disabled(self):
        self.cfg._config["healthcheck"] = {"enabled": False}
        started = self.hc.start()
        self.assertFalse(started)
        self.assertFalse(self.hc.is_running())

    def test_get_status_reflects_config(self):
        self.cfg._config["healthcheck"] = {
            "enabled": True, "interval_min": 7,
            "consecutive_failures": 3,
            "auto_reset": False, "services": ["youtube"],
            "history_size": 50,
        }
        st = self.hc.get_status()
        self.assertTrue(st["enabled"])
        self.assertEqual(st["interval_min"], 7)
        self.assertEqual(st["services"], ["youtube"])
        self.assertEqual(st["consecutive_failures"], 3)
        self.assertFalse(st["auto_reset"])


if __name__ == "__main__":
    unittest.main()
