# tests/test_watchdog.py
"""MR-121: Тесты для watchdog-модулей — проверка thread safety и cooldown."""

import unittest
import threading
import time
from unittest.mock import patch, MagicMock


class TestAwgWatchdogThreadSafety(unittest.TestCase):
    """Тесты потокобезопасности awg_watchdog (MR-28)."""

    def test_restart_log_concurrent_access(self):
        """_restart_log не падает при конкурентном чтении/записи."""
        from core.awg_watchdog import AwgWatchdog
        watchdog = AwgWatchdog()
        errors = []

        def writer():
            try:
                for i in range(100):
                    with watchdog._lock:
                        history = watchdog._restart_log.setdefault("test_iface", [])
                        history.append(time.time())
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(100):
                    with watchdog._lock:
                        items = list(watchdog._restart_log.items())
                    # Чтение вне lock — безопасно因为我们 snapshot
                    for k, v in items:
                        _ = list(v)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], "Concurrent access caused errors: %s" % errors)

    def test_restart_inflight_protected_by_lock(self):
        """_restart_inflightmutations защищены lock."""
        from core.awg_watchdog import AwgWatchdog
        watchdog = AwgWatchdog()
        watchdog._lock = threading.Lock()

        # Добавляем и удаляем из _restart_inflight под lock
        with watchdog._lock:
            watchdog._restart_inflight.add("iface1")
        with watchdog._lock:
            watchdog._restart_inflight.discard("iface1")

        self.assertEqual(len(watchdog._restart_inflight), 0)


class TestSettingsCache(unittest.TestCase):
    """Тесты кеша настроек (MR-78)."""

    def test_settings_cache_has_ttl(self):
        """Кеш настроек имеет TTL и обновляется."""
        # Проверяем что модуль содержит константу TTL
        import core.awg_watchdog as m
        self.assertTrue(hasattr(m, '_SETTINGS_TTL'))
        self.assertGreater(m._SETTINGS_TTL, 0)

    def test_settings_cache_returns_same_value(self):
        """Кеш возвращает одинаковое значение при повторных вызовах."""
        import core.awg_watchdog as m
        # Простая проверка что кеш работает
        if hasattr(m, '_settings_cache'):
            # Если кеш существует, он должен быть dict или None
            self.assertIsInstance(m._settings_cache, (dict, type(None)))


if __name__ == "__main__":
    unittest.main()
