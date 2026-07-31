# core/opera_proxy_watchdog.py
"""
Watchdog для Opera Proxy: автоматически рестартит если процесс упал.

Логика:
  1. Каждые N секунд (default 60) проверяем процесс alive.
  2. TCP-проба на bind-адрес (проверяем что прокси слушает).
  3. Если не отвечает consecutive_failures раз → restart.
  4. Cooldown после рестарта.
  5. Защита от петли.

По умолчанию ВЫКЛЮЧЕН (opera_proxy.autostart = false).
"""

import socket
import subprocess
import threading
import time

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 60
_DEFAULT_CONSECUTIVE_FAILURES = 3
_DEFAULT_COOLDOWN_SEC = 120
_DEFAULT_MAX_RESTARTS = 6


def probe_proxy(bind_addr: str, timeout: float = 3.0) -> bool:
    """
    TCP-проба: проверяем что прокси слушает на bind-адресе.

    Раньше проба была захардкожена под IPv4 (`rsplit(":", 1)` +
    AF_INET), поэтому при bind вида `[::1]:18080` она ВСЕГДА возвращала
    False и watchdog бесконечно перезапускал полностью исправный прокси.
    Wildcard-адреса (0.0.0.0 / ::) стучимся в loopback: сам wildcard —
    не адрес назначения.
    """
    from core.opera_proxy_manager import parse_bind
    try:
        host, port = parse_bind(bind_addr)
    except ValueError:
        return False
    if host in ("0.0.0.0", "*"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


class OperaProxyWatchdog:
    """Фоновый watchdog для Opera Proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._fail_count = 0
        self._restart_times = []
        self._last_restart = 0

    def reset(self):
        """Сбросить счетчик ошибок (вызывается при внешнем старте)."""
        self._fail_count = 0

    def reconfigure(self):
        """Перечитать конфиг и запустить/остановить watchdog."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("opera_proxy", "enabled", default=False):
            self._stop()
            return
        if not cfg.get("opera_proxy", "autostart", default=False):
            self._stop()
            return
        self._start()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            # Своё событие на каждый запуск: _stop() не дожидается потока, а
            # общий флаг следующий _start() сбрасывал — старый цикл
            # просыпался и начинал перезапускать прокси параллельно с новым.
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            t = threading.Thread(target=self._run_loop, args=(stop_evt,),
                                 name="opera-proxy-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("opera-proxy-watchdog: запущен", source="opera_proxy")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("opera-proxy-watchdog: остановлен", source="opera_proxy")

    def _run_loop(self, stop_evt=None):
        if stop_evt is None:
            stop_evt = self._stop_evt
        while not stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("opera-proxy-watchdog tick: %s" % e,
                            source="opera_proxy")
            stop_evt.wait(_DEFAULT_CHECK_INTERVAL)

    def _tick(self):
        from core.opera_proxy_manager import get_opera_proxy_manager, parse_bind
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        # Конфиг могли поменять из другой вкладки/через API — сверяемся на
        # каждом тике, иначе watchdog поднимал бы прокси, который
        # пользователь только что выключил.
        if not cfg.get("opera_proxy", "enabled", default=False) or \
           not cfg.get("opera_proxy", "autostart", default=False):
            self._stop()
            return

        mgr = get_opera_proxy_manager()

        if not mgr._is_running():
            # Процесс не работает — рестарт
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr)
            return

        # Процесс жив — проверяем что прокси слушает
        bind = cfg.get("opera_proxy", "bind", default="127.0.0.1:18080")
        try:
            parse_bind(bind)
        except ValueError as e:
            # Негодный bind пробой не проверить: раньше это давало вечный
            # цикл «проба не прошла → рестарт → прокси не стартует».
            log.warning("opera-proxy-watchdog: %s — проба пропущена"
                        % e, source="opera_proxy")
            self._fail_count = 0
            return

        if probe_proxy(bind):
            self._fail_count = 0  # всё ок
        else:
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                log.warning("opera-proxy-watchdog: прокси не отвечает на %s, рестарт"
                            % bind, source="opera_proxy")
                self._do_restart(mgr)

    def _do_restart(self, mgr):
        now = time.time()

        # Cooldown
        if (now - self._last_restart) < _DEFAULT_COOLDOWN_SEC:
            return

        # Rate limiting
        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning("opera-proxy-watchdog: лимит рестартов, пропуск",
                        source="opera_proxy")
            return

        log.info("opera-proxy-watchdog: рестарт Opera Proxy", source="opera_proxy")

        mgr.stop()
        self._stop_evt.wait(1.0)

        # Тот же набор параметров, что у API и автозапуска (здесь терялся
        # verbosity).
        from core.opera_proxy_manager import start_kwargs_from_config
        result = mgr.start(**start_kwargs_from_config())

        if not result.get("ok"):
            log.warning("opera-proxy-watchdog: рестарт не удался: %s"
                        % result.get("error"), source="opera_proxy")

        self._last_restart = now
        self._restart_times.append(now)
        self._restart_times = [t for t in self._restart_times
                               if (now - t) < 7200]
        self._fail_count = 0

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "fail_count": self._fail_count,
            "recent_restarts": len([t for t in self._restart_times
                                    if (time.time() - t) < 3600]),
        }


_instance = None
_instance_lock = threading.Lock()


def get_opera_proxy_watchdog():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = OperaProxyWatchdog()
    return _instance
