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


def _probe_proxy(bind_addr: str, timeout: float = 3.0) -> bool:
    """TCP-проба: проверяем что прокси слушает на bind-адресе."""
    try:
        host, port = bind_addr.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
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
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
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

    def _run_loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("opera-proxy-watchdog tick: %s" % e,
                            source="opera_proxy")
            self._stop_evt.wait(_DEFAULT_CHECK_INTERVAL)

    def _tick(self):
        from core.opera_proxy_manager import get_opera_proxy_manager
        mgr = get_opera_proxy_manager()

        if not mgr._is_running():
            # Процесс не работает — рестарт
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr)
            return

        # Процесс жив — проверяем что прокси слушает
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        bind = cfg.get("opera_proxy", "bind", default="127.0.0.1:18080")

        if _probe_proxy(bind):
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

        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        result = mgr.start(
            country=cfg.get("opera_proxy", "country", default="EU"),
            bind=cfg.get("opera_proxy", "bind", default="127.0.0.1:18080"),
            socks_mode=cfg.get("opera_proxy", "socks_mode", default=False),
            proxy_bypass=cfg.get("opera_proxy", "proxy_bypass", default=""),
            fake_sni=cfg.get("opera_proxy", "fake_sni", default=""),
        )

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
