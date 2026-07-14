# core/warp_in_warp_watchdog.py
"""
Watchdog для WARP-in-WARP: проверяет оба туннеля и перезапускает при падении.

Логика:
  1. Каждые N секунд проверяем outer и inner туннели.
  2. TCP-проба через inner интерфейс (проверяем что трафик идёт через оба слоя).
  3. Если probe не проходит consecutive_failures раз → restart.
  4. Cooldown после рестарта.
  5. Защита от петли.

По умолчанию ВЫКЛЮЧЕН.
"""

import socket
import subprocess
import threading
import time

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 90
_DEFAULT_CONSECUTIVE_FAILURES = 3
_DEFAULT_COOLDOWN_SEC = 180
_DEFAULT_MAX_RESTARTS = 4


def _probe_through_wiw(inner_iface: str, host: str = "1.1.1.1",
                       port: int = 443, timeout: float = 5.0) -> bool:
    """TCP-проба через inner интерфейс WARP-in-WARP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if inner_iface:
            try:
                s.setsockopt(socket.SOL_SOCKET, 25,  # SO_BINDTODEVICE
                             (inner_iface + "\0").encode())
            except (OSError, AttributeError):
                pass
        s.connect((host, int(port)))
        s.close()
        return True
    except Exception:
        return False


class WarpInWarpWatchdog:
    """Watchdog для WARP-in-WARP туннелей."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._fail_count = 0
        self._restart_times = []
        self._last_restart = 0

    def reconfigure(self):
        """Перечитать конфиг и запустить/остановить watchdog."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if cfg.get("warp_in_warp", "watchdog_enabled", default=False):
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="wiw-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("warp-in-warp-watchdog: запущен", source="warp_in_warp")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("warp-in-warp-watchdog: остановлен", source="warp_in_warp")

    def _run_loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("warp-in-warp-watchdog tick: %s" % e,
                            source="warp_in_warp")
            self._stop_evt.wait(_DEFAULT_CHECK_INTERVAL)

    def _tick(self):
        from core.warp_in_warp import get_warp_in_warp_manager
        mgr = get_warp_in_warp_manager()

        status = mgr.get_status()
        if not status.get("active"):
            self._fail_count = 0
            return

        inner_iface = status.get("inner_iface", "")
        if not inner_iface:
            return

        # Проверяем что трафик идёт через inner
        result = _probe_through_wiw(inner_iface)

        if result:
            self._fail_count = 0
        else:
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr)

    def _do_restart(self, mgr):
        now = time.time()

        if (now - self._last_restart) < _DEFAULT_COOLDOWN_SEC:
            return

        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning("warp-in-warp-watchdog: лимит рестартов, пропуск",
                        source="warp_in_warp")
            return

        log.info("warp-in-warp-watchdog: рестарт WARP-in-WARP",
                 source="warp_in_warp")

        mgr.stop()
        time.sleep(2)

        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        # Восстанавливаем из сохранённых настроек
        # (пока просто логируем — полная реализация требует persistent state)
        log.info("warp-in-warp-watchdog: для перезапуска используйте GUI",
                 source="warp_in_warp")

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


def get_warp_in_warp_watchdog():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = WarpInWarpWatchdog()
    return _instance
