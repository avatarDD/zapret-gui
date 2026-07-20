# core/usque_watchdog.py
"""
Watchdog для WARP/MASQUE (usque): автоматически рестартит туннель,
если probe через него не проходит.

Логика:
  1. Каждые N секунд (default 60) проверяем каждый активный usque-туннель.
  2. TCP-проба через туннельный интерфейс (SO_BINDTODEVICE).
  3. Если probe не проходит consecutive_failures раз подряд → restart.
  4. После рестарта — cooldown (не дёргаем снова N секунд).
  5. Защита от петли: максимум max_restarts_per_hour рестартов.

По умолчанию ВЫКЛЮЧЕН (usque.watchdog.enabled = false).
"""

import socket
import subprocess
import threading
import time

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 60
_DEFAULT_PROBE_HOST = "1.1.1.1"
_DEFAULT_PROBE_PORT = 443
_DEFAULT_PROBE_TIMEOUT = 4
_DEFAULT_CONSECUTIVE_FAILURES = 3
_DEFAULT_COOLDOWN_SEC = 120
_DEFAULT_MAX_RESTARTS = 6

_SO_BINDTODEVICE = 25


def _probe_via_iface(host, port, iface, timeout=4.0):
    """TCP-проба через интерфейс."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if iface:
            try:
                s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE,
                             (iface + "\0").encode())
            except (OSError, AttributeError):
                return None
            try:
                got = s.getsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, 256)
                bound = got.split(b"\0", 1)[0].decode(errors="ignore")
            except (OSError, AttributeError):
                bound = ""
            if bound != iface:
                return None
        s.connect((host, int(port)))
        s.close()
        return True
    except OSError:
        return False
    except Exception:
        return None


class UsqueWatchdog:
    """Фоновый watchdog для usque WARP туннелей."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._fail_counts = {}  # iface -> consecutive fails
        self._restart_times = []  # timestamps of restarts
        self._last_restart = {}  # iface -> timestamp

    def reconfigure(self):
        """Перечитать конфиг и запустить/остановить watchdog."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("usque", "watchdog", "enabled", default=False):
            self._stop()
            return
        if not cfg.get("usque", "enabled", default=False):
            self._stop()
            return
        self._start()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="usque-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("usque-watchdog: запущен", source="usque")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("usque-watchdog: остановлен", source="usque")

    def _run_loop(self):
        from core.config_manager import get_config_manager
        while not self._stop_evt.is_set():
            try:
                cfg = get_config_manager()
                interval = cfg.get("usque", "watchdog", "interval_sec",
                                   default=_DEFAULT_CHECK_INTERVAL)
                self._tick()
            except Exception as e:
                log.warning("usque-watchdog tick: %s" % e, source="usque")
            self._stop_evt.wait(_DEFAULT_CHECK_INTERVAL)

    def _tick(self):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        for c in configs:
            if not c.get("active"):
                continue
            iface = c.get("iface", "")
            if not iface:
                continue

            # Cooldown check
            last = self._last_restart.get(iface, 0)
            if (time.time() - last) < _DEFAULT_COOLDOWN_SEC:
                continue

            # Probe
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            host = cfg.get("usque", "watchdog", "probe_host",
                           default=_DEFAULT_PROBE_HOST)
            port = cfg.get("usque", "watchdog", "probe_port",
                           default=_DEFAULT_PROBE_PORT)

            result = _probe_via_iface(host, port, iface,
                                      timeout=_DEFAULT_PROBE_TIMEOUT)

            if result is True:
                # Probe прошёл — сбрасываем счётчик
                self._fail_counts.pop(iface, None)
                continue

            if result is None:
                # Недостоверно (нет root) — пропускаем
                continue

            # Probe не прошёл
            fails = self._fail_counts.get(iface, 0) + 1
            self._fail_counts[iface] = fails

            if fails >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr, iface, c.get("name", ""))

    def _do_restart(self, mgr, iface, name):
        # Rate limiting
        now = time.time()
        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning("usque-watchdog: лимит рестартов (%d/час) — %s пропущен"
                        % (_DEFAULT_MAX_RESTARTS, iface), source="usque")
            return

        log.info("usque-watchdog: рестарт %s (%s)" % (iface, name),
                 source="usque")

        target = next((c for c in mgr.list_configs()
                       if c.get("iface") == iface or c.get("name") == name), None)
        config_path = target.get("path") if target else ""
        mgr.stop(iface)
        self._stop_evt.wait(1.0)

        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        sni = cfg.get("usque", "default_sni", default="")
        http2 = cfg.get("usque", "http2_enable", default=False)
        profile = "restricted" if http2 else cfg.get(
            "usque", "transport_profile", default="auto")
        if config_path:
            new_iface = iface or mgr.allocate_iface("opkgtun")
            mgr.start(new_iface, config_path, sni=sni,
                      transport_profile=profile)

        self._last_restart[iface] = now
        self._restart_times.append(now)
        self._restart_times = [t for t in self._restart_times
                               if (now - t) < 7200]
        self._fail_counts.pop(iface, None)

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "fail_counts": dict(self._fail_counts),
            "recent_restarts": len([t for t in self._restart_times
                                    if (time.time() - t) < 3600]),
        }


_instance = None
_instance_lock = threading.Lock()


def get_usque_watchdog():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = UsqueWatchdog()
    return _instance
