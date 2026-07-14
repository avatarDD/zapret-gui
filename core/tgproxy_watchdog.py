# core/tgproxy_watchdog.py
"""
Watchdog для Telegram MTProto Proxy: автоматически рестартит,
если процесс упал или iptables chain пропала.

Логика:
  1. Каждые N секунд (default 60) проверяем:
     - Процесс жив?
     - iptables chain TG_TRANSPARENT существует?
  2. Если что-то не так → restart.
  3. Cooldown после рестарта.
  4. Защита от петли.

По умолчанию ВЫКЛЮЧЕН.
"""

import subprocess
import threading
import time

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 60
_DEFAULT_COOLDOWN_SEC = 120
_DEFAULT_MAX_RESTARTS = 6
CHAIN_NAME = "TG_TRANSPARENT"


def _check_chain_exists():
    """Проверить существует ли iptables chain."""
    try:
        r = subprocess.run(
            ["iptables", "-t", "nat", "-L", CHAIN_NAME, "-n"],
            capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


class TgProxyWatchdog:
    """Фоновый watchdog для Telegram proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._restart_times = []
        self._last_restart = 0

    def reconfigure(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("tgproxy", "autostart", default=False):
            self._stop()
            return
        if not cfg.get("tgproxy", "enabled", default=False):
            self._stop()
            return
        self._start()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="tgproxy-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("tgproxy-watchdog: запущен", source="tgproxy")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("tgproxy-watchdog: остановлен", source="tgproxy")

    def _run_loop(self):
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("tgproxy-watchdog tick: %s" % e, source="tgproxy")
            self._stop_evt.wait(_DEFAULT_CHECK_INTERVAL)

    def _tick(self):
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()

        status = mgr.status()
        running = status.get("running", False)

        if not running:
            # Процесс не работает — нужен рестарт
            self._do_restart(mgr)
            return

        # Проверяем iptables chain
        if not _check_chain_exists():
            log.warning("tgproxy-watchdog: chain %s пропала, рестарт"
                        % CHAIN_NAME, source="tgproxy")
            self._do_restart(mgr)

    def _do_restart(self, mgr):
        now = time.time()

        # Cooldown
        if (now - self._last_restart) < _DEFAULT_COOLDOWN_SEC:
            return

        # Rate limiting
        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning("tgproxy-watchdog: лимит рестартов, пропуск",
                        source="tgproxy")
            return

        log.info("tgproxy-watchdog: рестарт Telegram proxy", source="tgproxy")

        mgr.stop()
        time.sleep(1)

        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        result = mgr.start(
            engine=cfg.get("tgproxy", "engine", default="auto"),
            port=cfg.get("tgproxy", "port", default=9443),
            secret=cfg.get("tgproxy", "teleproxy_secret", default=""),
            domain=cfg.get("tgproxy", "teleproxy_domain", default=""),
            tunnel_url=cfg.get("tgproxy", "tunnel_url", default=""),
            tunnel_secret=cfg.get("tgproxy", "tunnel_secret", default=""),
        )

        if not result.get("ok"):
            log.warning("tgproxy-watchdog: рестарт не удался: %s"
                        % result.get("error"), source="tgproxy")

        self._last_restart = now
        self._restart_times.append(now)
        self._restart_times = [t for t in self._restart_times
                               if (now - t) < 7200]

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "recent_restarts": len([t for t in self._restart_times
                                    if (time.time() - t) < 3600]),
        }


_instance = None
_instance_lock = threading.Lock()


def get_tgproxy_watchdog():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TgProxyWatchdog()
    return _instance
