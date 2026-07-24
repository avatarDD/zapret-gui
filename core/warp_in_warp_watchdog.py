# core/warp_in_warp_watchdog.py
"""
Watchdog для WARP-in-WARP: проверяет оба туннеля и перезапускает при падении.

Логика:
  1. Каждые N секунд (настраивается) проверяем, активен ли WARP-in-WARP.
  2. TCP-проба через inner интерфейс (проверяем что трафик реально идёт).
  3. Если probe не проходит consecutive_failures раз подряд → restart.
  4. Cooldown после рестарта + верхний лимит рестартов в час (защита от петли).

По умолчанию ВЫКЛЮЧЕН (warp_in_warp.watchdog_enabled = false).

──────────────────────────────────────────────────────────────────────
Исправления относительно оригинала (см. ISSUE-001 / ISSUE-021 в отчётах
аудита):

1. ISSUE-001: было `self._stop_evt.wait(_DEFAULT_CHECK_INTERVAL)` —
   настройка `watchdog_interval_sec` из конфига читалась в других
   watchdog-файлах, но никогда не применялась. Здесь интервал
   действительно читается из конфига на каждой итерации и передаётся в
   `wait()`.

2. ISSUE-021 (high): `_do_restart()` раньше делал `mgr.stop()` и на этом
   всё — комментарий в коде гласил "для перезапуска используйте GUI".
   То есть включённый watchdog гарантированно обрывал туннель при первом
   сбое и не поднимал его обратно. Здесь `_do_restart()` реально
   вызывает `mgr.start(**last_params)`, используя параметры последнего
   успешного запуска, сохранённые в core/warp_in_warp.py
   (`_save_last_start()` / `_load_last_start()`). Если сохранённых
   параметров нет (например, туннель ни разу не запускался через
   `start()` после обновления с версии, где persistence не было) —
   watchdog честно логирует это и не пытается угадывать конфигурацию.
"""

import socket
import ssl
import threading
import time
from typing import Any

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 90
_DEFAULT_CONSECUTIVE_FAILURES = 3
_DEFAULT_COOLDOWN_SEC = 180
_DEFAULT_MAX_RESTARTS = 4


def _bind_to_iface(sock: socket.socket, inner_iface: str) -> bool | None:
    if not inner_iface:
        return False
    try:
        sock.setsockopt(
            socket.SOL_SOCKET,
            25,  # SO_BINDTODEVICE
            (inner_iface + "\0").encode(),
        )
        return True
    except (OSError, AttributeError):
        # A default-route probe is not a valid W-I-W health signal.
        return None


def _probe_through_wiw(
    inner_iface: str, host: str = "1.1.1.1", port: int = 443, timeout: float = 5.0
) -> bool | None:
    """TCP-проба через inner интерфейс WARP-in-WARP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        bound = _bind_to_iface(s, inner_iface)
        if bound is not True:
            s.close()
            return None
        s.connect((host, int(port)))
        s.close()
        return True
    except Exception:
        return False


def _http_probe_through_wiw(inner_iface: str, host: str = "one.one.one.one",
                            timeout: float = 5.0) -> bool | None:
    """HTTPS probe bound to inner; returns None if binding is impossible."""
    raw = None
    tls_sock = None
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            return False
        addr = infos[0][4]
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        if _bind_to_iface(raw, inner_iface) is not True:
            return None
        raw.connect(addr)
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
        tls_sock.settimeout(timeout)
        tls_sock.sendall(("HEAD /cdn-cgi/trace HTTP/1.1\r\n"
                          "Host: %s\r\nConnection: close\r\n\r\n" % host).encode())
        return tls_sock.recv(64).startswith(b"HTTP/")
    except Exception:
        return False
    finally:
        for s in (tls_sock, raw):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def _external_ip_probe(inner_iface: str, timeout: float = 5.0) -> bool | None:
    """Verify that a HTTPS request made through inner reaches an IP service."""
    raw = None
    tls_sock = None
    host = "api.ipify.org"
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            return False
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        if _bind_to_iface(raw, inner_iface) is not True:
            return None
        raw.connect(infos[0][4])
        tls_sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        tls_sock.settimeout(timeout)
        tls_sock.sendall(("GET / HTTP/1.1\r\nHost: %s\r\n"
                          "Connection: close\r\n\r\n" % host).encode())
        data = tls_sock.recv(512)
        return bool(data and b"HTTP/" in data)
    except Exception:
        return False
    finally:
        for s in (tls_sock, raw):
            try:
                if s:
                    s.close()
            except Exception:
                pass


class WarpInWarpWatchdog:
    """Watchdog для WARP-in-WARP туннелей."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._fail_count = 0
        self._restart_times = []
        self._last_restart = 0
        self._last_health = "unknown"

    def reconfigure(self) -> None:
        """Перечитать конфиг и запустить/остановить watchdog."""
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        if cfg.get("warp_in_warp", "watchdog_enabled", default=False):
            self._start()
        else:
            self._stop()

    def _start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(
                target=self._run_loop, name="wiw-watchdog", daemon=True
            )
            t.start()
            self._thread = t
            log.info("warp-in-warp-watchdog: запущен", source="warp_in_warp")

    def _stop(self) -> None:
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("warp-in-warp-watchdog: остановлен", source="warp_in_warp")

    def _get_interval(self) -> int:
        try:
            from core.config_manager import get_config_manager

            cfg = get_config_manager()
            v = cfg.get(
                "warp_in_warp", "watchdog_interval_sec", default=_DEFAULT_CHECK_INTERVAL
            )
            v = int(v)
            return v if v > 0 else _DEFAULT_CHECK_INTERVAL
        except Exception:
            return _DEFAULT_CHECK_INTERVAL

    def _run_loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("warp-in-warp-watchdog tick: %s" % e, source="warp_in_warp")
            # ISSUE-001: интервал реально читается на каждой итерации —
            # изменение в Settings подхватывается без перезапуска watchdog'а.
            self._stop_evt.wait(self._get_interval())

    def _tick(self) -> None:
        from core.warp_in_warp import get_warp_in_warp_manager

        mgr = get_warp_in_warp_manager()

        status = mgr.get_status()
        if not status.get("mode"):
            self._fail_count = 0
            return

        # If either layer died, restart immediately after the normal
        # consecutive-failure policy instead of returning forever. The
        # previous code treated inactive as "nothing to do" and never
        # recovered a crashed layer.
        if not status.get("active"):
            self._last_health = "unhealthy"
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr)
            return

        inner_iface = status.get("inner_iface", "")
        if not inner_iface:
            self._last_health = "unknown"
            return

        if not status.get("route_ok", True):
            result = False
        else:
            tcp_results = [_probe_through_wiw(inner_iface, host)
                           for host in ("1.1.1.1", "1.0.0.1")]
            http_result = _http_probe_through_wiw(inner_iface)
            external_result = _external_ip_probe(inner_iface)
            if None in tcp_results or http_result is None or external_result is None:
                self._last_health = "unknown"
                result = None
            else:
                result = (any(tcp_results) and bool(http_result)
                          and bool(external_result))

        if result:
            self._last_health = "healthy"
            self._fail_count = 0
        else:
            if result is False:
                self._last_health = "unhealthy"
            self._fail_count += 1
            if self._fail_count >= _DEFAULT_CONSECUTIVE_FAILURES:
                self._do_restart(mgr)

    def _do_restart(self, mgr: Any) -> None:
        now = time.time()

        if (now - self._last_restart) < _DEFAULT_COOLDOWN_SEC:
            return

        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning(
                "warp-in-warp-watchdog: лимит рестартов в час "
                "исчерпан (%d), пропуск — проверьте туннель вручную"
                % _DEFAULT_MAX_RESTARTS,
                source="warp_in_warp",
            )
            return

        # Параметры последнего успешного запуска нужны ДО stop() — stop()
        # их очищает (см. core.warp_in_warp._clear_last_start()).
        from core.warp_in_warp import _load_last_start

        last_params = _load_last_start()

        if not last_params or not last_params.get("mode"):
            log.warning(
                "warp-in-warp-watchdog: нет сохранённых параметров "
                "последнего запуска — не могу перезапустить автоматически, "
                "остановлен, требуется ручной запуск через GUI",
                source="warp_in_warp",
            )
            mgr.stop()
            self._last_restart = now
            self._restart_times.append(now)
            self._fail_count = 0
            return

        log.info(
            "warp-in-warp-watchdog: рестарт WARP-in-WARP (mode=%s)"
            % last_params.get("mode"),
            source="warp_in_warp",
        )

        mgr.stop()
        self._stop_evt.wait(2.0)

        result = mgr.start(
            mode=last_params.get("mode", "masque_masque"),
            outer_sni=last_params.get("outer_sni", ""),
            inner_sni=last_params.get("inner_sni", ""),
            outer_config=last_params.get("outer_config", ""),
            inner_config=last_params.get("inner_config", ""),
            awg_conf=last_params.get("awg_conf", ""),
            inner_endpoint_host=last_params.get("inner_endpoint_host", ""),
            transport_profile=last_params.get("transport_profile", "auto"),
        )

        if result.get("ok"):
            log.success(
                "warp-in-warp-watchdog: успешно перезапущен", source="warp_in_warp"
            )
        else:
            log.warning(
                "warp-in-warp-watchdog: рестарт не удался: %s" % result.get("error"),
                source="warp_in_warp",
            )

        self._last_restart = now
        self._restart_times.append(now)
        self._restart_times = [t for t in self._restart_times if (now - t) < 7200]
        self._fail_count = 0

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "fail_count": self._fail_count,
            "health": self._last_health,
            "recent_restarts": len(
                [t for t in self._restart_times if (time.time() - t) < 3600]
            ),
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
