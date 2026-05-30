# core/unified/monitor.py
"""
Автомониторинг успешности per-destination (TODO.md).

Периодически (опционально) проверяет доступность ключевого домена
каждого маршрута через текущий метод и хранит историю успешности в
RAM (как traffic-буферы — без записи на flash).

Архитектура:
  - история: {route_id: deque[(ts, ok)]} (maxlen ограничен);
  - `record()` — добавить замер;
  - `success_rate()` — доля успехов в окне (или None, если данных нет);
  - `probe_destination()` — реальная проба (TLS-connect к probe-домену);
  - фоновый цикл (singleton, default OFF) — `start()/stop()`.

Проба намеренно простая и без внешних зависимостей: TCP+TLS handshake
к <probe_domain>:443 с таймаутом. Это не полноценный DPI-тест (для него
есть core/testers), а быстрый сигнал «достучались/нет» через текущий
маршрут.
"""

import socket
import ssl
import threading
import time
from collections import deque

from core.log_buffer import log


_HISTORY_MAXLEN = 50
_history = {}
_history_lock = threading.Lock()


# ─────────────────────── history ─────────────────────────────────────

def record(route_id: str, ok: bool, ts: float = None):
    ts = ts if ts is not None else time.time()
    with _history_lock:
        dq = _history.get(route_id)
        if dq is None:
            dq = deque(maxlen=_HISTORY_MAXLEN)
            _history[route_id] = dq
        dq.append((ts, bool(ok)))


def history(route_id: str) -> list:
    with _history_lock:
        dq = _history.get(route_id)
        return list(dq) if dq else []


def success_rate(route_id: str, window: int = 10):
    """
    Доля успехов среди последних `window` замеров (0.0..1.0) или None,
    если замеров ещё нет.
    """
    h = history(route_id)
    if not h:
        return None
    recent = h[-window:]
    oks = sum(1 for _ts, ok in recent if ok)
    return oks / len(recent)


def last_ok(route_id: str):
    """Результат последнего замера (bool) или None."""
    h = history(route_id)
    return h[-1][1] if h else None


def clear(route_id: str = None):
    with _history_lock:
        if route_id is None:
            _history.clear()
        else:
            _history.pop(route_id, None)


def stats() -> dict:
    """Сводка по всем маршрутам для UI/API."""
    out = {}
    with _history_lock:
        for rid, dq in _history.items():
            data = list(dq)
            recent = data[-10:]
            oks = sum(1 for _t, ok in recent if ok)
            out[rid] = {
                "samples": len(data),
                "rate": (oks / len(recent)) if recent else None,
                "last_ok": data[-1][1] if data else None,
                "last_ts": data[-1][0] if data else None,
            }
    return out


# ─────────────────────── probe ───────────────────────────────────────

def probe_host(host: str, port: int = 443, timeout: float = 4.0,
               tls: bool = True) -> bool:
    """TCP(+TLS) проба до host:port. True = достучались/handshake ок."""
    if not host:
        return False
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, socket.timeout):
        return False
    try:
        if tls and port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.settimeout(timeout)
                return True
        return True
    except (ssl.SSLError, OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_route(route) -> bool:
    """
    Проба маршрута: берём probe_domain (или первый домен назначения).
    Если доменов нет (только CIDR) — пробуем первый IP из cidrs.
    """
    domain = (route.probe_domain or "").strip()
    if not domain:
        resolved = route.destination.resolve()
        domains = resolved.get("domains") or []
        if domains:
            domain = domains[0]
        else:
            cidrs = resolved.get("cidrs") or []
            if cidrs:
                host = cidrs[0].split("/", 1)[0]
                return probe_host(host, port=443, tls=False)
            return False
    return probe_host(domain, port=443, tls=True)


# ─────────────────────── background loop ─────────────────────────────

class _MonitorLoop:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._interval = 60

    def running(self) -> bool:
        # _stop.is_set() → пользователь остановил, даже если фоновый
        # поток ещё досыпает в wait(interval) и формально alive.
        return (self._thread is not None and self._thread.is_alive()
                and not self._stop.is_set())

    def start(self, interval: int = 60):
        if self.running():
            return
        self._interval = max(15, int(interval))
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("unified monitor: запущен (интервал %ds)" % self._interval,
                 source="unified")

    def stop(self):
        self._stop.set()
        log.info("unified monitor: остановлен", source="unified")

    def _run(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("unified monitor tick: %s" % e, source="unified")
            self._stop.wait(self._interval)

    def _tick(self):
        from core.unified import storage
        for route in storage.load_routes():
            # failover требует проб — поэтому пробуем маршрут, если включён
            # мониторинг ЛИБО автопереключение.
            if not route.enabled:
                continue
            if not (route.monitor_enabled or route.failover_enabled):
                continue
            ok = probe_route(route)
            record(route.id, ok)
            if route.failover_enabled:
                try:
                    from core.unified import failover
                    failover.step(route)
                except Exception as e:
                    log.warning("unified failover step %s: %s"
                                % (route.id, e), source="unified")


_loop = _MonitorLoop()


def needs_monitor() -> bool:
    """Есть ли хоть один включённый маршрут с мониторингом/failover."""
    try:
        from core.unified import storage
        for r in storage.load_routes():
            if r.enabled and (r.monitor_enabled or r.failover_enabled):
                return True
    except Exception:
        pass
    return False


def autostart_if_needed(interval: int = 60) -> bool:
    """
    Запустить фоновый мониторинг, если он нужен хотя бы одному маршруту,
    иначе остановить. Возвращает итоговое состояние (running).

    Так пользователю достаточно поставить галку «Автопереключение» у
    маршрута — отдельно включать глобальный мониторинг не нужно.
    """
    if needs_monitor():
        if not _loop.running():
            _loop.start(interval=interval)
    else:
        if _loop.running():
            _loop.stop()
    return _loop.running()


def get_monitor() -> _MonitorLoop:
    return _loop
