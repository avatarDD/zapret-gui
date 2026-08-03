# core/unified/monitor.py
"""
Автомониторинг успешности per-destination (TODO.md).

Периодически (опционально) проверяет доступность ключевого домена
каждого маршрута через текущий метод и хранит историю успешности в
RAM (как traffic-буферы — без записи на flash).

Архитектура:
  - история: {route_id: deque[(ts, ok, method)]} (maxlen ограничен);
  - `record()` — добавить замер;
  - `success_rate()` — доля успехов в окне (или None, если данных нет);
  - `probe_route()` — реальная проба (TLS-connect к probe-домену);
  - фоновый цикл (singleton, default OFF) — `start()/stop()`.

Проба намеренно простая и без внешних зависимостей: TCP+TLS handshake
к <probe_domain>:443 с таймаутом. Это не полноценный DPI-тест (для него
есть core/testers), а быстрый сигнал «достучались/нет» через текущий
маршрут.

Замер помнит МЕТОД, через который он сделан. Без этого failover считал
успешность нового метода вместе с неудачами старого: сразу после
переключения окно из 10 замеров почти целиком состояло из провалов
предыдущего метода, rate оставался ниже порога, и по истечении cooldown
маршрут уходил с исправного метода обратно на сломанный — и так по
кругу.
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

def record(route_id: str, ok: bool, ts: float = None, method: str = ""):
    ts = ts if ts is not None else time.time()
    with _history_lock:
        dq = _history.get(route_id)
        if dq is None:
            dq = deque(maxlen=_HISTORY_MAXLEN)
            _history[route_id] = dq
        dq.append((ts, bool(ok), method or ""))


def history(route_id: str, method: str = None) -> list:
    """Замеры маршрута; с `method` — только сделанные через этот метод.

    Замеры без метода (сделанные до того, как он стал записываться) при
    фильтрации отбрасываются: приписать их какому-то методу нельзя, а
    зачесть чужие провалы новому методу — ровно та ошибка, из-за которой
    failover и уводил маршрут с исправного метода.
    """
    with _history_lock:
        dq = _history.get(route_id)
        items = list(dq) if dq else []
    if method is None:
        return items
    return [e for e in items if len(e) > 2 and e[2] == method]


def success_rate(route_id: str, window: int = 10, method: str = None):
    """
    Доля успехов среди последних `window` замеров (0.0..1.0) или None,
    если замеров ещё нет. С `method` — только по замерам этого метода.
    """
    h = history(route_id, method=method)
    if not h:
        return None
    recent = h[-window:]
    oks = sum(1 for e in recent if e[1])
    return oks / len(recent)


def last_ok(route_id: str):
    """Результат последнего замера (bool) или None."""
    h = history(route_id)
    return h[-1][1] if h else None


def clear(route_id: str = None):
    with _history_lock:
        if route_id is None:
            _history.clear()
            _warned_unprobeable.clear()
        else:
            _history.pop(route_id, None)
            _warned_unprobeable.discard(route_id)


def stats() -> dict:
    """Сводка по всем маршрутам для UI/API.

    `rate` считается по замерам ТЕКУЩЕГО метода (метод последнего
    замера) — иначе после переключения UI показывал бы успешность,
    в которой половина провалов относится к уже брошенному методу.
    """
    out = {}
    with _history_lock:
        snapshot = {rid: list(dq) for rid, dq in _history.items()}
    for rid, data in snapshot.items():
        if not data:
            continue
        method = data[-1][2] if len(data[-1]) > 2 else ""
        same = [e for e in data if (e[2] if len(e) > 2 else "") == method]
        recent = same[-10:]
        oks = sum(1 for e in recent if e[1])
        out[rid] = {
            "samples": len(same),
            "rate": (oks / len(recent)) if recent else None,
            "last_ok": data[-1][1],
            "last_ts": data[-1][0],
            "method": method,
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
        # TLS-рукопожатие при tls=True на ЛЮБОМ порту (не только 443) —
        # иначе на нестандартном порту проба возвращала бы успех на голом
        # TCP-connect, и маршрут помечался здоровым без реального handshake.
        if tls:
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


def probe_route(route):
    """
    Проба маршрута: берём probe_domain (или первый домен назначения).
    Если доменов нет (только CIDR) — пробуем первый IP из cidrs.

    Возвращает True/False, либо **None — «пробовать нечего»**. Последнее
    бывает у маршрутов, назначение которых состоит только из geosite/
    geoip: категории разворачивает движок, конкретного адреса у маршрута
    нет. Раньше такой маршрут возвращал False, то есть выглядел вечно
    деградировавшим, и failover бесконечно гонял его по всей цепочке
    методов — включая заведомо неподходящие. Ответ None означает «нет
    данных»: замер не пишется, решение не принимается. Чтобы включить
    здесь failover, достаточно задать у маршрута probe_domain.
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
            return None
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
        from core.unified import storage, failover
        for route in storage.load_routes():
            # failover требует проб — поэтому пробуем маршрут, если включён
            # мониторинг ЛИБО автопереключение.
            if not route.enabled:
                continue
            if not (route.monitor_enabled or route.failover_enabled):
                continue
            ok = probe_route(route)
            if ok is None:
                _warn_unprobeable(route)
                continue
            # Замер принадлежит методу, через который он сделан:
            # успешность считается по каждому методу отдельно.
            record(route.id, ok,
                   method=failover.current_method(route.id) or route.method)
            if route.failover_enabled:
                try:
                    failover.step(route)
                except Exception as e:
                    log.warning("unified failover step %s: %s"
                                % (route.id, e), source="unified")


_loop = _MonitorLoop()

# Про какие маршруты уже сказали «пробовать нечего». Тик идёт раз в
# минуту — без этого предупреждение засоряло бы лог бесконечно.
_warned_unprobeable = set()


def _warn_unprobeable(route) -> None:
    if route.id in _warned_unprobeable:
        return
    _warned_unprobeable.add(route.id)
    log.warning(
        "unified monitor: у маршрута «%s» нечего пробовать (назначение —"
        " только geosite/geoip). Мониторинг и автопереключение для него"
        " не работают: укажите «домен для проверки» в настройках маршрута."
        % (route.name or route.id), source="unified")


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
