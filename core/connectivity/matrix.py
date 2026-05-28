# core/connectivity/matrix.py
"""
Матрица связности туннелей.

Для каждой пары (target, iface) запускаем ICMP-ping через указанный
интерфейс и собираем latency. Параллелизм ограничен (роутеры медленные),
результаты кэшируются в RAM. Никакой записи на flash.

Probe-стратегия:
  - Сначала пробуем `ping -I <iface>` (bind to interface). На большинстве
    Linux это работает; на BusyBox-ping флаг тоже есть.
  - При неудаче — фолбэк на `ping -c 1` без bind'а (используем
    основной маршрут роутера; результат при этом помечается как
    "default route", чтобы UI понимал, что цифра не репрезентативна
    для туннеля).

Защита от долгих probe'ов: на ОДИН target/iface уходит ≤ ping_timeout
секунд. Полная матрица 4×4 при последовательном проходе занимает
≤ 16×ping_timeout, что может быть многовато для UI с автообновлением,
поэтому probe_once() гоняет N параллельных задач (см. MAX_PARALLEL).
"""

import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.log_buffer import log


# ─────── defaults ───────

DEFAULT_TARGETS = [
    {"name": "Cloudflare DNS",  "host": "1.1.1.1"},
    {"name": "Google DNS",      "host": "8.8.8.8"},
    {"name": "Yandex DNS",      "host": "77.88.8.8"},
    {"name": "OpenDNS",         "host": "208.67.222.222"},
    {"name": "github.com",      "host": "github.com"},
    {"name": "google.com",      "host": "google.com"},
]

PING_TIMEOUT_SEC = 3
PING_COUNT = 1
MAX_PARALLEL = 4         # сколько probe'ов одновременно
SNAPSHOT_TTL_SEC = 30    # сколько считаем последний snapshot «свежим»


# ─────── цветовая шкала ───────

def classify_latency(ms):
    """Вернуть строковую метку для UI."""
    if ms is None:
        return "failed"
    if ms < 100:
        return "good"
    if ms < 250:
        return "ok"
    return "slow"


# ─────── ping ───────

_PING_REGEX = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def _ping_via_iface(host: str, iface: str, timeout: float = PING_TIMEOUT_SEC):
    """
    Один ping `host` через интерфейс `iface`.

    Возвращает dict:
      {"latency_ms": float|None, "via_iface": bool, "error": str}

    via_iface=True означает, что `-I <iface>` принят и пинг ушёл
    действительно через указанный интерфейс. False — был фолбэк на
    default route (мерили не туннель, а WAN). UI должен показывать
    цифру с оговоркой.
    """
    if not host:
        return {"latency_ms": None, "via_iface": False, "error": "empty host"}

    # Сначала с -I (через интерфейс)
    if iface:
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(int(timeout)),
               "-I", iface, host]
        rc, out, err = _run(cmd, timeout=timeout + 1)
        if rc == 0 and out:
            ms = _parse_first_latency(out)
            if ms is not None:
                return {"latency_ms": ms, "via_iface": True, "error": ""}
        # -I мог отвалиться по «No such device» (туннель не поднят) —
        # это всё ещё «failed для этого туннеля», не фолбэк.
        low_err = (err or "").lower()
        if "no such device" in low_err or "operation not permitted" in low_err:
            return {"latency_ms": None, "via_iface": True,
                    "error": err.strip() or "no such device"}

    # Без -I — фолбэк на default route. Это уже не «через туннель»,
    # помечаем via_iface=False.
    rc, out, err = _run(
        ["ping", "-c", str(PING_COUNT), "-W", str(int(timeout)), host],
        timeout=timeout + 1)
    if rc == 0 and out:
        ms = _parse_first_latency(out)
        if ms is not None:
            return {"latency_ms": ms, "via_iface": False, "error": ""}
    return {"latency_ms": None, "via_iface": False,
            "error": (err or "").strip() or "timeout"}


def _parse_first_latency(stdout: str):
    """Вытащить первое 'time=12.3 ms' из stdout."""
    m = _PING_REGEX.search(stdout)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _run(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


# ─────── matrix ───────

class ConnectivityMatrix:
    """
    Снимок и пересчёт матрицы связности.

    Хранится в RAM, потокобезопасный. Никакой записи в /var, чтобы
    не убивать flash на роутере.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot = None       # {"at": ts, "cells": [...]}
        self._running  = False
        self._custom_targets = None  # переопределение из API/UI

    def get_targets(self) -> list:
        with self._lock:
            return list(self._custom_targets or DEFAULT_TARGETS)

    def set_targets(self, targets):
        """
        Принять список таргетов (host + опциональный name).

        Формат: [{"name": "...", "host": "..."}, ...] либо просто
        список строк-хостов.
        """
        norm = []
        for t in targets or []:
            if isinstance(t, dict):
                host = (t.get("host") or "").strip()
                if not host:
                    continue
                norm.append({
                    "name": (t.get("name") or host).strip(),
                    "host": host,
                })
            elif isinstance(t, str):
                s = t.strip()
                if s:
                    norm.append({"name": s, "host": s})
        with self._lock:
            self._custom_targets = norm if norm else None

    def get_snapshot(self) -> dict:
        with self._lock:
            if self._snapshot is None:
                return {"at": 0, "fresh": False, "cells": [], "targets": [],
                        "ifaces": []}
            data = dict(self._snapshot)
            data["fresh"] = (time.time() - data["at"]) < SNAPSHOT_TTL_SEC
            return data

    def probe_once(self, ifaces=None) -> dict:
        """
        Гонит probe всех target × ifaces. Блокирующий вызов.

        Если ifaces не передан — берём все известные туннели
        через AwgManager.list_interfaces() (наши AWG + нативные NDMS).
        """
        with self._lock:
            if self._running:
                # Не даём двум одновременным probe'ам — отдаём текущий
                # снимок.
                return self.get_snapshot()
            self._running = True

        try:
            if not ifaces:
                ifaces = _enumerate_ifaces()
            targets = self.get_targets()
            if not ifaces or not targets:
                snap = {
                    "at": int(time.time()),
                    "cells": [], "targets": targets, "ifaces": ifaces,
                    "took_ms": 0,
                }
                with self._lock:
                    self._snapshot = snap
                return snap

            start = time.time()
            pairs = [(t, i) for t in targets for i in ifaces]
            results = {}

            # Параллельно, но с лимитом. ThreadPool stdlib — без deps.
            with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
                future_to_pair = {
                    pool.submit(_ping_via_iface, t["host"], i): (t, i)
                    for (t, i) in pairs
                }
                for fut in as_completed(future_to_pair):
                    t, i = future_to_pair[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = {"latency_ms": None, "via_iface": False,
                             "error": str(e)}
                    results[(t["host"], i)] = r

            cells = []
            for t in targets:
                for i in ifaces:
                    r = results.get((t["host"], i),
                                    {"latency_ms": None, "via_iface": False,
                                     "error": "no result"})
                    cells.append({
                        "target":     t["host"],
                        "target_name": t["name"],
                        "iface":      i,
                        "latency_ms": r["latency_ms"],
                        "via_iface":  r["via_iface"],
                        "error":      r["error"],
                        "level":      classify_latency(r["latency_ms"]),
                    })

            took = int((time.time() - start) * 1000)
            snap = {
                "at":      int(time.time()),
                "cells":   cells,
                "targets": targets,
                "ifaces":  ifaces,
                "took_ms": took,
            }
            with self._lock:
                self._snapshot = snap
            log.info("connectivity: probe готов (%d×%d, %dms)"
                     % (len(targets), len(ifaces), took),
                     source="connectivity")
            return snap
        finally:
            with self._lock:
                self._running = False


def _enumerate_ifaces() -> list:
    """Получить список интерфейсов-кандидатов для probe."""
    try:
        from core.awg_manager import AwgManager
        mgr = AwgManager()
        out = []
        for it in mgr.list_interfaces():
            nm = (it or {}).get("name", "")
            if nm and nm not in out:
                out.append(nm)
        return out
    except Exception as e:
        log.warning("connectivity: enumerate ifaces: %s" % e,
                    source="connectivity")
        return []


# ─────── singleton ───────

_manager = None
_manager_lock = threading.Lock()


def get_matrix_manager() -> ConnectivityMatrix:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = ConnectivityMatrix()
    return _manager
