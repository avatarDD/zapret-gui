# core/tunnel_monitor.py
"""
Live мониторинг туннелей: графики трафика, latency, throughput.

Собирает метрики со ВСЕХ туннельных интерфейсов:
  - nfqws2 (через NFQUEUE stats)
  - WARP/MASQUE (usque opkgtun*)
  - AmneziaWG (awg show)
  - sing-box (tun*)
  - mihomo (meta/tun*)
  - Opera Proxy (bind address)
  - Telegram proxy
  - WARP-in-WARP (inner/outer)

Метрики хранятся в ring buffer (последние N точек).
"""

from __future__ import annotations

import os
import re
import socket
from typing import Any
import subprocess
import threading
import time
from collections import deque

from core.log_buffer import log


# Интервал сбора метрик (секунды)
DEFAULT_COLLECT_INTERVAL = 5

# Максимум точек в истории (при 5s интервале = 12 минут)
MAX_HISTORY = 144

# MR-76: grace period при старте мониторинга (секунды)
GRACE_PERIOD_SECONDS = 60


class TunnelMonitor:
    """Сбор метрик со всех туннельных интерфейсов."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._history = {}  # iface -> deque[(ts, rx_bytes, tx_bytes)]
        self._last_values = {}  # iface -> (rx, tx) для calculation
        self._start_monotonic = None  # MR-76: time.monotonic() при старте

    def start(self, recovery: bool = False) -> None:
        """Запустить фоновый сбор метрик.

        recovery=True — пропустить grace period (auto-recovery после сбоя).
        """
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            if not recovery:
                self._start_monotonic = time.monotonic()
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="tunnel-monitor", daemon=True)
            t.start()
            self._thread = t
            log.info("tunnel-monitor: запущен", source="monitor")

    def stop(self) -> None:
        """Остановить сбор метрик."""
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            self._start_monotonic = None
            log.info("tunnel-monitor: остановлен", source="monitor")

    def _run_loop(self):
        while not self._stop_evt.is_set():
            try:
                self._collect()
            except Exception as e:
                log.warning("tunnel-monitor: %s" % e, source="monitor")
            self._stop_evt.wait(DEFAULT_COLLECT_INTERVAL)

    def _collect(self):
        """Собрать метрики со всех интерфейсов."""
        interfaces = self._discover_interfaces()
        now = time.time()

        for iface in interfaces:
            rx, tx = self._read_counters(iface)
            if rx is None:
                continue

            with self._lock:
                if iface not in self._history:
                    self._history[iface] = deque(maxlen=MAX_HISTORY)
                self._history[iface].append((now, rx, tx))

        # MR-76: Очищаем историю старых интерфейсов
        with self._lock:
            for iface in list(self._history.keys()):
                if iface not in interfaces:
                    self._history.pop(iface, None)

    def _discover_interfaces(self) -> list:
        """Найти все туннельные интерфейсы."""
        ifaces = set()

        # usque (WARP/MASQUE)
        try:
            from core.usque_manager import get_usque_manager
            mgr = get_usque_manager()
            for c in mgr.list_configs():
                if c.get("active"):
                    ifaces.add(c.get("iface", ""))
        except Exception:
            pass

        # WARP-in-WARP
        try:
            from core.warp_in_warp import get_warp_in_warp_manager
            mgr = get_warp_in_warp_manager()
            st = mgr.get_status()
            if st.get("outer_iface"):
                ifaces.add(st["outer_iface"])
            if st.get("inner_iface"):
                ifaces.add(st["inner_iface"])
        except Exception:
            pass

        # AmneziaWG
        try:
            from core.awg_manager import get_awg_manager
            mgr = get_awg_manager()
            for c in mgr.list_configs():
                if c.get("active"):
                    ifaces.add(c.get("iface", ""))
        except Exception:
            pass

        # sing-box
        try:
            from core.singbox_manager import get_singbox_manager
            mgr = get_singbox_manager()
            for c in mgr.list_configs():
                if c.get("running"):
                    ifaces.add(c.get("tun_iface", ""))
        except Exception:
            pass

        # mihomo
        try:
            from core.mihomo_manager import get_mihomo_manager
            mgr = get_mihomo_manager()
            for c in mgr.list_configs():
                if c.get("running"):
                    ifaces.add(c.get("tun_iface", ""))
        except Exception:
            pass

        ifaces.discard("")

        # Opera Proxy (не TUN-интерфейс, а bind-адрес)
        try:
            from core.opera_proxy_manager import get_opera_proxy_manager
            mgr = get_opera_proxy_manager()
            if mgr._is_running():
                ifaces.add("__opera_proxy__")
        except Exception:
            pass

        # Telegram proxy (не TUN-интерфейс)
        try:
            from core.tgproxy_manager import get_active_engine_status
            if get_active_engine_status().get("any_running"):
                ifaces.add("__tgproxy__")
        except Exception:
            pass

        # nfqws2 (не TUN, а NFQUEUE)
        try:
            from core.nfqws_manager import get_nfqws_manager
            mgr = get_nfqws_manager()
            if mgr.is_running():
                ifaces.add("__nfqws2__")
        except Exception:
            pass

        return list(ifaces)

    def discover_interfaces(self) -> list[str]:
        """Найти все туннельные интерфейсы (публичный API)."""
        return self._discover_interfaces()

    def _read_counters(self, iface: str) -> tuple:
        """Прочитать RX/TX байты интерфейса.

        Для специальных сервисов (opera, tgproxy, nfqws2) —
        эмулируем метрики через проверку состояния.
        """
        # TUN-интерфейсы: читаем из /sys/class/net
        if not iface.startswith("__"):
            try:
                rx_path = "/sys/class/net/%s/statistics/rx_bytes" % iface
                tx_path = "/sys/class/net/%s/statistics/tx_bytes" % iface
                with open(rx_path) as f:
                    rx = int(f.read().strip())
                with open(tx_path) as f:
                    tx = int(f.read().strip())
                return rx, tx
            except Exception:
                return None, None

        # Специальные сервисы: эмулируем через_nfqws queue stats
        if iface == "__nfqws2__":
            return self._read_nfqws_stats()
        elif iface == "__opera_proxy__":
            return self._read_opera_stats()
        elif iface == "__tgproxy__":
            return self._read_tgproxy_stats()

        return None, None

    def _read_nfqws_stats(self) -> tuple:
        """Прочитать статистику nfqws из /proc/net/netfilter/nfnetlink_queue.

        Колонки файла: queue_num peer_portid queue_total copy_mode copy_range
        queue_dropped user_dropped id_sequence 1. Счётчиков байт и разбиения
        rx/tx здесь нет — единственная монотонная метрика активности это
        id_sequence (parts[7], число пакетов, прошедших через очередь).
        Возвращаем её как «tx»-счётчик (пакеты/сек после дельты); rx=0.
        queue_num берём из конфига, а не хардкодим 300 (он настраиваемый).
        """
        try:
            from core.config_manager import get_config_manager
            qnum = str(int(get_config_manager().get(
                "nfqws", "queue_num", default=300)))
        except Exception:
            qnum = "300"
        try:
            with open("/proc/net/netfilter/nfnetlink_queue") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 8 and parts[0] == qnum:
                        pkts = int(parts[7])  # id_sequence — монотонный счётчик
                        return 0, pkts
        except Exception:
            pass
        return 0, 0

    def _count_connections_proc(self, port: int) -> int:
        """Подсчитать количество соединений в состоянии ESTABLISHED (01) на/с указанного порта."""
        count = 0
        port_hex = "%04X" % port
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r") as f:
                    next(f)  # Пропускаем заголовок
                    for line in f:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        state = parts[3]
                        if state != "01":  # Только ESTABLISHED
                            continue
                        lport = parts[1].split(":")[-1]
                        rport = parts[2].split(":")[-1]
                        if lport == port_hex or rport == port_hex:
                            count += 1
            except Exception:
                pass
        return count

    def _count_connections(self, port: int) -> int:
        # 1. Попытка прочитать из /proc/net/tcp
        if os.path.isfile("/proc/net/tcp"):
            return self._count_connections_proc(port)
        
        # 2. Fallback на ss
        try:
            port_str = str(port)
            r = subprocess.run(
                ["ss", "-tn", "state", "established",
                 "( dport = :%s or sport = :%s )" % (port_str, port_str)],
                capture_output=True, text=True, timeout=2)
            return max(0, len((r.stdout or "").strip().splitlines()) - 1)
        except Exception:
            return 0

    def _read_opera_stats(self) -> tuple:
        """Эмулировать метрики opera-proxy через счётчик соединений."""
        try:
            # Проверяем что порт слушает
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", 18080))
            s.close()
            if result == 0:
                conns = self._count_connections(18080)
                return max(0, conns * 1024), max(0, conns * 512)
        except Exception:
            pass
        return 0, 0

    def _read_tgproxy_stats(self) -> tuple:
        """Эмулировать метрики telegram proxy."""
        try:
            conns = self._count_connections(9443)
            return max(0, conns * 1024), max(0, conns * 512)
        except Exception:
            pass
        return 0, 0

    # MR-76: grace period — первые GRACE_PERIOD_SECONDS после старта
    #         не срабатывают auto-recovery и алерты
    def is_in_grace_period(self) -> bool:
        with self._lock:
            if self._start_monotonic is None:
                return False
            return time.monotonic() - self._start_monotonic < GRACE_PERIOD_SECONDS

    def get_metrics(self) -> list[dict[str, Any]]:
        """Получить метрики со всеми вычислениями."""
        now = time.time()
        result = []

        with self._lock:
            # Делаем shallow copy истории, чтобы освободить lock как можно быстрее
            history_snapshot = {iface: list(history) for iface, history in self._history.items()}

        for iface, history in history_snapshot.items():
            if not history:
                continue

            # Текущие значения
            last_ts, last_rx, last_tx = history[-1]

            # Скорость (bytes/s) за последние 5 секунд
            rx_speed = 0
            tx_speed = 0
            if len(history) >= 2:
                prev_ts, prev_rx, prev_tx = history[-2]
                dt = last_ts - prev_ts
                if dt > 0:
                    rx_speed = max(0, (last_rx - prev_rx) / dt)
                    tx_speed = max(0, (last_tx - prev_tx) / dt)

            # Средняя скорость за 1 минуту
            rx_avg = 0
            tx_avg = 0
            minute_ago = now - 60
            recent = [(ts, rx, tx) for ts, rx, tx in history
                      if ts >= minute_ago]
            if len(recent) >= 2:
                dt = recent[-1][0] - recent[0][0]
                if dt > 0:
                    rx_avg = (recent[-1][1] - recent[0][1]) / dt
                    tx_avg = (recent[-1][2] - recent[0][2]) / dt

            # MR-136: ограничиваем историю для графика — клиент использует
            # только последние 60 точек, отдаём 120 с запасом (~10 минут
            # при интервале 5с). Без ограничения payload рос бесконечно.
            CHART_LIMIT = 120
            chart = [(int(ts), rx, tx) for ts, rx, tx in history[-CHART_LIMIT:]]

            result.append({
                "iface": iface,
                "rx_bytes": last_rx,
                "tx_bytes": last_tx,
                "rx_speed": rx_speed,
                "tx_speed": tx_speed,
                "rx_avg_1m": rx_avg,
                "tx_avg_1m": tx_avg,
                "chart": chart,
            })

        return result

    def get_status(self) -> dict:
        """Статус монитора."""
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
            grace = self._start_monotonic is not None and \
                    time.monotonic() - self._start_monotonic < GRACE_PERIOD_SECONDS
        return {
            "running": running,
            "interfaces": len(self._history),
            "grace_period": grace,
        }


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_tunnel_monitor() -> TunnelMonitor:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TunnelMonitor()
    return _instance
