# core/connectivity/__init__.py
"""
Connectivity-monitoring engine.

Заимствовано из awg-manager: «матрица связности» — таблица где
строки = таргеты (8.8.8.8, github.com, ...), столбцы = туннели,
ячейки = latency в миллисекундах с цветовой шкалой:
  green   <100ms
  orange  <250ms
  red     >250ms
  failed  пакет не дошёл

Используется для:
  - визуальной проверки, что туннель реально работает
    (не «handshake есть, а трафика нет»)
  - сравнения нескольких туннелей по тому же набору таргетов
  - детекта потери канала до того, как пользователь заметит

Поверхностный API:

    from core.connectivity import get_matrix_manager

    mgr = get_matrix_manager()
    res = mgr.probe_once(ifaces=["awg0", "Wireguard0"])
    snapshot = mgr.get_snapshot()
"""

from core.connectivity.matrix import (
    ConnectivityMatrix,
    get_matrix_manager,
    DEFAULT_TARGETS,
)
from core.connectivity.traffic import (
    TrafficSampler,
    get_traffic_sampler,
    SAMPLE_INTERVAL_SEC,
    HISTORY_HOURS,
)

__all__ = [
    "ConnectivityMatrix",
    "get_matrix_manager",
    "DEFAULT_TARGETS",
    "TrafficSampler",
    "get_traffic_sampler",
    "SAMPLE_INTERVAL_SEC",
    "HISTORY_HOURS",
]
