# core/ndms/wg_discovery.py
"""
Обнаружение нативных Keenetic-WireGuard-интерфейсов через RCI.

Keenetic ОС умеет сама поднимать WireGuard-пиры (раздел «VPN
подключения» в веб-админке). Такие туннели:
  - живут в NDMS-конфиге (`interface Wireguard0..N`)
  - видны через `show interface` (RCI)
  - **не** видны через `awg show` / `wg show` пользователя Entware
    (они существуют только внутри ядра Keenetic'а и доступны на
    уровне NDMS)
  - могут быть использованы как target_iface для NDMS-роутинг-правил
    (dns-proxy route, ip route).

Мы собираем такой список и отдаём в UI отдельной секцией, чтобы
пользователь мог выбирать нативный WG-туннель Keenetic'а ровно
так же, как наши amneziawg-go-туннели.

На не-Keenetic платформах этот модуль всегда возвращает пустой
список — он никогда не делает RCI-запрос без `is_ndms_available()`.
"""

import threading
import time

from core.log_buffer import log


# Сколько кэшируем результат list_native_wg_interfaces(). Запрос
# `show interface` к RCI недешёвый (несколько килобайт JSON), а
# UI может тыкать его на каждое обновление страницы Routing.
_CACHE_TTL = 30   # секунд

_cache_lock = threading.Lock()
_cache_data = None    # list[dict] | None
_cache_at   = 0.0     # unix-ts


def list_native_wg_interfaces(force: bool = False) -> list:
    """
    Список нативных Keenetic WG-интерфейсов.

    Возвращает list of dict:
      [
        {"name": "Wireguard0", "description": "MyOffice",
         "state": "up", "address": "10.0.0.2/24",
         "type": "wireguard", "source": "ndms"},
        ...
      ]

    На любой платформе кроме Keenetic с доступным RCI — [].
    """
    global _cache_data, _cache_at

    # Быстрый отказ для не-Keenetic.
    try:
        from core.ndms import is_ndms_available
        if not is_ndms_available():
            return []
    except Exception:
        return []

    with _cache_lock:
        now = time.time()
        if not force and _cache_data is not None and (now - _cache_at) < _CACHE_TTL:
            return list(_cache_data)

        try:
            from core.ndms import get_ndms_commands
            data = get_ndms_commands().list_wireguard_interfaces()
        except Exception as e:
            log.warning("ndms wg_discovery: %s" % e, source="ndms")
            data = []

        _cache_data = data or []
        _cache_at   = now
        return list(_cache_data)


def invalidate_cache():
    """Сбросить кэш — например, после ручного refresh окружения."""
    global _cache_data, _cache_at
    with _cache_lock:
        _cache_data = None
        _cache_at   = 0.0


def is_native_wg(ifname: str) -> bool:
    """
    Является ли интерфейс с таким именем нативным Keenetic-WG.

    Используется для:
      - выбора NDMS vs ip-rule бэкенда для CIDR-правил
      - делегирования мониторинга (ping-check) на NDMS вместо
        нашего собственного check-loop в awg_detector
    """
    if not ifname:
        return False
    return any(it.get("name") == ifname
               for it in list_native_wg_interfaces())
