# core/ndms/ping_check.py
"""
Делегирование мониторинга нативных WG-туннелей на встроенный
Keenetic-механизм `ping-check`.

Когда мы решаем, поднят ли туннель Wireguard0/1, для:
  - нашего собственного userspace amneziawg-go — нужен `wg show <iface>`
    с проверкой last_handshake и pid живой;
  - нативного Keenetic-WG (поднимается NDMS'ом) — наш `wg show` НЕ
    видит этих интерфейсов вообще (они существуют в ядре Keenetic'а,
    Entware-юзер их не видит). У NDMS свой ping-check, и единственный
    разумный источник истины — RCI `show interface <name>`.

Этот модуль — тонкая обёртка над RCI, отдаёт unified dict:

    {
      "available": bool,        # удалось получить состояние
      "name":      str,
      "active":    bool,        # link up + connected
      "state":     str,         # 'up' | 'down' | ...
      "last_handshake": int,    # unix-ts; 0 если неизвестно
      "rx_bytes":  int,
      "tx_bytes":  int,
      "endpoint":  str,         # peer endpoint (host:port)
      "source":    "ndms",
    }

Все вызовы безопасны на не-Keenetic — возвращают {"available": False}.
"""

from core.log_buffer import log


def get_native_wg_status(name: str) -> dict:
    """
    Состояние нативного WG-туннеля по NDMS.

    Возвращает unified dict (см. модуль). Если RCI недоступен или
    интерфейс не найден — {"available": False, "name": name}.
    """
    base = {"available": False, "name": name, "source": "ndms"}
    if not name:
        return base

    try:
        from core.ndms import is_ndms_available, get_ndms_commands
        if not is_ndms_available():
            return base
        info = get_ndms_commands().show_interface(name)
    except Exception as e:
        log.warning("ndms ping_check(%s): %s" % (name, e), source="ndms")
        return base

    if not isinstance(info, dict) or not info:
        return base

    state    = str(info.get("state") or info.get("link") or "").lower()
    connected = str(info.get("connected") or "").lower() in ("yes", "true", "1")
    active   = state == "up" or connected

    return {
        "available":      True,
        "name":           name,
        "active":         bool(active),
        "state":          state or ("up" if active else "down"),
        "last_handshake": _safe_int(info.get("last-handshake")
                                    or info.get("handshake")
                                    or info.get("last_handshake")),
        "rx_bytes":       _safe_int(_dig(info, ("rxbytes",), ("rx", "bytes"),
                                          ("rx-bytes",))),
        "tx_bytes":       _safe_int(_dig(info, ("txbytes",), ("tx", "bytes"),
                                          ("tx-bytes",))),
        "endpoint":       _extract_endpoint(info),
        "description":    str(info.get("description") or ""),
        "source":         "ndms",
    }


def should_delegate_monitoring(name: str) -> bool:
    """
    Стоит ли отдать мониторинг туннеля на NDMS-ping-check.

    True, если интерфейс — нативный Keenetic-WG (Wireguard0/1...).
    Наши собственные userspace AWG-туннели мониторим сами через
    awg_detector + wg show.
    """
    if not name:
        return False
    try:
        from core.ndms.wg_discovery import is_native_wg
        return is_native_wg(name)
    except Exception:
        return False


# ─────── helpers ───────

def _safe_int(v) -> int:
    try:
        if v is None:
            return 0
        return int(v)
    except (TypeError, ValueError):
        return 0


def _dig(d, *paths):
    """Попробовать несколько путей-кортежей и вернуть первый непустой."""
    for path in paths:
        cur = d
        ok = True
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                ok = False
                break
        if ok and cur not in (None, "", {}, []):
            return cur
    return None


def _extract_endpoint(info: dict) -> str:
    """Достать строку endpoint из ответа `show interface`."""
    if not isinstance(info, dict):
        return ""
    ep = info.get("endpoint") or info.get("remote") or info.get("peer-endpoint")
    if isinstance(ep, str):
        return ep
    if isinstance(ep, dict):
        host = ep.get("address") or ep.get("host") or ""
        port = ep.get("port") or ""
        if host and port:
            return "%s:%s" % (host, port)
        if host:
            return str(host)
    return ""
