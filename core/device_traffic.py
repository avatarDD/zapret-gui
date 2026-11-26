# core/device_traffic.py
"""
Соединения одного устройства LAN: что оно открывает прямо сейчас.

Просьба из discussion #491: «для мобильных устройств используются
другие домены/IP, приходится лезть в PCAPdroid, чтобы понять, к какому
сайту обрывается соединение». Устройство уже видно GUI (NDM, DHCP-аренды,
ARP — :mod:`core.devices_discovery`), соединения уже лежат в conntrack
(парсер — :mod:`core.geneva_auto_observer`), домены уже знает DNS-детектор
(:func:`core.block_detector.ip_names`). Не хватало ровно одного: склейки
«устройство → его соединения → имена» одним вызовом — для AI через MCP
и для страницы «Устройства».

Здесь только чтение и агрегация; упаковка в MCP-инструмент —
``device_connections`` в :mod:`core.mcp.tools.traffic`.

Домены и хостнеймы — **untrusted data** (их пишут чужие серверы).
"""

import os

# Где ядро держит таблицу соединений — тот же список, что у
# core.traffic_recent: первый существующий и читаем.
_CONNTRACK_FILES = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")

# Столько строк читаем из таблицы: на роутере их бывают десятки тысяч,
# а нам нужны соединения одного устройства. Потолок наблюдателя «Авто».
MAX_LINES = 30000


def conntrack_lines():
    """Строки таблицы conntrack: ``(lines, truncated)`` или ``None``.

    ``None`` — таблицы нет вовсе (модуль nf_conntrack не загружен или
    ядро без него): ответ обязан назвать это причиной, а не «у
    устройства нет соединений».
    """
    path = next((p for p in _CONNTRACK_FILES if os.path.exists(p)), "")
    if not path:
        return None
    lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f):
                if n >= MAX_LINES:
                    return lines, True
                lines.append(line)
    except OSError:
        return None
    return lines, False


def _label(d):
    """Имя устройства с адресом: «pixel-7 (192.168.1.10)».

    Адрес — не украшение, а ключ следующего вызова: по одному имени
    два одинаковых телефона не различить, по IP — можно.
    """
    name = d.get("hostname") or d.get("ip") or "без имени"
    if d.get("ip"):
        return "%s (%s)" % (name, d["ip"])
    return "%s (без IP)" % name


def resolve_device(query):
    """Устройство по имени (подстрока) или точному IP.

    Возвращает ``{"ok": True, "device": {...}}`` либо ``{"ok": False,
    "error": …}`` с подсказкой: ``candidates`` при пустом запросе в
    таблице устройств, ``matches`` при неоднозначном имени. Устройство
    без IP (офлайн) — не ошибка поиска, а честное «сейчас не в сети».
    """
    from core.devices_discovery import list_devices

    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "не указано устройство: имя или IP"}

    devices = list_devices(include_offline=True)
    if not devices:
        return {"ok": False,
                "error": "таблица устройств пуста (нет ни DHCP-аренд, "
                         "ни ARP, ни NDM)"}

    # Точный IP — самый частый и самый надёжный запрос.
    by_ip = [d for d in devices if d.get("ip") == q]
    if by_ip:
        return {"ok": True, "device": by_ip[0]}

    by_name = [d for d in devices
               if q.lower() in (d.get("hostname") or "").lower()]
    if not by_name:
        return {"ok": False,
                "error": "устройство не найдено: %s" % q,
                "candidates": [_label(d) for d in devices]}
    if len(by_name) > 1:
        # В доме два «iPhone» — норма: отдаём все совпадения с их IP,
        # чтобы следующий вызов был точным (обзавестись списком
        # устройств через MCP больше негде — только здесь).
        return {"ok": False,
                "error": "имя неоднозначно, найдено %d: %s"
                         % (len(by_name), q),
                "matches": [_label(d) for d in by_name]}
    device = by_name[0]
    if not device.get("ip"):
        return {"ok": False,
                "error": "устройство «%s» сейчас не в сети — IP нет, "
                         "соединений быть не может" % q,
                "device": device}
    return {"ok": True, "device": device}


def _sum(value):
    """Число или 0: учёт пакетов у conntrack бывает выключен (None)."""
    return value if isinstance(value, int) else 0


def device_connections(query):
    """Соединения устройства: агрегат по ``адрес+порт+протокол+состояние``.

    Args:
        query: имя устройства (подстрока) или его IP.

    Returns:
        dict: ``device``, ``connections`` (записи — адрес, dport,
        протокол, состояние, счётчики, домен если известен),
        ``sources`` (доступность conntrack и DNS-имён), ``hints``.
        Окно и ``total`` нарезает обёртка MCP (:mod:`core.mcp.tools
        ._paging`) — здесь отдаются все агрегаты, их немного.
        Пустой список — тоже ответ: устройство есть, но сейчас оно
        ничего не открывает (или всё уже закрылось).
    """
    from core.geneva_auto_observer import parse_table

    found = resolve_device(query)
    if not found.get("ok"):
        return found

    device = found["device"]
    ip = device["ip"]

    report = {"device": device}
    sources = {}

    table = conntrack_lines()
    if table is None:
        sources["conntrack"] = {
            "available": False,
            "reason": "таблицы соединений нет (%s)"
                      % " / ".join(_CONNTRACK_FILES),
        }
        report["sources"] = sources
        report["connections"] = []
        report["hints"] = ["таблицу соединений не видно: nf_conntrack "
                           "не загружен или ядро без него"]
        return report

    lines, truncated = table
    sources["conntrack"] = {
        "available": True,
        "lines_read": len(lines),
        "truncated": truncated,
    }

    conns = [c for c in parse_table(lines) if c.src == ip]

    # Домены по обратной карте DNS-детектора: одного ip_names() хватает,
    # и «источник недоступен» не должен прерывать список адресов.
    names = {}
    try:
        from core.block_detector import ip_names
        names = ip_names() or {}
        sources["names"] = {"available": True, "known": len(names)}
    except Exception:                       # noqa: BLE001 — слой страховки
        sources["names"] = {"available": False,
                            "reason": "карта DNS-имён не читается"}

    agg = {}
    for c in conns:
        key = (c.dst, c.dport, c.proto, c.state)
        row = agg.setdefault(key, {
            "dst": c.dst, "dport": c.dport, "proto": c.proto,
            "state": c.state or "", "count": 0,
            "bytes_out": 0, "bytes_in": 0,
            "packets_out": 0, "packets_in": 0,
            "unreplied": False, "syn_sent": False,
        })
        row["count"] += 1
        row["bytes_out"] += _sum(c.obytes)
        row["bytes_in"] += _sum(c.rbytes)
        row["packets_out"] += _sum(c.opackets)
        row["packets_in"] += _sum(c.rpackets)
        row["unreplied"] = row["unreplied"] or bool(c.unreplied)
        row["syn_sent"] = row["syn_sent"] or c.state == "SYN_SENT"

    items = sorted(agg.values(),
                   key=lambda r: (r["bytes_out"] + r["bytes_in"],
                                  r["count"]),
                   reverse=True)
    for row in items:
        row["domain"] = names.get(row["dst"], "")
        # Читаемое поле ответа, чтобы модель не складывала три поля.
        row["label"] = row["domain"] or row["dst"]

    report["sources"] = sources
    report["connections"] = items
    report["hints"] = _hints(items, ip)
    return report


def _hints(items, ip):
    """Что список говорит глазами: где режут, где всё живое."""
    out = []
    if not items:
        out.append("у устройства сейчас нет живых соединений в conntrack")
        return out
    dead = [r for r in items if r["unreplied"] or r["syn_sent"]]
    if dead:
        top = dead[0]
        target = top["domain"] or top["dst"]
        out.append("«%s» не отвечает (соединение без ответа, %s) — "
                   "похоже на блокировку по адресу или порту"
                   % (target, top["proto"]))
    if len(dead) == len(items):
        out.append("ни одно соединение устройства не получает ответа — "
                   "либо все цели молчат, либо режут по адресу")
    else:
        out.append("остальные соединения живые — обход, скорее всего, "
                   "работает")
    return out
