# core/probe_mark.py
"""
Метка собственных проб GUI: замер «без обхода», не гася обход сети.

## Зачем

Чтобы узнать, открывается ли сайт БЕЗ обхода, раньше приходилось
останавливать nfqws2 — для всей сети сразу: у всех домашних устройств
обход пропадал на время замера (baseline эксперимента, сравнение «с
обходом и без»). Приём d2k (necronicle/d2k, ``core/meas.c``): сокет
пробы метится ``SO_MARK``, а firewall ставит такому соединению
connmark-исключение — его пакеты туда и обратно идут мимо NFQUEUE
(``core/firewall.py``, ``nfqws.desync_mark_probe``). Движок продолжает
работать для всех остальных.

## Чему нельзя верить на слово

1. ``setsockopt(SO_MARK)`` требует CAP_NET_ADMIN. Отказ — не повод
   мерить без метки: такая проба пошла бы СКВОЗЬ обход, и «открыто без
   обхода» оказалось бы самоподтверждением. Поэтому метка читается
   обратно (``getsockopt``), и при расхождении проба падает.
   В d2k метка однажды молча не ставилась вовсе (C-заголовок прятал
   ``SO_MARK``), и замер мерил собственный обход — это ловилось только
   счётчиком iptables.
2. Правила firewall могли поставить старая версия автозапуска или
   reapply-хука — без исключения проб. Тогда помеченная проба уйдёт в
   очередь, как любая другая. Поэтому «метить можно» решает
   :func:`baseline_mode`: правил нет вовсе (очередь пуста — проба и так
   идёт напрямую) или среди них есть правило с нашей меткой.
"""

import socket
import threading

from core.log_buffer import log


# Linux: SO_MARK = 36 (asm-generic/socket.h). В socket-модуле Python
# константа есть не на всех сборках.
SO_MARK = getattr(socket, "SO_MARK", 36)

_lock = threading.Lock()
_support_cache = {}


class MarkError(OSError):
    """Метка на сокет не встала — мерить без неё нельзя."""


def configured() -> int:
    """Метка проб из настроек (``nfqws.desync_mark_probe``); 0 — выключена."""
    try:
        from core.config_manager import get_config_manager
        from core.firewall import PROBE_MARK, normalize_mark
        value = normalize_mark(get_config_manager().get(
            "nfqws", "desync_mark_probe", default=PROBE_MARK))
    except Exception:                           # noqa: BLE001 — граница
        return 0
    return int(value, 16) if value else 0


def apply(sock, mark: int) -> bool:
    """Поставить метку на сокет и проверить, что она там действительно есть."""
    if not mark:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, int(mark))
        got = sock.getsockopt(socket.SOL_SOCKET, SO_MARK)
    except (OSError, ValueError, TypeError):
        return False
    return (int(got) & 0xFFFFFFFF) == (int(mark) & 0xFFFFFFFF)


def supported(mark: int) -> bool:
    """Умеет ли процесс ставить метку (кешируется по значению метки)."""
    if not mark:
        return False
    with _lock:
        if mark in _support_cache:
            return _support_cache[mark]
    ok = False
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ok = apply(probe, mark)
        finally:
            probe.close()
    except OSError:
        ok = False
    with _lock:
        _support_cache[mark] = ok
    return ok


def create_connection(address, timeout=None, mark: int = 0):
    """Как ``socket.create_connection``, но с меткой ДО ``connect``.

    ``mark=0`` — обычный ``socket.create_connection``. Метка не встала —
    :class:`MarkError`: соединение без неё мерило бы не то.
    """
    if not mark:
        return socket.create_connection(address, timeout=timeout)
    host, port = address[0], address[1]
    last = None
    for family, kind, proto, _, sockaddr in socket.getaddrinfo(
            host, port, 0, socket.SOCK_STREAM):
        sock = socket.socket(family, kind, proto)
        if not apply(sock, mark):
            sock.close()
            raise MarkError("метка 0x%x на сокет не встала (нужен "
                            "CAP_NET_ADMIN)" % mark)
        try:
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            last = e
            sock.close()
    raise last or OSError("нет адресов для %s" % host)


def rules_carry_mark(rules, mark: int) -> bool:
    """Есть ли среди строк правил firewall правило с этой меткой.

    iptables печатает ``mark match 0x10000000/0x10000000``, nft —
    ``meta mark & 0x10000000 == 0x10000000``: в обоих форма ``0x<hex>``.
    """
    needle = "0x%x" % mark
    for line in rules or []:
        text = str(line).lower()
        if needle in text and ("connmark" in text or "ct mark" in text):
            return True
    return False


def baseline_mode(firewall=None) -> dict:
    """Можно ли мерить «без обхода» помеченной пробой, не гася движок.

    Returns:
        dict: ``marked`` (bool), ``mark`` (int) и ``reason`` — почему
        нет (или как именно да). Человекочитаемо: уходит в отчёт.
    """
    mark = configured()
    if not mark:
        return {"marked": False, "mark": 0,
                "reason": "метка проб выключена (nfqws.desync_mark_probe)"}
    if not supported(mark):
        return {"marked": False, "mark": mark,
                "reason": "процесс не может ставить SO_MARK (нужен "
                          "CAP_NET_ADMIN / root)"}
    try:
        if firewall is None:
            from core.firewall import get_firewall_manager
            firewall = get_firewall_manager()
        rules = firewall.get_rules()
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Правила firewall не прочитаны: %s" % e, source="probes")
        return {"marked": False, "mark": mark,
                "reason": "правила firewall не прочитаны"}
    if not rules:
        return {"marked": True, "mark": mark,
                "reason": "правил перехвата нет — проба идёт напрямую"}
    if rules_carry_mark(rules, mark):
        return {"marked": True, "mark": mark,
                "reason": "проба с меткой 0x%x идёт мимо очереди, движок "
                          "работает" % mark}
    return {"marked": False, "mark": mark,
            "reason": "в правилах firewall нет исключения проб (их "
                      "поставила старая версия автозапуска?) — "
                      "переприменить правила"}
