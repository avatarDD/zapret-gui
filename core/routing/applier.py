# core/routing/applier.py
"""
Хуки для применения/снятия routing-правил при подъёме/опускании
сетевых интерфейсов.

Подключается из core/awg_manager.py:
    from core.routing.applier import (
        apply_all_on_interface_up,
        remove_all_on_interface_down,
    )

Делает безопасный try/except — ошибки не должны мешать up/down.
"""

from core.log_buffer import log


def apply_all_on_interface_up(ifname: str) -> dict:
    """Применить все правила, целевой iface которых = ifname."""
    try:
        from core.routing.manager import get_routing_manager
        res = get_routing_manager().apply_all_for_iface(ifname)
    except Exception as e:
        log.warning("routing applier (up %s): %s" % (ifname, e),
                    source="routing")
        return {"ok": False, "error": str(e)}
    _schedule_domain_recheck()
    return res


def _schedule_domain_recheck():
    """
    Догнать доменные правила, когда туннель уже прогрелся.

    Нас зовут сразу после `ip link set up`: handshake ещё не прошёл, и
    резолв доменов на этом шаге вполне может вернуть пусто (особенно
    если DNS роутера смотрит в туннель). Раньше такой пустой set жил до
    следующего такта рефрешера — по умолчанию 10 минут, ровно столько
    пользователь и ждал «пока заработает». Пара отложенных пинков
    закрывает окно за секунды, а сам рефрешер только ДОБАВЛЯЕТ IP,
    поэтому лишний проход безвреден.
    """
    try:
        from core.routing import domain_refresh
        for delay in (15, 60):
            domain_refresh.kick(delay_sec=delay)
    except Exception:
        pass


def remove_all_on_interface_down(ifname: str) -> dict:
    """Снять все правила, целевой iface которых = ifname."""
    try:
        from core.routing.manager import get_routing_manager
        return get_routing_manager().remove_all_for_iface(ifname)
    except Exception as e:
        log.warning("routing applier (down %s): %s" % (ifname, e),
                    source="routing")
        return {"ok": False, "error": str(e)}
