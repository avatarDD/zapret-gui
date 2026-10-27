# core/wiw_chain.py
"""
Какие туннели сейчас собраны в WARP-in-WARP — одним списком для UI.

Двойных туннелей в проекте два, и каждый хранит своё состояние:
  * AWG+AWG — core/awg_warp_in_warp.py, config["awg"]["warp_in_warp"];
  * MASQUE (masque_masque / masque_awg / awg_masque) — core/warp_in_warp.py,
    config["warp_in_warp"]["runtime"].

Страницам «Маршрутизация» и «AmneziaWG» нужно одно и то же: у какого
интерфейса какая роль. Без этого в списке целей стоят два одинаковых
«Туннель AmneziaWG · warpN», и непонятно, что трафик надо слать во
внутренний (inner), а внешний (outer) только везёт его endpoint.

Читаем только сохранённое состояние — без `ip`/`awg show`: модуль
дёргают на каждый опрос страницы маршрутизации. Живость слоёв
показывают собственные статусы WiW-страниц.
"""

# Метод-kind единого слоя маршрутизации по стороне MASQUE-режима
# (core/unified/model.METHOD_KINDS: usque — `warp:`, AmneziaWG — `awg:`).
_MASQUE_MODES = {
    # mode: (kind outer, kind inner)
    "masque_masque": ("warp", "warp"),
    "masque_awg":    ("warp", "awg"),
    "awg_masque":    ("awg", "warp"),
}


def _awg_chain(cm):
    st = cm.get("awg", "warp_in_warp") or {}
    if not isinstance(st, dict) or not st.get("active"):
        return None
    outer = (st.get("outer") or "").strip()
    inner = (st.get("inner") or "").strip()
    if not outer or not inner:
        return None
    return {"engine": "awg", "mode": "awg_awg",
            "outer": outer, "outer_kind": "awg",
            "inner": inner, "inner_kind": "awg"}


def _masque_chain(cm):
    st = cm.get("warp_in_warp", "runtime", default={}) or {}
    if not isinstance(st, dict):
        return None
    mode = st.get("mode") or ""
    kinds = _MASQUE_MODES.get(mode)
    outer = (st.get("outer_iface") or "").strip()
    inner = (st.get("inner_iface") or "").strip()
    if not kinds or not outer or not inner:
        return None
    return {"engine": "masque", "mode": mode,
            "outer": outer, "outer_kind": kinds[0],
            "inner": inner, "inner_kind": kinds[1]}


def chains(cm=None) -> list:
    """Собранные WARP-in-WARP: [{engine, mode, outer, outer_kind, inner,
    inner_kind}, …]. Пустой список — двойного туннеля нет."""
    if cm is None:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
    out = []
    for fn in (_awg_chain, _masque_chain):
        try:
            ch = fn(cm)
        except Exception:
            ch = None
        if ch:
            out.append(ch)
    return out


def roles_by_iface(chain_list) -> dict:
    """{iface: {"role": "outer"|"inner", "peer": <другой слой>,
    "engine", "mode"}} — для подписи интерфейсов."""
    roles = {}
    for ch in chain_list or []:
        roles[ch["outer"]] = {"role": "outer", "peer": ch["inner"],
                              "engine": ch["engine"], "mode": ch["mode"]}
        roles[ch["inner"]] = {"role": "inner", "peer": ch["outer"],
                              "engine": ch["engine"], "mode": ch["mode"]}
    return roles
