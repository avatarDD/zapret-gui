# core/unified/failover.py
"""
Адаптивное переключение метода (failover) для единого слоя (TODO.md).

Если назначение деградирует через текущий метод — пробуем следующий по
приоритету (method_chain: primary + fallbacks) с гистерезисом и
cooldown (как awg_watchdog), без флаппинга. По умолчанию выключено
(per-route флаг failover_enabled).

Состояние (RAM): {route_id: {"method": <активный>, "since": ts,
                             "last_switch": ts}}.

Решение о переключении — чистая функция `decide`, тестируется без I/O.
"""

import threading
import time

from core.log_buffer import log


# Пороги (настраиваемые через set_params).
_PARAMS = {
    "fail_threshold": 0.5,   # rate ниже → метод считается деградировавшим
    "min_samples":    4,     # не решаем, пока замеров меньше
    "cooldown":       180,   # сек между переключениями (анти-флаппинг)
}

_state = {}
_lock = threading.Lock()


def set_params(**kw):
    for k, v in kw.items():
        if k in _PARAMS and v is not None:
            _PARAMS[k] = v


def get_params() -> dict:
    return dict(_PARAMS)


def current_method(route_id: str) -> str:
    """Активный метод маршрута из состояния ('' если не выбирался)."""
    with _lock:
        st = _state.get(route_id)
        return st.get("method", "") if st else ""


def set_current(route_id: str, method: str, ts: float = None):
    ts = ts if ts is not None else time.time()
    with _lock:
        st = _state.get(route_id) or {}
        if st.get("method") != method:
            st["since"] = ts
            st["last_switch"] = ts
        st["method"] = method
        _state[route_id] = st


def reset(route_id: str = None):
    with _lock:
        if route_id is None:
            _state.clear()
        else:
            _state.pop(route_id, None)


def state(route_id: str) -> dict:
    with _lock:
        return dict(_state.get(route_id) or {})


# ─────────────────────── pure decision ───────────────────────────────

def decide(*, chain: list, current: str, rate, samples: int,
           now: float, last_switch: float,
           params: dict = None) -> dict:
    """
    Решить, нужно ли переключать метод. Чистая функция.

      chain        — приоритетная цепочка методов (primary..fallbacks);
      current      — текущий активный метод ('' = ещё не выбран);
      rate         — success_rate (0..1) или None;
      samples      — число замеров;
      now/last_switch — для cooldown;
      params       — пороги (по умолчанию _PARAMS).

    Возвращает {"switch": bool, "method": <на что>, "reason": str}.
    """
    p = params or _PARAMS
    if not chain:
        return {"switch": False, "method": current, "reason": "пустая цепочка"}

    cur = current or chain[0]
    # Недостаточно данных или метод не выбран — фиксируем primary.
    if not current:
        return {"switch": True, "method": chain[0], "reason": "init"}
    if rate is None or samples < p["min_samples"]:
        return {"switch": False, "method": cur, "reason": "мало данных"}

    # Метод здоров — остаёмся.
    if rate >= p["fail_threshold"]:
        return {"switch": False, "method": cur, "reason": "метод здоров"}

    # Деградация. Cooldown — не флаппим.
    if (now - (last_switch or 0)) < p["cooldown"]:
        return {"switch": False, "method": cur, "reason": "cooldown"}

    # Берём следующий метод по цепочке после текущего (циклически).
    try:
        idx = chain.index(cur)
    except ValueError:
        idx = 0
    nxt = chain[(idx + 1) % len(chain)]
    if nxt == cur:
        return {"switch": False, "method": cur, "reason": "нет альтернативы"}
    return {"switch": True, "method": nxt,
            "reason": "деградация rate=%.2f → %s" % (rate, nxt)}


# ─────────────────────── step (с побочными эффектами) ────────────────

def step(route) -> dict:
    """
    Один шаг failover для маршрута: смотрим историю монитора, при
    необходимости переключаем активный метод и переприменяем маршрут.
    """
    from core.unified import monitor, applier
    chain = route.method_chain()
    cur = current_method(route.id) or route.method
    rate = monitor.success_rate(route.id)
    samples = len(monitor.history(route.id))
    st = state(route.id)
    decision = decide(
        chain=chain, current=current_method(route.id),
        rate=rate, samples=samples, now=time.time(),
        last_switch=st.get("last_switch", 0))

    if not decision["switch"]:
        return {"switched": False, "method": cur, "reason": decision["reason"]}

    new_method = decision["method"]
    set_current(route.id, new_method)
    res = applier.apply_route(route, method=new_method)
    log.info("unified failover: маршрут %s %s → %s (%s)"
             % (route.id, cur, new_method, decision["reason"]),
             source="unified")
    return {"switched": True, "from": cur, "method": new_method,
            "reason": decision["reason"], "applied": res}
