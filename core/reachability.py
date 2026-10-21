# core/reachability.py
"""
«Упал интернет у провайдера» против «сломался туннель»: три сигнала.

## Зачем

Сторож туннеля видит одно: проба через туннель не прошла. Причин три,
и лечатся они по-разному (приём Tachyon,
``diagnostics/reachability_guard.uc``):

==================  ===============  ==============  =================
отечественный       зарубежный       зарубежный      что это
напрямую            напрямую         через туннель
==================  ===============  ==============  =================
нет                 нет              нет             ``wan_down``
да                  —                нет             ``tunnel_broken``
да                  нет              да              ``foreign_blocked``
да                  да               да              ``normal``
==================  ===============  ==============  =================

Когда пропадает WAN, все сторожа разом начинают перезапускать туннели,
единый слой — переключать методы, а в Telegram летит пачка «перезапускаю»
на каждый туннель. Пакет при этом всё равно не уходит с роутера, и
рестарты только жгут лимит в час: к возвращению интернета туннелю уже
нельзя перезапускаться. Поэтому каждый сторож перед рестартом спрашивает
:func:`hold_restart` — при ``wan_down`` рестарт откладывается, а
уведомление уходит одно: «пропал интернет у провайдера» (и «вернулся»).

## Как меряем WAN

TCP-соединение по IP — без DNS (DNS роутера может лежать отдельно, это
другая поломка, см. ``core/quick_fix``) и без TLS (часы). Отечественные
цели — DNS Яндекса по TCP/53, зарубежные — 1.1.1.1 и 8.8.8.8 на 443.
Хоть один ответ — WAN жив. Результат кешируется на ``CACHE_TTL``: шесть
сторожей за один тик не должны слать по шесть проб.

Ложный «WAN жив» безопасен (сторож поступит как раньше), ложный «WAN
лежит» — нет (туннель не перезапустится). Поэтому «лежит» — только когда
не ответил НИ ОДИН адрес, и только два замера подряд.
"""

from __future__ import annotations

import socket
import threading
import time

from core.log_buffer import log


DOMESTIC_TARGETS = (("77.88.8.8", 53), ("77.88.8.1", 53))
FOREIGN_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))
CONNECT_TIMEOUT = 3.0
CACHE_TTL = 20.0
# Сколько замеров «никто не ответил» подряд нужно, чтобы объявить WAN
# лежащим: один пропуск — это ещё перегруженный роутер или потеря пакета.
DOWN_CONFIRM = 2
# …и между первым и последним промахом должно пройти не меньше: два
# замера подряд от двух сторожей в одну секунду — это один замер.
DOWN_CONFIRM_SPAN = 15.0
# Пока WAN лежит, его проверяет отдельный поток — иначе «вернулся» узнали
# бы только от сторожа, которому снова понадобится рестарт.
RECOVERY_POLL = 30.0
WATCH_RECOVERY = True

_lock = threading.Lock()
# Один замер за раз: остальные ждут его и берут результат из кеша.
_probe_lock = threading.Lock()
_state = {"ts": 0.0, "result": None, "down_streak": 0, "first_miss": 0.0,
          "outage_since": 0.0, "held": {}}
_watcher = None


# ─────────────────────────── чистая логика ───────────────────────────

def classify(direct_domestic, direct_foreign, tunnel_foreign) -> str:
    """Свести три сигнала в вердикт (None — сигнал не мерили)."""
    if direct_domestic is False and direct_foreign is False \
            and tunnel_foreign is not True:
        return "wan_down"
    if tunnel_foreign is False and (direct_domestic or direct_foreign):
        return "tunnel_broken"
    if direct_domestic and direct_foreign is False and tunnel_foreign:
        return "foreign_blocked"
    if tunnel_foreign and (direct_foreign or direct_domestic):
        return "normal"
    if direct_domestic or direct_foreign:
        return "wan_up"
    return "unknown"


# ───────────────────────────── замер ─────────────────────────────────

def _connect(addr, timeout: float = CONNECT_TIMEOUT) -> bool:
    try:
        sock = socket.create_connection(addr, timeout=timeout)
    except OSError:
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True


def _any(targets) -> bool:
    return any(_connect(t) for t in targets)


def uplink(force: bool = False) -> dict:
    """Состояние WAN: ``{state, domestic, foreign, checked_at}``.

    ``state``: ``up`` / ``foreign_blocked`` / ``down`` (подтверждённый) /
    ``suspect`` (промахи есть, но ещё не подтверждены — считаем живым).
    """
    def _cached(max_age):
        with _lock:
            cached = _state["result"]
            if cached and time.time() - _state["ts"] < max_age:
                return dict(cached)
        return None

    if not force:
        hit = _cached(CACHE_TTL)
        if hit:
            return hit
    started = time.time()
    with _probe_lock:
        # Пока ждали замок, замер мог сделать другой сторож.
        with _lock:
            fresh = _state["result"] and _state["ts"] >= started
        if fresh:
            return _cached(CACHE_TTL)
        domestic = _any(DOMESTIC_TARGETS)
        foreign = _any(FOREIGN_TARGETS)
        now = time.time()
        with _lock:
            if not domestic and not foreign:
                if not _state["down_streak"]:
                    _state["first_miss"] = now
                _state["down_streak"] += 1
            else:
                _state["down_streak"] = 0
                _state["first_miss"] = 0.0
            if _state["down_streak"] >= DOWN_CONFIRM and \
                    now - _state["first_miss"] >= DOWN_CONFIRM_SPAN:
                state = "down"
            elif _state["down_streak"]:
                state = "suspect"
            elif domestic and not foreign:
                state = "foreign_blocked"
            else:
                state = "up"
            result = {"state": state, "domestic": domestic,
                      "foreign": foreign, "checked_at": now}
            _state.update(ts=now, result=result)
    _note_transition(state)
    return dict(result)


def wan_down(force: bool = False) -> bool:
    """WAN подтверждённо лежит (никто не ответил ``DOWN_CONFIRM`` раз)."""
    try:
        return uplink(force=force)["state"] == "down"
    except Exception:                           # noqa: BLE001 — граница
        return False


def _note_transition(state: str) -> None:
    """Одно уведомление на пропажу и одно на возвращение WAN."""
    now = time.time()
    with _lock:
        was_down = bool(_state["outage_since"])
        if state == "down" and not was_down:
            _state["outage_since"] = now
            msg = ("🌐 Пропал интернет у провайдера — перезапуски туннелей "
                   "отложены до его возвращения")
            _start_watcher()
        elif state in ("up", "foreign_blocked") and was_down:
            lasted = now - _state["outage_since"]
            held = sorted(_state["held"])
            _state["outage_since"] = 0.0
            _state["held"] = {}
            msg = ("🌐 Интернет вернулся (не было %d мин)%s"
                   % (max(1, lasted // 60),
                      "; сторожа проверят туннели: %s" % ", ".join(held)
                      if held else ""))
        else:
            return
    log.warning(msg, source="watchdog")
    try:
        from core import notify
        notify.event("wan", msg, dedup=False)
    except Exception:                           # noqa: BLE001 — граница
        pass


def _watch() -> None:
    """Проверять WAN, пока он лежит: «вернулся» должно прийти само."""
    global _watcher
    try:
        while True:
            time.sleep(RECOVERY_POLL)
            with _lock:
                if not _state["outage_since"]:
                    return
            try:
                uplink(force=True)
            except Exception:                   # noqa: BLE001 — граница
                pass
    finally:
        with _lock:
            _watcher = None


def _start_watcher() -> None:
    """Зовётся под ``_lock``."""
    global _watcher
    if _watcher is not None or not WATCH_RECOVERY:
        return
    _watcher = threading.Thread(target=_watch, name="wan-recovery",
                                daemon=True)
    _watcher.start()


def hold_restart(source: str, target: str = "") -> bool:
    """Спросить перед рестартом туннеля: True — WAN лежит, рестарт отложить.

    Сторож, получив True, не тратит рестарт из часового лимита и не
    шлёт своё «перезапускаю»: про пропажу интернета пользователь
    узнаёт одним сообщением отсюда.
    """
    if not wan_down():
        return False
    key = "%s %s" % (source, target) if target else source
    with _lock:
        first = key not in _state["held"]
        _state["held"][key] = time.time()
    if first:
        log.info("%s: %s — интернет у провайдера пропал, рестарт отложен"
                 % (source, target or "туннель"), source=source)
    return True


def status() -> dict:
    """Для страниц и MCP: последний замер и текущий простой."""
    with _lock:
        res = dict(_state["result"] or {})
        res["outage_since"] = _state["outage_since"] or None
        res["held"] = sorted(_state["held"])
    return res


def reset() -> None:
    """Сбросить кеш и состояние (тесты)."""
    with _lock:
        _state.update(ts=0.0, result=None, down_streak=0, first_miss=0.0,
                      outage_since=0.0, held={})
