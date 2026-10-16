# core/safe_apply.py
"""
Применение стратегии с проверкой и откатом, «Вернуть рабочее состояние».

## Зачем

Новая стратегия может сделать хуже: сайты, которые открывались, перестают,
а движок и вовсе падает на неудачном аргументе. Тогда человек ищет, что
было до, по памяти. Здесь (приём nfqws2-ui, «guard job» + «confirm
point») применение идёт в три шага:

1. **Замер до** — сайты мониторинга (``healthcheck.services`` и
   ``custom_domains``) пробуются мимо кеша.
2. **Применение и замер после** — через :data:`SETTLE_SEC` секунд.
   Если движок не поднялся или умер, или все сайты, что открывались до,
   перестали — откат сразу.
3. **Ожидание подтверждения** — до ``deadline``. «Всё работает» —
   стратегия остаётся и становится рабочей точкой; «Откатить» или
   истёкший срок — всё возвращается: выбор стратегии в настройках —
   поштучно (не весь ``settings.json``: за время ожидания там могли
   поменять своё), прочие файлы этого действия — по истории
   (``core.file_history``), движок — с прежними аргументами (или
   останавливается, если не работал), автозапуск — пересобирается.

Срок ожидания нужен на случай, когда после применения до GUI уже не
достучаться: подтверждать некому — значит, откат.

## Переживает перезагрузку

Состояние — ``<config_dir>/safe-apply.json``. При старте
:func:`recover`: истёкший срок или прерванное применение — откат;
иначе ожидание продолжается.

## Рабочая точка

После подтверждения запоминается момент и аргументы движка
(``working``). «Вернуть рабочее состояние» возвращает все отслеживаемые
файлы к тому моменту (:func:`core.file_history.restore_to`) и
поднимает движок с теми аргументами. Отметить состояние рабочим можно и
вручную (:func:`mark_working`).

Если пока ждём подтверждения стратегию сменили иначе (страница
«Стратегии», MCP), проверка снимается без отката: решение уже принято
другим путём.
"""

from __future__ import annotations

import json
import os
import threading
import time

from core.log_buffer import log

# Пауза после запуска движка перед замером «после», сек.
SETTLE_SEC = 6
# Срок подтверждения по умолчанию и пределы, сек.
DEFAULT_TIMEOUT = 180
MIN_TIMEOUT = 30
MAX_TIMEOUT = 1800
# Таймаут одной пробы сайта, сек.
PROBE_TIMEOUT = 6

SOURCE = "safe-apply"

_lock = threading.RLock()
_thread = None
_wake = threading.Event()


# ─────────────────────────── состояние ────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _state_path() -> str:
    return os.path.join(_cfg().config_dir, "safe-apply.json")


def _read() -> dict:
    try:
        with open(_state_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    from core.safe_io import atomic_write_json
    atomic_write_json(_state_path(), data)


def _update(**fields) -> dict:
    with _lock:
        data = _read()
        session = dict(data.get("session") or {})
        session.update(fields)
        data["session"] = session
        _write(data)
        return session


def status() -> dict:
    """Текущая проверка и рабочая точка — для баннера и страницы."""
    data = _read()
    session = data.get("session") or None
    if session:
        session = dict(session)
        if session.get("phase") == "waiting":
            session["left"] = max(0, int(session.get("deadline", 0)
                                         - time.time()))
    working = data.get("working") or None
    out = {"ok": True, "session": session, "working": working,
           "changed_since_working": []}
    if working:
        out["changed_since_working"] = _changed_since_cached(
            float(working.get("ts") or 0))
    return out


# Баннер опрашивает статус каждые 2 с, а сверка читает и хеширует все
# изменённые с рабочей точки файлы (ipset'ы — мегабайты с флеша).
CHANGED_TTL = 30
_changed_cache = {"key": None, "at": 0.0, "value": []}


def _changed_since_cached(ts: float) -> list:
    now = time.time()
    if _changed_cache["key"] == ts and now - _changed_cache["at"] \
            < CHANGED_TTL:
        return list(_changed_cache["value"])
    try:
        from core import file_history
        value = file_history.changed_since(ts)
    except Exception:                               # noqa: BLE001
        value = []
    _changed_cache.update(key=ts, at=now, value=value)
    return list(value)


def active() -> bool:
    s = (_read().get("session") or {})
    return s.get("phase") in ("probing", "applying", "waiting",
                              "rolling_back")


# ─────────────────────────── замеры ────────────────────────────

def _targets() -> list:
    from core.healthcheck import HealthcheckDaemon
    return HealthcheckDaemon._build_targets(_cfg())


def probe() -> dict:
    """Пробы сайтов мониторинга мимо кеша: {ok, total, sites:{key: bool}}."""
    from core.diagnostics import check_http
    sites = {}
    for t in _targets():
        try:
            r = check_http(t["url"], timeout=PROBE_TIMEOUT, fresh=True,
                           single=True)
            sites[t["display"]] = bool(r.get("ok"))
        except Exception:                           # noqa: BLE001
            sites[t["display"]] = False
    return {"ok": sum(1 for v in sites.values() if v),
            "total": len(sites), "sites": sites}


def compare(before: dict, after: dict) -> dict:
    """Чистая функция: что сломалось и что починилось.

    ``broken_all`` — всё, что открывалось до, после не открывается
    (и до открывалось хоть что-то): повод откатить, не дожидаясь.
    """
    b, a = before.get("sites") or {}, after.get("sites") or {}
    lost = sorted(k for k, v in b.items() if v and not a.get(k))
    gained = sorted(k for k, v in a.items() if v and not b.get(k))
    was = [k for k, v in b.items() if v]
    return {"lost": lost, "gained": gained,
            "broken_all": bool(was) and len(lost) == len(was)}


# ─────────────────────────── применение ────────────────────────────

def _engine():
    from core.nfqws_manager import get_nfqws_manager
    return get_nfqws_manager()


def start(strategy_id: str, timeout: int = DEFAULT_TIMEOUT,
          auto_target: str = "", since: float = 0.0,
          paths: list = None) -> dict:
    """Начать применение с проверкой (фоном). Ответ — сразу.

    ``auto_target`` — режим без человека (автоподбор, core/autopick.py):
    подтверждать некому, поэтому решает замер «после». Стратегия
    остаётся, если ``auto_target`` (имя сайта мониторинга) открылся и
    ничего из открывавшегося не перестало; иначе — откат сразу.

    ``since``/``paths`` — файлы, записанные вызывающим ДО старта (своя
    стратегия, список): откат вернёт их к моменту ``since``
    (``file_history.checkpoint()`` перед записью — на вызывающем).
    """
    global _thread
    from core.strategy_builder import get_strategy_manager
    strategy = get_strategy_manager().get_strategy(strategy_id)
    if not strategy:
        return {"ok": False, "error": "Стратегия не найдена: %s"
                % strategy_id, "error_code": "not_found"}
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout))
    with _lock:
        if active():
            return {"ok": False, "error_code": "busy",
                    "error": "уже идёт проверка другой стратегии — "
                             "подтвердите или откатите её"}
        mgr = _engine()
        cfg = _cfg()
        # Запись после этого момента не склеится с версией до него —
        # откат найдёт ровно «как было на старте».
        try:
            from core import file_history
            file_history.checkpoint()
        except Exception:                           # noqa: BLE001
            pass
        session = {
            "phase": "probing",
            "strategy_id": strategy_id,
            "strategy_name": strategy.get("name", ""),
            "previous_id": cfg.get("strategy", "current_id"),
            "previous_name": cfg.get("strategy", "current_name"),
            "was_running": bool(mgr.is_running()),
            "previous_args": list(mgr.get_last_args() or []),
            "started": time.time(),
            "timeout": timeout,
            "deadline": 0,
            "before": None, "after": None, "verdict": None,
            "op": None, "paths": [], "result": "", "reason": "",
            "auto_target": str(auto_target or ""),
            "since": float(since or 0),
            "pre_paths": [str(p) for p in (paths or [])],
        }
        data = _read()
        data["session"] = session
        _write(data)
        _wake.clear()
        _thread = threading.Thread(target=_run, name="safe-apply",
                                   daemon=True)
        _thread.start()
    log.info("Применение с проверкой: %s" % session["strategy_name"],
             source=SOURCE)
    return {"ok": True, "session": session}


def _run() -> None:
    try:
        _run_inner()
    except Exception as e:                          # noqa: BLE001 — граница
        log.error("Применение с проверкой: сбой: %s" % e, source=SOURCE)
        s = _read().get("session") or {}
        if s.get("phase") in ("probing", "applying"):
            _rollback("сбой проверки: %s" % e)


def _run_inner() -> None:
    from core import file_history, nfqws_control
    s = _read().get("session") or {}
    before = probe()
    s = _update(before=before, phase="applying")

    label = "Применение с проверкой: %s" % s["strategy_name"]
    with file_history.operation(label) as op:
        res = nfqws_control.apply_strategy(s["strategy_id"], source=SOURCE)
    paths = _op_paths(op["id"])
    s = _update(op=op["id"], paths=paths)
    if not res.get("ok"):
        if res.get("error_code") == "busy":
            _finish("failed", res.get("error") or "движок занят")
            return
        _rollback("стратегия не применилась: %s" % (res.get("error") or ""))
        return

    _wake.wait(SETTLE_SEC)
    if not _engine().is_running():
        _rollback("движок упал после применения")
        return
    after = probe()
    verdict = compare(before, after)
    s = _update(after=after, verdict=verdict)
    if verdict["broken_all"]:
        _rollback("перестало открываться всё, что открывалось до: %s"
                  % ", ".join(verdict["lost"]))
        return
    target = s.get("auto_target")
    if target:
        reason = auto_verdict(target, after, verdict)
        if reason:
            _rollback(reason)
        else:
            # Под замком и со сверкой сессии — как confirm(): между
            # замером и этой строкой сессию мог сменить другой путь.
            with _lock:
                cur = _read().get("session") or {}
                if (cur.get("started") != s.get("started")
                        or cur.get("phase") != "applying"):
                    return
                _finish("confirmed", "автоподбор: %s открывается" % target)
            mark_working("автоподбор для %s" % target)
            from core import notify
            notify.event("autopick", "✅ «%s» применена: %s открывается"
                         % (s.get("strategy_name", ""), target))
        return
    _update(phase="waiting", deadline=time.time() + int(s["timeout"]))
    _wait()


def auto_verdict(target: str, after: dict, verdict: dict) -> str:
    """Чистая функция: почему автоприменение не оставлять ("" — оставить)."""
    if verdict.get("lost"):
        return "автоподбор: перестали открываться %s" % ", ".join(
            verdict["lost"])
    if not (after.get("sites") or {}).get(target):
        return "автоподбор: %s так и не открылся" % target
    return ""


def _op_paths(op_id: str) -> list:
    from core import file_history
    with file_history._lock:
        return sorted({e["path"] for e in file_history._load()["entries"]
                       if e.get("op") == op_id})


def _wait() -> None:
    """Ждать подтверждения, отката, срока или чужой смены стратегии.

    Срок — страховка на случай «до GUI не достучаться», поэтому сбой
    любой проверки внутри цикла не обрывает ожидание: срок проверяется
    первым и сработает всё равно.
    """
    while True:
        s = _read().get("session") or {}
        if s.get("phase") != "waiting":
            return
        if time.time() >= float(s.get("deadline") or 0):
            _rollback("не подтверждено за %d с" % int(s.get("timeout", 0)))
            return
        try:
            if _cfg().get("strategy", "current_id") != s.get("strategy_id"):
                _finish("superseded",
                        "стратегию сменили иначе — проверка снята")
                return
            if not _engine().is_running():
                _rollback("движок остановился, пока ждали подтверждения")
                return
        except Exception as e:                      # noqa: BLE001 — граница
            log.warning("Применение с проверкой: проверка не удалась: %s"
                        % e, source=SOURCE)
        _wake.wait(2)
        _wake.clear()


def _finish(phase: str, reason: str = "") -> None:
    _update(phase=phase, reason=reason, finished=time.time())
    log.info("Применение с проверкой: %s%s" % (
        {"confirmed": "подтверждено", "rolled_back": "откачено",
         "superseded": "снято", "failed": "не удалось"}.get(phase, phase),
        (" — %s" % reason) if reason else ""), source=SOURCE)


def confirm() -> dict:
    """«Всё работает»: оставить стратегию и запомнить рабочую точку."""
    with _lock:
        s = _read().get("session") or {}
        if s.get("phase") != "waiting":
            return {"ok": False, "error": "подтверждать нечего"}
        _finish("confirmed")
    mark_working("подтверждена «%s»" % s.get("strategy_name", ""))
    _wake.set()
    return {"ok": True}


def cancel() -> dict:
    """«Откатить» вручную."""
    s = _read().get("session") or {}
    if s.get("phase") not in ("waiting", "applying", "probing"):
        return {"ok": False, "error": "откатывать нечего"}
    if s.get("phase") != "waiting":
        return {"ok": False, "error": "дождитесь окончания замера"}
    res = _rollback("откат по кнопке")
    _wake.set()
    return res


# Сколько откат ждёт движок, занятый другим (подбор, проба).
ENGINE_WAIT_SEC = 120


def _restart_engine(was_running: bool, args: list) -> dict:
    """Вернуть движок; занят — подождать, а не сдаться сразу: иначе
    выбор в настройках уже прежний, а nfqws2 работает с отвергнутой."""
    from core import nfqws_control
    from core.nfqws_session import (OWNER_UI, SessionBusy,
                                    get_nfqws_session)
    try:
        with get_nfqws_session().acquire(owner=OWNER_UI,
                                         timeout=ENGINE_WAIT_SEC,
                                         reason="откат стратегии"):
            if was_running and args:
                return nfqws_control.restart(args, source=SOURCE)
            if was_running:
                return nfqws_control.restart(None, source=SOURCE)
            return nfqws_control.stop(source=SOURCE)
    except SessionBusy as busy:
        return {"ok": False, "error_code": "busy",
                "error": "движок занят (%s) — стратегия в настройках "
                         "возвращена, nfqws2 перезапустите сами" % busy}


def _regen_autostart() -> None:
    if not _cfg().get("autostart", "enabled", default=False):
        return
    try:
        from core.autostart_manager import get_autostart_manager
        get_autostart_manager().regenerate()
    except Exception as e:                          # noqa: BLE001 — граница
        log.warning("Не удалось обновить автозапуск: %s" % e, source=SOURCE)


def _restore_strategy_choice(s: dict) -> None:
    """Вернуть выбор стратегии в настройках поштучно.

    Не весь ``settings.json`` с начала проверки: за минуты ожидания
    человек мог поменять что-то своё (разрешения MCP, туннель), и откат
    стратегии не должен это стирать. И без истории файлов
    (``history.enabled: false``) выбор всё равно вернётся.
    """
    from core import file_history
    cfg = _cfg()
    with file_history.operation("Откат: %s" % s.get("strategy_name", ""),
                                source="restore"):
        cfg.set("strategy", "current_id", s.get("previous_id"))
        cfg.set("strategy", "current_name", s.get("previous_name"))
        cfg.save()


def _rollback(reason: str, resume: bool = False) -> dict:
    """Вернуть выбор стратегии, файлы действия и движок как было.

    ``resume`` — продолжить откат, прерванный перезапуском (фаза
    ``rolling_back`` уже записана); иначе второй вызов на ту же сессию —
    кнопка и срок одновременно — ничего не делает.
    """
    from core import file_history
    with _lock:
        s = _read().get("session") or {}
        done = ("rolled_back", "confirmed", "superseded")
        if s.get("phase") in done or (s.get("phase") == "rolling_back"
                                      and not resume):
            return {"ok": True, "already": s.get("phase")}
        _update(phase="rolling_back", reason=reason)
    restored = {"ok": True, "restored": []}
    try:
        _restore_strategy_choice(s)
    except Exception as e:                          # noqa: BLE001 — граница
        restored = {"ok": False, "error": "выбор стратегии не вернулся: %s"
                    % e}
    # Прочие файлы, записанные самим применением (settings.json уже
    # вернули поштучно выше).
    cfg_path = os.path.abspath(_cfg().path)
    paths = [p for p in (s.get("paths") or (_op_paths(s["op"])
                                            if s.get("op") else []))
             if os.path.abspath(p) != cfg_path]
    paths += [p for p in s.get("pre_paths") or [] if p not in paths]
    if paths and restored.get("ok"):
        targets = file_history.versions_at(
            float(s.get("since") or s.get("started") or 0),
            paths=set(paths))
        restored = file_history.restore_to_targets(
            targets, "Откат: %s" % s.get("strategy_name", ""))
    eng = _restart_engine(bool(s.get("was_running")),
                          list(s.get("previous_args") or []))
    _regen_autostart()
    ok = bool(restored.get("ok")) and bool(eng.get("ok"))
    _update(phase="rolled_back", reason=reason, finished=time.time(),
            result="" if ok else (restored.get("error")
                                  or eng.get("error") or ""))
    log.warning("Применение с проверкой откачено: %s" % reason,
                source=SOURCE)
    from core import notify
    notify.event("safe_apply", "↩️ Стратегия «%s» откачена: %s"
                 % (s.get("strategy_name", ""), reason))
    return {"ok": ok, "reason": reason, "restored": restored.get("restored"),
            "error": "" if ok else (restored.get("error")
                                    or eng.get("error") or "")}


def recover() -> None:
    """При старте: продолжить ожидание или откатить прерванное."""
    global _thread
    s = _read().get("session") or {}
    phase = s.get("phase")
    if phase in ("probing", "applying", "rolling_back"):
        _rollback("применение прервано перезапуском", resume=True)
        return
    if phase != "waiting":
        return
    if time.time() >= float(s.get("deadline") or 0):
        _rollback("срок подтверждения истёк, пока GUI не работал")
        return
    _thread = threading.Thread(target=_wait, name="safe-apply", daemon=True)
    _thread.start()


# ─────────────────────────── рабочая точка ────────────────────────────

def mark_working(note: str = "") -> dict:
    """Запомнить текущее состояние как рабочее."""
    try:
        from core import file_history
        file_history.checkpoint()
    except Exception:                               # noqa: BLE001
        pass
    mgr = _engine()
    cfg = _cfg()
    point = {"ts": time.time(), "note": note or "отмечено вручную",
             "strategy_id": cfg.get("strategy", "current_id"),
             "strategy_name": cfg.get("strategy", "current_name"),
             "running": bool(mgr.is_running()),
             "args": list(mgr.get_last_args() or [])}
    with _lock:
        data = _read()
        data["working"] = point
        _write(data)
    return {"ok": True, "working": point}


def restore_working() -> dict:
    """«Вернуть рабочее состояние»: файлы — к рабочей точке, движок — тоже."""
    from core import file_history
    if active():
        return {"ok": False, "error": "идёт проверка стратегии — "
                                      "сначала подтвердите или откатите её"}
    point = _read().get("working") or {}
    if not point.get("ts"):
        return {"ok": False, "error": "рабочее состояние ещё не отмечено"}
    # settings.json — не целиком: в нём и разрешения MCP, и пароли, и
    # токены, и их правки после рабочей точки возврат стратегии стирать
    # не должен. Из него возвращается только выбор стратегии.
    label = "Возврат рабочего состояния (%s)" % time.strftime(
        "%d.%m %H:%M", time.localtime(point["ts"]))
    cfg_path = os.path.abspath(_cfg().path)
    targets = {p: sha for p, sha in file_history.versions_at(
        float(point["ts"])).items() if os.path.abspath(p) != cfg_path}
    res = file_history.restore_to_targets(targets, label)
    try:
        _restore_strategy_choice({
            "strategy_name": point.get("strategy_name", ""),
            "previous_id": point.get("strategy_id"),
            "previous_name": point.get("strategy_name")})
    except Exception as e:                          # noqa: BLE001 — граница
        res = {"ok": False, "error": "выбор стратегии не вернулся: %s" % e}
    notes = list(res.get("notes") or []) + file_history.incomplete_since(
        float(point["ts"]), set(targets))
    res["notes"] = notes
    eng = _restart_engine(bool(point.get("running")),
                          list(point.get("args") or []))
    _regen_autostart()
    ok = bool(res.get("ok")) and bool(eng.get("ok"))
    return {"ok": ok, "restored": res.get("restored") or [],
            "notes": res.get("notes") or [],
            "error": "" if ok else (res.get("error") or eng.get("error")
                                    or "")}
