# core/bypass_engine.py
"""
Чем обходить блокировки на самом роутере: nfqws2 или geneva_c.

Два движка DPI-обхода не должны работать одновременно на одних портах:
каждый пакет прошёл бы через оба, и ни одна стратегия не значила бы
того, что про неё думают. Поэтому активный движок один —
``bypass.engine`` в settings.json, — а переключение идёт здесь одной
последовательностью для веб-интерфейса, MCP и загрузки роутера:

1. снимок рабочих настроек уходящего движка (``state/engines.json``):
   стратегия, был ли запущен, был ли автозапуск — чтобы вернуться
   ровно туда, откуда ушли;
2. остановка уходящего (у nfqws2 ещё и выключение S99zapret, иначе
   после перезагрузки поднялись бы оба);
3. запуск выбранного; не поднялся — откат к прежнему движку.

Настройки движков при этом не теряются: у nfqws2 стратегия остаётся в
``strategy.current_id``, у geneva — в ``geneva.strategy``. Снимок нужен
для того, что настройкой не является: «работал ли движок» и «был ли у
него автозапуск».

Здесь же — пауза обхода на время подбора geneva (``pause_for_search``):
пробы подборщика идут с роутера на те же 443/80, и работающий обход
сделал бы заблокированный сайт «доступным без стратегии».
"""

import json
import os
import threading
import time

from core.log_buffer import log


ENGINES = ("nfqws2", "geneva")
ENGINE_NAMES = {"nfqws2": "nfqws2 (zapret2)", "geneva": "geneva_c (Geneva)"}

_lock = threading.RLock()


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def snapshot_path() -> str:
    from core.platform_dirs import config_dir
    return os.path.join(config_dir(), "state", "engines.json")


def load_snapshots() -> dict:
    try:
        with open(snapshot_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_snapshots(data: dict) -> None:
    path = snapshot_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("engines.json не записан: %s" % e, source="bypass")


def get_active() -> str:
    engine = str(_cfg().get("bypass", "engine", default="nfqws2") or "")
    return engine if engine in ENGINES else "nfqws2"


def is_geneva_active() -> bool:
    return get_active() == "geneva"


# ─────────────────────────── состояние ──────────────────────────────

def _nfqws_running() -> bool:
    try:
        from core import nfqws_control
        return nfqws_control.running()
    except Exception:                           # noqa: BLE001 — граница
        return False


def _nfqws_snapshot() -> dict:
    cfg = _cfg()
    return {
        "strategy_id": cfg.get("strategy", "current_id", default=None),
        "strategy_name": cfg.get("strategy", "current_name", default=None),
        "running": _nfqws_running(),
        "autostart": bool(cfg.get("autostart", "enabled", default=False)),
        "saved_at": time.time(),
    }


def _geneva_snapshot() -> dict:
    from core.geneva_manager import get_geneva_manager, run_settings
    s = run_settings()
    return {
        "strategy": s["strategy"],
        "strategy_source": s["strategy_source"],
        "ports": s["ports"],
        "running": get_geneva_manager().is_running(),
        "autostart": bool(s["autostart"]),
        "saved_at": time.time(),
    }


def overview() -> dict:
    """Оба движка одним ответом: карточка выбора на странице и MCP."""
    from core.geneva_manager import get_geneva_manager
    active = get_active()
    cfg = _cfg()
    snaps = load_snapshots()
    gm = get_geneva_manager()
    det = gm.detect()
    nf = {
        "running": _nfqws_running(),
        "strategy_id": cfg.get("strategy", "current_id", default=None),
        "strategy_name": cfg.get("strategy", "current_name", default=None),
        "autostart": bool(cfg.get("autostart", "enabled", default=False)),
        "snapshot": snaps.get("nfqws2") or {},
    }
    try:
        from core.strategy_scanner import get_strategy_scanner
        nf["scan_resume"] = get_strategy_scanner().saved_resume_info()
    except Exception:                           # noqa: BLE001 — граница
        nf["scan_resume"] = {}
    s = gm.search_status()
    ge = {
        "installed": det.get("installed", False),
        "version": det.get("version", ""),
        "proto_ok": det.get("proto_ok", False),
        "hint": det.get("hint", ""),
        "running": gm.is_running(),
        "strategy": cfg.get("geneva", "strategy", default=""),
        "autostart": bool(cfg.get("geneva", "autostart", default=False)),
        "snapshot": snaps.get("geneva") or {},
        "search": {k: s.get(k) for k in (
            "running", "kind", "status", "generation", "generations",
            "percent", "best_fitness", "target", "can_resume")},
    }
    return {"ok": True, "active": active, "names": ENGINE_NAMES,
            "nfqws2": nf, "geneva": ge,
            "history": (snaps.get("history") or [])[-10:]}


# ─────────────────────────── переключение ───────────────────────────

def _nfqws_busy() -> dict:
    try:
        from core import nfqws_control
        return nfqws_control.busy()
    except Exception:                           # noqa: BLE001 — граница
        return {}


def _set_engine(engine: str) -> None:
    cfg = _cfg()
    cfg.set("bypass", "engine", engine)
    cfg.save()


def _disable_nfqws_autostart() -> None:
    try:
        from core.autostart_manager import get_autostart_manager
        get_autostart_manager().disable()
    except Exception as e:                      # noqa: BLE001 — граница
        log.warning("Автозапуск nfqws2 не выключен: %s" % e, source="bypass")


def _enable_nfqws_autostart() -> None:
    try:
        from core.autostart_manager import get_autostart_manager
        res = get_autostart_manager().enable()
        if not res.get("ok"):
            log.warning("Автозапуск nfqws2 не включён: %s"
                        % res.get("message", ""), source="bypass")
    except Exception as e:                      # noqa: BLE001 — граница
        log.warning("Автозапуск nfqws2 не включён: %s" % e, source="bypass")


def _start_nfqws() -> dict:
    from core import nfqws_control
    if not _cfg().get("strategy", "current_id", default=None):
        return {"ok": False, "error": "у nfqws2 не выбрана стратегия"}
    return nfqws_control.start(source="engine_switch")


def _record(snaps: dict, frm: str, to: str, ok: bool, note: str = ""):
    hist = list(snaps.get("history") or [])
    hist.append({"ts": time.time(), "from": frm, "to": to, "ok": ok,
                 "note": note[:200]})
    snaps["history"] = hist[-30:]


def switch(target: str, start: bool = True) -> dict:
    """Сделать ``target`` активным движком обхода.

    ``start=False`` — только выбрать (и остановить прежний), не
    запуская: пригодится, когда у geneva ещё нет стратегии, а человек
    хочет сначала её подобрать. Без стратегии geneva всё равно не
    стартует — и это ответ с подсказкой, а не исключение.
    """
    target = str(target or "").strip().lower()
    if target in ("nfqws", "zapret", "zapret2"):
        target = "nfqws2"
    if target in ("geneva_c", "geneva-c"):
        target = "geneva"
    if target not in ENGINES:
        return {"ok": False, "error": "движок: nfqws2 или geneva"}
    with _lock:
        current = get_active()
        busy = _nfqws_busy()
        if busy:
            return {"ok": False, "error_code": "busy",
                    "error": "nfqws2 занят: %s" % busy.get("reason", ""),
                    "hint": busy.get("hint", "")}
        from core.geneva_manager import get_geneva_manager
        gm = get_geneva_manager()
        if gm.job_running():
            return {"ok": False, "error_code": "busy",
                    "error": "идёт подбор geneva — дождитесь окончания или "
                             "остановите его"}
        snaps = load_snapshots()
        if target == "geneva":
            return _to_geneva(current, start, snaps, gm)
        return _to_nfqws(current, start, snaps, gm)


def _to_geneva(current: str, start: bool, snaps: dict, gm) -> dict:
    det = gm.detect()
    if start:
        if not det.get("installed"):
            return {"ok": False, "error": "geneva не установлен",
                    "hint": "установите его на странице «Движок обхода»"}
        if not det.get("proto_ok"):
            return {"ok": False, "error": det.get("hint") or
                    "несовместимая версия geneva"}
        if not _cfg().get("geneva", "strategy", default=""):
            return {"ok": False, "error_code": "no_strategy",
                    "error": "у geneva нет рабочей стратегии",
                    "hint": "выберите её в библиотеке или найдите подбором;"
                            " переключить можно и без запуска"}
    nf = _nfqws_snapshot()
    if current == "nfqws2":
        snaps["nfqws2"] = nf
    if nf["running"]:
        from core import nfqws_control
        res = nfqws_control.stop(source="engine_switch")
        if not res.get("ok"):
            return {"ok": False, "error": "nfqws2 не остановился: %s"
                    % res.get("error", "?")}
    if nf["autostart"]:
        _disable_nfqws_autostart()
    cfg = _cfg()
    prev_autostart = bool(cfg.get("geneva", "autostart", default=False))
    # Предпочтение «поднимать при загрузке» переезжает вместе с движком.
    cfg.set("geneva", "autostart", bool(nf["autostart"]) or bool(
        (snaps.get("geneva") or {}).get("autostart")))
    cfg.save()
    _set_engine("geneva")
    started = {}
    if start:
        started = gm.start()
        if not started.get("ok"):
            # Откат: человек остался бы совсем без обхода.
            cfg.set("geneva", "autostart", prev_autostart)
            _set_engine(current)
            if current == "nfqws2":
                if nf["autostart"]:
                    _enable_nfqws_autostart()
                if nf["running"]:
                    _start_nfqws()
            _record(snaps, current, "geneva", False,
                    started.get("error", ""))
            _save_snapshots(snaps)
            return {"ok": False, "rolled_back": True,
                    "error": "geneva не запустился: %s — вернул %s"
                             % (started.get("error", "?"), current)}
    _record(snaps, current, "geneva", True)
    _save_snapshots(snaps)
    log.success("Движок обхода: geneva_c%s"
                % (" (запущен)" if start else ""), source="bypass")
    return {"ok": True, "active": "geneva", "started": bool(start),
            "geneva": started, "nfqws2_stopped": nf["running"]}


def _to_nfqws(current: str, start: bool, snaps: dict, gm) -> dict:
    ge = _geneva_snapshot()
    if current == "geneva":
        snaps["geneva"] = ge
    if ge["running"]:
        res = gm.stop()
        if not res.get("ok"):
            return {"ok": False, "error": "geneva не остановился: %s"
                    % res.get("error", "?")}
    _set_engine("nfqws2")
    prev = snaps.get("nfqws2") or {}
    if prev.get("autostart"):
        _enable_nfqws_autostart()
    started = {}
    want_start = start and (prev.get("running", True) or not prev)
    if want_start and not _nfqws_running():
        started = _start_nfqws()
        if not started.get("ok"):
            _record(snaps, current, "nfqws2", False,
                    started.get("error", ""))
            _save_snapshots(snaps)
            note = started.get("error", "?")
            log.warning("Движок обхода: nfqws2 выбран, но не запущен: %s"
                        % note, source="bypass")
            return {"ok": True, "active": "nfqws2", "started": False,
                    "warning": "nfqws2 выбран, но не запустился: %s" % note}
    _record(snaps, current, "nfqws2", True)
    _save_snapshots(snaps)
    log.success("Движок обхода: nfqws2", source="bypass")
    return {"ok": True, "active": "nfqws2", "started": bool(started),
            "geneva_stopped": ge["running"]}


# ───────────────────── пауза на время подбора ───────────────────────

def pause_for_search() -> str:
    """Остановить работающий обход перед подбором geneva.

    Возвращает, что остановили: ``"geneva"``, ``"nfqws2"`` или ``""``,
    либо ``"busy"`` — nfqws2 держит другая операция (сканер, blockcheck),
    и трогать его нельзя.
    """
    with _lock:
        from core.geneva_manager import get_geneva_manager
        gm = get_geneva_manager()
        if gm.is_running():
            gm.stop()
            log.info("Подбор geneva: обход geneva приостановлен",
                     source="bypass")
            return "geneva"
        if _nfqws_busy():
            return "busy"
        if _nfqws_running():
            from core import nfqws_control
            res = nfqws_control.stop(source="engine_switch")
            if res.get("ok"):
                log.info("Подбор geneva: nfqws2 приостановлен",
                         source="bypass")
                return "nfqws2"
            return "busy" if res.get("error_code") == "busy" else ""
        return ""


def resume_after_search(engine: str) -> None:
    """Вернуть обход, остановленный перед подбором.

    Только если этот движок по-прежнему активный: переключили движок во
    время подбора — поднимать прежний значило бы запустить оба.
    """
    with _lock:
        if engine not in ENGINES or get_active() != engine:
            return
        if engine == "geneva":
            from core.geneva_manager import get_geneva_manager
            gm = get_geneva_manager()
            if not gm.is_running():
                res = gm.start()
                log.info("После подбора geneva снова запущен: %s"
                         % ("да" if res.get("ok") else res.get("error")),
                         source="bypass")
            return
        if not _nfqws_running():
            res = _start_nfqws()
            log.info("После подбора nfqws2 снова запущен: %s"
                     % ("да" if res.get("ok") else res.get("error")),
                     source="bypass")


def hold_geneva_for(owner: str) -> str:
    """nfqws2 идёт по живой сети (сканер, blockcheck, пробы).

    ``"paused"`` — движок geneva остановлен на это время, ``"busy"`` —
    идёт подбор geneva (его пробы nfqws2 исказил бы), ``""`` — geneva
    не работал. Вызывает ``core/nfqws_session`` под своим захватом.
    """
    from core.geneva_manager import get_geneva_manager
    gm = get_geneva_manager()
    if gm.job_running():
        return "busy"
    if not gm.is_running():
        return ""
    res = gm.stop()
    log.info("geneva приостановлен на время: %s" % owner, source="bypass")
    return "paused" if res.get("ok") else ""


def release_geneva_hold(owner: str) -> None:
    """Вернуть geneva после :func:`hold_geneva_for` — если он ещё выбран."""
    with _lock:
        if not is_geneva_active():
            return
        from core.geneva_manager import get_geneva_manager
        gm = get_geneva_manager()
        if gm.is_running() or gm.job_running():
            return
        res = gm.start()
        log.info("geneva снова запущен после «%s»: %s"
                 % (owner, "да" if res.get("ok") else res.get("error")),
                 source="bypass")


def nfqws_refusal(source: str = "") -> dict:
    """Отказ запускать nfqws2, пока активный движок — geneva.

    Пусто — можно. Переключение и возврат после подбора ходят с
    ``source="engine_switch"`` и мимо этой проверки.
    """
    if source == "engine_switch" or not is_geneva_active():
        return {}
    return {"ok": False, "error_code": "engine_geneva",
            "error": "Обход сейчас идёт через geneva_c — nfqws2 не "
                     "запущен, чтобы движки не делили трафик",
            "hint": "переключите движок на nfqws2 (страница «Движок обхода» "
                    "или POST /api/bypass/engine)"}


def boot_apply() -> None:
    """Загрузка GUI: поднять geneva, если выбран он и стоит автозапуск."""
    from core.geneva_manager import get_geneva_manager
    gm = get_geneva_manager()
    try:
        gm.recover_on_boot()
    except Exception as e:                      # noqa: BLE001 — граница
        log.warning("geneva: восстановление после старта: %s" % e,
                    source="geneva")
    if not is_geneva_active():
        return
    cfg = _cfg()
    if not cfg.get("geneva", "autostart", default=False):
        return
    if gm.is_running() or gm.job_running():
        return
    res = gm.start()
    if res.get("ok"):
        log.info("geneva: автозапуск при старте", source="geneva")
    else:
        log.warning("geneva: автозапуск не удался: %s" % res.get("error"),
                    source="geneva")
