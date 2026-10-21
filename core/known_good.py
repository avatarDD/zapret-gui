# core/known_good.py
"""
Рабочая точка туннелей и маршрутов: «последнее, что точно работало».

## Зачем

У стратегий nfqws2 рабочая точка уже есть (``core/safe_apply``: «Отметить
рабочим» / «Вернуть рабочее состояние»). У туннелей и маршрутов единого
слоя — нет: обновилась подписка mihomo, поправили конфиг AWG, добавили
маршрут — и сайты перестали открываться, а что было до правки, никто не
помнит. Приём Tachyon (known-good с окном наблюдения):

1. Отпечаток текущего состояния — маршруты единого слоя
   (``unified_routes`` в settings.json) и конфиги туннелей AWG, sing-box,
   mihomo (файлы целиком).
2. Отпечаток изменился — начинается окно наблюдения
   (``known_good.window_sec``). Правки внутри окна его перезапускают:
   судим состояние, которое простояло спокойно.
3. В конце окна — пробы сайтов мониторинга (те же, что у проверки
   стратегии, ``safe_apply.probe``) и сравнение с пробой рабочей точки.
   Ничего не потерялось — состояние становится новой рабочей точкой.
   Потерялось — уведомление «после правки перестали открываться …»
   с предложением вернуть, а при ``known_good.auto_rollback`` — возврат
   сам (один раз на рабочую точку, чтобы не качаться).
4. Пока у провайдера нет интернета (``core/reachability``), окно не
   судится: иначе любая правка, совпавшая с аварией, считалась бы
   поломкой.

## Хранилище

``<config_dir>/known-good.json`` с правами 0600 — в конфигах туннелей
приватные ключи. Файлы крупнее :data:`MAX_FILE_BYTES` не сохраняются (и
не входят в отпечаток): их не вернуть, а судить по ним без возврата
незачем.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from core.log_buffer import log

SOURCE = "known-good"
TICK_SEC = 60
DEFAULT_WINDOW = 600
MIN_WINDOW = 60
MAX_WINDOW = 86400
MAX_FILE_BYTES = 256 * 1024
# Сколько последних «плохих» отпечатков помнить (чтобы не судить заново).
MAX_FAILED = 20
# Как часто обновлять пробу рабочей точки, пока состояние с ней совпадает.
PROBE_REFRESH = 3600

KINDS = ("awg", "singbox", "mihomo")

_lock = threading.RLock()
_thread = None
_stop = threading.Event()


# ─────────────────────────── настройки ────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def settings() -> dict:
    cfg = _cfg()
    try:
        window = int(cfg.get("known_good", "window_sec",
                             default=DEFAULT_WINDOW) or DEFAULT_WINDOW)
    except (TypeError, ValueError):
        window = DEFAULT_WINDOW
    return {
        "enabled": bool(cfg.get("known_good", "enabled", default=True)),
        "window_sec": max(MIN_WINDOW, min(MAX_WINDOW, window)),
        "auto_rollback": bool(cfg.get("known_good", "auto_rollback",
                                      default=False)),
    }


def save_settings(body: dict) -> dict:
    """Сохранить известные поля ``known_good`` (остальное игнорируется)."""
    cfg = _cfg()
    window = None
    if "window_sec" in body:
        try:
            window = int(body["window_sec"])
        except (TypeError, ValueError):
            return {"ok": False, "error": "window_sec — целое число секунд"}
    if "enabled" in body:
        cfg.set("known_good", "enabled", bool(body["enabled"]))
    if "auto_rollback" in body:
        cfg.set("known_good", "auto_rollback", bool(body["auto_rollback"]))
    if window is not None:
        cfg.set("known_good", "window_sec",
                max(MIN_WINDOW, min(MAX_WINDOW, window)))
    cfg.save()
    return {"ok": True, "settings": settings()}


def _state_path() -> str:
    return os.path.join(_cfg().config_dir, "known-good.json")


def _read() -> dict:
    try:
        with open(_state_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    from core.safe_io import atomic_write_text
    # atomic_write_* оставляет права mkstemp (0600) — ключи туннелей.
    atomic_write_text(_state_path(),
                      json.dumps(data, ensure_ascii=False, indent=1))


# ─────────────────────────── снимок ────────────────────────────

def _manager(kind: str):
    if kind == "awg":
        from core.awg_manager import get_awg_manager
        return get_awg_manager()
    if kind == "singbox":
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager()
    from core.mihomo_manager import get_mihomo_manager
    return get_mihomo_manager()


# Расширения конфигов по видам — как в list_configs() менеджеров.
_EXTS = {"awg": (".conf",), "singbox": (".json",),
         "mihomo": (".yaml", ".yml")}

# path → (size, mtime_ns, text): тик раз в минуту не перечитывает файлы,
# которые не менялись.
_text_cache = {}


def _dirs(kind: str) -> list:
    """Каталоги конфигов вида. Не ``list_configs()``: тот на каждый файл
    зовёт ``awg show``/``ip link`` и разбирает конфиг ради TUN — для тика
    раз в минуту это лишнее."""
    mgr = _manager(kind)
    if kind == "awg":
        return list(mgr._scan_dirs())
    return [mgr._platform().config_dir]


def _config_files() -> tuple:
    """``({path: {"kind", "name"}}, [виды, которые не прочитались])``."""
    out, errors = {}, []
    for kind in KINDS:
        try:
            for d in _dirs(kind):
                if not d or not os.path.isdir(d):
                    continue
                for fn in sorted(os.listdir(d)):
                    if fn.startswith(".") or not fn.endswith(_EXTS[kind]):
                        continue
                    path = os.path.join(d, fn)
                    if path not in out and os.path.isfile(path):
                        out[path] = {"kind": kind,
                                     "name": fn.rsplit(".", 1)[0]}
        except Exception:                           # noqa: BLE001 — граница
            errors.append(kind)
    return out, errors


def _read_text(path: str):
    """Текст конфига; None — слишком большой или не читается."""
    try:
        st = os.stat(path)
        if st.st_size > MAX_FILE_BYTES:
            return None
        key = (st.st_size, st.st_mtime_ns)
        hit = _text_cache.get(path)
        if hit and hit[0] == key:
            return hit[1]
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return None
    _text_cache[path] = (key, text)
    return text


def collect() -> dict:
    """Текущее состояние: маршруты и тексты конфигов туннелей.

    ``errors`` — виды, чьи каталоги не прочитались: такой снимок неполон,
    по нему нельзя ни судить, ни откатывать (пропавшие из него файлы
    выглядели бы удалёнными).
    """
    routes = _cfg().get("unified_routes")
    routes = routes if isinstance(routes, list) else []
    listed, errors = _config_files()
    files = {}
    for path, meta in listed.items():
        text = _read_text(path)
        if text is not None:
            files[path] = dict(meta, text=text)
    return {"routes": list(routes), "files": files, "errors": errors}


def fingerprint(snap: dict) -> str:
    """Отпечаток снимка (чистая функция)."""
    body = {"routes": snap.get("routes") or [],
            "files": {p: f.get("text", "")
                      for p, f in sorted((snap.get("files") or {}).items())}}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def diff_summary(good: dict, cur: dict) -> dict:
    """Что изменилось с рабочей точки (чистая функция): имена, без текста."""
    gf, cf = good.get("files") or {}, cur.get("files") or {}

    def _label(meta, path):
        return "%s %s" % (meta.get("kind", ""), meta.get("name")
                          or os.path.basename(path))

    changed = sorted(_label(cf[p], p) for p in cf
                     if p in gf and gf[p].get("text") != cf[p].get("text"))
    added = sorted(_label(cf[p], p) for p in cf if p not in gf)
    removed = sorted(_label(gf[p], p) for p in gf if p not in cf)
    return {"routes_changed": (good.get("routes") or [])
            != (cur.get("routes") or []),
            "files_changed": changed, "files_added": added,
            "files_removed": removed}


# ─────────────────────────── решение ────────────────────────────

def judge(good_probe: dict, probe: dict) -> dict:
    """Вердикт окна наблюдения (чистая функция).

    ``promote`` — ничего из открывавшегося на рабочей точке не потерялось.
    Без сайтов мониторинга судить нечем: состояние принимается, но
    помечается непроверенным.
    """
    from core.safe_apply import compare
    if not probe.get("total"):
        return {"promote": True, "verified": False, "lost": []}
    if not good_probe or not good_probe.get("ok"):
        # Рабочая точка без единого открывшегося сайта — сравнивать не с
        # чем; хоть что-то открылось — уже лучше.
        return {"promote": bool(probe.get("ok")), "verified": True,
                "lost": []}
    # Сайты, которых нет в одном из замеров (список мониторинга поменяли
    # после рабочей точки), не судятся: их «пропажа» — не от правки.
    common = set(good_probe.get("sites") or {}) & set(probe.get("sites")
                                                      or {})
    cmp = compare(
        {"sites": {k: v for k, v in good_probe["sites"].items()
                   if k in common}},
        {"sites": {k: v for k, v in probe["sites"].items() if k in common}})
    return {"promote": not cmp["lost"], "verified": True,
            "lost": cmp["lost"]}


def _probe() -> dict:
    from core.safe_apply import probe
    return probe()


def _wan_down() -> bool:
    from core import reachability
    return reachability.wan_down()


def _notify(text: str) -> None:
    try:
        from core import notify
        notify.event("known_good", text)
    except Exception:                               # noqa: BLE001
        pass


def _point(snap: dict, fp: str, probe: dict, note: str,
           verified: bool = True, now: float = None) -> dict:
    now = time.time() if now is None else now
    return {"ts": now, "probe_ts": now, "fp": fp, "note": note,
            "verified": verified, "probe": probe,
            "routes": snap["routes"], "files": snap["files"]}


def _refresh_probe(fp: str, now: float) -> None:
    """Обновить пробу рабочей точки, пока состояние с ней совпадает.

    Правка судится сравнением с этой пробой; недельной давности она
    приписала бы правке всё, что отвалилось само (сайт закрылся, сервис
    сменил адрес).
    """
    probe = _probe()
    with _lock:
        data = _read()
        good = data.get("good") or {}
        if good.get("fp") != fp:
            return
        good["probe"], good["probe_ts"] = probe, now
        data["good"] = good
        _write(data)


def tick(now: float = None) -> dict:
    """Один шаг наблюдения. Возвращает, что произошло (для тестов и логов)."""
    st = settings()
    if not st["enabled"]:
        return {"action": "disabled"}
    from core import safe_apply
    if safe_apply.active():
        # Идёт проверка стратегии — её пробы и её откат важнее.
        return {"action": "busy"}
    now = time.time() if now is None else now
    snap = collect()
    if snap["errors"]:
        return {"action": "incomplete", "errors": snap["errors"]}
    fp = fingerprint(snap)
    with _lock:
        data = _read()
        good = data.get("good") or {}
        cand = data.get("candidate") or {}
        if good.get("fp") == fp:
            if cand:
                data.pop("candidate", None)
                _write(data)
            stale = now - float(good.get("probe_ts") or good.get("ts")
                                or 0) >= PROBE_REFRESH
        else:
            stale = None
    if stale is not None:
        if stale and not _wan_down():
            _refresh_probe(fp, now)
            return {"action": "same", "refreshed": True}
        return {"action": "same"}
    with _lock:
        data = _read()
        good = data.get("good") or {}
        cand = data.get("candidate") or {}
        baseline = not good
        if not baseline:
            if fp in (data.get("failed") or []):
                return {"action": "known_bad"}
            if cand.get("fp") != fp:
                data["candidate"] = {"fp": fp, "since": now}
                _write(data)
                return {"action": "watching"}
            if now - float(cand.get("since") or now) < st["window_sec"]:
                return {"action": "watching"}
    if baseline:
        # Первый запуск: судить не с чем — текущее и есть точка отсчёта.
        point = _point(snap, fp, _probe(), "первый снимок", now=now)
        with _lock:
            data = _read()
            if not data.get("good"):
                data["good"] = point
                _write(data)
        return {"action": "baseline"}
    if _wan_down():
        return {"action": "wan_down"}
    probe = _probe()
    with _lock:
        data = _read()
        good = data.get("good") or {}
        verdict = judge(good.get("probe") or {}, probe)
        if verdict["promote"]:
            data["good"] = _point(snap, fp, probe, "проверено окном",
                                  verdict["verified"], now=now)
            data.pop("candidate", None)
            data.pop("last_failure", None)
            _write(data)
            log.info("Туннели и маршруты: новая рабочая точка (%s)"
                     % ("проверено" if verdict["verified"]
                        else "сайтов мониторинга нет — без проверки"),
                     source=SOURCE)
            return {"action": "promoted", "verified": verdict["verified"]}
        failed = [f for f in (data.get("failed") or []) if f != fp]
        data["failed"] = (failed + [fp])[-MAX_FAILED:]
        data.pop("candidate", None)
        data["last_failure"] = {"ts": now, "fp": fp, "lost": verdict["lost"],
                                "changes": diff_summary(good, snap)}
        auto = st["auto_rollback"] and not good.get("auto_rolled_back")
        if auto:
            good["auto_rolled_back"] = True
            data["good"] = good
        _write(data)
    lost = ", ".join(verdict["lost"][:5])
    log.warning("Туннели и маршруты: после правки не открываются %s"
                % lost, source=SOURCE)
    if auto:
        res = rollback(reason="авто")
        _notify("↩️ После правки туннелей/маршрутов перестали открываться "
                "%s — вернул рабочую точку%s"
                % (lost, "" if res.get("ok") else
                   " с ошибками: %s" % res.get("error", "")))
        return {"action": "rolled_back", "lost": verdict["lost"],
                "result": res}
    _notify("⚠️ После правки туннелей/маршрутов перестали открываться %s. "
            "Вернуть рабочую точку: «Маршрутизация → Рабочая точка»."
            % lost)
    return {"action": "failed", "lost": verdict["lost"]}


# ─────────────────────────── действия ────────────────────────────

def status() -> dict:
    data = _read()
    good = data.get("good") or {}
    out = {"settings": settings(), "has_good": bool(good)}
    if good:
        out["good"] = {k: good.get(k) for k in ("ts", "fp", "note",
                                                "verified")}
        probe = good.get("probe") or {}
        out["good"]["probe"] = {"ok": probe.get("ok", 0),
                                "total": probe.get("total", 0)}
        cur = collect()
        fp = fingerprint(cur)
        out["current_fp"] = fp
        out["matches_good"] = fp == good.get("fp")
        if fp != good.get("fp"):
            out["changes"] = diff_summary(good, cur)
    cand = data.get("candidate") or {}
    if cand:
        left = cand.get("since", 0) + settings()["window_sec"] - time.time()
        out["candidate"] = {"fp": cand.get("fp"), "since": cand.get("since"),
                            "judged_in_sec": max(0, int(left))}
    if data.get("last_failure"):
        out["last_failure"] = data["last_failure"]
    return out


def promote(note: str = "") -> dict:
    """«Отметить рабочим»: текущее состояние — новая рабочая точка."""
    snap = collect()
    if snap["errors"]:
        return {"ok": False, "error": "не прочитались конфиги: %s — "
                                      "снимок был бы неполным"
                                      % ", ".join(snap["errors"])}
    fp = fingerprint(snap)
    probe = _probe()
    with _lock:
        data = _read()
        data["good"] = _point(snap, fp, probe, note or "отмечено вручную")
        data.pop("candidate", None)
        data.pop("last_failure", None)
        data["failed"] = [f for f in (data.get("failed") or []) if f != fp]
        _write(data)
    return {"ok": True, "fp": fp,
            "probe": {"ok": probe["ok"], "total": probe["total"]}}


def _restart_tunnel(kind: str, name: str, path: str) -> str:
    """Перезапустить туннель, если он поднят. Ошибка — строкой."""
    mgr = _manager(kind)
    if kind == "awg":
        running = False
        for it in mgr.list_configs() or []:
            if it.get("path") == path:
                running = bool(it.get("active"))
        if not running:
            return ""
    elif not mgr.is_running(name):
        return ""
    res = mgr.restart(name) or {}
    return "" if res.get("ok", True) else "%s %s: %s" % (
        kind, name, res.get("error") or "не перезапустился")


def _restore_routes(good_routes: list, cur_routes: list) -> None:
    """Маршруты — к рабочей точке, вместе с тем, что они разложили в ядре.

    Добавленные после точки удаляются как обычно (``delete_route`` снимает
    их правила и ipset'ы — одна перезапись списка оставила бы их в ядре);
    изменённые теряют историю монитора и failover — она про другой
    маршрут.
    """
    from core.unified import failover, manager, monitor, storage
    good_by_id = {r.get("id"): r for r in good_routes}
    cur_by_id = {r.get("id"): r for r in cur_routes}
    for rid in cur_by_id:
        if rid not in good_by_id:
            manager.delete_route(rid)
    storage.replace_all(good_routes)
    for rid, route in good_by_id.items():
        if cur_by_id.get(rid) != route:
            failover.reset(rid)
            monitor.clear(rid)
    manager.apply_all()


def rollback(reason: str = "") -> dict:
    """Вернуть маршруты и конфиги туннелей к рабочей точке.

    Новые конфиги, которых на рабочей точке не было, не трогаются: они
    ничего не ломают, пока не подняты, а удалить чужую работу — хуже.
    Удалённые после рабочей точки — возвращаются. Виды, чьи каталоги
    сейчас не прочитались, пропускаются: их файлы только выглядят
    пропавшими.
    """
    from core.safe_io import atomic_write_text
    good = (_read().get("good") or {})
    if not good:
        return {"ok": False, "error": "рабочей точки ещё нет"}
    cur = collect()
    restored, errors = [], []
    for path, meta in (good.get("files") or {}).items():
        if meta.get("kind") in cur["errors"]:
            errors.append("%s %s: каталог не прочитался — не тронут"
                          % (meta.get("kind"), meta.get("name")))
            continue
        now = (cur["files"].get(path) or {}).get("text")
        if now == meta.get("text"):
            continue
        try:
            atomic_write_text(path, meta.get("text", ""))
        except OSError as e:
            errors.append("%s: %s" % (path, e))
            continue
        restored.append("%s %s" % (meta.get("kind"), meta.get("name")))
        err = _restart_tunnel(meta.get("kind"), meta.get("name"), path)
        if err:
            errors.append(err)
    if (good.get("routes") or []) != cur["routes"]:
        try:
            _restore_routes(list(good.get("routes") or []), cur["routes"])
        except Exception as e:                      # noqa: BLE001 — граница
            errors.append("маршруты: %s" % e)
        restored.append("маршруты единого слоя")
    with _lock:
        data = _read()
        data.pop("candidate", None)
        data.pop("last_failure", None)
        _write(data)
    log.info("Туннели и маршруты: возврат к рабочей точке%s — %s"
             % (" (%s)" % reason if reason else "",
                ", ".join(restored) or "всё уже совпадало"), source=SOURCE)
    return {"ok": not errors, "restored": restored,
            "error": "; ".join(errors)}


# ─────────────────────────── фон ────────────────────────────

def _loop() -> None:
    while not _stop.wait(TICK_SEC):
        try:
            tick()
        except Exception as e:                      # noqa: BLE001 — граница
            log.warning("Рабочая точка туннелей: %s" % e, source=SOURCE)


def start() -> None:
    """Фоновое наблюдение (из загрузки приложения)."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="known-good",
                               daemon=True)
    _thread.start()
