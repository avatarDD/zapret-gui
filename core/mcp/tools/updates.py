# core/mcp/tools/updates.py
"""
Версии движков и доступные обновления.

По умолчанию инструмент **не ходит в сеть**: он отдаёт последнюю
сохранённую проверку, сверенную с диском (`update_checker
.get_cached_results`). «Установлен» там пересчитывается каждый раз —
файл, найденный вчера, мог исчезнуть, — а «последняя версия» остаётся
из кеша, потому что за ней надо в GitHub.

Свежая проверка — это исходящие запросы с роутера, то есть то же
разрешение `probes`, что и у сетевой части `diagnostics_run`. Граница
одна и та же: выпустить трафик — не то же самое, что прочитать
состояние. Без разрешения `refresh: true` не отказывает, а честно
отдаёт кеш и объясняет, чего не хватило: на роутере без интернета
инструмент не должен ни подвешивать GUI, ни оставлять модель без
ответа.
"""

import time

from core.mcp import permissions as perms_mod
from core.mcp.registry import tool
from core.mcp.tools import _paging


# Возраст кеша, после которого он перестаёт быть ответом на вопрос
# «есть ли обновления». Проверка ходит в GitHub и кешируется на сутки.
STALE_SEC = 24 * 3600


@tool(
    name="updates_check",
    scope="read",
    mutating=False,
    title="Engine versions and updates",
    description=("Installed versions of zapret2, sing-box, mihomo, "
                 "AmneziaWG, usque, Telegram proxy, Opera Proxy and the "
                 "GUI, plus what is newer upstream (pinned rows: "
                 "`upstream_latest`/`upstream_newer`). Cached; refresh "
                 "needs `probes`. / Версии движков и доступные "
                 "обновления (из кеша)."),
    schema={
        "type": "object",
        "properties": {
            "refresh": {
                "type": "boolean",
                "description": ("Ask upstream now instead of using the "
                                "cache (needs `probes`). / Спросить "
                                "апстрим сейчас."),
                "default": False,
            },
            "updates_only": {
                "type": "boolean",
                "description": ("Only rows with an update (or a newer "
                                "upstream release than the pin). / Только "
                                "то, для чего есть обновление."),
                "default": False,
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0,
                       "description": "Window start. / Начало окна."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50,
                      "default": 25,
                      "description": "How many rows (1-50). / Сколько "
                                     "строк вернуть."},
        },
        "additionalProperties": False,
    },
)
def updates_check(args: dict) -> dict:
    """Что установлено и что из этого устарело."""
    from core import update_checker

    refresh = bool(args.get("refresh"))
    probes = perms_mod.granted("probes")
    refused = refresh and not probes

    report, network_error = _load(update_checker, refresh and probes)

    rows = [_row(r) for r in report.get("results") or []]
    if args.get("updates_only"):
        # и строки, где апстрим ушёл дальше пина: обновления через GUI
        # пока нет, но знать о нём — ровно то, о чём спрашивают
        rows = [r for r in rows
                if r["has_update"] or r.get("upstream_newer")]

    offset, limit = _paging.limits(args, default=25, maximum=50)
    result = _paging.page(rows, offset, limit)

    checked_at = int(report.get("checked_at") or 0)
    age = int(time.time() - checked_at) if checked_at else 0
    result.update({
        "updates_count": report.get("updates_count", 0),
        "checked_at": checked_at,
        "age_sec": age,
        "from_cache": not (refresh and probes),
        "stale": bool(not checked_at or age > STALE_SEC),
        "refresh": {
            "requested": refresh,
            "done": refresh and probes and not network_error,
            "permission": "probes",
            "error": network_error,
        },
    })

    result["daemon"] = _daemon(update_checker)
    # S13: обновление GUI затирает локальные правки кода. Сказать об
    # этом надо ДО обновления — после говорить уже не о чем.
    result["local_code_changes"] = _local_code_changes()

    if not checked_at:
        result["reason"] = ("апстрим ни разу не опрашивался: сравнивать "
                            "не с чем, поэтому таблица пуста")
    result["hint"] = _hint(refused, network_error, checked_at, age,
                           report.get("updates_count", 0))
    ahead = ["%s %s" % (r["name"], r["upstream_latest"].lstrip("vV"))
             for r in (_row(x) for x in report.get("results") or [])
             if r.get("upstream_newer")]
    if ahead:
        more = ("у апстрима новее закреплённой версии (GUI её пока не "
                "ставит): " + ", ".join(ahead))
        result["hint"] = "; ".join(p for p in (result["hint"], more) if p)
    return result


# ───────────────────────────── частности ────────────────────────────

def _load(update_checker, do_refresh) -> tuple:
    """Кеш или свежая проверка; сетевой сбой — не отказ инструмента."""
    if do_refresh:
        try:
            return update_checker.check_all(), ""
        except Exception as e:                  # noqa: BLE001 — граница
            # Роутер без интернета — штатная ситуация, а не ошибка
            # вызова: отдаём кеш и говорим, почему он кеш.
            error = "%s: %s" % (type(e).__name__, e)
            return update_checker.get_cached_results(), error
    return update_checker.get_cached_results(), ""


def _local_code_changes() -> dict:
    """Правки кода, которые переживут всё, кроме обновления GUI."""
    try:
        from core.code_editor import local_changes_warning
        return local_changes_warning()
    except Exception:                           # noqa: BLE001 — граница
        return {"count": 0, "files": []}


def _daemon(update_checker) -> dict:
    """Состояние фонового сторожа обновлений — он и наполняет кеш."""
    try:
        status = update_checker.get_update_checker().get_status()
    except Exception:                           # noqa: BLE001 — граница
        return {"running": False, "checking": False, "stale_check": False}
    return {"running": bool(status.get("running")),
            "checking": bool(status.get("checking")),
            "stale_check": bool(status.get("stale_check"))}


def _row(entry) -> dict:
    """Одна строка таблицы обновлений, без внутренних полей страницы."""
    row = {
        "name": entry.get("name", ""),
        "installed": bool(entry.get("installed")),
        "current": entry.get("current", ""),
        "latest": entry.get("latest", ""),
        "has_update": bool(entry.get("has_update")),
        "path": entry.get("path", ""),
        "installed_at": entry.get("path_mtime", 0),
        # Путь, по которому файл лежал и исчез: иначе самокоррекция
        # кеша выглядит так, будто GUI ничего и не находил.
        "vanished_path": entry.get("vanished_path", ""),
        "error": entry.get("error", ""),
    }
    # Закреплённая версия (geneva, tg-ws-proxy): «последняя» — пин, а
    # правду об апстриме несут эти поля. Без них «1.1.1 = 1.1.1» при
    # вышедшей 1.2.0 читается как «новее нет».
    if entry.get("pinned"):
        row["pinned"] = True
        row["upstream_latest"] = entry.get("upstream_latest", "")
        row["upstream_newer"] = bool(entry.get("upstream_newer"))
        row["pin_reason"] = entry.get("pin_reason", "")
    for key in ("latest_source", "note"):
        if entry.get(key):
            row[key] = entry[key]
    return row


def _hint(refused, network_error, checked_at, age, updates) -> str:
    """Чему верить в этом ответе."""
    parts = []
    if refused:
        parts.append("свежая проверка требует разрешения «probes» — "
                     "отдан кеш")
    if network_error:
        parts.append("апстрим не ответил (%s) — отдан кеш" % network_error)
    if not checked_at:
        parts.append("кеша нет, таблица пуста; установленные версии "
                     "туннелей отдаёт tunnels_status, движка обхода — "
                     "nfqws_status, GUI — system_status")
    elif age > STALE_SEC:
        parts.append("кешу больше суток (%d ч)" % (age // 3600))
    if updates and not parts:
        parts.append("обновлений: %d" % updates)
    return "; ".join(parts)
