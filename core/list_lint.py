# core/list_lint.py
"""
Проверка хостлистов nfqws2: мусор в записях и конфликты между списками.

## Зачем

Список, набранный руками или склеенный из чужих, обычно «работает» — но
часть записей в нём мёртвая, и по nfqws2 этого не видно:

* ``*.example.com`` — wildcard'ов nfqws2 не знает и сравнивает строку
  буквально: запись не срабатывает никогда (поддомены он покрывает сам);
* ``https://example.com/path``, ``Example.COM``, ``www.example.com`` —
  nfqws2 сравнивает с SNI/Host, так запись тоже не совпадёт или совпадёт
  уже, чем задумано;
* повторы и поддомены, уже покрытые родителем в том же списке, —
  безвредны, но раздувают файл, который nfqws2 держит в памяти;
* один и тот же домен в обходе и в исключениях (``--hostlist-exclude``,
  ``netrogat``) — исключение побеждает, и «я же добавил сайт в список»
  не работает.

Приём nfqws2-ui («Проверка записей» + «Дубликаты и конфликты»). Здесь —
чистые функции (:func:`lint_entries`, :func:`fix_entries`,
:func:`cross_check`); чтение файлов и стратегии — в :func:`report`.

Исправление меняет только то, что можно исправить без потери смысла:
нормализует запись тем же ``HostlistManager.normalize_domain``, что и
ввод в GUI, убирает повторы и покрытые родителем поддомены. Нераспознанное
не удаляется — его называет отчёт, решает человек.
"""

from __future__ import annotations

import os

# Коды — стабильные символы для UI и тестов.
CODE_WILDCARD = "wildcard"          # *.example.com / .example.com
CODE_NOT_NORMAL = "not_normalized"  # URL, регистр, www., порт, кириллица
CODE_INVALID = "invalid"            # не домен и не IPv4
CODE_DUPLICATE = "duplicate"        # повтор в том же списке
CODE_COVERED = "covered_by_parent"  # поддомен при родителе в том же списке
CODE_CROSS_DUP = "in_several_lists"
CODE_CONFLICT = "bypass_and_exclude"

TITLES = {
    CODE_WILDCARD: "маска «*.» — nfqws2 её не понимает, поддомены покрывает сам",
    CODE_NOT_NORMAL: "запись в другом виде, чем её сравнивает nfqws2",
    CODE_INVALID: "не похоже на домен",
    CODE_DUPLICATE: "повтор",
    CODE_COVERED: "поддомен уже покрыт родителем",
    CODE_CROSS_DUP: "одна запись в нескольких списках",
    CODE_CONFLICT: "сайт и в обходе, и в исключениях — исключение побеждает",
}

# Сколько примеров на код отдавать в отчёте: в списке на 50 тысяч строк
# тысячи повторов не нужны ни глазу, ни ответу API.
SAMPLE = 20


def _normalizer():
    from core.hostlist_manager import get_hostlist_manager
    return get_hostlist_manager().normalize_domain


# Префиксы записи хостлиста nfqws2: «^» — строго, «!» — исключение (1.0.7).
_PREFIXES = ("^", "!")


def _parents(domain: str):
    """b.example.com, example.com, com для a.b.example.com.

    TLD — тоже родитель: nfqws2 проходит все суффиксы имени
    (nfq2/hostlist.c), и запись «xn--p1ai» в исключениях снимает обход со
    всех сайтов .рф.
    """
    parts = domain.split(".")
    for i in range(1, len(parts)):
        yield ".".join(parts[i:])


def lint_entries(entries, normalize=None) -> dict:
    """Замечания по одному списку.

    Args:
        entries: строки списка (без комментариев и пустых).
        normalize: ``normalize_domain`` (для тестов — подмена).

    Returns:
        {"total", "issues": {code: {"count", "samples": [{"entry", "fix"}]}},
         "fixable": int} — fixable: сколько строк уйдёт или изменится
        при :func:`fix_entries`.
    """
    normalize = normalize or _normalizer()
    issues: dict = {}

    def add(code, entry, fix=None):
        slot = issues.setdefault(code, {"count": 0, "samples": []})
        slot["count"] += 1
        if len(slot["samples"]) < SAMPLE:
            slot["samples"].append({"entry": entry, "fix": fix})

    seen = set()
    normalized = []
    changed = 0            # строк, которые «Исправить» перепишет на месте
    total = 0
    for raw in entries or ():
        entry = str(raw).strip()
        if not entry or entry.startswith("#"):
            continue
        total += 1
        norm = normalize(entry)
        if norm is None:
            add(CODE_INVALID, entry)
            continue
        if norm in seen:
            add(CODE_DUPLICATE, entry)
            continue
        if entry.lstrip("^!").startswith(("*.", ".")):
            add(CODE_WILDCARD, entry, norm)
            changed += 1
        elif norm != entry:
            add(CODE_NOT_NORMAL, entry, norm)
            changed += 1
        seen.add(norm)
        normalized.append(norm)

    # «^» — без поддоменов, «!» — исключение (zapret2 1.0.7): ни то, ни
    # другое не покрывает поддомены и само «покрытым» не бывает —
    # «!vk.com» под «com» как раз и нужен.
    plain = {d for d in normalized if not d.startswith(_PREFIXES)}
    covered = 0
    for domain in normalized:
        if domain.startswith(_PREFIXES):
            continue
        parent = next((p for p in _parents(domain) if p in plain), None)
        if parent:
            add(CODE_COVERED, domain, parent)
            covered += 1

    # Одна строка — одно действие: повтор, который ещё и с маской, уйдёт
    # один раз, а не «исправится и удалится».
    duplicates = issues.get(CODE_DUPLICATE, {}).get("count", 0)
    return {"total": total, "issues": issues,
            "fixable": changed + duplicates + covered}


def fix_lines(lines, normalize=None) -> list:
    """Как :func:`fix_entries`, но по строкам файла: комментарии и пустые
    строки остаются на своих местах (их пишут для себя — «# банки»)."""
    normalize = normalize or _normalizer()
    keep = set(fix_entries(lines, normalize=normalize))
    out = []
    emitted = set()
    for raw in lines or ():
        line = str(raw).rstrip("\n")
        entry = line.strip()
        if not entry or entry.startswith("#"):
            out.append(line)
            continue
        norm = normalize(entry)
        value = norm if norm is not None else entry
        if value in keep and value not in emitted:
            emitted.add(value)
            out.append(value)
    return out


def fix_entries(entries, normalize=None) -> list:
    """Исправленный список: нормализованные записи без повторов и
    покрытых родителем поддоменов. Нераспознанные строки остаются как
    есть — удалять то, чего не поняли, нельзя.
    """
    normalize = normalize or _normalizer()
    out = []
    seen = set()
    for raw in entries or ():
        entry = str(raw).strip()
        if not entry or entry.startswith("#"):
            continue
        norm = normalize(entry)
        value = norm if norm is not None else entry
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    plain = {d for d in out if not d.startswith(_PREFIXES)}
    return [d for d in out
            if d.startswith(_PREFIXES)
            or not any(p in plain for p in _parents(d))]


def cross_check(lists: dict, excludes=(), normalize=None,
                bypass=None) -> dict:
    """Конфликты между списками.

    Args:
        lists: {имя: [записи]}.
        excludes: имена списков-исключений (``--hostlist-exclude``).
        bypass: имена списков обхода, которые реально читает стратегия;
            None — все, что не исключения. Список, который стратегия не
            читает, с исключениями не конфликтует.

    Returns:
        {"duplicates": [{"entry", "lists"}], "conflicts":
         [{"entry", "bypass", "exclude", "exclude_entry"}]}
    """
    normalize = normalize or _normalizer()
    excludes = set(excludes or ())
    where: dict = {}
    for name, entries in (lists or {}).items():
        for raw in entries or ():
            norm = normalize(str(raw).strip()) if str(raw).strip() else None
            if norm:
                where.setdefault(norm, set()).add(name)

    duplicates = [{"entry": e, "lists": sorted(names)}
                  for e, names in sorted(where.items()) if len(names) > 1]

    # Исключение покрывает запись, если совпадает с ней или с её
    # родителем; строгое «^имя» — только саму запись. Поиск по множеству,
    # а не перебором пар: в списке бывают десятки тысяч строк.
    exclude_hits: dict = {}
    for entry, names in where.items():
        for name in names & excludes:
            exclude_hits.setdefault(entry, []).append(name)

    conflicts = []
    bypass_set = None if bypass is None else set(bypass)
    for entry, names in sorted(where.items()):
        if entry.startswith("!"):
            continue                # исключение внутри списка — не обход
        by = names - excludes
        if bypass_set is not None:
            by &= bypass_set
        if not by:
            continue
        bare = entry.lstrip("^")
        for cand in [bare, "^" + bare] + list(_parents(bare)):
            for ex_name in exclude_hits.get(cand, ()):
                conflicts.append({"entry": entry, "bypass": sorted(by),
                                  "exclude": ex_name,
                                  "exclude_entry": cand})
    return {"duplicates": duplicates, "conflicts": conflicts}


# ---------------------------------------------------------------------------
# I/O: какие списки читает текущая стратегия
# ---------------------------------------------------------------------------

def _list_name(path: str) -> str:
    base = os.path.basename(str(path).strip().strip("\"'"))
    return base[:-4] if base.endswith(".txt") else base


def strategy_list_usage(argv) -> dict:
    """{имя списка: "bypass" | "exclude"} по argv стратегии."""
    usage: dict = {}
    for arg in argv or ():
        arg = str(arg)
        for flag, kind in (("--hostlist-exclude=", "exclude"),
                           ("--hostlist=", "bypass"),
                           ("--hostlist-auto=", "bypass")):
            if arg.startswith(flag):
                for path in arg[len(flag):].split(","):
                    if path.strip():
                        name = _list_name(path)
                        # exclude сильнее: тот же файл исключением —
                        # это и есть конфликт, его видно по cross_check.
                        if usage.get(name) != "exclude":
                            usage[name] = kind
    return usage


def _current_argv() -> list:
    """argv активной стратегии: собранный заново, иначе — последний запуск.

    Плюс ``--hostlist`` единого слоя (``nfqws.unified_hostlist``): его
    дописывает в командную строку nfqws_manager, а не сборщик стратегии.
    """
    extra = []
    try:
        from core.unified import nfqws_hostlist
        extra = list(nfqws_hostlist.compose_extra_args() or [])
    except Exception:                               # noqa: BLE001 — граница
        extra = []
    return _strategy_argv() + extra


def _strategy_argv() -> list:
    try:
        from core.config_manager import get_config_manager
        from core.strategy_builder import get_strategy_manager
        sid = get_config_manager().get("strategy", "current_id")
        if sid:
            sm = get_strategy_manager()
            strategy = sm.get_strategy(sid)
            if strategy:
                return list(sm.build_nfqws_args(strategy) or [])
    except Exception:                               # noqa: BLE001 — граница
        pass
    try:
        from core.nfqws_manager import get_nfqws_manager
        return list(get_nfqws_manager().get_status().get("last_args") or [])
    except Exception:                               # noqa: BLE001 — граница
        return []


def report(names=None) -> dict:
    """Проверка всех (или перечисленных) хостлистов и конфликтов.

    Returns:
        {"lists": [{name, usage, total, fixable, issues}],
         "duplicates", "conflicts", "excludes"}
    """
    import functools
    from core.hostlist_manager import get_hostlist_manager
    hm = get_hostlist_manager()
    all_names = list(hm.list_names())
    names = [n for n in (names or all_names) if n in all_names]
    # Только то, что стратегия реально передаёт nfqws2: netrogat — тоже
    # (сборщик добавляет его при filter.protect_excluded, а не всегда).
    argv = _current_argv()
    usage = strategy_list_usage(argv)
    excludes = sorted(n for n, k in usage.items() if k == "exclude")
    bypass = sorted(n for n, k in usage.items() if k == "bypass")
    # Одна нормализация на запись: списки бывают на десятки тысяч строк.
    normalize = functools.lru_cache(maxsize=None)(hm.normalize_domain)

    contents = {n: hm.get_hostlist(n) for n in all_names}
    lists = []
    for name in names:
        res = lint_entries(contents[name], normalize=normalize)
        lists.append({"name": name, "usage": usage.get(name, ""),
                      "total": res["total"], "fixable": res["fixable"],
                      "issues": res["issues"]})
    cross = cross_check(contents, excludes, normalize=normalize,
                        bypass=bypass if argv else None)
    return {"lists": lists, "excludes": excludes, "titles": TITLES,
            "duplicates": cross["duplicates"][:200],
            "duplicates_total": len(cross["duplicates"]),
            "conflicts": cross["conflicts"][:200],
            "conflicts_total": len(cross["conflicts"])}


def fix_list(name: str) -> dict:
    """Исправить один список на диске, сохранив комментарии.

    Под замком менеджера на всё «прочитать → исправить → записать»: иначе
    параллельный add_domains (детектор, MCP) потерялся бы.

    Returns {ok, before, after, changed} — before/after в записях.
    """
    from core.hostlist_manager import get_hostlist_manager
    hm = get_hostlist_manager()
    if name not in hm.list_names():
        return {"ok": False, "error": "нет такого списка: %s" % name}
    path = hm._file_path(name)

    def count(lines):
        return sum(1 for x in lines
                   if x.strip() and not x.strip().startswith("#"))

    with hm._lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            return {"ok": False, "error": "не прочитать список: %s" % e}
        fixed = fix_lines(lines, normalize=hm.normalize_domain)
        if fixed == lines:
            return {"ok": True, "before": count(lines),
                    "after": count(lines), "changed": False}
        ok = hm._write_text(name, "\n".join(fixed) + "\n" if fixed else "")
    return {"ok": bool(ok), "before": count(lines), "after": count(fixed),
            "changed": bool(ok),
            "error": "" if ok else "не удалось записать список"}
