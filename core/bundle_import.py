# core/bundle_import.py
"""
Импорт бандла Zapret2_AutoTuner (``zapret-autotuner-bundle`` v1).

## Зачем

Текстовый импорт (``core/profile_import``) переносит только аргументы:
списки, блобы и lua приходится создавать руками, и о каждом сказано
отдельным предупреждением. Бандл — один JSON-файл, в котором AutoTuner
кладёт всё, что нужно подобранной стратегии: саму стратегию, hostlist'ы,
ipset'ы, блобы (base64) и lua-скрипты. Здесь он проверяется, сверяется с
тем, что уже есть на роутере, и сохраняется теми же менеджерами, что и
ручное создание.

## Что делается

* :func:`validate_bundle` — форма и лимиты (имена — по правилам наших
  менеджеров, блоб ≤ 64 КБ и не встроенный, args профиля без ``--new``).
* :func:`plan_bundle` — что будет создано и какие имена уже заняты.
  Чистая функция: занятые имена приходят аргументом.
* :func:`rename_map` + :func:`rewrite_args` — «переименовать» вместо
  «заменить»: новое имя получает и сам объект, и каждая ссылка на него в
  args (``lists/<имя>.txt``, ``blob=<имя>``, ``@lua/<имя>.lua``).
* :func:`apply_bundle` — запись. Стратегия только **сохраняется**:
  применяет её пользователь отдельной кнопкой, как любую другую.

Закрепления IP (``hosts_pins``) пока не импортируются — о них сказано
предупреждением.
"""

from __future__ import annotations

import base64
import binascii
import re

FORMAT = "zapret-autotuner-bundle"
FORMAT_VERSION = 1
# NFQWS2_COMPAT_VER_REQUIRED поставляемого zapret-lib.lua (см.
# core/asset_importer): другой номер — предупреждение, не отказ.
LUA_COMPAT = 6

MAX_BLOB = 65536
MAX_LUA = 1024 * 1024

_LIST_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_LUA_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")
_STRATEGY_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
# Аргументы lua-функций, значение которых — имя блоба.
_BLOB_ARGS = ("blob", "pattern", "seqovl_pattern")


def _ipset_name_ok(name: str) -> bool:
    from core.ipset_manager import IPSET_NAMESPACE_RE
    return bool(_LIST_RE.match(name or "")) and bool(
        IPSET_NAMESPACE_RE.match(name))


def _hostlist_name_ok(name: str) -> bool:
    from core.hostlist_manager import BUILTIN_NAMES, IPSET_NAME_RE
    return (bool(_LIST_RE.match(name or ""))
            and not IPSET_NAME_RE.match(name)
            and name not in BUILTIN_NAMES)


def _lua_stem(name: str) -> str:
    return name[:-4] if name.endswith(".lua") else name


def _items(data: dict, key: str) -> list:
    v = data.get(key)
    return v if isinstance(v, list) else []


# ─────────────────────── validate ─────────────────────────────────────

def validate_bundle(data) -> tuple:
    """(ошибки, предупреждения). Пустой список ошибок — бандл годен."""
    errors, warnings = [], []
    if not isinstance(data, dict):
        return ["Бандл должен быть JSON-объектом"], []
    if data.get("format") != FORMAT:
        return ["Это не бандл AutoTuner (format != %s)" % FORMAT], []
    fv = data.get("format_version")
    if not isinstance(fv, int) or fv < 1:
        errors.append("format_version должен быть целым числом ≥ 1")
    elif fv > FORMAT_VERSION:
        errors.append("бандл версии %d новее поддерживаемой (%d): обновите "
                      "zapret-gui" % (fv, FORMAT_VERSION))
    compat = data.get("zapret2_compat")
    if isinstance(compat, int) and compat != LUA_COMPAT:
        warnings.append("стратегия подобрана для lua zapret2 версии "
                        "совместимости %d, здесь %d — проверьте её перед "
                        "применением" % (compat, LUA_COMPAT))
    for key in ("hostlists", "ipsets", "blobs", "lua", "hosts_pins"):
        if key in data and not isinstance(data[key], list):
            errors.append("секция '%s' должна быть списком" % key)

    strategy = data.get("strategy")
    if not isinstance(strategy, dict):
        errors.append("нет секции strategy")
    else:
        sid = strategy.get("id")
        if not isinstance(sid, str) or not _STRATEGY_ID_RE.match(sid):
            errors.append("strategy.id должен быть [a-zA-Z0-9_-]{1,64}")
        if not strategy.get("name"):
            errors.append("strategy.name обязателен")
        profiles = strategy.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            errors.append("strategy.profiles — непустой список")
        else:
            for i, p in enumerate(profiles, 1):
                if not isinstance(p, dict) or not isinstance(
                        p.get("args"), str) or not p.get("id"):
                    errors.append("профиль %d: нужны id и args" % i)
                elif re.search(r"(?:^|\s)--new(?:\s|=|$)", p["args"]):
                    errors.append("профиль %d: --new в args профиля "
                                  "недопустим" % i)
                elif "--dpi-desync" in p["args"]:
                    errors.append("профиль %d: синтаксис nfqws v1 "
                                  "(--dpi-desync)" % i)

    for h in _items(data, "hostlists"):
        name = h.get("name") if isinstance(h, dict) else None
        if not _hostlist_name_ok(name or ""):
            errors.append("hostlist '%s': недопустимое имя" % name)
        elif not isinstance(h.get("domains"), list):
            errors.append("hostlist %s: domains — список" % name)
    for s in _items(data, "ipsets"):
        name = s.get("name") if isinstance(s, dict) else None
        if not _ipset_name_ok(name or ""):
            errors.append("ipset '%s': имя вне пространства IP-списков "
                          "(ipset-*, my-ipset*, *-ipset)" % name)
        elif not isinstance(s.get("cidrs"), list):
            errors.append("ipset %s: cidrs — список" % name)
    for b in _items(data, "blobs"):
        name = b.get("name") if isinstance(b, dict) else None
        if not isinstance(name, str) or not _IDENT_RE.match(name):
            errors.append("блоб '%s': имя — идентификатор Lua" % name)
            continue
        if name.startswith("fake_default_"):
            errors.append("блоб %s: имя встроенного блоба" % name)
            continue
        raw = blob_bytes(b)
        if raw is None:
            errors.append("блоб %s: base64 не разбирается" % name)
        elif not 0 < len(raw) <= MAX_BLOB:
            errors.append("блоб %s: %d байт, допустимо 1…%d"
                          % (name, len(raw), MAX_BLOB))
    for item in _items(data, "lua"):
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not _LUA_RE.match(name) \
                or name in (".", ".."):
            errors.append("lua '%s': недопустимое имя" % name)
        elif not isinstance(item.get("text"), str) or len(
                item["text"].encode("utf-8")) > MAX_LUA:
            errors.append("lua %s: текст до 1 МиБ" % name)
    if _items(data, "hosts_pins"):
        warnings.append("закрепления IP (hosts_pins) не импортируются: "
                        "задайте их на роутере вручную")
    return errors, warnings


def blob_bytes(item: dict):
    try:
        return base64.b64decode(item.get("base64") or "", validate=True)
    except (binascii.Error, ValueError, TypeError):
        return None


# ─────────────────────── plan ─────────────────────────────────────────

def plan_bundle(data: dict, existing: dict) -> dict:
    """Что будет создано и что уже занято.

    ``existing``: {"hostlists", "ipsets", "blobs", "lua", "strategies",
    "builtin_strategies"} — множества имён на этом роутере.
    """
    items, conflicts = [], []

    def add(kind, name, taken):
        items.append({"kind": kind, "name": name})
        if name in taken:
            conflicts.append({"kind": kind, "name": name})

    for h in _items(data, "hostlists"):
        add("hostlist", h["name"], existing.get("hostlists", set()))
    for s in _items(data, "ipsets"):
        add("ipset", s["name"], existing.get("ipsets", set()))
    for b in _items(data, "blobs"):
        add("blob", b["name"], existing.get("blobs", set()))
    for item in _items(data, "lua"):
        add("lua", _lua_stem(item["name"]), existing.get("lua", set()))
    sid = data["strategy"]["id"]
    add("strategy", sid, existing.get("strategies", set()))
    return {"items": items, "conflicts": conflicts,
            "builtin_strategy": sid in existing.get("builtin_strategies",
                                                     set())}


def _free(name: str, taken: set, kind: str) -> str:
    for n in range(2, 1000):
        if kind == "blob":
            cand = "%s_%d" % (name, n)
        elif kind == "ipset" and re.search(r"-ipset$", name):
            cand = "%s-%d" % (name, n)      # zt-x-ipset-2 — в namespace
        else:
            cand = "%s-%d" % (name, n)
        if cand not in taken and len(cand) <= 64:
            return cand
    raise ValueError("нет свободного имени для %s" % name)


def rename_map(plan: dict, existing: dict) -> dict:
    """{kind: {старое: новое}} для занятых имён (режим «переименовать»)."""
    out = {}
    keys = {"hostlist": "hostlists", "ipset": "ipsets", "blob": "blobs",
            "lua": "lua", "strategy": "strategies"}
    for c in plan["conflicts"]:
        taken = set(existing.get(keys[c["kind"]], set()))
        taken |= set(out.get(c["kind"], {}).values())
        kind = c["kind"]
        new = _free(c["name"], taken, kind) if kind != "strategy" else \
            _free(c["name"].replace("-", "_"), taken, "blob")
        out.setdefault(kind, {})[c["name"]] = new
    return out


def rewrite_args(args: str, renames: dict) -> str:
    """Перенести переименования в строку args профиля."""
    lists = dict(renames.get("hostlist", {}))
    lists.update(renames.get("ipset", {}))
    blobs = renames.get("blob", {})
    lua = renames.get("lua", {})

    def list_ref(m):
        return m.group(1) + lists.get(m.group(2), m.group(2)) + m.group(3)

    if lists:
        args = re.sub(r"(lists/)([A-Za-z0-9_-]+)(\.txt\b)", list_ref, args)
    if lua:
        args = re.sub(r"(@lua/)([A-Za-z0-9_.\-]+?)(\.lua\b)",
                      lambda m: m.group(1) + lua.get(m.group(2), m.group(2))
                      + m.group(3), args)
    if blobs:
        args = re.sub(r"(?<=:)(%s)=([A-Za-z_][A-Za-z0-9_]*)(?=[:\s]|$)"
                      % "|".join(_BLOB_ARGS),
                      lambda m: "%s=%s" % (m.group(1),
                                           blobs.get(m.group(2), m.group(2))),
                      args)
        args = re.sub(r"(--blob=)([A-Za-z_][A-Za-z0-9_]*)(:)",
                      lambda m: m.group(1) + blobs.get(m.group(2), m.group(2))
                      + m.group(3), args)
    return args


# ─────────────────────── apply ─────────────────────────────────────────

def existing_names() -> dict:
    """Занятые имена на этом роутере (для :func:`plan_bundle`)."""
    from core.blob_manager import get_blob_manager
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    from core.strategy_builder import get_strategy_manager
    strategies = get_strategy_manager().get_strategies()
    return {
        "hostlists": set(get_hostlist_manager().list_names()),
        "ipsets": set(get_ipset_manager().list_names()),
        "blobs": {b["name"] for b in get_blob_manager().get_blobs()},
        "lua": set(get_lua_manager().list_names()),
        "strategies": {s.get("id") for s in strategies},
        "builtin_strategies": {s.get("id") for s in strategies
                               if s.get("is_builtin")},
    }


def apply_bundle(data: dict, *, on_conflict=None, existing=None) -> dict:
    """Проверить и сохранить. Ничего не применяет.

    ``on_conflict``: None — при занятых именах ничего не пишем и
    возвращаем план (``error_code: conflict``); "replace" — перезаписать;
    "rename" — новые имена и ссылки на них.
    """
    errors, warnings = validate_bundle(data)
    if errors:
        return {"ok": False, "error": "; ".join(errors),
                "error_code": "invalid", "warnings": warnings}
    existing = existing if existing is not None else existing_names()
    plan = plan_bundle(data, existing)
    if plan["builtin_strategy"] and on_conflict != "rename":
        return {"ok": False, "error_code": "conflict", "plan": plan,
                "warnings": warnings,
                "error": "id стратегии совпадает со встроенной — "
                         "выберите «переименовать»"}
    if plan["conflicts"] and on_conflict not in ("replace", "rename"):
        return {"ok": False, "error_code": "conflict", "plan": plan,
                "warnings": warnings,
                "error": "имена уже заняты: " + ", ".join(
                    "%s %s" % (c["kind"], c["name"])
                    for c in plan["conflicts"])}
    renames = rename_map(plan, existing) if on_conflict == "rename" else {}

    def new(kind, name):
        return renames.get(kind, {}).get(name, name)

    from core.blob_manager import get_blob_manager
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    from core.strategy_builder import get_strategy_manager
    saved, failed = [], []

    hm = get_hostlist_manager()
    for h in _items(data, "hostlists"):
        name = new("hostlist", h["name"])
        ok = hm.save_hostlist(name, [str(d) for d in h["domains"]])
        (saved if ok else failed).append("hostlist %s" % name)
    im = get_ipset_manager()
    for s in _items(data, "ipsets"):
        name = new("ipset", s["name"])
        if name not in im.list_names():
            im.create_ipset(name)
        ok = im.save_ipset(name, [str(c) for c in s["cidrs"]])
        ok = ok[0] if isinstance(ok, tuple) else ok
        (saved if ok else failed).append("ipset %s" % name)
    bm = get_blob_manager()
    for b in _items(data, "blobs"):
        name = new("blob", b["name"])
        ok, err = bm.save_blob(name, blob_bytes(b))
        (saved if ok else failed).append("blob %s%s"
                                         % (name, "" if ok else ": %s" % err))
    lm = get_lua_manager()
    for item in _items(data, "lua"):
        name = new("lua", _lua_stem(item["name"]))
        ok, err = lm.save_script(name, item["text"])
        (saved if ok else failed).append("lua %s%s"
                                         % (name, "" if ok else ": %s" % err))

    strategy = dict(data["strategy"])
    strategy["id"] = new("strategy", strategy["id"])
    strategy["profiles"] = [dict(p, args=rewrite_args(p["args"], renames))
                            for p in data["strategy"]["profiles"]]
    result = get_strategy_manager().save_user_strategy(strategy)
    if not result or (isinstance(result, dict)
                      and result.get("ok") is False):
        failed.append("strategy %s" % strategy["id"])
    else:
        saved.append("strategy %s" % strategy["id"])
    return {"ok": not failed, "strategy_id": strategy["id"],
            "saved": saved, "failed": failed, "renamed": renames,
            "warnings": warnings,
            "error": ("не сохранено: " + ", ".join(failed)) if failed
            else None}
