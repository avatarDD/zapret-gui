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
# Аргументы lua-функций, значение которых — имя блоба (blob/pattern/
# seqovl_pattern zapret2, fake_blob у fakemultidisorder, dataxor у
# zapret-obfs). Hex (0x…) — не имя.
_BLOB_ARGS = ("blob", "pattern", "seqovl_pattern", "fake_blob", "dataxor")
# Функции, у которых аргументы значат другое: tls_client_hello_clone
# пишет клон в desync.<blob> (это имя переменной, а не блоба), а блоб
# берёт из fallback. У multisplit_tls fallback — режим (pass/split/
# pattern), поэтому в общий список он не входит.
_FUNC_BLOB_ARGS = {"tls_client_hello_clone": ("fallback",)}
_FUNC_VAR_ARGS = {"tls_client_hello_clone": ("blob",)}


def desync_blob_refs(value: str) -> tuple:
    """Значение ``--lua-desync=`` → ``([(аргумент, имя блоба)], [имена
    переменных desync])``. Переменные — то, что функция сама кладёт в
    desync (клон ClientHello): ссылки на них блобами не считаются."""
    func, _, rest = _unquote(str(value or ""))[1].partition(":")
    keys = _FUNC_BLOB_ARGS.get(func, _BLOB_ARGS)
    var_keys = _FUNC_VAR_ARGS.get(func, ())
    refs, variables = [], []
    for part in rest.split(":") if rest else ():
        key, eq, val = part.partition("=")
        if not eq or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", val):
            continue
        if key in var_keys:
            variables.append(val)
        elif key in keys:
            refs.append((key, val))
    return refs, variables


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
    "builtin_strategies", "same", "gui_lua", "catalog_blobs"} — множества
    имён на этом роутере;
    ``same`` — пары ``(вид, имя)``, у которых здесь уже ровно то же
    содержимое (бандл с другого zapret-gui везёт копии своих списков,
    фейков каталога и скриптов GUI): они не пишутся (``skipped``) и
    конфликтом не считаются. Отличается хоть байтом — обычный конфликт:
    «заменить» или «переименовать» решает человек.

    Скрипты, которые поставляет сам GUI (``gui_lua``), и имена блобов
    каталога (``catalog_blobs``) заменить нельзя: свой экземпляр скрипта
    подменил бы поставляемый для всех стратегий, а блоб с именем
    каталога nfqws2 не получит — реестр отдаёт имя каталогу. Если они
    другие (или файла каталога здесь нет), это конфликт с пометкой
    ``rename_only``: содержимое бандла сохраняется под новым именем, и
    ссылки стратегии переходят на него, — она идёт с тем, что проверял
    отправитель. ``rename_only`` плана — когда «заменить» недоступно.
    """
    items, conflicts, skipped = [], [], []

    same = existing.get("same", set())
    owned = {"lua": existing.get("gui_lua", set()),
             "blob": existing.get("catalog_blobs", set())}

    def add(kind, name, taken):
        if (kind, name) in same:
            skipped.append({"kind": kind, "name": name})
            return
        items.append({"kind": kind, "name": name})
        if name in owned.get(kind, ()):
            conflicts.append({"kind": kind, "name": name,
                              "rename_only": True})
        elif name in taken:
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
    builtin = sid in existing.get("builtin_strategies", set())
    return {"items": items, "conflicts": conflicts, "skipped": skipped,
            "builtin_strategy": builtin,
            "rename_only": builtin or any(c.get("rename_only")
                                          for c in conflicts)}


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
        # новое имя не должно снова оказаться именем каталога или GUI
        taken |= set(existing.get({"blob": "catalog_blobs",
                                   "lua": "gui_lua"}.get(c["kind"], ""),
                                  set()))
        taken |= set(out.get(c["kind"], {}).values())
        kind = c["kind"]
        new = _free(c["name"], taken, kind) if kind != "strategy" else \
            _free(c["name"].replace("-", "_"), taken, "blob")
        out.setdefault(kind, {})[c["name"]] = new
    return out


def _unquote(tok: str) -> tuple:
    """Токен ``tokenize_args`` (кавычки остаются в нём) → (кавычка, суть)."""
    if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
        return tok[0], tok[1:-1]
    return "", tok


def _rewrite_desync(value: str, blobs: dict) -> str:
    """Переименовать блобы в значении ``--lua-desync=`` теми же
    правилами, что у :func:`desync_blob_refs`."""
    q, inner = _unquote(value)
    parts = inner.split(":")
    func = parts[0]
    keys = _FUNC_BLOB_ARGS.get(func, _BLOB_ARGS)
    for i, part in enumerate(parts[1:], 1):
        key, eq, val = part.partition("=")
        if eq and key in keys and val in blobs:
            parts[i] = "%s=%s" % (key, blobs[val])
    return q + ":".join(parts) + q


def _rewrite_token(tok: str, lists: dict, blobs: dict, lua: dict) -> str:
    q, inner = _unquote(tok)
    if lists:
        m = re.match(r"^(--(?:hostlist|hostlist-exclude|hostlist-auto|ipset|"
                     r"ipset-exclude)=(?:.*/)?lists/)([A-Za-z0-9_-]+)(\.txt)$",
                     inner)
        if m and m.group(2) in lists:
            return q + m.group(1) + lists[m.group(2)] + m.group(3) + q
    if lua:
        m = re.match(r"^(--lua-init=@(?:.*/)?lua/)([A-Za-z0-9_.\-]+?)(\.lua)$",
                     inner)
        if m and m.group(2) in lua:
            return q + m.group(1) + lua[m.group(2)] + m.group(3) + q
    if blobs:
        if inner.startswith("--lua-desync="):
            return q + "--lua-desync=" + _rewrite_desync(
                inner[len("--lua-desync="):], blobs) + q
        m = re.match(r"^--blob=([A-Za-z_][A-Za-z0-9_]*):", inner)
        if m and m.group(1) in blobs:
            return q + "--blob=%s:" % blobs[m.group(1)] + \
                inner[m.end():] + q
    return tok


def rewrite_args(args: str, renames: dict) -> str:
    """Перенести переименования в строку args профиля: по токенам, тем
    же разбором, что у запуска (кавычки остаются на месте)."""
    lists = dict(renames.get("hostlist", {}))
    lists.update(renames.get("ipset", {}))
    blobs = renames.get("blob", {})
    lua = renames.get("lua", {})
    if not (lists or blobs or lua):
        return args
    from core.models import tokenize_args
    out = args
    for tok in dict.fromkeys(tokenize_args(args)):
        new = _rewrite_token(tok, lists, blobs, lua)
        if new != tok:
            out = re.sub(r"(?<!\S)%s(?!\S)" % re.escape(tok),
                         lambda _m: new, out)
    return out


# ─────────────────────── apply ─────────────────────────────────────────

def existing_names(data: dict = None) -> dict:
    """Занятые имена на этом роутере (для :func:`plan_bundle`); с
    ``data`` — и ``same``: что из бандла здесь уже есть таким же."""
    from core.blob_manager import get_blob_manager
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    from core.strategy_builder import get_strategy_manager
    strategies = get_strategy_manager().get_strategies()
    out = {
        "hostlists": set(get_hostlist_manager().list_names()),
        "ipsets": set(get_ipset_manager().list_names()),
        "blobs": {b["name"] for b in get_blob_manager().get_blobs()},
        "lua": set(get_lua_manager().list_names()),
        "strategies": {s.get("id") for s in strategies},
        "builtin_strategies": {s.get("id") for s in strategies
                               if s.get("is_builtin")},
        "gui_lua": _gui_lua(),
        "catalog_blobs": _catalog_blobs(),
    }
    out["same"] = _same_here(data, out) if isinstance(data, dict) else set()
    return out


def _gui_lua() -> set:
    """Скрипты, которые поставляет GUI (``import/lua``)."""
    import os
    from core.lua_manager import BUNDLED_LUA_DIR
    try:
        return {e[:-4] for e in os.listdir(BUNDLED_LUA_DIR)
                if e.endswith(".lua")}
    except OSError:
        return set()


def _catalog_blobs() -> set:
    """Имена блобов, которые реестр отдаёт каталогу (tls_google …)."""
    try:
        from core import blob_registry as br
        br._ensure_loaded()
        with br._lock:
            return set(br._registry)
    except Exception:                           # noqa: BLE001 — граница
        return set()


def _same_here(data: dict, names: dict) -> set:
    """``(вид, имя)`` из бандла, которые здесь уже ровно такие же.
    Каждый элемент сверяется сам: сбой чтения одного не прячет другие."""
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    hm, im, lm = (get_hostlist_manager(), get_ipset_manager(),
                  get_lua_manager())

    def hostlist(h):
        return h["name"] in names["hostlists"] and \
            list(hm.get_hostlist(h["name"])) == list(h["domains"])

    def ipset(i):
        return i["name"] in names["ipsets"] and \
            list(im.get_ipset(i["name"])) == list(i["cidrs"])

    def blob(b):
        here = _blob_here(b["name"])
        return here is not None and here == blob_bytes(b)

    def lua(item):
        stem = _lua_stem(str(item["name"]))
        return stem in names["lua"] and lm.get_script(stem) == item["text"]

    out = set()
    for key, kind, same in (("hostlists", "hostlist", hostlist),
                            ("ipsets", "ipset", ipset),
                            ("blobs", "blob", blob), ("lua", "lua", lua)):
        for item in _items(data, key):
            try:
                if same(item):
                    name = item["name"]
                    out.add((kind, _lua_stem(name) if kind == "lua"
                             else name))
            except Exception:                   # noqa: BLE001 — граница
                continue
    return out


def _blob_here(name):
    """Байты, которые nfqws2 этого роутера получит под именем (реестр
    каталога, затем свой блоб), или None."""
    try:
        from core import blob_registry as br
        value = br.get_blob_value(str(name or ""))
        if value is None:
            return None
        value = str(value)
        if value.lower().startswith("0x"):
            return bytes.fromhex(value[2:])
        with open(br._blob_file_path(value), "rb") as f:
            return f.read(MAX_BLOB + 1)
    except (OSError, ValueError):
        return None


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
    existing = existing if existing is not None else existing_names(data)
    plan = plan_bundle(data, existing)
    if plan["builtin_strategy"] and on_conflict != "rename":
        return {"ok": False, "error_code": "conflict", "plan": plan,
                "warnings": warnings,
                "error": "id стратегии совпадает со встроенной — "
                         "выберите «переименовать»"}
    if plan["rename_only"] and on_conflict != "rename":
        return {"ok": False, "error_code": "conflict", "plan": plan,
                "warnings": warnings,
                "error": "скрипты GUI и блобы каталога заменить нельзя — "
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
    # то, что здесь уже есть таким же, не пишется
    own = {(x["kind"], x["name"]) for x in plan.get("skipped") or ()}

    hm = get_hostlist_manager()
    for h in _items(data, "hostlists"):
        if ("hostlist", h["name"]) in own:
            continue
        name = new("hostlist", h["name"])
        ok = hm.save_hostlist(name, [str(d) for d in h["domains"]])
        (saved if ok else failed).append("hostlist %s" % name)
    im = get_ipset_manager()
    for s in _items(data, "ipsets"):
        if ("ipset", s["name"]) in own:
            continue
        name = new("ipset", s["name"])
        if name not in im.list_names():
            im.create_ipset(name)
        ok = im.save_ipset(name, [str(c) for c in s["cidrs"]])
        ok = ok[0] if isinstance(ok, tuple) else ok
        (saved if ok else failed).append("ipset %s" % name)
    bm = get_blob_manager()
    for b in _items(data, "blobs"):
        if ("blob", b["name"]) in own:
            continue
        name = new("blob", b["name"])
        ok, err = bm.save_blob(name, blob_bytes(b))
        (saved if ok else failed).append("blob %s%s"
                                         % (name, "" if ok else ": %s" % err))
    lm = get_lua_manager()
    for item in _items(data, "lua"):
        if ("lua", _lua_stem(item["name"])) in own:
            continue
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
            "skipped": ["%s %s" % (x["kind"], x["name"])
                        for x in plan.get("skipped") or ()],
            "warnings": warnings,
            "error": ("не сохранено: " + ", ".join(failed)) if failed
            else None}
