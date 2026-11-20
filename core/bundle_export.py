# core/bundle_export.py
"""
Экспорт стратегии бандлом Zapret2_AutoTuner (``zapret-autotuner-bundle`` v1).

## Зачем

Обратная сторона :mod:`core.bundle_import`: стратегия zapret-gui уходит в
AutoTuner (или на другой роутер с zapret-gui) одним файлом вместе со
всем, на что ссылаются её профили, — hostlist'ами, ipset'ами, блобами
(base64) и своими lua-скриптами. Формат тот же, что пишет AutoTuner
(``ZapretGuiExporter.Bundle``) и читает его ``StrategyImporter``, поэтому
стратегиями можно меняться в обе стороны без ручного создания файлов.

## Что берётся

Только то, на что ссылаются **включённые и выключенные** профили:

* ``--hostlist[-exclude]=…lists/<имя>.txt`` → ``hostlists`` (или
  ``ipsets``, если имя из пространства IP-списков);
* ``--ipset[-exclude]=…/<имя>.txt`` → ``ipsets`` (``cidrs``);
* ``blob=``/``pattern=``/``seqovl_pattern=`` и ``--blob=<имя>:…`` →
  ``blobs`` — байты, которые получит nfqws2: свой блоб или файл, на
  который имя ведёт реестр (``quic_vk`` → ``quic_initial_vk_com.bin``).
  Объявленные в самих args (``--blob=<имя>:@путь``) едут там же, как
  hex, как и ``fake_default_udp`` из реестра GUI (блобом бандла имя
  ``fake_default_*`` не передать). Не берутся ``fake_default_tls``/
  ``http``/``quic`` (встроены в nfqws2) и имена,
  которые при запуске задаёт ``init_vars.lua`` (``tls_google``,
  ``tls_rnd``…: скрипт присваивает их заново, поверх любого ``--blob``);
* lua: и явные ``--lua-init=@lua/<имя>.lua``, и скрипты, которые GUI сам
  подключает по функциям профиля (``fakemultisplit``, ``flood_white``,
  оркестратор ``circular``, ``init_vars``… — та же логика, что у запуска,
  ``NFQWSManager._build_lua_init_args``). Скрипты самого zapret2
  (:data:`ZAPRET2_LUA`) есть у любого получателя и не берутся.

Встроенные hostlist'ы (``other``, ``other2``, ``netrogat``) и ipset'ы в
бандл не входят: у получателя они свои. Списки и lua берутся только из
``lists/<имя>.txt`` и ``lua/<имя>.lua`` или из каталогов их менеджеров:
файл по другому пути бандл перенести не может.

Профили уходят такими, какими их запускает GUI: «голый» приём получает
тот же фильтр (``autowrap_bare_trick``: по ``--payload``, у встроенной
стратегии — и по протоколу и портам перехвата), иначе у получателя он
задел бы весь трафик очереди. Пути к спискам и lua становятся
``lists/<имя>.txt`` и ``@lua/<имя>.lua`` — так их понимает импорт. О
каждом пропуске сказано в ``warnings`` ответа — сам бандл остаётся
чистым форматом.
"""

from __future__ import annotations

import base64
import re

from core.blob_registry import BUILTIN_BLOB_NAMES
from core.bundle_import import (FORMAT, FORMAT_VERSION, LUA_COMPAT,
                                MAX_BLOB, NOT_INIT_VARS_ARGS,
                                desync_blob_refs)

_STRATEGY_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")
_LIST_REF_RE = re.compile(
    r"^--(hostlist|hostlist-exclude|hostlist-auto|ipset|ipset-exclude)=(.+)$")
# Предел блоба у AutoTuner (StrategyValidator.MaxBlobSize); у zapret-gui
# свой, :data:`MAX_BLOB`.
AUTOTUNER_MAX_BLOB = 16384
# Скрипты, которые поставляет сам zapret2: у любого получателя они свои.
ZAPRET2_LUA = frozenset({
    "zapret-lib", "zapret-antidpi", "zapret-auto", "zapret-obfs",
    "zapret-pcap", "zapret-wgobfs", "zapret-tests"})
_BLOB_DECL_RE = re.compile(r"^--blob=([A-Za-z_][A-Za-z0-9_]*):")
_LUA_REF_RE = re.compile(r"^--lua-init=@(.+)$")
_LIST_FILE_RE = re.compile(r"^([a-zA-Z0-9_-]{1,64})\.txt$")
_LUA_FILE_RE = re.compile(r"^([a-zA-Z0-9_.\-]+)\.lua$")
# Поля стратегии, которые несёт бандл (остальное — состояние роутера).
_STRATEGY_KEYS = ("id", "name", "description", "version", "type")


def _tokens(args: str) -> list:
    # так же, как разбирает профиль запуск (кавычки остаются в токене)
    from core.models import tokenize_args
    return tokenize_args(args or "")


def _auto_lua(tokens: list) -> list:
    """Скрипты GUI, которые запуск подключит этим профилям сам (по их
    функциям и значениям): та же логика, что у запуска, на каталоге
    поставляемых скриптов, где есть все."""
    try:
        from core.lua_manager import BUNDLED_LUA_DIR
        from core.nfqws_manager import NFQWSManager
        inits = NFQWSManager._build_lua_init_args(tokens, BUNDLED_LUA_DIR)
    except Exception:                           # noqa: BLE001 — граница
        return []
    out = []
    for a in inits:
        stem = a.rsplit("/", 1)[-1]
        stem = stem[:-4] if stem.endswith(".lua") else stem
        if stem and stem not in ZAPRET2_LUA and stem not in out:
            out.append(stem)
    return out


def _stem(path: str, kind: str, roots) -> str:
    """Имя списка (``kind`` = ``lists``) или скрипта (``lua``) по пути из
    args, если это файл менеджера: ``lists/<имя>.txt`` / ``lua/<имя>.lua``
    (их запуск резолвит в каталоги менеджеров) или путь прямо в этих
    каталогах (``roots[kind]``). Иначе ``""`` — такой файл менеджер не
    знает, и его содержимое бандл перенести не может."""
    import os
    path = str(path or "").replace("\\", "/")
    head, _, base = path.rpartition("/")
    m = (_LIST_FILE_RE if kind == "lists" else _LUA_FILE_RE).match(base)
    if not m:
        return ""
    if head == kind:
        return m.group(1)
    dirs = {os.path.normpath(d) for d in (roots or {}).get(kind) or ()
            if d}
    return m.group(1) if head and os.path.normpath(head) in dirs else ""


def references(strategy: dict, roots=None) -> dict:
    """Ссылки профилей: ``{"lists": [(вид, имя)], "blobs": [...],
    "patterns": [...], "lua": [...]}``; вид — ``hostlist`` или ``ipset``
    по опции, ``patterns`` — имена из ``pattern=``/``seqovl_pattern=``
    (их может задать и ``init_vars``). ``roots`` — каталоги менеджеров
    (``{"lists": [...], "lua": [...]}``), см. :func:`_stem`."""
    lists, blobs, patterns, lua, unknown = [], [], [], [], []
    named = set()       # имена, по которым запуск подключит init_vars.lua
    declared = {}
    # что видит запуск: только включённые профили (build_nfqws_args)
    declared_on, used_on = set(), set()
    every = []
    off_lua = []        # скрипты, которые называют только выключенные
    for p in strategy.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        toks = _tokens(p.get("args") or "")
        on = bool(p.get("enabled", True))
        if on:          # lua запуск подключает только включённым
            every += toks
        # переменные desync, которые профиль сам заводит (клон
        # ClientHello): в этом профиле такое имя — не блоб
        local = set()
        for tok in toks:
            if tok.startswith("--lua-desync="):
                local |= set(desync_blob_refs(tok[len("--lua-desync="):])[1])
        for tok in toks:
            m = _LIST_REF_RE.match(tok)
            if m:
                stem = _stem(m.group(2), "lists", roots)
                kind = "ipset" if m.group(1).startswith("ipset") \
                    else "hostlist"
                if not stem:
                    unknown.append(tok)
                elif (kind, stem) not in lists:
                    lists.append((kind, stem))
                continue
            m = _LUA_REF_RE.match(tok)
            if m:   # инлайн-код (--lua-init=код) едет в args как есть
                stem = _stem(m.group(1), "lua", roots)
                if not stem:
                    unknown.append(tok)
                elif not on:
                    off_lua.append(stem)
                elif stem not in lua:
                    lua.append(stem)
                continue
            m = _BLOB_DECL_RE.match(tok)
            if m:
                declared.setdefault(m.group(1), tok.split(":", 1)[1])
                if on:
                    declared_on.add(m.group(1))
                if m.group(1) not in blobs:
                    blobs.append(m.group(1))
            if tok.startswith("--lua-desync="):
                for key, n in desync_blob_refs(
                        tok[len("--lua-desync="):])[0]:
                    if n in local and n not in declared:
                        continue
                    if on:
                        used_on.add(n)
                        if key not in NOT_INIT_VARS_ARGS:
                            named.add(n)
                    into = patterns if key.endswith("pattern") else blobs
                    if n not in into:
                        into.append(n)
    # порядок загрузки как у запуска: скрипты GUI (lua_args) раньше
    # --lua-init из самих профилей
    auto = _auto_lua(every)
    lua = auto + [n for n in lua if n not in auto]
    # импорт AutoTuner грузит каждый lua бандла глобально — скрипт
    # выключенного профиля поменял бы и включённые; в бандл он не идёт
    off_lua = [n for n in dict.fromkeys(off_lua)
               if n not in lua and n not in ZAPRET2_LUA]
    return {"lists": lists, "blobs": blobs, "patterns": patterns,
            "declared": declared, "unknown": unknown, "named": named,
            "off_lua": off_lua,
            # объявлены только в выключенных профилях, а нужны включённым:
            # запуск берёт их из реестра
            "registry_too": [n for n in blobs + patterns
                             if n in declared and n not in declared_on
                             and n in used_on],
            "lua": [n for n in lua if n not in ZAPRET2_LUA]}


def _portable_paths(args: str, roots=None) -> str:
    """Пути этого роутера к спискам и lua → ``lists/<имя>.txt`` и
    ``@lua/<имя>.lua``: так их пишет импорт (и переименовывает)."""
    for tok in dict.fromkeys(_tokens(args)):
        m = _LIST_REF_RE.match(tok)
        if m:
            stem = _stem(m.group(2), "lists", roots)
            new = "--%s=lists/%s.txt" % (m.group(1), stem) if stem else ""
        else:
            m = _LUA_REF_RE.match(tok)
            stem = _stem(m.group(1), "lua", roots) if m else ""
            new = "--lua-init=@lua/%s.lua" % stem if stem else ""
        if not new:
            continue
        if new != tok:
            args = re.sub(r"(?<!\S)%s(?!\S)" % re.escape(tok),
                          lambda _m, new=new: new, args)
    return args


def _inline_decl(args: str, inline: dict) -> str:
    """``--blob=<имя>:@путь`` этого роутера → ``--blob=<имя>:0x<hex>``:
    объявление в args самодостаточно и у получателя значит то же, что
    здесь (и поверх имени каталога, и без файла)."""
    for tok in dict.fromkeys(_tokens(args)):
        m = _BLOB_DECL_RE.match(tok)
        if not m or m.group(1) not in inline:
            continue
        hexed = "--blob=%s:0x%s" % (m.group(1), inline[m.group(1)].hex())
        # токен целиком, с кавычками внутри (@"путь с пробелом")
        args = re.sub(r"(?<!\S)%s(?!\S)" % re.escape(tok),
                      lambda _m: hexed, args)
    return args


def _clean_strategy(strategy: dict, inline=None, roots=None,
                    inject=None) -> dict:
    out = {k: strategy[k] for k in _STRATEGY_KEYS if k in strategy}
    out["id"] = _STRATEGY_ID_RE.sub("_", str(strategy.get("id") or
                                             "strategy"))[:64] or "strategy"
    out["name"] = str(strategy.get("name") or "").strip() or out["id"]
    out.setdefault("version", 1)
    out["profiles"] = []
    for i, p in enumerate(strategy.get("profiles") or [], 1):
        if not isinstance(p, dict):
            continue
        out["profiles"].append({
            "id": str(p.get("id") or "p%d" % i),
            "name": str(p.get("name") or "p%d" % i),
            # как при запуске (strategy_builder): выключен любой «ложный»
            "enabled": bool(p.get("enabled", True)),
            "args": _portable_paths(_inline_decl(str(p.get("args") or ""),
                                                 inline or {}), roots),
        })
    # объявления, которых в args не было (fake_default_udp из реестра
    # GUI): один раз, в начале первого включённого профиля — до первого
    # --new, как их ставит запуск (импорт AutoTuner берёт только
    # включённые профили)
    target = next((p for p in out["profiles"] if p["enabled"]),
                  out["profiles"][0] if out["profiles"] else None)
    for name, data in (inject or {}).items():
        if target is not None:
            target["args"] = ("--blob=%s:0x%s " % (name, data.hex())
                              + target["args"]).strip()
    return out


def _declared_bytes(value: str, blob_file):
    value = str(value or "")
    if value.lower().startswith("0x"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            return None
    # @файл и +N@файл (со смещения N) — читает blob_file
    if re.match(r"^(?:\+\d+)?@.", value) and blob_file is not None:
        return blob_file(value)
    return None


def build_bundle(strategy: dict, *, hostlists, ipsets, blobs, lua,
                 blob_file=None, compat: int = LUA_COMPAT,
                 version: str = "", roots=None) -> tuple:
    """Стратегия + доступ к файлам → ``(бандл, предупреждения)``.

    Доступ — функции, чтобы модуль был чистым и проверялся без роутера:
    ``hostlists(имя)`` → список доменов или ``None`` (нет такого или
    встроенный), ``ipsets(имя)`` → список CIDR или ``None``,
    ``blobs(имя)`` → байты, которые nfqws2 получит под этим именем, или
    ``None``, ``lua(имя)`` → текст скрипта или ``None``,
    ``blob_file(значение)`` — байты по значению ``--blob=<имя>:<значение>``
    из самих args (``@путь`` или ``+N@путь`` — со смещения N),
    ``compat`` — версия совместимости lua zapret2 этого роутера, ``roots``
    — каталоги менеджеров списков и lua (см. :func:`_stem`).
    """
    refs = references(strategy, roots)
    warnings = []
    out_lists, out_ipsets, out_blobs, out_lua = [], [], [], []
    for tok in refs["unknown"]:
        warnings.append("%s: файл не входит в бандл (путь вне lists/ и "
                        "lua/)" % tok[:120])
    for kind, name in refs["lists"]:
        from core.ipset_manager import IPSET_NAMESPACE_RE
        if kind == "ipset" or IPSET_NAMESPACE_RE.match(name):
            items = ipsets(name)
            if items is None:
                warnings.append("ipset %s не входит в бандл (встроенный "
                                "или его нет)" % name)
            else:
                out_ipsets.append({"name": name, "cidrs": list(items)})
            continue
        items = hostlists(name)
        if items is None:
            warnings.append("hostlist %s не входит в бандл (встроенный "
                            "или его нет)" % name)
        else:
            out_lists.append({"name": name, "domains": list(items)})
    try:
        from core.nfqws_manager import _INIT_VARS_NAMES
    except Exception:                           # noqa: BLE001
        _INIT_VARS_NAMES = set()
    # init_vars.lua подключается по blob=/pattern= с именем init_vars и
    # тогда задаёт все свои имена (и в fallback=/dataxor=); без такой
    # ссылки имя init_vars — файл реестра, как любой блоб
    init_vars = set(_INIT_VARS_NAMES) \
        if set(_INIT_VARS_NAMES) & refs["named"] else set()
    names = refs["blobs"] + [n for n in refs["patterns"]
                             if n not in refs["blobs"]]
    inline = {}             # объявленные в args — едут там же, как hex
    inject = {}             # объявления, которые добавляются в args
    for name in names:
        if name in BUILTIN_BLOB_NAMES:
            continue                    # встроены в nfqws2
        value = refs["declared"].get(name)
        if value is not None:
            data = _declared_bytes(value, blob_file)
        elif name in init_vars:
            # имя init_vars: запуск подключает init_vars.lua, и тот задаёт
            # глобал заново (поверх --blob) — байты nfqws2 даёт скрипт,
            # файл каталога был бы не тем, что получает nfqws2
            data = None
        else:
            data = blobs(name)
        if not data:
            if name in init_vars:
                warnings.append("%s задаёт init_vars.lua при запуске: "
                                "байтов в бандле нет, AutoTuner такую "
                                "стратегию не проверит" % name)
            else:
                warnings.append("блоб %s не найден на роутере — в бандл "
                                "не входит" % name)
            continue
        if len(data) > MAX_BLOB:
            warnings.append("блоб %s больше %d КБ — в бандл не входит"
                            % (name, MAX_BLOB // 1024))
            continue
        if len(data) > AUTOTUNER_MAX_BLOB:
            warnings.append("блоб %s больше %d КБ: zapret-gui его примет, "
                            "AutoTuner — нет" % (name,
                                                 AUTOTUNER_MAX_BLOB // 1024))
        if value is not None:
            inline[name] = data
            continue
        if name.startswith("fake_default_"):
            # имя из реестра GUI (fake_default_udp) — блобом бандла его
            # не передать (имя встроенных зарезервировано), только
            # объявлением в args
            inject[name] = data
            continue
        out_blobs.append({"name": name,
                          "base64": base64.b64encode(data).decode()})
    for name in refs["registry_too"]:
        # объявление едет в выключенном профиле, а импорт AutoTuner
        # берёт только включённые: нужны и байты, которые запуск возьмёт
        # из реестра
        if name in BUILTIN_BLOB_NAMES or name in init_vars or \
                name.startswith("fake_default_"):
            continue
        data = blobs(name)
        if not data or len(data) > MAX_BLOB:
            warnings.append("блоб %s не найден на роутере — в бандл "
                            "не входит" % name)
            continue
        out_blobs.append({"name": name,
                          "base64": base64.b64encode(data).decode()})
    for name in refs["off_lua"]:
        warnings.append("lua %s.lua нужен только выключенному профилю — в "
                        "бандл не входит" % name)
    for name in refs["lua"]:
        text = lua(name)
        if text:
            out_lua.append({"name": name + ".lua", "text": text})
        else:
            warnings.append("lua %s.lua не найден на роутере — в бандл не "
                            "входит" % name)
    bundle = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "generator": {"name": "zapret-gui", "version": version or ""},
        "zapret2_compat": int(compat or LUA_COMPAT),
        "strategy": _clean_strategy(strategy, inline, roots, inject),
        # по имени, как у AutoTuner: один и тот же бандл — один и тот же
        # файл, сколько его ни выгружай
        "hostlists": sorted(out_lists, key=lambda x: x["name"]),
        "ipsets": sorted(out_ipsets, key=lambda x: x["name"]),
        "blobs": sorted(out_blobs, key=lambda x: x["name"]),
        # lua — в порядке загрузки у GUI (скрипты GUI, затем свои)
        "lua": out_lua,
    }
    return bundle, warnings


def export_strategy(strategy: dict) -> tuple:
    """Бандл стратегии с файлами этого роутера."""
    strategy = _as_launched(strategy)
    from core.backup import _HL_BUILTIN, _IPSET_BUILTIN, _app_version
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    hm, im, lm = (get_hostlist_manager(), get_ipset_manager(),
                  get_lua_manager())

    def hostlists(name):
        if name in _HL_BUILTIN or name not in hm.list_names():
            return None
        return hm.get_hostlist(name)

    def ipsets(name):
        if name in _IPSET_BUILTIN or name not in im.list_names():
            return None
        return im.get_ipset(name)

    from core import blob_registry as br

    def blob_file(value):
        # +N@файл: nfqws2 берёт файл со смещения N — лимит считается
        # от него, а не от начала файла
        m = re.match(r"^\+(\d+)(@.+)$", value)
        offset, value = (int(m.group(1)), m.group(2)) if m else (0, value)
        try:
            with open(br._blob_file_path(value), "rb") as f:
                f.seek(offset)
                return f.read(MAX_BLOB + 1)
        except OSError:
            return None

    def blobs(name):
        # как при запуске: реестр (каталожные имена, затем свои блобы)
        value = br.get_blob_value(name)
        if value is None:
            return None         # запуск его тоже не объявит
        return _declared_bytes(value, blob_file)

    def lua(name):
        # свой экземпляр, если есть, иначе поставляемый с GUI
        return lm.get_script(name) or None

    roots = {"lists": [hm.lists_path, im.ipset_path, im.lists_path],
             "lua": [lm.lua_path]}
    return build_bundle(strategy, hostlists=hostlists, ipsets=ipsets,
                        blobs=blobs, lua=lua, blob_file=blob_file,
                        compat=_installed_compat(lm),
                        version=_app_version(), roots=roots)


def _as_launched(strategy: dict) -> dict:
    """Профили с фильтром, который им добавит запуск
    (``autowrap_bare_trick``): по однозначному ``--payload`` у любой
    стратегии, по протоколу и портам перехвата — у встроенной."""
    try:
        from core.strategy_builder import (StrategyManager,
                                           autowrap_bare_trick)
        scope = StrategyManager._autowrap_scope(strategy)
    except Exception:                           # noqa: BLE001 — граница
        return strategy
    profiles = []
    changed = False
    for p in strategy.get("profiles") or []:
        if isinstance(p, dict) and isinstance(p.get("args"), str):
            toks = _tokens(p["args"])
            wrapped = autowrap_bare_trick(list(toks), **scope)
            if len(wrapped) > len(toks):
                head = wrapped[:len(wrapped) - len(toks)]
                p = dict(p, args=" ".join(head + [p["args"].strip()]))
                changed = True
        profiles.append(p)
    return dict(strategy, profiles=profiles) if changed else strategy


def _installed_compat(lm) -> int:
    """NFQWS2_COMPAT_VER_REQUIRED установленного zapret-lib.lua."""
    import os
    try:
        from core.asset_importer import _lua_compat_ver
        return _lua_compat_ver(os.path.join(lm.lua_path,
                                            "zapret-lib.lua")) or LUA_COMPAT
    except Exception:                           # noqa: BLE001 — граница
        return LUA_COMPAT
