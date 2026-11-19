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
  который имя ведёт реестр (``tls_google`` → ``tls_clienthello_…bin``).
  Только ``fake_default_*`` (встроены в nfqws2) и паттерны ``init_vars``
  (их задаёт сам скрипт) не берутся;
* lua: и явные ``--lua-init=@lua/<имя>.lua``, и скрипты, которые GUI сам
  подключает по функциям профиля (``fakemultisplit``, ``flood_white``,
  оркестратор ``circular``, ``init_vars``… — та же логика, что у запуска,
  ``NFQWSManager._build_lua_init_args``). Скрипты самого zapret2
  (:data:`ZAPRET2_LUA`) есть у любого получателя и не берутся.

Встроенные hostlist'ы (``other``, ``other2``, ``netrogat``) и ipset'ы в
бандл не входят: у получателя они свои. О каждом пропуске сказано в
``warnings`` ответа — сам бандл остаётся чистым форматом.
"""

from __future__ import annotations

import base64
import re

from core.bundle_import import FORMAT, FORMAT_VERSION, LUA_COMPAT, MAX_BLOB

_STRATEGY_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")
_LIST_REF_RE = re.compile(
    r"^--(hostlist|hostlist-exclude|hostlist-auto|ipset|ipset-exclude)=(.+)$")
# Скрипты, которые поставляет сам zapret2: у любого получателя они свои.
ZAPRET2_LUA = frozenset({
    "zapret-lib", "zapret-antidpi", "zapret-auto", "zapret-obfs",
    "zapret-pcap", "zapret-wgobfs", "zapret-tests"})
_BLOB_DECL_RE = re.compile(r"^--blob=([A-Za-z_][A-Za-z0-9_]*):")
_BLOB_ARG_RE = re.compile(
    r"(?:^|:)(blob|pattern|seqovl_pattern)=([A-Za-z_][A-Za-z0-9_]*)")
_LUA_REF_RE = re.compile(r"^--lua-init=@(?:.*/)?lua/([a-zA-Z0-9_.\-]+)\.lua$")
_STEM_RE = re.compile(r"(?:^|/)([a-zA-Z0-9_-]{1,64})\.txt$")
# Поля стратегии, которые несёт бандл (остальное — состояние роутера).
_STRATEGY_KEYS = ("id", "name", "description", "version", "type")


def _tokens(args: str) -> list:
    import shlex
    try:
        return shlex.split(args or "")
    except ValueError:
        return (args or "").split()


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


def references(strategy: dict) -> dict:
    """Ссылки профилей: ``{"lists": [(вид, имя)], "blobs": [...],
    "patterns": [...], "lua": [...]}``; вид — ``hostlist`` или ``ipset``
    по опции, ``patterns`` — имена из ``pattern=``/``seqovl_pattern=``
    (их может задать и ``init_vars``)."""
    lists, blobs, patterns, lua = [], [], [], []
    every = []
    for p in strategy.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        toks = _tokens(p.get("args") or "")
        every += toks
        for tok in toks:
            m = _LIST_REF_RE.match(tok)
            if m:
                stem = _STEM_RE.search(m.group(2))
                kind = "ipset" if m.group(1).startswith("ipset") \
                    else "hostlist"
                if stem and (kind, stem.group(1)) not in lists:
                    lists.append((kind, stem.group(1)))
                continue
            m = _LUA_REF_RE.match(tok)
            if m:
                if m.group(1) not in lua:
                    lua.append(m.group(1))
                continue
            m = _BLOB_DECL_RE.match(tok)
            if m and m.group(1) not in blobs:
                blobs.append(m.group(1))
            if tok.startswith("--lua-desync="):
                for key, n in _BLOB_ARG_RE.findall(tok[len("--lua-desync="):]):
                    into = blobs if key == "blob" else patterns
                    if n not in into:
                        into.append(n)
    for stem in _auto_lua(every):
        if stem not in lua:
            lua.append(stem)
    return {"lists": lists, "blobs": blobs, "patterns": patterns,
            "lua": [n for n in lua if n not in ZAPRET2_LUA]}


def _clean_strategy(strategy: dict) -> dict:
    out = {k: strategy[k] for k in _STRATEGY_KEYS if k in strategy}
    out["id"] = _STRATEGY_ID_RE.sub("_", str(strategy.get("id") or
                                             "strategy"))[:64] or "strategy"
    out.setdefault("name", out["id"])
    out.setdefault("version", 1)
    out["profiles"] = []
    for i, p in enumerate(strategy.get("profiles") or [], 1):
        if not isinstance(p, dict):
            continue
        out["profiles"].append({
            "id": str(p.get("id") or "p%d" % i),
            "name": str(p.get("name") or "p%d" % i),
            "enabled": p.get("enabled", True) is not False,
            "args": str(p.get("args") or ""),
        })
    return out


def build_bundle(strategy: dict, *, hostlists, ipsets, blobs, lua,
                 version: str = "") -> tuple:
    """Стратегия + доступ к файлам → ``(бандл, предупреждения)``.

    Доступ — функции, чтобы модуль был чистым и проверялся без роутера:
    ``hostlists(имя)`` → список доменов или ``None`` (нет такого или
    встроенный), ``ipsets(имя)`` → список CIDR или ``None``,
    ``blobs(имя)`` → байты, которые nfqws2 получит под этим именем, или
    ``None``, ``lua(имя)`` → текст скрипта или ``None``.
    """
    refs = references(strategy)
    warnings = []
    out_lists, out_ipsets, out_blobs, out_lua = [], [], [], []
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
        from core.nfqws_manager import _INIT_VARS_NAMES as init_vars
    except Exception:                           # noqa: BLE001
        init_vars = set()
    # pattern=/seqovl_pattern= с именем init_vars задаёт сам скрипт (он
    # уже в lua); прочие имена паттернов — такие же блобы
    names = refs["blobs"] + [n for n in refs["patterns"]
                             if n not in init_vars and n not in refs["blobs"]]
    for name in names:
        if name.startswith("fake_default_"):
            continue
        data = blobs(name)
        if not data:
            warnings.append("блоб %s не найден на роутере — в бандл не "
                            "входит" % name)
        elif len(data) > MAX_BLOB:
            warnings.append("блоб %s больше %d КБ — в бандл не входит"
                            % (name, MAX_BLOB // 1024))
        else:
            out_blobs.append({"name": name,
                              "base64": base64.b64encode(data).decode()})
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
        "zapret2_compat": LUA_COMPAT,
        "strategy": _clean_strategy(strategy),
        # по имени, как у AutoTuner: один и тот же бандл — один и тот же
        # файл, сколько его ни выгружай
        "hostlists": sorted(out_lists, key=lambda x: x["name"]),
        "ipsets": sorted(out_ipsets, key=lambda x: x["name"]),
        "blobs": sorted(out_blobs, key=lambda x: x["name"]),
        # lua — в порядке загрузки (оркестратор после zapret-auto и т.п.)
        "lua": out_lua,
    }
    return bundle, warnings


def export_strategy(strategy: dict) -> tuple:
    """Бандл стратегии с файлами этого роутера."""
    from core.backup import _HL_BUILTIN, _IPSET_BUILTIN, _app_version
    from core.blob_manager import get_blob_manager
    from core.hostlist_manager import get_hostlist_manager
    from core.ipset_manager import get_ipset_manager
    from core.lua_manager import get_lua_manager
    hm, im, bm, lm = (get_hostlist_manager(), get_ipset_manager(),
                      get_blob_manager(), get_lua_manager())

    def hostlists(name):
        if name in _HL_BUILTIN or name not in hm.list_names():
            return None
        return hm.get_hostlist(name)

    def ipsets(name):
        if name in _IPSET_BUILTIN or name not in im.list_names():
            return None
        return im.get_ipset(name)

    def blobs(name):
        # как при запуске: реестр (каталожные имена, затем свои блобы)
        from core import blob_registry as br
        value = br.get_blob_value(name)
        if value is None:
            return bm.get_blob_content(name) or None
        value = str(value)
        if value.lower().startswith("0x"):
            try:
                return bytes.fromhex(value[2:])
            except ValueError:
                return None
        path = br._blob_file_path(value)
        try:
            with open(path, "rb") as f:
                return f.read(MAX_BLOB + 1)
        except OSError:
            return None

    def lua(name):
        # свой экземпляр, если есть, иначе поставляемый с GUI
        return lm.get_script(name) or None

    return build_bundle(strategy, hostlists=hostlists, ipsets=ipsets,
                        blobs=blobs, lua=lua, version=_app_version())
