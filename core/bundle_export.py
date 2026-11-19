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
  ``blobs`` — только загруженные пользователем (встроенные есть везде);
* ``--lua-init=@lua/<имя>.lua`` → ``lua`` — только свои скрипты, не
  поставляемые с zapret2.

Встроенные hostlist'ы (``other``, ``other2``, ``netrogat``) и ipset'ы в
бандл не входят: у получателя они свои. О каждом пропуске сказано в
``warnings`` ответа — сам бандл остаётся чистым форматом.
"""

from __future__ import annotations

import base64
import re

from core.bundle_import import FORMAT, FORMAT_VERSION, LUA_COMPAT

_STRATEGY_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")
_LIST_REF_RE = re.compile(
    r"^--(hostlist|hostlist-exclude|ipset|ipset-exclude)=(.+)$")
_BLOB_DECL_RE = re.compile(r"^--blob=([A-Za-z_][A-Za-z0-9_]*):")
_BLOB_ARG_RE = re.compile(
    r"(?:^|:)(?:blob|pattern|seqovl_pattern)=([A-Za-z_][A-Za-z0-9_]*)")
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


def references(strategy: dict) -> dict:
    """Ссылки профилей: ``{"lists": [(вид, имя)], "blobs": [...],
    "lua": [...]}``; вид — ``hostlist`` или ``ipset`` по опции."""
    lists, blobs, lua = [], [], []
    for p in strategy.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        for tok in _tokens(p.get("args") or ""):
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
            names = []
            m = _BLOB_DECL_RE.match(tok)
            if m:
                names.append(m.group(1))
            if tok.startswith("--lua-desync="):
                names += _BLOB_ARG_RE.findall(tok[len("--lua-desync="):])
            for n in names:
                if n not in blobs:
                    blobs.append(n)
    return {"lists": lists, "blobs": blobs, "lua": lua}


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
    ``blobs(имя)`` → байты своего блоба или ``None`` (встроенный, нет),
    ``lua(имя)`` → текст своего скрипта или ``None`` (поставляемый, нет).
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
    for name in refs["blobs"]:
        if name.startswith("fake_default_"):
            continue
        data = blobs(name)
        if data:
            out_blobs.append({"name": name,
                              "base64": base64.b64encode(data).decode()})
        else:
            warnings.append("блоб %s не входит в бандл (встроенный "
                            "или его нет)" % name)
    for name in refs["lua"]:
        text = lua(name)
        if text is not None:
            out_lua.append({"name": name + ".lua", "text": text})
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
        "lua": sorted(out_lua, key=lambda x: x["name"]),
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
        info = bm.get_blob(name)
        if not info or info.get("is_builtin"):
            return None
        return bm.get_blob_content(name)

    def lua(name):
        if not lm._validate_name(name) or lm._is_bundled(name):
            return None
        return lm.get_script(name) or None

    return build_bundle(strategy, hostlists=hostlists, ipsets=ipsets,
                        blobs=blobs, lua=lua, version=_app_version())
