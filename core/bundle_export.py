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
# Предел блоба у AutoTuner (StrategyValidator.MaxBlobSize); у zapret-gui
# свой, :data:`MAX_BLOB`.
AUTOTUNER_MAX_BLOB = 16384
# Скрипты, которые поставляет сам zapret2: у любого получателя они свои.
ZAPRET2_LUA = frozenset({
    "zapret-lib", "zapret-antidpi", "zapret-auto", "zapret-obfs",
    "zapret-pcap", "zapret-wgobfs", "zapret-tests"})
_BLOB_DECL_RE = re.compile(r"^--blob=([A-Za-z_][A-Za-z0-9_]*):")
# Аргументы lua-функций со значением-именем блоба: blob/pattern/
# seqovl_pattern zapret2 и аргументы скриптов GUI (fake_blob у
# fakemultidisorder, fallback у tls_client_hello_clone, dataxor у
# zapret-obfs). Hex (0x…) — не имя, его регэксп не берёт.
from core.bundle_import import _BLOB_ARGS  # noqa: E402
_BLOB_ARG_RE = re.compile(r"(?:^|:)(%s)=([A-Za-z_][A-Za-z0-9_]*)"
                          % "|".join(_BLOB_ARGS))
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
    lists, blobs, patterns, lua, unknown = [], [], [], [], []
    declared = {}
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
                if not stem:
                    unknown.append(tok)
                elif (kind, stem.group(1)) not in lists:
                    lists.append((kind, stem.group(1)))
                continue
            m = _LUA_REF_RE.match(tok)
            if m:
                if m.group(1) not in lua:
                    lua.append(m.group(1))
                continue
            if tok.startswith("--lua-init=@"):
                unknown.append(tok)     # файл вне lua/ (инлайн-код едет в args)
                continue
            m = _BLOB_DECL_RE.match(tok)
            if m:
                declared.setdefault(m.group(1), tok.split(":", 1)[1])
                if m.group(1) not in blobs:
                    blobs.append(m.group(1))
            if tok.startswith("--lua-desync="):
                for key, n in _BLOB_ARG_RE.findall(tok[len("--lua-desync="):]):
                    into = patterns if key.endswith("pattern") else blobs
                    if n not in into:
                        into.append(n)
    # порядок загрузки как у запуска: скрипты GUI (lua_args) раньше
    # --lua-init из самих профилей
    auto = _auto_lua(every)
    lua = auto + [n for n in lua if n not in auto]
    return {"lists": lists, "blobs": blobs, "patterns": patterns,
            "declared": declared, "unknown": unknown,
            "lua": [n for n in lua if n not in ZAPRET2_LUA]}


def _inline_decl(args: str, inline: dict) -> str:
    """``--blob=<имя>:@путь`` этого роутера → ``--blob=<имя>:0x<hex>``:
    объявление в args самодостаточно и у получателя значит то же, что
    здесь (и поверх имени каталога, и без файла)."""
    for name, data in inline.items():
        args = re.sub(r"(?<!\S)--blob=%s:\S+" % re.escape(name),
                      lambda m: "--blob=%s:0x%s" % (name, data.hex()), args)
    return args


def _clean_strategy(strategy: dict, inline=None) -> dict:
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
            "args": _inline_decl(str(p.get("args") or ""), inline or {}),
        })
    return out


def _declared_bytes(value: str, blob_file):
    value = str(value or "")
    if value.lower().startswith("0x"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            return None
    if value.startswith("@") and blob_file is not None:
        return blob_file(value)
    return None


def build_bundle(strategy: dict, *, hostlists, ipsets, blobs, lua,
                 blob_file=None, compat: int = LUA_COMPAT,
                 version: str = "") -> tuple:
    """Стратегия + доступ к файлам → ``(бандл, предупреждения)``.

    Доступ — функции, чтобы модуль был чистым и проверялся без роутера:
    ``hostlists(имя)`` → список доменов или ``None`` (нет такого или
    встроенный), ``ipsets(имя)`` → список CIDR или ``None``,
    ``blobs(имя)`` → байты, которые nfqws2 получит под этим именем, или
    ``None``, ``lua(имя)`` → текст скрипта или ``None``,
    ``blob_file(значение)`` — байты по значению ``--blob=<имя>:<значение>``
    из самих args (``@путь``), ``compat`` — версия совместимости lua
    zapret2 этого роутера.
    """
    refs = references(strategy)
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
        from core.nfqws_manager import _INIT_VARS_NAMES as init_vars
    except Exception:                           # noqa: BLE001
        init_vars = set()
    names = refs["blobs"] + [n for n in refs["patterns"]
                             if n not in refs["blobs"]]
    inline = {}             # объявленные в args — едут там же, как hex
    for name in names:
        if name.startswith("fake_default_"):
            continue
        value = refs["declared"].get(name)
        if value is not None:
            data = _declared_bytes(value, blob_file)
        else:
            data = blobs(name)
        if not data:
            if name in init_vars:
                # паттерн init_vars без файла каталога (tls_rnd…) GUI
                # получает из скрипта, байтов у него нет
                warnings.append("паттерн %s задаёт init_vars.lua при "
                                "запуске: в бандле его нет, AutoTuner "
                                "такую стратегию не проверит" % name)
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
        "zapret2_compat": int(compat or LUA_COMPAT),
        "strategy": _clean_strategy(strategy, inline),
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

    from core import blob_registry as br

    def blob_file(value):
        try:
            with open(br._blob_file_path(value), "rb") as f:
                return f.read(MAX_BLOB + 1)
        except OSError:
            return None

    def blobs(name):
        # как при запуске: реестр (каталожные имена, затем свои блобы)
        value = br.get_blob_value(name)
        if value is None:
            return bm.get_blob_content(name) or None
        return _declared_bytes(value, blob_file)

    def lua(name):
        # свой экземпляр, если есть, иначе поставляемый с GUI
        return lm.get_script(name) or None

    return build_bundle(strategy, hostlists=hostlists, ipsets=ipsets,
                        blobs=blobs, lua=lua, blob_file=blob_file,
                        compat=_installed_compat(lm),
                        version=_app_version())


def _installed_compat(lm) -> int:
    """NFQWS2_COMPAT_VER_REQUIRED установленного zapret-lib.lua."""
    import os
    try:
        from core.asset_importer import _lua_compat_ver
        return _lua_compat_ver(os.path.join(lm.lua_path,
                                            "zapret-lib.lua")) or LUA_COMPAT
    except Exception:                           # noqa: BLE001 — граница
        return LUA_COMPAT
