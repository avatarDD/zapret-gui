# core/profile_import.py
"""
Импорт чужого профиля: конфиг другого роутера → наша стратегия.

## Зачем

Рабочую стратегию часто приносят целым конфигом: ``/opt/zapret2/config``
(``NFQWS2_OPT="…"``), конфиг nfqws2-keenetic (``NFQWS_ARGS="…"``,
``NFQWS_ARGS_QUIC``, ``NFQWS_EXTRA_ARGS``), строка запуска ``nfqws2 …``.
Вставить такое как есть нельзя: пути к lua, блобам и спискам у того
роутера свои, опции движка (``--qnum``, ``--user``…) GUI ставит сам,
маркеры ``<HOSTLIST>`` раскрывает чужой init-скрипт. Здесь текст
разбирается, пути переносятся на наши, лишнее отбрасывается — и о каждом
действии сказано (приём nfqws2-ui).

## Что делается

* Профили — из переменных, где есть опции nfqws2, по порядку, и внутри
  них — по ``--new``. Переменная только со списками
  (``NFQWS_EXTRA_ARGS``) дописывается к каждому профилю — так её
  подмешивает init-скрипт Keenetic.
* ``--lua-init=@…/x.lua`` → ``@lua/x.lua``, ``--blob=имя:@…/f.bin`` →
  ``@bin/f.bin``, списки (``--hostlist*``, ``--ipset*``) → ``lists/имя``;
  чего у нас нет — предупреждение.
* Опции движка и ``--debug=@файл`` — выбрасываются; ``<HOSTLIST>`` и
  ``<HOSTLIST_NOAUTO>`` — тоже: списки подставит наш режим фильтра.
* Интерфейс WAN (``ISP_INTERFACE``, ``IFACE_WAN``), которого здесь нет, —
  называется: внешний интерфейс GUI берёт из своих настроек.
* Стратегии nfqws v1 (``--dpi-desync``) не переводятся — только
  предупреждение.

Разбор — чистые функции, окружение (наши пути и «есть ли файл») —
аргументом; ввод-вывод — в :func:`import_text`.
"""

from __future__ import annotations

import os
import re

from core.models import tokenize_args

_VAR_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)="
    r"(?:\"([^\"]*)\"|'([^']*)'|([^\s#]*))", re.M)
_IFACE_VARS = ("ISP_INTERFACE", "IFACE_WAN", "IFACE_WAN6", "WAN_IFACE")
_LIST_OPTS = ("--hostlist", "--hostlist-exclude", "--hostlist-auto",
              "--ipset", "--ipset-exclude")
_IPSET_OPTS = ("--ipset", "--ipset-exclude")


def detect(text: str) -> str:
    """Что вставили: zapret2 / keenetic / zapret1 / args / unknown."""
    names = {m.group(1) for m in _VAR_RE.finditer(text or "")}
    if "NFQWS2_OPT" in names:
        return "zapret2"
    if names & {"NFQWS_ARGS", "NFQWS_ARGS_QUIC", "NFQWS_ARGS_UDP",
                "NFQWS_EXTRA_ARGS", "NFQWS_BASE_ARGS", "ISP_INTERFACE"}:
        return "keenetic"
    if "NFQWS_OPT" in names:
        return "zapret1"
    if re.search(r"--(?:lua-desync|dpi-desync|filter-)", text or ""):
        return "args"
    return "unknown"


KIND_TITLES = {
    "zapret2": "конфиг zapret2 (NFQWS2_OPT)",
    "keenetic": "конфиг nfqws2-keenetic",
    "zapret1": "конфиг zapret v1 (NFQWS_OPT)",
    "args": "строка аргументов nfqws2",
    "unknown": "не распознано",
}


def _sources(text: str, kind: str) -> tuple:
    """([(имя, значение)] с опциями nfqws, {имя: значение} интерфейсов)."""
    found, ifaces = [], {}
    for m in _VAR_RE.finditer(text or ""):
        name = m.group(1)
        value = next((g for g in m.group(2, 3, 4) if g is not None), "")
        value = value.replace("\\\n", " ")
        if name in _IFACE_VARS:
            ifaces[name] = value
        elif re.search(r"(?:^|\s)--[a-z]", value):
            found.append((name, value))
    if kind == "args" or not found:
        body = re.sub(r"^\s*(?:\S*/)?(?:nfqws2?|winws2?)(?:\s|$)", "",
                      text or "", flags=re.M | re.I)
        # Комментарии: строка целиком и хвост «  # рабочая» после опций.
        body = "\n".join(re.sub(r"(?:^|\s)#.*$", "", line)
                         for line in body.replace("\\\n", " ").splitlines())
        found = [("", body.replace("\\\n", " "))]
    return found, ifaces


_MARKER_RE = re.compile(r"<[A-Z_]+>")
_DECL = ("--blob=", "--lua-init=")
# Опции с путём: getopt_long принимает и `--hostlist /путь` двумя токенами.
_PATH_OPTS = _LIST_OPTS + ("--lua-init", "--blob")


def _merge_split_values(tokens: list) -> list:
    """``--hostlist /путь`` → ``--hostlist=/путь`` (чтобы перенести путь)."""
    out, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if (t in _PATH_OPTS and i + 1 < len(tokens)
                and not tokens[i + 1].startswith("-")):
            out.append("%s=%s" % (t, tokens[i + 1]))
            i += 2
            continue
        out.append(t)
        i += 1
    return out


def _strip_owned(tokens: list, dropped: list, notes: list) -> list:
    """Опции движка — вон (тем же правилом, что линтер и сборщик)."""
    from core.strategy_lint import engine_owned
    bad = engine_owned(tokens)
    for item in bad:
        dropped.append(item["arg"])
        if item["reason"] not in notes and not item["reason"].startswith(
                "значение "):
            notes.append(item["reason"])
    skip = {item["index"] for item in bad}
    return [t for i, t in enumerate(tokens) if i not in skip]


def _split_new(tokens: list) -> list:
    out, cur = [], []
    for t in tokens:
        if t == "--new":
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    out.append(cur)
    return [p for p in out if p]


def _is_lists_only(tokens: list) -> bool:
    return bool(tokens) and all(t.split("=", 1)[0] in _LIST_OPTS
                                or t.startswith("--hostlist-domains")
                                for t in tokens)


def adapt_token(tok: str, env: dict) -> tuple:
    """(новый токен или None, замечание или "").

    ``env``: lua_path, bin_path, lists_path, ipset_path и ``exists(path)``.
    """
    opt, eq, val = tok.partition("=")
    exists = env.get("exists") or os.path.exists
    if opt == "--lua-init" and val.startswith("@") and "/" in val:
        name = os.path.basename(val[1:])
        note = "" if exists(os.path.join(env["lua_path"], name)) else (
            "lua-скрипта %s здесь нет — загрузите его в «Lua-скрипты»"
            % name)
        return "--lua-init=@lua/%s" % name, note
    if opt == "--blob" and ":@" in val:
        bname, _, path = val.partition(":@")
        if "/" in path:
            fname = os.path.basename(path)
            note = "" if exists(os.path.join(env["bin_path"], fname)) else (
                "файла блоба %s здесь нет — загрузите его в «Блобы»"
                % fname)
            return "--blob=%s:@bin/%s" % (bname, fname), note
    if opt in _LIST_OPTS and eq and "/" in val:
        fname = os.path.basename(val)
        base = env["ipset_path"] if opt in _IPSET_OPTS else env["lists_path"]
        note = "" if exists(os.path.join(base, fname)) else (
            "списка %s здесь нет — создайте его или уберите %s" % (fname, opt))
        return "%s=lists/%s" % (opt, fname), note
    return tok, ""


def missing_file(tok: str, env: dict):
    """{"kind", "name"} файла, на который ссылается токен и которого здесь
    нет (для ``missing_files`` ответа импорта), или None."""
    new_tok, note = adapt_token(tok, env)
    if not note:
        return None
    opt, _, val = new_tok.partition("=")
    if opt == "--lua-init":
        return {"kind": "lua", "name": os.path.basename(val[1:])}
    if opt == "--blob":
        return {"kind": "blob", "name": os.path.basename(val.partition(":@")[2])}
    return {"kind": "ipset" if opt in _IPSET_OPTS else "hostlist",
            "name": os.path.basename(val)}


def convert(text: str, env: dict) -> dict:
    """Разобрать и перенести. Чистая функция (кроме ``env['exists']``).

    Returns:
        {"ok", "kind", "kind_title", "profiles": [{"id","name","enabled",
         "args"}], "warnings": [...], "dropped": [...],
         "missing_files": [{"kind": "lua|blob|hostlist|ipset", "name"}]}
    """
    kind = detect(text)
    warnings, dropped = [], []
    sources, ifaces = _sources(text, kind)
    iface_exists = env.get("iface_exists")
    for var, value in ifaces.items():
        missing = [i for i in value.split()
                   if iface_exists and not iface_exists(i)]
        if missing:
            warnings.append(
                "интерфейса %s (%s) на этом роутере нет — внешний "
                "интерфейс GUI берёт из своих настроек"
                % (", ".join(missing), var))

    groups, extra, notes = [], [], []
    has_marker = False
    for var, value in sources:
        tokens = _merge_split_values(tokenize_args(value))
        if any(_MARKER_RE.fullmatch(t) for t in tokens):
            has_marker = True
        tokens = [t for t in tokens if not _MARKER_RE.fullmatch(t)]
        tokens = _strip_owned(tokens, dropped, notes)
        if _is_lists_only(tokens):
            extra += tokens
            continue
        for part in _split_new(tokens):
            groups.append((var, part))

    profiles = []
    missing = []        # файлы, которые надо создать (missing_files)
    carry = []          # глобальные --blob/--lua-init — к следующему профилю
    for var, part in groups:
        if any(t.startswith("--dpi-desync") for t in part):
            warnings.append("%sстратегия nfqws v1 (--dpi-desync) — для "
                            "nfqws2 её надо переписать на --lua-desync"
                            % ("%s: " % var if var else ""))
            carry += [t for t in part if t.startswith(_DECL)]
            continue
        if not any(t.startswith("--lua-desync=") for t in part):
            # Объявления (blob, lua-init) — едут к следующему профилю.
            carry += [t for t in part if t.startswith(_DECL)]
            rest = [t for t in part if not t.startswith(_DECL)]
            if rest:
                warnings.append("часть без --lua-desync пропущена: %s"
                                % " ".join(rest)[:120])
            continue
        part, carry = carry + part, []
        # Повторы внутри профиля НЕ схлопываем: у nfqws2 порядок опций —
        # смысл (--payload перед каждым --lua-desync). Не дублируем только
        # общие списки, если профиль уже их несёт.
        part += [t for t in extra if t not in part]
        args = []
        for t in part:
            new_tok, note = adapt_token(t, env)
            if note and note not in notes:
                notes.append(note)
            _note_missing(t, note, env, missing)
            args.append(new_tok)
        n = len(profiles) + 1
        profiles.append({"id": "import%d" % n,
                         "name": _profile_name(args, n, var),
                         "enabled": True, "args": " ".join(args)})
    if carry:
        if profiles:
            # Глобальные объявления после последнего --new: nfqws2 читает
            # их до первого профиля — ставим в начало первого.
            first = profiles[0]
            decl = []
            for t in carry:
                new_tok, note = adapt_token(t, env)
                if note and note not in notes:
                    notes.append(note)
                _note_missing(t, note, env, missing)
                decl.append(new_tok)
            first["args"] = " ".join(decl + [first["args"]])
        else:
            warnings.append("объявления без профиля пропущены: %s"
                            % " ".join(carry)[:120])
    if has_marker:
        notes.append("маркеры <HOSTLIST> убраны: списки подставит режим "
                     "фильтра GUI (Настройки → nfqws)")
    warnings += notes
    out = {"ok": bool(profiles), "kind": kind,
           "kind_title": KIND_TITLES.get(kind, kind),
           "profiles": profiles, "warnings": warnings,
           "dropped": sorted(set(dropped)), "missing_files": missing}
    if not profiles:
        out["error"] = ("не нашлось ни одного профиля nfqws2 с "
                        "--lua-desync" if kind != "zapret1" else
                        "это конфиг zapret v1 — стратегии nfqws2 в нём нет")
    return out


def _note_missing(tok: str, note: str, env: dict, missing: list):
    if note:
        item = missing_file(tok, env)
        if item and item not in missing:
            missing.append(item)


def _profile_name(args: list, n: int, var: str) -> str:
    for a in args:
        if a.startswith("--filter-tcp="):
            return "TCP %s" % a.split("=", 1)[1]
        if a.startswith("--filter-udp="):
            return "UDP %s" % a.split("=", 1)[1]
    return var or "Профиль %d" % n


def import_text(text: str) -> dict:
    """:func:`convert` с путями и файлами ЭТОГО устройства."""
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    env = {
        "lua_path": cfg.get("zapret", "lua_path", default="/opt/zapret2/lua"),
        "bin_path": cfg.get("zapret", "bin_path",
                            default="/opt/zapret2/files/fake"),
        "lists_path": cfg.get("zapret", "lists_path",
                              default="/opt/zapret2/lists"),
        "ipset_path": cfg.get("zapret", "ipset_path",
                              default="/opt/zapret2/ipset"),
        "exists": os.path.exists,
        "iface_exists": lambda i: os.path.exists("/sys/class/net/%s" % i),
    }
    return convert(text, env)
