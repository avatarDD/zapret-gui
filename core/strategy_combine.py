# core/strategy_combine.py
"""
Комбинированная стратегия из находок blockcheck2 по нескольким доменам.

Вход — список находок (как их отдаёт ``core/blockcheck2_multi``): домен,
тип теста, приём (``--payload=… --lua-desync=…``) и успешность ok/total.
Выход — профили nfqws2, склеенные через ``--new``: по профилю на
семейство трафика (HTTP / TLS / QUIC) и набор доменов, у которых этот
приём сработал.

Варианты сборки (``mode``):

  grouped    — минимум профилей: жадное покрытие множеств. Приём,
               сработавший у большинства ещё не покрытых доменов, берёт
               их всех одним профилем (``--hostlist-domains=a,b,c``), и так
               до покрытия всех. Это то же «COMMON», что печатает сам
               blockcheck2, но без требования «у всех сразу».
  per_domain — у каждого домена свой профиль с его лучшим приёмом.
  custom     — приём для пары (домен, семейство) выбран руками в GUI.
  all        — все сочетания: декартово произведение кандидатов по парам
               (домен, семейство). Домены с одинаковым выбранным приёмом
               склеиваются в один профиль, одинаковые итоговые наборы —
               дедуп. Число сочетаний растёт как произведение, поэтому
               возвращается не больше ``limit`` вариантов + полное число.

TLS 1.2 и TLS 1.3 — одно семейство (порт 443, ``tls_client_hello``). Если
домен проверялся обоими, кандидатами первыми идут приёмы, прошедшие оба
теста: браузер сам выбирает версию, и стратегия должна держать любую.

Профиль собирается по той же конвенции, что бейдж находки на вкладке
blockcheck2 (``web/js/pages/blockcheck2.js:_buildArgs``): фильтр из типа
теста, ``--hostlist-domains``, ``--payload`` (если приём его не задал) и
приём дословно. Глобальные опции из приёмов (``--blob=``, ``--lua-init=``)
выносятся в начало: декларации глобальны и обязаны стоять до первого
``--new`` (скил nfqws2-strategies §2, инвариант 6).

Модуль — чистые функции, без I/O.
"""

from __future__ import annotations

import itertools
import re


FAMILIES = {
    "http": {"proto": "tcp", "port": "80", "l7": "http",
             "payload": "http_req", "label": "HTTP"},
    "tls": {"proto": "tcp", "port": "443", "l7": "tls",
            "payload": "tls_client_hello", "label": "TLS"},
    "quic": {"proto": "udp", "port": "443", "l7": "quic",
             "payload": "quic_initial", "label": "QUIC"},
}
FAMILY_ORDER = ("http", "tls", "quic")

MODES = ("grouped", "per_domain", "custom", "all")

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

# Опции, которые в nfqws2 глобальны и должны идти до первого --new.
_GLOBAL_PREFIXES = ("--blob=", "--lua-init=")


def family_of(test: str) -> str:
    """Тип теста blockcheck2 → семейство (http/tls/quic)."""
    t = str(test or "").lower()
    if "http3" in t or "quic" in t:
        return "quic"
    if "tls" in t or "https" in t:
        return "tls"
    return "http"


def _norm(strategy: str) -> str:
    return re.sub(r"\s+", " ", str(strategy or "")).strip()


def _is_full(f: dict) -> bool:
    if f.get("full"):
        return True
    ok, total = f.get("ok"), f.get("total")
    try:
        return int(total) > 0 and int(ok) >= int(total)
    except (TypeError, ValueError):
        return False


def candidates(found, include_partial: bool = False) -> dict:
    """Кандидаты по паре (домен, семейство) в порядке предпочтения.

    Возвращает ``{(domain, family): [strategy, ...]}``. Порядок: сначала
    приёмы, прошедшие все проверенные тесты семейства у домена (для TLS —
    и 1.2, и 1.3), затем остальные — в порядке находки.
    """
    tests = {}       # (dom, fam) -> set(test)
    passed = {}      # (dom, fam) -> {strategy: set(test)}
    order = {}       # (dom, fam) -> [strategy] в порядке находки
    for f in found or []:
        if not include_partial and not _is_full(f):
            continue
        dom = str(f.get("domain") or "").strip().lower()
        strat = _norm(f.get("strategy"))
        if not dom or not strat:
            continue
        fam = family_of(f.get("test") or f.get("label"))
        key = (dom, fam)
        tests.setdefault(key, set()).add(f.get("test") or fam)
        passed.setdefault(key, {}).setdefault(strat, set()).add(
            f.get("test") or fam)
        lst = order.setdefault(key, [])
        if strat not in lst:
            lst.append(strat)
    out = {}
    for key, lst in order.items():
        need = tests[key]
        both = [s for s in lst if passed[key][s] >= need]
        rest = [s for s in lst if s not in both]
        out[key] = both + rest
    return out


def _profile_args(fam: str, domains, strategy: str) -> list:
    info = FAMILIES[fam]
    args = ["--filter-%s=%s" % (info["proto"], info["port"]),
            "--filter-l7=%s" % info["l7"]]
    if domains:
        args.append("--hostlist-domains=%s" % ",".join(domains))
    toks = strategy.split()
    if not any(t.startswith("--payload=") for t in toks):
        args.append("--payload=%s" % info["payload"])
    args.extend(toks)
    return args


def build_profiles(assign: dict) -> list:
    """{(domain, family): strategy} → профили, домены одного приёма вместе.

    Профиль: ``{family, label, domains, strategy, args}``; порядок —
    HTTP, TLS, QUIC, внутри — по первому появлению приёма.
    """
    groups = {}
    order = []
    for (dom, fam), strat in assign.items():
        if not strat:
            continue
        key = (fam, strat)
        if key not in groups:
            groups[key] = []
            order.append(key)
        if dom not in groups[key]:
            groups[key].append(dom)
    profiles = []
    for fam in FAMILY_ORDER:
        for key in order:
            if key[0] != fam:
                continue
            doms = groups[key]
            profiles.append({
                "family": fam,
                "label": FAMILIES[fam]["label"],
                "domains": list(doms),
                "strategy": key[1],
                "args": _profile_args(fam, doms, key[1]),
            })
    return profiles


def hoist_globals(profiles) -> tuple:
    """Вынести ``--blob=``/``--lua-init=`` из профилей в общий заголовок.

    Возвращает (globals, profiles) — профили с вырезанными глобальными
    опциями; дубликаты деклараций убраны.
    """
    globs = []
    out = []
    for p in profiles:
        keep = []
        for a in p["args"]:
            if a.startswith(_GLOBAL_PREFIXES):
                if a not in globs:
                    globs.append(a)
            else:
                keep.append(a)
        q = dict(p)
        q["args"] = keep
        out.append(q)
    return globs, out


def render(profiles) -> dict:
    """Профили → {args (строка с --new), globals, profiles}."""
    globs, profs = hoist_globals(profiles)
    parts = []
    for i, p in enumerate(profs):
        a = list(p["args"])
        if i == 0 and globs:
            a = globs + a
        parts.append(" ".join(a))
    return {
        "globals": globs,
        "profiles": [dict(p, args=" ".join(p["args"])) for p in profs],
        "args": " --new ".join(parts),
    }


def _grouped(cands: dict) -> dict:
    """Жадное покрытие: на семейство — приём, покрывающий больше доменов."""
    assign = {}
    for fam in FAMILY_ORDER:
        left = {dom for (dom, f) in cands if f == fam}
        while left:
            score = {}
            first_seen = {}
            n = 0
            for (dom, f), lst in cands.items():
                if f != fam or dom not in left:
                    continue
                for rank, s in enumerate(lst):
                    score.setdefault(s, [0, 0])
                    score[s][0] += 1
                    score[s][1] += rank        # меньше — предпочтительнее
                    if s not in first_seen:
                        first_seen[s] = n
                        n += 1
            if not score:
                break
            best = max(score, key=lambda s: (score[s][0], -score[s][1],
                                             -first_seen[s]))
            took = [dom for dom in sorted(left)
                    if best in cands.get((dom, fam), [])]
            for dom in took:
                assign[(dom, fam)] = best
                left.discard(dom)
    return assign


def combine(found, mode: str = "grouped", choices=None,
            include_partial: bool = False, limit: int = DEFAULT_LIMIT,
            families=None) -> dict:
    """Собрать комбинированную стратегию (или варианты) из находок.

    Args:
        found: находки blockcheck2 (domain, test, strategy, ok/total/full).
        mode: grouped | per_domain | custom | all.
        choices: для custom — ``{"домен|семейство": strategy}``.
        include_partial: брать и приёмы, прошедшие не все попытки.
        limit: потолок числа вариантов для ``all``.
        families: ограничить семействами (по умолчанию все найденные).

    Returns:
        dict: ``{ok, mode, variants: [{args, profiles, globals}],
        total_combinations, truncated, candidates}``;
        при ошибке — ``{ok: False, error}``.
    """
    mode = str(mode or "grouped")
    if mode not in MODES:
        return {"ok": False, "error": "mode: %s" % "|".join(MODES)}
    cands = candidates(found, include_partial=include_partial)
    if families:
        fams = {str(f) for f in families}
        cands = {k: v for k, v in cands.items() if k[1] in fams}
    if not cands:
        return {"ok": False,
                "error": "Нет рабочих стратегий для сборки"
                         + ("" if include_partial else
                            " (учитываются только прошедшие все попытки)")}
    try:
        limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT

    keys = sorted(cands, key=lambda k: (FAMILY_ORDER.index(k[1]), k[0]))
    total = 1
    for k in keys:
        total *= max(1, len(cands[k]))

    variants = []
    truncated = False
    if mode == "grouped":
        variants.append(render(build_profiles(_grouped(cands))))
    elif mode == "per_domain":
        variants.append(render(build_profiles(
            {k: cands[k][0] for k in keys})))
    elif mode == "custom":
        choices = choices or {}
        assign = {}
        for k in keys:
            want = _norm(choices.get("%s|%s" % k) or "")
            assign[k] = want if want in cands[k] else cands[k][0]
        variants.append(render(build_profiles(assign)))
    else:  # all
        seen = set()
        for combo in itertools.product(*(cands[k] for k in keys)):
            r = render(build_profiles(dict(zip(keys, combo))))
            if r["args"] in seen:
                continue
            seen.add(r["args"])
            if len(variants) >= limit:
                truncated = True
                break
            variants.append(r)

    return {
        "ok": True,
        "mode": mode,
        "variants": variants,
        "total_combinations": total,
        "truncated": truncated,
        "candidates": [
            {"domain": k[0], "family": k[1],
             "label": FAMILIES[k[1]]["label"], "strategies": cands[k]}
            for k in keys
        ],
    }
