# core/strategy_generator.py
"""
Генератор стратегий обхода DPI «на лету».

Вместо хранения тысяч готовых стратегий в файлах (как делает комбинаторный
перебор blockcheckw — ~13K строк в strategies/*.txt) генерируем их из
строительных блоков по запросу. Это:
  • не раздувает каталоги и UI-список;
  • даёт сканеру широкое покрытие без файлов на диске;
  • легко расширяется: добавил метод/позицию → получил все комбинации.

Идея и часть параметрических сеток заимствованы из rcd27/blockcheckw (MIT):
порядок перебора — от простых стратегий к сложным (ранжирование по
«сложности»), чтобы рабочая находилась раньше и щадила CPU роутера.

Выдаёт CatalogEntry с «голыми» args (один-два --lua-desync) — сканер сам
оборачивает их в шаблон цели (--filter-*/--payload/--hostlist), как и
обычные «приёмы» из basic/advanced каталогов.

API:
    from core.strategy_generator import generate, complexity_key
    entries = generate(protocol="tcp", level="standard")   # list[CatalogEntry]
"""

from __future__ import annotations

import re
from typing import Optional

from core.models import CatalogEntry


# ─────────────────────────────────────────────────────────────
#  Строительные блоки
# ─────────────────────────────────────────────────────────────

# Уровни «фулинга» (как сбиваем DPI на fake/split): имя → фрагмент параметров.
_FOOLING = {
    "":        "",
    "badseq":  "tcp_ack=-66000",
    "md5":     "tcp_md5",
    "ttl1":    "ip_ttl=1:ip6_ttl=1",
    "autottl": "ip_autottl=-1,3-20:ip6_autottl=-1,3-20",
}

# Позиции разреза для split/disorder.
_POSITIONS_QUICK = ["1", "midsld"]
_POSITIONS_STD = ["1", "2", "midsld", "sniext+1", "1,midsld"]
_POSITIONS_FULL = ["1", "2", "midsld", "sniext+1", "host+1", "1,midsld", "1,midsld,1220"]

# tcpseg-позиции и повторы (из blockcheckw).
_TCPSEG_POS = ["0,1", "0,midsld"]
_TCPSEG_REPEATS = {"quick": [1], "standard": [1, 20], "full": [1, 20, 100, 260]}

# oob urgent-pointer варианты.
_OOB_URP = {"quick": ["b"], "standard": ["b", "midsld"], "full": ["b", "0", "2", "midsld"]}

# Сетки на уровень.
_GRID = {
    "quick": {
        "positions": _POSITIONS_QUICK,
        "seqovl": [None],
        "fooling": ["", "badseq"],
        "repeats": [6],
    },
    "standard": {
        "positions": _POSITIONS_STD,
        "seqovl": [None, 1],
        "fooling": ["", "badseq", "md5"],
        "repeats": [6, 11],
    },
    "full": {
        "positions": _POSITIONS_FULL,
        "seqovl": [None, 1, 652],
        "fooling": ["", "badseq", "md5", "ttl1", "autottl"],
        "repeats": [2, 6, 11],
    },
}

# Встроенные blob-имена nfqws2 (регистрация не нужна).
_TLS_BLOB = "fake_default_tls"
_QUIC_BLOB = "fake_default_quic"


def _slug(s: str) -> str:
    """ID-безопасный слаг из строки args."""
    s = s.replace("--lua-desync=", "").replace("--in-range=", "ir_")
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()
    return s[:60]


def _join_params(*parts: str) -> str:
    """Склеить непустые параметры через ':' (формат nfqws2 lua-desync)."""
    return ":".join(p for p in parts if p)


def complexity_key(args_list: list[str]) -> tuple:
    """Ключ «сложности» стратегии для ранжирования (меньше = проще = раньше).

    Заимствовано из blockcheckw/rank.rs: при прочих равных предпочитаем
    стратегии с меньшим числом desync-действий, меньшим repeats и
    одноступенчатые (без --new / без предварительного send).

    Returns:
        (action_count, max_repeats, is_multi_stage)
    """
    action_count = sum(1 for a in args_list if a.startswith("--lua-desync="))
    max_repeats = 0
    multi_stage = 0
    for a in args_list:
        m = re.search(r"repeats=(\d+)", a)
        if m:
            max_repeats = max(max_repeats, int(m.group(1)))
        if a == "--new" or a.startswith("--lua-desync=send"):
            multi_stage = 1
    return (action_count, max_repeats, multi_stage)


# ─────────────────────────────────────────────────────────────
#  Генерация
# ─────────────────────────────────────────────────────────────

def _entry(desync_args: list[str], name: str, desc: str,
           protocol: str) -> CatalogEntry:
    args_str = "\n".join(desync_args)
    sid = "gen_" + _slug(" ".join(desync_args))
    return CatalogEntry(
        section_id=sid,
        name=name,
        description=desc,
        author="generator",
        label="generated",
        blobs=[],
        args=args_str,
        protocol=protocol,
        level="generated",
        source_file="generator",
    )


def _gen_tcp(level: str) -> list[CatalogEntry]:
    grid = _GRID[level]
    out: list[CatalogEntry] = []

    # multisplit / multidisorder по позициям × seqovl
    for method in ("multisplit", "multidisorder"):
        for pos in grid["positions"]:
            for seqovl in grid["seqovl"]:
                params = _join_params(
                    "pos=%s" % pos,
                    "seqovl=%d" % seqovl if seqovl else "",
                )
                arg = "--lua-desync=%s:%s" % (method, params)
                out.append(_entry(
                    [arg],
                    "%s pos=%s%s" % (method, pos,
                                     " seqovl=%d" % seqovl if seqovl else ""),
                    "Нарезка %s по позициям %s%s." % (
                        method, pos, " с seqovl=%d" % seqovl if seqovl else ""),
                    "tcp",
                ))

    # fakedsplit / fakeddisorder по позициям × фулинг
    for method in ("fakedsplit", "fakeddisorder"):
        for pos in grid["positions"][:3]:
            for fool in grid["fooling"]:
                params = _join_params("pos=%s" % pos, _FOOLING[fool])
                arg = "--lua-desync=%s:%s" % (method, params)
                out.append(_entry(
                    [arg],
                    "%s pos=%s%s" % (method, pos,
                                     " +%s" % fool if fool else ""),
                    "%s по позиции %s%s." % (
                        method, pos, " с фулингом %s" % fool if fool else ""),
                    "tcp",
                ))

    # fake (TLS) × repeats × фулинг
    for repeats in grid["repeats"]:
        for fool in grid["fooling"]:
            params = _join_params(
                "blob=%s" % _TLS_BLOB,
                "repeats=%d" % repeats,
                _FOOLING[fool],
            )
            arg = "--lua-desync=fake:%s" % params
            out.append(_entry(
                [arg],
                "fake TLS ×%d%s" % (repeats, " +%s" % fool if fool else ""),
                "Fake TLS-пакет, %d повторов%s." % (
                    repeats, " с фулингом %s" % fool if fool else ""),
                "tcp",
            ))

    # tcpseg (TCP-сегментация, из blockcheckw)
    for pos in _TCPSEG_POS:
        for repeats in _TCPSEG_REPEATS[level]:
            arg = "--lua-desync=tcpseg:pos=%s:ip_id=rnd:repeats=%d" % (pos, repeats)
            out.append(_entry(
                [arg],
                "tcpseg pos=%s ×%d" % (pos, repeats),
                "TCP-сегментация на позициях %s, %d повторов." % (pos, repeats),
                "tcp",
            ))
    # tcpseg + seqovl
    out.append(_entry(
        ["--lua-desync=tcpseg:pos=0,-1:seqovl=1"],
        "tcpseg seqovl=1",
        "TCP-сегментация с перекрытием по sequence.",
        "tcp",
    ))

    # oob urgent-pointer (из blockcheckw)
    for urp in _OOB_URP[level]:
        out.append(_entry(
            ["--in-range=-s1", "--lua-desync=oob:urp=%s" % urp],
            "oob urp=%s" % urp,
            "Out-of-band байт через TCP urgent pointer (urp=%s)." % urp,
            "tcp",
        ))

    return out


def _gen_udp(level: str) -> list[CatalogEntry]:
    grid = _GRID[level]
    out: list[CatalogEntry] = []
    # fake QUIC × repeats × (ttl)
    for repeats in grid["repeats"]:
        out.append(_entry(
            ["--lua-desync=fake:blob=%s:repeats=%d" % (_QUIC_BLOB, repeats)],
            "fake QUIC ×%d" % repeats,
            "Fake QUIC initial, %d повторов." % repeats,
            "udp",
        ))
        if level != "quick":
            out.append(_entry(
                ["--lua-desync=fake:blob=%s:repeats=%d:ip_ttl=1:ip6_ttl=1"
                 % (_QUIC_BLOB, repeats)],
                "fake QUIC ×%d ttl=1" % repeats,
                "Fake QUIC initial с ip_ttl=1, %d повторов." % repeats,
                "udp",
            ))
    return out


def _existing_args_set() -> set:
    """Нормализованные args всех записей каталога — для дедупликации."""
    seen: set = set()
    try:
        from core.catalog_loader import get_catalog_manager
        cm = get_catalog_manager()
        for key in cm.get_catalog_keys():
            lvl, proto = key.split("/")[0], key.split("/")[-1]
            for e in cm.get_catalog_entries(protocol=proto, level=lvl):
                seen.add(_norm_args(e.get_args_list()))
    except Exception:
        pass
    return seen


def _norm_args(args_list: list[str]) -> str:
    """Нормализовать args для сравнения (порядок desync сохраняем)."""
    return " ".join(a.strip() for a in args_list if a.strip())


def generate(
    protocol: str = "tcp",
    level: str = "standard",
    dedup_against_catalog: bool = True,
) -> list[CatalogEntry]:
    """Сгенерировать стратегии на лету.

    Args:
        protocol: "tcp" | "udp".
        level: "quick" | "standard" | "full" — размер сетки.
        dedup_against_catalog: убрать комбинации, уже присутствующие в каталоге.

    Returns:
        list[CatalogEntry], отсортированный от простых стратегий к сложным.
    """
    level = level if level in _GRID else "standard"
    protocol = "udp" if protocol == "udp" else "tcp"

    entries = _gen_udp(level) if protocol == "udp" else _gen_tcp(level)

    # Дедуп внутри генерации (по args) + против каталога.
    seen_gen: set = set()
    catalog_args = _existing_args_set() if dedup_against_catalog else set()
    unique: list[CatalogEntry] = []
    for e in entries:
        key = _norm_args(e.get_args_list())
        if key in seen_gen or key in catalog_args:
            continue
        seen_gen.add(key)
        unique.append(e)

    # Ранжирование: от простых к сложным (blockcheckw rank).
    unique.sort(key=lambda e: complexity_key(e.get_args_list()))
    return unique
