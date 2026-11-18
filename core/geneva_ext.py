# core/geneva_ext.py
"""
x-стратегии geneva_c 2.0 и фейки zapret2 — общий договор с
Zapret2_AutoTuner.

**x-стратегия** — строка Geneva с x-действием (``xfake``, ``xsplit``,
``xwhen``…: функции zapret2, docs/EXT.md geneva_c) или триггером
``[L7:``, ``[FLOW:``, ``[META:``. Такие строки понимает только geneva_c
2.0 с ключом ``--ext`` сразу после команды (``run --ext …``,
``eval --ext …``, ``check --ext …``); обычные стратегии запускаются как
раньше, без ключа. Признак расширений в ``geneva version --json`` —
фича ``ext_xact``.

**Фейки zapret2** — файлы ``files/fake/*.bin`` установленного zapret2
(``zapret.base_path``, по умолчанию ``/opt/zapret2``). geneva получает
каждый как блоб ``--ext-blob z2_<имя>:@<файл>``, и стратегия называет
его по имени: ``xfake{blob=z2_tls_clienthello_vk_com;ttl=3}``. Имя —
одинаковое в zapret-gui и Zapret2_AutoTuner (``GenevaBlobs.NameOf``):

- берутся файлы ``*.bin``; имя — ``z2_`` + имя файла без расширения;
- латинские A–Z → a–z, любой другой символ вне ``[a-z0-9_]`` → ``_``
  (``discord-ip-discovery-with-port.bin`` →
  ``z2_discord_ip_discovery_with_port``);
- символ — кодовая точка Unicode: не ASCII даёт один ``_``;
- имя длиннее 63 символов (предел geneva_c), пустое (файл ``.bin``),
  файл пустой или больше 1 МБ, ссылка — не берутся; два файла с одним
  именем — берётся первый по пути (порядок кодовых точек).

Префикс ``z2_`` занят под фейки zapret2: другие блобы так не называются.
Свои блобы geneva (``fake_default_tls`` и т.п.) ничего не требуют.
"""

from __future__ import annotations

import os
import re

BLOB_PREFIX = "z2_"
BLOB_NAME_MAX = 63
BLOB_FILE_MAX = 1 << 20
DEFAULT_FAKE_DIR = "/opt/zapret2/files/fake"

# Фича geneva_c 2.0: x-действия (функции zapret2) по ключу --ext.
FEATURE = "ext_xact"

# Как GenevaStrategyText.NeedsExt в Zapret2_AutoTuner: действие на «x»
# (у Geneva их нет: tamper, duplicate, fragment, drop, sleep, trace) или
# триггер расширений.
_X_RE = re.compile(r"(?:^|[-(,])x[a-z0-9]+(?=[{(,)-]|$)|\[(?:L7|FLOW|META):")
_BLOB_RE = re.compile(r"(?<![A-Za-z0-9_])z2_[a-z0-9_]+")


def needs_ext(strategy) -> bool:
    """Нужен ли стратегии ``--ext`` (geneva_c 2.0)."""
    return bool(strategy) and bool(_X_RE.search(str(strategy)))


def blob_refs(strategy) -> list:
    """Фейки zapret2 (``z2_*``), которые называет стратегия, по порядку."""
    out = []
    for m in _BLOB_RE.finditer(str(strategy or "")):
        if m.group(0) not in out:
            out.append(m.group(0))
    return out


def blob_name(path: str) -> str:
    """Имя блоба файла фейка (правило выше). Символы — кодовые точки
    Unicode (в C# — ``Rune``), любая не ASCII — один ``_``."""
    base = os.path.basename(path)
    # как Path.GetFileNameWithoutExtension в C#: «.bin» — пустое имя
    stem = base[:-4] if base.endswith(".bin") else os.path.splitext(base)[0]
    chars = []
    for c in stem:
        if "A" <= c <= "Z":
            c = c.lower()
        chars.append(c if ("a" <= c <= "z" or "0" <= c <= "9" or c == "_")
                     else "_")
    return BLOB_PREFIX + "".join(chars)


def fake_dir() -> str:
    """Каталог фейков zapret2 — тот же, откуда их берёт nfqws2:
    ``zapret.bin_path``, без него ``<zapret.base_path>/files/fake``."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        path = cfg.get("zapret", "bin_path", default="")
        if path:
            return str(path)
        base = cfg.get("zapret", "base_path", default="/opt/zapret2")
    except Exception:                               # noqa: BLE001
        return DEFAULT_FAKE_DIR
    return os.path.join(str(base or "/opt/zapret2"), "files", "fake")


def blob_files(directory: str = None) -> list:
    """``[(имя, путь)]`` фейков каталога, по имени; пусто без каталога.

    Ссылки не берутся: geneva читает файлы от root, а каталог фейков —
    файлы поставки zapret2, а не чужие ссылки куда угодно.
    """
    directory = fake_dir() if directory is None else directory
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    picked = {}
    for fn in names:
        if not fn.endswith(".bin"):
            continue
        path = os.path.join(directory, fn)
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
        except OSError:
            continue
        if not 0 < size <= BLOB_FILE_MAX:
            continue
        name = blob_name(fn)
        if name == BLOB_PREFIX or len(name) > BLOB_NAME_MAX or \
                name in picked:
            continue
        picked[name] = path
    return sorted(picked.items())


def loaded_blobs(args) -> set:
    """Фейки, которые получил запущенный geneva (``--ext-blob ИМЯ:…``)."""
    out = set()
    args = list(args or [])
    for i, a in enumerate(args[:-1]):
        if a == "--ext-blob":
            out.add(str(args[i + 1]).split(":", 1)[0])
    return out


def fits_args(strategy, args) -> bool:
    """Заработает ли стратегия у процесса с такими ``args`` через сокет:
    x-стратегии нужен ``--ext`` и все её фейки, загруженные при запуске
    (geneva ищет блоб по имени на каждом пакете; не найденный просто не
    отправляется, без ошибки)."""
    if not needs_ext(strategy):
        return True
    args = list(args or [])
    return "--ext" in args and not missing_blobs(strategy,
                                                 loaded_blobs(args))


def missing_blobs(strategy, available) -> list:
    """Фейки ``z2_*`` стратегии, которых нет среди ``available``."""
    have = set(available or ())
    return [b for b in blob_refs(strategy) if b not in have]


def problem(strategy, features, available) -> str:
    """Почему стратегию нельзя запустить этой geneva, или ``""``.

    ``features`` — из ``geneva version --json``, ``available`` — имена
    фейков zapret2 (:func:`blob_files`).
    """
    if not needs_ext(strategy):
        return ""
    if FEATURE not in (features or ()):
        return ("x-стратегия: нужна geneva_c 2.0 — обновите geneva на "
                "странице «Обновления»")
    miss = missing_blobs(strategy, available)
    if miss:
        return ("нет фейков zapret2: %s — их даёт files/fake установленного "
                "zapret2" % ", ".join(miss[:5]))
    return ""


def argv(strategies, features, files=None) -> list:
    """Ключи после команды geneva: ``--ext`` и все фейки zapret2, если
    хоть одной стратегии нужны расширения и geneva их знает; иначе
    пусто (поведение как у geneva_c 1.x)."""
    if FEATURE not in (features or ()):
        return []
    if not any(needs_ext(s) for s in strategies or ()):
        return []
    files = blob_files() if files is None else files
    out = ["--ext"]
    for name, path in files:
        out += ["--ext-blob", "%s:@%s" % (name, path)]
    return out
