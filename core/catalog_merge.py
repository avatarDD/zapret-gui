# core/catalog_merge.py
"""
Разбор, merge и конвертация INI-каталогов стратегий nfqws2.

Каталоги живут в `catalogs/`:
  * `catalogs/direct/{tcp,udp,http80,voice}.txt` — одиночные приёмы desync
    (их разбирает strategy scanner);
  * `catalogs/builtin/winws2_presets.txt` — полные конфигурации winws2
    с `--filter-*`, `--new` и глобалами.

Здесь только работа с ТЕКСТОМ каталогов; ставит и обновляет файлы
`core/asset_importer.py` из bundled-ассетов (`import/`).

Семантика merge:
  * по section_id: обновляем существующие, добавляем новые, а локальные
    секции, которых нет в источнике, сохраняются в конце файла;
  * никаких дубликатов section_id в результирующем файле;
  * winws2-пресеты получают префикс `winws2_`, чтобы не пересекаться с
    одиночными приёмами из direct-каталогов;
  * Windows-специфичные флаги (`--wf-*`) вырезаются при конвертации
    пресетов — для nfqws2 на Linux они бесполезны.

Историческая справка. Раньше рядом жил CatalogUpdater: кнопка «Обновить
стратегии» тянула свежие каталоги из github.com/youtubediscord/zapret.
В августе 2026 этот источник сняли целиком — вместе со всей организацией
(404, как у Flowseal/zapret-discord-youtube месяцем раньше). Тянуть стало
неоткуда, и загрузчик убран: каталоги теперь приезжают только с самой
сборкой GUI (см. `import/`). Если появится новый доверенный источник,
загрузчик восстанавливается из истории git — merge-семантика, ради
которой всё и писалось, осталась здесь нетронутой.
"""

from __future__ import annotations

import os
import re
from collections import OrderedDict
from typing import Optional

from core.log_buffer import log


# Префикс для section_id winws2-пресетов (защита от коллизий с direct)
WINWS2_PREFIX = "winws2_"

# Windows-специфичные флаги — вырезаем при конвертации пресетов
_WINDOWS_ONLY_PREFIXES = (
    "--wf-",              # WinDivert filter
)



# ═══════════════════════════════════════════════════════════
#  INI-парсинг и merge
# ═══════════════════════════════════════════════════════════

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _parse_ini_sections(content: str) -> tuple:
    """
    Распарсить INI-каталог на (header_lines, OrderedDict[sid → section_text]).

    section_text включает строку [id] и все следующие строки до следующей
    секции или EOF.

    Дубликаты section_id в исходнике схлопываются (последний выигрывает).
    """
    header: list = []
    sections: "OrderedDict[str, list]" = OrderedDict()

    current_id: Optional[str] = None
    current_lines: list = []

    for line in content.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            if current_id is not None:
                sections[current_id] = current_lines
            current_id = m.group(1).strip()
            current_lines = [line]
        elif current_id is None:
            header.append(line)
        else:
            current_lines.append(line)

    if current_id is not None:
        sections[current_id] = current_lines

    text_sections: "OrderedDict[str, str]" = OrderedDict()
    for sid, lines in sections.items():
        text_sections[sid] = _trim_trailing_blank(lines)

    return header, text_sections


def _trim_trailing_blank(lines: list) -> str:
    buf = list(lines)
    while buf and not buf[-1].strip():
        buf.pop()
    return "\n".join(buf)


def _merge_content(local_content: str, remote_content: str) -> tuple:
    """
    Смерджить два INI-содержания по section_id.

    Правила:
      * remote побеждает на коллизии (актуальный апстрим).
      * Локальные секции, которых нет в remote — сохраняются в конце.
      * Дубликатов section_id в результате не бывает.

    Returns:
        (merged_text, added, updated, preserved)
    """
    local_header, local_sections = _parse_ini_sections(local_content or "")
    remote_header, remote_sections = _parse_ini_sections(remote_content or "")

    remote_ids = set(remote_sections.keys())
    local_ids = set(local_sections.keys())

    added_ids = remote_ids - local_ids
    updated_ids = remote_ids & local_ids
    preserved_ids = local_ids - remote_ids

    parts: list = []

    header_lines = remote_header if any(l.strip() for l in remote_header) \
        else local_header
    header_text = _trim_trailing_blank(list(header_lines))
    if header_text:
        parts.append(header_text)

    for sid, text in remote_sections.items():
        parts.append(text)

    if preserved_ids:
        preserved_chunks = [
            local_sections[sid]
            for sid in local_sections
            if sid in preserved_ids
        ]
        if preserved_chunks:
            parts.append(
                "# ─── Сохранённые локальные секции "
                "(отсутствуют в upstream) ───"
            )
            parts.extend(preserved_chunks)

    merged = "\n\n".join(p for p in parts if p) + "\n"
    return merged, len(added_ids), len(updated_ids), len(preserved_ids)


def _merge_file(local_path: str, remote_path: str) -> tuple:
    """Merge файлов. Возвращает (text, added, updated, preserved)."""
    local_content = _read_text(local_path)
    remote_content = _read_text(remote_path)
    return _merge_content(local_content, remote_content)


def _read_text(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ═══════════════════════════════════════════════════════════
#  Конвертация winws2 full-пресетов в INI
# ═══════════════════════════════════════════════════════════

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    s = text.lower().strip()
    s = s.replace("&", " and ")
    s = s.replace("+", " plus ")
    s = _SLUG_RE.sub("_", s)
    s = s.strip("_")
    return s


def _is_windows_only(line: str) -> bool:
    s = line.strip()
    return any(s.startswith(p) for p in _WINDOWS_ONLY_PREFIXES)


def _convert_preset(filename: str, content: str) -> Optional[tuple]:
    """
    Конвертировать один winws2-пресет в (section_id, section_ini_text).
    Возвращает None если пресет должен быть пропущен.
    """
    base = filename
    if base.startswith("_"):
        return None

    display_from_file = base
    if display_from_file.lower().endswith(".txt"):
        display_from_file = display_from_file[:-4]

    preset_name = display_from_file
    description = ""
    for line in content.splitlines():
        s = line.strip()
        if s.startswith("# Preset:"):
            v = s[len("# Preset:"):].strip()
            if v:
                preset_name = v
        elif s.startswith("# Description:"):
            description = s[len("# Description:"):].strip()

    body: list = []
    dropped_wf = 0
    for line in content.splitlines():
        raw = line.rstrip()
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if _is_windows_only(s):
            dropped_wf += 1
            continue
        body.append(s)

    if not body:
        return None

    slug = _slugify(preset_name) or _slugify(display_from_file) or "preset"
    section_id = WINWS2_PREFIX + slug

    lines: list = [
        "[%s]" % section_id,
        "name = %s" % preset_name,
        "author = youtubediscord/zapret",
    ]
    if description:
        lines.append("description = %s" % description.replace("\n", " "))
    if dropped_wf > 0:
        lines.append(
            "# (Удалено %d Windows-only WinDivert-флагов при конвертации)"
            % dropped_wf,
        )
    lines.append("")
    lines.extend(body)

    return section_id, "\n".join(lines)


def _build_presets_ini(preset_files: dict) -> str:
    """Собрать единый INI-текст из словаря {filename: content}."""
    header = (
        "# ─────────────────────────────────────────────────────────────\n"
        "#  winws2 full-presets (конвертированы из youtubediscord/zapret)\n"
        "#\n"
        "#  Источник: src/core/presets/builtin/winws2/*.txt\n"
        "#  Файл пересоздаётся при обновлении каталогов, но секции,\n"
        "#  отсутствующие в upstream, сохраняются в конце файла.\n"
        "#\n"
        "#  Windows-специфичные флаги (--wf-*) вырезаются при\n"
        "#  конвертации. Прочие флаги (--lua-init=@lua/..., --blob=...,\n"
        "#  --ctrack-*, --ipcache-*, --filter-*, --lua-desync=*)\n"
        "#  сохраняются как есть; @lua/ и @bin/ резолвятся nfqws2.\n"
        "# ─────────────────────────────────────────────────────────────"
    )

    seen: set = set()
    sections: list = []
    for fname in sorted(preset_files.keys()):
        result = _convert_preset(fname, preset_files[fname])
        if result is None:
            continue
        sid, text = result
        if sid in seen:
            log.warning(
                "Пропущен дубликат winws2-пресета: %s (файл %s)"
                % (sid, fname),
                source="catalog-merge",
            )
            continue
        seen.add(sid)
        sections.append(text)

    return header + "\n\n" + "\n\n".join(sections) + "\n"
