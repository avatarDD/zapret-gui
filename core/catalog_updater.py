# core/catalog_updater.py
"""
Обновление INI-каталогов стратегий nfqws2 из внешнего источника.

Источник: https://github.com/youtubediscord/zapret

Берём ДВА набора файлов:
  1) src/direct_preset/catalogs/winws2/{tcp,udp,http80,voice}.txt
     → catalogs/direct/{tcp,udp,http80,voice}.txt
     (одиночные приёмы desync для strategy scanner)

  2) src/core/presets/builtin/winws2/*.txt  (~90 файлов)
     → catalogs/builtin/winws2_presets.txt  (одна INI-сборка)
     (полные конфигурации с --filter-*, --new и глобалами)

Семантика обновления:
  * MERGE по section_id: обновляем существующие, добавляем новые,
    локальные секции, которых нет в upstream, сохраняются.
  * Никаких дубликатов section_id в результирующем файле.
  * winws2-пресеты получают префикс `winws2_` в section_id, чтобы не
    пересекаться с одиночными приёмами из direct-каталогов.
  * Windows-специфичные флаги (`--wf-*`) вырезаются при конвертации
    пресетов — они бесполезны для nfqws2 на Linux.

.lua-скриптов и .bin-блобов в этом репозитории нет — они
поставляются бинарной сборкой zapret2 (bol-van/zapret2) и
обновляются через core/zapret_installer.py.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import time
from collections import OrderedDict
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.log_buffer import log
from core.version import GUI_VERSION


# ── Настройки ─────────────────────────────────────────────────

SOURCE_OWNER = "youtubediscord"
SOURCE_REPO = "zapret"
SOURCE_BRANCH = "main"

# Путь в архиве: одиночные приёмы (для direct/)
SOURCE_DIRECT_SUBPATH = "src/direct_preset/catalogs/winws2"
CATALOG_FILES = ("tcp.txt", "udp.txt", "http80.txt", "voice.txt")

# Путь в архиве: full-пресеты (для builtin/winws2_presets.txt)
SOURCE_PRESETS_SUBPATH = "src/core/presets/builtin/winws2"

# Префикс для section_id winws2-пресетов (защита от коллизий с direct)
WINWS2_PREFIX = "winws2_"

GITHUB_COMMITS_API = (
    "https://api.github.com/repos/%s/%s/commits/%s"
    % (SOURCE_OWNER, SOURCE_REPO, SOURCE_BRANCH)
)
GITHUB_ARCHIVE_URL = (
    "https://github.com/%s/%s/archive/refs/heads/%s.tar.gz"
    % (SOURCE_OWNER, SOURCE_REPO, SOURCE_BRANCH)
)
GITHUB_REPO_URL = (
    "https://github.com/%s/%s" % (SOURCE_OWNER, SOURCE_REPO)
)

HTTP_TIMEOUT = 30
REMOTE_INFO_CACHE_TTL = 300  # 5 минут

# Автоопределение пути проекта (zapret-gui)
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TARGET_DIR = os.path.join(_APP_DIR, "catalogs", "direct")
_BUILTIN_DIR = os.path.join(_APP_DIR, "catalogs", "builtin")
_PRESETS_FILE = os.path.join(_BUILTIN_DIR, "winws2_presets.txt")
_STATE_FILE = os.path.join(_APP_DIR, "catalogs", ".direct_update.json")

# Лимит на размер одного файла каталога (защита от мусора)
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
# Лимит на размер одного preset-файла
_MAX_PRESET_SIZE = 256 * 1024  # 256 KB
# Лимит на количество preset-файлов
_MAX_PRESETS = 500

# Windows-специфичные флаги — вырезаем при конвертации пресетов
_WINDOWS_ONLY_PREFIXES = (
    "--wf-",              # WinDivert filter
)


class CatalogUpdater:
    """Проверка и обновление каталогов стратегий winws2."""

    def __init__(self):
        self._lock = threading.Lock()
        self._in_progress = False
        self._status = ""
        self._progress = 0

        self._remote_cache: Optional[dict] = None
        self._remote_cache_time: float = 0.0

    # ═══════════════════ PUBLIC API ═══════════════════

    def get_local_info(self) -> dict:
        """
        Информация о локальной версии каталогов.
        """
        files_info = []
        if os.path.isdir(_TARGET_DIR):
            for name in CATALOG_FILES:
                path = os.path.join(_TARGET_DIR, name)
                if not os.path.isfile(path):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                files_info.append({
                    "name": name,
                    "size": size,
                    "strategies": _count_strategies_in_file(path),
                })

        presets_info = None
        if os.path.isfile(_PRESETS_FILE):
            try:
                size = os.path.getsize(_PRESETS_FILE)
            except OSError:
                size = 0
            presets_info = {
                "name": os.path.basename(_PRESETS_FILE),
                "size": size,
                "strategies": _count_strategies_in_file(_PRESETS_FILE),
            }

        return {
            "target_dir": _TARGET_DIR,
            "files": files_info,
            "presets": presets_info,
            "last_update": _load_state(),
        }

    def get_remote_info(self, force_refresh: bool = False) -> dict:
        """
        Информация о последнем коммите в репозитории-источнике.
        """
        now = time.time()
        if (not force_refresh
                and self._remote_cache is not None
                and (now - self._remote_cache_time) < REMOTE_INFO_CACHE_TTL):
            return self._remote_cache

        result = {
            "ok": False,
            "sha": None,
            "short_sha": None,
            "committed_at": None,
            "message": None,
            "repo_url": GITHUB_REPO_URL,
            "error": None,
        }

        try:
            data = _fetch_json(GITHUB_COMMITS_API)
            sha = (data.get("sha") or "").strip()
            commit = data.get("commit") or {}
            author = commit.get("author") or {}

            result["ok"] = bool(sha)
            result["sha"] = sha or None
            result["short_sha"] = sha[:7] if sha else None
            result["committed_at"] = author.get("date")
            msg = commit.get("message") or ""
            result["message"] = msg.splitlines()[0][:200] if msg else None
        except Exception as e:
            result["error"] = str(e)
            log.error(
                "Ошибка получения версии каталогов с GitHub: %s" % e,
                source="catalog-updater",
            )

        self._remote_cache = result
        self._remote_cache_time = now
        return result

    def get_comparison(self, force_refresh: bool = False) -> dict:
        """
        Сравнить локальное и удалённое состояние.
        """
        local = self.get_local_info()
        remote = self.get_remote_info(force_refresh=force_refresh)

        update_available = False
        if remote.get("ok") and remote.get("sha"):
            last = local.get("last_update") or {}
            update_available = (last.get("sha") or "") != remote["sha"]
            if not last.get("sha"):
                update_available = True

        return {
            "local": local,
            "remote": remote,
            "update_available": update_available,
            "source_url": GITHUB_REPO_URL,
            "source_path": SOURCE_DIRECT_SUBPATH,
        }

    def update(self) -> dict:
        """Скачать и обновить каталоги (merge-семантика)."""
        with self._lock:
            if self._in_progress:
                return {
                    "ok": False,
                    "message": "Обновление уже выполняется",
                }
            self._in_progress = True
            self._status = "Начало обновления каталогов..."
            self._progress = 0

        try:
            return self._do_update()
        finally:
            with self._lock:
                self._in_progress = False

    def get_operation_status(self) -> dict:
        """Прогресс текущей операции."""
        with self._lock:
            return {
                "in_progress": self._in_progress,
                "status": self._status,
                "progress": self._progress,
            }

    # ═══════════════════ INTERNAL ═══════════════════

    def _set_progress(self, status: str, progress: int) -> None:
        with self._lock:
            self._status = status
            self._progress = max(0, min(100, progress))
        log.info(status, source="catalog-updater")

    def _do_update(self) -> dict:
        tmp_dir = tempfile.mkdtemp(prefix="zapret-catalog-update-")
        archive_path = os.path.join(tmp_dir, "source.tar.gz")

        try:
            # 1. Получаем SHA последнего коммита.
            self._set_progress("Проверка удалённой версии...", 5)
            remote = self.get_remote_info(force_refresh=True)
            if not remote.get("ok"):
                return {
                    "ok": False,
                    "message": (
                        "Не удалось получить информацию о репозитории: %s"
                        % (remote.get("error") or "неизвестная ошибка")
                    ),
                }

            # 2. Скачиваем архив.
            self._set_progress("Загрузка архива с GitHub...", 15)
            if not _download(GITHUB_ARCHIVE_URL, archive_path):
                return {
                    "ok": False,
                    "message": "Не удалось скачать архив с GitHub",
                }

            # 3. Извлекаем direct-каталоги (4 файла).
            self._set_progress("Распаковка direct-каталогов...", 35)
            direct_extracted = _extract_direct_catalogs(archive_path, tmp_dir)
            if not direct_extracted:
                return {
                    "ok": False,
                    "message": (
                        "В архиве не найдено файлов %s (путь %s)"
                        % (", ".join(CATALOG_FILES), SOURCE_DIRECT_SUBPATH)
                    ),
                }

            # 4. Извлекаем winws2 full-пресеты.
            self._set_progress("Распаковка winws2-пресетов...", 50)
            preset_files = _extract_preset_files(archive_path, tmp_dir)

            # 5. Бэкап.
            self._set_progress("Бэкап текущих каталогов...", 60)
            backup_dir = _backup_everything()

            # 6. Merge-установка direct-каталогов.
            self._set_progress("Установка direct-каталогов (merge)...", 70)
            os.makedirs(_TARGET_DIR, exist_ok=True)
            installed: list = []
            for name, src_path in direct_extracted.items():
                dst = os.path.join(_TARGET_DIR, name)
                merged, added, updated, preserved = _merge_file(dst, src_path)
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(merged)
                installed.append({
                    "name": name,
                    "size": os.path.getsize(dst),
                    "strategies": _count_strategies_in_file(dst),
                    "added": added,
                    "updated": updated,
                    "preserved": preserved,
                })

            # 7. Конвертация и merge winws2-пресетов.
            presets_info = None
            if preset_files:
                self._set_progress(
                    "Конвертация winws2-пресетов...", 80,
                )
                remote_presets_ini = _build_presets_ini(preset_files)
                os.makedirs(_BUILTIN_DIR, exist_ok=True)
                local_content = _read_text(_PRESETS_FILE)
                merged, added, updated, preserved = _merge_content(
                    local_content, remote_presets_ini,
                )
                with open(_PRESETS_FILE, "w", encoding="utf-8") as f:
                    f.write(merged)
                presets_info = {
                    "name": os.path.basename(_PRESETS_FILE),
                    "size": os.path.getsize(_PRESETS_FILE),
                    "strategies": _count_strategies_in_file(_PRESETS_FILE),
                    "added": added,
                    "updated": updated,
                    "preserved": preserved,
                    "source_files": len(preset_files),
                }

            # 8. Обновляем state-файл.
            state = {
                "sha": remote.get("sha"),
                "short_sha": remote.get("short_sha"),
                "committed_at": remote.get("committed_at"),
                "updated_at": _iso_now(),
                "source_url": GITHUB_REPO_URL,
                "source_path": SOURCE_DIRECT_SUBPATH,
                "files": [f["name"] for f in installed],
                "presets_file": (
                    os.path.basename(_PRESETS_FILE)
                    if presets_info else None
                ),
            }
            _save_state(state)

            # 8b. Досливаем bundled-ассеты (import/).
            # Это гарантирует что после обновления:
            #   * blobs/lua/lists на месте в /opt/zapret2/{bin,lua,lists}
            #   * basic/advanced/builtin каталоги включают локальные
            #     bundled-дополнения (если есть).
            self._set_progress("Импорт bundled-ассетов...", 88)
            try:
                from core.asset_importer import import_all as _import_all
                _import_all()
            except Exception as e:
                log.warning(
                    "Не удалось импортировать bundled-ассеты: %s" % e,
                    source="catalog-updater",
                )

            # 9. Перечитываем каталоги.
            self._set_progress("Перечитывание каталогов...", 95)
            try:
                from core.catalog_loader import get_catalog_manager
                get_catalog_manager().reload()
            except Exception as e:
                log.warning(
                    "Не удалось перечитать каталоги: %s" % e,
                    source="catalog-updater",
                )
            try:
                from core.strategy_builder import get_strategy_manager
                get_strategy_manager().load_strategies()
            except Exception as e:
                log.warning(
                    "Не удалось перечитать стратегии: %s" % e,
                    source="catalog-updater",
                )

            total_direct = sum(f["strategies"] for f in installed)
            total_presets = presets_info["strategies"] if presets_info else 0
            self._set_progress("Обновление завершено", 100)
            self._remote_cache = None

            log.success(
                "Каталоги обновлены до %s: direct=%d, winws2-presets=%d"
                % (remote.get("short_sha") or "?",
                   total_direct, total_presets),
                source="catalog-updater",
            )

            message_parts = [
                "Версия: %s." % (remote.get("short_sha") or "?"),
                "Direct: %d стратегий в %d файлах." % (
                    total_direct, len(installed),
                ),
            ]
            if presets_info:
                message_parts.append(
                    "Winws2-пресеты: %d стратегий." % total_presets,
                )

            return {
                "ok": True,
                "message": " ".join(message_parts),
                "details": {
                    "files": installed,
                    "presets": presets_info,
                    "sha": remote.get("sha"),
                    "short_sha": remote.get("short_sha"),
                    "committed_at": remote.get("committed_at"),
                    "backup_dir": backup_dir,
                },
            }

        except Exception as e:
            log.error(
                "Ошибка обновления каталогов: %s" % e,
                source="catalog-updater",
            )
            return {
                "ok": False,
                "message": "Ошибка обновления: %s" % e,
            }
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


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
                source="catalog-updater",
            )
            continue
        seen.add(sid)
        sections.append(text)

    return header + "\n\n" + "\n\n".join(sections) + "\n"


# ═══════════════════════════════════════════════════════════
#  Хелперы модуля
# ═══════════════════════════════════════════════════════════

def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fetch_json(url: str) -> dict:
    req = Request(
        url,
        headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "zapret-gui/%s" % GUI_VERSION,
        },
    )
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 403:
            raise Exception(
                "Лимит запросов GitHub API исчерпан. Попробуйте позже."
            )
        raise Exception("GitHub API вернул HTTP %d" % e.code)
    except URLError as e:
        raise Exception("Нет доступа к GitHub: %s" % e.reason)
    except json.JSONDecodeError:
        raise Exception("Ошибка разбора ответа GitHub API")


def _download(url: str, dest: str) -> bool:
    req = Request(
        url,
        headers={"User-Agent": "zapret-gui/%s" % GUI_VERSION},
    )
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        return True
    except (HTTPError, URLError, OSError) as e:
        log.error(
            "Ошибка загрузки %s: %s" % (url, e),
            source="catalog-updater",
        )
        return False


def _extract_direct_catalogs(archive_path: str, tmp_dir: str) -> dict:
    """Извлечь direct-каталоги (4 файла) из архива."""
    found: dict = {}
    wanted = set(CATALOG_FILES)
    suffix = "/" + SOURCE_DIRECT_SUBPATH.rstrip("/") + "/"

    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                path = member.name
                if suffix not in path:
                    continue
                basename = os.path.basename(path)
                if basename not in wanted:
                    continue
                if member.size > _MAX_FILE_SIZE:
                    log.warning(
                        "Пропущен слишком большой файл: %s (%d байт)"
                        % (path, member.size),
                        source="catalog-updater",
                    )
                    continue
                safe_name = "direct_" + basename
                dest = os.path.join(tmp_dir, safe_name)
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                with open(dest, "wb") as out:
                    shutil.copyfileobj(fobj, out)
                found[basename] = dest
    except (tarfile.TarError, OSError) as e:
        log.error(
            "Ошибка распаковки direct-каталогов: %s" % e,
            source="catalog-updater",
        )
        return {}

    return found


def _extract_preset_files(archive_path: str, tmp_dir: str) -> dict:
    """Извлечь все winws2 full-пресеты (*.txt) из архива."""
    found: dict = {}
    suffix = "/" + SOURCE_PRESETS_SUBPATH.rstrip("/") + "/"
    count = 0

    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                path = member.name
                if suffix not in path:
                    continue
                basename = os.path.basename(path)
                if not basename.lower().endswith(".txt"):
                    continue
                if basename.startswith("_"):
                    continue
                if member.size > _MAX_PRESET_SIZE:
                    log.warning(
                        "Пропущен большой winws2-пресет: %s (%d байт)"
                        % (path, member.size),
                        source="catalog-updater",
                    )
                    continue
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                try:
                    content = fobj.read().decode("utf-8", errors="replace")
                except Exception:
                    continue
                found[basename] = content
                count += 1
                if count > _MAX_PRESETS:
                    log.warning(
                        "Превышен лимит winws2-пресетов (%d)" % _MAX_PRESETS,
                        source="catalog-updater",
                    )
                    break
    except (tarfile.TarError, OSError) as e:
        log.error(
            "Ошибка распаковки winws2-пресетов: %s" % e,
            source="catalog-updater",
        )
        return {}

    return found


def _backup_everything() -> Optional[str]:
    """Бэкап direct/ и builtin/winws2_presets.txt."""
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    backup_dir = os.path.join(
        os.path.dirname(_TARGET_DIR),
        ".direct.backup.%s" % ts,
    )

    created = False
    try:
        os.makedirs(backup_dir, exist_ok=True)
        if os.path.isdir(_TARGET_DIR):
            for name in CATALOG_FILES:
                src = os.path.join(_TARGET_DIR, name)
                if os.path.isfile(src):
                    shutil.copy2(src, os.path.join(backup_dir, name))
                    created = True
        if os.path.isfile(_PRESETS_FILE):
            shutil.copy2(
                _PRESETS_FILE,
                os.path.join(backup_dir, os.path.basename(_PRESETS_FILE)),
            )
            created = True
    except OSError as e:
        log.warning(
            "Не удалось создать бэкап каталогов: %s" % e,
            source="catalog-updater",
        )
        return None

    if not created:
        try:
            os.rmdir(backup_dir)
        except OSError:
            pass
        return None

    return backup_dir


def _load_state() -> Optional[dict]:
    if not os.path.isfile(_STATE_FILE):
        return None
    try:
        with open(_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        return None
    return None


def _save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log.warning(
            "Не удалось сохранить state каталогов: %s" % e,
            source="catalog-updater",
        )


def _count_strategies_in_file(path: str) -> int:
    """Быстрый подсчёт секций [section_id] в INI-каталоге."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s.startswith("[") and s.endswith("]") and len(s) > 2:
                    count += 1
    except OSError:
        return 0
    return count


# ═══════════════════════════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════════════════════════

_instance: Optional[CatalogUpdater] = None
_instance_lock = threading.Lock()


def get_catalog_updater() -> CatalogUpdater:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = CatalogUpdater()
    return _instance
