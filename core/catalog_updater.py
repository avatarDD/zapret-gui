# core/catalog_updater.py
"""
Обновление INI-каталогов стратегий nfqws2 из внешнего источника.

Источник: https://github.com/youtubediscord/zapret
Путь в репозитории: src/direct_preset/catalogs/winws2/{tcp,udp,http80,voice}.txt

Файлы ровно в том же INI-формате, что и наши catalogs/direct/*.txt
(см. core/catalog_loader.py). В репозитории youtubediscord/zapret нет
.lua и .bin-блобов — они поставляются бинарной сборкой zapret2
(bol-van/zapret2) и обновляются через core/zapret_installer.py.

Singleton: get_catalog_updater().
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import threading
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.log_buffer import log
from core.version import GUI_VERSION


# ── Настройки ─────────────────────────────────────────────────

SOURCE_OWNER = "youtubediscord"
SOURCE_REPO = "zapret"
SOURCE_BRANCH = "main"

# Путь внутри архива до директории с каталогами nfqws2
SOURCE_SUBPATH = "src/direct_preset/catalogs/winws2"

# Имена файлов, которые мы извлекаем и которые имеют смысл для nfqws2
CATALOG_FILES = ("tcp.txt", "udp.txt", "http80.txt", "voice.txt")

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
_STATE_FILE = os.path.join(_APP_DIR, "catalogs", ".direct_update.json")

# Лимит на размер одного файла каталога (защита от мусора)
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


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

        Returns:
            {
                "target_dir": str,
                "files": [{"name": str, "size": int, "strategies": int}, ...],
                "last_update": {
                    "sha": str | None,
                    "short_sha": str | None,
                    "committed_at": str | None,
                    "updated_at": str | None,
                } | None,
            }
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

        return {
            "target_dir": _TARGET_DIR,
            "files": files_info,
            "last_update": _load_state(),
        }

    def get_remote_info(self, force_refresh: bool = False) -> dict:
        """
        Информация о последнем коммите в репозитории-источнике.

        Returns:
            {
                "ok": bool,
                "sha": str | None,
                "short_sha": str | None,
                "committed_at": str | None,
                "message": str | None,
                "repo_url": str,
                "error": str | None,
            }
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

        Returns:
            {
                "local": {...},
                "remote": {...},
                "update_available": bool,
                "source_url": str,
                "source_path": str,
                "note": str,
            }
        """
        local = self.get_local_info()
        remote = self.get_remote_info(force_refresh=force_refresh)

        update_available = False
        if remote.get("ok") and remote.get("sha"):
            last = local.get("last_update") or {}
            update_available = (last.get("sha") or "") != remote["sha"]
            # Если локально нет отметки — считаем, что обновление доступно.
            if not last.get("sha"):
                update_available = True

        return {
            "local": local,
            "remote": remote,
            "update_available": update_available,
            "source_url": GITHUB_REPO_URL,
            "source_path": SOURCE_SUBPATH,
        }

    def update(self) -> dict:
        """
        Скачать и установить последние каталоги winws2.

        Returns:
            {"ok": bool, "message": str, "details": {...}}
        """
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
            # 1. Получить SHA последнего коммита (для записи в state).
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

            # 2. Скачать архив main-ветки.
            self._set_progress("Загрузка архива с GitHub...", 15)
            if not _download(GITHUB_ARCHIVE_URL, archive_path):
                return {
                    "ok": False,
                    "message": "Не удалось скачать архив с GitHub",
                }

            # 3. Распаковать только нужные файлы.
            self._set_progress("Распаковка каталогов...", 45)
            extracted = _extract_catalogs(archive_path, tmp_dir)
            if not extracted:
                return {
                    "ok": False,
                    "message": (
                        "В архиве не найдено файлов %s (путь %s)"
                        % (", ".join(CATALOG_FILES), SOURCE_SUBPATH)
                    ),
                }

            # 4. Бэкап текущих файлов.
            self._set_progress("Бэкап текущих каталогов...", 65)
            backup_dir = _backup_target()

            # 5. Копируем новые файлы.
            self._set_progress("Установка новых каталогов...", 80)
            os.makedirs(_TARGET_DIR, exist_ok=True)
            installed = []
            for name, src_path in extracted.items():
                dst = os.path.join(_TARGET_DIR, name)
                shutil.copy2(src_path, dst)
                installed.append({
                    "name": name,
                    "size": os.path.getsize(dst),
                    "strategies": _count_strategies_in_file(dst),
                })

            # 6. Обновляем state-файл.
            state = {
                "sha": remote.get("sha"),
                "short_sha": remote.get("short_sha"),
                "committed_at": remote.get("committed_at"),
                "updated_at": _iso_now(),
                "source_url": GITHUB_REPO_URL,
                "source_path": SOURCE_SUBPATH,
                "files": [f["name"] for f in installed],
            }
            _save_state(state)

            # 7. Инвалидация кэша CatalogManager.
            self._set_progress("Перечитывание каталогов...", 95)
            try:
                from core.catalog_loader import get_catalog_manager
                get_catalog_manager().reload()
            except Exception as e:
                log.warning(
                    "Не удалось перечитать каталоги после обновления: %s" % e,
                    source="catalog-updater",
                )

            total_strategies = sum(f["strategies"] for f in installed)
            self._set_progress("Обновление завершено", 100)
            self._remote_cache = None  # форсируем пересчёт сравнения

            log.success(
                "Каталоги winws2 обновлены до %s (%d стратегий в %d файлах)"
                % (remote.get("short_sha") or "?",
                   total_strategies, len(installed)),
                source="catalog-updater",
            )

            return {
                "ok": True,
                "message": (
                    "Обновлено %d каталогов, всего стратегий: %d. Версия: %s."
                    % (len(installed), total_strategies,
                       remote.get("short_sha") or "?")
                ),
                "details": {
                    "files": installed,
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


def _extract_catalogs(archive_path: str, tmp_dir: str) -> dict:
    """
    Извлечь из tar.gz-архива только нужные файлы каталогов winws2.

    Возвращает: {filename: extracted_path, ...}
    """
    found: dict = {}
    wanted = set(CATALOG_FILES)
    # Суффикс внутри архива: <repo>-<branch>/src/direct_preset/catalogs/winws2/<file>
    suffix = "/" + SOURCE_SUBPATH.rstrip("/") + "/"

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
                # Защита от слишком больших файлов.
                if member.size > _MAX_FILE_SIZE:
                    log.warning(
                        "Пропущен слишком большой файл: %s (%d байт)"
                        % (path, member.size),
                        source="catalog-updater",
                    )
                    continue
                # Защита от path traversal при извлечении.
                safe_name = "extracted_" + basename
                dest = os.path.join(tmp_dir, safe_name)
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                with open(dest, "wb") as out:
                    shutil.copyfileobj(fobj, out)
                found[basename] = dest
    except (tarfile.TarError, OSError) as e:
        log.error(
            "Ошибка распаковки архива: %s" % e,
            source="catalog-updater",
        )
        return {}

    return found


def _backup_target() -> Optional[str]:
    """
    Скопировать текущее содержимое catalogs/direct/ в соседнюю папку
    .direct.backup.<timestamp>/. Возвращает путь бэкапа или None.
    """
    if not os.path.isdir(_TARGET_DIR):
        return None

    has_any = False
    for name in CATALOG_FILES:
        if os.path.isfile(os.path.join(_TARGET_DIR, name)):
            has_any = True
            break
    if not has_any:
        return None

    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    backup_dir = os.path.join(
        os.path.dirname(_TARGET_DIR),
        ".direct.backup.%s" % ts,
    )
    try:
        os.makedirs(backup_dir, exist_ok=True)
        for name in CATALOG_FILES:
            src = os.path.join(_TARGET_DIR, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(backup_dir, name))
        return backup_dir
    except OSError as e:
        log.warning(
            "Не удалось создать бэкап каталогов: %s" % e,
            source="catalog-updater",
        )
        return None


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
