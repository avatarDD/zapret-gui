# core/gui_updater.py
"""
Проверка и обновление zapret-gui из GitHub.

Аналог core/zapret_installer.py, но для самого GUI:
  - Проверка последней версии через GitHub API
  - Сравнение с текущей установленной
  - Обновление на месте (скачать архив → распаковать → перезапустить)

Singleton: get_gui_updater()
"""

import json
import os
import shutil
import subprocess
import tarfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.log_buffer import log
from core.version import GUI_VERSION


# ── Настройки ─────────────────────────────────────────────────

GITHUB_API_URL = "https://api.github.com/repos/avatarDD/zapret-gui/releases/latest"
GITHUB_RELEASES_URL = "https://github.com/avatarDD/zapret-gui/releases"
GITHUB_REPO_URL = "https://github.com/avatarDD/zapret-gui"

HTTP_TIMEOUT = 30
REMOTE_VERSION_CACHE_TTL = 300  # 5 минут

# Автоопределение пути установки GUI
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GuiUpdater:
    """Проверка обновлений и самообновление zapret-gui."""

    def __init__(self):
        self._lock = threading.Lock()
        self._operation_in_progress = False
        self._operation_status = ""
        self._operation_progress = 0

        # Кэш удалённой версии
        self._remote_version_cache = None
        self._remote_version_time = 0

    # ═══════════════════ PUBLIC API ═══════════════════

    def get_installed_version(self) -> dict:
        """
        Текущая установленная версия GUI.

        Returns:
            {
                "version": str,       # "0.14.0"
                "app_dir": str,       # "/opt/share/zapret-gui"
            }
        """
        return {
            "version": GUI_VERSION,
            "app_dir": _APP_DIR,
        }

    def get_latest_version(self, force_refresh: bool = False) -> dict:
        """
        Последняя доступная версия из GitHub Releases.

        Returns:
            {
                "ok": bool,
                "version": str | None,      # "0.14.1"
                "tag_name": str | None,      # "v0.14.1"
                "published_at": str | None,
                "release_url": str,
                "description": str | None,
                "error": str | None,
            }
        """
        now = time.time()
        if (not force_refresh
                and self._remote_version_cache is not None
                and (now - self._remote_version_time) < REMOTE_VERSION_CACHE_TTL):
            return self._remote_version_cache

        result = {
            "ok": False,
            "version": None,
            "tag_name": None,
            "published_at": None,
            "release_url": GITHUB_RELEASES_URL,
            "description": None,
            "error": None,
        }

        try:
            data = self._fetch_github_latest_release()
            if data:
                tag = data.get("tag_name", "").strip()
                result["ok"] = True
                result["tag_name"] = tag
                result["version"] = tag.lstrip("v")
                result["published_at"] = data.get("published_at")
                result["release_url"] = data.get(
                    "html_url", GITHUB_RELEASES_URL
                )
                result["description"] = (data.get("body") or "")[:500]
        except Exception as e:
            result["error"] = str(e)
            log.error(
                "Ошибка получения версии GUI с GitHub: %s" % e,
                source="gui-updater",
            )

        self._remote_version_cache = result
        self._remote_version_time = now
        return result

    def get_version_comparison(self) -> dict:
        """
        Сравнить установленную и последнюю версии GUI.

        Returns:
            {
                "installed_version": str,
                "latest_version": str | None,
                "update_available": bool,
                "release_url": str,
                "description": str | None,
                "error": str | None,
            }
        """
        installed = self.get_installed_version()
        latest = self.get_latest_version()

        update_available = False
        if latest["ok"] and latest["version"]:
            update_available = self._is_newer_version(
                installed["version"], latest["version"]
            )

        return {
            "installed_version": installed["version"],
            "latest_version": latest.get("version"),
            "update_available": update_available,
            "release_url": latest.get("release_url", GITHUB_RELEASES_URL),
            "description": latest.get("description"),
            "published_at": latest.get("published_at"),
            "error": latest.get("error"),
        }

    def update(self, branch: str = "main") -> dict:
        """
        Обновить zapret-gui из GitHub.

        Скачивает архив ветки, распаковывает поверх текущей установки,
        сохраняя конфигурацию и пользовательские стратегии.

        Returns:
            {"ok": bool, "message": str, "version": str | None}
        """
        with self._lock:
            if self._operation_in_progress:
                return {"ok": False, "message": "Операция уже выполняется"}
            self._operation_in_progress = True
            self._operation_status = "Начало обновления GUI..."
            self._operation_progress = 0

        try:
            return self._do_update(branch)
        finally:
            with self._lock:
                self._operation_in_progress = False

    def get_operation_status(self) -> dict:
        """Статус текущей операции."""
        with self._lock:
            return {
                "in_progress": self._operation_in_progress,
                "status": self._operation_status,
                "progress": self._operation_progress,
            }

    # ═══════════════════ INTERNAL ═══════════════════

    def _set_progress(self, status: str, progress: int) -> None:
        with self._lock:
            self._operation_status = status
            self._operation_progress = min(100, max(0, progress))

    def _do_update(self, branch: str) -> dict:
        """Основная логика обновления."""
        app_dir = _APP_DIR
        tmp_dir = "/tmp/zapret-gui-update-%d" % os.getpid()

        try:
            # 1. Скачать архив
            self._set_progress("Загрузка с GitHub...", 10)
            archive_path = os.path.join(tmp_dir, "gui.tar.gz")
            os.makedirs(tmp_dir, exist_ok=True)

            archive_url = (
                "%s/archive/refs/heads/%s.tar.gz"
                % (GITHUB_REPO_URL, branch)
            )
            if not self._download_file(archive_url, archive_path):
                return {
                    "ok": False,
                    "message": "Не удалось скачать архив с GitHub",
                    "version": None,
                }

            self._set_progress("Распаковка...", 30)

            # 2. Распаковать
            try:
                with tarfile.open(archive_path, "r:gz") as tf:
                    tf.extractall(tmp_dir)
            except (tarfile.TarError, OSError) as e:
                return {
                    "ok": False,
                    "message": "Ошибка распаковки: %s" % e,
                    "version": None,
                }

            # Найти корневую директорию в архиве
            src_dir = None
            for entry in os.listdir(tmp_dir):
                full = os.path.join(tmp_dir, entry)
                if os.path.isdir(full) and entry != "__MACOSX":
                    src_dir = full
                    break

            if not src_dir:
                return {
                    "ok": False,
                    "message": "Не найдена директория проекта в архиве",
                    "version": None,
                }

            self._set_progress("Бэкап конфигурации...", 45)

            self._set_progress("Обновление файлов...", 55)

            # 4. Копировать новые файлы поверх старых
            dirs_to_update = [
                "api", "core", "web", "config", "catalogs", "data",
            ]
            files_to_update = ["app.py"]

            for d in dirs_to_update:
                src = os.path.join(src_dir, d)
                dst = os.path.join(app_dir, d)
                if os.path.isdir(src):
                    # Удаляем старое (кроме user-данных)
                    if os.path.isdir(dst):
                        # Для config — не удаляем user strategies
                        if d == "config":
                            self._safe_update_config_dir(src, dst)
                        else:
                            shutil.rmtree(dst, ignore_errors=True)
                            shutil.copytree(src, dst)
                    else:
                        shutil.copytree(src, dst)

            for f in files_to_update:
                src = os.path.join(src_dir, f)
                dst = os.path.join(app_dir, f)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

            self._set_progress("Очистка кэша...", 90)
            for root, dirs, _files in os.walk(app_dir):
                for d in dirs:
                    if d == "__pycache__":
                        shutil.rmtree(
                            os.path.join(root, d), ignore_errors=True
                        )

            # 7. Прочитать новую версию
            new_version = self._read_version_from_dir(src_dir)

            self._set_progress("Обновление завершено!", 100)

            # Сброс кэша
            self._remote_version_cache = None

            log.success(
                "GUI обновлён до %s" % (new_version or "новой версии"),
                source="gui-updater",
            )

            return {
                "ok": True,
                "message": (
                    "GUI обновлён до версии %s. "
                    "Перезагрузите страницу (F5) для применения."
                    % (new_version or "?")
                ),
                "version": new_version,
                "restart_required": True,
            }

        except Exception as e:
            log.error("Ошибка обновления GUI: %s" % e, source="gui-updater")
            return {
                "ok": False,
                "message": "Ошибка обновления: %s" % e,
                "version": None,
            }
        finally:
            # Очистка tmp
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _safe_update_config_dir(self, src: str, dst: str) -> None:
        """
        Обновить config/ без потери user strategies и settings.
        """
        # Сохраняем user strategies во временное место
        user_dir = os.path.join(dst, "strategies", "user")
        user_backup = None
        if os.path.isdir(user_dir):
            user_backup = user_dir + ".bak"
            if os.path.exists(user_backup):
                shutil.rmtree(user_backup, ignore_errors=True)
            shutil.copytree(user_dir, user_backup)

        # Обновляем
        # Не удаляем dst целиком — копируем содержимое поверх
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                if item == "strategies":
                    # Обновляем builtin, но не user
                    builtin_src = os.path.join(s, "builtin")
                    builtin_dst = os.path.join(d, "builtin")
                    if os.path.isdir(builtin_src):
                        if os.path.isdir(builtin_dst):
                            shutil.rmtree(builtin_dst, ignore_errors=True)
                        shutil.copytree(builtin_src, builtin_dst)
                else:
                    if os.path.isdir(d):
                        shutil.rmtree(d, ignore_errors=True)
                    shutil.copytree(s, d)
            elif os.path.isfile(s):
                shutil.copy2(s, d)

        # Восстанавливаем user strategies
        if user_backup and os.path.isdir(user_backup):
            os.makedirs(user_dir, exist_ok=True)
            for item in os.listdir(user_backup):
                s = os.path.join(user_backup, item)
                d = os.path.join(user_dir, item)
                if os.path.isfile(s):
                    shutil.copy2(s, d)
            shutil.rmtree(user_backup, ignore_errors=True)

    def _read_version_from_dir(self, src_dir: str) -> str:
        """Прочитать версию из скачанного проекта."""
        version_file = os.path.join(src_dir, "core", "version.py")
        if os.path.isfile(version_file):
            try:
                with open(version_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("GUI_VERSION"):
                            # GUI_VERSION = "0.14.1"
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                return (
                                    parts[1]
                                    .strip()
                                    .strip("'\"")
                                )
            except (IOError, OSError):
                pass
        return None

    def _download_file(self, url: str, dest: str) -> bool:
        """Скачать файл."""
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
                source="gui-updater",
            )
            return False

    def _fetch_github_latest_release(self) -> dict:
        """Получить данные последнего релиза с GitHub API."""
        req = Request(
            GITHUB_API_URL,
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
                    "Лимит запросов GitHub API исчерпан. "
                    "Попробуйте позже."
                )
            raise Exception("GitHub API вернул HTTP %d" % e.code)
        except URLError as e:
            raise Exception("Нет доступа к GitHub: %s" % e.reason)
        except json.JSONDecodeError:
            raise Exception("Ошибка разбора ответа GitHub API")

    def _is_newer_version(self, installed: str, latest: str) -> bool:
        """Проверить, является ли latest более новой версией."""
        def parse_ver(v):
            v = v.lstrip("v").strip()
            parts = []
            for p in v.split("."):
                try:
                    parts.append(int(p))
                except ValueError:
                    parts.append(0)
            return parts

        try:
            inst_parts = parse_ver(installed)
            lat_parts = parse_ver(latest)
            maxlen = max(len(inst_parts), len(lat_parts))
            inst_parts += [0] * (maxlen - len(inst_parts))
            lat_parts += [0] * (maxlen - len(lat_parts))
            return lat_parts > inst_parts
        except Exception:
            return installed.lstrip("v") != latest.lstrip("v")


# ═══════════════════════════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════════════════════════

_instance = None
_lock = threading.Lock()


def get_gui_updater() -> GuiUpdater:
    """Получить глобальный экземпляр GuiUpdater."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = GuiUpdater()
    return _instance
