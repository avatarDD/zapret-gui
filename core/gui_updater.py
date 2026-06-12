# core/gui_updater.py
"""
Проверка и обновление zapret-gui из GitHub.

Аналог core/zapret_installer.py, но для самого GUI:
  - Проверка последней версии через GitHub API
  - Сравнение с текущей установленной
  - Обновление на месте (скачать архив → распаковать → перезапустить)

Singleton: get_gui_updater()
"""

from __future__ import annotations

import json
import os
import re
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
GITHUB_API_RELEASES = "https://api.github.com/repos/avatarDD/zapret-gui/releases"
GITHUB_RELEASES_URL = "https://github.com/avatarDD/zapret-gui/releases"
GITHUB_REPO_URL = "https://github.com/avatarDD/zapret-gui"

# Тэг GUI-релиза: vX.Y[.Z]. Бинарные релизы (singbox-bin-*/awg-bin-*/
# manual-*) под этот шаблон не подходят и при проверке обновлений
# игнорируются.
_GUI_TAG_RE = re.compile(r"^v?\d+\.\d+(\.\d+)?$")

HTTP_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 300       # архив всего GUI — на роутере качается долго
REMOTE_VERSION_CACHE_TTL = 300  # 5 минут
RELEASES_CACHE_TTL = 300


def _http_get_json(url: str, transport: str = "", timeout: int = HTTP_TIMEOUT):
    """
    GET JSON с GitHub через выбранный транспорт скачивания.

    transport='' — обычное соединение; иначе через AWG/sing-box/mihomo
    (см. core/download_transport). URL переписывается на зеркало
    (resolve_url). Используется для списка версий и резолва последнего
    тэга — чтобы выбор/установка работали и при заблокированном GitHub.
    """
    from core.binary_installer import resolve_url
    from core.download_transport import urlopen_via
    with urlopen_via(
            resolve_url(url), transport=transport, timeout=timeout,
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": "zapret-gui/%s" % GUI_VERSION}) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))

# Автоопределение пути установки GUI
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Кандидаты init-скриптов сервиса. Первый существующий и исполняемый —
# побеждает (Entware → S99zapret-gui, OpenWrt → /etc/init.d/zapret-gui).
_SERVICE_INIT_SCRIPTS = [
    "/opt/etc/init.d/S99zapret-gui",
    "/etc/init.d/zapret-gui",
]

# Имя systemd-юнита (создаётся install.sh на generic Linux с systemctl).
_SYSTEMD_UNIT = "zapret-gui"


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

        # Кэш списка релизов (для выбора версии)
        self._releases_cache = None
        self._releases_time = 0

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

    def list_releases(self, transport: str = "", force: bool = False,
                      limit: int = 30) -> dict:
        """
        Список релизов GUI (тэги vX.Y[.Z]) для выбора версии при
        обновлении — последняя по умолчанию, но можно поставить старую.

        Бинарные релизы (singbox-bin-*/awg-bin-*/manual-*) и предрелизы
        отсеиваются (_GUI_TAG_RE + флаги draft/prerelease). transport —
        через что обращаться к GitHub. Кэш 5 минут. Бросает RuntimeError
        при недоступности GitHub.

        Returns: {"ok": True, "releases": [{tag, version, published_at,
                  description}]}
        """
        now = time.time()
        with self._lock:
            if (self._releases_cache is not None and not force
                    and (now - self._releases_time) < RELEASES_CACHE_TTL):
                return self._releases_cache

        rels = []
        want = max(1, min(int(limit or 30), 100))
        for page in (1, 2):
            url = "%s?per_page=100&page=%d" % (GITHUB_API_RELEASES, page)
            try:
                data = _http_get_json(url, transport=transport)
            except HTTPError as e:
                if e.code == 403:
                    raise RuntimeError("Лимит запросов GitHub API исчерпан. "
                                       "Попробуйте позже.")
                raise RuntimeError("GitHub API вернул HTTP %d" % e.code)
            except (URLError, OSError, ValueError) as e:
                raise RuntimeError("Нет доступа к GitHub: %s" % e)

            if not isinstance(data, list) or not data:
                break
            for rel in data:
                if not isinstance(rel, dict):
                    continue
                if rel.get("draft") or rel.get("prerelease"):
                    continue
                tag = (rel.get("tag_name") or "").strip()
                if not _GUI_TAG_RE.match(tag):
                    continue
                rels.append({
                    "tag":          tag,
                    "version":      tag.lstrip("v"),
                    "published_at": rel.get("published_at") or "",
                    "description":  (rel.get("body") or "")[:300],
                })
                if len(rels) >= want:
                    break
            if len(rels) >= want or len(data) < 100:
                break

        out = {"ok": True, "releases": rels}
        with self._lock:
            self._releases_cache = out
            self._releases_time = now
        return out

    def _resolve_latest_tag(self, transport: str = "") -> str:
        """
        Тэг самого свежего GUI-релиза через выбранный транспорт ('' если
        не удалось). Нужен для дефолта «последняя версия», когда GitHub
        напрямую заблокирован, а обход поднят — list_releases пройдёт
        через туннель.
        """
        try:
            rels = self.list_releases(transport=transport).get("releases") or []
        except Exception as e:
            log.warning("Не удалось получить список релизов GUI: %s" % e,
                        source="gui-updater")
            return ""
        return rels[0]["tag"] if rels else ""

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

    def update(self, tag: str = "", branch: str = "",
               transport: str = "") -> dict:
        """
        Обновить zapret-gui из GitHub.

        Скачивает архив релиза/ветки, распаковывает поверх текущей
        установки, сохраняя конфигурацию и пользовательские стратегии.

        Источник (по приоритету):
          tag    — конкретная версия (тэг релиза vX.Y.Z) →
                   archive/refs/tags/<tag>.tar.gz;
          branch — ветка (для разработки) → archive/refs/heads/<branch>;
          ничего — последний релиз (latest by default); если его не
                   удалось определить — фолбэк на ветку main.
        transport — через что качать ('' — напрямую; иначе через
                    AWG/sing-box/mihomo, см. core/download_transport).

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
            return self._do_update(tag=tag, branch=branch, transport=transport)
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

    def _do_update(self, tag: str = "", branch: str = "",
                   transport: str = "") -> dict:
        """Основная логика обновления."""
        app_dir = _APP_DIR
        tmp_dir = "/tmp/zapret-gui-update-%d" % os.getpid()

        # Что качаем: конкретный тэг → ветка → последний релиз (фолбэк main).
        ref_label = ""
        if tag:
            archive_url = "%s/archive/refs/tags/%s.tar.gz" % (
                GITHUB_REPO_URL, tag)
            ref_label = "версии %s" % tag
        elif branch:
            archive_url = "%s/archive/refs/heads/%s.tar.gz" % (
                GITHUB_REPO_URL, branch)
            ref_label = "ветки %s" % branch
        else:
            latest_tag = self._resolve_latest_tag(transport=transport)
            if latest_tag:
                archive_url = "%s/archive/refs/tags/%s.tar.gz" % (
                    GITHUB_REPO_URL, latest_tag)
                ref_label = "последней версии (%s)" % latest_tag
            else:
                # Не смогли определить последний релиз (нет сети/лимит) —
                # тянем main, как делали раньше.
                archive_url = "%s/archive/refs/heads/main.tar.gz" % (
                    GITHUB_REPO_URL)
                ref_label = "ветки main"

        try:
            # 1. Скачать архив
            self._set_progress("Загрузка %s%s..." % (
                ref_label, " через обход" if transport else " с GitHub"), 10)
            archive_path = os.path.join(tmp_dir, "gui.tar.gz")
            os.makedirs(tmp_dir, exist_ok=True)

            if not self._download_file(archive_url, archive_path,
                                       transport=transport):
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

            # 4. Копировать новые файлы поверх старых.
            #
            # import/ обязателен: там лежат bundled lua/blob/lists, которые
            # после копирования синхронизируются в /opt/zapret2/ через
            # asset_importer (шаг 5). Без него self-update приносит новый
            # core/ с триггерами на z2k-*.lua, но сами файлы остаются от
            # предыдущей версии (или отсутствуют), и nfqws2 падает с
            # «LUA ERROR: invalid failure detector function ...» (issue #144).
            # vendor/ — встроенный bottle.py: без него свежая установка
            # (или система, где удалили python3-bottle) не запустится.
            dirs_to_update = [
                "api", "core", "web", "config", "catalogs", "data", "import",
                "vendor",
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

            # 5. Импорт обновлённых bundled-ассетов в runtime zapret2:
            #    import/lua/*.lua    → /opt/zapret2/lua/
            #    import/bin/*.bin    → /opt/zapret2/files/fake/
            #    import/lists/*.txt  → /opt/zapret2/{lists,ipset}/
            # Без этого новые lua-скрипты (например, z2k-*.lua), на которые
            # ссылается обновлённый core/nfqws_manager.py, остаются только в
            # import/ и не попадают в lua_path → _build_lua_init_args их
            # молча пропускает (os.path.isfile=False), и nfqws2 пытается
            # вызвать функцию из необъявленного файла.
            self._set_progress("Импорт ассетов в zapret2...", 75)
            try:
                from core.asset_importer import import_runtime_assets
                import_runtime_assets()
            except Exception as e:
                # Best-effort: ошибка импорта не должна срывать обновление,
                # но её нужно громко залогировать — иначе следующий запуск
                # nfqws2 загадочно упадёт на отсутствующей lua-функции.
                log.warning(
                    "Не удалось импортировать bundled-ассеты после "
                    "обновления: %s. Проверьте права на %s/lua и при "
                    "необходимости запустите `python3 -m core.asset_importer "
                    "--only runtime` вручную." % (e, "/opt/zapret2"),
                    source="gui-updater",
                )

            # Гарантируем CLI-обёртку `zapret-gui` в PATH. Старые ipk
            # (до появления CLI) её не клали, а self-update раньше не
            # создавал — поэтому после обновления команда отсутствовала.
            self._ensure_cli_wrapper(app_dir)

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

            # Скопированные файлы лежат на диске, но текущий Python-процесс
            # продолжает работать со старым кодом в памяти. Без перезапуска
            # сервиса GUI продолжит показывать прежнюю версию даже после
            # F5 в браузере. Планируем рестарт через init-скрипт в
            # detached-режиме — HTTP-ответ успеет уйти клиенту до того,
            # как сервис убьёт сам себя.
            restart_scheduled = self._schedule_service_restart()

            if restart_scheduled:
                msg = (
                    "GUI обновлён до версии %s. Сервис автоматически "
                    "перезапустится через несколько секунд — обновите "
                    "страницу (F5) после этого."
                    % (new_version or "?")
                )
            else:
                # Не нашли init-скрипт — пользователь должен рестартануть
                # сервис вручную, иначе обновление не применится.
                msg = (
                    "GUI обновлён до версии %s, файлы на диске, но "
                    "init-скрипт не найден — перезапустите сервис "
                    "вручную (S99zapret-gui restart / "
                    "/etc/init.d/zapret-gui restart). Без рестарта "
                    "продолжит работать старый код."
                    % (new_version or "?")
                )

            return {
                "ok": True,
                "message": msg,
                "version": new_version,
                "restart_required": True,
                "restart_scheduled": restart_scheduled,
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

    def _ensure_cli_wrapper(self, app_dir: str):
        """
        Создать обёртку `zapret-gui` в PATH, если её нет.

        Старые ipk (до появления CLI) обёртку не ставили, а раньше и
        self-update её не создавал — поэтому после установки старого ipk
        и обновления через GUI команда `zapret-gui` отсутствовала. Теперь
        обновление гарантирует её наличие. Best-effort: любая ошибка лишь
        логируется и не срывает обновление.
        """
        try:
            # bin-dir + дефолтный конфиг по расположению приложения.
            if app_dir.startswith("/opt"):
                bin_dir, cfg_default = "/opt/bin", "/opt/etc/zapret-gui"
            else:
                bin_dir, cfg_default = "/usr/bin", "/etc/zapret-gui"
            if not os.path.isdir(bin_dir):
                return  # некуда ставить (generic Linux без /opt/bin|/usr/bin)

            # Реальный каталог конфига текущего процесса (надёжнее дефолта).
            cfg_dir = cfg_default
            try:
                from core.config_manager import get_config_manager
                cfg_dir = os.path.dirname(
                    get_config_manager().config_path) or cfg_default
            except Exception:
                pass

            wrapper = os.path.join(bin_dir, "zapret-gui")
            # Если уже есть и ссылается на app.py — не трогаем (мог быть
            # кастомизирован пакетом).
            if os.path.isfile(wrapper):
                try:
                    with open(wrapper, "r", encoding="utf-8",
                              errors="ignore") as f:
                        if "app.py" in f.read():
                            return
                except OSError:
                    return

            content = (
                "#!/bin/sh\n"
                "# zapret-gui — консольная обёртка над app.py "
                "(создана self-update).\n"
                'exec python3 "%s/app.py" --config "%s" "$@"\n'
                % (app_dir, cfg_dir)
            )
            with open(wrapper, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
            os.chmod(wrapper, 0o755)
            log.success("CLI-команда установлена: %s" % wrapper,
                        source="gui-updater")
        except Exception as e:
            log.warning("Не удалось создать CLI-обёртку: %s" % e,
                        source="gui-updater")

    @staticmethod
    def _find_init_script() -> str | None:
        """Найти исполняемый init-скрипт сервиса GUI."""
        for path in _SERVICE_INIT_SCRIPTS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    @staticmethod
    def _find_systemd_restart_cmd() -> str | None:
        """
        Вернуть команду для рестарта через systemd, если на машине есть
        systemctl и установлен наш unit. Используется на Debian/Ubuntu
        и других дистрибутивах с systemd — там install.sh создаёт
        /etc/systemd/system/zapret-gui.service.
        """
        systemctl = shutil.which("systemctl")
        if not systemctl:
            return None
        # `is-enabled` отвечает быстро и не зависит от runtime-состояния:
        # нам важен факт существования юнита, а не то, что он сейчас
        # запущен (мы как раз внутри него).
        try:
            r = subprocess.run(
                [systemctl, "cat", "--", "%s.service" % _SYSTEMD_UNIT],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        return "%s restart %s" % (systemctl, _SYSTEMD_UNIT)

    def _resolve_restart_command(self) -> str | None:
        """
        Подобрать команду перезапуска под текущую платформу.

        Приоритет: init-скрипт (Entware/OpenWrt — он сам знает про
        PID-файл и procd) → systemctl (generic Linux). На router-сборках
        systemctl формально может присутствовать, но запускает нас
        именно init-скрипт, поэтому его и предпочитаем.
        """
        init_script = self._find_init_script()
        if init_script:
            return "%s restart" % init_script
        return self._find_systemd_restart_cmd()

    def _schedule_service_restart(self, delay_seconds: int = 3) -> bool:
        """Запланировать рестарт сервиса в detached-shell.

        Запускает `(sleep N && <restart-cmd>) &` через nohup так, чтобы:
          1) текущий HTTP-ответ успел уйти клиенту;
          2) при kill старого Python-процесса детачед-shell не умер вместе
             с ним (start_new_session + nohup);
          3) после паузы init-скрипт / systemctl сделал stop + start
             (PID-файл, pgrep, очистка stale __pycache__ — всё его).
        """
        restart_cmd = self._resolve_restart_command()
        if not restart_cmd:
            log.warning(
                "init-скрипт/systemd-юнит сервиса не найдены, авто-рестарт"
                " пропущен. Перезапустите вручную: "
                "S99zapret-gui restart / systemctl restart zapret-gui",
                source="gui-updater",
            )
            return False

        # Каскад «sleep + restart» в новой сессии. Перенаправляем потоки
        # в /dev/null — иначе шелл унаследует трубы Python и умрёт при
        # первой попытке записи после нашего exit.
        cmd_str = "sleep %d && %s" % (
            int(delay_seconds), restart_cmd,
        )
        try:
            subprocess.Popen(
                ["sh", "-c", cmd_str],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            log.info(
                "Запланирован рестарт сервиса через %d сек: %s"
                % (delay_seconds, restart_cmd),
                source="gui-updater",
            )
            return True
        except OSError as e:
            log.error(
                "Не удалось запланировать рестарт: %s" % e,
                source="gui-updater",
            )
            return False

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

    def _download_file(self, url: str, dest: str, transport: str = "") -> bool:
        """Скачать файл.

        Делегируем core/binary_installer.download_file — зеркало
        (ZAPRET_GUI_MIRROR / install.mirror), оффлайн (file://), транспорт
        скачивания (awg/sing-box/mihomo) и retry. Прогресс загрузки
        маппим в полосу обновления (диапазон 10%-28%, дальше идёт
        распаковка/копирование).
        """
        try:
            from core import binary_installer as bi

            def _cb(_stage, pct, _label):
                self._set_progress("Загрузка с GitHub...",
                                   max(10, min(28, int(pct))))

            res = bi.download_file(url, dest, progress_cb=_cb,
                                   progress_from=10, progress_to=28,
                                   timeout=DOWNLOAD_TIMEOUT,
                                   transport=transport)
            if res.get("ok"):
                return True
            log.error("Ошибка загрузки %s: %s" % (url, res.get("error")),
                      source="gui-updater")
            return False
        except Exception as e:
            log.error("Ошибка загрузки %s: %s" % (url, e),
                      source="gui-updater")
            return False

    def _fetch_github_latest_release(self) -> dict:
        """
        Получить последний релиз ИМЕННО GUI (тэг вида vX.Y.Z).

        НЕ используем /releases/latest: GitHub отдаёт там самый свежий
        non-prerelease релиз по дате, а у нас в репозитории публикуются и
        бинарные релизы (singbox-bin-*, awg-bin-*, manual-*) тоже как
        non-prerelease — они «перебивали» /releases/latest, и проверка
        обновлений GUI переставала видеть новый vX.Y.Z. Поэтому берём
        список релизов и выбираем новейший с тэгом-семвером, отбрасывая
        бинарные.
        """
        for page in (1, 2):
            url = ("https://api.github.com/repos/avatarDD/zapret-gui/"
                   "releases?per_page=100&page=%d" % page)
            req = Request(url, headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "zapret-gui/%s" % GUI_VERSION,
            })
            try:
                with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except HTTPError as e:
                if e.code == 403:
                    raise Exception("Лимит запросов GitHub API исчерпан. "
                                    "Попробуйте позже.")
                raise Exception("GitHub API вернул HTTP %d" % e.code)
            except URLError as e:
                raise Exception("Нет доступа к GitHub: %s" % e.reason)
            except json.JSONDecodeError:
                raise Exception("Ошибка разбора ответа GitHub API")

            if not isinstance(data, list) or not data:
                break
            for rel in data:
                if rel.get("draft") or rel.get("prerelease"):
                    continue
                tag = (rel.get("tag_name") or "").strip()
                if _GUI_TAG_RE.match(tag):
                    return rel
            if len(data) < 100:
                break

        raise Exception("Не найден GUI-релиз (тэг vX.Y.Z) среди релизов")

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
