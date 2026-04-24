# core/zapret_installer.py
"""
Менеджер установки/обновления/удаления zapret2 (nfqws2).

Функции:
  - Определение установленной версии nfqws2 (--version)
  - Получение последней версии из GitHub Releases API
  - Установка zapret2 из релизного архива
  - Обновление zapret2 (с сохранением конфигурации)
  - Удаление zapret2 с очисткой
  - Определение архитектуры и платформы

Использование:
    from core.zapret_installer import get_zapret_installer
    inst = get_zapret_installer()
    inst.get_installed_version()
    inst.get_latest_version()
    inst.install()
    inst.update()
    inst.get_uninstall_plan()
    inst.uninstall()
"""

import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import threading
import time
import zipfile
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from core.log_buffer import log


# GitHub API для проверки последней версии
GITHUB_API_URL = "https://api.github.com/repos/bol-van/zapret2/releases/latest"
GITHUB_RELEASES_URL = "https://github.com/bol-van/zapret2/releases"

# Таймауты (секунды)
HTTP_TIMEOUT = 30
VERSION_TIMEOUT = 5
INSTALL_TIMEOUT = 300  # 5 минут на загрузку + установку

# Кэширование remote-версии (не чаще раза в 5 минут)
REMOTE_VERSION_CACHE_TTL = 300


class ZapretInstaller:
    """
    Управление установкой, обновлением, удалением zapret2.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._operation_in_progress = False
        self._operation_status = ""
        self._operation_progress = 0  # 0-100

        # Кэш удалённой версии
        self._remote_version_cache = None
        self._remote_version_time = 0
        self._remote_release_data = None

    # ═══════════════════ PUBLIC API ═══════════════════

    def get_installed_version(self) -> dict:
        """
        Определить установленную версию zapret2.

        Returns:
            {
                "installed": bool,
                "version": str | None,      # "v0.9.4.5"
                "binary_path": str,
                "binary_exists": bool,
                "base_path": str,
                "base_exists": bool,
            }
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        base_path = cfg.get("zapret", "base_path") or "/opt/zapret2"
        binary_path = cfg.get("zapret", "nfqws_binary") or "/opt/zapret2/nfq2/nfqws2"

        result = {
            "installed": False,
            "version": None,
            "binary_path": binary_path,
            "binary_exists": os.path.isfile(binary_path),
            "base_path": base_path,
            "base_exists": os.path.isdir(base_path),
        }

        if not result["binary_exists"]:
            return result

        # Попытка получить версию через --version
        version = self._run_binary_version(binary_path)
        if version:
            result["installed"] = True
            result["version"] = version
        elif result["base_exists"]:
            # Бинарник есть, но --version не сработал
            # Попробуем определить версию из файлов в дистрибутиве
            version = self._detect_version_from_files(base_path)
            if version:
                result["installed"] = True
                result["version"] = version
            else:
                # Бинарник есть, директория есть, но версию не определить
                result["installed"] = True
                result["version"] = "неизвестна"

        return result

    def get_latest_version(self, force_refresh: bool = False) -> dict:
        """
        Получить последнюю доступную версию из GitHub Releases.

        Returns:
            {
                "ok": bool,
                "version": str | None,      # "v0.9.4.5"
                "tag_name": str | None,
                "published_at": str | None,
                "release_url": str,
                "description": str | None,
                "assets": [...],
                "error": str | None,
            }
        """
        # Проверяем кэш
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
            "assets": [],
            "error": None,
        }

        try:
            data = self._fetch_github_latest_release()
            if data:
                result["ok"] = True
                result["version"] = data.get("tag_name", "").strip()
                result["tag_name"] = data.get("tag_name", "").strip()
                result["published_at"] = data.get("published_at")
                result["release_url"] = data.get("html_url", GITHUB_RELEASES_URL)
                result["description"] = (data.get("body") or "")[:500]

                # Список ассетов для загрузки
                assets = []
                for asset in data.get("assets", []):
                    assets.append({
                        "name": asset.get("name", ""),
                        "size": asset.get("size", 0),
                        "download_url": asset.get("browser_download_url", ""),
                    })
                result["assets"] = assets

                self._remote_release_data = data
        except Exception as e:
            result["error"] = str(e)
            log.error("Ошибка получения версии с GitHub: %s" % e,
                      source="installer")

        # Кэшируем
        self._remote_version_cache = result
        self._remote_version_time = now

        return result

    def get_version_comparison(self) -> dict:
        """
        Сравнить установленную и последнюю версии.

        Returns:
            {
                "installed": { ... },
                "latest": { ... },
                "update_available": bool,
                "is_installed": bool,
            }
        """
        installed = self.get_installed_version()
        latest = self.get_latest_version()

        update_available = False
        if (installed["installed"]
                and installed["version"]
                and installed["version"] != "неизвестна"
                and latest["ok"]
                and latest["version"]):
            update_available = self._is_newer_version(
                installed["version"], latest["version"]
            )

        return {
            "installed": installed,
            "latest": latest,
            "update_available": update_available,
            "is_installed": installed["installed"],
        }

    def install(self) -> dict:
        """
        Установить zapret2 из последнего релиза.

        Returns:
            {"ok": bool, "message": str, "version": str | None}
        """
        with self._lock:
            if self._operation_in_progress:
                return {"ok": False, "message": "Операция уже выполняется"}

            self._operation_in_progress = True
            self._operation_status = "Начало установки..."
            self._operation_progress = 0

        try:
            return self._do_install(is_update=False)
        finally:
            with self._lock:
                self._operation_in_progress = False

    def update(self) -> dict:
        """
        Обновить zapret2 до последней версии (с сохранением конфигурации).

        Returns:
            {"ok": bool, "message": str, "version": str | None}
        """
        with self._lock:
            if self._operation_in_progress:
                return {"ok": False, "message": "Операция уже выполняется"}

            self._operation_in_progress = True
            self._operation_status = "Начало обновления..."
            self._operation_progress = 0

        try:
            return self._do_install(is_update=True)
        finally:
            with self._lock:
                self._operation_in_progress = False

    def get_uninstall_plan(self) -> dict:
        """
        Получить план удаления — что будет удалено.

        Returns:
            {
                "ok": bool,
                "items": [{"path": str, "type": "dir"|"file", "description": str}],
                "warnings": [str],
            }
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        base_path = cfg.get("zapret", "base_path") or "/opt/zapret2"
        items = []
        warnings = []

        # Основная директория
        if os.path.isdir(base_path):
            size = self._get_dir_size(base_path)
            items.append({
                "path": base_path,
                "type": "dir",
                "description": "Директория zapret2 (%s)" % self._format_size(size),
            })

        # Init.d скрипты
        init_scripts = [
            "/opt/etc/init.d/S99zapret",
            "/opt/etc/init.d/S99zapret2",
        ]
        for script in init_scripts:
            if os.path.isfile(script):
                items.append({
                    "path": script,
                    "type": "file",
                    "description": "Init-скрипт автозапуска",
                })

        # PID-файлы
        pid_files = [
            "/var/run/zapret-gui-nfqws.pid",
            "/var/run/nfqws2.pid",
        ]
        for pf in pid_files:
            if os.path.isfile(pf):
                items.append({
                    "path": pf,
                    "type": "file",
                    "description": "PID-файл",
                })

        # Логи в /tmp
        tmp_logs = [
            "/tmp/zapret-gui.log",
            "/tmp/nfqws2.log",
        ]
        for tl in tmp_logs:
            if os.path.isfile(tl):
                items.append({
                    "path": tl,
                    "type": "file",
                    "description": "Лог-файл (в RAM)",
                })

        # Iptables/nftables правила (предупреждение)
        warnings.append(
            "Правила firewall (iptables/nftables) будут очищены"
        )

        if not items:
            return {
                "ok": True,
                "items": [],
                "warnings": ["zapret2 не установлен — нечего удалять"],
            }

        return {
            "ok": True,
            "items": items,
            "warnings": warnings,
        }

    def uninstall(self) -> dict:
        """
        Удалить zapret2 из системы.

        Returns:
            {"ok": bool, "message": str, "removed": [str]}
        """
        with self._lock:
            if self._operation_in_progress:
                return {"ok": False, "message": "Операция уже выполняется",
                        "removed": []}

            self._operation_in_progress = True
            self._operation_status = "Удаление zapret2..."
            self._operation_progress = 0

        try:
            return self._do_uninstall()
        finally:
            with self._lock:
                self._operation_in_progress = False

    def is_nfqws_running(self) -> dict:
        """
        Проверить, запущен ли nfqws2 в системе.

        Проверяет как через наш PID-файл, так и через поиск процесса.

        Returns:
            {
                "running": bool,
                "pid": int | None,
                "source": "manager" | "system" | None,
            }
        """
        # Проверяем через наш менеджер
        from core.nfqws_manager import get_nfqws_manager
        mgr = get_nfqws_manager()
        if mgr.is_running():
            return {
                "running": True,
                "pid": mgr.get_pid(),
                "source": "manager",
            }

        # Проверяем через поиск процесса в системе
        pid = self._find_nfqws_process()
        if pid:
            return {
                "running": True,
                "pid": pid,
                "source": "system",
            }

        return {"running": False, "pid": None, "source": None}

    def stop_nfqws(self) -> dict:
        """
        Остановить nfqws2 перед операцией.

        Останавливает как через менеджер, так и через системный kill.

        Returns:
            {"ok": bool, "message": str}
        """
        status = self.is_nfqws_running()
        if not status["running"]:
            return {"ok": True, "message": "nfqws2 не запущен"}

        log.info("Остановка nfqws2 перед операцией...", source="installer")

        # Через менеджер
        from core.nfqws_manager import get_nfqws_manager
        mgr = get_nfqws_manager()
        if mgr.is_running():
            if mgr.stop():
                log.success("nfqws2 остановлен через менеджер",
                            source="installer")
                return {"ok": True, "message": "nfqws2 остановлен"}

        # Системный kill
        pid = self._find_nfqws_process()
        if pid:
            return self._kill_process(pid)

        return {"ok": True, "message": "nfqws2 остановлен"}

    def get_operation_status(self) -> dict:
        """
        Текущий статус длительной операции.

        Returns:
            {
                "in_progress": bool,
                "status": str,
                "progress": int (0-100),
            }
        """
        return {
            "in_progress": self._operation_in_progress,
            "status": self._operation_status,
            "progress": self._operation_progress,
        }

    def get_arch(self) -> str:
        """Определить архитектуру для загрузки бинарников."""
        machine = platform.machine().lower()

        arch_map = {
            "mips": "linux-mipsel" if self._is_little_endian() else "linux-mips",
            "mipsel": "linux-mipsel",
            "mips64": "linux-mipsel64" if self._is_little_endian() else "linux-mips64",
            "aarch64": "linux-arm64",
            "arm64": "linux-arm64",
            "armv7l": "linux-arm",
            "armv6l": "linux-arm",
            "x86_64": "linux-x86_64",
            "amd64": "linux-x86_64",
            "i686": "linux-x86",
            "i386": "linux-x86",
            "riscv64": "linux-riscv64",
            "ppc": "linux-ppc",
        }

        for key, val in arch_map.items():
            if key in machine:
                return val

        return "linux-" + machine

    def get_platform_type(self) -> str:
        """Определить тип платформы: keenetic, openwrt, entware, linux."""
        if os.path.exists("/tmp/ndnproxy_acl"):
            return "keenetic"
        if os.path.exists("/etc/openwrt_release"):
            return "openwrt"
        if os.path.exists("/opt/etc/entware_release"):
            return "entware"
        return "linux"

    # ═══════════════════ INTERNAL METHODS ═══════════════════

    def _run_binary_version(self, binary_path: str) -> str:
        """Запустить бинарник с --version и получить версию."""
        if not os.path.isfile(binary_path):
            return None
        if not os.access(binary_path, os.X_OK):
            return None

        try:
            result = subprocess.run(
                [binary_path, "--version"],
                capture_output=True, text=True,
                timeout=VERSION_TIMEOUT,
            )
            output = (result.stdout + result.stderr).strip()
            if output:
                # Ищем паттерн версии: v0.9.4.5, 0.9.4.5, etc.
                version = self._extract_version_string(output)
                if version:
                    return version
                # Если не нашли паттерн, возвращаем первую строку
                first_line = output.split("\n")[0].strip()
                if first_line and len(first_line) < 100:
                    return first_line
        except subprocess.TimeoutExpired:
            log.warning("Таймаут при запуске %s --version" % binary_path,
                        source="installer")
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("Ошибка запуска %s --version: %s" % (binary_path, e),
                      source="installer")

        return None

    def _detect_version_from_files(self, base_path: str) -> str:
        """Попытаться определить версию из файлов в директории zapret2."""
        # Проверяем VERSION файл
        for vfile in ["VERSION", "version", "version.txt"]:
            vpath = os.path.join(base_path, vfile)
            if os.path.isfile(vpath):
                try:
                    with open(vpath, "r") as f:
                        ver = f.read().strip()
                    if ver:
                        return self._extract_version_string(ver) or ver
                except IOError:
                    pass

        # Проверяем config.default на предмет комментариев с версией
        config_default = os.path.join(base_path, "config.default")
        if os.path.isfile(config_default):
            try:
                with open(config_default, "r") as f:
                    header = f.read(500)
                ver = self._extract_version_string(header)
                if ver:
                    return ver
            except IOError:
                pass

        return None

    @staticmethod
    def _extract_version_string(text: str) -> str:
        """Извлечь строку версии из текста."""
        # Паттерн: v0.9.4.5, v1.0, 0.9.4 и т.д.
        match = re.search(r'v?(\d+\.\d+(?:\.\d+)*(?:\.\d+)*)', text)
        if match:
            ver = match.group(0)
            # Добавляем v если нет
            if not ver.startswith("v"):
                ver = "v" + ver
            return ver
        return None

    def _fetch_github_latest_release(self) -> dict:
        """Получить данные последнего релиза с GitHub API."""
        req = Request(
            GITHUB_API_URL,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "zapret-gui/1.0",
            },
        )

        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data
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
        """
        Проверить, является ли latest более новой версией чем installed.
        Сравнивает числовые компоненты версии.
        """
        def parse_ver(v):
            # Убираем 'v' и разбиваем по точкам
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

            # Выравниваем длину
            maxlen = max(len(inst_parts), len(lat_parts))
            inst_parts += [0] * (maxlen - len(inst_parts))
            lat_parts += [0] * (maxlen - len(lat_parts))

            return lat_parts > inst_parts
        except Exception:
            # При любой ошибке — просто строковое сравнение
            return installed.lstrip("v") != latest.lstrip("v")

    def _find_nfqws_process(self) -> int:
        """Найти PID работающего nfqws2 процесса в системе."""
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                try:
                    cmdline_path = "/proc/%s/cmdline" % pid_dir
                    with open(cmdline_path, "r") as f:
                        cmdline = f.read()
                    if "nfqws2" in cmdline:
                        return int(pid_dir)
                except (IOError, OSError, ValueError):
                    continue
        except (IOError, OSError):
            pass

        # Fallback через pidof/pgrep
        for cmd in [["pidof", "nfqws2"], ["pgrep", "-x", "nfqws2"]]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    pids = result.stdout.strip().split()
                    if pids:
                        return int(pids[0])
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                continue

        return None

    def _kill_process(self, pid: int) -> dict:
        """Завершить процесс по PID (SIGTERM → SIGKILL)."""
        import signal

        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return {"ok": True, "message": "Процесс уже завершён"}
        except PermissionError:
            return {"ok": False,
                    "message": "Нет прав для остановки PID %d" % pid}

        # Ждём до 3 секунд
        for _ in range(30):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)  # Проверяем жив ли
            except ProcessLookupError:
                log.success("nfqws2 (PID %d) остановлен" % pid,
                            source="installer")
                return {"ok": True, "message": "nfqws2 остановлен (SIGTERM)"}

        # SIGKILL
        try:
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
        except ProcessLookupError:
            pass

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log.success("nfqws2 (PID %d) остановлен (SIGKILL)" % pid,
                        source="installer")
            return {"ok": True, "message": "nfqws2 остановлен (SIGKILL)"}

        return {"ok": False,
                "message": "Не удалось остановить nfqws2 (PID %d)" % pid}

    def _do_install(self, is_update: bool = False) -> dict:
        """
        Выполнить установку или обновление zapret2.

        Шаги:
        1. Проверяем, запущен ли nfqws2 → останавливаем
        2. Получаем данные последнего релиза
        3. Определяем подходящий архив для архитектуры
        4. Скачиваем
        5. Распаковываем во временную директорию
        6. При обновлении — бэкапим конфиг
        7. Копируем файлы
        8. Устанавливаем бинарники (install_bin.sh)
        9. Восстанавливаем конфиг
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        action_name = "обновление" if is_update else "установку"
        base_path = cfg.get("zapret", "base_path") or "/opt/zapret2"

        log.info("Начинаем %s zapret2..." % action_name, source="installer")

        # ── Шаг 1: Остановить nfqws2 ──
        self._update_op("Проверка запущенных процессов...", 5)
        status = self.is_nfqws_running()
        if status["running"]:
            self._update_op("Остановка nfqws2...", 8)
            stop_result = self.stop_nfqws()
            if not stop_result["ok"]:
                return {
                    "ok": False,
                    "message": "Не удалось остановить nfqws2: %s"
                               % stop_result["message"],
                    "version": None,
                }
            # Снимаем правила firewall
            self._remove_firewall_rules()
            time.sleep(0.5)

        # ── Шаг 2: Получить последний релиз ──
        self._update_op("Получение информации о последнем релизе...", 12)
        latest = self.get_latest_version(force_refresh=True)
        if not latest["ok"]:
            return {
                "ok": False,
                "message": "Не удалось получить информацию о релизе: %s"
                           % (latest.get("error") or "неизвестная ошибка"),
                "version": None,
            }

        version = latest["version"]
        log.info("Целевая версия: %s" % version, source="installer")

        # ── Шаг 3: Найти подходящий архив ──
        self._update_op("Определение архитектуры...", 16)
        download_url = self._find_download_url(latest)
        if not download_url:
            return {
                "ok": False,
                "message": "Не найден подходящий архив для загрузки. "
                           "Архитектура: %s. Проверьте релиз вручную: %s"
                           % (self.get_arch(), latest.get("release_url", "")),
                "version": None,
            }

        log.info("URL загрузки: %s" % download_url, source="installer")

        # ── Шаг 4: Загрузка ──
        self._update_op("Загрузка архива...", 20)
        tmp_dir = "/tmp/zapret-gui-install-%d" % int(time.time())
        archive_path = os.path.join(tmp_dir, "zapret2-release.tar.gz")

        try:
            os.makedirs(tmp_dir, exist_ok=True)

            success = self._download_file(download_url, archive_path)
            if not success:
                return {
                    "ok": False,
                    "message": "Не удалось загрузить архив",
                    "version": None,
                }

            # ── Шаг 5: Распаковка ──
            self._update_op("Распаковка архива...", 50)
            extract_dir = os.path.join(tmp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            success = self._extract_archive(archive_path, extract_dir)
            if not success:
                return {
                    "ok": False,
                    "message": "Не удалось распаковать архив",
                    "version": None,
                }

            # Находим корневую директорию внутри архива
            source_dir = self._find_source_dir(extract_dir)
            if not source_dir:
                return {
                    "ok": False,
                    "message": "Не удалось найти файлы zapret2 в архиве",
                    "version": None,
                }

            # ── Шаг 6: Бэкап конфигурации при обновлении ──
            backup_files = {}
            if is_update and os.path.isdir(base_path):
                self._update_op("Бэкап конфигурации...", 60)
                backup_files = self._backup_config(base_path)

            # ── Шаг 7: Копирование файлов ──
            self._update_op("Установка файлов...", 65)

            # Если обновляем — удаляем старое, кроме конфигов
            if is_update and os.path.isdir(base_path):
                self._clean_old_installation(base_path)

            # Копируем
            os.makedirs(base_path, exist_ok=True)
            self._copy_tree(source_dir, base_path)
            log.info("Файлы скопированы в %s" % base_path, source="installer")

            # ── Шаг 8: Установка бинарников ──
            self._update_op("Установка бинарников...", 75)
            self._install_binaries(base_path)

            # ── Шаг 9: Восстановление конфигурации ──
            if backup_files:
                self._update_op("Восстановление конфигурации...", 85)
                self._restore_config(base_path, backup_files)

            # ── Шаг 9b: Импорт bundled-ассетов (blobs/lua/lists) ──
            # Базовый zapret2 идёт только с бинарником; blobs/lua/lists,
            # на которые ссылаются наши стратегии, выкладывает GUI.
            self._update_op("Импорт blobs/lua/lists...", 88)
            try:
                from core.asset_importer import import_runtime_assets
                _imp = import_runtime_assets(base_path=base_path)
                if _imp.get("copied", 0) > 0:
                    log.info(
                        "Импортировано %d файл(ов) в %s "
                        "(blobs/lua/lists)" % (_imp["copied"], base_path),
                        source="installer",
                    )
            except Exception as e:
                log.warning(
                    "Не удалось импортировать bundled-ассеты: %s" % e,
                    source="installer",
                )

            # ── Шаг 10: Выставляем права ──
            self._update_op("Настройка прав...", 90)
            self._set_permissions(base_path)

            # ── Проверяем установку ──
            self._update_op("Проверка установки...", 95)
            check = self.get_installed_version()
            if check["installed"]:
                self._update_op("Готово!", 100)
                final_version = check["version"] or version
                log.success(
                    "zapret2 %s успешно: %s"
                    % ("обновлён" if is_update else "установлен",
                       final_version),
                    source="installer"
                )
                return {
                    "ok": True,
                    "message": "zapret2 %s успешно: %s"
                               % ("обновлён" if is_update else "установлен",
                                  final_version),
                    "version": final_version,
                }
            else:
                log.warning(
                    "Файлы скопированы, но бинарник не найден/не работает",
                    source="installer"
                )
                return {
                    "ok": True,
                    "message": "Файлы установлены в %s, но бинарник "
                               "может потребовать ручной настройки "
                               "(install_bin.sh)" % base_path,
                    "version": version,
                }

        except Exception as e:
            log.error("Ошибка установки: %s" % e, source="installer")
            return {
                "ok": False,
                "message": "Ошибка установки: %s" % str(e),
                "version": None,
            }
        finally:
            # Чистим временные файлы
            try:
                if os.path.isdir(tmp_dir):
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    def _do_uninstall(self) -> dict:
        """Выполнить удаление zapret2."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        base_path = cfg.get("zapret", "base_path") or "/opt/zapret2"
        removed = []

        log.info("Начинаем удаление zapret2...", source="installer")

        # ── Шаг 1: Остановить nfqws2 ──
        self._update_op("Остановка nfqws2...", 10)
        status = self.is_nfqws_running()
        if status["running"]:
            stop_result = self.stop_nfqws()
            if not stop_result["ok"]:
                return {
                    "ok": False,
                    "message": "Не удалось остановить nfqws2: %s"
                               % stop_result["message"],
                    "removed": [],
                }

        # ── Шаг 2: Снять правила firewall ──
        self._update_op("Очистка правил firewall...", 20)
        self._remove_firewall_rules()

        # ── Шаг 3: Удалить init-скрипты ──
        self._update_op("Удаление init-скриптов...", 30)
        init_scripts = [
            "/opt/etc/init.d/S99zapret",
            "/opt/etc/init.d/S99zapret2",
        ]
        for script in init_scripts:
            if os.path.isfile(script):
                try:
                    os.remove(script)
                    removed.append(script)
                    log.info("Удалён: %s" % script, source="installer")
                except OSError as e:
                    log.warning("Не удалось удалить %s: %s" % (script, e),
                                source="installer")

        # ── Шаг 4: Удалить PID-файлы ──
        self._update_op("Очистка PID-файлов...", 40)
        pid_files = [
            "/var/run/zapret-gui-nfqws.pid",
            "/var/run/nfqws2.pid",
        ]
        for pf in pid_files:
            if os.path.isfile(pf):
                try:
                    os.remove(pf)
                    removed.append(pf)
                except OSError:
                    pass

        # ── Шаг 5: Удалить логи ──
        self._update_op("Очистка логов...", 50)
        tmp_logs = ["/tmp/zapret-gui.log", "/tmp/nfqws2.log"]
        for tl in tmp_logs:
            if os.path.isfile(tl):
                try:
                    os.remove(tl)
                    removed.append(tl)
                except OSError:
                    pass

        # ── Шаг 6: Удалить основную директорию ──
        self._update_op("Удаление директории zapret2...", 60)
        if os.path.isdir(base_path):
            try:
                shutil.rmtree(base_path)
                removed.append(base_path)
                log.info("Удалена директория: %s" % base_path,
                         source="installer")
            except OSError as e:
                log.error("Не удалось удалить %s: %s" % (base_path, e),
                          source="installer")
                return {
                    "ok": False,
                    "message": "Не удалось удалить %s: %s"
                               % (base_path, str(e)),
                    "removed": removed,
                }

        self._update_op("Готово!", 100)
        log.success("zapret2 успешно удалён", source="installer")

        return {
            "ok": True,
            "message": "zapret2 успешно удалён. "
                       "Удалено элементов: %d" % len(removed),
            "removed": removed,
        }

    def _find_download_url(self, latest_data: dict) -> str:
        """Найти URL подходящего архива для загрузки."""
        assets = latest_data.get("assets", [])

        # Ищем основной архив (не embedded, не source)
        # Обычно это zapret2-vX.Y.Z.tar.gz или zapret2-vX.Y.Z.zip
        priority_patterns = [
            r"zapret2.*\.tar\.gz$",
            r"zapret2.*\.zip$",
        ]

        # Исключаем embedded и source
        exclude_patterns = [
            r"embedded",
            r"source",
            r"src",
        ]

        for pattern in priority_patterns:
            for asset in assets:
                name = asset.get("name", "").lower()
                url = asset.get("download_url", "")

                if not url:
                    continue

                if re.search(pattern, name, re.IGNORECASE):
                    # Проверяем исключения
                    excluded = False
                    for excl in exclude_patterns:
                        if re.search(excl, name, re.IGNORECASE):
                            excluded = True
                            break
                    if not excluded:
                        return url

        # Если не нашли по паттерну — берём первый tar.gz или zip
        for asset in assets:
            name = asset.get("name", "").lower()
            url = asset.get("download_url", "")
            if url and (name.endswith(".tar.gz") or name.endswith(".zip")):
                return url

        # Формируем URL из tag_name вручную
        tag = latest_data.get("tag_name", "")
        if tag:
            return ("https://github.com/bol-van/zapret2/archive/refs/tags/"
                    "%s.tar.gz" % tag)

        return None

    def _download_file(self, url: str, dest: str) -> bool:
        """Загрузить файл по URL."""
        log.info("Загрузка: %s" % url, source="installer")

        # Пробуем через urllib (стандартная библиотека)
        try:
            req = Request(url, headers={"User-Agent": "zapret-gui/1.0"})
            with urlopen(req, timeout=INSTALL_TIMEOUT) as resp:
                total = resp.getheader("Content-Length")
                total = int(total) if total else 0
                downloaded = 0
                chunk_size = 64 * 1024  # 64KB

                with open(dest, "wb") as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Обновляем прогресс (20%-50% — загрузка)
                        if total > 0:
                            pct = 20 + int(30 * downloaded / total)
                            size_str = "%s / %s" % (
                                self._format_size(downloaded),
                                self._format_size(total),
                            )
                        else:
                            pct = 35
                            size_str = self._format_size(downloaded)

                        self._update_op(
                            "Загрузка: %s" % size_str, pct
                        )

            log.info("Загружено: %s (%s)" % (
                dest, self._format_size(os.path.getsize(dest))
            ), source="installer")
            return True

        except Exception as e:
            log.error("Ошибка загрузки через urllib: %s" % e,
                      source="installer")

        # Fallback: wget
        try:
            result = subprocess.run(
                ["wget", "-q", "-O", dest, url],
                timeout=INSTALL_TIMEOUT,
                capture_output=True, text=True,
            )
            if result.returncode == 0 and os.path.isfile(dest):
                log.info("Загружено через wget", source="installer")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: curl
        try:
            result = subprocess.run(
                ["curl", "-sL", "-o", dest, url],
                timeout=INSTALL_TIMEOUT,
                capture_output=True, text=True,
            )
            if result.returncode == 0 and os.path.isfile(dest):
                log.info("Загружено через curl", source="installer")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        log.error("Все методы загрузки не сработали", source="installer")
        return False

    def _extract_archive(self, archive_path: str, dest_dir: str) -> bool:
        """Распаковать архив (tar.gz или zip)."""
        try:
            if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(dest_dir)
                return True
            elif archive_path.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(dest_dir)
                return True
            else:
                # Пробуем как tar.gz
                try:
                    with tarfile.open(archive_path, "r:gz") as tar:
                        tar.extractall(dest_dir)
                    return True
                except tarfile.TarError:
                    pass
                # Пробуем как zip
                try:
                    with zipfile.ZipFile(archive_path, "r") as zf:
                        zf.extractall(dest_dir)
                    return True
                except zipfile.BadZipFile:
                    pass

                log.error("Неизвестный формат архива", source="installer")
                return False
        except Exception as e:
            log.error("Ошибка распаковки: %s" % e, source="installer")
            return False

    def _find_source_dir(self, extract_dir: str) -> str:
        """Найти корневую директорию zapret2 внутри распакованного архива."""
        # Проверяем — может файлы прямо в extract_dir
        if os.path.isfile(os.path.join(extract_dir, "install_bin.sh")):
            return extract_dir

        # Ищем поддиректорию с install_bin.sh или nfq2/
        for entry in os.listdir(extract_dir):
            subdir = os.path.join(extract_dir, entry)
            if os.path.isdir(subdir):
                if (os.path.isfile(os.path.join(subdir, "install_bin.sh"))
                        or os.path.isdir(os.path.join(subdir, "nfq2"))
                        or os.path.isdir(os.path.join(subdir, "binaries"))):
                    return subdir

        # Рекурсивный поиск (1 уровень глубже)
        for entry in os.listdir(extract_dir):
            subdir = os.path.join(extract_dir, entry)
            if os.path.isdir(subdir):
                for sub2 in os.listdir(subdir):
                    subdir2 = os.path.join(subdir, sub2)
                    if os.path.isdir(subdir2):
                        if os.path.isfile(
                            os.path.join(subdir2, "install_bin.sh")
                        ):
                            return subdir2

        return None

    def _backup_config(self, base_path: str) -> dict:
        """Бэкап конфигурационных файлов перед обновлением."""
        backup = {}
        files_to_backup = [
            "config",
            "config.default",
            "ipset/zapret-hosts-user.txt",
            "ipset/zapret-hosts-user-exclude.txt",
            "ipset/zapret-hosts-user-ipban.txt",
            "ipset/zapret-hosts-auto.txt",
        ]

        # Также бэкапим custom.d директории
        custom_dirs = [
            "init.d/sysv/custom.d",
            "init.d/openwrt/custom.d",
        ]

        for relpath in files_to_backup:
            fullpath = os.path.join(base_path, relpath)
            if os.path.isfile(fullpath):
                try:
                    with open(fullpath, "rb") as f:
                        backup[relpath] = f.read()
                    log.debug("Бэкап: %s" % relpath, source="installer")
                except IOError:
                    pass

        for reldir in custom_dirs:
            fulldir = os.path.join(base_path, reldir)
            if os.path.isdir(fulldir):
                for fname in os.listdir(fulldir):
                    fpath = os.path.join(fulldir, fname)
                    if os.path.isfile(fpath):
                        relpath = os.path.join(reldir, fname)
                        try:
                            with open(fpath, "rb") as f:
                                backup[relpath] = f.read()
                        except IOError:
                            pass

        log.info("Бэкап: %d файлов" % len(backup), source="installer")
        return backup

    def _restore_config(self, base_path: str, backup: dict):
        """Восстановить конфигурационные файлы после обновления."""
        restored = 0
        for relpath, content in backup.items():
            fullpath = os.path.join(base_path, relpath)
            try:
                os.makedirs(os.path.dirname(fullpath), exist_ok=True)
                with open(fullpath, "wb") as f:
                    f.write(content)
                restored += 1
            except IOError as e:
                log.warning("Не удалось восстановить %s: %s"
                            % (relpath, e), source="installer")

        log.info("Восстановлено: %d файлов" % restored, source="installer")

    def _clean_old_installation(self, base_path: str):
        """Очистить старые бинарники, сохранив конфиги."""
        # Удаляем только директории с бинарниками и скриптами
        dirs_to_clean = [
            "binaries", "nfq2", "ip2net", "mdig",
            "common", "tmp",
        ]
        for dirname in dirs_to_clean:
            dirpath = os.path.join(base_path, dirname)
            if os.path.isdir(dirpath):
                try:
                    shutil.rmtree(dirpath)
                except OSError:
                    pass

        # Удаляем скрипты в корне (но не config)
        scripts_to_remove = [
            "install_bin.sh", "install_easy.sh", "install_prereq.sh",
            "uninstall_easy.sh", "blockcheck2.sh",
        ]
        for script in scripts_to_remove:
            spath = os.path.join(base_path, script)
            if os.path.isfile(spath):
                try:
                    os.remove(spath)
                except OSError:
                    pass

    def _install_binaries(self, base_path: str):
        """Установить бинарники через install_bin.sh или вручную."""
        install_script = os.path.join(base_path, "install_bin.sh")

        if os.path.isfile(install_script):
            # Делаем исполняемым
            try:
                os.chmod(install_script, 0o755)
            except OSError:
                pass

            # Запускаем
            try:
                env = os.environ.copy()
                env["ZAPRET_BASE"] = base_path
                result = subprocess.run(
                    ["/bin/sh", install_script],
                    capture_output=True, text=True,
                    timeout=60,
                    cwd=base_path,
                    env=env,
                )
                if result.returncode == 0:
                    log.info("install_bin.sh выполнен успешно",
                             source="installer")
                else:
                    log.warning(
                        "install_bin.sh завершился с кодом %d: %s"
                        % (result.returncode, result.stderr[:300]),
                        source="installer"
                    )
            except subprocess.TimeoutExpired:
                log.warning("Таймаут install_bin.sh", source="installer")
            except OSError as e:
                log.warning("Ошибка install_bin.sh: %s" % e,
                            source="installer")
        else:
            log.info("install_bin.sh не найден, пропускаем",
                     source="installer")

        # Проверяем, что бинарник есть
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        binary = cfg.get("zapret", "nfqws_binary")
        if binary and os.path.isfile(binary):
            try:
                os.chmod(binary, 0o755)
            except OSError:
                pass

    def _set_permissions(self, base_path: str):
        """Выставить права на файлы."""
        # Делаем исполняемыми ключевые скрипты
        for pattern in ["*.sh"]:
            for root, dirs, files in os.walk(base_path):
                for fname in files:
                    if fname.endswith(".sh"):
                        fpath = os.path.join(root, fname)
                        try:
                            os.chmod(fpath, 0o755)
                        except OSError:
                            pass

        # Бинарники
        binaries_dir = os.path.join(base_path, "binaries")
        if os.path.isdir(binaries_dir):
            for root, dirs, files in os.walk(binaries_dir):
                for fname in files:
                    if fname in ("nfqws2", "ip2net", "mdig", "dvtws2"):
                        fpath = os.path.join(root, fname)
                        try:
                            os.chmod(fpath, 0o755)
                        except OSError:
                            pass

        # nfq2/nfqws2
        nfq_dir = os.path.join(base_path, "nfq2")
        if os.path.isdir(nfq_dir):
            for fname in os.listdir(nfq_dir):
                if "nfqws" in fname:
                    try:
                        os.chmod(os.path.join(nfq_dir, fname), 0o755)
                    except OSError:
                        pass

    def _remove_firewall_rules(self):
        """Попытаться снять правила firewall."""
        try:
            from core.firewall import get_firewall_manager
            fw = get_firewall_manager()
            fw.remove_rules()
            log.info("Правила firewall очищены", source="installer")
        except Exception as e:
            log.warning("Ошибка очистки firewall: %s" % e,
                        source="installer")

    @staticmethod
    def _copy_tree(src: str, dst: str):
        """Рекурсивно скопировать содержимое src в dst."""
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                if os.path.exists(d):
                    # Мержим директории
                    ZapretInstaller._copy_tree(s, d)
                else:
                    shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

    def _update_op(self, status: str, progress: int):
        """Обновить статус операции."""
        self._operation_status = status
        self._operation_progress = min(100, max(0, progress))
        log.debug("Прогресс: %d%% — %s" % (progress, status),
                  source="installer")

    @staticmethod
    def _is_little_endian() -> bool:
        """Проверить порядок байт (для MIPS)."""
        import struct
        return struct.pack("H", 1)[0] == 1

    @staticmethod
    def _get_dir_size(path: str) -> int:
        """Подсчитать размер директории."""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    try:
                        total += os.path.getsize(fp)
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Форматировать размер файла."""
        if size_bytes < 1024:
            return "%d B" % size_bytes
        elif size_bytes < 1024 * 1024:
            return "%.1f KB" % (size_bytes / 1024)
        else:
            return "%.1f MB" % (size_bytes / (1024 * 1024))


# === Глобальный экземпляр (singleton) ===

_zapret_installer = None
_installer_lock = threading.Lock()


def get_zapret_installer() -> ZapretInstaller:
    """Получить глобальный экземпляр ZapretInstaller."""
    global _zapret_installer
    if _zapret_installer is None:
        with _installer_lock:
            if _zapret_installer is None:
                _zapret_installer = ZapretInstaller()
    return _zapret_installer
