# core/mihomo_installer.py
"""
Установщик mihomo (Clash.Meta).

В отличие от sing-box (который мы кросс-собираем сами и публикуем в
своих релизах), mihomo берём напрямую из апстрим-релизов
MetaCubeX/mihomo. Бинари публикуются как одиночные .gz под каждую
архитектуру: `mihomo-linux-<arch>-<version>.gz`.

Все сетевые загрузки идут через `core/binary_installer.download_file`,
который уже умеет зеркало (`ZAPRET_GUI_MIRROR` / `install.mirror`) и
оффлайн (`file://`) — для нашей аудитории, у которой GitHub часто
заблокирован.

Чистые (юнит-тестируемые) части:
  - `map_arch()`         — artifact_arch (наш детектор) → mihomo-токен;
  - `select_asset()`     — выбор нужного .gz из списка ассетов релиза.

gvisor: официальные сборки `mihomo-linux-<arch>-*.gz` (включая mips/mipsle-
softfloat для Keenetic) идут с build-тегом `with_gvisor` — его видно в
`mihomo -v` («Use tags: with_gvisor …», проверено на v1.19.x). Поэтому
`tun.stack: gvisor` доступен на всех арх-ассетах, которые мы ставим; отдельный
«gvisor-вариант» качать не нужно. Если у пользователя кастомная сборка без
gvisor — оркестратор маршрутизации откатится на `system` по результату
`mihomo -t` (см. core/mihomo_routing).
"""

import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log
from core.binary_installer import (
    download_file, extract_gz, install_binary, resolve_url,
)
from core.mihomo_detector import get_mihomo_detector
from core.mihomo_platform import detect_mihomo_platform


GITHUB_REPO = "MetaCubeX/mihomo"
GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT = 15

INSTALLED_STATE_FILE = "/opt/etc/zapret-gui/mihomo-installed.json"
INSTALLED_STATE_FILE_FALLBACK = "/var/lib/zapret-gui/mihomo-installed.json"


# artifact_arch (из awg_detector) → токен архитектуры в имени ассета.
# mihomo-токены: amd64 / arm64 / armv7 / mips-softfloat / mipsle-softfloat.
_ARCH_MAP = {
    "x86_64":           "amd64",
    "aarch64":          "arm64",
    "armv7":            "armv7",
    "mips-softfloat":   "mips-softfloat",
    "mipsel-softfloat": "mipsle-softfloat",
}


def map_arch(artifact_arch: str) -> str:
    """Наш artifact_arch → mihomo arch-токен ('' если неизвестен)."""
    return _ARCH_MAP.get((artifact_arch or "").strip().lower(), "")


def select_asset(assets, arch_token: str) -> dict:
    """
    Выбрать ассет `mihomo-linux-<arch_token>-<version>.gz` из списка
    ассетов релиза (каждый — dict с 'name' и 'browser_download_url').

    Тонкость: для amd64 нельзя просто matchить префикс, иначе поймаем
    `amd64-compatible` / `amd64-v3`. Поэтому после токена требуем сразу
    версию (`-v<digit>` или `-<digit>`), без промежуточных квалификаторов.

    Возвращает {"ok", "name", "url", "candidates"} либо
    {"ok": False, ...}.
    """
    if not arch_token:
        return {"ok": False, "error": "неизвестная архитектура"}
    # mihomo-linux-<token>-v1.18.0.gz  /  ...-2024xxxx.gz (alpha)
    pat = re.compile(
        r"^mihomo-linux-" + re.escape(arch_token) + r"-v?\d[\w.]*\.gz$")
    names = []
    for a in assets or []:
        name = (a.get("name") or "") if isinstance(a, dict) else ""
        if not name:
            continue
        names.append(name)
        if pat.match(name):
            url = a.get("browser_download_url") or ""
            return {"ok": True, "name": name, "url": url}
    return {"ok": False, "error": "ассет для arch '%s' не найден" % arch_token,
            "candidates": names}


# ─────── http ───────

def _http_json(url: str, timeout: int = HTTP_TIMEOUT, transport: str = ""):
    from core.download_transport import urlopen_via
    with urlopen_via(
            resolve_url(url), transport=transport, timeout=timeout,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "zapret-gui/mihomo-installer"}) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


# ─────── state ───────

def _state_path() -> str:
    for p in (INSTALLED_STATE_FILE, INSTALLED_STATE_FILE_FALLBACK):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            return p
        except OSError:
            continue
    return INSTALLED_STATE_FILE_FALLBACK


def _save_state(tag: str, version: str, path: str):
    try:
        with open(_state_path(), "w") as f:
            json.dump({"tag": tag, "version": version, "binary": path,
                       "installed_at": int(time.time())}, f)
    except OSError as e:
        log.warning("mihomo_installer: save state: %s" % e,
                    source="mihomo_installer")


def _read_state() -> dict:
    for p in (INSTALLED_STATE_FILE, INSTALLED_STATE_FILE_FALLBACK):
        try:
            with open(p, "r") as f:
                return json.load(f) or {}
        except (IOError, OSError, ValueError):
            continue
    return {}


# ─────── installer ───────

class MihomoInstaller:

    def __init__(self):
        self._lock = threading.Lock()
        self._progress = {"status": "idle", "progress": 0, "message": ""}
        self._release_cache = None
        self._release_at = 0
        self._releases_cache = None     # список релизов для выбора версии
        self._releases_at = 0

    def _set_progress(self, status, progress, message=""):
        with self._lock:
            self._progress = {"status": status, "progress": int(progress),
                              "message": message}

    def get_operation_status(self) -> dict:
        with self._lock:
            return dict(self._progress)

    # ─── release metadata ───

    def get_release(self, tag: str = "", force: bool = False,
                    transport: str = "") -> dict:
        now = time.time()
        if (self._release_cache and not force and not tag
                and (now - self._release_at) < 300):
            return self._release_cache
        if tag:
            url = "%s/repos/%s/releases/tags/%s" % (GITHUB_API, GITHUB_REPO, tag)
        else:
            url = "%s/repos/%s/releases/latest" % (GITHUB_API, GITHUB_REPO)
        try:
            data = _http_json(url, timeout=30, transport=transport)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            raise RuntimeError("GitHub API недоступен: %s" % e)
        if not isinstance(data, dict) or not data.get("tag_name"):
            raise RuntimeError("Некорректный ответ GitHub releases")
        if not tag:
            self._release_cache = data
            self._release_at = now
        return data

    def list_releases(self, transport: str = "", force: bool = False,
                      limit: int = 30) -> dict:
        """
        Список релизов MetaCubeX/mihomo для выбора версии при установке
        (последняя — по умолчанию, но можно поставить старую).
        Кэш 5 минут. Может бросить RuntimeError (нет сети).
        """
        now = time.time()
        with self._lock:
            if (self._releases_cache and not force
                    and (now - self._releases_at) < 300):
                return self._releases_cache
        url = "%s/repos/%s/releases?per_page=%d" % (
            GITHUB_API, GITHUB_REPO, max(1, min(int(limit or 30), 100)))
        try:
            data = _http_json(url, timeout=30, transport=transport)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            raise RuntimeError("GitHub API недоступен: %s" % e)
        if not isinstance(data, list):
            raise RuntimeError("Некорректный ответ GitHub releases (не список)")
        rels = []
        for rel in data:
            if not isinstance(rel, dict) or rel.get("draft"):
                continue
            tag = rel.get("tag_name") or ""
            if not tag:
                continue
            rels.append({
                "tag":          tag,
                "version":      tag.lstrip("v"),
                "prerelease":   bool(rel.get("prerelease")),
                "published_at": rel.get("published_at") or "",
            })
        out = {"ok": True, "releases": rels}
        with self._lock:
            self._releases_cache = out
            self._releases_at = now
        return out

    def _detect_arch_token(self) -> str:
        try:
            from core.awg_detector import get_awg_detector
            arch = get_awg_detector().detect_architecture()
            return map_arch(arch.get("artifact_arch") or "")
        except Exception as e:
            log.warning("mihomo_installer: arch detect: %s" % e,
                        source="mihomo_installer")
            return ""

    # ─── installed / updates ───

    def get_installed_version(self) -> dict:
        bin_info = get_mihomo_detector().detect_binary()
        state = _read_state()
        return {
            "installed":    bin_info.get("installed", False),
            "path":         bin_info.get("path", ""),
            "version":      bin_info.get("version", ""),
            "tag":          state.get("tag", ""),
            "installed_at": state.get("installed_at", 0),
        }

    def check_for_updates(self) -> dict:
        installed = self.get_installed_version()
        try:
            rel = self.get_release()
        except Exception as e:
            return {"ok": False, "error": str(e), "installed": installed}
        latest_tag = rel.get("tag_name", "")
        latest_ver = latest_tag.lstrip("v")
        has_update = bool(latest_ver) and latest_ver != installed.get("version")
        return {"ok": True, "installed": installed,
                "latest": {"tag": latest_tag, "version": latest_ver},
                "has_update": has_update}

    # ─── install ───

    def install(self, arch: str = "", tag: str = "",
                transport: str = "") -> dict:
        with self._lock:
            if self._progress["status"] in ("downloading", "installing",
                                            "extracting", "manifest"):
                return {"ok": False, "error": "Установка уже идёт"}
            self._progress = {"status": "starting", "progress": 0,
                              "message": "Подготовка"}
        try:
            return self._do_install(arch=arch, tag=tag, transport=transport)
        finally:
            try:
                get_mihomo_detector().get_environment_report(force=True)
            except Exception:
                pass

    def _do_install(self, arch: str = "", tag: str = "",
                    transport: str = "") -> dict:
        self._set_progress("manifest", 5, "Получаем релиз mihomo")
        try:
            rel = self.get_release(tag=tag, force=True, transport=transport)
        except Exception as e:
            self._set_progress("error", 0, str(e))
            return {"ok": False, "error": str(e)}

        arch_token = arch or self._detect_arch_token()
        if not arch_token:
            err = "Не удалось определить архитектуру для mihomo"
            self._set_progress("error", 0, err)
            return {"ok": False, "error": err}

        sel = select_asset(rel.get("assets") or [], arch_token)
        if not sel.get("ok"):
            self._set_progress("error", 0, sel.get("error", "нет ассета"))
            return {"ok": False, "error": sel.get("error"),
                    "candidates": sel.get("candidates")}

        version = (rel.get("tag_name") or "").lstrip("v")
        platform = detect_mihomo_platform()
        target_binary = platform.binary_path()

        from core.binary_installer import workbase
        with tempfile.TemporaryDirectory(
                prefix="mihomo-install-",
                dir=workbase(target_binary)) as workdir:
            gz_path = os.path.join(workdir, sel["name"])
            dl = download_file(
                sel["url"], gz_path,
                progress_cb=lambda s, p, m: self._set_progress(s, p, m),
                label="mihomo %s" % version,
                progress_from=0, progress_to=70,
                transport=transport)
            if not dl.get("ok"):
                self._set_progress("error", 0, dl.get("error", "загрузка"))
                return {"ok": False, "error": dl.get("error"),
                        "stage": "download"}

            self._set_progress("extracting", 80, "Распаковка mihomo")
            bin_tmp = os.path.join(workdir, "mihomo")
            ex = extract_gz(gz_path, bin_tmp)
            if not ex.get("ok"):
                self._set_progress("error", 0, ex.get("error", "распаковка"))
                return {"ok": False, "error": ex.get("error"),
                        "stage": "extract"}

            self._set_progress("installing", 90, "Установка mihomo")
            ins = install_binary(bin_tmp, target_binary)
            if not ins.get("ok"):
                self._set_progress("error", 0, ins.get("error", "установка"))
                return {"ok": False, "error": ins.get("error"),
                        "stage": "install"}

        _save_state(tag=rel.get("tag_name", ""), version=version,
                    path=target_binary)
        self._set_progress("done", 100, "Установлено mihomo %s" % version)
        log.info("mihomo %s установлен в %s" % (version, target_binary),
                 source="mihomo_installer")
        return {"ok": True, "version": version, "path": target_binary,
                "arch": arch_token, "tag": rel.get("tag_name", "")}

    # ─── локальная установка (файл от пользователя, без сети) ───

    def install_local(self, src_path: str, orig_name: str = "") -> dict:
        """
        Установить mihomo из локально загруженного файла (.gz из релиза /
        tar.gz / голый ELF). Для роутеров вообще без интернета: пользователь
        скачивает релиз на компьютер и загружает через GUI.
        """
        with self._lock:
            if self._progress["status"] in ("downloading", "installing",
                                            "extracting", "manifest"):
                return {"ok": False, "error": "Установка уже идёт"}
            self._progress = {"status": "starting", "progress": 0,
                              "message": "Локальная установка"}
        try:
            return self._do_install_local(src_path, orig_name)
        finally:
            try:
                get_mihomo_detector().get_environment_report(force=True)
            except Exception:
                pass

    def _do_install_local(self, src_path: str, orig_name: str = "") -> dict:
        from core.binary_installer import workbase, prepare_local_binary
        platform = detect_mihomo_platform()
        target_binary = platform.binary_path()

        self._set_progress("extracting", 30, "Распаковка локального файла")
        with tempfile.TemporaryDirectory(
                prefix="mihomo-local-",
                dir=workbase(target_binary)) as workdir:
            prep = prepare_local_binary(src_path, "mihomo", workdir)
            if not prep.get("ok"):
                self._set_progress("error", 0, prep.get("error", "файл"))
                return {"ok": False, "error": prep.get("error"),
                        "stage": "extract"}
            self._set_progress("installing", 80, "Установка mihomo")
            ins = install_binary(prep["path"], target_binary)
            if not ins.get("ok"):
                self._set_progress("error", 0, ins.get("error", "установка"))
                return {"ok": False, "error": ins.get("error"),
                        "stage": "install"}

        version = ""
        try:
            version = get_mihomo_detector().detect_binary().get("version") or ""
        except Exception:
            pass
        warning = "" if version else (
            "Бинарь установлен, но не отвечает на запрос версии — "
            "проверьте, что архитектура совпадает с устройством")
        _save_state(tag="local", version=version, path=target_binary)
        self._set_progress("done", 100,
                           "Установлено mihomo из локального файла")
        log.info("mihomo установлен из локального файла %s → %s"
                 % (orig_name or src_path, target_binary),
                 source="mihomo_installer")
        return {"ok": True, "version": version, "path": target_binary,
                "tag": "local", "source": "local", "warning": warning}

    # ─── uninstall ───

    def uninstall(self) -> dict:
        bin_info = get_mihomo_detector().detect_binary()
        if not bin_info.get("installed"):
            return {"ok": True, "removed": False,
                    "message": "mihomo не установлен"}
        path = bin_info["path"]
        try:
            os.remove(path)
        except OSError as e:
            return {"ok": False, "error": "rm %s: %s" % (path, e)}
        for extra in (path + ".bak", INSTALLED_STATE_FILE,
                      INSTALLED_STATE_FILE_FALLBACK):
            try:
                os.remove(extra)
            except OSError:
                pass
        log.info("mihomo удалён из %s" % path, source="mihomo_installer")
        try:
            get_mihomo_detector().get_environment_report(force=True)
        except Exception:
            pass
        return {"ok": True, "removed": True, "path": path}


_installer = None
_installer_lock = threading.Lock()


def get_mihomo_installer() -> MihomoInstaller:
    global _installer
    if _installer is None:
        with _installer_lock:
            if _installer is None:
                _installer = MihomoInstaller()
    return _installer
