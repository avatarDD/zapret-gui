# core/singbox_installer.py
"""
Установщик sing-box.

Стоит на `core/binary_installer.py` — фундаментальная утилита для
скачивания/верификации/распаковки. Здесь только GitHub-specific
часть: чтение manifest.json из релизов нашего репозитория,
выбор архитектуры, маппинг на target-пути из `singbox_platform`.
"""

import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log
from core.binary_installer import (
    fetch_verify_extract_install,
    sha256_of, verify_sha256, download_file, extract_tarball,
    install_binary,
)
from core.singbox_detector import get_singbox_detector


# ─────── константы ───────

GITHUB_REPO = "avatardd/zapret-gui"
RELEASE_TAG_PREFIX = "singbox-bin-"
MANIFEST_ASSET = "manifest.json"

GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT = 15

INSTALLED_STATE_FILE = "/opt/etc/zapret-gui/singbox-installed.json"
INSTALLED_STATE_FILE_FALLBACK = "/var/lib/zapret-gui/singbox-installed.json"


# ─────── http ───────

def _http_get(url: str, accept: str = "application/json",
              timeout: int = HTTP_TIMEOUT, transport: str = ""):
    from core.binary_installer import resolve_url
    from core.download_transport import urlopen_via
    return urlopen_via(
        resolve_url(url), transport=transport, timeout=timeout,
        headers={
            "Accept":     accept,
            "User-Agent": "zapret-gui/singbox-installer",
        })


def _http_json(url: str, timeout: int = HTTP_TIMEOUT, transport: str = ""):
    with _http_get(url, accept="application/json", timeout=timeout,
                   transport=transport) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


# ─────── state ───────

def _state_path() -> str:
    """Где хранить запись о последнем удачном install'е."""
    for p in (INSTALLED_STATE_FILE, INSTALLED_STATE_FILE_FALLBACK):
        d = os.path.dirname(p)
        try:
            os.makedirs(d, exist_ok=True)
            return p
        except OSError:
            continue
    return INSTALLED_STATE_FILE_FALLBACK


def _save_state(tag: str, version: str, path: str):
    blob = {
        "tag": tag, "version": version, "binary": path,
        "installed_at": int(time.time()),
    }
    p = _state_path()
    try:
        with open(p, "w") as f:
            json.dump(blob, f)
    except OSError as e:
        log.warning("singbox_installer: save state %s: %s" % (p, e),
                    source="singbox_installer")


def _read_state() -> dict:
    for p in (INSTALLED_STATE_FILE, INSTALLED_STATE_FILE_FALLBACK):
        try:
            with open(p, "r") as f:
                return json.load(f) or {}
        except (IOError, OSError, ValueError):
            continue
    return {}


# ─────── installer ───────

class SingboxInstaller:

    def __init__(self):
        self._lock     = threading.Lock()
        self._progress = {"status": "idle", "progress": 0, "message": ""}
        self._manifest_cache = None
        self._manifest_at    = 0
        self._releases_cache = None     # список релизов для выбора версии
        self._releases_at    = 0

    # ─── progress ───

    def _set_progress(self, status: str, progress: int,
                      message: str = ""):
        with self._lock:
            self._progress = {
                "status":  status,
                "progress": int(progress),
                "message": message,
            }

    def get_operation_status(self) -> dict:
        with self._lock:
            return dict(self._progress)

    # ─── manifest ───

    def _list_all_releases(self, transport: str = "") -> list:
        """
        Все релизы репозитория с пагинацией. Не зависим от номера
        страницы: проходим по страницам, пока они не кончатся. Так
        бинарный релиз не «теряется» за десятками GUI-релизов
        (singbox-bin-* / manual-* могут оказаться на 3-4-й странице).
        """
        out = []
        for page in range(1, 21):  # потолок 2000 релизов — с запасом
            url = ("%s/repos/%s/releases?per_page=100&page=%d"
                   % (GITHUB_API, GITHUB_REPO, page))
            try:
                data = _http_json(url, transport=transport)
            except (urllib.error.URLError, urllib.error.HTTPError,
                    OSError) as e:
                if not out:
                    raise RuntimeError("GitHub API недоступен: %s" % e)
                break
            if not isinstance(data, list) or not data:
                break
            out.extend(data)
            if len(data) < 100:
                break
        return out

    def list_releases(self, transport: str = "",
                      force: bool = False) -> dict:
        """
        Релизы с бинарниками sing-box (тэги singbox-bin-*) для выбора
        версии при установке. manual-* сюда не попадают: чтобы понять,
        чей у них manifest, пришлось бы качать каждый — а опция
        «Последняя» и так умеет manual-фолбэк. Кэш 5 минут.
        """
        now = time.time()
        with self._lock:
            if (self._releases_cache and not force
                    and (now - self._releases_at) < 300):
                return self._releases_cache
        data = self._list_all_releases(transport=transport)
        rels = []
        for rel in data:
            if not isinstance(rel, dict) or rel.get("draft"):
                continue
            tag = rel.get("tag_name") or ""
            if not tag.startswith(RELEASE_TAG_PREFIX):
                continue
            rels.append({
                "tag":          tag,
                "version":      tag[len(RELEASE_TAG_PREFIX):].lstrip("v"),
                "prerelease":   bool(rel.get("prerelease")),
                "published_at": rel.get("published_at") or "",
            })
        out = {"ok": True, "releases": rels}
        with self._lock:
            self._releases_cache = out
            self._releases_at = now
        return out

    def _resolve_latest_tag(self, transport: str = "") -> str:
        """
        Найти самый свежий релиз с бинарниками sing-box в нашем репо.

        Приоритет — тэг `singbox-bin-*` (штатный, создаётся auto-tag job'ом
        и push'ем тэга). Фолбэк — релиз, опубликованный ручным
        workflow_dispatch: он получает тэг вида `manual-<timestamp>`, но
        несёт тот же ассет `manifest.json`. Релизы AWG (`awg-bin-*`) и
        самого GUI (`v*`) под фолбэк не попадают — у них нет нашего
        manifest.json sing-box (а `awg-bin-*` ещё и не `manual-*`).

        Фильтруем по имени тэга и пагинируем — НЕ зависим от того, на
        какой странице лежит релиз.
        """
        data = self._list_all_releases(transport=transport)
        if not isinstance(data, list):
            raise RuntimeError("Не массив релизов")

        # 1) штатный тэг singbox-bin-* (новейший сверху)
        for rel in data:
            tag = rel.get("tag_name", "")
            if tag.startswith(RELEASE_TAG_PREFIX):
                return tag

        # 2) фолбэк: ручной релиз manual-* с manifest.json ИМЕННО sing-box.
        # Проверяем содержимое манифеста (ключ `sing_box`), чтобы не
        # перепутать с манифестом другого движка (AWG), который тоже
        # лежит как manifest.json в релизе manual-* (ср. issue #111).
        for rel in data:
            tag = rel.get("tag_name", "")
            if not tag.startswith("manual-"):
                continue
            assets = rel.get("assets") or []
            if not any(a.get("name") == MANIFEST_ASSET for a in assets):
                continue
            man_url = ("https://github.com/%s/releases/download/%s/%s" %
                       (GITHUB_REPO, tag, MANIFEST_ASSET))
            try:
                man = _http_json(man_url, timeout=20, transport=transport)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                continue
            if isinstance(man, dict) and (man.get("sing_box")
                                          or man.get("sing-box")):
                return tag

        raise RuntimeError("Не найден релиз с тэгом %s*" % RELEASE_TAG_PREFIX)

    def get_manifest(self, tag: str = "", force: bool = False,
                     transport: str = "") -> dict:
        """
        Прочитать manifest.json указанного релиза (или последнего).
        Кэшируется в RAM на 5 минут.
        """
        now = time.time()
        if (self._manifest_cache and not force and not tag
                and (now - self._manifest_at) < 300):
            return self._manifest_cache

        if not tag:
            tag = self._resolve_latest_tag(transport=transport)

        # Manifest публикуется как файл-asset в релизе.
        url = ("https://github.com/%s/releases/download/%s/%s" %
               (GITHUB_REPO, tag, MANIFEST_ASSET))
        try:
            data = _http_json(url, timeout=30, transport=transport)
        except (urllib.error.URLError, urllib.error.HTTPError,
                OSError) as e:
            raise RuntimeError("manifest.json (%s) недоступен: %s" %
                               (tag, e))
        if not isinstance(data, dict):
            raise RuntimeError("manifest.json: невалидный формат")

        self._manifest_cache = data
        self._manifest_at    = now
        return data

    # ─── installed version ───

    def get_installed_version(self) -> dict:
        bin_info = get_singbox_detector().detect_binary()
        state = _read_state()
        return {
            "installed":     bin_info.get("installed", False),
            "path":          bin_info.get("path", ""),
            "version":       bin_info.get("version", ""),
            "tags":          bin_info.get("tags", []),
            "has_clash_api": bin_info.get("has_clash_api", False),
            "tag":           state.get("tag", ""),
            "installed_at":  state.get("installed_at", 0),
        }

    def check_for_updates(self) -> dict:
        installed = self.get_installed_version()
        try:
            manifest = self.get_manifest()
        except Exception as e:
            return {"ok": False, "error": str(e),
                    "installed": installed}
        latest_ver = (manifest.get("sing_box") or {}).get("version", "")
        latest_tag = manifest.get("tag", "")
        has_update = bool(latest_ver) and latest_ver != installed.get("version")
        # Переустановка нужна, даже если версия совпадает: наши сборки
        # начиная с тэга «clash_api в бинаре» включают with_clash_api, без
        # которого не работает тестер серверов (proxy_tester). Если в
        # установленном бинаре уверенно нет clash_api (теги распарсились и
        # тега там нет) — подсказываем переустановиться. has_update при
        # этом может быть False (одна и та же upstream-версия), поэтому
        # сигнал нужен отдельный, иначе пользователь никогда не узнает.
        needs_reinstall = bool(
            installed.get("installed")
            and installed.get("tags")               # теги распарсились
            and not installed.get("has_clash_api")  # но clash_api среди них нет
        )
        return {
            "ok":              True,
            "installed":       installed,
            "latest":          {"tag": latest_tag, "version": latest_ver},
            "has_update":      has_update,
            "needs_reinstall": needs_reinstall,
            "reinstall_reason": ("Бинарь собран без clash_api — тестер серверов"
                                 " работает только по TCP. Переустановите, чтобы"
                                 " включить полную e2e-проверку."
                                 if needs_reinstall else ""),
        }

    # ─── architecture ───

    def _detect_arch(self) -> str:
        """
        Используем тот же mapping, что и AWG-инсталлер — чтобы один
        релиз заведомо имел совместимые архитектуры.
        """
        try:
            from core.awg_detector import get_awg_detector
            arch = get_awg_detector().detect_architecture()
            return arch.get("artifact_arch") or arch.get("uname_m") or ""
        except Exception as e:
            log.warning("singbox_installer: arch detect: %s" % e,
                        source="singbox_installer")
            return ""

    # ─── install ───

    def install(self, arch: str = "", tag: str = "",
                transport: str = "") -> dict:
        """
        Главный метод. Скачивает manifest, выбирает архитектуру,
        делает download → verify → extract → install через
        binary_installer.
        """
        with self._lock:
            if self._progress["status"] in ("downloading", "installing",
                                            "extracting", "verifying"):
                return {"ok": False, "error": "Установка уже идёт"}
            self._progress = {"status": "starting", "progress": 0,
                              "message": "Подготовка"}

        try:
            return self._do_install(arch=arch, tag=tag, transport=transport)
        finally:
            # При успехе перезагружаем кэш detector'а.
            try:
                get_singbox_detector().get_environment_report(force=True)
            except Exception:
                pass

    def _do_install(self, arch: str = "", tag: str = "",
                    transport: str = "") -> dict:
        self._set_progress("manifest", 5, "Получаем manifest.json")
        try:
            manifest = self.get_manifest(tag=tag, force=True,
                                         transport=transport)
        except Exception as e:
            self._set_progress("error", 0, str(e))
            return {"ok": False, "error": str(e)}

        if not arch:
            arch = self._detect_arch()
        if not arch:
            err = "Не удалось определить архитектуру"
            self._set_progress("error", 0, err)
            return {"ok": False, "error": err}

        sb = manifest.get("sing_box") or {}
        version = sb.get("version") or ""
        binaries = sb.get("binaries") or {}
        info = binaries.get(arch)
        if not info:
            err = ("Архитектура '%s' не поддерживается релизом (доступны: %s)"
                   % (arch, ", ".join(sorted(binaries.keys()))))
            self._set_progress("error", 0, err)
            return {"ok": False, "error": err,
                    "available_archs": sorted(binaries.keys())}

        url     = info.get("url")
        sha256  = info.get("sha256") or ""
        if not url:
            err = "В manifest для %s нет URL" % arch
            self._set_progress("error", 0, err)
            return {"ok": False, "error": err}

        # Платформа знает, куда класть бинарь.
        from core.singbox_platform import detect_singbox_platform
        platform = detect_singbox_platform()
        target_binary = platform.binary_path()

        from core.binary_installer import workbase
        with tempfile.TemporaryDirectory(
                prefix="singbox-install-",
                dir=workbase(target_binary)) as workdir:
            archive_path = os.path.join(workdir, info.get("filename")
                                        or "sing-box.tar.gz")
            extract_dir  = os.path.join(workdir, "extracted")

            res = fetch_verify_extract_install(
                url=url,
                sha256=sha256,
                archive_path=archive_path,
                extract_dir=extract_dir,
                binary_in_archive="sing-box",
                final_dest=target_binary,
                progress_cb=lambda stage, pct, msg:
                    self._set_progress(stage, pct, msg),
                label="sing-box %s" % version,
                transport=transport,
            )

        if not res.get("ok"):
            self._set_progress("error", 0, res.get("error", "ошибка"))
            return {"ok": False, "error": res.get("error", "?"),
                    "stage": res.get("stage")}

        # Записать state-файл
        _save_state(tag=manifest.get("tag", ""), version=version,
                    path=target_binary)

        self._set_progress("done", 100, "Установлено sing-box %s" % version)
        log.info("sing-box %s установлен в %s" % (version, target_binary),
                 source="singbox_installer")
        return {"ok": True, "version": version, "path": target_binary,
                "arch": arch, "tag": manifest.get("tag", "")}

    # ─── локальная установка (файл от пользователя, без сети) ───

    def install_local(self, src_path: str, orig_name: str = "") -> dict:
        """
        Установить sing-box из локально загруженного файла (tar.gz из
        релиза / .gz / голый ELF). Для устройств вообще без интернета.
        """
        with self._lock:
            if self._progress["status"] in ("downloading", "installing",
                                            "extracting", "verifying"):
                return {"ok": False, "error": "Установка уже идёт"}
            self._progress = {"status": "starting", "progress": 0,
                              "message": "Локальная установка"}
        try:
            return self._do_install_local(src_path, orig_name)
        finally:
            try:
                get_singbox_detector().get_environment_report(force=True)
            except Exception:
                pass

    def _do_install_local(self, src_path: str, orig_name: str = "") -> dict:
        from core.binary_installer import workbase, prepare_local_binary
        from core.singbox_platform import detect_singbox_platform
        platform = detect_singbox_platform()
        target_binary = platform.binary_path()

        self._set_progress("extracting", 30, "Распаковка локального файла")
        with tempfile.TemporaryDirectory(
                prefix="singbox-local-",
                dir=workbase(target_binary)) as workdir:
            prep = prepare_local_binary(src_path, "sing-box", workdir)
            if not prep.get("ok"):
                self._set_progress("error", 0, prep.get("error", "файл"))
                return {"ok": False, "error": prep.get("error"),
                        "stage": "extract"}
            self._set_progress("installing", 80, "Установка sing-box")
            ins = install_binary(prep["path"], target_binary)
            if not ins.get("ok"):
                self._set_progress("error", 0, ins.get("error", "установка"))
                return {"ok": False, "error": ins.get("error"),
                        "stage": "install"}

        version = ""
        try:
            version = (get_singbox_detector().detect_binary()
                       .get("version") or "")
        except Exception:
            pass
        warning = "" if version else (
            "Бинарь установлен, но не отвечает на запрос версии — "
            "проверьте, что архитектура совпадает с устройством")
        _save_state(tag="local", version=version, path=target_binary)
        self._set_progress("done", 100,
                           "Установлено sing-box из локального файла")
        log.info("sing-box установлен из локального файла %s → %s"
                 % (orig_name or src_path, target_binary),
                 source="singbox_installer")
        return {"ok": True, "version": version, "path": target_binary,
                "tag": "local", "source": "local", "warning": warning}

    # ─── uninstall ───

    def uninstall(self) -> dict:
        bin_info = get_singbox_detector().detect_binary()
        if not bin_info.get("installed"):
            return {"ok": True, "removed": False,
                    "message": "sing-box не установлен"}
        path = bin_info["path"]
        try:
            os.remove(path)
        except OSError as e:
            return {"ok": False, "error": "rm %s: %s" % (path, e)}
        # Также удалим .bak, если есть
        try:
            os.remove(path + ".bak")
        except OSError:
            pass
        # И state-файл
        for p in (INSTALLED_STATE_FILE, INSTALLED_STATE_FILE_FALLBACK):
            try:
                os.remove(p)
            except OSError:
                continue
        log.info("sing-box удалён из %s" % path, source="singbox_installer")
        try:
            get_singbox_detector().get_environment_report(force=True)
        except Exception:
            pass
        return {"ok": True, "removed": True, "path": path}


# ─────── singleton ───────

_installer = None
_installer_lock = threading.Lock()


def get_singbox_installer() -> SingboxInstaller:
    global _installer
    if _installer is None:
        with _installer_lock:
            if _installer is None:
                _installer = SingboxInstaller()
    return _installer
