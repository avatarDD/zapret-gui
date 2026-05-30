# core/awg_installer.py
"""
Установка/обновление/удаление бинарников amneziawg-go и amneziawg-tools
из GitHub Releases нашего репозитория.

Релизы публикуются workflow .github/workflows/build-awg-binaries.yml.
Каждый релиз содержит manifest.json со списком бинарников по архитектурам:

    {
      "schema": 1,
      "tag": "awg-bin-go-X-tools-Y",
      "amneziawg_go":    {"version": "...", "binaries": {arch: {filename,url,sha256,size}}},
      "amneziawg_tools": {"version": "...", "binaries": {arch: {...}}}
    }

Использование:
    from core.awg_installer import get_awg_installer
    inst = get_awg_installer()
    inst.install_binaries(arch="aarch64")
    inst.get_installed_version()
    inst.uninstall_binaries()
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.awg_detector import get_awg_detector
from core.config_manager import get_config_manager
from core.log_buffer import log


HTTP_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 300

DEFAULT_REPO         = "avatardd/zapret-gui"
DEFAULT_TAG_PREFIX   = "awg-bin-"
GITHUB_API_BASE      = "https://api.github.com"

# Кэш manifest'а — TTL 5 минут
MANIFEST_CACHE_TTL = 300


def _http_get(url: str, accept: str = "application/json", timeout: int = HTTP_TIMEOUT):
    # Применяем зеркало (ZAPRET_GUI_MIRROR / install.mirror) к GitHub-URL.
    try:
        from core.binary_installer import resolve_url
        url = resolve_url(url)
    except Exception:
        pass
    req = Request(url, headers={
        "User-Agent": "zapret-gui-awg/1.0",
        "Accept": accept,
    })
    return urlopen(req, timeout=timeout)


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+){1,3}(?:[A-Za-z][\w.\-]*)?)")


def _opkg_pkg_version(pkg_name: str) -> str:
    """
    Версия установленного opkg-пакета (Entware/OpenWrt).

    `opkg status <pkg>` пишет `Version: vX.Y.Z` для установленных
    пакетов. Это надёжнее, чем `--version` бинарника: апстрим
    amneziawg-go нередко собирается без ldflags, и `--version`
    возвращает дату сборки вместо тэга релиза.

    Возвращает '' если opkg не нашёл пакет или opkg недоступен.
    """
    if not pkg_name:
        return ""
    try:
        r = subprocess.run(
            ["opkg", "status", pkg_name],
            capture_output=True, text=True, timeout=4,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""
    if r.returncode != 0 or not r.stdout:
        return ""
    for line in r.stdout.splitlines():
        m = re.match(r"\s*Version\s*:\s*(\S+)", line)
        if m:
            return m.group(1).strip()
    return ""


def _detect_binary_version(path: str) -> str:
    """
    Спросить у бинарника его версию через `--version` / `-v`.
    Возвращает строку вроде '0.2.17' или '' если не удалось.

    Менее надёжно opkg'a: апстрим может зашить дату сборки,
    а не релизный тэг. Используется как fallback.
    """
    if not path or not os.path.isfile(path):
        return ""
    for flag in ("--version", "-v"):
        try:
            r = subprocess.run(
                [path, flag], capture_output=True, text=True, timeout=4,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        out = (r.stdout or "") + (r.stderr or "")
        m = _VERSION_RE.search(out)
        if m:
            return m.group(1)
    return ""


def _resolve_external_version(pkg_name: str, bin_path: str) -> tuple:
    """
    Вернуть (version, source) — самый достоверный источник версии
    для внешнего бинарника. source: 'opkg' | 'binary' | ''.
    """
    v = _opkg_pkg_version(pkg_name)
    if v:
        return v, "opkg"
    v = _detect_binary_version(bin_path)
    if v:
        return v, "binary"
    return "", ""


class AwgInstaller:
    """Установка/удаление AWG-бинарников."""

    def __init__(self):
        self._lock = threading.Lock()
        self._op_in_progress = False
        self._op_status = ""
        self._op_progress = 0  # 0..100

        self._manifest_cache = None
        self._manifest_time = 0

    # ─────────────────── settings ─────────────────────────────────

    def _settings(self) -> dict:
        cfg = get_config_manager()
        section = cfg.get("awg") or {}
        return {
            "repo":             section.get("release_repo")        or DEFAULT_REPO,
            "tag_prefix":       section.get("release_tag_prefix")  or DEFAULT_TAG_PREFIX,
            "installed_tag":    section.get("installed_tag")       or "",
            "installed_go":     section.get("installed_go")        or "",
            "installed_tools":  section.get("installed_tools")     or "",
            "installed_dir":    section.get("installed_dir")       or "",
        }

    def _save_installed(self, tag: str, go_version: str,
                        tools_version: str, arch: str, installed_dir: str):
        cfg = get_config_manager()
        existing = cfg.get("awg") or {}
        existing.update({
            "installed_tag":   tag,
            "installed_go":    go_version,
            "installed_tools": tools_version,
            "installed_arch":  arch,
            "installed_dir":   installed_dir,
            "installed_at":    int(time.time()),
        })
        cfg.set("awg", existing)
        cfg.save()

    def _clear_installed(self):
        cfg = get_config_manager()
        existing = cfg.get("awg") or {}
        for k in ("installed_tag", "installed_go", "installed_tools",
                  "installed_arch", "installed_dir", "installed_at"):
            existing.pop(k, None)
        cfg.set("awg", existing)
        cfg.save()

    # ─────────────────── target dir resolution ────────────────────

    def _resolve_target_dir(self, platform, prefer: str = "") -> dict:
        """
        Решить, куда ставить бинарники.

        Приоритет:
          1) явное значение `prefer` (передаётся из API/UI)
          2) installed_dir из settings (наша прошлая установка)
          3) каталог уже найденного внешнего amneziawg-go или awg
          4) дефолт платформы (platform.binary_dir)

        Возвращает {dir, source, external_paths: [...]}.
        """
        det = get_awg_detector()
        existing = det.detect_existing_awg()

        external_paths = []
        for key in ("binary_awg_go", "binary_awg"):
            p = existing.get(key) or ""
            if not p or not os.path.isfile(p):
                continue
            # binary_awg может быть и обычным wireguard `wg` — это не AWG.
            if key == "binary_awg" and os.path.basename(p) != "awg":
                continue
            external_paths.append(p)

        if prefer:
            return {"dir": prefer, "source": "explicit",
                    "external_paths": external_paths}

        s = self._settings()
        if s["installed_dir"] and os.path.isdir(s["installed_dir"]):
            return {"dir": s["installed_dir"], "source": "settings",
                    "external_paths": external_paths}

        # Каталог из найденной внешней установки. Только настоящий
        # AWG (amneziawg-go или awg), не обычный `wg` из wireguard-tools.
        for p in external_paths:
            d = os.path.dirname(p)
            if os.path.isdir(d):
                return {"dir": d, "source": "external",
                        "external_paths": external_paths}

        return {"dir": platform.binary_dir, "source": "platform_default",
                "external_paths": external_paths}

    def get_target_info(self, prefer: str = "") -> dict:
        """
        Публичный helper для UI: показать куда пойдёт установка
        и предупредить про конфликты с внешней установкой.
        """
        det = get_awg_detector()
        platform = det.detect_platform()
        target = self._resolve_target_dir(platform, prefer=prefer)

        existing = det.detect_existing_awg()
        active_ifaces = [i.get("name", "") for i in existing.get("active_interfaces", [])]

        # Конфликт: target_dir отличается от каталога, где уже что-то лежит.
        existing_dirs = sorted({os.path.dirname(p) for p in target["external_paths"]})
        will_overwrite = [p for p in target["external_paths"]
                          if os.path.dirname(p) == target["dir"]]
        out_of_dir = [p for p in target["external_paths"]
                      if os.path.dirname(p) != target["dir"]]

        return {
            "target_dir":       target["dir"],
            "target_source":    target["source"],     # explicit|settings|external|platform_default
            "platform_default": platform.binary_dir,
            "external_paths":   target["external_paths"],
            "external_dirs":    existing_dirs,
            "will_overwrite":   will_overwrite,
            "out_of_target":    out_of_dir,           # бинари в других каталогах — конфликт PATH
            "active_interfaces": active_ifaces,
        }

    # ─────────────────── manifest fetch ───────────────────────────

    def _resolve_release_tag(self, repo: str, tag_prefix: str) -> str:
        """
        Найти последний релиз, в котором есть manifest.json.

        Логика поиска:
          1. Если есть релиз с tag_name, начинающимся на tag_prefix,
             и в его assets есть manifest.json — берём его (новые сверху).
          2. Иначе берём первый релиз с manifest.json в assets независимо
             от префикса — это работает для ручных релизов (например
             `manual-YYYYMMDDHHMMSS`).
          3. Если ни в одном релизе нет manifest.json — кидаем понятную
             ошибку с найденными тэгами.

        GitHub API releases возвращает их в порядке создания (новые сверху).
        """
        url = "%s/repos/%s/releases?per_page=30" % (GITHUB_API_BASE, repo)
        try:
            with _http_get(url) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, ValueError, OSError) as e:
            raise RuntimeError(
                "Не удалось получить список релизов %s: %s" % (url, e)
            )

        def _has_manifest(rel):
            for a in rel.get("assets") or []:
                if (a.get("name") or "").lower() == "manifest.json":
                    return True
            return False

        # 1) Предпочтительно — последний релиз с нужным префиксом.
        for rel in data:
            tag = rel.get("tag_name") or ""
            if rel.get("draft"):
                continue
            if tag.startswith(tag_prefix) and _has_manifest(rel):
                return tag

        # 2) Любой релиз с manifest.json (для ручных загрузок).
        for rel in data:
            tag = rel.get("tag_name") or ""
            if rel.get("draft"):
                continue
            if _has_manifest(rel):
                log.info(
                    "Используем релиз %s (нет тэга с префиксом '%s', "
                    "но есть manifest.json)" % (tag, tag_prefix),
                    source="awg_installer",
                )
                return tag

        # 3) Ничего не нашли — расскажем что есть.
        seen = [r.get("tag_name") or "" for r in data][:10]
        raise RuntimeError(
            "Не найден релиз с manifest.json в репозитории %s. "
            "Проверены тэги (искали префикс '%s' или релиз с asset'ом "
            "manifest.json): %s. Соберите бинарники через workflow "
            "build-awg-binaries.yml или загрузите manifest.json в существующий релиз." %
            (repo, tag_prefix,
             (", ".join(t for t in seen if t) or "(нет релизов)"))
        )

    def _list_candidate_tags(self, repo: str, tag_prefix: str) -> list:
        """Тэги релизов с asset'ом manifest.json: сначала с префиксом
        (новые сверху), затем прочие (ручные `manual-*`)."""
        url = "%s/repos/%s/releases?per_page=30" % (GITHUB_API_BASE, repo)
        try:
            with _http_get(url) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, ValueError, OSError):
            return []

        def _has_manifest(rel):
            for a in rel.get("assets") or []:
                if (a.get("name") or "").lower() == "manifest.json":
                    return True
            return False

        prefixed, others = [], []
        for rel in data:
            if rel.get("draft"):
                continue
            tag = rel.get("tag_name") or ""
            if not tag or not _has_manifest(rel):
                continue
            (prefixed if tag.startswith(tag_prefix) else others).append(tag)
        return prefixed + others

    @staticmethod
    def _manifest_supports_arch(manifest: dict, arch: str) -> bool:
        """В манифесте объявлены бинарники go И tools под arch."""
        if not arch:
            return True
        go = ((manifest.get("amneziawg_go") or {}).get("binaries") or {})
        tools = ((manifest.get("amneziawg_tools") or {}).get("binaries") or {})
        return arch in go and arch in tools

    def _fetch_manifest(self, repo: str, tag: str) -> dict:
        """Скачать+распарсить manifest.json конкретного тэга (без кэша)."""
        url = "https://github.com/%s/releases/download/%s/manifest.json" % (
            repo, tag)
        with _http_get(url) as resp:
            manifest = json.loads(resp.read().decode("utf-8"))
        manifest.setdefault("tag", tag)
        return manifest

    def _detect_arch(self) -> str:
        try:
            return get_awg_detector().detect_architecture().get(
                "artifact_arch") or ""
        except Exception:
            return ""

    def _resolve_best_release(self, repo: str, tag_prefix: str,
                              arch: str) -> tuple:
        """
        (tag, manifest) последнего релиза, у которого реально есть
        бинарники под `arch`. Если такого нет — первый кандидат (для
        диагностики). Так пустой/битый ручной релиз без бинарников под
        нашу арх не перетягивает на себя «последний» и не вызывает
        фантомное «доступно обновление» + ошибку установки.
        """
        tags = self._list_candidate_tags(repo, tag_prefix)
        if not tags:
            raise RuntimeError(
                "Не найден релиз с manifest.json в репозитории %s "
                "(префикс '%s'). Соберите бинарники через workflow "
                "build-awg-binaries.yml или загрузите manifest.json." %
                (repo, tag_prefix))
        first = None
        for tag in tags[:12]:
            try:
                manifest = self._fetch_manifest(repo, tag)
            except (HTTPError, URLError, ValueError, OSError):
                continue
            if first is None:
                first = (tag, manifest)
            if self._manifest_supports_arch(manifest, arch):
                return tag, manifest
        if first is None:
            raise RuntimeError(
                "Не удалось скачать ни один manifest.json в %s" % repo)
        log.info("awg: нет релиза с бинарниками под '%s' — берём %s "
                 "для диагностики" % (arch, first[0]), source="awg_installer")
        return first

    def get_manifest(self, tag: str = None, force: bool = False,
                     arch: str = None) -> dict:
        """
        Получить manifest.json. Если tag не задан — берётся последний
        релиз с бинарниками под текущую (или переданную) архитектуру.

        Кэшируется на MANIFEST_CACHE_TTL секунд.
        """
        with self._lock:
            now = time.time()
            cached_ok = (
                self._manifest_cache is not None
                and not force
                and now - self._manifest_time < MANIFEST_CACHE_TTL
                and (tag is None or self._manifest_cache.get("tag") == tag)
            )
            if cached_ok:
                return self._manifest_cache

        s = self._settings()
        repo = s["repo"]

        if not tag:
            if arch is None:
                arch = self._detect_arch()
            tag, manifest = self._resolve_best_release(
                repo, s["tag_prefix"], arch)
        else:
            try:
                manifest = self._fetch_manifest(repo, tag)
            except (HTTPError, URLError, ValueError, OSError) as e:
                raise RuntimeError(
                    "Не удалось скачать manifest.json (%s): %s" % (tag, e))

        with self._lock:
            self._manifest_cache = manifest
            self._manifest_time = time.time()
        return manifest

    # ─────────────────── version state ────────────────────────────

    def get_installed_version(self) -> dict:
        """
        Что сейчас установлено. Учитывает:
          - запись в settings (наша установка),
          - бинари в installed_dir,
          - бинари в platform.binary_dir,
          - найденные detector'ом внешние бинари.
        """
        det = get_awg_detector()
        platform = det.detect_platform()
        s = self._settings()

        # Каталоги, в которых ищем бинари: settings.installed_dir,
        # каталог по платформе, плюс пути из detector'а.
        search_dirs = []
        if s["installed_dir"]:
            search_dirs.append(s["installed_dir"])
        if platform.binary_dir not in search_dirs:
            search_dirs.append(platform.binary_dir)

        existing = det.detect_existing_awg()
        for key in ("binary_awg_go", "binary_awg"):
            p = existing.get(key) or ""
            if p:
                d = os.path.dirname(p)
                if d and d not in search_dirs:
                    search_dirs.append(d)

        def _find(name):
            for d in search_dirs:
                p = os.path.join(d, name)
                if os.path.isfile(p):
                    return p
            return ""

        bin_go = _find("amneziawg-go")
        bin_awg = _find("awg")

        # external = бинари есть, но settings_tag пуст → не наша установка
        is_external = bool(bin_go or bin_awg) and not s["installed_tag"]
        installed = bool(s["installed_tag"]) or bool(bin_go and bin_awg)

        # Какой каталог считать «текущим» для install_dir UI:
        if s["installed_dir"]:
            current_dir = s["installed_dir"]
        elif bin_go:
            current_dir = os.path.dirname(bin_go)
        elif bin_awg:
            current_dir = os.path.dirname(bin_awg)
        else:
            current_dir = platform.binary_dir

        # Для внешних установок версии в settings'ах нет — спрашиваем
        # opkg (если Entware/OpenWrt), а в крайнем случае сам бинарь
        # через --version. opkg надёжнее: апстримный amneziawg-go может
        # вернуть дату сборки вместо релизного тэга.
        go_version       = s["installed_go"]
        tools_version    = s["installed_tools"]
        go_version_src   = "settings" if go_version else ""
        tools_version_src = "settings" if tools_version else ""
        if is_external:
            if not go_version:
                v, src = _resolve_external_version("amneziawg-go", bin_go)
                if v:
                    go_version, go_version_src = v, src
            if not tools_version:
                v, src = _resolve_external_version("amneziawg-tools", bin_awg)
                if v:
                    tools_version, tools_version_src = v, src

        return {
            "installed":      installed,
            "external":       is_external,
            "tag":            s["installed_tag"],
            "go_version":     go_version,
            "tools_version":  tools_version,
            "go_version_source":    go_version_src,    # opkg|binary|settings|''
            "tools_version_source": tools_version_src,
            "binary_dir":     current_dir,
            "platform_default_dir": platform.binary_dir,
            "amneziawg_go":   bin_go,
            "awg":            bin_awg,
        }

    def check_for_updates(self) -> dict:
        """
        Сравнить установленную версию с последней доступной в манифесте.
        """
        arch = self._detect_arch()
        try:
            manifest = self.get_manifest(force=True, arch=arch)
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}

        installed = self.get_installed_version()
        latest_go = manifest.get("amneziawg_go", {}).get("version") or ""
        latest_tools = manifest.get("amneziawg_tools", {}).get("version") or ""
        latest_tag = manifest.get("tag") or ""

        # Поддерживает ли последний релиз нашу архитектуру. Если нет —
        # не предлагаем обновление (иначе фантомный апдейт на битый/пустой
        # релиз → ошибка установки «нет бинарников для <arch>»).
        arch_supported = self._manifest_supports_arch(manifest, arch)
        available_archs = sorted(set(
            list(((manifest.get("amneziawg_go") or {}).get("binaries") or {}).keys())
            + list(((manifest.get("amneziawg_tools") or {}).get("binaries") or {}).keys())
        ))

        update_available = (
            installed["installed"] and arch_supported and
            (latest_tag and installed["tag"] != latest_tag)
        )
        return {
            "ok":               True,
            "installed":        installed,
            "latest_tag":       latest_tag,
            "latest_go":        latest_go,
            "latest_tools":     latest_tools,
            "arch":             arch,
            "arch_supported":   bool(arch_supported),
            "available_archs":  available_archs,
            "update_available": bool(update_available),
        }

    # ─────────────────── progress ─────────────────────────────────

    def _set_progress(self, status: str, progress: int):
        with self._lock:
            self._op_status = status
            self._op_progress = max(0, min(100, int(progress)))
        log.debug("[awg_installer] %d%% — %s" % (progress, status),
                  source="awg_installer")

    def get_operation_status(self) -> dict:
        with self._lock:
            return {
                "in_progress": self._op_in_progress,
                "status":      self._op_status,
                "progress":    self._op_progress,
            }

    # ─────────────────── install / uninstall ──────────────────────

    def install_binaries(self, arch: str = None, tag: str = None,
                         target_dir: str = None) -> dict:
        """
        Скачать и установить amneziawg-go и amneziawg-tools (awg).

        arch        — имя арх. из manifest'а (mipsel-softfloat, aarch64, ...).
                      Если не задано — берём из awg_detector.
        tag         — конкретный тэг релиза. Если не задано — последний awg-bin-*.
        target_dir  — куда поставить бинари. Если не задано — _resolve_target_dir():
                      сначала уважаем settings.installed_dir, потом каталог
                      найденной внешней установки, потом дефолт платформы.
        """
        with self._lock:
            if self._op_in_progress:
                return {"ok": False, "message": "Операция уже выполняется"}
            self._op_in_progress = True
            self._op_status = "Подготовка..."
            self._op_progress = 0
        try:
            return self._do_install(arch=arch, tag=tag, target_dir=target_dir)
        except Exception as e:
            log.error("Установка AWG провалилась: %s" % e, source="awg_installer")
            return {"ok": False, "message": "Ошибка установки: %s" % e}
        finally:
            with self._lock:
                self._op_in_progress = False

    def uninstall_binaries(self) -> dict:
        """
        Удалить установленные AWG-бинарники из всех известных мест:
        installed_dir (наша установка), platform.binary_dir, а также
        внешние пути, найденные detector'ом — чтобы пользователю не
        пришлось чистить вручную.
        Конфиги в config_dir не трогаем.
        """
        with self._lock:
            if self._op_in_progress:
                return {"ok": False, "message": "Операция уже выполняется"}
            self._op_in_progress = True
            self._op_status = "Удаление..."
            self._op_progress = 0
        try:
            det = get_awg_detector()
            platform = det.detect_platform()
            s = self._settings()

            candidates = []
            if s["installed_dir"]:
                candidates.append(os.path.join(s["installed_dir"], "amneziawg-go"))
                candidates.append(os.path.join(s["installed_dir"], "awg"))

            candidates.append(platform.binary_path("amneziawg-go"))
            candidates.append(platform.awg_path())

            existing = det.detect_existing_awg()
            for key in ("binary_awg_go", "binary_awg"):
                p = existing.get(key) or ""
                # Никогда не трогаем `wg` — это обычный wireguard-tools
                if p and os.path.basename(p) in ("amneziawg-go", "awg"):
                    candidates.append(p)

            removed = []
            seen = set()
            for path in candidates:
                if path in seen:
                    continue
                seen.add(path)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                        removed.append(path)
                        log.info("Удалён %s" % path, source="awg_installer")
                    except OSError as e:
                        log.error("Не удалось удалить %s: %s" % (path, e),
                                  source="awg_installer")

            self._clear_installed()
            self._set_progress("Готово", 100)
            return {"ok": True, "removed": removed,
                    "message": "Удалено %d файлов" % len(removed)}
        finally:
            with self._lock:
                self._op_in_progress = False

    # ─────────────────── internals ────────────────────────────────

    def _do_install(self, arch: str, tag: str, target_dir: str = None) -> dict:
        det = get_awg_detector()
        platform = det.detect_platform()

        # Архитектура
        if not arch:
            arch_info = det.detect_architecture()
            arch = arch_info.get("artifact_arch") or ""
        if not arch:
            return {"ok": False, "message":
                    "Не удалось определить архитектуру"}

        # Target directory — если есть внешний AWG, ставим туда же
        target = self._resolve_target_dir(platform, prefer=target_dir or "")
        install_dir = target["dir"]

        self._set_progress("Получение manifest.json...", 5)
        manifest = self.get_manifest(tag=tag, force=True)
        actual_tag = manifest.get("tag", "")

        go_section    = manifest.get("amneziawg_go", {}) or {}
        tools_section = manifest.get("amneziawg_tools", {}) or {}
        go_bin    = (go_section.get("binaries") or {}).get(arch)
        tools_bin = (tools_section.get("binaries") or {}).get(arch)

        if not go_bin or not tools_bin:
            available = sorted(set(
                list((go_section.get("binaries") or {}).keys()) +
                list((tools_section.get("binaries") or {}).keys())
            ))
            return {"ok": False, "message":
                    "В релизе %s нет бинарников для %s. Доступные: %s" %
                    (actual_tag, arch, ", ".join(available) or "(пусто)")}

        # Создаём install_dir
        try:
            os.makedirs(install_dir, exist_ok=True)
        except OSError as e:
            return {"ok": False, "message":
                    "Не удалось создать %s: %s" % (install_dir, e)}

        from core.binary_installer import workbase
        with tempfile.TemporaryDirectory(
                prefix="awg-install-", dir=workbase(install_dir)) as tmp:
            # 1) amneziawg-go
            self._set_progress("Загрузка amneziawg-go...", 10)
            go_archive = os.path.join(tmp, go_bin["filename"])
            self._download(go_bin["url"], go_archive,
                           progress_from=10, progress_to=40,
                           label="amneziawg-go")
            self._verify_sha256(go_archive, go_bin.get("sha256", ""))

            # 2) amneziawg-tools (awg)
            self._set_progress("Загрузка amneziawg-tools...", 45)
            tools_archive = os.path.join(tmp, tools_bin["filename"])
            self._download(tools_bin["url"], tools_archive,
                           progress_from=45, progress_to=75,
                           label="amneziawg-tools")
            self._verify_sha256(tools_archive, tools_bin.get("sha256", ""))

            # 3) Распаковка
            self._set_progress("Распаковка amneziawg-go...", 80)
            self._extract_to(go_archive, install_dir, expect="amneziawg-go")

            self._set_progress("Распаковка amneziawg-tools...", 90)
            self._extract_to(tools_archive, install_dir, expect="awg")

        # 4) +x на бинари
        self._set_progress("Установка прав...", 95)
        for name in ("amneziawg-go", "awg"):
            path = os.path.join(install_dir, name)
            if os.path.isfile(path):
                try:
                    st = os.stat(path)
                    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                except OSError as e:
                    log.warning("chmod %s: %s" % (path, e), source="awg_installer")

        # 5) Сохранить версию
        self._save_installed(
            tag=actual_tag,
            go_version=go_section.get("version", ""),
            tools_version=tools_section.get("version", ""),
            arch=arch,
            installed_dir=install_dir,
        )

        self._set_progress("Готово", 100)
        log.success("AWG-бинарники установлены: %s (%s) → %s" %
                    (actual_tag, arch, install_dir), source="awg_installer")
        return {
            "ok": True,
            "message": "Установлено: amneziawg-go %s, amneziawg-tools %s в %s" %
                       (go_section.get("version", "?"),
                        tools_section.get("version", "?"),
                        install_dir),
            "tag":            actual_tag,
            "arch":           arch,
            "go_version":     go_section.get("version", ""),
            "tools_version":  tools_section.get("version", ""),
            "binary_dir":     install_dir,
            "target_source":  target["source"],
        }

    def _download(self, url: str, dest: str,
                  progress_from: int, progress_to: int, label: str):
        log.info("Загрузка %s → %s" % (url, dest), source="awg_installer")
        # Делегируем общей утилите: зеркало (ZAPRET_GUI_MIRROR /
        # install.mirror), оффлайн (file://), retry. Прогресс маппим в
        # _set_progress в исходном диапазоне.
        from core import binary_installer as bi
        res = bi.download_file(
            url, dest,
            progress_cb=lambda _s, pct, lbl: self._set_progress(lbl, pct),
            label=label, progress_from=progress_from,
            progress_to=progress_to, timeout=DOWNLOAD_TIMEOUT)
        if not res.get("ok"):
            raise RuntimeError("Ошибка загрузки %s: %s"
                               % (url, res.get("error")))

    def _verify_sha256(self, path: str, expected: str):
        if not expected:
            log.warning("В manifest нет sha256 для %s — пропускаем проверку" %
                        os.path.basename(path), source="awg_installer")
            return
        actual = _sha256_of(path)
        if actual.lower() != expected.lower():
            raise RuntimeError(
                "sha256 не совпадает для %s: ожидалось %s, получено %s" %
                (os.path.basename(path), expected, actual)
            )

    def _extract_to(self, archive: str, dest_dir: str, expect: str):
        """Распаковать tar.gz, ожидая внутри файл с именем `expect`."""
        try:
            with tarfile.open(archive, "r:gz") as tar:
                members = tar.getmembers()
                target = None
                for m in members:
                    base = os.path.basename(m.name)
                    if m.isfile() and base == expect:
                        target = m
                        break
                if target is None:
                    raise RuntimeError(
                        "В архиве %s нет файла '%s'" %
                        (os.path.basename(archive), expect)
                    )
                # Извлекаем в tmp и копируем в dest_dir под нужным именем
                tmpdir = tempfile.mkdtemp(prefix="awg-extract-")
                try:
                    tar.extract(target, tmpdir)
                    src = os.path.join(tmpdir, target.name)
                    dst = os.path.join(dest_dir, expect)
                    if os.path.exists(dst):
                        try:
                            os.remove(dst)
                        except OSError:
                            pass
                    shutil.copy2(src, dst)
                finally:
                    shutil.rmtree(tmpdir, ignore_errors=True)
        except (tarfile.TarError, OSError) as e:
            raise RuntimeError("Ошибка распаковки %s: %s" %
                               (os.path.basename(archive), e))


def _human_size(n: int) -> str:
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024)
    return "%.1f MB" % (n / (1024 * 1024))


# ───────────────────── singleton ─────────────────────────────────

_installer = None
_installer_lock = threading.Lock()


def get_awg_installer() -> AwgInstaller:
    global _installer
    if _installer is None:
        with _installer_lock:
            if _installer is None:
                _installer = AwgInstaller()
    return _installer
