# core/ext_binary_installer.py
"""
Установщик внешних бинарников (не из zapret-gui репозитория).

Скачивает бинарники с GitHub releases сторонних проектов:
  - usque-keenetic (side-effect-tm/usque-keenetic)
  - tg-mtproxy-client (necronicle/z2k)
  - opera-proxy (Alexey71/opera-proxy)

Паттерн: GitHub API → latest release → архитектура → скачивание → install.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from core.log_buffer import log


class InstallError(Exception):
    """Ошибка установки бинарника."""


HTTP_TIMEOUT = 15
DOWNLOAD_TIMEOUT = 120

_operation_status = {}

def get_operation_status(name: str) -> dict:
    """Получить статус текущей операции (установки)."""
    return _operation_status.get(name, {"status": "idle", "progress": 0, "message": ""})


def _pkg_version(pkg_name: str) -> str:
    """Версия установленного пакета через opkg/apk."""
    if not pkg_name:
        return ""
    for cmd, args in (
        ("opkg", ["status", pkg_name]),
        ("apk", ["info", "-v", pkg_name]),
    ):
        try:
            proc = subprocess.run(
                [cmd, *args], capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0 or not proc.stdout:
            continue
        if cmd == "opkg":
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        else:
            prefix = pkg_name + "-"
            first = proc.stdout.splitlines()[0].strip()
            if first.startswith(prefix):
                return first[len(prefix):].split()[0].strip()
            if first:
                return first.split()[0]
    return ""


def _package_manager() -> str:
    """Найти пакетный менеджер хоста."""
    for cmd in ("opkg", "apk"):
        if shutil.which(cmd):
            return cmd
    return ""


# ─────── Архитектуры ───────

def detect_arch() -> str:
    """Определить архитектуру системы."""
    try:
        r = subprocess.run(["uname", "-m"], capture_output=True, text=True, timeout=5)
        m = (r.stdout or "").strip().lower()
        if "aarch64" in m or "arm64" in m:
            return "aarch64"
        if "x86_64" in m or "x86-64" in m:
            return "x86_64"
        if "mipsel" in m:
            return "mipsel"
        if "mips" in m:
            return "mips"
        if "armv7" in m or "armhf" in m:
            return "armv7"
    except Exception:
        pass
    # Fallback: opkg
    try:
        r = subprocess.run(["opkg", "print-architecture"],
                           capture_output=True, text=True, timeout=5)
        for line in (r.stdout or "").splitlines():
            if "mipsel" in line:
                return "mipsel"
            if "mips" in line:
                return "mips"
            if "aarch64" in line:
                return "aarch64"
            if "arm" in line:
                return "armv7"
    except Exception:
        pass
    return ""


# ─────── GitHub API ───────

def _parse_retry_after(headers) -> int:
    """Парсит Retry-After (сек) или X-RateLimit-Reset (unix-ts) из заголовков ответа.
    Возвращает 0 если ни один заголовок не распознан."""
    raw = headers.get("Retry-After")
    if raw and raw.isdigit():
        return int(raw)
    raw = headers.get("X-RateLimit-Reset")
    if raw and raw.isdigit():
        return max(0, int(raw) - int(time.time()))
    return 0


def github_release(repo: str, tag: str = "") -> dict:
    """Получить информацию о release.

    Если tag пустой — берём latest, иначе фиксированный release/tags/<tag>.
    """
    from core.binary_installer import resolve_url
    if tag:
        url = "https://api.github.com/repos/%s/releases/tags/%s" % (repo, tag)
    else:
        url = "https://api.github.com/repos/%s/releases/latest" % repo
    url = resolve_url(url)

    # Токен авторизации из конфига github.token (опционально)
    token = ""
    try:
        from core.config_manager import get_config_manager
        token = (get_config_manager().get("github", "token", default="") or "").strip()
    except Exception:
        pass

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "zapret-gui/ext-installer",
    }
    if token:
        headers["Authorization"] = "token %s" % token

    max_attempts = 3
    backoff = [2, 4]  # секунд между попытками (3-я — последняя, без повтора)

    for attempt in range(max_attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                remaining = r.headers.get("X-RateLimit-Remaining", "")
                if remaining.isdigit() and int(remaining) < 10:
                    log.warning(
                        "github_latest_release(%s): осталось %s запросов к GitHub API"
                        % (repo, remaining),
                        source="ext_installer",
                    )
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429):
                log.warning(
                    "github_latest_release(%s): HTTP %s" % (repo, e.code),
                    source="ext_installer",
                )
                return {"error_detail": "GitHub API HTTP error %s" % e.code}

            # Rate-limit: пытаемся восстановиться
            if attempt == max_attempts - 1:
                retry_after = _parse_retry_after(e.headers)
                if retry_after:
                    err_msg = (
                        "Превышен лимит запросов GitHub API (Rate Limit). "
                        "Повторите через ~%d с или настройте зеркало." % retry_after
                    )
                else:
                    err_msg = (
                        "Превышен лимит запросов GitHub API (HTTP %d). "
                        "Настройте зеркало." % e.code
                    )
                log.warning(
                    "github_latest_release(%s): %s" % (repo, err_msg),
                    source="ext_installer",
                )
                return {"error_detail": err_msg}

            # Определяем сколько ждать перед повтором
            wait = _parse_retry_after(e.headers)
            if not wait:
                wait = backoff[attempt] if attempt < len(backoff) else backoff[-1]
            else:
                wait = min(wait, 60)

            log.warning(
                "github_latest_release(%s): HTTP %d (attempt %d/%d), "
                "жду %d с перед повтором"
                % (repo, e.code, attempt + 1, max_attempts, wait),
                source="ext_installer",
            )
            time.sleep(wait)
        except Exception as e:
            log.warning(
                "github_latest_release(%s): %s" % (repo, e),
                source="ext_installer",
            )
            return {}

    return {"error_detail": (
        "Не удалось получить данные с GitHub API после %d попыток" % max_attempts
    )}


def github_latest_release(repo: str) -> dict:
    """Совместимость со старыми тестами и моками."""
    return github_release(repo)


def github_download_url(repo: str, tag: str, filename: str) -> str:
    """Сформировать URL для скачивания asset'а."""
    return ("https://github.com/%s/releases/download/%s/%s"
            % (repo, tag, filename))


# ─────── Скачивание и установка ───────

def download_file(url: str, dest: str, timeout: int = DOWNLOAD_TIMEOUT) -> bool:
    """Скачать файл по URL с поддержкой докачки (resume)."""
    part_file = dest + ".part"
    try:
        from core.binary_installer import resolve_url
        from core.download_transport import urlopen_via
        
        resolved_url = resolve_url(url)
        headers = {"User-Agent": "zapret-gui/ext-installer"}
        
        existing_size = 0
        if os.path.exists(part_file):
            existing_size = os.path.getsize(part_file)

        if existing_size > 0:
            headers["Range"] = "bytes=%d-" % existing_size

        try:
            req_ctx = urlopen_via(resolved_url, timeout=timeout, headers=headers)
        except Exception as e:
            if "Range" in headers:
                log.warning("download_file: Range request failed, retrying from scratch: %s" % e, source="ext_installer")
                if os.path.exists(part_file):
                    try:
                        os.remove(part_file)
                    except OSError:
                        pass
                headers.pop("Range")
                req_ctx = urlopen_via(resolved_url, timeout=timeout, headers=headers)
            else:
                raise

        with req_ctx as r:
            code = getattr(r, "status", getattr(r, "code", 200))
            if code == 416:
                if os.path.exists(part_file):
                    try:
                        os.remove(part_file)
                    except OSError:
                        pass
                return download_file(url, dest, timeout)

            mode = "wb"
            if code == 206 and existing_size > 0:
                mode = "ab"
                log.info("download_file: resuming download from byte %d" % existing_size, source="ext_installer")
            else:
                if existing_size > 0:
                    log.info("download_file: server does not support Range, starting from scratch", source="ext_installer")

            with open(part_file, mode) as f:
                while True:
                    chunk = r.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)

        if os.path.exists(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        os.rename(part_file, dest)
        return True
    except Exception as e:
        log.warning("download_file: %s → %s" % (url, e), source="ext_installer")
        return False


def install_binary(source: str, dest: str) -> bool:
    """Установить бинарник: скопировать + chmod +x."""
    try:
        dest_dir = os.path.dirname(dest)
        os.makedirs(dest_dir, exist_ok=True)
        import shutil
        shutil.copy2(source, dest)
        os.chmod(dest, 0o755)
        return True
    except Exception as e:
        log.warning("install_binary: %s" % e, source="ext_installer")
        return False


# ─────── Конкретные установщики ───────

# Конфигурация каждого бинарника
BINARIES = {
    "tgwsproxy": {
        "repo": "spatiumstas/tg-ws-proxy-go",
        "release_tag": "0.9.2",
        "install_kind": "package",
        "package_name": "tg-ws-proxy",
        "dest": "/opt/bin/tg-ws-proxy",
        "arch_map": {
            "aarch64": "tg-ws-proxy_0.9.2-1_entware_aarch64-3.10.ipk",
            "armv7": "tg-ws-proxy_0.9.2-1_entware_armv7-3.2.ipk",
            "mips": "tg-ws-proxy_0.9.2-1_entware_mips-3.4.ipk",
            "mipsel": "tg-ws-proxy_0.9.2-1_entware_mipsel-3.4.ipk",
        },
        "package_assets": {
            "opkg": {
                "aarch64": "tg-ws-proxy_0.9.2-1_entware_aarch64-3.10.ipk",
                "armv7": "tg-ws-proxy_0.9.2-1_entware_armv7-3.2.ipk",
                "mips": "tg-ws-proxy_0.9.2-1_entware_mips-3.4.ipk",
                "mipsel": "tg-ws-proxy_0.9.2-1_entware_mipsel-3.4.ipk",
            },
            "apk": {
                "aarch64": "tg-ws-proxy_0.9.2-r1_openwrt_aarch64_generic.apk",
                "mips": "tg-ws-proxy_0.9.2-r1_openwrt_mips_24kc.apk",
                "mipsel": "tg-ws-proxy_0.9.2-r1_openwrt_mipsel_24kc.apk",
            },
        },
        "sha256_map": {
            "opkg:aarch64": "9e8737f43ec7114ba904179f54908dd1d21a7bb9151f7b10a38207fda2bd9f50",
            "opkg:armv7": "f2dae8651859032609e1c3914c488448ca8dee26fbf8294967c3c6c895137415",
            "opkg:mips": "cc9420023d3dc18facbd6e7f4398002afe2ae6e4f2c67cd129adebd1b3c913f3",
            "opkg:mipsel": "baea8552ec1b212e220177b712e959edc45c6f0a5c6ef42cfa0b8fadeb7e2850",
            "apk:aarch64": "1516d79e73146a1886c2ad4348a54804fff2acc558fe2f4f2ab0e35500dc8925",
            "apk:mips": "cc3dd05de4550ddc74246f9e626deaa6d695503b68d6510c6e024e50cf0e2b1a",
            "apk:mipsel": "cd827276c1e8b09efdc8207ae3cc9615c4f19c82aee765dfcfa47af35107340e",
        },
    },

    "usque": {
        "repo": "side-effect-tm/usque-keenetic",
        "release_tag": "v0.3.0",
        "dest": "/opt/usr/bin/usque",
        "arch_map": {
            "aarch64": "usque-keenetic_0.3.0_aarch64-3.10.ipk",
            "mipsel": "usque-keenetic_0.3.0_mipsel-3.4.ipk",
            "mips": "usque-keenetic_0.3.0_mips-3.4.ipk",
            "armv7": "usque-keenetic_0.3.0_all_entware.ipk",
        },
        "sha256_map": {
            "aarch64": "9ff3072a6fb607d404cca65cbfef25d286723f9b76fce8c2d6fc2f9135580a55",
            "mipsel": "300fa4b3d083636f1a8eeb8cd0ace1ecbbc68de58826831cb7b7426fc2b1aa79",
            "mips": "8b89ea2656d9fa7fa877e4fc2b9f311fce77c95c7fc2fce4e701e8579733ec9a",
            "armv7": "2ec8f7d1a40caaf16576567b6fc059877eb5b2fc627a08a8fb8d797d5f9ffb39",
        },
    },

    "tgproto": {
        "repo": "necronicle/z2k",
        "release_tag": "z2k-classify-rolling",
        "dest": "/opt/sbin/tg-mtproxy-client",
        "arch_map": {
            "mipsel": "tg-mtproxy-client-mipsel",
            "mips": "tg-mtproxy-client-mips",
            "x86_64": "z2k-classify-x86_64",
        },
        "sha256_map": {
            "mipsel": "77e32695a9324cee75e176d216df37883cb2711fe6caec30cae24f7c2a5bc32d",
            "mips": "d582b74ba0f4638a9d2a6636ddf8408fceace0416758cd1fd0dcbdab0c5e0b96",
            "x86_64": "6a8d10c1e42001a4e8e9570d114e6ac2b30b954c553c8970a4573d3fe21e3910",
        },
    },
    "opera": {
        "repo": "Alexey71/opera-proxy",
        "release_tag": "v1.27.0",
        "dest": "/opt/usr/bin/opera-proxy",
        "arch_map": {
            "aarch64": "opera-proxy.linux-arm64",
            "x86_64": "opera-proxy.linux-amd64",
            "mipsel": "opera-proxy.linux-mipsle",
            "mips": "opera-proxy.linux-mips",
        },
        "sha256_map": {
            "aarch64": "97e47545297ddceabb262833ed0424d5ec41176e3b63ed8180bdb8d629a626f2",
            "x86_64": "06e0bc4597b61f75ba26632df64c876b9c5879c7fde17cf7ec0f8aa12c646fa0",
            "mipsel": "ba1a04b463fabdb67debc033de9e60d8c9aa2bd2608e0b6068947db9a121fef0",
            "mips": "49dc72173627a009384ace966c882c15b86d8254621f70b56f7771a1561be60a",
        },
    },
}

# TODO: add sha256 from verified release assets for WARP binaries
# (warp, wgcf, warp-go, masque-client, awg)


def get_install_status(name: str) -> dict:
    """Проверить статус установки бинарника."""
    cfg = BINARIES.get(name)
    if not cfg:
        return {"installed": False, "error": "Неизвестный бинарник: %s" % name}

    install_kind = cfg.get("install_kind", "binary")
    arch = detect_arch()
    pkg_mgr = _package_manager() if install_kind == "package" else ""
    asset_name = _resolve_asset_name(cfg, arch, pkg_mgr)
    if not asset_name:
        return {"installed": False, "arch": arch,
                "error": "Архитектура %s не поддерживается для %s" % (arch, name)}

    if install_kind == "package":
        pkg = cfg.get("package_name", name)
        version = _pkg_version(pkg)
        installed = bool(version) or os.path.isfile("/opt/etc/init.d/S99tg-ws-proxy")
        binary = "/opt/etc/init.d/S99tg-ws-proxy"
    else:
        binary = cfg["dest"]
        installed = os.path.isfile(binary) and os.access(binary, os.X_OK)
        version = ""
        if installed:
            version = _get_version(binary)

    return {
        "installed": installed,
        "arch": arch,
        "binary": binary,
        "version": version,
        "repo": cfg["repo"],
    }


def _resolve_asset_name(cfg: dict, arch: str, pkg_mgr: str = "") -> str:
    """Получить asset для выбранного типа установки."""
    if cfg.get("install_kind", "binary") == "package":
        package_assets = cfg.get("package_assets", {}) or {}
        if pkg_mgr and pkg_mgr in package_assets:
            return (package_assets.get(pkg_mgr) or {}).get(arch, "")
        return (package_assets.get("opkg") or {}).get(arch, "")
    return (cfg.get("arch_map", {}) or {}).get(arch, "")


def _expected_sha256(cfg: dict, arch: str, pkg_mgr: str = "") -> str:
    """Получить ожидаемый sha256 из встроенного манифеста."""
    sha_map = cfg.get("sha256_map", {}) or {}
    if pkg_mgr and "%s:%s" % (pkg_mgr, arch) in sha_map:
        return sha_map["%s:%s" % (pkg_mgr, arch)]
    return sha_map.get(arch, "")


def _verify_downloaded_file(release: dict, asset_name: str, filepath: str) -> dict:
    """
    Находит хэш для asset_name в релизе (из файлов контрольных сумм) и проверяет файл.
    Возвращает {"ok": True} или {"ok": False, "error": ...}.
    """
    from core.binary_installer import sha256_of
    try:
        actual_hash = sha256_of(filepath)
    except Exception as e:
        return {"ok": False, "error": "Не удалось вычислить sha256: %s" % e}

    # Ищем ассет с контрольными суммами в релизе
    checksum_asset = None
    for asset in release.get("assets", []):
        aname = asset.get("name", "").lower()
        if "sha256" in aname or "checksum" in aname or "sums" in aname:
            # Исключаем сам бинарник, если в его названии вдруг есть sha256
            if aname != asset_name.lower():
                checksum_asset = asset
                break

    if not checksum_asset:
        log.warning("ext_installer: файл контрольных сумм не найден в релизе. Проверка sha256 пропущена.",
                    source="ext_installer")
        return {"ok": True, "skipped": True}

    # Скачиваем файл контрольных сумм во временный файл
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp_checksum_path = tmp.name

    try:
        download_url = checksum_asset.get("browser_download_url")
        if not download_file(download_url, tmp_checksum_path):
            log.warning("ext_installer: не удалось скачать файл контрольных сумм. Проверка sha256 пропущена.",
                        source="ext_installer")
            return {"ok": True, "skipped": True}

        # Читаем файл контрольных сумм и ищем там наш ассет
        expected_hash = ""
        with open(tmp_checksum_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    # parts[0] - хэш, parts[1...] - имя файла (или наоборот)
                    # Ищем совпадение по имени файла
                    for p in parts[1:]:
                        clean_p = os.path.basename(p.strip("* "))
                        if clean_p == asset_name:
                            h = parts[0].strip()
                            if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
                                expected_hash = h
                                break
                    if expected_hash:
                        break
                    # Обратный формат: <filename> <hash>
                    for p in parts[:-1]:
                        clean_p = os.path.basename(p.strip("* "))
                        if clean_p == asset_name:
                            h = parts[-1].strip()
                            if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
                                expected_hash = h
                                break
                    if expected_hash:
                        break

        if not expected_hash:
            log.warning("ext_installer: хэш для %s не найден в файле контрольных сумм. Проверка пропущена." % asset_name,
                        source="ext_installer")
            return {"ok": True, "skipped": True}

        # Сверяем хэши
        if actual_hash.lower() != expected_hash.lower():
            return {
                "ok": False,
                "error": "Ошибка целостности: sha256 не совпадает. Ожидался: %s, получен: %s" % (expected_hash, actual_hash)
            }

        log.info("ext_installer: sha256 верифицирован успешно для %s" % asset_name, source="ext_installer")
        return {"ok": True, "actual": actual_hash}

    finally:
        try:
            if os.path.isfile(tmp_checksum_path):
                os.unlink(tmp_checksum_path)
        except Exception:
            pass


def install_binary_by_name(name: str, *, progress_cb=None) -> dict:
    """
    Установить бинарник по имени.

    Args:
        name: "tgwsproxy" | "usque" | "tgproto" | "opera"
        progress_cb: callback(stage, pct, label) для UI

    Returns:
        {ok, binary, version, error}
    """
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник: %s" % name}

    arch = detect_arch()

    install_kind = cfg.get("install_kind", "binary")
    pkg_mgr = _package_manager() if install_kind == "package" else ""
    asset_name = _resolve_asset_name(cfg, arch, pkg_mgr)
    if not asset_name:
        return {"ok": False, "error": "Архитектура %s не поддерживается" % arch}

    # 1. Получаем pinned release
    if progress_cb:
        progress_cb("fetch", 10, "Получение информации о релизе...")
    release_tag = cfg.get("release_tag", "")
    release = github_release(cfg["repo"], release_tag)
    if not release:
        return {"ok": False, "error": "Не удалось получить release с GitHub (сеть или DNS)"}
    if "error_detail" in release:
        return {"ok": False, "error": release["error_detail"]}

    tag = release.get("tag_name", "")
    if not tag:
        return {"ok": False, "error": "Release без tag"}

    # Проверка версии: если установленный бинарник уже имеет ту же версию, что и tag
    dest_path = cfg.get("dest", "")
    package_name = cfg.get("package_name", "")
    if install_kind == "package":
        current_version = _pkg_version(package_name)
        if current_version:
            cv_norm = current_version.strip().lstrip("vV")
            tag_norm = tag.strip().lstrip("vV")
            if cv_norm == tag_norm:
                log.info("install_binary_by_name: %s version %s is already up to date" % (name, tag), source="ext_installer")
                if progress_cb:
                    progress_cb("install", 100, "Уже установлена актуальная версия %s" % tag)
                return {"ok": True, "binary": dest_path or package_name, "version": tag, "noop": True}
    elif os.path.isfile(dest_path):
        current_version = _get_version(dest_path)
        if current_version:
            # Нормализуем обе версии (удаляем начальные v/V)
            cv_norm = current_version.strip().lstrip("vV")
            tag_norm = tag.strip().lstrip("vV")
            if cv_norm == tag_norm:
                log.info("install_binary_by_name: %s version %s is already up to date" % (name, tag), source="ext_installer")
                if progress_cb:
                    progress_cb("install", 100, "Уже установлена актуальная версия %s" % tag)
                return {"ok": True, "binary": dest_path, "version": tag, "noop": True}

    # 2. Ищем asset
    if progress_cb:
        progress_cb("download", 30, "Скачивание %s..." % asset_name)

    # Пробуем разные варианты имени файла
    if install_kind == "package":
        candidates = [
            "tg-ws-proxy_%s-1_%s" % (tag, asset_name),
            "tg-ws-proxy_%s_%s" % (tag, asset_name),
            "tg-ws-proxy_%s" % tag,
        ]
    else:
        candidates = [
            asset_name,
            asset_name + ".gz",
            asset_name + ".tar.gz",
        ]

    download_url = ""
    downloaded_asset_name = ""
    assets = release.get("assets", []) or []
    if install_kind == "package":
        for asset in assets:
            aname = asset.get("name", "")
            if not aname.startswith("tg-ws-proxy_%s" % tag):
                continue
            if aname.endswith(asset_name):
                download_url = asset.get("browser_download_url", "")
                downloaded_asset_name = aname
                break
    else:
        for c in candidates:
            url = github_download_url(cfg["repo"], tag, c)
            # Проверяем существует ли asset в release
            for asset in assets:
                if asset.get("name") == c:
                    download_url = asset.get("browser_download_url", url)
                    downloaded_asset_name = c
                    break
            if download_url:
                break

    if not download_url:
        # Fallback: пробуем напрямую
        download_url = github_download_url(cfg["repo"], tag, candidates[0])
        downloaded_asset_name = candidates[0]

    # 3. Скачиваем
    # MR-138: определяем суффикс из URL, а не хардкодим .bin
    url_path = download_url.split("?")[0]  # убираем query-string
    if url_path.endswith(".tar.gz"):
        url_suffix = ".tar.gz"
    elif "." in os.path.basename(url_path):
        url_suffix = os.path.splitext(url_path)[1]
    else:
        url_suffix = ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=url_suffix) as tmp:
        tmp_path = tmp.name

    pkg_mgr = _package_manager() if install_kind == "package" else ""

    try:
        if not download_file(download_url, tmp_path):
            return {"ok": False, "error": "Не удалось скачать %s" % asset_name}

        # MR-06: Проверка sha256
        if progress_cb:
            progress_cb("download", 60, "Проверка контрольной суммы...")
        v_res = _verify_downloaded_file(release, downloaded_asset_name, tmp_path)
        if not v_res.get("ok"):
            return v_res

        # MR-06: обязательная проверка sha256 из встроенного манифеста.
        cfg_sha256 = _expected_sha256(cfg, arch, pkg_mgr)
        if not cfg_sha256:
            return {
                "ok": False,
                "error": "SHA256 для %s (%s) не задан в манифесте" % (name, arch),
            }
        h = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        if h.hexdigest().lower() != cfg_sha256.lower():
            raise InstallError("SHA256 mismatch for %s" % name)

        if install_kind == "package":
            if progress_cb:
                progress_cb("install", 70, "Установка пакета...")
            if not pkg_mgr:
                return {"ok": False, "error": "Не найден opkg/apk для установки пакета"}
            if pkg_mgr == "apk":
                install_cmd = [pkg_mgr, "add", "--allow-untrusted"]
            else:
                install_cmd = [pkg_mgr, "install"]
            install_cmd.append(tmp_path)
            if pkg_mgr == "opkg":
                install_cmd.insert(2, "--force-reinstall")
            proc = subprocess.run(install_cmd, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                return {
                    "ok": False,
                    "error": "Установка пакета не удалась: %s"
                             % ((proc.stderr or proc.stdout or "").strip()),
                }
            if progress_cb:
                progress_cb("done", 100, "Установлено: %s" % tag)
            version = _pkg_version(package_name) or tag
            return {"ok": True, "binary": dest_path or package_name, "version": version, "tag": tag}

        # 4. Распаковываем если нужно
        if progress_cb:
            progress_cb("install", 70, "Установка...")

        final_path = tmp_path
        if tmp_path.endswith(".gz"):
            import gzip
            uncompressed = tmp_path + ".unc"
            with gzip.open(tmp_path, "rb") as f_in:
                with open(uncompressed, "wb") as f_out:
                    while True:
                        chunk = f_in.read(64 * 1024)
                        if not chunk:
                            break
                        f_out.write(chunk)
            final_path = uncompressed
        elif tmp_path.endswith(".tar.gz"):
            import tarfile
            extract_dir = tempfile.mkdtemp()
            with tarfile.open(tmp_path, "r:gz") as tar:
                # Ищем бинарник в архиве
                for member in tar.getmembers():
                    if not member.isfile() or member.name.startswith("."):
                        continue
                    # MR-143: валидация пути члена архива (защита от zip-slip)
                    member_path = os.path.realpath(os.path.join(extract_dir, member.name))
                    if not member_path.startswith(os.path.realpath(extract_dir) + os.sep):
                        log.warning("ext_installer: tar path traversal blocked: %s" % member.name,
                                    source="ext_installer")
                        continue
                    tar.extract(member, extract_dir)
                    final_path = member_path
                    break

        # 5. Устанавливаем
        if progress_cb:
            progress_cb("install", 90, "Копирование бинарника...")

        if not install_binary(final_path, cfg["dest"]):
            return {"ok": False, "error": "Не удалось установить бинарник"}

        # 6. Проверяем
        version = _get_version(cfg["dest"])

        if progress_cb:
            progress_cb("done", 100, "Установлено: %s" % version)

        log.info("ext_installer: %s установлен (%s, %s)"
                 % (name, tag, version), source="ext_installer")

        return {"ok": True, "binary": cfg["dest"], "version": version,
                "tag": tag}

    finally:
        # Очистка
        for p in (tmp_path, tmp_path + ".unc"):
            try:
                if os.path.isfile(p):
                    os.unlink(p)
            except Exception:
                pass


def uninstall_binary(name: str) -> dict:
    """Удалить бинарник."""
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник"}
    try:
        if os.path.isfile(cfg["dest"]):
            os.unlink(cfg["dest"])
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _get_version(binary: str) -> str:
    """Получить версию бинарника."""
    for flag in ["--version", "-version", "-v", "version"]:
        try:
            r = subprocess.run([binary, flag],
                               capture_output=True, text=True, timeout=5)
            out = (r.stdout or r.stderr or "").strip()
            if out and len(out) < 100:
                return out
        except Exception:
            pass
    return ""
