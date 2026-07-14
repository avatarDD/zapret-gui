# core/ext_binary_installer.py
"""
Установщик внешних бинарников (не из zapret-gui репозитория).

Скачивает бинарники с GitHub releases сторонних проектов:
  - usque-keenetic (side-effect-tm/usque-keenetic)
  - teleproxy (teleproxy/teleproxy)
  - tg-mtproxy-client (necronicle/z2k)
  - opera-proxy (Alexey71/opera-proxy)

Паттерн: GitHub API → latest release → архитектура → скачивание → install.
"""

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from core.log_buffer import log


HTTP_TIMEOUT = 15
DOWNLOAD_TIMEOUT = 120


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

def github_latest_release(repo: str) -> dict:
    """Получить информацию о latest release."""
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "zapret-gui/ext-installer",
        })
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        log.warning("github_latest_release(%s): %s" % (repo, e),
                    source="ext_installer")
        return {}


def github_download_url(repo: str, tag: str, filename: str) -> str:
    """Сформировать URL для скачивания asset'а."""
    return ("https://github.com/%s/releases/download/%s/%s"
            % (repo, tag, filename))


# ─────── Скачивание и установка ───────

def download_file(url: str, dest: str, timeout: int = DOWNLOAD_TIMEOUT) -> bool:
    """Скачать файл по URL."""
    try:
        from core.binary_installer import resolve_url
        from core.download_transport import urlopen_via
        with urlopen_via(resolve_url(url), timeout=timeout,
                         headers={"User-Agent": "zapret-gui/ext-installer"}) as r:
            with open(dest, "wb") as f:
                while True:
                    chunk = r.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
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
    "usque": {
        "repo": "side-effect-tm/usque-keenetic",
        "dest": "/opt/usr/bin/usque",
        "arch_map": {
            "aarch64": "usque-aarch64",
            "mipsel": "usque-mipsel",
            "mips": "usque-mips",
            "armv7": "usque-armv7",
        },
    },
    "teleproxy": {
        "repo": "teleproxy/teleproxy",
        "dest": "/opt/usr/bin/teleproxy",
        "arch_map": {
            "aarch64": "teleproxy-linux-arm64",
            "x86_64": "teleproxy-linux-amd64",
        },
    },
    "tgproto": {
        "repo": "necronicle/z2k",
        "dest": "/opt/sbin/tg-mtproxy-client",
        "arch_map": {
            "aarch64": "tg-mtproxy-client-arm64",
            "mipsel": "tg-mtproxy-client-mipsel",
            "mips": "tg-mtproxy-client-mips",
            "armv7": "tg-mtproxy-client-armv7",
            "x86_64": "tg-mtproxy-client-amd64",
        },
        # В z2k бинарники лежат в поддиректории builds/
        "asset_prefix": "mtproxy-client/builds/",
    },
    "opera": {
        "repo": "Alexey71/opera-proxy",
        "dest": "/opt/usr/bin/opera-proxy",
        "arch_map": {
            "aarch64": "opera-proxy.linux.arm64",
            "x86_64": "opera-proxy.linux.amd64",
            "mipsel": "opera-proxy.linux.mipsel",
        },
    },
}


def get_install_status(name: str) -> dict:
    """Проверить статус установки бинарника."""
    cfg = BINARIES.get(name)
    if not cfg:
        return {"installed": False, "error": "Неизвестный бинарник: %s" % name}

    arch = detect_arch()
    if arch not in cfg["arch_map"]:
        return {"installed": False, "arch": arch,
                "error": "Архитектура %s не поддерживается для %s" % (arch, name)}

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


def install_binary_by_name(name: str, *, progress_cb=None) -> dict:
    """
    Установить бинарник по имени.

    Args:
        name: "usque" | "teleproxy" | "tgproto" | "opera"
        progress_cb: callback(stage, pct, label) для UI

    Returns:
        {ok, binary, version, error}
    """
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник: %s" % name}

    arch = detect_arch()
    if arch not in cfg["arch_map"]:
        return {"ok": False, "error": "Архитектура %s не поддерживается" % arch}

    asset_name = cfg["arch_map"][arch]
    asset_prefix = cfg.get("asset_prefix", "")

    # 1. Получаем latest release
    if progress_cb:
        progress_cb("fetch", 10, "Получение информации о релизе...")
    release = github_latest_release(cfg["repo"])
    if not release:
        return {"ok": False, "error": "Не удалось получить release с GitHub"}

    tag = release.get("tag_name", "")
    if not tag:
        return {"ok": False, "error": "Release без tag"}

    # 2. Ищем asset
    if progress_cb:
        progress_cb("download", 30, "Скачивание %s..." % asset_name)

    # Пробуем разные варианты имени файла
    candidates = [
        asset_prefix + asset_name,
        asset_name,
        asset_name + ".gz",
        asset_name + ".tar.gz",
    ]

    download_url = ""
    for c in candidates:
        url = github_download_url(cfg["repo"], tag, c)
        # Проверяем существует ли asset в release
        for asset in release.get("assets", []):
            if asset.get("name") == c:
                download_url = asset.get("browser_download_url", url)
                break
        if download_url:
            break

    if not download_url:
        # Fallback: пробуем напрямую
        download_url = github_download_url(cfg["repo"], tag, candidates[0])

    # 3. Скачиваем
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp_path = tmp.name

    try:
        if not download_file(download_url, tmp_path):
            return {"ok": False, "error": "Не удалось скачать %s" % asset_name}

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
            with tarfile.open(tmp_path, "r:gz") as tar:
                # Ищем бинарник в архиве
                for member in tar.getmembers():
                    if member.isfile() and not member.name.startswith("."):
                        tar.extract(member, tempfile.gettempdir())
                        final_path = os.path.join(tempfile.gettempdir(),
                                                   member.name)
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
