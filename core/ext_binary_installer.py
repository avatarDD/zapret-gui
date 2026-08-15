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
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


class InstallError(Exception):
    """Ошибка установки бинарника."""


HTTP_TIMEOUT = 15
DOWNLOAD_TIMEOUT = 120

_operation_status = {}

# Кэш списка релизов: (name, transport) → (timestamp, ответ). SetupUI
# перерисовывается часто, а GitHub API лимитирован по IP.
_releases_cache = {}
_releases_lock = threading.Lock()

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

# Разрядность наших архитектур — для проверки правдоподобия детекта.
_ARCH_BITS = {"aarch64": 64, "x86_64": 64,
              "mipsel": 32, "mips": 32, "armv7": 32}


def _arch_from_name(name: str) -> str:
    """Наше имя архитектуры из произвольной строки (uname/opkg-арка)."""
    m = (name or "").strip().lower()
    if not m:
        return ""
    if "aarch64" in m or "arm64" in m:
        return "aarch64"
    if "x86_64" in m or "x86-64" in m or "amd64" in m:
        return "x86_64"
    # mipsel ДО mips: "mipsel-3.4" содержит и то и другое.
    if "mipsel" in m or "mipsle" in m:
        return "mipsel"
    if "mips" in m:
        # `uname -m` на mips возвращает "mips" для обоих порядков байт;
        # у массовых Keenetic (MT7621) это little-endian. Endianness
        # надёжно даёт только байт-порядок работающего интерпретатора.
        import sys
        return "mipsel" if sys.byteorder == "little" else "mips"
    if "armv7" in m or "armhf" in m or m.startswith("arm"):
        return "armv7"
    return ""


def _arch_from_opkg() -> str:
    """
    Архитектура по `opkg print-architecture` — по ПРИОРИТЕТУ, а не по
    порядку строк.

    Формат вывода: `arch <имя> <приоритет>`, и там перечислены ВСЕ
    настроенные арки, а не только родная:

        arch all 1
        arch noarch 1
        arch mipsel-3.4 10

    Раньше мы возвращали первую строку, в которой нашлось хоть одно
    знакомое слово. Достаточно чужой строки (лишний фид в opkg.conf —
    в руководствах по Keenetic такое копипастят регулярно), оказавшейся
    выше родной, чтобы на mipsel-роутер поехала aarch64-сборка. Родная
    арка у opkg — с наибольшим приоритетом; `all`/`noarch` не про
    процессор и пропускаются.
    """
    try:
        r = subprocess.run(["opkg", "print-architecture"],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return ""
    best, best_prio = "", -1
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "arch":
            continue
        name = parts[1]
        if name.lower() in ("all", "noarch"):
            continue
        try:
            prio = int(parts[2]) if len(parts) > 2 else 0
        except ValueError:
            prio = 0
        arch = _arch_from_name(name)
        if arch and prio > best_prio:
            best, best_prio = arch, prio
    return best


def _arch_matches_host(arch: str) -> bool:
    """Совместим ли детект с системой, на которой мы работаем.

    Интерпретатор собран под эту же машину, поэтому его разрядность —
    независимый свидетель: 64-битная арка при 32-битном userland
    означает, что детект соврал (ровно так на mipsel-роутер уезжала
    aarch64-сборка).

    Проверка ОДНОСТОРОННЯЯ. Обратное сочетание — 32-битная арка на
    64-битной системе — совершенно законно: так живут aarch64-роутеры с
    32-битным Entware, и запрещать его нельзя.
    """
    return not (_ARCH_BITS.get(arch, 0) == 64 and _host_bits() == 32)


def detect_arch() -> str:
    """Определить архитектуру системы (uname, затем opkg)."""
    uname = ""
    try:
        r = subprocess.run(["uname", "-m"], capture_output=True, text=True,
                           timeout=5)
        uname = (r.stdout or "").strip()
    except Exception:
        uname = ""

    for source, value in (("uname -m", _arch_from_name(uname)),
                          ("opkg print-architecture", _arch_from_opkg())):
        if not value:
            continue
        if not _arch_matches_host(value):
            log.warning("detect_arch: %s даёт %s, но userland 32-битный —"
                        " игнорирую (иначе поставили бы 64-битный бинарник,"
                        " который здесь не запускается)"
                        % (source, value),
                        source="ext_installer")
            continue
        return value
    return ""


def detect_openwrt_arch() -> str:
    """Целевая архитектура OpenWrt (`DISTRIB_ARCH`) или "" — не OpenWrt.

    Апстримы выпускают пакеты OpenWrt под ТАРГЕТ (`x86_64`,
    `arm_cortex-a7`, `aarch64_generic`, `mipsel_24kc`), а `uname -m` даёт
    только семейство: два разных таргета (`arm_cortex-a7` и
    `arm_cortex-a9`) неотличимы. apk сверяет арку пакета со своей и
    откажет при несовпадении, поэтому имя ассета выбираем по DISTRIB_ARCH,
    а не по догадке.
    """
    try:
        with open("/etc/openwrt_release", encoding="utf-8",
                  errors="replace") as f:
            for line in f:
                if line.startswith("DISTRIB_ARCH="):
                    val = line.split("=", 1)[1].strip().strip("'\"")
                    return val
    except OSError:
        pass
    return ""


def _arch_keys(arch: str, pkg_mgr: str = "") -> list:
    """Ключи архитектуры для поиска в манифесте, от точного к общему.

    Для apk (OpenWrt 25.12+/SNAPSHOT) сначала пробуем таргет OpenWrt
    (`x86_64`, `arm_cortex-a7`), затем семейство от `uname -m`
    (`armv7`) — так один манифест обслуживает и точные таргеты, и
    случай, когда DISTRIB_ARCH прочитать не удалось.
    """
    keys = []
    if pkg_mgr == "apk":
        target = detect_openwrt_arch()
        if target:
            keys.append(target)
    if arch and arch not in keys:
        keys.append(arch)
    return keys


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


def github_release(repo: str, tag: str = "", transport: str = "") -> dict:
    """Получить информацию о release.

    Если tag пустой — берём latest, иначе фиксированный release/tags/<tag>.
    transport — через что идти к GitHub API (см. core/download_transport);
    без него у пользователя с заблокированным GitHub список релизов не
    загрузится, хотя туннель для этого уже поднят.
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

    from core.download_transport import urlopen_via

    for attempt in range(max_attempts):
        try:
            with urlopen_via(url, transport=transport, timeout=HTTP_TIMEOUT,
                             headers=headers) as r:
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


def github_release_by_prefix(repo: str, prefix: str,
                             transport: str = "") -> dict:
    """Самый свежий релиз, чей тэг начинается с prefix.

    В одном репозитории живут релизы GUI и наши сборки бинарников
    (usque-bin-*, singbox-bin-*, awg-bin-*), поэтому `latest` тут не
    годится — он вернёт релиз самого GUI.
    """
    url = "https://api.github.com/repos/%s/releases?per_page=50" % repo
    headers = {"Accept": "application/vnd.github.v3+json",
               "User-Agent": "zapret-gui/ext-installer"}
    try:
        from core.config_manager import get_config_manager
        token = (get_config_manager().get("github", "token",
                                          default="") or "").strip()
        if token:
            headers["Authorization"] = "token %s" % token
    except Exception:
        pass
    try:
        from core.binary_installer import resolve_url
        from core.download_transport import urlopen_via
        with urlopen_via(resolve_url(url), transport=transport,
                         timeout=HTTP_TIMEOUT, headers=headers) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"error_detail": "GitHub API недоступен: %s" % e}
    if not isinstance(data, list):
        return {"error_detail": "Некорректный ответ GitHub releases"}
    for rel in data:
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        if (rel.get("tag_name") or "").startswith(prefix):
            return rel
    return {"error_detail": "В репозитории %s нет релиза с префиксом %s"
                            % (repo, prefix)}


def _manifest_entry(release: dict, cfg: dict, arch: str,
                    transport: str = "") -> dict:
    """Запись об этой архитектуре из manifest.json релиза.

    Возвращает {} — значит манифеста/записи нет и ставить по нему нельзя
    (вызывающий уходит на legacy_source). Хэши наших сборок известны
    только после сборки, поэтому в манифесте их и держим.
    """
    asset_name = cfg.get("manifest_asset") or ""
    if not asset_name:
        return {}
    url = ""
    for asset in (release.get("assets") or []):
        if asset.get("name") == asset_name:
            url = asset.get("browser_download_url", "")
            break
    if not url:
        return {}
    try:
        from core.binary_installer import resolve_url
        from core.download_transport import urlopen_via
        with urlopen_via(resolve_url(url), transport=transport,
                         timeout=HTTP_TIMEOUT,
                         headers={"User-Agent": "zapret-gui/ext-installer"}) as r:
            manifest = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        log.warning("ext_installer: не удалось прочитать %s: %s"
                    % (asset_name, e), source="ext_installer")
        return {}
    section = manifest.get(cfg.get("manifest_section") or "", {})
    entry = ((section.get("binaries") or {}).get(arch) or {})
    if not entry.get("url") or not entry.get("sha256"):
        return {}
    entry = dict(entry)
    entry["version"] = section.get("version", "")
    return entry


def github_download_url(repo: str, tag: str, filename: str) -> str:
    """Сформировать URL для скачивания asset'а."""
    return ("https://github.com/%s/releases/download/%s/%s"
            % (repo, tag, filename))


# ─────── Скачивание и установка ───────

def download_file(url: str, dest: str, timeout: int = DOWNLOAD_TIMEOUT,
                  transport: str = "") -> bool:
    """Скачать файл по URL с поддержкой докачки (resume).

    transport — через что качать (см. core/download_transport): у
    пользователя с заблокированным GitHub единственный рабочий путь —
    уже поднятый туннель.
    """
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
            req_ctx = urlopen_via(resolved_url, transport=transport,
                                  timeout=timeout, headers=headers)
        except Exception as e:
            if "Range" in headers:
                log.warning("download_file: Range request failed, retrying from scratch: %s" % e, source="ext_installer")
                if os.path.exists(part_file):
                    try:
                        os.remove(part_file)
                    except OSError:
                        pass
                headers.pop("Range")
                req_ctx = urlopen_via(resolved_url, transport=transport,
                                  timeout=timeout, headers=headers)
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


# ─────── проверка «а это вообще запустится?» ───────
#
# Мотив: пользователь получал всплывающее «[Errno 8] Exec format error:
# '/opt/usr/bin/usque'» — рабочий бинарник был затёрт файлом, который ядро
# отказывается исполнять (архив вместо ELF, сборка под другой порядок байт,
# битая упаковка). Установщик рапортовал успех, потому что не проверял
# НИЧЕГО, кроме факта записи файла. Проверяем в два шага: сначала дёшево по
# заголовку (без exec — работает и для чужой архитектуры), затем реальным
# запуском там, где это возможно.

# Сигнатуры не-ELF файлов, которые чаще всего приезжают вместо бинарника.
_MAGIC_HINTS = (
    (b"\x1f\x8b",      "это gzip-архив (.gz), а не бинарник — его нужно"
                       " распаковать"),
    (b"BZh",           "это bzip2-архив, а не бинарник"),
    (b"\xfd7zXZ\x00",  "это xz-архив, а не бинарник"),
    (b"PK\x03\x04",    "это zip-архив, а не бинарник"),
    (b"!<arch>",       "это ar-архив (.ipk/.deb), а не бинарник — такой"
                       " файл ставится пакетным менеджером"),
    (b"<!DOCTYPE",     "это HTML-страница (скачалась ошибка сервера, а не"
                       " файл)"),
    (b"<html",         "это HTML-страница (скачалась ошибка сервера, а не"
                       " файл)"),
)

# e_machine → архитектуры, на которых такой ELF исполним.
_ELF_MACHINES = {
    0x08: "mips",       # MIPS (порядок байт различаем по EI_DATA)
    0x28: "armv7",
    0xB7: "aarch64",
    0x3E: "x86_64",
}


def _host_bits() -> int:
    """Разрядность системы (по интерпретатору — он собран под неё же)."""
    import sys
    return 64 if sys.maxsize > 2 ** 32 else 32


def _elf_arch(path: str):
    """
    (arch, error): что за файл лежит по пути.

    arch — наше имя архитектуры ('mipsel'/'mips'/'aarch64'/'armv7'/
    'x86_64') либо '' если распознать не удалось. error — человеческое
    объяснение, если файл заведомо не исполняемый.

    Разрядность (EI_CLASS) проверяется отдельно от e_machine: 64-битная
    сборка на 32-битном роутере — самый частый способ получить «Exec
    format error», и ловить её нужно даже когда e_machine нам незнаком
    (mips64el, riscv и прочее, чего нет в таблице).
    """
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError as e:
        return "", "файл не читается: %s" % e

    if not head:
        return "", "файл пустой (0 байт) — закачка оборвалась"
    if head[:2] == b"#!":
        return "", ""                     # скрипт — не наше дело, пропускаем
    if head[:4] != b"\x7fELF":
        for magic, hint in _MAGIC_HINTS:
            if head.startswith(magic):
                return "", hint
        return "", "файл не является исполняемым (нет сигнатуры ELF)"

    if len(head) < 20:
        return "", "ELF-заголовок обрезан — файл повреждён"

    bits = 64 if head[4] == 2 else 32     # EI_CLASS: 1 = 32-bit, 2 = 64-bit
    host_bits = _host_bits()
    if bits != host_bits:
        return "", ("%d-битная сборка, а система %d-битная"
                    % (bits, host_bits))

    little = head[5] == 1                 # EI_DATA: 1 = LSB, 2 = MSB
    machine = (head[18] | (head[19] << 8)) if little \
        else (head[19] | (head[18] << 8))
    arch = _ELF_MACHINES.get(machine, "")
    if arch == "mips":
        arch = "mipsel" if little else "mips"
    return arch, ""


def verify_installed_binary(path: str, probe_args=("version", "--version",
                                                   "--help")) -> dict:
    """
    Проверить, что установленный файл реально исполняется на этой машине.

    Возвращает {"ok": bool, "error": str}. Ненулевой код возврата ошибкой
    НЕ считается: многие программы отвечают rc=1 на неизвестный аргумент,
    а нам важно ровно одно — соглашается ли ядро запустить файл.
    """
    arch, err = _elf_arch(path)
    if err:
        return {"ok": False, "error": err}

    host = detect_arch()
    if arch and host and arch != host:
        # mipsel-роутер и mips-сборка внешне неотличимы (`uname -m` на обоих
        # даёт "mips") — именно на этом ловились «Exec format error».
        return {"ok": False,
                "error": "сборка под %s, а система — %s" % (arch, host)}

    import errno as _errno
    fatal = {_errno.ENOEXEC, _errno.ELIBBAD, _errno.EACCES, _errno.EPERM}
    last = ""
    for arg in probe_args:
        try:
            subprocess.run([path, arg], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=15)
            return {"ok": True, "error": ""}
        except OSError as e:
            if e.errno in fatal:
                return {"ok": False,
                        "error": "не запускается: %s" % e.strerror}
            last = str(e)
        except subprocess.SubprocessError as e:
            # Таймаут/зависание на --help — файл исполнился, значит формат
            # верный; это всё, что мы здесь проверяем.
            last = str(e)
            return {"ok": True, "error": ""}
    return {"ok": True, "error": last}


# ─────── Конкретные установщики ───────

# Конфигурация каждого бинарника
BINARIES = {
    # tg-ws-proxy ЗАКРЕПЛЁН на 0.9.3 — и это вынужденно.
    #
    # Раньше здесь стоял `release_tag: ""` («ставить последний релиз»), и это
    # было правильно, пока апстрим оставался роутерным демоном. Но в v1.0.0
    # spatiumstas/tg-ws-proxy-go переписан с Go на Python и превращён в
    # ДЕСКТОПНОЕ GUI-приложение: сборка через PyInstaller под Windows/macOS/
    # Linux. Роутерной упаковки там больше нет вообще — в 0.9.3 её 52 файла
    # (Makefile, common/ipk/*, init.d), начиная с v1.0.0 — ноль, и релизы
    # несут .exe вместо `tg-ws-proxy_<ver>_entware_<arch>.ipk`.
    #
    # С пустым release_tag установка ходила в /releases/latest, не находила
    # ни точного имени ассета, ни версионно-независимого суффикса, и падала
    # на 404 — то есть движок Telegram просто не ставился. Поэтому тег
    # закреплён на последнем релизе, который реально содержит пакеты для
    # роутера. Показывать пользователю v1.4.0 как «доступно обновление» тоже
    # неверно: это программа для другой платформы.
    #
    # Отменять закрепление можно только вместе с переездом на новый источник
    # (другой форк или своя сборка) — см. docs/upstream.json, запись
    # tg-ws-proxy-go с полем `hold`.
    "tgwsproxy": {
        "repo": "spatiumstas/tg-ws-proxy-go",
        "release_tag": "0.9.3",
        "pinned_tag": "0.9.3",
        "allow_unpinned": True,
        "install_kind": "package",
        "package_name": "tg-ws-proxy",
        "dest": "/opt/bin/tg-ws-proxy",
        # Пакет кладёт init-скрипт — он же маркер установки для
        # get_install_status (бинарник может лежать не в dest).
        "status_file": "/opt/etc/init.d/S99tg-ws-proxy",
        "arch_map": {
            "aarch64": "tg-ws-proxy_0.9.3-1_entware_aarch64-3.10.ipk",
            "armv7": "tg-ws-proxy_0.9.3-1_entware_armv7-3.2.ipk",
            "mips": "tg-ws-proxy_0.9.3-1_entware_mips-3.4.ipk",
            "mipsel": "tg-ws-proxy_0.9.3-1_entware_mipsel-3.4.ipk",
        },
        "package_assets": {
            "opkg": {
                "aarch64": "tg-ws-proxy_0.9.3-1_entware_aarch64-3.10.ipk",
                "armv7": "tg-ws-proxy_0.9.3-1_entware_armv7-3.2.ipk",
                "mips": "tg-ws-proxy_0.9.3-1_entware_mips-3.4.ipk",
                "mipsel": "tg-ws-proxy_0.9.3-1_entware_mipsel-3.4.ipk",
            },
            # Ключи apk — ТАРГЕТЫ OpenWrt (DISTRIB_ARCH), а не семейства
            # из `uname -m`: apk сверяет арку пакета со своей, а
            # arm_cortex-a7 и arm_cortex-a9 по `uname -m` неразличимы
            # (оба armv7l). Семейные ключи (aarch64/mips/mipsel) оставлены
            # как запасные — на случай, если DISTRIB_ARCH не прочитался.
            # x86_64 не было вовсе, хотя апстрим его собирает
            # (config/openwrt/x86_64.config) — issue #280.
            "apk": {
                "x86_64": "tg-ws-proxy_0.9.3-r1_openwrt_x86_64.apk",
                "aarch64_generic": "tg-ws-proxy_0.9.3-r1_openwrt_aarch64_generic.apk",
                "arm_cortex-a7": "tg-ws-proxy_0.9.3-r1_openwrt_arm_cortex-a7.apk",
                "arm_cortex-a9": "tg-ws-proxy_0.9.3-r1_openwrt_arm_cortex-a9.apk",
                "mips_24kc": "tg-ws-proxy_0.9.3-r1_openwrt_mips_24kc.apk",
                "mipsel_24kc": "tg-ws-proxy_0.9.3-r1_openwrt_mipsel_24kc.apk",
                "aarch64": "tg-ws-proxy_0.9.3-r1_openwrt_aarch64_generic.apk",
                "mips": "tg-ws-proxy_0.9.3-r1_openwrt_mips_24kc.apk",
                "mipsel": "tg-ws-proxy_0.9.3-r1_openwrt_mipsel_24kc.apk",
            },
        },
        # Версионно-независимый «хвост» имени ассета: меняется только
        # версия и ревизия сборки, платформа с архитектурой — нет.
        "package_asset_suffixes": {
            "opkg": {
                "aarch64": "_entware_aarch64-3.10.ipk",
                "armv7": "_entware_armv7-3.2.ipk",
                "mips": "_entware_mips-3.4.ipk",
                "mipsel": "_entware_mipsel-3.4.ipk",
            },
            "apk": {
                "x86_64": "_openwrt_x86_64.apk",
                "aarch64_generic": "_openwrt_aarch64_generic.apk",
                "arm_cortex-a7": "_openwrt_arm_cortex-a7.apk",
                "arm_cortex-a9": "_openwrt_arm_cortex-a9.apk",
                "mips_24kc": "_openwrt_mips_24kc.apk",
                "mipsel_24kc": "_openwrt_mipsel_24kc.apk",
                "aarch64": "_openwrt_aarch64_generic.apk",
                "mips": "_openwrt_mips_24kc.apk",
                "mipsel": "_openwrt_mipsel_24kc.apk",
            },
        },
        # sha256 сборок 0.9.3 (посчитаны с релизных URL; процедура
        # сверена — пересчитанные тем же способом хэши 0.9.2 совпали со
        # всеми значениями прежнего манифеста).
        "sha256_map": {
            "opkg:aarch64": "8ab049572108028a57dccab166102fee248f5e8ba486d8d8d1fdd9bdb4941a53",
            "opkg:armv7": "91428498cc8b426ba4b3e93dd7be03355ae26d0878692b585b66b1e9a0f37989",
            "opkg:mips": "63f004c00f530cc5c574860cb4a4e04110cd54957a23e6ef38d188bb667aee26",
            "opkg:mipsel": "dc86818e78b7bf3c58e39f032b402ca2ebd9dec1a4f1989fa4f8ace258c765b4",
            "apk:x86_64": "1423a6ba454d6721827b7e318acec2109979d90db2c7744ab1a0305b614a836c",
            "apk:aarch64_generic": "e205d4ad04364bda82f2991deabf94ebca2c8355018cd620980461a01a3da003",
            "apk:arm_cortex-a7": "564c2090c0f746af8c92be21e08910bd2f2d7f51d93b99863c943308ad13df73",
            "apk:arm_cortex-a9": "4543b04bd457dc7540c42ca69f1bbcff289b820e900e4341ffee36300a471555",
            "apk:mips_24kc": "354fcfd8b1eae2f88d7429539de7f0ca6a1b8caa3ea8e49597240ab2bf051321",
            "apk:mipsel_24kc": "0c152081f04a27e40f4cfb0be082308c6700db1110dba8834f913202510c5774",
            "apk:aarch64": "e205d4ad04364bda82f2991deabf94ebca2c8355018cd620980461a01a3da003",
            "apk:mips": "354fcfd8b1eae2f88d7429539de7f0ca6a1b8caa3ea8e49597240ab2bf051321",
            "apk:mipsel": "0c152081f04a27e40f4cfb0be082308c6700db1110dba8834f913202510c5774",
        },
    },

    # usque собираем сами (.github/workflows/build-usque-binaries.yml) —
    # как amneziawg-go и sing-box. Причины перехода со стороннего .ipk:
    #   * usque-keenetic отстаёт от самого usque (в v0.3.0 лежал 4.2.0,
    #     когда апстрим уже выпустил 4.2.1) — версией управляем сами;
    #   * в его .ipk НЕТ x86_64, поэтому на Linux-ПК/VPS usque было не
    #     поставить вообще, хотя сам GUI там работает;
    #   * .ipk требует opkg/apk, а сырой бинарник ставится всюду;
    #   * на одну стороннюю зависимость в цепочке поставки меньше.
    # sha256 берём не из этого файла, а из manifest.json релиза
    # (manifest_asset): хэши каждой сборки известны только после неё, но
    # проверка при этом остаётся обязательной и fail-closed.
    "usque": {
        "repo": "avatarDD/zapret-gui",
        "release_tag": "",          # последний usque-bin-*
        "release_prefix": "usque-bin-",
        "manifest_asset": "manifest.json",
        "manifest_section": "usque",
        "install_kind": "binary",
        "dest": "/opt/usr/bin/usque",
        # Чем проверять, что поставленный файл вообще исполняется:
        # у usque это подкоманда `version` (флага --version нет).
        "version_args": ("version",),
        # Имена ассетов версионные (usque-<ver>-<arch>.gz), поэтому здесь
        # только суффиксы: точный файл берётся из манифеста релиза.
        "arch_map": {
            "aarch64": "aarch64",
            "mipsel": "mipsel-softfloat",
            "mips": "mips-softfloat",
            "armv7": "armv7",
            "x86_64": "x86_64",
        },
        "legacy_source": {
            # Запасной путь, пока не опубликован первый usque-bin-*
            # релиз (и на случай, если наша сборка почему-то недоступна).
            "repo": "side-effect-tm/usque-keenetic",
            "release_tag": "v0.3.0",
            "install_kind": "package",
            "package_name": "usque-keenetic",
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
    },

    # tg-mtproxy-client (резервный движок Telegram) собираем сами —
    # .github/workflows/build-tgproto-binaries.yml. Причины:
    #   * у апстрима в релизных ассетах НЕТ aarch64 и armv7 — на массовых
    #     aarch64-Keenetic резервный движок было не поставить вообще;
    #   * ассеты лежат под ROLLING-тэгом (z2k-classify-rolling) и могут
    #     перезаливаться, а закреплённые sha256 при этом протухают:
    #     установка начала бы падать на несовпадении хэша.
    # Секрет туннеля в нашу сборку не зашит и не нужен: менеджер всегда
    # передаёт --tunnel-url и --tunnel-secret явно (core/tgproxy_manager).
    "tgproto": {
        "repo": "avatarDD/zapret-gui",
        "release_tag": "",          # последний tgproto-bin-*
        "release_prefix": "tgproto-bin-",
        "manifest_asset": "manifest.json",
        "manifest_section": "tgproto",
        "install_kind": "binary",
        "dest": "/opt/sbin/tg-mtproxy-client",
        "arch_map": {
            "aarch64": "aarch64",
            "armv7": "armv7",
            "mipsel": "mipsel-softfloat",
            "mips": "mips-softfloat",
            "x86_64": "x86_64",
        },
        "legacy_source": {
            # Прежний источник — на случай, если наша сборка недоступна.
            # Здесь по-прежнему нет aarch64/armv7, это и чинилось.
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
    },
    # opera-proxy собираем сами — .github/workflows/build-opera-binaries.yml.
    # Апстрим релизится раз в 1–2 недели, поэтому здесь стоял allow_unpinned:
    # ставился ПОСЛЕДНИЙ релиз, а закреплённый sha256 относился к более
    # старой pinned-версии. На практике почти каждая установка шла по
    # «мягкому» пути — без сверки хэша, если апстрим не публиковал
    # контрольные суммы. Своя сборка + manifest.json возвращают строгую
    # проверку, не теряя «всегда последняя версия».
    "opera": {
        "repo": "avatarDD/zapret-gui",
        "release_tag": "",          # последний opera-bin-*
        "release_prefix": "opera-bin-",
        "manifest_asset": "manifest.json",
        "manifest_section": "opera",
        "install_kind": "binary",
        "dest": "/opt/usr/bin/opera-proxy",
        "arch_map": {
            "aarch64": "aarch64",
            "armv7": "armv7",
            "mipsel": "mipsel-softfloat",
            "mips": "mips-softfloat",
            "x86_64": "x86_64",
        },
        "legacy_source": {
            "repo": "Alexey71/opera-proxy",
            "release_tag": "",
            "pinned_tag": "v1.28.0",
            "allow_unpinned": True,
            "dest": "/opt/usr/bin/opera-proxy",
            "arch_map": {
                "aarch64": "opera-proxy.linux-arm64",
                "x86_64": "opera-proxy.linux-amd64",
                "mipsel": "opera-proxy.linux-mipsle",
                "mips": "opera-proxy.linux-mips",
                # armv7 у апстрима есть (ELF ARM EABI5, статическая
                # сборка) — без этой строки установка на armv7-роутерах
                # отказывала «архитектура не поддерживается», хотя
                # бинарник опубликован.
                "armv7": "opera-proxy.linux-arm",
            },
            # sha256 сборок v1.28.0 (посчитаны с релизных URL; процедура
            # сверена — хэши v1.27.0, посчитанные так же, совпали с
            # прежним манифестом).
            "sha256_map": {
                "aarch64": "9f34d6bcd0c12ccc9a1e13cf5fa630098d6c52cf8b68d9e7e1c17a58f04a9e94",
                "x86_64": "19cdb8f80dfae56cb0be2c5a2e228f48a7ab2a6a0d382bdef29a7afe7e918227",
                "mipsel": "179826987cd1861836b21bf49dc1674e9efb94c142fb4a2bcc2599f909ec1f41",
                "mips": "3c0a1dab4fefd95b3c232e3df81bbb9bbb7a191e6a3e5a6da7adb567df52edcf",
                "armv7": "bfecc0c667f76e3ce62404ec4847040c9f7a14169deb2d3f7558f9e0a751b394",
            },
        },
    },
}


def _same_tag(a: str, b: str) -> bool:
    """Сравнение тегов без учёта ведущего v/V (`v1.28.0` == `1.28.0`)."""
    return (a or "").strip().lstrip("vV") == (b or "").strip().lstrip("vV")


def _pkg_version_matches_tag(pkg_version: str, tag: str) -> bool:
    """Версия установленного ПАКЕТА против тега релиза.

    opkg/apk хранят версию вместе с ревизией сборки (`0.9.3-1`, `0.9.3-r1`),
    а тег релиза — без неё (`0.9.3`). Прямое сравнение всегда давало
    «не совпало», и «Установить» каждый раз качало и переустанавливало
    пакет, который уже стоит.
    """
    pkg_version = (pkg_version or "").strip().lstrip("vV")
    tag = (tag or "").strip().lstrip("vV")
    if not pkg_version or not tag:
        return False
    if pkg_version == tag:
        return True
    # Отрезаем ревизию сборки: "0.9.3-1" / "0.9.3-r1" → "0.9.3".
    return pkg_version.split("-", 1)[0] == tag.split("-", 1)[0]


def _asset_suffix_for(cfg: dict, arch: str, pkg_mgr: str = "") -> str:
    """Версионно-независимый суффикс имени ассета (или "")."""
    suffixes = cfg.get("package_asset_suffixes") or {}
    if not suffixes:
        return ""
    by_mgr = suffixes.get(pkg_mgr) or suffixes.get("opkg") or {}
    return _pick_by_arch(by_mgr, arch, pkg_mgr)

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
        # status_file — платформенный маркер установки пакета (init-скрипт
        # у tg-ws-proxy); для остальных пакетов (usque) — сам бинарник dest.
        status_file = cfg.get("status_file") or cfg.get("dest", "")
        installed = bool(version) or (
            bool(status_file) and os.path.isfile(status_file))
        binary = status_file
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


def get_installability(name: str) -> dict:
    """Есть ли в манифесте сборка под эту машину — БЕЗ запуска бинарника.

    get_install_status() для «сырых» бинарников зовёт _get_version(), то
    есть ЗАПУСКАЕТ файл. Для tg-mtproxy-client это означало бы поднимать
    прокси на каждый опрос /api/tgproxy/detect, поэтому здесь только
    манифест и `uname -m`.

    Нужно, чтобы GUI показывал «нет сборки под вашу архитектуру» ДО
    нажатия «Установить», а не отдавал кнопку, которая всегда падает.
    """
    cfg = BINARIES.get(name)
    if not cfg:
        return {"installable": False, "arch": "", "supported_archs": []}

    install_kind = cfg.get("install_kind", "binary")
    arch = detect_arch()
    pkg_mgr = _package_manager() if install_kind == "package" else ""

    if install_kind == "package" and (cfg.get("package_assets") or {}):
        by_mgr = (cfg["package_assets"].get(pkg_mgr)
                  or cfg["package_assets"].get("opkg") or {})
        supported = _distinct_archs(by_mgr)
    else:
        supported = sorted((cfg.get("arch_map") or {}).keys())

    # Показываем ту арку, по которой реально шёл выбор: на apk это таргет
    # OpenWrt (x86_64 / arm_cortex-a7), а не семейство из `uname -m`.
    keys = _arch_keys(arch, pkg_mgr)
    return {
        "installable": bool(_resolve_asset_name(cfg, arch, pkg_mgr)),
        "arch": keys[0] if keys else arch,
        "supported_archs": supported,
        "repo": cfg.get("repo", ""),
    }


def _distinct_archs(by_arch: dict) -> list:
    """Список архитектур без синонимов, ведущих на один и тот же ассет.

    В манифесте один ассет может лежать под таргетом OpenWrt
    (`aarch64_generic`) и под семейным алиасом (`aarch64`) — в UI это
    один и тот же вариант, дважды его перечислять незачем.
    """
    seen = {}
    for arch_key, asset in sorted((by_arch or {}).items()):
        seen.setdefault(asset, arch_key)
    return sorted(seen.values())


def _pick_by_arch(table: dict, arch: str, pkg_mgr: str = "") -> str:
    """Значение из {арка: значение} по ключам от точного к общему."""
    for key in _arch_keys(arch, pkg_mgr):
        val = (table or {}).get(key)
        if val:
            return val
    return ""


def _resolve_asset_name(cfg: dict, arch: str, pkg_mgr: str = "") -> str:
    """Получить asset для выбранного типа установки."""
    if cfg.get("install_kind", "binary") == "package":
        package_assets = cfg.get("package_assets", {}) or {}
        if package_assets:
            if pkg_mgr and pkg_mgr in package_assets:
                return _pick_by_arch(package_assets.get(pkg_mgr), arch, pkg_mgr)
            return _pick_by_arch(package_assets.get("opkg"), arch, "opkg")
        # Пакеты без раздельного package_assets (usque): единый набор .ipk
        # по архитектурам лежит в arch_map — используем его.
        return _pick_by_arch(cfg.get("arch_map"), arch, pkg_mgr)
    return (cfg.get("arch_map", {}) or {}).get(arch, "")


def _expected_sha256(cfg: dict, arch: str, pkg_mgr: str = "") -> str:
    """Получить ожидаемый sha256 из встроенного манифеста."""
    sha_map = cfg.get("sha256_map", {}) or {}
    if pkg_mgr:
        for key in _arch_keys(arch, pkg_mgr):
            val = sha_map.get("%s:%s" % (pkg_mgr, key))
            if val:
                return val
    return _pick_by_arch(sha_map, arch, pkg_mgr)


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


def list_releases(name: str, transport: str = "", force: bool = False,
                  limit: int = 30) -> dict:
    """Релизы репозитория бинарника — для выбора версии в UI.

    Тот же контракт, что у singbox/mihomo-установщиков: SetupUI ждёт
    {"ok", "releases": [{tag, published_at, prerelease}]}. Кэш на 5 минут,
    чтобы перерисовка страницы не била по rate-limit GitHub API.
    """
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник: %s" % name}

    now = time.time()
    key = (name, transport)
    with _releases_lock:
        cached = _releases_cache.get(key)
        if cached and not force and (now - cached[0]) < 300:
            return cached[1]

    limit = max(1, min(int(limit or 30), 100))
    url = "https://api.github.com/repos/%s/releases?per_page=%d" % (
        cfg["repo"], limit)
    try:
        from core.binary_installer import resolve_url
        from core.download_transport import urlopen_via
        headers = {"Accept": "application/vnd.github.v3+json",
                   "User-Agent": "zapret-gui/ext-installer"}
        try:
            from core.config_manager import get_config_manager
            token = (get_config_manager().get("github", "token",
                                              default="") or "").strip()
            if token:
                headers["Authorization"] = "token %s" % token
        except Exception:
            pass
        with urlopen_via(resolve_url(url), transport=transport,
                         timeout=HTTP_TIMEOUT, headers=headers) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"ok": False, "error": "GitHub API недоступен: %s" % e}

    if not isinstance(data, list):
        return {"ok": False,
                "error": "Некорректный ответ GitHub releases (не список)"}

    # Наши сборки бинарников живут в одном репозитории с релизами самого
    # GUI, поэтому без фильтра по префиксу в выборе версии usque
    # оказались бы версии GUI (v0.24.0 и т.п.).
    prefix = cfg.get("release_prefix") or ""
    releases = []
    for rel in data:
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        tag = rel.get("tag_name") or ""
        if not tag or (prefix and not tag.startswith(prefix)):
            continue
        releases.append({
            "tag": tag,
            "published_at": rel.get("published_at") or "",
            "prerelease": bool(rel.get("prerelease")),
        })

    out = {"ok": True, "releases": releases,
           "pinned": cfg.get("release_tag", "")}
    with _releases_lock:
        _releases_cache[key] = (now, out)
    return out


def install_local_file(name: str, path: str, orig_name: str = "") -> dict:
    """Установить бинарник/пакет из ЛОКАЛЬНОГО файла.

    Путь «GitHub недоступен вообще»: пользователь скачивает .ipk на
    телефоне и загружает через форму. Проверять sha256 тут не с чем и
    незачем — файл принёс сам администратор роутера; но и молчать об
    этом не будем, отдаём warning.
    """
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник: %s" % name}
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "Файл не найден"}

    install_kind = cfg.get("install_kind", "binary")
    warning = ("Файл установлен как есть: контрольная сумма не сверялась"
               " (для загруженного вручную файла её не с чем сравнивать)")

    if install_kind == "package":
        pkg_mgr = _package_manager()
        if not pkg_mgr:
            return {"ok": False,
                    "error": "Не найден opkg/apk для установки пакета"}
        # opkg/apk определяют формат по расширению — временный файл от
        # загрузчика называется upload.bin, поэтому кладём рядом копию с
        # правильным именем.
        suffix = ".apk" if pkg_mgr == "apk" else ".ipk"
        if orig_name and orig_name.lower().endswith((".ipk", ".apk")):
            suffix = os.path.splitext(orig_name)[1].lower()
        pkg_path = os.path.join(os.path.dirname(path),
                                "%s%s" % (cfg.get("package_name", name),
                                          suffix))
        try:
            if pkg_path != path:
                shutil.copyfile(path, pkg_path)
        except OSError as e:
            return {"ok": False, "error": "Подготовка файла: %s" % e}

        if pkg_mgr == "apk":
            install_cmd = [pkg_mgr, "add", "--allow-untrusted", pkg_path]
        else:
            install_cmd = [pkg_mgr, "install", "--force-reinstall", pkg_path]
        try:
            proc = subprocess.run(install_cmd, capture_output=True,
                                  text=True, timeout=600)
        except (subprocess.SubprocessError, OSError) as e:
            return {"ok": False, "error": "Установка пакета: %s" % e}
        if proc.returncode != 0:
            return {"ok": False,
                    "error": "Установка пакета не удалась: %s"
                             % ((proc.stderr or proc.stdout or "").strip())}
        version = _pkg_version(cfg.get("package_name", "")) or ""
        log.info("ext_installer: %s установлен из локального файла %s"
                 % (name, orig_name or path), source="ext_installer")
        return {"ok": True, "version": version, "sha256_verified": False,
                "binary": cfg.get("dest", ""), "warning": warning}

    dest = cfg.get("dest", "")
    if not dest:
        return {"ok": False, "error": "Не задан путь установки"}

    # Ассеты наших релизов лежат сжатыми (`usque-<ver>-<arch>.gz`,
    # `amneziawg-go-<ver>-<arch>.tar.gz`), и именно их пользователь
    # скачивает на телефоне, когда GitHub с роутера недоступен. Раньше
    # такой файл копировался на место бинарника КАК ЕСТЬ — получался
    # исполняемый архив и «[Errno 8] Exec format error» при запуске.
    # Имя из формы (orig_name) надёжнее временного upload.bin.
    staged_name = orig_name or os.path.basename(path)
    upload = path
    made_copy = False
    for ext in (".tar.gz", ".tgz", ".gz"):
        if staged_name.lower().endswith(ext) and not path.endswith(ext):
            upload = path + ext
            try:
                shutil.copyfile(path, upload)
                made_copy = True
            except OSError as e:
                return {"ok": False, "error": "Подготовка файла: %s" % e}
            break

    try:
        res = _install_binary_file(cfg, upload)
    finally:
        if made_copy:
            try:
                os.unlink(upload)
            except OSError:
                pass
    if not res.get("ok"):
        return res

    log.info("ext_installer: %s установлен из локального файла %s"
             % (name, orig_name or path), source="ext_installer")
    return {"ok": True, "binary": dest, "version": _get_version(dest),
            "sha256_verified": False, "warning": warning}


def _install_from_manifest(name: str, cfg: dict, arch: str, progress_cb,
                           transport: str, tag: str = ""):
    """Установка нашей сборки по manifest.json релиза.

    None — манифест/сборка под эту архитектуру недоступны; вызывающий
    уходит на legacy_source. dict — окончательный результат.
    """
    if progress_cb:
        progress_cb("fetch", 10, "Поиск релиза...")
    if tag:
        release = github_release(cfg["repo"], tag, transport=transport)
    else:
        release = github_release_by_prefix(cfg["repo"], cfg["release_prefix"],
                                           transport=transport)
    if not release or "error_detail" in release:
        log.warning("ext_installer: %s — релиз %s не найден: %s"
                    % (name, tag or (cfg["release_prefix"] + "*"),
                       (release or {}).get("error_detail", "?")),
                    source="ext_installer")
        return None

    entry = _manifest_entry(release, cfg, arch, transport=transport)
    if not entry:
        log.warning("ext_installer: %s — в манифесте релиза %s нет сборки для"
                    " %s" % (name, release.get("tag_name", "?"), arch),
                    source="ext_installer")
        return None

    tag = release.get("tag_name", "")
    filename = entry.get("filename") or os.path.basename(entry["url"])
    suffix = ".tar.gz" if filename.endswith(".tar.gz") \
        else (os.path.splitext(filename)[1] or ".bin")
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp_path = tmp.name

    try:
        if progress_cb:
            progress_cb("download", 30, "Скачивание %s..." % filename)
        if not download_file(entry["url"], tmp_path, transport=transport):
            return {"ok": False, "error": "Не удалось скачать %s" % filename}

        if progress_cb:
            progress_cb("download", 60, "Проверка контрольной суммы...")
        actual = _sha256_file(tmp_path)
        if actual.lower() != str(entry["sha256"]).lower():
            # Fail-closed: расхождение хэша — это либо подмена, либо битая
            # загрузка; в обоих случаях ставить нельзя.
            return {"ok": False,
                    "error": "SHA256 не совпал для %s (ожидался %s, получен %s)"
                             % (filename, entry["sha256"][:16], actual[:16])}

        if progress_cb:
            progress_cb("install", 80, "Установка...")
        res = _install_binary_file(cfg, tmp_path)
        if res.get("exec_error"):
            # Наша сборка под эту архитектуру не исполняется. Ведём себя
            # так же, как при её отсутствии: None → вызывающий уходит на
            # legacy_source. Иначе единственным выходом остаётся SSH.
            log.warning("ext_installer: %s — сборка из релиза %s не"
                        " запускается, пробую запасной источник: %s"
                        % (name, tag, res.get("error")),
                        source="ext_installer")
            return None
        if not res.get("ok"):
            return res

        if progress_cb:
            progress_cb("done", 100, "Установлено: %s" % tag)
        log.info("ext_installer: %s %s установлен из нашей сборки (%s)"
                 % (name, entry.get("version") or tag, arch),
                 source="ext_installer")
        return {"ok": True, "binary": cfg["dest"], "tag": tag,
                "version": entry.get("version") or tag,
                "sha256_verified": True, "sha256_pinned": True}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _unpack_if_needed(path: str) -> tuple:
    """
    (путь_к_бинарнику, временный_ли, ошибка) — распаковать .gz/.tar.gz.

    Порядок проверок важен: '.tar.gz' тоже оканчивается на '.gz', и если
    сначала спросить про '.gz', тарбол «распакуется» в сам tar-архив,
    который потом ляжет на место бинарника (и получится ровно тот самый
    «Exec format error»).
    """
    if path.endswith(".tar.gz") or path.endswith(".tgz"):
        import tarfile
        extract_dir = tempfile.mkdtemp()
        try:
            with tarfile.open(path, "r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or member.name.startswith("."):
                        continue
                    member_path = os.path.realpath(
                        os.path.join(extract_dir, member.name))
                    if not member_path.startswith(
                            os.path.realpath(extract_dir) + os.sep):
                        continue        # zip-slip
                    tar.extract(member, extract_dir)
                    return member_path, True, ""
        except (OSError, tarfile.TarError) as e:
            return "", False, "Распаковка архива: %s" % e
        return "", False, "В архиве нет файлов"

    if path.endswith(".gz"):
        import gzip
        out = path + ".bin"
        try:
            with gzip.open(path, "rb") as f_in, open(out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        except (OSError, EOFError) as e:
            return "", False, "Распаковка: %s" % e
        return out, True, ""

    return path, False, ""


def _install_binary_file(cfg: dict, tmp_path: str) -> dict:
    """Распаковать (если нужно) и положить бинарник в cfg['dest'].

    Перед заменой сохраняем прежний бинарник, после — проверяем, что новый
    вообще исполняется. Не исполняется — откатываемся: пользователь
    остаётся с рабочей версией, а не с файлом, на котором всё падает с
    «Exec format error».
    """
    dest = cfg["dest"]
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
    except OSError as e:
        return {"ok": False, "error": "Каталог %s: %s"
                                      % (os.path.dirname(dest), e)}

    src, tmp_made, err = _unpack_if_needed(tmp_path)
    if err:
        return {"ok": False, "error": err}

    backup = dest + ".prev"
    had_backup = False
    try:
        if os.path.isfile(dest):
            shutil.copyfile(dest, backup)
            shutil.copystat(dest, backup)
            had_backup = True
    except OSError:
        had_backup = False

    try:
        # Через временный файл рядом с целью + os.replace: иначе при
        # обрыве на месте рабочего бинарника остаётся огрызок.
        staged = dest + ".new"
        shutil.copyfile(src, staged)
        os.chmod(staged, 0o755)
        os.replace(staged, dest)
    except OSError as e:
        return {"ok": False, "error": "Запись %s: %s" % (dest, e)}
    finally:
        if tmp_made:
            try:
                os.unlink(src)
            except OSError:
                pass

    check = verify_installed_binary(dest, _probe_args(cfg))
    if not check.get("ok"):
        restored = False
        if had_backup:
            try:
                os.replace(backup, dest)
                restored = True
            except OSError:
                pass
        if not restored:
            try:
                os.unlink(dest)
            except OSError:
                pass
        log.warning("ext_installer: %s не прошёл проверку запуска (%s)%s"
                    % (dest, check.get("error"),
                       " — вернул прежнюю версию" if restored else ""),
                    source="ext_installer")
        return {"ok": False, "exec_error": True, "restored": restored,
                "error": "Скачанный файл не запускается на этом устройстве"
                         " (%s).%s" % (check.get("error"),
                                       " Прежняя версия возвращена на место."
                                       if restored else "")}

    if had_backup:
        try:
            os.unlink(backup)
        except OSError:
            pass
    return {"ok": True}


def _probe_args(cfg: dict) -> tuple:
    """Чем проверять запуск: у каждого движка своя подкоманда версии."""
    args = cfg.get("version_args")
    if isinstance(args, (list, tuple)) and args:
        return tuple(args)
    return ("version", "--version", "--help")


def install_binary_by_name(name: str, *, progress_cb=None, tag: str = "",
                           transport: str = "", _cfg: dict = None) -> dict:
    """
    Установить бинарник по имени.

    Args:
        name: "tgwsproxy" | "usque" | "tgproto" | "opera"
        progress_cb: callback(stage, pct, label) для UI
        tag: поставить КОНКРЕТНЫЙ релиз вместо закреплённого в манифесте.
             Ослабляет проверку sha256 ровно так же, как allow_unpinned:
             хэши в манифесте относятся к закреплённой версии, для чужого
             тега сверять их не с чем.
        transport: через что качать ("", "awg:wg0", "singbox:<name>", …) —
             см. core/download_transport.

    Returns:
        {ok, binary, version, tag, error}
    """
    cfg = _cfg or BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник: %s" % name}

    arch = detect_arch()

    # Наша собственная сборка: релиз ищем по префиксу тэга (или берём
    # явно выбранный в UI), sha256 — из manifest.json релиза.
    if cfg.get("manifest_asset") and cfg.get("release_prefix"):
        res = _install_from_manifest(name, cfg, arch, progress_cb, transport,
                                     tag=tag)
        if res is not None:
            return res
        legacy = cfg.get("legacy_source")
        if legacy:
            log.warning("ext_installer: %s — переключаюсь на запасной"
                        " источник %s" % (name, legacy.get("repo", "?")),
                        source="ext_installer")
            return install_binary_by_name(name, progress_cb=progress_cb,
                                          transport=transport, _cfg=legacy)
        return {"ok": False,
                "error": "Нет сборки %s под архитектуру %s" % (name, arch)}

    install_kind = cfg.get("install_kind", "binary")
    pkg_mgr = _package_manager() if install_kind == "package" else ""
    asset_name = _resolve_asset_name(cfg, arch, pkg_mgr)
    if not asset_name:
        return {"ok": False, "error": "Архитектура %s не поддерживается" % arch}

    # 1. Получаем release: явно запрошенный тег имеет приоритет над
    #    закреплённым в манифесте.
    if progress_cb:
        progress_cb("fetch", 10, "Получение информации о релизе...")
    requested_tag = str(tag or "").strip()
    release_tag = requested_tag or cfg.get("release_tag", "")
    release = github_release(cfg["repo"], release_tag, transport=transport)
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
        if current_version and _pkg_version_matches_tag(current_version, tag):
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
        # asset_name из _resolve_asset_name — уже полное имя пакета
        # (напр. usque-keenetic_0.3.0_aarch64-3.10.ipk или
        # tg-ws-proxy_0.9.2-1_entware_aarch64-3.10.ipk). Прямое имя —
        # надёжный кандидат для fallback-загрузки.
        candidates = [asset_name]
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
        # Матчим ассет по полному имени пакета (или суффиксу) — обобщённо
        # для любого пакета, не только tg-ws-proxy.
        for asset in assets:
            aname = asset.get("name", "")
            if aname == asset_name or (asset_name and aname.endswith(asset_name)):
                download_url = asset.get("browser_download_url", "")
                downloaded_asset_name = aname
                break
        if not download_url:
            # Точного имени в релизе нет — значит приехала версия, отличная
            # от закреплённой в манифесте (мы ставим последний релиз, а имя
            # ассета содержит версию). Ищем по версионно-независимому
            # хвосту: `…_entware_aarch64-3.10.ipk`. Без этого «последний
            # релиз» упирался бы в fallback-URL с несуществующим именем.
            suffix = _asset_suffix_for(cfg, arch, pkg_mgr)
            prefix = (package_name + "_") if package_name else ""
            if suffix:
                for asset in assets:
                    aname = asset.get("name", "")
                    if aname.endswith(suffix) and (
                            not prefix or aname.startswith(prefix)):
                        download_url = asset.get("browser_download_url", "")
                        downloaded_asset_name = aname
                        break
                if download_url:
                    log.info(
                        "ext_installer: %s — ассет найден по суффиксу %s (%s)"
                        % (name, suffix, downloaded_asset_name),
                        source="ext_installer")
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
        if not download_file(download_url, tmp_path, transport=transport):
            return {"ok": False, "error": "Не удалось скачать %s" % asset_name}

        # MR-06: Проверка sha256
        if progress_cb:
            progress_cb("download", 60, "Проверка контрольной суммы...")
        v_res = _verify_downloaded_file(release, downloaded_asset_name, tmp_path)
        if not v_res.get("ok"):
            return v_res

        # MR-06: обязательная проверка sha256 из встроенного манифеста.
        #
        # Манифестный хэш относится к конкретной версии, поэтому он
        # применим, только если поставили именно её: pinned_tag (или
        # release_tag, если тег закреплён). Для бинарников, которые
        # ставятся «последним релизом» (allow_unpinned), хэша более новой
        # версии в манифесте физически быть не может — там опираемся на
        # файл контрольных сумм релиза, если апстрим его публикует.
        cfg_sha256 = _expected_sha256(cfg, arch, pkg_mgr)
        pinned_tag = cfg.get("pinned_tag") or cfg.get("release_tag") or ""
        is_pinned_version = not pinned_tag or _same_tag(tag, pinned_tag)
        sha256_pinned = bool(cfg_sha256) and is_pinned_version

        if sha256_pinned:
            h = hashlib.sha256()
            with open(tmp_path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            if h.hexdigest().lower() != cfg_sha256.lower():
                raise InstallError("SHA256 mismatch for %s" % name)
        elif is_pinned_version and pinned_tag and not cfg_sha256:
            # Приехала ровно та версия, что закреплена в манифесте, а хэша
            # под эту архитектуру там нет — это дыра в манифесте, а не
            # ожидаемый случай «версия новее». Fail-closed даже у
            # allow_unpinned-бинарников.
            return {
                "ok": False,
                "error": "SHA256 для %s (%s) не задан в манифесте" % (name, arch),
            }
        elif requested_tag and not is_pinned_version:
            # Пользователь ЯВНО выбрал другой тег в UI. Манифестный хэш
            # относится к закреплённой версии, сверять его тут не с чем —
            # но и запрещать выбор версии нельзя, иначе селектор релизов
            # бессмысленен. Политика та же, что у allow_unpinned: доверяем
            # файлу контрольных сумм релиза, а если его нет — HTTPS к
            # GitHub, и об этом громко сообщаем (в лог и в ответ).
            if v_res.get("skipped"):
                log.warning(
                    "ext_installer: %s — установлен выбранный вручную тег %s"
                    " (закреплён %s), файла контрольных сумм в релизе нет —"
                    " sha256 не сверялся" % (name, tag, pinned_tag),
                    source="ext_installer")
        elif not cfg.get("allow_unpinned"):
            return {
                "ok": False,
                "error": "SHA256 для %s (%s) не задан в манифесте" % (name, arch),
            }
        elif v_res.get("skipped"):
            # Ставим версию новее известной, а апстрим не публикует
            # контрольные суммы: целостность держится только на HTTPS к
            # GitHub. Не молчим об этом — пишем в лог и отдаём в ответе.
            log.warning(
                "ext_installer: %s %s новее известной %s, файла контрольных "
                "сумм в релизе нет — sha256 не сверялся"
                % (name, tag, pinned_tag), source="ext_installer")

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
            # Те же поля, что и у бинарного пути: пакеты тоже ставятся
            # «последним релизом», и «проверено» не должно подразумеваться
            # по умолчанию.
            return {"ok": True, "binary": dest_path or package_name,
                    "version": version, "tag": tag,
                    "sha256_verified": bool(sha256_pinned or
                                            not v_res.get("skipped")),
                    "sha256_pinned": bool(sha256_pinned)}

        # 4. Распаковываем если нужно
        if progress_cb:
            progress_cb("install", 70, "Установка...")

        # `.tar.gz` тоже оканчивается на `.gz` — порядок проверок внутри
        # _unpack_if_needed не даёт «распаковать» тарбол в самого себя и
        # положить tar-архив на место бинарника (MR-143: защита от
        # zip-slip осталась там же).
        final_path, unpacked_tmp, unpack_err = _unpack_if_needed(tmp_path)
        if unpack_err:
            return {"ok": False, "error": unpack_err}

        # 5. Устанавливаем
        if progress_cb:
            progress_cb("install", 90, "Копирование бинарника...")

        if not install_binary(final_path, cfg["dest"]):
            return {"ok": False, "error": "Не удалось установить бинарник"}
        if unpacked_tmp:
            try:
                os.unlink(final_path)
            except OSError:
                pass

        check = verify_installed_binary(cfg["dest"], _probe_args(cfg))
        if not check.get("ok"):
            try:
                os.unlink(cfg["dest"])
            except OSError:
                pass
            return {"ok": False, "exec_error": True,
                    "error": "Скачанный файл не запускается на этом"
                             " устройстве (%s)" % check.get("error")}

        # 6. Проверяем
        version = _get_version(cfg["dest"])

        if progress_cb:
            progress_cb("done", 100, "Установлено: %s" % version)

        log.info("ext_installer: %s установлен (%s, %s)"
                 % (name, tag, version), source="ext_installer")

        # sha256_verified: сверяли ли хэш вообще — по манифесту или по
        # файлу контрольных сумм релиза. GUI показывает это пользователю,
        # чтобы «проверено» не подразумевалось по умолчанию.
        return {"ok": True, "binary": cfg["dest"], "version": version,
                "tag": tag,
                "sha256_verified": bool(sha256_pinned or
                                        not v_res.get("skipped")),
                "sha256_pinned": bool(sha256_pinned)}

    finally:
        # Очистка (.bin — распакованный из .gz, .part — хвост докачки)
        for p in (tmp_path, tmp_path + ".bin", tmp_path + ".part"):
            try:
                if os.path.isfile(p):
                    os.unlink(p)
            except Exception:
                pass


def uninstall_binary(name: str) -> dict:
    """Удалить бинарник (или пакет, если ставился пакетным менеджером)."""
    cfg = BINARIES.get(name)
    if not cfg:
        return {"ok": False, "error": "Неизвестный бинарник"}
    try:
        if cfg.get("install_kind", "binary") == "package":
            # Установлено через opkg/apk — удалять надо пакетом, иначе база
            # пакетов продолжит считать его установленным и повторная
            # установка завершится noop («уже актуально») без бинарника.
            pkg = cfg.get("package_name", name)
            pkg_mgr = _package_manager()
            if pkg_mgr and _pkg_version(pkg):
                cmd = ([pkg_mgr, "remove", pkg] if pkg_mgr == "opkg"
                       else [pkg_mgr, "del", pkg])
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=300)
                if proc.returncode != 0:
                    return {"ok": False,
                            "error": "Удаление пакета не удалось: %s"
                                     % ((proc.stderr or proc.stdout
                                         or "").strip())}
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
