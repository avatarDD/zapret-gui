# core/binary_installer.py
"""
Общая утилита для скачивания / проверки / распаковки бинарных
депенденси zapret-gui.

Сейчас у нас три места, где живёт похожая логика:
  - `core/awg_installer.py`    — amneziawg-go / amneziawg-tools
  - `core/zapret_installer.py` — nfqws2 (zapret2)
  - в будущем: `core/singbox_installer.py` — sing-box

Все три делают одно и то же:
  1. Получают manifest / release-метаданные с GitHub.
  2. Скачивают tarball с retry.
  3. Проверяют sha256 (если есть).
  4. Распаковывают `tar.gz`.
  5. Кладут бинарь в `<platform.binary_dir>/<name>` и chmod +x.

Эта утилита инкапсулирует шаги 2-5 и слабо завязана на конкретный
вид installer'а — `awg_installer` и `zapret_installer` могут
переезжать на неё постепенно. Sing-box installer стартует
прямо на ней.

Все функции — pure-side-effect, никаких глобальных синглтонов;
прогресс отдаётся через callback (`progress_cb(stage, pct, label)`).
"""

import gzip
import hashlib
import os
import shutil
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_HTTP_TIMEOUT = 30
DEFAULT_DOWNLOAD_TIMEOUT = 600     # большие бинарники + медленный mipsel
DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 2          # секунды; экспоненциально


# ─────── mirror / offline (заимствовано из XKeen) ───────
#
# Наша аудитория — пользователи в условиях блокировок, у которых
# github.com и githubusercontent.com часто недоступны напрямую.
# XKeen умеет ставить компоненты с self-hosted зеркала и оффлайн.
# Реализуем это как тонкий слой переписывания URL:
#
#   • mirror-prefix    — самый распространённый для GitHub-прокси
#     (ghproxy и аналоги): зеркало проксирует ПОЛНЫЙ url, дописанный
#     в хвост. Пример: ZAPRET_GUI_MIRROR=https://mirror.example →
#     https://mirror.example/https://github.com/owner/repo/...
#   • локальный путь / file:// — полностью оффлайн: URL не трогаем,
#     download_file копирует файл вместо HTTP.
#
# Источник зеркала (по приоритету):
#   1. env ZAPRET_GUI_MIRROR
#   2. settings.json → install.mirror
# Пустая строка / отсутствие → прямые GitHub-ссылки (как раньше).

_GITHUB_HOSTS = (
    "github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com",
    "api.github.com",
)


def _configured_mirror() -> str:
    """Базовый URL зеркала (или ''). env имеет приоритет над конфигом."""
    env = (os.environ.get("ZAPRET_GUI_MIRROR") or "").strip()
    if env:
        return env
    try:
        from core.config_manager import get_config_manager
        v = get_config_manager().get("install", "mirror", default="")
        return (v or "").strip()
    except Exception:
        return ""


def is_local_url(url: str) -> bool:
    """True для file:// и абсолютных/относительных локальных путей."""
    if not url:
        return False
    if url.startswith("file://"):
        return True
    scheme = urllib.parse.urlparse(url).scheme
    # http/https/ftp → не локальный; пусто или 'c' (винда) → локальный путь.
    return scheme in ("", "file")


def local_path_of(url: str) -> str:
    """Превратить file:// или локальный путь в обычный путь ФС."""
    if url.startswith("file://"):
        return urllib.parse.urlparse(url).path
    return url


def resolve_url(url: str, mirror: str = None) -> str:
    """
    Переписать GitHub-URL на зеркало, если оно задано. Чистая функция.

    Локальные/file:// URL и не-GitHub хосты возвращаются как есть.
    mirror=None → берём из окружения/конфига; '' → принудительно без
    зеркала (для тестов и явного отключения).
    """
    if not url or is_local_url(url):
        return url
    if mirror is None:
        mirror = _configured_mirror()
    if not mirror:
        return url
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host not in _GITHUB_HOSTS:
        return url
    return mirror.rstrip("/") + "/" + url


# ─────── http ───────

def _http_open(url: str, accept: str = "application/octet-stream",
               timeout: int = DEFAULT_HTTP_TIMEOUT):
    """Открыть HTTP-соединение, вернуть response-объект."""
    req = urllib.request.Request(url, headers={"Accept": accept})
    return urllib.request.urlopen(req, timeout=timeout)


def _human_size(n: int) -> str:
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024)
    return "%.1f MB" % (n / (1024 * 1024))


# ─────── download ───────

def download_file(url: str, dest_path: str,
                  progress_cb=None, label: str = "",
                  progress_from: int = 0, progress_to: int = 100,
                  retries: int = DEFAULT_RETRIES,
                  timeout: int = DEFAULT_DOWNLOAD_TIMEOUT) -> dict:
    """
    Скачать файл по URL в dest_path. Retry с экспоненциальным backoff
    на сетевые ошибки.

    Параметры:
      progress_cb : callable(stage_str, pct_int, label_str) — отчёт
                    о прогрессе. None — не вызывать.
      progress_from, progress_to : диапазон прогресса для этой
                    операции (например, 0..50 если за этим идёт ещё
                    верификация / распаковка).

    Возвращает:
      {"ok": bool, "path": dest_path, "size": int, "error": str?}
    """
    label = label or os.path.basename(url) or "файл"

    # Оффлайн: file:// или локальный путь — просто копируем, без сети.
    if is_local_url(url):
        return _copy_local(local_path_of(url), dest_path, progress_cb,
                           label, progress_to)

    # Переписываем на зеркало (если настроено).
    url = resolve_url(url)

    last_err = ""
    for attempt in range(1, max(1, retries) + 1):
        try:
            return _download_once(
                url, dest_path, progress_cb, label,
                progress_from, progress_to, timeout)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_err = "%s (попытка %d/%d)" % (e, attempt, retries)
            if attempt < retries:
                time.sleep(DEFAULT_RETRY_BACKOFF ** attempt)
                continue
    return {"ok": False, "path": dest_path, "size": 0, "error": last_err}


def _copy_local(src: str, dest_path: str, progress_cb, label,
                progress_to: int) -> dict:
    """Скопировать локальный файл (оффлайн-установка)."""
    if not os.path.isfile(src):
        return {"ok": False, "path": dest_path, "size": 0,
                "error": "локальный файл не найден: %s" % src}
    try:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        shutil.copy2(src, dest_path)
        size = os.path.getsize(dest_path)
    except OSError as e:
        return {"ok": False, "path": dest_path, "size": 0,
                "error": "копирование %s: %s" % (src, e)}
    if progress_cb:
        progress_cb("downloading", progress_to,
                    "Локальный файл %s (%s)" % (label, _human_size(size)))
    return {"ok": True, "path": dest_path, "size": size, "error": ""}


def _download_once(url, dest_path, progress_cb, label,
                   progress_from, progress_to, timeout) -> dict:
    """Один проход — выбрасывает исключения для outer retry-loop."""
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with _http_open(url, timeout=timeout) as resp:
        total = resp.getheader("Content-Length")
        total = int(total) if total and total.isdigit() else 0
        downloaded = 0
        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if progress_cb:
                    if total > 0:
                        pct = progress_from + int(
                            (progress_to - progress_from) * downloaded / total)
                    else:
                        pct = (progress_from + progress_to) // 2
                    progress_cb("downloading", pct,
                                "Загрузка %s (%s)" %
                                (label, _human_size(downloaded)))
    return {"ok": True, "path": dest_path, "size": downloaded, "error": ""}


# ─────── verify ───────

def sha256_of(path: str) -> str:
    """SHA256 одного файла в hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(DEFAULT_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: str, expected: str) -> dict:
    """
    Проверить sha256 файла. Если expected пустой — skip с ok=True
    (вызывающая сторона решает, что делать с отсутствующим хэшем).
    """
    if not expected:
        return {"ok": True, "skipped": True,
                "reason": "no expected sha256"}
    actual = sha256_of(path)
    if actual.lower() != expected.strip().lower():
        return {"ok": False, "actual": actual, "expected": expected,
                "error": "sha256 mismatch"}
    return {"ok": True, "actual": actual}


# ─────── extract ───────

def extract_tarball(archive_path: str, dest_dir: str,
                    members_filter=None,
                    safe_paths: bool = True) -> dict:
    """
    Распаковать tar.gz в dest_dir. Возвращает список extracted names.

    members_filter : callable(member: TarInfo) -> bool. None — все.
    safe_paths : True (default) — отвергнуть архивы с абсолютными
                 путями или `..` в именах (CVE-2007-4559, Slip-tar).
    """
    if not os.path.isfile(archive_path):
        return {"ok": False, "error": "архив не существует: %s" % archive_path}
    try:
        os.makedirs(dest_dir, exist_ok=True)
        names = []
        with tarfile.open(archive_path, "r:*") as tf:
            members = []
            for m in tf.getmembers():
                if members_filter is not None and not members_filter(m):
                    continue
                if safe_paths and not _is_safe_path(m.name):
                    return {"ok": False,
                            "error": "небезопасный путь в архиве: %s"
                                     % m.name}
                members.append(m)
                names.append(m.name)
            # Python 3.12+ предлагает filter='data'; для совместимости
            # 3.11 используем explicit-members-loop с уже отфильтрованным
            # списком.
            try:
                tf.extractall(dest_dir, members=members, filter="data")
            except TypeError:
                # Python < 3.12 — filter аргумента нет
                tf.extractall(dest_dir, members=members)
        return {"ok": True, "names": names, "dest_dir": dest_dir}
    except (tarfile.TarError, OSError) as e:
        return {"ok": False, "error": "распаковка: %s" % e}


def extract_gz(archive_path: str, dest_path: str) -> dict:
    """
    Распаковать одиночный .gz (gzipped binary) в dest_path.

    Mihomo и многие апстрим-проекты публикуют бинарь как один
    gzip-файл (`mihomo-linux-arm64-v1.X.gz`), а не tar.gz. Здесь —
    потоковая декомпрессия в файл.
    """
    if not os.path.isfile(archive_path):
        return {"ok": False, "error": "архив не существует: %s" % archive_path}
    try:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with gzip.open(archive_path, "rb") as src, open(dest_path, "wb") as dst:
            shutil.copyfileobj(src, dst, length=DEFAULT_CHUNK_SIZE)
        return {"ok": True, "dest": dest_path}
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        return {"ok": False, "error": "gunzip: %s" % e}


def _is_safe_path(name: str) -> bool:
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


# ─────── install ───────

def chmod_executable(path: str) -> bool:
    """`chmod +x` (для владельца/группы/всех — как 0755 для бинарей)."""
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP |
                 stat.S_IXOTH)
        return True
    except OSError:
        return False


def install_binary(src_path: str, dest_path: str,
                   backup_old: bool = True) -> dict:
    """
    Положить бинарь в финальное место с +x и атомарной заменой.

    backup_old=True — если в dest_path уже есть файл, переименовать
    в `<dest_path>.bak`. Защищает от случая, когда новый бинарь упадёт
    и пользователь хочет вернуть прежний.

    Атомарность гарантируется через `os.replace` — он atomic на одной
    файловой системе.
    """
    if not os.path.isfile(src_path):
        return {"ok": False, "error": "src не существует: %s" % src_path}
    dest_dir = os.path.dirname(dest_path) or "."
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        return {"ok": False, "error": "mkdir %s: %s" % (dest_dir, e)}

    if backup_old and os.path.exists(dest_path):
        try:
            shutil.copy2(dest_path, dest_path + ".bak")
        except OSError as e:
            # Бэкап не вышел — не критично, продолжаем установку,
            # но возвращаем флаг.
            return _replace_now(src_path, dest_path,
                                backup_warning=str(e))
    return _replace_now(src_path, dest_path)


def _replace_now(src_path: str, dest_path: str,
                 backup_warning: str = "") -> dict:
    try:
        # os.replace требует чтобы src и dest были на одной FS.
        # На разных FS используем shutil.move (он переключится на
        # copy+unlink).
        try:
            os.replace(src_path, dest_path)
        except OSError:
            shutil.move(src_path, dest_path)
        if not chmod_executable(dest_path):
            return {"ok": True, "warning": "chmod +x failed",
                    "dest": dest_path,
                    "backup_warning": backup_warning}
        return {"ok": True, "dest": dest_path,
                "backup_warning": backup_warning}
    except OSError as e:
        return {"ok": False, "error": "install: %s" % e,
                "backup_warning": backup_warning}


# ─────── one-shot pipeline ───────

def fetch_verify_extract_install(
        url: str,
        sha256: str,
        archive_path: str,
        extract_dir: str,
        binary_in_archive: str,
        final_dest: str,
        progress_cb=None,
        label: str = "") -> dict:
    """
    Полный пайплайн: download → verify → extract → install.

    Используется новыми installer'ами как один вызов; старые
    `awg_installer` и `zapret_installer` могут поэтапно перейти
    на него вместо своих внутренних `_do_install()`.

    Возвращает dict с итоговым статусом и подробностями каждой
    стадии.
    """
    label = label or os.path.basename(final_dest) or "binary"

    # 1) download
    dl = download_file(url, archive_path, progress_cb=progress_cb,
                       label=label,
                       progress_from=0, progress_to=60)
    if not dl.get("ok"):
        return {"ok": False, "stage": "download", "error": dl.get("error"),
                "download": dl}

    # 2) verify
    if progress_cb:
        progress_cb("verifying", 65, "Проверка sha256 %s" % label)
    vr = verify_sha256(archive_path, sha256)
    if not vr.get("ok"):
        return {"ok": False, "stage": "verify", "error": vr.get("error"),
                "verify": vr}

    # 3) extract
    if progress_cb:
        progress_cb("extracting", 75, "Распаковка %s" % label)
    ex = extract_tarball(archive_path, extract_dir)
    if not ex.get("ok"):
        return {"ok": False, "stage": "extract", "error": ex.get("error"),
                "extract": ex}

    # 4) install
    if progress_cb:
        progress_cb("installing", 90, "Установка %s" % label)
    src = os.path.join(extract_dir, binary_in_archive)
    if not os.path.isfile(src):
        # Возможно архив содержит бинарь в корне без подкаталога
        return {"ok": False, "stage": "install",
                "error": "бинарь %s не найден в архиве" % binary_in_archive,
                "extracted": ex.get("names")}
    ins = install_binary(src, final_dest)
    if not ins.get("ok"):
        return {"ok": False, "stage": "install", "error": ins.get("error"),
                "install": ins}

    if progress_cb:
        progress_cb("done", 100, "Установлено %s" % label)
    return {"ok": True, "stage": "done", "final_path": final_dest,
            "size": dl.get("size", 0),
            "sha256_verified": not vr.get("skipped"),
            "stages": {"download": dl, "verify": vr,
                       "extract": ex, "install": ins}}
