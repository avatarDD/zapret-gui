# core/safe_io.py
"""
Безопасные общие I/O-утилиты zapret-gui.

Два класса задач, которые исторически дублировались и делались небезопасно
в нескольких модулях:

  1. **Атомарная запись** (`atomic_write_*`) — запись во временный файл в той
     же ФС → ``fsync`` → ``os.replace``. Гарантирует, что читатель никогда не
     увидит усечённый/частично записанный файл (важно для ``settings.json``:
     креш/``ENOSPC``/потеря питания на роутере не должны обнулять конфиг).

  2. **Безопасная распаковка** (`safe_extract_archive`) — tar/zip с защитой от
     path-traversal (CVE-2007-4559, «slip-tar»/«slip-zip») и от symlink-escape.
     Архивы скачиваются под root с настраиваемого зеркала, поэтому
     ``extractall`` без валидации = запись произвольных файлов вне dest.

Модуль — только stdlib, без синглтонов и без импорта других ``core/*`` —
его безопасно импортировать откуда угодно (в т.ч. из ``config_manager``)
без риска циклических импортов.
"""

import json
import os
import tarfile
import tempfile
import zipfile


# ───────────────────────── атомарная запись ──────────────────────────

def atomic_write_bytes(path: str, data: bytes) -> None:
    """Атомарно записать ``data`` в ``path`` (temp в той же ФС → fsync →
    ``os.replace``). Бросает ``OSError`` при неудаче — вызывающий решает,
    логировать/глотать ли."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    # temp обязан лежать в той же ФС, что и dest — иначе os.replace не атомарен.
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".swp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None  # успех — temp уже переименован
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass


def atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    """Атомарно записать текст (см. :func:`atomic_write_bytes`)."""
    atomic_write_bytes(path, text.encode(encoding))


def atomic_write_json(path: str, obj, *, indent: int = 2,
                      ensure_ascii: bool = False) -> None:
    """Атомарно сериализовать ``obj`` в JSON и записать в ``path``.

    Сериализация выполняется ДО открытия temp-файла: если ``obj`` не
    сериализуем, существующий файл остаётся нетронутым."""
    payload = json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii)
    atomic_write_text(path, payload)


# ─────────────────────── безопасная распаковка ───────────────────────

def is_safe_member_name(name: str) -> bool:
    """True, если имя члена архива не содержит абсолютного пути или ``..``.

    Идентично ``binary_installer._is_safe_path`` — поведение намеренно
    совпадает (один контракт на весь проект)."""
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


def _within(base_real: str, name: str) -> bool:
    """True, если ``base/name`` после нормализации остаётся внутри ``base``."""
    target = os.path.realpath(os.path.join(base_real, name))
    return target == base_real or target.startswith(base_real + os.sep)


def _looks_like_zip(path: str) -> bool:
    if path.endswith(".zip"):
        return True
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def safe_extract_archive(archive_path: str, dest_dir: str):
    """Распаковать ``tar.gz``/``tgz``/``tar``/``zip`` в ``dest_dir``.

    Защита: отвергает членов с абсолютным путём или ``..``, члены, чей путь
    после нормализации выходит за ``dest_dir``, и symlink/hardlink с целью
    вне ``dest_dir``. На Python 3.12+ дополнительно применяется штатный
    ``filter="data"``.

    Возвращает ``(ok: bool, error: str | None)`` — не бросает на штатных
    ошибках формата/ввода-вывода.
    """
    if not os.path.isfile(archive_path):
        return False, "архив не существует: %s" % archive_path

    dest_real = os.path.realpath(dest_dir)
    try:
        os.makedirs(dest_real, exist_ok=True)

        if _looks_like_zip(archive_path):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    nm = info.filename
                    if not is_safe_member_name(nm) or not _within(dest_real, nm):
                        return False, "небезопасный путь в архиве: %s" % nm
                zf.extractall(dest_real)
            return True, None

        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            for m in members:
                if not is_safe_member_name(m.name) or not _within(dest_real, m.name):
                    return False, "небезопасный путь в архиве: %s" % m.name
                # Спец-файлы (block/char/fifo) — не нужны в наших архивах.
                if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
                    return False, "недопустимый тип члена: %s" % m.name
                # Symlink/hardlink — цель не должна вести наружу dest.
                if m.issym() or m.islnk():
                    link_base = (os.path.dirname(m.name)
                                 if m.issym() else "")
                    if not _within(dest_real, os.path.join(link_base,
                                                            m.linkname)):
                        return False, ("небезопасная ссылка в архиве: %s → %s"
                                       % (m.name, m.linkname))
            try:
                tf.extractall(dest_real, members=members, filter="data")
            except TypeError:
                # Python < 3.12 — параметра filter нет; защита выше уже
                # отвергла опасных членов.
                tf.extractall(dest_real, members=members)
        return True, None
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as e:
        return False, "распаковка: %s" % e
