# core/asset_importer.py
"""
Импортёр вспомогательных ассетов nfqws2 из bundled-директории `import/`.

Зачем он нужен:
    Базовая установка zapret2 (bol-van/zapret2) даёт только бинарник nfqws2.
    Стратегии же ссылаются на:
      - blob-файлы    (--blob=name:@bin/*.bin)            → /opt/zapret2/files/fake/
      - Lua-скрипты   (--lua-init=@lua/*.lua)             → /opt/zapret2/lua/
      - Hostlist'ы    (--hostlist=lists/*.txt)            → /opt/zapret2/lists/
      - Ipset'ы       (--ipset[-exclude]=lists/ipset-*.txt) → /opt/zapret2/ipset/

    Эти файлы поставляются вместе с нашим GUI в директории `import/`
    и должны быть выложены в нужные места /opt/zapret2/ при установке
    или обновлении GUI — иначе стратегии не работают.

    Layout import/ → runtime:
      import/bin/*.bin             → /opt/zapret2/files/fake/
      import/lua/*.lua             → /opt/zapret2/lua/
      import/lists/ipset-*.txt     → /opt/zapret2/ipset/
      import/lists/*ipset*.txt     → /opt/zapret2/ipset/
      import/lists/*.txt (hostlists) → /opt/zapret2/lists/

Также этот модуль импортирует дополнительные INI-каталоги стратегий:
      - import/_internal/preset_zapret2/basic_strategies/*.txt
              → catalogs/basic/      (merge по section_id)
      - import/_internal/preset_zapret2/advanced_strategies/*.txt
              → catalogs/advanced/   (merge по section_id)
      - import/_internal/preset_zapret2/builtin_presets/*.txt
              → catalogs/builtin/winws2_presets.txt
                (конвертация: срез --wf-* + merge по section_id)

Семантика:
  * Идемпотентно: одинаковое содержимое → не перезаписываем.
  * Файлы, присутствующие в `import/`, являются "managed" — upstream
    побеждает при изменениях.
  * Файлы в целевых директориях, которых нет в `import/`, не трогаем
    (это могут быть пользовательские blob'ы/lua/lists).
  * `_`-префиксные файлы (`_HOWTO.txt`, `_TEMPLATE.txt`, `_README.txt`)
    пропускаются.
  * Windows-специфичное игнорируется: `import/windivert.filter/`
    и `--wf-*` строки при конвертации builtin-пресетов.

Использование:
    from core.asset_importer import import_all, import_runtime_assets

    stats = import_all()
    # или отдельными шагами:
    stats = import_runtime_assets()    # blobs/lua/lists → /opt/zapret2/
    stats = import_bundled_strategies()  # catalogs/basic|advanced|builtin
"""

from __future__ import annotations

import hashlib
import os
import shutil
from typing import Optional

from core.log_buffer import log


# ─── Пути ────────────────────────────────────────────────────

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Bundled (наш GUI-пакет)
IMPORT_DIR = os.path.join(_APP_DIR, "import")
IMPORT_BIN_DIR = os.path.join(IMPORT_DIR, "bin")
IMPORT_LUA_DIR = os.path.join(IMPORT_DIR, "lua")
IMPORT_LISTS_DIR = os.path.join(IMPORT_DIR, "lists")
IMPORT_STRATS_DIR = os.path.join(
    IMPORT_DIR, "_internal", "preset_zapret2",
)
IMPORT_BASIC_DIR = os.path.join(IMPORT_STRATS_DIR, "basic_strategies")
IMPORT_ADV_DIR = os.path.join(IMPORT_STRATS_DIR, "advanced_strategies")
IMPORT_PRESETS_DIR = os.path.join(IMPORT_STRATS_DIR, "builtin_presets")

# Целевые каталоги в репо (не runtime!) — сюда мержим стратегии
CATALOG_BASIC_DIR = os.path.join(_APP_DIR, "catalogs", "basic")
CATALOG_ADV_DIR = os.path.join(_APP_DIR, "catalogs", "advanced")
CATALOG_BUILTIN_DIR = os.path.join(_APP_DIR, "catalogs", "builtin")
CATALOG_BUILTIN_FILE = os.path.join(
    CATALOG_BUILTIN_DIR, "winws2_presets.txt",
)

# Пропускаемые имена (техническая служебка репозитория-источника)
_SKIP_PREFIXES = ("_",)


# ─── Публичный API ───────────────────────────────────────────

def import_all(base_path: Optional[str] = None) -> dict:
    """
    Импортировать всё: runtime-ассеты и bundled-стратегии.

    Args:
        base_path: Путь к zapret2 (по умолчанию — из конфига или
                   /opt/zapret2). Используется, если конфиг ещё не
                   загружен (вызов из install.sh до первого запуска).

    Returns:
        dict со статистикой по подсистемам.
    """
    runtime = import_runtime_assets(base_path=base_path)
    strategies = import_bundled_strategies()
    return {
        "ok": runtime.get("ok", True) and strategies.get("ok", True),
        "runtime": runtime,
        "strategies": strategies,
    }


def import_runtime_assets(base_path: Optional[str] = None) -> dict:
    """
    Скопировать blobs/lua/lists из `import/` в стандартные runtime-каталоги
    zapret2:

        bin/*.bin                → <base>/files/fake/
        lua/*.lua                → <base>/lua/
        lists/ipset-*.txt и
        lists/*ipset*.txt        → <base>/ipset/
        lists/*.txt (hostlists)  → <base>/lists/

    Идемпотентно (checksum-based). Пропускает identical-файлы.

    Args:
        base_path: Корень zapret2 runtime. Если None — читаем конфиг
                   (если доступен), иначе /opt/zapret2.
    """
    if base_path is None:
        base_path = _resolve_zapret_base_path()

    if not os.path.isdir(IMPORT_DIR):
        log.debug(
            "asset-importer: директория import/ отсутствует, пропускаем",
            source="asset-importer",
        )
        return {
            "ok": True, "skipped": True,
            "fake": {}, "lua": {}, "lists": {}, "ipset": {},
        }

    fake_stats = _sync_dir(
        IMPORT_BIN_DIR,
        os.path.join(base_path, "files", "fake"),
    )
    lua_stats = _sync_dir(
        IMPORT_LUA_DIR,
        os.path.join(base_path, "lua"),
    )
    # lists/ → split: ipset-файлы в ipset/, остальные в lists/
    lists_stats, ipset_stats = _sync_lists_split(
        IMPORT_LISTS_DIR,
        lists_dst=os.path.join(base_path, "lists"),
        ipset_dst=os.path.join(base_path, "ipset"),
    )

    total_copied = (fake_stats["copied"] + lua_stats["copied"]
                    + lists_stats["copied"] + ipset_stats["copied"])
    total_skipped = (fake_stats["skipped"] + lua_stats["skipped"]
                     + lists_stats["skipped"] + ipset_stats["skipped"])

    if total_copied > 0:
        log.success(
            "asset-importer: скопировано %d файл(ов) в %s "
            "(fake=%d, lua=%d, lists=%d, ipset=%d)" % (
                total_copied, base_path,
                fake_stats["copied"], lua_stats["copied"],
                lists_stats["copied"], ipset_stats["copied"],
            ),
            source="asset-importer",
        )
    else:
        log.debug(
            "asset-importer: все runtime-ассеты актуальны "
            "(пропущено %d файл(ов))" % total_skipped,
            source="asset-importer",
        )

    return {
        "ok": True,
        "base_path": base_path,
        "fake": fake_stats,
        "lua": lua_stats,
        "lists": lists_stats,
        "ipset": ipset_stats,
        "copied": total_copied,
        "skipped": total_skipped,
    }


def _is_ipset_filename(name: str) -> bool:
    """
    True для файлов, содержащих IP-адреса (а не доменные имена).

    Эвристика по имени:
      * `ipset-*.txt`               (стандартный префикс zapret2)
      * `*-ipset.txt`, `*-ipset_*`  (cloudflare-ipset.txt и пр.)
    """
    low = name.lower()
    if not low.endswith(".txt"):
        return False
    if low.startswith("ipset-"):
        return True
    # cloudflare-ipset.txt, cloudflare-ipset_v6.txt, russia-discord-ipset.txt
    base = low[:-4]  # strip .txt
    if base.endswith("-ipset") or "-ipset_" in base or "-ipset." in low:
        return True
    return False


def _sync_lists_split(src_dir: str, lists_dst: str, ipset_dst: str):
    """
    Разнести содержимое import/lists/ по двум целевым директориям:
      * ipset-* и *-ipset → ipset_dst
      * остальные         → lists_dst

    Возвращает (lists_stats, ipset_stats).
    """
    lists_stats = {"copied": 0, "skipped": 0, "errors": []}
    ipset_stats = {"copied": 0, "skipped": 0, "errors": []}

    if not os.path.isdir(src_dir):
        return lists_stats, ipset_stats

    for dst in (lists_dst, ipset_dst):
        try:
            os.makedirs(dst, exist_ok=True)
        except OSError as e:
            msg = "Не удалось создать %s: %s" % (dst, e)
            log.warning(msg, source="asset-importer")

    for name in sorted(os.listdir(src_dir)):
        if name.startswith(_SKIP_PREFIXES):
            continue
        src = os.path.join(src_dir, name)
        if not os.path.isfile(src):
            continue
        if _is_ipset_filename(name):
            stats, dst_dir = ipset_stats, ipset_dst
        else:
            stats, dst_dir = lists_stats, lists_dst
        dst = os.path.join(dst_dir, name)
        try:
            if _files_identical(src, dst):
                stats["skipped"] += 1
                continue
            shutil.copy2(src, dst)
            stats["copied"] += 1
        except (OSError, shutil.Error) as e:
            msg = "Ошибка копирования %s → %s: %s" % (src, dst, e)
            log.warning(msg, source="asset-importer")
            stats["errors"].append(msg)

    return lists_stats, ipset_stats


def import_bundled_strategies() -> dict:
    """
    Импортировать bundled-стратегии в catalogs/:
      * basic/*.txt    — merge по section_id (remote wins)
      * advanced/*.txt — merge по section_id (remote wins)
      * builtin_presets/*.txt — конвертация (вырезаем --wf-*)
        + merge в catalogs/builtin/winws2_presets.txt
    """
    if not os.path.isdir(IMPORT_STRATS_DIR):
        return {"ok": True, "skipped": True}

    basic = _merge_ini_dir(IMPORT_BASIC_DIR, CATALOG_BASIC_DIR)
    advanced = _merge_ini_dir(IMPORT_ADV_DIR, CATALOG_ADV_DIR)
    presets = _merge_bundled_presets(
        IMPORT_PRESETS_DIR, CATALOG_BUILTIN_FILE,
    )

    added = basic["added"] + advanced["added"] + presets["added"]
    updated = basic["updated"] + advanced["updated"] + presets["updated"]
    preserved = (basic["preserved"] + advanced["preserved"]
                 + presets["preserved"])

    if added or updated or preserved:
        log.success(
            "asset-importer: bundled-стратегии (basic/advanced/builtin): "
            "added=%d updated=%d preserved=%d" % (
                added, updated, preserved,
            ),
            source="asset-importer",
        )

    # Переcчитываем каталоги в runtime, если менеджер уже живой
    if added or updated:
        _try_reload_catalogs()

    return {
        "ok": True,
        "basic": basic,
        "advanced": advanced,
        "builtin_presets": presets,
        "added": added,
        "updated": updated,
        "preserved": preserved,
    }


# ─── Внутренние хелперы: runtime assets ──────────────────────

def _sync_dir(src_dir: str, dst_dir: str,
              ext_whitelist: Optional[set] = None) -> dict:
    """
    Синхронизировать `src_dir` → `dst_dir` (однонаправленно).

    Поведение:
      * Файлы в src_dir с `_`-префиксом пропускаются.
      * Если dst-файл не существует или отличается по содержимому —
        копируется (с сохранением mtime).
      * Если существует и идентичен — не трогается (идемпотентно).
      * Файлы в dst_dir, не представленные в src_dir — НЕ УДАЛЯЮТСЯ
        (это могут быть пользовательские).

    Args:
        src_dir:       Откуда копируем (bundled).
        dst_dir:       Куда копируем.
        ext_whitelist: Множество разрешённых расширений (с точкой),
                       или None для всех файлов.

    Returns: {"copied": N, "skipped": M, "errors": [...]}
    """
    stats = {"copied": 0, "skipped": 0, "errors": []}

    if not os.path.isdir(src_dir):
        return stats

    try:
        os.makedirs(dst_dir, exist_ok=True)
    except OSError as e:
        msg = "Не удалось создать %s: %s" % (dst_dir, e)
        log.warning(msg, source="asset-importer")
        stats["errors"].append(msg)
        return stats

    for name in sorted(os.listdir(src_dir)):
        if name.startswith(_SKIP_PREFIXES):
            continue
        src = os.path.join(src_dir, name)
        if not os.path.isfile(src):
            continue
        if ext_whitelist is not None:
            ext = os.path.splitext(name)[1].lower()
            if ext not in ext_whitelist:
                continue

        dst = os.path.join(dst_dir, name)
        try:
            if _files_identical(src, dst):
                stats["skipped"] += 1
                continue
            shutil.copy2(src, dst)
            stats["copied"] += 1
        except (OSError, shutil.Error) as e:
            msg = "Ошибка копирования %s → %s: %s" % (src, dst, e)
            log.warning(msg, source="asset-importer")
            stats["errors"].append(msg)

    return stats


def _files_identical(a: str, b: str) -> bool:
    """True, если оба файла существуют и совпадают по размеру+sha1."""
    if not os.path.isfile(b):
        return False
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
    except OSError:
        return False
    try:
        return _sha1(a) == _sha1(b)
    except OSError:
        return False


def _sha1(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_zapret_base_path() -> str:
    """Определить /opt/zapret2 из конфига (fallback /opt/zapret2)."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return cfg.get("zapret", "base_path", default="/opt/zapret2") \
            or "/opt/zapret2"
    except Exception:
        return "/opt/zapret2"


# ─── Внутренние хелперы: INI-каталоги ────────────────────────

def _merge_ini_dir(src_dir: str, dst_dir: str) -> dict:
    """
    Merge-импорт каждого *.txt из src_dir в одноимённый файл в dst_dir.

    Использует `catalog_updater._merge_content`, чтобы семантика
    совпадала с апстримом youtubediscord/zapret.
    """
    stats = {"added": 0, "updated": 0, "preserved": 0, "files": []}
    if not os.path.isdir(src_dir):
        return stats

    os.makedirs(dst_dir, exist_ok=True)

    from core.catalog_updater import _merge_content, _read_text

    for name in sorted(os.listdir(src_dir)):
        if name.startswith(_SKIP_PREFIXES):
            continue
        if not name.lower().endswith(".txt"):
            continue

        src = os.path.join(src_dir, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(dst_dir, name)

        remote_content = _read_text(src)
        local_content = _read_text(dst)
        merged, added, updated, preserved = _merge_content(
            local_content, remote_content,
        )

        if merged != local_content:
            try:
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(merged)
            except OSError as e:
                log.warning(
                    "Не удалось записать %s: %s" % (dst, e),
                    source="asset-importer",
                )
                continue

        stats["added"] += added
        stats["updated"] += updated
        stats["preserved"] += preserved
        stats["files"].append({
            "name": name,
            "added": added,
            "updated": updated,
            "preserved": preserved,
        })

    return stats


def _merge_bundled_presets(src_dir: str, dst_file: str) -> dict:
    """
    Merge-импорт winws2-пресетов из src_dir в единый INI-файл dst_file.

    Конвертация (срез --wf-*, префикс `winws2_`) полностью повторяет
    логику catalog_updater, чтобы section_id-ы были сравнимы между
    bundled-импортом и GitHub-обновлением.
    """
    stats = {"added": 0, "updated": 0, "preserved": 0, "files": 0}
    if not os.path.isdir(src_dir):
        return stats

    preset_files: dict = {}
    for name in sorted(os.listdir(src_dir)):
        if name.startswith(_SKIP_PREFIXES):
            continue
        if not name.lower().endswith(".txt"):
            continue
        path = os.path.join(src_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                preset_files[name] = f.read()
        except OSError:
            continue

    if not preset_files:
        return stats

    stats["files"] = len(preset_files)

    from core.catalog_updater import (
        _build_presets_ini,
        _merge_content,
        _read_text,
    )

    remote_content = _build_presets_ini(preset_files)
    local_content = _read_text(dst_file)
    merged, added, updated, preserved = _merge_content(
        local_content, remote_content,
    )

    if merged != local_content:
        try:
            os.makedirs(os.path.dirname(dst_file), exist_ok=True)
            with open(dst_file, "w", encoding="utf-8") as f:
                f.write(merged)
        except OSError as e:
            log.warning(
                "Не удалось записать %s: %s" % (dst_file, e),
                source="asset-importer",
            )
            return stats

    stats["added"] = added
    stats["updated"] = updated
    stats["preserved"] = preserved
    return stats


def _try_reload_catalogs() -> None:
    """Перечитать CatalogManager и StrategyManager, если они уже живые."""
    try:
        from core.catalog_loader import get_catalog_manager
        get_catalog_manager().reload()
    except Exception as e:
        log.debug(
            "asset-importer: не удалось перечитать каталоги: %s" % e,
            source="asset-importer",
        )
    try:
        from core.strategy_builder import get_strategy_manager
        get_strategy_manager().load_strategies()
    except Exception as e:
        log.debug(
            "asset-importer: не удалось перечитать стратегии: %s" % e,
            source="asset-importer",
        )


# ─── CLI (для вызова из install.sh) ───────────────────────────

def _main() -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(
        description="Импорт bundled-ассетов zapret-gui в /opt/zapret2/",
    )
    p.add_argument(
        "--base-path",
        default=None,
        help="Корень zapret2 (default: из конфига или /opt/zapret2)",
    )
    p.add_argument(
        "--only",
        choices=("all", "runtime", "strategies"),
        default="all",
        help="Что импортировать",
    )
    args = p.parse_args()

    if args.only == "runtime":
        result = import_runtime_assets(base_path=args.base_path)
    elif args.only == "strategies":
        result = import_bundled_strategies()
    else:
        result = import_all(base_path=args.base_path)

    if result.get("ok"):
        sys.stderr.write("asset-importer: OK\n")
        return 0
    sys.stderr.write("asset-importer: FAILED\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
