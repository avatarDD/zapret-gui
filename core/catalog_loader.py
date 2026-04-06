# core/catalog_loader.py
"""
Загрузчик INI-каталогов стратегий.

Каталоги — текстовые файлы с нестандартным INI-подобным форматом
(configparser НЕ подходит). Содержат стратегии nfqws2 для
перебора в strategy scanner.

Структура каталогов:
    <APP_DIR>/catalogs/
    ├── basic/
    │   ├── tcp_zapret2_basic.txt
    │   ├── udp_zapret_basic.txt
    │   ├── http80_zapret2_basic.txt
    │   └── discord_voice_zapret2_basic.txt
    ├── advanced/
    │   ├── tcp_zapret2_advanced.txt
    │   ├── udp_zapret2_advanced.txt
    │   ├── http80_zapret2_advanced.txt
    │   ├── tcp_fake_zapret2_advanced.txt
    │   └── discord_voice_zapret2_advanced.txt
    ├── direct/
    │   ├── tcp.txt
    │   ├── udp.txt
    │   ├── http80.txt
    │   └── voice.txt
    └── presets/        ← НЕ сканируется (raw-файлы, конвертированы в JSON)

INI-формат:
    [strategy_id]
    name = Display Name
    author = Author
    label = recommended
    description = Описание
    blobs = blob1, blob2
    --lua-desync=fake:blob=...
    --lua-desync=multisplit:pos=1,midsld

Использование:
    from core.catalog_loader import get_catalog_manager

    cm = get_catalog_manager()
    entries = cm.get_catalog_entries(protocol="tcp", level="basic")
    quick = cm.get_quick_set(protocol="tcp")
    full = cm.get_full_set(protocol="tcp")
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

from core.log_buffer import log
from core.models import CatalogEntry


# WinDivert-специфичные аргументы — фильтруются при парсинге
# (каталоги портированы из Windows-проекта и могут содержать их)
_WINDIVERT_PREFIXES = (
    "--wf-tcp",
    "--wf-udp",
    "--wf-raw",
    "--wf-l3",
    "--wf-ip",
)

# Допустимые значения label
_VALID_LABELS = frozenset({
    "recommended", "experimental", "game",
    "stable", "caution", "deprecated",
})

# Лимиты для наборов стратегий
_QUICK_SET_SIZE = 30
_STANDARD_SET_SIZE = 80

# Уровни, которые НЕ используются scanner-ом
# (builtin — полные конфигурации с --filter-*, не отдельные приёмы desync)
_SCANNER_EXCLUDED_LEVELS = frozenset({"builtin"})

# Директории, которые НЕ содержат INI-каталоги
# (presets/ содержит raw-файлы пресетов, конвертированных в JSON)
_EXCLUDED_DIRS = frozenset({"presets", "__pycache__"})

# Маппинг ключевых слов из имени файла → протокол
# Порядок проверки: сначала явные, потом fallback
_PROTOCOL_KEYWORDS = (
    # UDP-протоколы (проверяются первыми, чтобы "discord_voice" не попал в tcp)
    ("udp", "udp"),
    ("voice", "udp"),
    ("discord", "udp"),
    ("stun", "udp"),
    ("quic", "udp"),
    # TCP-протоколы
    ("tcp", "tcp"),
    ("http80", "tcp"),
    ("http", "tcp"),
    ("tls", "tcp"),
)


# ═══════════════════════════════════════════════════════════
#  Парсер одного INI-файла
# ═══════════════════════════════════════════════════════════

def parse_catalog_file(
    filepath: str,
    protocol: str = "",
    level: str = "",
) -> list[CatalogEntry]:
    """
    Распарсить один INI-файл каталога стратегий.

    Args:
        filepath:  Абсолютный путь к .txt файлу.
        protocol:  Протокол (tcp/udp) — определяется из имени файла если пуст.
        level:     Уровень (basic/advanced/direct).

    Returns:
        Список CatalogEntry.
    """
    if not os.path.isfile(filepath):
        log.warning(
            "Файл каталога не найден: %s" % filepath,
            source="catalog",
        )
        return []

    source_file = os.path.basename(filepath)

    # Определяем protocol из имени файла если не задан
    if not protocol:
        protocol = _guess_protocol(source_file)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (IOError, OSError) as e:
        log.error(
            "Ошибка чтения каталога %s: %s" % (filepath, e),
            source="catalog",
        )
        return []

    return _parse_catalog_content(
        content,
        source_file=source_file,
        protocol=protocol,
        level=level,
    )


def _parse_catalog_content(
    content: str,
    source_file: str = "",
    protocol: str = "",
    level: str = "",
) -> list[CatalogEntry]:
    """
    Распарсить содержимое INI-каталога.

    Формат:
        [section_id]
        name = Display Name
        author = Author
        label = recommended
        description = Описание
        blobs = blob1, blob2
        --arg1=value1
        --arg2=value2

    Строки, начинающиеся с '#' — комментарии.
    Пустые строки — пропускаются.
    WinDivert-аргументы (--wf-*) — фильтруются.
    """
    entries: list[CatalogEntry] = []

    current_id: Optional[str] = None
    current_name = ""
    current_author = ""
    current_label = ""
    current_description = ""
    current_blobs: list[str] = []
    current_args: list[str] = []

    def _flush() -> None:
        nonlocal current_id, current_name, current_author
        nonlocal current_label, current_description
        nonlocal current_blobs, current_args

        if current_id is None:
            return

        # Собираем args (только не-WinDivert)
        filtered_args = [
            a for a in current_args
            if not _is_windivert_arg(a)
        ]

        args_str = "\n".join(filtered_args).strip()

        # Пропускаем стратегии без аргументов
        if not args_str:
            log.debug(
                "Пропущена стратегия без аргументов: [%s] в %s"
                % (current_id, source_file),
                source="catalog",
            )
            return

        entry = CatalogEntry(
            section_id=current_id,
            name=current_name or current_id,
            args=args_str,
            author=current_author,
            label=current_label if current_label in _VALID_LABELS else "",
            description=current_description,
            blobs=list(current_blobs),
            protocol=protocol,
            level=level,
            source_file=source_file,
        )
        entries.append(entry)

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        # Пустые строки и комментарии
        if not stripped or stripped.startswith("#"):
            continue

        # Начало новой секции [section_id]
        if stripped.startswith("[") and stripped.endswith("]"):
            _flush()
            current_id = stripped[1:-1].strip()
            current_name = current_id
            current_author = ""
            current_label = ""
            current_description = ""
            current_blobs = []
            current_args = []
            continue

        # Строки до первой секции — игнорируем
        if current_id is None:
            continue

        # Аргументы nfqws2 (начинаются с --)
        if stripped.startswith("--"):
            current_args.append(stripped)
            continue

        # Метаданные (key = value)
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if key == "name":
                current_name = value
            elif key == "author":
                current_author = value
            elif key == "label":
                current_label = value.lower()
            elif key == "description":
                current_description = value
            elif key == "blobs":
                current_blobs = [
                    b.strip() for b in value.split(",")
                    if b.strip()
                ]

    # Последняя секция
    _flush()

    return entries


def _is_windivert_arg(arg: str) -> bool:
    """Проверить, является ли аргумент WinDivert-специфичным."""
    lower = arg.lower()
    return any(lower.startswith(prefix) for prefix in _WINDIVERT_PREFIXES)


def _guess_protocol(filename: str) -> str:
    """
    Определить протокол из имени файла.

    Маппинг:
        *udp*, *voice*, *discord*, *stun*, *quic* → udp
        *tcp*, *http80*, *http*, *tls* → tcp
        default → tcp

    Проверяет ключевые слова в имени файла.
    """
    name_lower = filename.lower()
    for keyword, proto in _PROTOCOL_KEYWORDS:
        if keyword in name_lower:
            return proto
    return "tcp"  # default


# ═══════════════════════════════════════════════════════════
#  CatalogManager — singleton для работы с каталогами
# ═══════════════════════════════════════════════════════════

class CatalogManager:
    """
    Управление INI-каталогами стратегий.

    Каталоги — read-only данные для strategy scanner.
    Не пересекаются с JSON-стратегиями StrategyManager.
    """

    def __init__(self, catalogs_dir: str = None):
        # <APP_DIR>/catalogs/
        if catalogs_dir:
            self._catalogs_dir = catalogs_dir
        else:
            app_dir = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
            self._catalogs_dir = os.path.join(app_dir, "catalogs")

        self._lock = threading.Lock()
        # Кэш: ключ = "level/protocol" (напр. "basic/tcp"), значение = list[CatalogEntry]
        self._cache: dict[str, list[CatalogEntry]] = {}
        self._loaded = False

    @property
    def catalogs_dir(self) -> str:
        """Путь к директории каталогов."""
        return self._catalogs_dir

    # ─────────────────── Загрузка ───────────────────

    def load_all(self) -> dict[str, list[CatalogEntry]]:
        """
        Загрузить все каталоги из catalogs/.

        Сканирует поддиректории (basic/, advanced/, direct/),
        парсит все .txt файлы.
        Директории из _EXCLUDED_DIRS (presets/ и т.п.) пропускаются.

        Returns:
            Словарь: "level/protocol" → list[CatalogEntry]
            Например: "basic/tcp" → [CatalogEntry, ...]
        """
        with self._lock:
            self._cache.clear()

            if not os.path.isdir(self._catalogs_dir):
                log.warning(
                    "Директория каталогов не найдена: %s" % self._catalogs_dir,
                    source="catalog",
                )
                self._loaded = True
                return {}

            total = 0

            for level in sorted(os.listdir(self._catalogs_dir)):
                # Пропускаем исключённые директории и файлы
                if level in _EXCLUDED_DIRS:
                    continue

                level_dir = os.path.join(self._catalogs_dir, level)
                if not os.path.isdir(level_dir):
                    continue

                for filename in sorted(os.listdir(level_dir)):
                    if not filename.endswith(".txt"):
                        continue
                    # Пропускаем файлы, начинающиеся с _
                    if filename.startswith("_"):
                        continue

                    filepath = os.path.join(level_dir, filename)
                    entries = parse_catalog_file(
                        filepath,
                        protocol="",   # auto-detect from filename
                        level=level,
                    )

                    if not entries:
                        continue

                    # Ключ кэша: "basic/tcp", "advanced/udp", etc.
                    proto = entries[0].protocol or _guess_protocol(filename)
                    cache_key = "%s/%s" % (level, proto)

                    if cache_key in self._cache:
                        self._cache[cache_key].extend(entries)
                    else:
                        self._cache[cache_key] = entries

                    total += len(entries)

            self._loaded = True

            log.info(
                "Каталоги загружены: %d стратегий из %s"
                % (total, self._catalogs_dir),
                source="catalog",
            )

            return dict(self._cache)

    def reload(self) -> dict[str, list[CatalogEntry]]:
        """Перезагрузить каталоги."""
        self._loaded = False
        return self.load_all()

    def _ensure_loaded(self) -> None:
        """Загрузить каталоги если ещё не загружены."""
        if not self._loaded:
            self.load_all()

    # ─────────────────── Getters ───────────────────

    def get_catalog_keys(self) -> list[str]:
        """
        Получить список доступных ключей каталогов.

        Returns:
            ['basic/tcp', 'basic/udp', 'advanced/tcp', 'direct/tcp', ...]
        """
        self._ensure_loaded()
        with self._lock:
            return sorted(self._cache.keys())

    def get_catalog_entries(
        self,
        protocol: str = "tcp",
        level: str = "basic",
    ) -> list[CatalogEntry]:
        """
        Получить стратегии из конкретного каталога.

        Args:
            protocol: "tcp" или "udp"
            level:    "basic", "advanced" или "direct"

        Returns:
            Список CatalogEntry (может быть пустой).
        """
        self._ensure_loaded()
        cache_key = "%s/%s" % (level, protocol)
        with self._lock:
            return list(self._cache.get(cache_key, []))

    def get_all_for_protocol(
        self,
        protocol: str = "tcp",
        exclude_levels: frozenset = frozenset(),
    ) -> list[CatalogEntry]:
        """
        Получить ВСЕ стратегии для протокола (из всех уровней).

        Порядок: basic → advanced → direct (по алфавиту ключей).
        Дубликаты по section_id удаляются (приоритет у первого).

        Args:
            protocol:       "tcp" или "udp"
            exclude_levels: уровни для исключения (напр. {"builtin"})

        Returns:
            Список CatalogEntry.
        """
        self._ensure_loaded()

        seen_ids: set[str] = set()
        result: list[CatalogEntry] = []

        with self._lock:
            for key in sorted(self._cache.keys()):
                if not key.endswith("/%s" % protocol):
                    continue
                # Пропускаем исключённые уровни
                level = key.split("/")[0]
                if level in exclude_levels:
                    continue
                for entry in self._cache[key]:
                    if entry.section_id not in seen_ids:
                        seen_ids.add(entry.section_id)
                        result.append(entry)

        return result

    def get_quick_set(self, protocol: str = "tcp") -> list[CatalogEntry]:
        """
        Быстрый набор стратегий (~30 шт.):
        recommended + первые N из basic.

        Для быстрого сканирования.
        Builtin-стратегии (полные конфигурации) исключаются.
        """
        all_entries = self.get_all_for_protocol(
            protocol,
            exclude_levels=_SCANNER_EXCLUDED_LEVELS,
        )

        # Сначала recommended
        recommended = [e for e in all_entries if e.label == "recommended"]
        # Потом остальные (без recommended)
        others = [e for e in all_entries if e.label != "recommended"]

        result = list(recommended)
        remaining = _QUICK_SET_SIZE - len(result)
        if remaining > 0:
            result.extend(others[:remaining])

        return result[:_QUICK_SET_SIZE]

    def get_standard_set(self, protocol: str = "tcp") -> list[CatalogEntry]:
        """
        Стандартный набор (~80 шт.):
        basic полностью + recommended из advanced.
        """
        self._ensure_loaded()

        basic = self.get_catalog_entries(protocol=protocol, level="basic")
        advanced = self.get_catalog_entries(protocol=protocol, level="advanced")

        seen_ids: set[str] = set()
        result: list[CatalogEntry] = []

        # basic целиком
        for entry in basic:
            if entry.section_id not in seen_ids:
                seen_ids.add(entry.section_id)
                result.append(entry)

        # recommended из advanced
        for entry in advanced:
            if entry.label == "recommended" and entry.section_id not in seen_ids:
                seen_ids.add(entry.section_id)
                result.append(entry)

        # Если мало — добираем из advanced
        if len(result) < _STANDARD_SET_SIZE:
            for entry in advanced:
                if entry.section_id not in seen_ids:
                    seen_ids.add(entry.section_id)
                    result.append(entry)
                if len(result) >= _STANDARD_SET_SIZE:
                    break

        return result[:_STANDARD_SET_SIZE]

    def get_full_set(self, protocol: str = "tcp") -> list[CatalogEntry]:
        """
        Полный набор: все стратегии для протокола.
        Builtin-стратегии (полные конфигурации) исключаются.
        """
        return self.get_all_for_protocol(
            protocol,
            exclude_levels=_SCANNER_EXCLUDED_LEVELS,
        )

    def get_entry_by_id(
        self,
        section_id: str,
        protocol: str = "tcp",
    ) -> Optional[CatalogEntry]:
        """
        Найти стратегию по section_id.

        Returns:
            CatalogEntry или None.
        """
        all_entries = self.get_all_for_protocol(protocol)
        for entry in all_entries:
            if entry.section_id == section_id:
                return entry
        return None

    def search_entries(
        self,
        query: str,
        protocol: str = "",
        limit: int = 50,
    ) -> list[CatalogEntry]:
        """
        Поиск стратегий по имени, автору или описанию.

        Args:
            query:    Строка поиска (регистронезависимая).
            protocol: Фильтр по протоколу ("tcp"/"udp"/"" для всех).
            limit:    Максимум результатов.

        Returns:
            Список найденных CatalogEntry.
        """
        self._ensure_loaded()
        q = query.lower()
        results: list[CatalogEntry] = []

        with self._lock:
            for key in sorted(self._cache.keys()):
                if protocol and not key.endswith("/%s" % protocol):
                    continue
                for entry in self._cache[key]:
                    if (
                        q in entry.name.lower()
                        or q in entry.author.lower()
                        or q in entry.description.lower()
                        or q in entry.section_id.lower()
                    ):
                        results.append(entry)
                        if len(results) >= limit:
                            return results

        return results

    def get_stats(self) -> dict[str, Any]:
        """
        Статистика по каталогам.

        Returns:
            {
                "catalogs": {"basic/tcp": 150, "advanced/tcp": 80, ...},
                "total": 1500,
                "by_protocol": {"tcp": 900, "udp": 600},
                "by_level": {"basic": 500, "advanced": 600, "direct": 400},
            }
        """
        self._ensure_loaded()

        catalogs: dict[str, int] = {}
        by_protocol: dict[str, int] = {}
        by_level: dict[str, int] = {}
        total = 0

        with self._lock:
            for key, entries in self._cache.items():
                count = len(entries)
                catalogs[key] = count
                total += count

                # Разбираем key "level/proto"
                parts = key.split("/", 1)
                if len(parts) == 2:
                    lvl, proto = parts
                    by_protocol[proto] = by_protocol.get(proto, 0) + count
                    by_level[lvl] = by_level.get(lvl, 0) + count

        return {
            "catalogs": catalogs,
            "total": total,
            "by_protocol": by_protocol,
            "by_level": by_level,
        }

    # ─────────────────── Args builder ───────────────────

    @staticmethod
    def build_nfqws_args_from_entry(entry: CatalogEntry) -> list[str]:
        """
        Собрать аргументы nfqws2 из записи каталога.

        Каждая строка args — это один аргумент (--lua-desync=...).
        Результат — плоский список строк для передачи в nfqws2.

        Args:
            entry: CatalogEntry из INI-каталога.

        Returns:
            ['--lua-desync=fake:blob=...', '--lua-desync=multisplit:...']
        """
        return entry.get_args_list()

    @staticmethod
    def resolve_paths_in_args(
        args: list[str],
        lua_path: str = "/opt/zapret2/lua",
        lists_path: str = "/opt/zapret2/lists",
    ) -> list[str]:
        """
        Резолвить специальные пути в аргументах.

        Маппинг:
            @lua/  → lua_path
            lists/ → lists_path (в начале значения аргумента)

        Args:
            args:       Список аргументов.
            lua_path:   Путь к Lua-скриптам.
            lists_path: Путь к спискам.

        Returns:
            Список аргументов с резолвленными путями.
        """
        resolved = []
        for arg in args:
            a = arg
            if "@lua/" in a:
                a = a.replace("@lua/", lua_path.rstrip("/") + "/")
            if "=lists/" in a:
                a = a.replace("=lists/", "=" + lists_path.rstrip("/") + "/")
            resolved.append(a)
        return resolved


# ═══════════════════════════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════════════════════════

_catalog_manager: Optional[CatalogManager] = None
_catalog_lock = threading.Lock()


def get_catalog_manager() -> CatalogManager:
    """Получить глобальный экземпляр CatalogManager."""
    global _catalog_manager
    if _catalog_manager is None:
        with _catalog_lock:
            if _catalog_manager is None:
                _catalog_manager = CatalogManager()
    return _catalog_manager
