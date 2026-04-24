# core/strategy_builder.py
"""
Менеджер стратегий (Вариант В — единый источник).

Архитектура:
    catalogs/*.txt  — ЕДИНСТВЕННЫЙ источник всех builtin-стратегий (INI, read-only)
    config/strategies/user/*.json  — только пользовательские стратегии (CRUD)

Builtin-стратегии загружаются из CatalogManager и конвертируются
в формат strategy-dict с profiles[]. User-стратегии хранятся в JSON.

При совпадении id — user-стратегия перезаписывает builtin.

Использование:
    from core.strategy_builder import get_strategy_manager

    sm = get_strategy_manager()
    strategies = sm.get_strategies()
    strategy = sm.get_strategy("tcp_default")
    args = sm.build_nfqws_args(strategy, hostlist_path="/opt/zapret2/lists/other.txt")
    sm.save_user_strategy(strategy_data)
    sm.delete_user_strategy("my_custom")
"""

import os
import json
import copy
import re
import threading

from core.log_buffer import log


class StrategyManager:
    """
    Загрузка, хранение и сборка стратегий.

    Единый источник builtin-стратегий — INI-каталоги (CatalogManager).
    User-стратегии хранятся в config/strategies/user/*.json.
    """

    def __init__(self, base_dir: str = None):
        self._base_dir = base_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config", "strategies"
        )
        self._user_dir = os.path.join(self._base_dir, "user")
        self._lock = threading.Lock()
        self._cache = {}       # id → strategy dict
        self._loaded = False

    # ─────────────────── Loading ───────────────────

    def load_strategies(self) -> list:
        """
        Загрузить все стратегии: builtin из каталогов + user из JSON.

        User-стратегии перезаписывают builtin по id.

        Returns:
            Список словарей стратегий.
        """
        with self._lock:
            self._cache.clear()

            # 1) Builtin — из CatalogManager (INI-каталоги)
            builtin_count = self._load_from_catalogs()

            # 2) User (JSON, перезаписывает builtin по id)
            user_count = 0
            for s in self._load_json_dir(self._user_dir, is_builtin=False):
                self._cache[s["id"]] = s
                user_count += 1

            self._loaded = True

            log.info(
                "Стратегии загружены: %d из каталогов, %d user, %d всего" % (
                    builtin_count, user_count, len(self._cache)
                ),
                source="strategies"
            )

            return self._get_sorted_list()

    def _load_from_catalogs(self) -> int:
        """
        Загрузить builtin-стратегии из CatalogManager.

        Каждая CatalogEntry конвертируется в strategy-dict с profiles[].

        Returns:
            Количество загруженных стратегий.
        """
        try:
            from core.catalog_loader import get_catalog_manager
            cm = get_catalog_manager()
        except ImportError:
            log.warning(
                "CatalogManager недоступен, builtin-стратегии не загружены",
                source="strategies",
            )
            return 0

        count = 0
        # Загружаем все каталоги
        for key in cm.get_catalog_keys():
            for entry in cm.get_catalog_entries(
                protocol=key.split("/")[-1],
                level=key.split("/")[0],
            ):
                strategy = _catalog_entry_to_strategy(entry)
                if strategy and strategy["id"] not in self._cache:
                    self._cache[strategy["id"]] = strategy
                    count += 1

        return count

    def _load_json_dir(self, dir_path: str, is_builtin: bool) -> list:
        """Загрузить стратегии из директории JSON-файлов."""
        strategies = []
        if not os.path.isdir(dir_path):
            return strategies

        for filename in sorted(os.listdir(dir_path)):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(dir_path, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if self._validate_strategy(data):
                    data["is_builtin"] = is_builtin
                    data["_filepath"] = filepath
                    strategies.append(data)
            except (json.JSONDecodeError, IOError) as e:
                log.warning(
                    "Ошибка загрузки стратегии %s: %s" % (filename, e),
                    source="strategies"
                )

        return strategies

    def _validate_strategy(self, data: dict) -> bool:
        """Базовая валидация формата стратегии."""
        if not isinstance(data, dict):
            return False
        if not data.get("id") or not data.get("name"):
            return False
        if "profiles" not in data or not isinstance(data["profiles"], list):
            return False
        for p in data["profiles"]:
            if not isinstance(p, dict):
                return False
            if not p.get("id") or "args" not in p:
                return False
        return True

    # ─────────────────── Getters ───────────────────

    def get_strategies(self) -> list:
        """Получить список всех стратегий (загружает если не загружены)."""
        if not self._loaded:
            self.load_strategies()
        with self._lock:
            return self._get_sorted_list()

    def get_strategy(self, strategy_id: str) -> dict:
        """
        Получить стратегию по ID.

        Returns:
            dict стратегии или None.
        """
        if not self._loaded:
            self.load_strategies()
        with self._lock:
            s = self._cache.get(strategy_id)
            return copy.deepcopy(s) if s else None

    def _get_sorted_list(self) -> list:
        """Отсортированный список стратегий (builtin первыми)."""
        items = list(self._cache.values())
        # Сортировка: builtin первыми, затем по имени
        items.sort(key=lambda s: (
            0 if s.get("is_builtin") else 1,
            s.get("name", ""),
        ))
        return [self._clean_for_api(s) for s in items]

    def _clean_for_api(self, strategy: dict) -> dict:
        """Убрать внутренние поля перед отдачей в API."""
        s = copy.deepcopy(strategy)
        s.pop("_filepath", None)
        return s

    # ─────────────────── CRUD (user only) ───────────────────

    def save_user_strategy(self, data: dict) -> dict:
        """
        Сохранить пользовательскую стратегию.

        Если id совпадает с builtin — создаётся user-override.

        Args:
            data: Словарь стратегии (должен содержать id, name, profiles).

        Returns:
            Сохранённая стратегия или None при ошибке.
        """
        if not self._validate_strategy(data):
            log.error("Невалидная стратегия", source="strategies")
            return None

        with self._lock:
            sid = data["id"]

            # Санитизация id
            sid = re.sub(r'[^a-zA-Z0-9_-]', '_', sid)
            data["id"] = sid

            data["is_builtin"] = False
            data.setdefault("version", 1)
            data.setdefault("type", "combined")

            # Сохраняем файл
            os.makedirs(self._user_dir, exist_ok=True)
            filepath = os.path.join(self._user_dir, "%s.json" % sid)

            # Не пишем служебные поля
            save_data = {k: v for k, v in data.items()
                         if k not in ("is_builtin", "_filepath")}

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(save_data, f, indent=2, ensure_ascii=False)
            except (IOError, OSError) as e:
                log.error("Ошибка сохранения стратегии: %s" % e,
                          source="strategies")
                return None

            data["_filepath"] = filepath
            self._cache[sid] = data

            log.success("Стратегия сохранена: %s" % data["name"],
                        source="strategies")
            return self._clean_for_api(data)

    def delete_user_strategy(self, strategy_id: str) -> bool:
        """
        Удалить пользовательскую стратегию.

        Builtin-стратегии удалить нельзя.

        Returns:
            True если удалено.
        """
        with self._lock:
            strategy = self._cache.get(strategy_id)
            if not strategy:
                log.warning("Стратегия не найдена: %s" % strategy_id,
                            source="strategies")
                return False

            if strategy.get("is_builtin"):
                log.warning("Нельзя удалить встроенную стратегию: %s" % strategy_id,
                            source="strategies")
                return False

            # Удаляем файл
            filepath = strategy.get("_filepath")
            if filepath and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except OSError as e:
                    log.error("Ошибка удаления файла: %s" % e,
                              source="strategies")
                    return False

            del self._cache[strategy_id]

            log.info("Стратегия удалена: %s" % strategy_id,
                     source="strategies")
            return True

    # ─────────────────── Args Builder ───────────────────

    def build_nfqws_args(self, strategy: dict,
                         hostlist_path: str = None) -> list:
        """
        Собрать аргументы nfqws2 из стратегии.

        Берёт включённые профили, вставляет --hostlist в каждый,
        объединяет через --new.

        Args:
            strategy:      Словарь стратегии.
            hostlist_path:  Путь к hostlist-файлу (или None).

        Returns:
            Список строк-аргументов для NFQWSManager.start().
        """
        if not strategy or "profiles" not in strategy:
            return []

        # Определяем hostlist из конфига если не задан
        if hostlist_path is None:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            lists_path = cfg.get("zapret", "lists_path",
                                 default="/opt/zapret2/lists")
            hostlist_path = os.path.join(lists_path, "other.txt")

        enabled_profiles = [
            p for p in strategy["profiles"]
            if p.get("enabled", True)
        ]

        if not enabled_profiles:
            log.warning("Нет включённых профилей в стратегии: %s" %
                        strategy.get("name", "?"), source="strategies")
            return []

        all_args = []

        for i, profile in enumerate(enabled_profiles):
            # Разделитель --new между профилями
            if i > 0:
                all_args.append("--new")

            # Парсим args из профиля
            profile_args = self._parse_profile_args(profile["args"])

            # Вставляем --hostlist= перед --payload (если есть hostlist и
            # профиль содержит filter)
            if hostlist_path and os.path.isfile(hostlist_path):
                profile_args = self._inject_hostlist(
                    profile_args, hostlist_path
                )

            all_args.extend(profile_args)

        # Резолвим @lua/, @bin/, lists/ → абсолютные пути zapret2
        from core.catalog_loader import CatalogManager
        from core.config_manager import get_config_manager
        _cfg = get_config_manager()
        all_args = CatalogManager.resolve_paths_in_args(
            all_args,
            lua_path=_cfg.get("zapret", "lua_path",
                              default="/opt/zapret2/lua"),
            lists_path=_cfg.get("zapret", "lists_path",
                                default="/opt/zapret2/lists"),
            bin_path=_cfg.get("zapret", "bin_path",
                              default="/opt/zapret2/bin"),
        )

        return all_args

    def _parse_profile_args(self, args_str: str) -> list:
        """
        Разобрать строку аргументов профиля в список.

        Поддерживает аргументы с пробелами внутри кавычек.
        """
        if not args_str:
            return []

        # Простой парсинг: разбиваем по пробелам, но учитываем кавычки
        result = []
        current = ""
        in_quote = None

        for char in args_str:
            if char in ('"', "'") and in_quote is None:
                in_quote = char
                continue
            elif char == in_quote:
                in_quote = None
                continue
            elif char == ' ' and in_quote is None:
                if current:
                    result.append(current)
                    current = ""
                continue
            current += char

        if current:
            result.append(current)

        return result

    def _inject_hostlist(self, args: list, hostlist_path: str) -> list:
        """
        Вставить --hostlist=path в список аргументов профиля.

        Вставляет после --filter-* аргументов, перед --payload.
        Если --hostlist уже есть — не дублируем.
        """
        # Проверяем: не содержит ли уже hostlist
        for a in args:
            if a.startswith("--hostlist=") or a.startswith("--hostlist-exclude="):
                return args  # Уже есть

        # Ищем позицию: после последнего --filter-* и перед --payload
        insert_pos = 0
        for i, a in enumerate(args):
            if a.startswith("--filter-"):
                insert_pos = i + 1
            elif a.startswith("--payload"):
                insert_pos = i
                break

        result = list(args)
        result.insert(insert_pos, "--hostlist=%s" % hostlist_path)
        return result

    def build_preview_command(self, strategy: dict,
                              hostlist_path: str = None) -> str:
        """
        Собрать превью полной команды nfqws2 (для отображения в UI).

        Returns:
            Строка вида "nfqws2 --user=nobody ... --filter-tcp=443 ..."
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        binary = cfg.get("zapret", "nfqws_binary",
                         default="/opt/zapret2/nfq2/nfqws2")

        # base args
        parts = [binary]

        user = cfg.get("nfqws", "user", default="nobody")
        mark = cfg.get("nfqws", "desync_mark", default="0x40000000")
        qnum = cfg.get("nfqws", "queue_num", default=300)

        parts.append("--user=%s" % user)
        parts.append("--fwmark=%s" % mark)
        parts.append("--qnum=%d" % int(qnum))

        lua_path = cfg.get("zapret", "lua_path", default="/opt/zapret2/lua")
        for lf in ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"]:
            parts.append("--lua-init=@%s/%s" % (lua_path, lf))

        # strategy args
        strategy_args = self.build_nfqws_args(strategy, hostlist_path)
        parts.extend(strategy_args)

        return " \\\n  ".join(parts)


# ═══════════════════════════════════════════════════════════
#  Конвертер: CatalogEntry → strategy dict
# ═══════════════════════════════════════════════════════════

def _catalog_entry_to_strategy(entry) -> dict:
    """
    Конвертировать CatalogEntry из INI-каталога в strategy dict.

    Стратегия из каталога может содержать:
    - Простые args (только --lua-desync=...)
    - Полные args (--filter-tcp=... --lua-desync=... --new --filter-udp=...)

    Args с --new разбиваются на отдельные profiles.
    Args без --filter-* оборачиваются в один profile.
    """
    args_list = entry.get_args_list()
    if not args_list:
        return None

    # Разбиваем по --new на секции (profiles)
    sections = []
    current = []
    for arg in args_list:
        if arg == "--new":
            if current:
                sections.append(current)
                current = []
        else:
            current.append(arg)
    if current:
        sections.append(current)

    # Строим profiles
    profiles = []
    for idx, section_args in enumerate(sections):
        prof_id, prof_name = _detect_profile_info(section_args, idx)
        profiles.append({
            "id": prof_id,
            "name": prof_name,
            "enabled": True,
            "args": " ".join(section_args),
        })

    if not profiles:
        return None

    strategy = {
        "id": entry.section_id,
        "name": entry.name,
        "description": entry.description,
        "type": "combined" if len(profiles) > 1 else "single",
        "version": 1,
        "is_builtin": True,
        "source": "catalog",
        "level": entry.level,
        "label": entry.label,
        "author": entry.author,
        "protocol": entry.protocol,
        "profiles": profiles,
    }

    return strategy


def _detect_profile_info(args: list, idx: int) -> tuple:
    """
    Определить id и имя профиля из его аргументов.

    Returns:
        (profile_id, profile_name)
    """
    for arg in args:
        if arg.startswith("--filter-tcp="):
            port = arg.split("=", 1)[1]
            if port == "80":
                return ("http%d" % (idx + 1), "HTTP (порт 80)")
            return ("tcp%d" % (idx + 1), "TCP (порты %s)" % port)
        elif arg.startswith("--filter-udp="):
            port = arg.split("=", 1)[1]
            return ("udp%d" % (idx + 1), "UDP (порты %s)" % port)
        elif arg.startswith("--filter-l3="):
            ver = arg.split("=", 1)[1]
            return ("%s_%d" % (ver, idx + 1), ver.upper())

    # Нет фильтра — одиночная стратегия desync
    return ("profile%d" % (idx + 1), "Profile %d" % (idx + 1))


# ═══════════════════ Singleton ═══════════════════

_strategy_manager = None
_sm_lock = threading.Lock()


def get_strategy_manager() -> StrategyManager:
    """Получить глобальный экземпляр StrategyManager."""
    global _strategy_manager
    if _strategy_manager is None:
        with _sm_lock:
            if _strategy_manager is None:
                _strategy_manager = StrategyManager()
    return _strategy_manager
