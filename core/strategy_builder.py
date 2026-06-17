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


# ── Авто-ограничение «голого приёма» (SKILL.md §1/§2/§3) ────────────────────
# Стратегия-приём вида «--lua-desync=fake:...» без --filter-* десинхронизирует
# ВЕСЬ трафик очереди (skill §4 п.5). По конвенции проекта (как
# StrategyScanner._wrap_trick_args) такой приём оборачивается фильтром,
# выведенным из протокола/порта — это не «отсебятина», а штатное ограничение.
# Профили, у которых уже есть --filter-*/--filter-l7 (в т.ч. полные пресеты и
# реконструкции из blockcheck2 с фильтром), НЕ трогаем.
_FILTER_FLAG_RE = re.compile(r"^--filter-(?:tcp|udp|l7)\b")
# payload-тип → (proto, порт, l7); значения согласованы с дефолтами
# core.scan_targets.ScanTarget.
_PAYLOAD_FILTER = {
    "tls_client_hello": ("tcp", "443", "tls"),
    "http_req":         ("tcp", "80",  "http"),
    "http_reply":       ("tcp", "80",  "http"),
    "quic_initial":     ("udp", "443", "quic"),
}


def autowrap_bare_trick(profile_args: list) -> list:
    """Ограничить «голый приём» фильтром, выведенным из однозначного --payload.

    Возвращает profile_args без изменений, если:
      • нет --lua-desync; либо
      • уже есть какой-либо --filter-tcp/--filter-udp/--filter-l7 (профиль уже
        ограничен или это полный пресет); либо
      • --payload отсутствует или неоднозначен (`all`, пусто, неизвестный тип).
    Последнее — намеренно: каталожные QUIC/UDP-приёмы идут с `--payload=all` и
    `blob=quic_*`; угадывать протокол по умолчанию (TCP/TLS) нельзя — это
    сломало бы их скоуп. Ограничиваем ТОЛЬКО при явном
    tls_client_hello/http_req/http_reply/quic_initial.
    """
    if not any(a.startswith("--lua-desync") for a in profile_args):
        return profile_args
    if any(_FILTER_FLAG_RE.match(a) for a in profile_args):
        return profile_args

    payload = None
    for a in profile_args:
        if a.startswith("--payload="):
            payload = a.split("=", 1)[1].split(",")[0].strip()
            break

    if payload not in _PAYLOAD_FILTER:
        return profile_args

    proto, port, l7 = _PAYLOAD_FILTER[payload]
    return ["--filter-%s=%s" % (proto, port),
            "--filter-l7=%s" % l7] + profile_args


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
        # Сортировка: featured (флагман — z2k auto) → builtin → по имени.
        # featured поднимает «витринную» стратегию в самый верх списка/группы,
        # чтобы рекомендованный автоподбор был на виду, а не терялся среди сотен.
        items.sort(key=lambda s: (
            0 if s.get("featured") else 1,
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

        # Флаги списков (--hostlist / --hostlist-auto / --hostlist-exclude),
        # которые надо подмешать в каждый профиль.
        #   • hostlist_path задан явно (сканер) → один --hostlist=<path>
        #     (обратная совместимость);
        #   • иначе — по режиму filter.mode из конфига.
        if hostlist_path is not None:
            list_flags = (["--hostlist=%s" % hostlist_path]
                          if os.path.isfile(hostlist_path) else [])
        else:
            list_flags = self._compute_list_flags()

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

            # Авто-ограничение «голого приёма» фильтром (SKILL §1/§2/§3):
            # приём без --filter-* иначе десинхронизирует весь трафик очереди.
            profile_args = autowrap_bare_trick(profile_args)

            # Вставляем флаги списков перед --payload (если профиль их ещё
            # не содержит).
            if list_flags:
                profile_args = self._inject_list_flags(
                    profile_args, list_flags
                )

            all_args.extend(profile_args)

        # Регистрация именованных blob'ов. Компактные каталоги (basic/advanced)
        # ссылаются на blob=tls_google и т.п. через метаполе `blobs =`, но саму
        # декларацию --blob=NAME:@bin/file.bin не несут — без неё nfqws2 шлёт
        # ПУСТОЙ fake и обход не работает. Подмешиваем недостающие декларации
        # ОДИН раз в начало (blob-декларации в nfqws2 глобальны, до первого
        # --new). Уже объявленные в стратегии (полные winws2-пресеты) не дублируем.
        from core.blob_registry import build_blob_declarations
        blob_decls = build_blob_declarations(all_args)
        if blob_decls:
            all_args = blob_decls + all_args

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
                              default="/opt/zapret2/files/fake"),
            ipset_path=_cfg.get("zapret", "ipset_path",
                                default="/opt/zapret2/ipset"),
        )

        return all_args

    def _parse_profile_args(self, args_str: str) -> list:
        """
        Разобрать строку аргументов профиля в список argv.

        Кавычки используются ТОЛЬКО для группировки (пробел внутри кавычек не
        разрывает токен), но сами символы кавычек СОХРАНЯЮТСЯ в токене. Это
        критично для inline-Lua в ``--lua-init=``: одинарные кавычки там —
        строковый литерал Lua, напр. ``--lua-init=fake_default_tls=tls_mod(
        fake_default_tls,'rnd')``. Если их вырезать, nfqws2 получит
        ``tls_mod(...,rnd)`` и Lua упадёт с «bad argument #2 to 'tls_mod'
        (string expected, got nil)» — rnd станет неопределённой переменной.

        argv уходит в nfqws2 через subprocess списком (без shell), поэтому
        кавычки доходят дословно — повторной интерпретации оболочкой нет.
        """
        # Делегируем общей quote-aware токенизации (core.models.tokenize_args):
        # каталоги (CatalogManager.build_nfqws_args_from_entry) и профили
        # стратегий разбираются ОДНИМ и тем же протестированным кодом.
        from core.models import tokenize_args
        return tokenize_args(args_str)

    @staticmethod
    def _compute_list_flags() -> list:
        """Вычислить флаги списков по режиму filter.mode.

        ВАЖНО (поведение по умолчанию): include-список ``other.txt`` БОЛЬШЕ НЕ
        подмешивается автоматически ни в одном режиме. Стратегия по умолчанию
        применяется ко ВСЕМУ трафику на своих портах (``--filter-*``); circular
        сам подбирает приём per-домен. Если нужно сузить — пользователь явно
        добавляет ``--hostlist=`` / ``--hostlist-domains=`` в саму стратегию
        (в редакторе это подсказка-INFO, не ошибка).

        Режимы (config.filter.mode):
          • none          — без include-списков (дефолт): десинк на весь
                            трафик под ``--filter-*``;
          • hostlist      — то же, что none (other.txt не подмешивается;
                            оставлено для совместимости старых конфигов);
          • autohostlist  — + авто-список auto.txt, куда nfqws2 сам добавляет
                            недоступные домены;
          • ipset         — фильтрация по IP (``--ipset``), hostlist не трогаем.

        Предохранитель (отдельно от include-логики): exclude ``netrogat.txt``
        (банки/госуслуги/vk и т.п. — их НЕ десинкаем, чтобы не сломать).
        Включён по умолчанию, отключается ``filter.protect_excluded=false``.
        Применяется во всех режимах, кроме ipset; файл добавляется только если
        существует.
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        mode = (cfg.get("filter", "mode", default="none") or "none").lower()
        lists_path = cfg.get("zapret", "lists_path",
                             default="/opt/zapret2/lists")

        # ipset-режим: фильтрация по IP, hostlist-флаги не подмешиваем.
        if mode == "ipset":
            return []

        flags = []

        # Автохостлист: nfqws2 сам копит недоступные домены в auto.txt.
        if mode in ("autohostlist", "auto"):
            auto = os.path.join(lists_path, "auto.txt")
            flags.append("--hostlist-auto=%s" % auto)

        # Предохранитель: не десинкаем банки/госуслуги/vk (netrogat.txt).
        # Это НЕ сужающий include, а защита от поломки критичных сервисов.
        if cfg.get("filter", "protect_excluded", default=True):
            netrogat = os.path.join(lists_path, "netrogat.txt")
            if os.path.isfile(netrogat):
                flags.append("--hostlist-exclude=%s" % netrogat)

        return flags

    @staticmethod
    def _inject_list_flags(args: list, list_flags: list) -> list:
        """Вставить флаги списков в профиль (после --filter-*, перед --payload).

        Если профиль уже содержит какой-либо --hostlist*/--ipset* — не трогаем
        (полные winws2-пресеты несут свои списки).
        """
        for a in args:
            if a.startswith("--hostlist") or a.startswith("--ipset"):
                return args  # профиль сам задаёт списки

        insert_pos = 0
        for i, a in enumerate(args):
            if a.startswith("--filter-"):
                insert_pos = i + 1
            elif a.startswith("--payload"):
                insert_pos = i
                break

        result = list(args)
        for j, flag in enumerate(list_flags):
            result.insert(insert_pos + j, flag)
        return result

    def build_preview_command(self, strategy: dict,
                              hostlist_path: str = None) -> str:
        """
        Собрать превью полной команды nfqws2 (для отображения в UI).

        Превью обязано совпадать с тем, что реально запускается. Поэтому argv
        собирается ЧЕРЕЗ NFQWSManager.compose_command() — единый источник
        истины (то же, что live-запуск и автозапуск): base-args
        (--user/--fwmark/--qnum[/--debug][/--bind-fix*]), условный lua-init
        (core+extension, только при наличии --lua-desync и существующих
        файлов, с дедупом), единый --hostlist-слой и сами strategy_args.

        Returns:
            Строка вида "nfqws2 --user=nobody ... --filter-tcp=443 ..."
        """
        from core.nfqws_manager import get_nfqws_manager

        # strategy args (с blob-декларациями и резолвом путей)
        strategy_args = self.build_nfqws_args(strategy, hostlist_path)

        # Полная команда — тем же путём, что и реальный запуск.
        full_args = get_nfqws_manager().compose_command(strategy_args)

        return " \\\n  ".join(full_args)


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
        "featured": bool(getattr(entry, "featured", False)),
        "blobs": list(getattr(entry, "blobs", []) or []),
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
