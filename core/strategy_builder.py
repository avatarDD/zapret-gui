import os
import json
import copy
import re
import threading
from core.log_buffer import log
class StrategyManager:
    def __init__(self, base_dir: str = None):
        self._base_dir = base_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config", "strategies"
        )
        self._builtin_dir = os.path.join(self._base_dir, "builtin")
        self._user_dir = os.path.join(self._base_dir, "user")
        self._lock = threading.Lock()
        self._cache = {}
        self._loaded = False
    def load_strategies(self) -> list:
        with self._lock:
            self._cache.clear()
            builtin_count = 0
            for s in self._load_dir(self._builtin_dir, is_builtin=True):
                self._cache[s["id"]] = s
                builtin_count += 1
            user_count = 0
            for s in self._load_dir(self._user_dir, is_builtin=False):
                self._cache[s["id"]] = s
                user_count += 1
            self._loaded = True
            log.info(
                "Стратегии загружены: %d builtin, %d user, %d всего" % (
                    builtin_count, user_count, len(self._cache)
                ),
                source="strategies"
            )
            return self._get_sorted_list()
    def _load_dir(self, dir_path: str, is_builtin: bool) -> list:
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
    def get_strategies(self) -> list:
        if not self._loaded:
            self.load_strategies()
        with self._lock:
            return self._get_sorted_list()
    def get_strategy(self, strategy_id: str) -> dict:
        if not self._loaded:
            self.load_strategies()
        with self._lock:
            s = self._cache.get(strategy_id)
            return copy.deepcopy(s) if s else None
    def _get_sorted_list(self) -> list:
        items = list(self._cache.values())
        items.sort(key=lambda s: (0 if s.get("is_builtin") else 1, s.get("name", "")))
        return [self._clean_for_api(s) for s in items]
    def _clean_for_api(self, strategy: dict) -> dict:
        """Убрать внутренние поля перед отдачей в API."""
        s = copy.deepcopy(strategy)
        s.pop("_filepath", None)
        return s
    def save_user_strategy(self, data: dict) -> dict:
        if not self._validate_strategy(data):
            log.error("Невалидная стратегия", source="strategies")
            return None
        with self._lock:
            sid = data["id"]
            sid = re.sub(r'[^a-zA-Z0-9_-]', '_', sid)
            data["id"] = sid
            data["is_builtin"] = False
            data.setdefault("version", 1)
            data.setdefault("type", "combined")
            os.makedirs(self._user_dir, exist_ok=True)
            filepath = os.path.join(self._user_dir, "%s.json" % sid)
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
    def build_nfqws_args(self, strategy: dict,
                         hostlist_path: str = None) -> list:
        if not strategy or "profiles" not in strategy:
            return []
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
            if i > 0:
                all_args.append("--new")
            profile_args = self._parse_profile_args(profile["args"])
            if hostlist_path and os.path.isfile(hostlist_path):
                profile_args = self._inject_hostlist(
                    profile_args, hostlist_path
                )
            all_args.extend(profile_args)
        return all_args
    def _parse_profile_args(self, args_str: str) -> list:
        if not args_str:
            return []
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
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        binary = cfg.get("zapret", "nfqws_binary",
                         default="/opt/zapret2/nfq2/nfqws2")
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
        strategy_args = self.build_nfqws_args(strategy, hostlist_path)
        parts.extend(strategy_args)
        return " \\\n  ".join(parts)
_strategy_manager = None
_sm_lock = threading.Lock()
def get_strategy_manager() -> StrategyManager:
    global _strategy_manager
    if _strategy_manager is None:
        with _sm_lock:
            if _strategy_manager is None:
                _strategy_manager = StrategyManager()
    return _strategy_manager
