import os
import json
import copy
import threading
from core.log_buffer import log
DEFAULT_CONFIG_DIR = "/opt/etc/zapret-gui"
DEFAULT_CONFIG_FILE = "settings.json"
DEFAULT_CONFIG = {
    "version": 1,
    "zapret": {
        "base_path": "/opt/zapret2",
        "nfqws_binary": "/opt/zapret2/nfq2/nfqws2",
        "lua_path": "/opt/zapret2/lua",
        "lists_path": "/opt/zapret2/lists",
    },
    "gui": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": False,
        "auth_enabled": False,
        "auth_user": "admin",
        "auth_password": "",
    },
    # --- Настройки nfqws ---
    "nfqws": {
        "queue_num": 300,
        "ports_tcp": "80,443",
        "ports_udp": "443",
        "tcp_pkt_out": 20,
        "tcp_pkt_in": 10,
        "udp_pkt_out": 5,
        "udp_pkt_in": 3,
        "desync_mark": "0x40000000",
        "desync_mark_postnat": "0x20000000",
        "user": "nobody",
        "disable_ipv6": True,
    },
    "firewall": {
        "type": "auto",
        "apply_on_start": True,
        "flowoffload": "donttouch",
        "postnat": True,
    },
    "filter": {
        "mode": "hostlist",
    },
    "strategy": {
        "current_id": None,
        "current_name": None,
        "favorites": [],
    },
    "autostart": {
        "enabled": False,
        "method": "initd",
    },
    "logging": {
        "max_entries": 2000,
        "file_enabled": True,
        "file_path": "/tmp/zapret-gui.log",
        "level": "INFO",
    },
    "interfaces": {
        "wan": "",   # Авто-определение если пусто
        "wan6": "",
        "lan": "",
    },
}
class ConfigManager:
    """
    Потокобезопасный менеджер конфигурации.
    Загружает настройки из JSON, мержит с дефолтами (чтобы новые
    поля автоматически добавлялись при обновлении), сохраняет обратно.
    """
    def __init__(self, config_dir: str = None, config_file: str = None):
        self._config_dir = config_dir or DEFAULT_CONFIG_DIR
        self._config_file = config_file or DEFAULT_CONFIG_FILE
        self._config_path = os.path.join(self._config_dir, self._config_file)
        self._lock = threading.Lock()
        self._config = {}
        self._loaded = False
    @property
    def path(self) -> str:
        return self._config_path
    def load(self) -> dict:
        """
        Загрузить конфигурацию. Если файла нет — создать с дефолтами.
        Новые поля из DEFAULT_CONFIG добавляются автоматически.
        """
        with self._lock:
            # Начинаем с глубокой копии дефолтов
            self._config = copy.deepcopy(DEFAULT_CONFIG)
            if os.path.exists(self._config_path):
                try:
                    with open(self._config_path, "r", encoding="utf-8") as f:
                        saved = json.load(f)
                    self._deep_merge(self._config, saved)
                    log.info(f"Конфигурация загружена: {self._config_path}",
                             source="config")
                except (json.JSONDecodeError, IOError) as e:
                    log.error(f"Ошибка чтения конфигурации: {e}", source="config")
                    log.warning("Используются настройки по умолчанию",
                                source="config")
            else:
                log.info("Конфигурация не найдена, создаём с дефолтами",
                         source="config")
                self._save_locked()
            self._loaded = True
            return self._config
    def save(self) -> bool:
        with self._lock:
            return self._save_locked()
    def _save_locked(self) -> bool:
        try:
            os.makedirs(self._config_dir, exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except (IOError, OSError) as e:
            log.error(f"Не удалось сохранить конфигурацию: {e}", source="config")
            return False
    def get(self, *keys, default=None):
        with self._lock:
            value = self._config
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            return value
    def set(self, *args):
        if len(args) < 2:
            raise ValueError("Нужно минимум 2 аргумента: ключ и значение")
        keys = args[:-1]
        value = args[-1]
        with self._lock:
            target = self._config
            for key in keys[:-1]:
                if key not in target or not isinstance(target[key], dict):
                    target[key] = {}
                target = target[key]
            target[keys[-1]] = value
    def get_all(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._config)
    def update_section(self, section: str, data: dict) -> bool:
        with self._lock:
            if section in self._config and isinstance(self._config[section], dict):
                self._config[section].update(data)
                return True
            return False
    def reset(self) -> dict:
        with self._lock:
            self._config = copy.deepcopy(DEFAULT_CONFIG)
            self._save_locked()
            log.info("Конфигурация сброшена к дефолтам", source="config")
            return copy.deepcopy(self._config)
    def export_json(self) -> str:
        with self._lock:
            return json.dumps(self._config, indent=2, ensure_ascii=False)
    def import_json(self, json_str: str) -> bool:
        try:
            data = json.loads(json_str)
            if not isinstance(data, dict):
                raise ValueError("Конфигурация должна быть JSON-объектом")
            with self._lock:
                self._config = copy.deepcopy(DEFAULT_CONFIG)
                self._deep_merge(self._config, data)
                self._save_locked()
            log.info("Конфигурация импортирована", source="config")
            return True
        except (json.JSONDecodeError, ValueError) as e:
            log.error(f"Ошибка импорта конфигурации: {e}", source="config")
            return False
    @staticmethod
    def _deep_merge(base: dict, override: dict):
        for key, value in override.items():
            if (key in base
                    and isinstance(base[key], dict)
                    and isinstance(value, dict)):
                ConfigManager._deep_merge(base[key], value)
            else:
                base[key] = value
_config_manager = ConfigManager()
def get_config_manager() -> ConfigManager:
    return _config_manager
def init_config(config_dir: str = None) -> dict:
    global _config_manager
    if config_dir:
        _config_manager = ConfigManager(config_dir=config_dir)
    return _config_manager.load()
