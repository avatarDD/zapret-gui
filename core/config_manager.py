# core/config_manager.py
"""
Менеджер конфигурации.

Хранит настройки в JSON-файле. При первом запуске создаёт
конфиг с разумными дефолтами. Обеспечивает потокобезопасный
доступ к настройкам.

Использование:
    from core.config_manager import config, save_config

    zapret_base = config["zapret"]["base_path"]
    config["gui"]["port"] = 8081
    save_config()
"""

import os
import json
import copy
import threading
from core.log_buffer import log


# Путь по умолчанию для конфигурации
DEFAULT_CONFIG_DIR = "/opt/etc/zapret-gui"
DEFAULT_CONFIG_FILE = "settings.json"

# Дефолтная конфигурация
DEFAULT_CONFIG = {
    # --- Версия конфига (для миграций) ---
    "version": 1,

    # --- Пути к zapret2 ---
    # Стандартный layout zapret2:
    #   base_path/files/fake/   — blob-файлы (--blob=...:@bin/*.bin)
    #   base_path/lua/          — Lua-скрипты (--lua-init=@lua/*.lua)
    #   base_path/lists/        — hostlist'ы (--hostlist=lists/*.txt)
    #   base_path/ipset/        — IP-списки (--ipset[-exclude]=lists/ipset-*.txt)
    "zapret": {
        "base_path": "/opt/zapret2",
        "nfqws_binary": "/opt/zapret2/nfq2/nfqws2",
        "lua_path": "/opt/zapret2/lua",
        "lists_path": "/opt/zapret2/lists",
        "ipset_path": "/opt/zapret2/ipset",
        "bin_path": "/opt/zapret2/files/fake",
    },

    # --- Настройки Web-GUI ---
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

    # --- Firewall ---
    "firewall": {
        "type": "auto",  # auto, iptables, nftables
        "apply_on_start": True,
        "flowoffload": "donttouch",  # donttouch, none, software, hardware
        "postnat": True,
    },

    # --- Фильтрация ---
    "filter": {
        "mode": "hostlist",  # none, ipset, hostlist, autohostlist
    },

    # --- Текущая стратегия ---
    "strategy": {
        "current_id": None,
        "current_name": None,
        "favorites": [],
    },

    # --- Автозапуск ---
    "autostart": {
        "enabled": False,
        "method": "initd",  # initd
    },

    # --- Логирование ---
    "logging": {
        "max_entries": 2000,
        "file_enabled": True,
        "file_path": "/tmp/zapret-gui.log",
        "level": "INFO",  # DEBUG, INFO, WARNING, ERROR
    },

    # --- Сетевые интерфейсы ---
    "interfaces": {
        "wan": "",   # Авто-определение если пусто
        "wan6": "",
        "lan": "",
    },

    # --- BlockCheck ---
    "blockcheck": {
        "default_mode": "quick",
        "max_workers": 2,
        "probe_timeout": 10,
    },

    # --- Strategy Scanner ---
    "scan": {
        "default_mode": "quick",
        "default_protocol": "tcp",
        "stabilization_delay": 2,
        "probe_timeout": 10,
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
                    # Мержим: saved перезаписывает дефолты
                    self._deep_merge(self._config, saved)
                    # Миграция legacy путей под фактический layout zapret2
                    if self._migrate_legacy_paths():
                        self._save_locked()
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

    def _migrate_legacy_paths(self) -> bool:
        """
        Привести zapret-пути к актуальному layout'у zapret2.

        До 0.16.3 дефолт bin_path = /opt/zapret2/bin был неверным:
        блоб-файлы лежат в /opt/zapret2/files/fake/. Также раньше
        отсутствовал ipset_path — ipset'ы и hostlist'ы лежали в
        одной директории.
        """
        z = self._config.get("zapret", {})
        changed = False
        if z.get("bin_path") in ("/opt/zapret2/bin", "/opt/zapret2/bin/"):
            z["bin_path"] = "/opt/zapret2/files/fake"
            changed = True
        if "ipset_path" not in z:
            z["ipset_path"] = "/opt/zapret2/ipset"
            changed = True
        return changed

    def save(self) -> bool:
        """Сохранить текущую конфигурацию в файл."""
        with self._lock:
            return self._save_locked()

    def _save_locked(self) -> bool:
        """Сохранение (вызывается под lock)."""
        try:
            os.makedirs(self._config_dir, exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except (IOError, OSError) as e:
            log.error(f"Не удалось сохранить конфигурацию: {e}", source="config")
            return False

    def get(self, *keys, default=None):
        """
        Получить значение по вложенному ключу.

        Пример: config.get("zapret", "base_path")
        """
        with self._lock:
            value = self._config
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            return value

    def set(self, *args):
        """
        Установить значение по вложенному ключу.

        Пример: config.set("gui", "port", 8081)
        Последний аргумент — значение, остальные — путь.
        """
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
        """Получить полную копию конфигурации."""
        with self._lock:
            return copy.deepcopy(self._config)

    def update_section(self, section: str, data: dict) -> bool:
        """
        Обновить секцию конфигурации.

        Пример: config.update_section("gui", {"port": 8081})
        """
        with self._lock:
            if section in self._config and isinstance(self._config[section], dict):
                self._config[section].update(data)
                return True
            return False

    def reset(self) -> dict:
        """Сбросить к настройкам по умолчанию."""
        with self._lock:
            self._config = copy.deepcopy(DEFAULT_CONFIG)
            self._save_locked()
            log.info("Конфигурация сброшена к дефолтам", source="config")
            return copy.deepcopy(self._config)

    def export_json(self) -> str:
        """Экспортировать конфигурацию как JSON-строку."""
        with self._lock:
            return json.dumps(self._config, indent=2, ensure_ascii=False)

    def import_json(self, json_str: str) -> bool:
        """Импортировать конфигурацию из JSON-строки."""
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
        """
        Рекурсивное слияние: override перезаписывает base.
        Новые ключи из base сохраняются (для обратной совместимости).
        """
        for key, value in override.items():
            if (key in base
                    and isinstance(base[key], dict)
                    and isinstance(value, dict)):
                ConfigManager._deep_merge(base[key], value)
            else:
                base[key] = value


# === Глобальный экземпляр ===

_config_manager = ConfigManager()


def get_config_manager() -> ConfigManager:
    """Получить глобальный менеджер конфигурации."""
    return _config_manager


def init_config(config_dir: str = None) -> dict:
    """Инициализировать конфигурацию при старте приложения."""
    global _config_manager
    if config_dir:
        _config_manager = ConfigManager(config_dir=config_dir)
    return _config_manager.load()
