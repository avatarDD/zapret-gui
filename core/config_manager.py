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
from core.safe_io import atomic_write_json


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
        # Путь к штатному скрипту blockcheck zapret2. Пусто → автопоиск
        # blockcheck2.sh / blockcheck.sh в base_path (см. core/blockcheck2.py).
        "blockcheck2_path": "",
    },

    # --- Настройки Web-GUI ---
    "gui": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": False,
        "auth_enabled": False,
        "auth_user": "admin",
        "auth_password": "",
        # Доверенные cross-origin источники для CORS (по умолчанию пусто —
        # разрешён только same-origin; `*` НЕ используется). Пример:
        # ["https://my.dashboard.example"].
        "cors_origins": [],
    },

    # --- Настройки nfqws ---
    "nfqws": {
        "queue_num": 300,
        # Расширенный набор портов (паритет с nfqws2-keenetic): помимо HTTP/
        # HTTPS — Cloudflare alt-порты (2053/2083/2087/2096/8443), Telegram
        # MTProto (5222), а по UDP — QUIC (443), STUN/TURN, WireGuard-диапазоны
        # и Discord voice (49152:65535).
        "ports_tcp": "80,443,2053,2083,2087,2096,5222,8443",
        "ports_udp": "443,3478:3481,5349,19294:19344,49152:65535",
        "tcp_pkt_out": 20,
        "tcp_pkt_in": 10,
        "udp_pkt_out": 5,
        "udp_pkt_in": 3,
        "desync_mark": "0x40000000",
        "desync_mark_postnat": "0x20000000",
        "user": "nobody",
        "disable_ipv6": True,
        # Включить пер-пакетный отладочный вывод nfqws2 (--debug). Вывод
        # nfqws2 (stderr) уже пишется в лог-буфер; при debug=True он логируется
        # на уровне INFO (видимый), что нужно для диагностики «почему стратегия
        # не сработала» (грузятся ли lua, объявлены ли blob'ы, матчится ли цель).
        "debug": False,
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
        # Режим include-списков. other.txt НЕ подмешивается автоматически —
        # стратегия по умолчанию применяется ко всему трафику на своих портах
        # (--filter-*). Сузить можно, добавив --hostlist=/--hostlist-domains=
        # прямо в стратегию.
        #   none         — без include-списков (дефолт);
        #   autohostlist — + auto.txt (nfqws2 копит недоступные домены);
        #   ipset        — фильтрация по IP (--ipset);
        #   hostlist     — алиас none (для совместимости старых конфигов).
        "mode": "none",
        # Предохранитель: exclude netrogat.txt (банки/госуслуги/vk и т.п.) от
        # десинка, чтобы не сломать критичные сервисы. True по умолчанию;
        # false — десинкать вообще всё без исключений.
        "protect_excluded": True,
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
        # Персистентный лог критичных событий: пишется рядом с settings.json
        # (постоянный носитель), поэтому ПЕРЕЖИВАЕТ перезагрузку роутера.
        # Главный файл логов лежит в /tmp (ОЗУ) и при ребуте теряется — без
        # этого нечем диагностировать «роутер ушёл в перезагрузку».
        "persist_critical": True,
        "persist_min_level": "WARNING",  # WARNING+ (или ERROR)
        "persist_path": "",              # пусто = <config_dir>/critical.log
    },

    # --- Сетевые интерфейсы ---
    "interfaces": {
        "wan": "",   # Авто-определение если пусто
        "wan6": "",
        "lan": "",
    },

    # --- Сетевое окружение (core/network_env) ---
    # profile: auto | router | pc — роутер с LAN либо ПК/VPS с одной
    # сетевой картой (локальный режим). auto — детект по платформе
    # и интерфейсам.
    "network": {
        "profile": "auto",
    },

    # --- AmneziaWG ---
    "awg": {
        "release_repo":       "avatardd/zapret-gui",
        "release_tag_prefix": "awg-bin-",
        "installed_tag":      "",
        "installed_go":       "",
        "installed_tools":    "",
        "installed_arch":     "",
        "installed_at":       0,
        # Лимит памяти userspace-демона amneziawg-go (Go) — для слабых
        # роутеров, чтобы он не разрастался и не доводил систему до OOM
        # (типичная причина «роутер ушёл в перезагрузку»). Применяется при
        # следующем подъёме туннеля. Выключено по умолчанию.
        "go_mem_enabled":     False,
        "go_gogc":            50,   # GOGC: ниже = чаще GC, меньше пик heap
        "go_memlimit_mb":     64,   # GOMEMLIMIT, МиБ (0 = не задавать)
        # PreUp/PostUp/PreDown/PostDown из .conf исполняются через shell под
        # root (стиль wg-quick). Конфиги часто импортируются из публичных
        # подписок, поэтому по умолчанию хуки ВЫКЛЮЧЕНЫ — иначе строка
        # `PostUp = ...` в чужом конфиге = RCE на роутере. Включать осознанно.
        "allow_hooks":        False,
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
        # Включать сгенерированные «на лету» стратегии в режимах standard/full
        # (комбинаторное расширение без хранения файлов). См. strategy_generator.
        "use_generated": True,
    },

    # --- Healthcheck (фоновый watchdog для autocircular) ---
    # Демон периодически проверяет референс-домены и при провалах сбрасывает
    # выученные circular-стратегии (state.tsv) по затронутым хостам — чтобы
    # nfqws2 переподобрал стратегию автоматически, без участия пользователя.
    # По умолчанию ВЫКЛЮЧЕН: создаёт фоновый трафик роутера наружу. Включается
    # в GUI на странице Стратегии («Авто-починка»).
    "healthcheck": {
        "enabled": False,
        # Интервал между проверками (минуты). Слишком частые проверки
        # маскируются как DDoS-щуп на стороне CDN — минимум 1 мин.
        "interval_min": 5,
        # Сколько подряд провалов одной службы заставляют сбросить state
        # выученной стратегии для её хостов. 1 = первый же провал; 2 — баланс
        # между «не дёргать на временный лаг» и «починить быстро».
        "consecutive_failures": 2,
        # Автоматический сброс state.tsv по затронутым хостам при провале.
        # Без него healthcheck только логирует; полезно для дебага.
        "auto_reset": True,
        # Какие сервисы из core/diagnostics.SERVICES проверять. Полные имена
        # должны существовать в SERVICES — иначе игнорируются.
        "services": ["youtube", "discord", "telegram"],
        # Пользовательские домены для проверки (помимо известных сервисов).
        # Каждый — "example.com" или "https://example.com/path". Хост для
        # сброса state выводится из URL.
        "custom_domains": [],
        # Защита от ложного сброса при «общем обвале»: если упали ВСЕ
        # проверяемые сайты — это может быть отсутствие связи, а не DPI.
        # control_domain — «контрольный» сайт, который НЕ блокируется (РКН и
        # т.п.). Если он открывается, значит связь есть → провал всех целевых
        # трактуется как DPI, и сброс ВЫПОЛНЯЕТСЯ. Если и он недоступен —
        # это реальный обвал, сброс пропускается. Пусто = старая эвристика
        # «упали все ≥2 → обвал».
        "control_domain": "ya.ru",
        # Включена ли защита от обвала вообще. Выключите, если у вас реально
        # бывает, что все целевые сайты заблокированы одновременно и сброс
        # всё равно нужен.
        "outage_guard": True,
        # Сколько последних результатов хранить в памяти (ring buffer).
        "history_size": 50,
    },

    # --- WARP/MASQUE (usque-keenetic) ---
    # Управление Cloudflare WARP через usque (MASQUE-протокол).
    # Usque тянется как бинарник из side-effect-tm/usque-keenetic —
    # по аналогии с sing-box из SagerNet/sing-box.
    "usque": {
        "enabled": False,
        "autostart": False,
        # SNI-маскировка: WARP-трафик маскируется под этот домен.
        # По умолчанию ozon.ru — крупный российский e-commerce.
        "default_sni": "ozon.ru",
        "http2_enable": False,
        # Метаданные установленного бинарника (заполняется при установке).
        "installed_tag": "",
        "installed_arch": "",
        "installed_at": 0,
        # Watchdog: проверка доступности туннеля.
        "watchdog": {
            "enabled": False,
            "interval_sec": 60,
            "probe_host": "1.1.1.1",
            "probe_port": 443,
        },
    },

    # --- Auto-Remediation ---
    # Автоматический выбор метода обхода по DPI-классификации.
    "auto_remediation": {
        "enabled": False,
        # Приоритет туннелей для remediation при "ip_block"/"full_block".
        # Первый доступный используется. Порядок = приоритет (сверху вниз).
        "tunnel_priority": ["warp", "awg", "opera", "singbox", "mihomo"],
    },

    # --- Update Checker (Unified) ---
    # Фоновая проверка обновлений всех бинарников.
    "update_checker": {
        "enabled": False,
        "interval_hours": 24,
    },

    # --- Opera Proxy (Alexey71/opera-proxy) ---
    # Standalone Opera VPN клиент: HTTP/SOCKS5 прокси через SurfEasy.
    # Бинарник тянется из Alexey71/opera-proxy — по аналогии с sing-box.
    "opera_proxy": {
        "enabled": False,
        "autostart": False,
        "country": "EU",  # EU | AS | AM
        "bind": "127.0.0.1:18080",
        "socks_mode": False,  # HTTP proxy по умолчанию
        "proxy_bypass": "",   # домены-исключения
        "fake_sni": "",       # SNI-маскировка
        "verbosity": 20,      # 10=debug, 20=info, 30=warn, 40=error
        "installed_tag": "",
        "installed_arch": "",
    },

    # --- Telegram MTProto Proxy (teleproxy / tg-mtproxy-client) ---
    # Два движка для разных архитектур:
    #   teleproxy (C)     —最强 DPI resistance, только ARM64
    #   tg-mtproxy-client — Go, все архитектуры включая MIPS
    "tgproxy": {
        "enabled": False,
        "engine": "auto",  # auto | teleproxy | mtproto
        "port": 9443,
        # teleproxy-specific
        "teleproxy_secret": "",
        "teleproxy_domain": "",  # fake-TLS домен (напр. "www.google.com")
        "teleproxy_direct_dc": True,
        # mtproto-specific (tg-mtproxy-client)
        "tunnel_url": "",     # WSS relay URL
        "tunnel_secret": "",
        "max_conns": 1024,
        # common
        "verbose": False,
        "autostart": False,
    },

    # --- Block Detector (DNS-мониторинг + автообнаружение блокировок) ---
    # Мониторит DNS-запросы клиентов, пронирует новые домены,
    # автодобавляет заблокированные в named lists.
    "block_detector": {
        "enabled": False,
        "dns_source": "auto",  # auto | af_packet | dnsmasq_log | adguard_log
        "probe_timeout": 5,
        "auto_add_enabled": False,
        "auto_add_list_id": "",  # целевой named list для автодобавления
        "whitelist": [],        # домены-исключения
        "interval_sec": 300,
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
            # Логируем «загружена/создана» только при ПЕРВОЙ загрузке.
            # load() дёргается многими модулями (подписки, пул, статус-
            # эндпоинты) — без этого гейта лог засорялся повторами
            # «Конфигурация загружена…» на каждый тик/запрос.
            first_load = not self._loaded

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
                    if first_load:
                        log.info(f"Конфигурация загружена: {self._config_path}",
                                 source="config")
                except (json.JSONDecodeError, IOError) as e:
                    log.error(f"Ошибка чтения конфигурации: {e}", source="config")
                    log.warning("Используются настройки по умолчанию",
                                source="config")
            else:
                if first_load:
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

        # Расширение портов: только если значение НЕ трогали (равно прежнему
        # узкому дефолту). Кастомные значения пользователя не перетираем.
        n = self._config.get("nfqws", {})
        if n.get("ports_tcp") == "80,443":
            n["ports_tcp"] = "80,443,2053,2083,2087,2096,5222,8443"
            changed = True
        if n.get("ports_udp") == "443":
            n["ports_udp"] = "443,3478:3481,5349,19294:19344,49152:65535"
            changed = True
        return changed

    def save(self) -> bool:
        """Сохранить текущую конфигурацию в файл."""
        with self._lock:
            return self._save_locked()

    def _save_locked(self) -> bool:
        """Сохранение (вызывается под lock).

        Атомарно: запись во временный файл в том же каталоге → ``fsync`` →
        ``os.replace``. Без этого креш/``ENOSPC``/потеря питания во время
        записи на роутере усекали бы ``settings.json``, и при следующем
        старте ``load()`` молча падал бы в дефолты (потеря всей конфигурации).
        """
        try:
            os.makedirs(self._config_dir, exist_ok=True)
            atomic_write_json(self._config_path, self._config)
            return True
        except (IOError, OSError, TypeError, ValueError) as e:
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
