import os
import re
import threading
from core.log_buffer import log
from core.config_manager import get_config_manager
DEFAULT_OTHER = [
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "googleapis.com",
    "gstatic.com",
    "ggpht.com",
    "ytimg.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discord.media",
    "discordapp.net",
    "gateway.discord.gg",
    "t.me",
    "telegram.org",
    "web.telegram.org",
    "core.telegram.org",
    "instagram.com",
    "cdninstagram.com",
    "facebook.com",
    "fbcdn.net",
    "twitter.com",
    "x.com",
    "twimg.com",
    "tiktok.com",
    "reddit.com",
    "pinterest.com",
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
]
DEFAULT_NETROGAT = [
    "gosuslugi.ru",
    "vk.com",
    "vk.ru",
    "vkvideo.ru",
    "mail.ru",
    "ya.ru",
    "yandex.ru",
    "dzen.ru",
    "rutube.ru",
    "ok.ru",
    "sberbank.ru",
    "tinkoff.ru",
    "tbank.ru",
    "vtb.ru",
    "kaspersky.com",
    "kaspersky.ru",
    "ozon.ru",
    "wildberries.ru",
    "mos.ru",
    "nalog.ru",
]
DEFAULT_OTHER2 = []
VALID_NAMES = {"other", "other2", "netrogat"}
DEFAULTS_MAP = {
    "other": DEFAULT_OTHER,
    "other2": DEFAULT_OTHER2,
    "netrogat": DEFAULT_NETROGAT,
}
DESCRIPTIONS = {
    "other": "Базовый список доменов",
    "other2": "Пользовательские домены",
    "netrogat": "Исключения (не обрабатываются)",
}
DOMAIN_RE = re.compile(
    r'^(?:\*\.)?'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z]{2,63}$'
)
class HostlistManager:
    def __init__(self):
        self._lock = threading.Lock()
    @property
    def lists_path(self):
        cfg = get_config_manager()
        return cfg.get("zapret", "lists_path", default="/opt/zapret2/lists")
    def _file_path(self, name):
        return os.path.join(self.lists_path, name + ".txt")
    def _ensure_dir(self):
        path = self.lists_path
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
                log.info(f"Создана директория списков: {path}", source="hostlists")
            except OSError as e:
                log.error(f"Не удалось создать директорию: {e}", source="hostlists")
    def _validate_name(self, name):
        return name in VALID_NAMES
    def get_hostlist(self, name):
        if not self._validate_name(name):
            log.warning(f"Недопустимое имя списка: {name}", source="hostlists")
            return []
        filepath = self._file_path(name)
        if not os.path.exists(filepath):
            defaults = DEFAULTS_MAP.get(name, [])
            if defaults:
                self.save_hostlist(name, defaults)
            return list(defaults)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            domains = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
            return domains
        except Exception as e:
            log.error(f"Ошибка чтения {name}.txt: {e}", source="hostlists")
            return []
    def save_hostlist(self, name, domains):
        if not self._validate_name(name):
            return False
        self._ensure_dir()
        filepath = self._file_path(name)
        clean = []
        seen = set()
        for d in domains:
            d = d.strip().lower()
            if d and not d.startswith("#") and d not in seen:
                clean.append(d)
                seen.add(d)
        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(clean) + "\n" if clean else "")
            log.info(f"Сохранён {name}.txt ({len(clean)} доменов)", source="hostlists")
            return True
        except Exception as e:
            log.error(f"Ошибка записи {name}.txt: {e}", source="hostlists")
            return False
    def add_domains(self, name, domains):
        if not self._validate_name(name):
            return 0
        current = self.get_hostlist(name)
        current_set = set(d.lower() for d in current)
        added = 0
        for d in domains:
            normalized = self.normalize_domain(d)
            if normalized and normalized not in current_set:
                current.append(normalized)
                current_set.add(normalized)
                added += 1
        if added > 0:
            self.save_hostlist(name, current)
            log.info(f"Добавлено {added} доменов в {name}.txt", source="hostlists")
        return added
    def remove_domains(self, name, domains):
        if not self._validate_name(name):
            return 0
        current = self.get_hostlist(name)
        remove_set = set(d.strip().lower() for d in domains if d.strip())
        new_list = [d for d in current if d.lower() not in remove_set]
        removed = len(current) - len(new_list)
        if removed > 0:
            self.save_hostlist(name, new_list)
            log.info(f"Удалено {removed} доменов из {name}.txt", source="hostlists")
        return removed
    def normalize_domain(self, text):
        if not text or not isinstance(text, str):
            return None
        text = text.strip().lower()
        for prefix in ("https://", "http://", "//"):
            if text.startswith(prefix):
                text = text[len(prefix):]
        text = text.split("/")[0]
        text = text.split("?")[0]
        text = text.split("#")[0]
        if ":" in text and not text.startswith("["):
            text = text.rsplit(":", 1)[0]
        if text.startswith("www."):
            text = text[4:]
        text = text.rstrip(".")
        if not text:
            return None
        if DOMAIN_RE.match(text):
            return text
        return None
    def get_stats(self):
        stats = {}
        for name in VALID_NAMES:
            filepath = self._file_path(name)
            exists = os.path.exists(filepath)
            count = 0
            if exists:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                count += 1
                except Exception:
                    pass
            writable = os.access(os.path.dirname(filepath), os.W_OK) if exists else True
            stats[name] = {
                "name": name,
                "filename": name + ".txt",
                "path": filepath,
                "count": count,
                "exists": exists,
                "writable": writable,
                "description": DESCRIPTIONS.get(name, ""),
                "has_defaults": name in DEFAULTS_MAP and len(DEFAULTS_MAP[name]) > 0,
            }
        return stats
    def reset_to_defaults(self, name):
        if not self._validate_name(name):
            return False
        defaults = DEFAULTS_MAP.get(name, [])
        result = self.save_hostlist(name, defaults)
        if result:
            log.info(
                f"Список {name}.txt сброшен к дефолтам ({len(defaults)} доменов)",
                source="hostlists",
            )
        return result
    def import_from_url(self, name, url):
        if not self._validate_name(name):
            return -1
        log.info(f"Импорт из URL: {url} → {name}.txt", source="hostlists")
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "zapret-gui/1.0"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            return self.import_from_text(name, text)
        except Exception as e:
            log.error(f"Ошибка загрузки URL {url}: {e}", source="hostlists")
            return -1
    def import_from_text(self, name, text):
        if not self._validate_name(name):
            return 0
        lines = text.strip().split("\n")
        domains = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            normalized = self.normalize_domain(line)
            if normalized:
                domains.append(normalized)
        if not domains:
            return 0
        added = self.add_domains(name, domains)
        log.info(
            f"Импортировано: {len(domains)} найдено, {added} добавлено в {name}.txt",
            source="hostlists",
        )
        return added
_instance = None
_instance_lock = threading.Lock()
def get_hostlist_manager():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = HostlistManager()
    return _instance
