import os
import re
import json
import threading
from core.log_buffer import log
from core.config_manager import get_config_manager
DEFAULT_IPSET_BASE = [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "104.16.0.0/13",
    "172.64.0.0/13",
    "131.0.72.0/22",
]
DEFAULT_MY_IPSET = []
VALID_NAMES = {"ipset-base", "my-ipset"}
DEFAULTS_MAP = {
    "ipset-base": DEFAULT_IPSET_BASE,
    "my-ipset": DEFAULT_MY_IPSET,
}
DESCRIPTIONS = {
    "ipset-base": "Базовые IP-адреса и подсети",
    "my-ipset": "Пользовательские IP/подсети",
}
IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
# IPv4 CIDR
IPV4_CIDR_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/(?:[12]?\d|3[0-2])$'
)
# IPv6 — упрощённая проверка (поддерживает :: сокращения)
IPV6_RE = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^(?:[0-9a-fA-F]{1,4}:)*:(?::[0-9a-fA-F]{1,4})*$|'
    r'^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|'
    r'^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4})*::$|'
    r'^::$'
)
# IPv6 CIDR
IPV6_CIDR_RE = re.compile(
    r'^(?:[0-9a-fA-F:]+)/(?:[1-9]?\d|1[0-2][0-8])$'
)
def validate_ip_entry(text):
    if not text or not isinstance(text, str):
        return None
    text = text.strip()
    if not text:
        return None
    if IPV4_RE.match(text):
        return text
    if IPV4_CIDR_RE.match(text):
        return text
    if "/" in text:
        ip_part, prefix_part = text.rsplit("/", 1)
        try:
            prefix_len = int(prefix_part)
            if 0 <= prefix_len <= 128 and _is_valid_ipv6(ip_part):
                return text
        except ValueError:
            pass
    else:
        if _is_valid_ipv6(text):
            return text
    return None
def _is_valid_ipv6(text):
    if not text:
        return False
    if IPV6_RE.match(text):
        return True
    if "::" in text:
        parts = text.split("::")
        if len(parts) != 2:
            return False
        left = parts[0].split(":") if parts[0] else []
        right = parts[1].split(":") if parts[1] else []
        if len(left) + len(right) > 7:
            return False
        for part in left + right:
            if not part:
                continue
            if len(part) > 4:
                return False
            try:
                int(part, 16)
            except ValueError:
                return False
        return True
    return False
class IPSetManager:
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
                log.info(f"Создана директория списков: {path}", source="ipsets")
            except OSError as e:
                log.error(f"Не удалось создать директорию: {e}", source="ipsets")
    def _validate_name(self, name):
        return name in VALID_NAMES
    def get_ipset(self, name):
        if not self._validate_name(name):
            log.warning(f"Недопустимое имя IPset: {name}", source="ipsets")
            return []
        filepath = self._file_path(name)
        if not os.path.exists(filepath):
            defaults = DEFAULTS_MAP.get(name, [])
            if defaults:
                self.save_ipset(name, defaults)
            return list(defaults)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            entries = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
            return entries
        except Exception as e:
            log.error(f"Ошибка чтения {name}.txt: {e}", source="ipsets")
            return []
    def save_ipset(self, name, entries):
        if not self._validate_name(name):
            return False
        self._ensure_dir()
        filepath = self._file_path(name)
        clean = []
        seen = set()
        for entry in entries:
            entry = entry.strip()
            if entry and not entry.startswith("#") and entry not in seen:
                clean.append(entry)
                seen.add(entry)
        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(clean) + "\n" if clean else "")
            log.info(f"Сохранён {name}.txt ({len(clean)} записей)", source="ipsets")
            return True
        except Exception as e:
            log.error(f"Ошибка записи {name}.txt: {e}", source="ipsets")
            return False
    def add_entries(self, name, entries):
        if not self._validate_name(name):
            return 0
        current = self.get_ipset(name)
        current_set = set(current)
        added = 0
        for entry in entries:
            validated = validate_ip_entry(entry)
            if validated and validated not in current_set:
                current.append(validated)
                current_set.add(validated)
                added += 1
        if added > 0:
            self.save_ipset(name, current)
            log.info(f"Добавлено {added} записей в {name}.txt", source="ipsets")
        return added
    def remove_entries(self, name, entries):
        if not self._validate_name(name):
            return 0
        current = self.get_ipset(name)
        remove_set = set(e.strip() for e in entries if e.strip())
        new_list = [e for e in current if e not in remove_set]
        removed = len(current) - len(new_list)
        if removed > 0:
            self.save_ipset(name, new_list)
            log.info(f"Удалено {removed} записей из {name}.txt", source="ipsets")
        return removed
    def validate_entry(self, text):
        return validate_ip_entry(text)
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
        result = self.save_ipset(name, defaults)
        if result:
            log.info(
                f"IPset {name}.txt сброшен к дефолтам ({len(defaults)} записей)",
                source="ipsets",
            )
        return result
    def load_by_asn(self, asn_number):
        asn_number = str(asn_number).strip()
        if asn_number.upper().startswith("AS"):
            asn_number = asn_number[2:]
        if not asn_number.isdigit():
            log.error(f"Невалидный ASN: {asn_number}", source="ipsets")
            return []
        url = (
            f"https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource=AS{asn_number}"
        )
        log.info(f"Загрузка IP по ASN {asn_number}...", source="ipsets")
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "zapret-gui/1.0"})
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            prefixes = []
            if "data" in data and "prefixes" in data["data"]:
                for item in data["data"]["prefixes"]:
                    prefix = item.get("prefix", "")
                    if prefix:
                        prefixes.append(prefix)
            log.info(
                f"ASN {asn_number}: получено {len(prefixes)} префиксов",
                source="ipsets",
            )
            return prefixes
        except Exception as e:
            log.error(f"Ошибка загрузки ASN {asn_number}: {e}", source="ipsets")
            return []
_instance = None
_instance_lock = threading.Lock()
def get_ipset_manager():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = IPSetManager()
    return _instance
