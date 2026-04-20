# core/ipset_manager.py
"""
Менеджер IP-списков (ipsets).

Управляет файлами в директории lists_path:
  - ipset-base.txt — базовые IP-адреса (Cloudflare DNS и др.)
  - my-ipset.txt   — пользовательские IP/подсети
  - ipset-*.txt    — произвольные пользовательские IP-списки
  - my-ipset-*.txt — пользовательские IP-списки (альтернативный префикс)

Имя файла должно удовлетворять одному из условий:
  - встроенное имя ("ipset-base", "my-ipset");
  - начинается с "ipset-", "ipset_", "my-ipset-" или "my-ipset_";
  - длина 1..64 символа, допустимые символы — [a-zA-Z0-9_-].

Таким образом IP-списки и hostlists живут в одной директории, но имеют
разделённые namespaces: файлы IP-списков ВСЕГДА начинаются с "ipset" либо
равны "my-ipset".

Поддерживает загрузку IP-диапазонов по ASN через RIPE API.

Использование:
    from core.ipset_manager import get_ipset_manager
    im = get_ipset_manager()
    entries = im.get_ipset("my-ipset")
    im.add_entries("my-ipset", ["1.2.3.4", "10.0.0.0/8"])
    im.create_ipset("ipset-myvpn")
    im.delete_ipset("ipset-myvpn")
    im.rename_ipset("ipset-old", "ipset-new")
    prefixes = im.load_by_asn(13335)  # Cloudflare
"""

import os
import re
import json
import threading

from core.log_buffer import log
from core.config_manager import get_config_manager

# ═══════════════════ Дефолтные списки ═══════════════════

DEFAULT_IPSET_BASE = [
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    # Google DNS
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    # Cloudflare CDN основные подсети
    "104.16.0.0/13",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

DEFAULT_MY_IPSET = []

# Встроенные имена (защищены от удаления/переименования)
BUILTIN_NAMES = ("ipset-base", "my-ipset")

# Маппинг имя → дефолтный список
DEFAULTS_MAP = {
    "ipset-base": DEFAULT_IPSET_BASE,
    "my-ipset": DEFAULT_MY_IPSET,
}

# Описания файлов
DESCRIPTIONS = {
    "ipset-base": "Базовые IP-адреса и подсети",
    "my-ipset": "Пользовательские IP/подсети",
}

# Общий паттерн валидации символов имени
_NAME_CHARS_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Паттерн namespace'а IP-списков: имя либо встроенное, либо начинается с
# одного из префиксов ipset- / ipset_ / my-ipset- / my-ipset_ (для
# произвольных кастомных IP-списков).
IPSET_NAMESPACE_RE = re.compile(
    r"^(?:ipset-base|my-ipset|ipset[-_][a-zA-Z0-9_-]+|my-ipset[-_][a-zA-Z0-9_-]+)$"
)

# ═══════════════════ Валидация IP ═══════════════════

# IPv4 address
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
    """
    Валидация IP-адреса или CIDR-подсети.

    Args:
        text: Строка с IP или CIDR

    Returns:
        str|None: Нормализованная запись или None если невалидна
    """
    if not text or not isinstance(text, str):
        return None

    text = text.strip()
    if not text:
        return None

    # IPv4
    if IPV4_RE.match(text):
        return text

    # IPv4 CIDR
    if IPV4_CIDR_RE.match(text):
        return text

    # IPv6 или IPv6 CIDR
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
    """Проверить является ли строка валидным IPv6-адресом."""
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
    """Управление файлами IP-списков."""

    def __init__(self):
        self._lock = threading.Lock()

    @property
    def lists_path(self):
        """Путь к директории списков."""
        cfg = get_config_manager()
        return cfg.get("zapret", "lists_path", default="/opt/zapret2/lists")

    def _file_path(self, name):
        """Полный путь к файлу списка."""
        return os.path.join(self.lists_path, name + ".txt")

    def _ensure_dir(self):
        """Создать директорию списков если не существует."""
        path = self.lists_path
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
                log.info(f"Создана директория списков: {path}", source="ipsets")
            except OSError as e:
                log.error(f"Не удалось создать директорию: {e}", source="ipsets")

    def _validate_name(self, name):
        """Проверить что имя допустимо для ipset-файла."""
        if not isinstance(name, str):
            return False
        if not _NAME_CHARS_RE.match(name):
            return False
        return bool(IPSET_NAMESPACE_RE.match(name))

    def _is_builtin(self, name):
        """Встроенное (защищённое от удаления/переименования) имя."""
        return name in BUILTIN_NAMES

    def list_names(self):
        """
        Список имён всех ipset-файлов в директории.

        Всегда включает встроенные имена, плюс любые *.txt файлы,
        удовлетворяющие namespace'у IP-списков.
        """
        names = set(BUILTIN_NAMES)
        path = self.lists_path
        try:
            if os.path.isdir(path):
                for entry in os.listdir(path):
                    if not entry.endswith(".txt"):
                        continue
                    stem = entry[:-4]
                    if self._validate_name(stem):
                        names.add(stem)
        except OSError as e:
            log.error(f"Не удалось прочитать {path}: {e}", source="ipsets")

        builtin_order = [n for n in BUILTIN_NAMES if n in names]
        custom = sorted(n for n in names if n not in BUILTIN_NAMES)
        return builtin_order + custom

    def get_ipset(self, name):
        """
        Прочитать файл IP-списка.

        Args:
            name: Имя списка (ipset-base, my-ipset, ipset-*, my-ipset-*)

        Returns:
            list[str]: Список IP/подсетей
        """
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
        """
        Сохранить IP-список в файл.

        Args:
            name: Имя списка
            entries: Список IP/подсетей

        Returns:
            bool: Успешность операции
        """
        if not self._validate_name(name):
            return False

        self._ensure_dir()
        filepath = self._file_path(name)

        # Дедуплицируем
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

    def create_ipset(self, name):
        """
        Создать новый пустой ipset-файл.

        Args:
            name: Имя списка (должно начинаться с ipset- или my-ipset-)

        Returns:
            tuple[bool, str]: (успех, сообщение об ошибке или "")
        """
        if not isinstance(name, str) or not _NAME_CHARS_RE.match(name):
            return False, "Недопустимое имя списка"
        if not IPSET_NAMESPACE_RE.match(name):
            return False, (
                "Имя IP-списка должно начинаться с 'ipset-', 'ipset_', "
                "'my-ipset-' или 'my-ipset_'"
            )

        self._ensure_dir()
        filepath = self._file_path(name)

        if os.path.exists(filepath):
            return False, "Список с таким именем уже существует"

        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("")
            log.info(f"Создан IP-список {name}.txt", source="ipsets")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка создания {name}.txt: {e}", source="ipsets")
            return False, str(e)

    def delete_ipset(self, name):
        """
        Удалить пользовательский ipset-файл.

        Встроенные списки (ipset-base/my-ipset) удалить нельзя.

        Args:
            name: Имя списка

        Returns:
            tuple[bool, str]: (успех, сообщение об ошибке или "")
        """
        if not self._validate_name(name):
            return False, "Недопустимое имя списка"

        if self._is_builtin(name):
            return False, "Нельзя удалить встроенный список"

        filepath = self._file_path(name)
        if not os.path.exists(filepath):
            return False, "Список не существует"

        try:
            with self._lock:
                os.remove(filepath)
            log.info(f"Удалён IP-список {name}.txt", source="ipsets")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка удаления {name}.txt: {e}", source="ipsets")
            return False, str(e)

    def rename_ipset(self, old_name, new_name):
        """
        Переименовать пользовательский ipset-файл.

        Встроенные списки переименовывать нельзя.

        Args:
            old_name: Текущее имя
            new_name: Новое имя (должно соответствовать namespace'у ipset)

        Returns:
            tuple[bool, str]: (успех, сообщение об ошибке или "")
        """
        if not self._validate_name(old_name):
            return False, "Недопустимое имя исходного списка"
        if not isinstance(new_name, str) or not _NAME_CHARS_RE.match(new_name):
            return False, "Недопустимое новое имя"
        if not IPSET_NAMESPACE_RE.match(new_name):
            return False, (
                "Имя IP-списка должно начинаться с 'ipset-', 'ipset_', "
                "'my-ipset-' или 'my-ipset_'"
            )
        if old_name == new_name:
            return False, "Новое имя совпадает со старым"
        if self._is_builtin(old_name):
            return False, "Нельзя переименовать встроенный список"
        if self._is_builtin(new_name):
            return False, "Нельзя использовать имя встроенного списка"

        src = self._file_path(old_name)
        dst = self._file_path(new_name)

        if not os.path.exists(src):
            return False, "Исходный список не существует"
        if os.path.exists(dst):
            return False, "Список с новым именем уже существует"

        try:
            with self._lock:
                os.rename(src, dst)
            log.info(f"IP-список {old_name}.txt переименован в {new_name}.txt",
                     source="ipsets")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка переименования {old_name}.txt → {new_name}.txt: {e}",
                      source="ipsets")
            return False, str(e)

    def add_entries(self, name, entries):
        """
        Добавить IP/подсети в список (без дубликатов).

        Args:
            name: Имя списка
            entries: Список IP/подсетей

        Returns:
            int: Количество добавленных записей
        """
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
        """
        Удалить IP/подсети из списка.

        Args:
            name: Имя списка
            entries: Список для удаления

        Returns:
            int: Количество удалённых записей
        """
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
        """
        Валидация IP/CIDR.

        Args:
            text: Строка для проверки

        Returns:
            str|None: Нормализованная запись или None
        """
        return validate_ip_entry(text)

    def get_stats(self):
        """
        Статистика по всем файлам IP-списков.

        Returns:
            dict: {name: {count, path, exists, writable, description, is_builtin}}
        """
        stats = {}
        for name in self.list_names():
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

            writable = os.access(os.path.dirname(filepath), os.W_OK) if os.path.isdir(os.path.dirname(filepath)) else True

            stats[name] = {
                "name": name,
                "filename": name + ".txt",
                "path": filepath,
                "count": count,
                "exists": exists,
                "writable": writable,
                "description": DESCRIPTIONS.get(name, "Пользовательский IP-список"),
                "has_defaults": name in DEFAULTS_MAP and len(DEFAULTS_MAP[name]) > 0,
                "is_builtin": self._is_builtin(name),
            }

        return stats

    def reset_to_defaults(self, name):
        """
        Сбросить список к дефолтным значениям.

        Для пользовательских списков без дефолтов — очищает файл.

        Args:
            name: Имя списка

        Returns:
            bool: Успешность операции
        """
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
        """
        Загрузить IP-диапазоны по номеру ASN через RIPE API.

        Args:
            asn_number: Номер ASN (число, например 13335 для Cloudflare)

        Returns:
            list[str]: Список IP-префиксов или пустой список при ошибке
        """
        asn_number = str(asn_number).strip()
        # Убираем префикс AS если есть
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


# ═══════════════════ Singleton ═══════════════════

_instance = None
_instance_lock = threading.Lock()


def get_ipset_manager():
    """Получить singleton-экземпляр IPSetManager."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = IPSetManager()
    return _instance
