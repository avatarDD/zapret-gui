# core/hostlist_manager.py
"""
Менеджер списков доменов (hostlists).

Управляет файлами в директории lists_path (обычно /opt/zapret2/lists):
  - other.txt     — базовый список доменов для обработки nfqws
  - other2.txt    — пользовательские домены
  - netrogat.txt  — исключения (домены, которые НЕ обрабатываются)
  - *.txt         — произвольные пользовательские списки

Имя списка должно соответствовать паттерну [a-zA-Z0-9_-]+ (1..64 символов).

Использование:
    from core.hostlist_manager import get_hostlist_manager
    hm = get_hostlist_manager()
    domains = hm.get_hostlist("other")
    hm.add_domains("other2", ["example.com", "test.org"])
    hm.create_hostlist("myvpn")   # создать новый список myvpn.txt
    hm.delete_hostlist("myvpn")   # удалить пользовательский список
"""

import os
import re
import threading

from core.log_buffer import log
from core.config_manager import get_config_manager

# ═══════════════════ Дефолтные списки ═══════════════════

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

# Встроенные (защищённые от удаления) имена списков
BUILTIN_NAMES = ("other", "other2", "netrogat")

# Маппинг имя → дефолтный список
DEFAULTS_MAP = {
    "other": DEFAULT_OTHER,
    "other2": DEFAULT_OTHER2,
    "netrogat": DEFAULT_NETROGAT,
}

# Описания встроенных файлов
DESCRIPTIONS = {
    "other": "Базовый список доменов",
    "other2": "Пользовательские домены",
    "netrogat": "Исключения (не обрабатываются)",
}

# Regex для валидации имени списка — разрешены латиница, цифры, "_" и "-"
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Имена, принадлежащие namespace'у IP-списков (ipset_manager): такие файлы
# не должны показываться в hostlists и не могут быть созданы как hostlist.
# Покрываем все формы: "ipset-base", "my-ipset", префиксы "ipset-/ipset_/
# my-ipset-/my-ipset_*" и суффиксы "*-ipset/*-ipset_*" (для импортируемых
# upstream-файлов вроде "cloudflare-ipset", "russia-discord-ipset").
# Список синхронизирован с core/ipset_manager.IPSET_NAMESPACE_RE.
IPSET_NAME_RE = re.compile(
    r"^(?:"
    r"ipset-base|my-ipset|"
    r"ipset[-_][a-zA-Z0-9_-]*|"
    r"my-ipset[-_][a-zA-Z0-9_-]*|"
    r"[a-zA-Z0-9][a-zA-Z0-9_-]*-ipset(?:[-_][a-zA-Z0-9_-]+)?"
    r")$"
)


def _is_ipset_name(name):
    """True, если имя принадлежит namespace'у IP-списков."""
    return isinstance(name, str) and bool(IPSET_NAME_RE.match(name))

# Regex для валидации домена
# Допускает: example.com, sub.example.com, *.example.com
DOMAIN_RE = re.compile(
    r'^(?:\*\.)?'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z]{2,63}$'
)


class HostlistManager:
    """Управление файлами списков доменов."""

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
                log.info(f"Создана директория списков: {path}", source="hostlists")
            except OSError as e:
                log.error(f"Не удалось создать директорию: {e}", source="hostlists")

    def _validate_name(self, name):
        """
        Проверить что имя файла допустимо как hostlist.

        Имя должно:
          - соответствовать [a-zA-Z0-9_-]{1,64};
          - НЕ принадлежать namespace'у IP-списков (ipset-*, my-ipset).
        """
        if not isinstance(name, str):
            return False
        if not NAME_RE.match(name):
            return False
        if _is_ipset_name(name):
            return False
        return True

    def _is_builtin(self, name):
        """Встроенное (защищённое от удаления) имя."""
        return name in BUILTIN_NAMES

    def list_names(self):
        """
        Список имён всех hostlist-файлов в директории.

        Возвращает встроенные имена (other/other2/netrogat) даже если файлы
        ещё не созданы, плюс любые *.txt файлы с валидным именем. Файлы
        namespace'а IP-списков (ipset-*, my-ipset) исключаются.
        """
        names = set(BUILTIN_NAMES)
        path = self.lists_path
        try:
            if os.path.isdir(path):
                for entry in os.listdir(path):
                    if not entry.endswith(".txt"):
                        continue
                    stem = entry[:-4]
                    # _validate_name уже отсекает ipset-* и my-ipset
                    if self._validate_name(stem):
                        names.add(stem)
        except OSError as e:
            log.error(f"Не удалось прочитать {path}: {e}", source="hostlists")

        # Сначала встроенные в каноническом порядке, затем кастомные по алфавиту
        builtin_order = [n for n in BUILTIN_NAMES if n in names]
        custom = sorted(n for n in names if n not in BUILTIN_NAMES)
        return builtin_order + custom

    def get_hostlist(self, name):
        """
        Прочитать файл списка доменов.

        Args:
            name: Имя списка (other, other2, netrogat, либо пользовательское)

        Returns:
            list[str]: Список доменов
        """
        if not self._validate_name(name):
            log.warning(f"Недопустимое имя списка: {name}", source="hostlists")
            return []

        filepath = self._file_path(name)

        if not os.path.exists(filepath):
            # Если файл не существует — для встроенных имён возвращаем дефолт
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
                # Пропускаем пустые строки и комментарии
                if line and not line.startswith("#"):
                    domains.append(line)

            return domains
        except Exception as e:
            log.error(f"Ошибка чтения {name}.txt: {e}", source="hostlists")
            return []

    def save_hostlist(self, name, domains):
        """
        Сохранить список доменов в файл.

        Args:
            name: Имя списка
            domains: Список доменов

        Returns:
            bool: Успешность операции
        """
        if not self._validate_name(name):
            return False

        self._ensure_dir()
        filepath = self._file_path(name)

        # Очищаем и дедуплицируем
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

    def create_hostlist(self, name):
        """
        Создать новый пустой hostlist-файл.

        Args:
            name: Имя списка

        Returns:
            tuple[bool, str]: (успех, сообщение об ошибке или "")
        """
        if not self._validate_name(name):
            return False, "Недопустимое имя списка"

        self._ensure_dir()
        filepath = self._file_path(name)

        if os.path.exists(filepath):
            return False, "Список с таким именем уже существует"

        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("")
            log.info(f"Создан список {name}.txt", source="hostlists")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка создания {name}.txt: {e}", source="hostlists")
            return False, str(e)

    def rename_hostlist(self, old_name, new_name):
        """
        Переименовать пользовательский hostlist-файл.

        Встроенные списки переименовывать нельзя.

        Args:
            old_name: Текущее имя
            new_name: Новое имя

        Returns:
            tuple[bool, str]: (успех, сообщение об ошибке или "")
        """
        if not self._validate_name(old_name):
            return False, "Недопустимое имя исходного списка"
        if not self._validate_name(new_name):
            return False, "Недопустимое новое имя"
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
            log.info(f"Список {old_name}.txt переименован в {new_name}.txt",
                     source="hostlists")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка переименования {old_name}.txt → {new_name}.txt: {e}",
                      source="hostlists")
            return False, str(e)

    def delete_hostlist(self, name):
        """
        Удалить пользовательский hostlist-файл.

        Встроенные списки (other/other2/netrogat) удалить нельзя.

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
            log.info(f"Удалён список {name}.txt", source="hostlists")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка удаления {name}.txt: {e}", source="hostlists")
            return False, str(e)

    def add_domains(self, name, domains):
        """
        Добавить домены в список (без дубликатов).

        Args:
            name: Имя списка
            domains: Список доменов для добавления

        Returns:
            int: Количество реально добавленных доменов
        """
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
        """
        Удалить домены из списка.

        Args:
            name: Имя списка
            domains: Список доменов для удаления

        Returns:
            int: Количество реально удалённых доменов
        """
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
        """
        Нормализация домена: убрать протокол, www, путь, порт.

        Args:
            text: Строка (может быть URL или домен)

        Returns:
            str|None: Нормализованный домен или None если невалидный
        """
        if not text or not isinstance(text, str):
            return None

        text = text.strip().lower()

        # Убираем протокол
        for prefix in ("https://", "http://", "//"):
            if text.startswith(prefix):
                text = text[len(prefix):]

        # Убираем путь, query, fragment
        text = text.split("/")[0]
        text = text.split("?")[0]
        text = text.split("#")[0]

        # Убираем порт
        if ":" in text and not text.startswith("["):
            text = text.rsplit(":", 1)[0]

        # Убираем www.
        if text.startswith("www."):
            text = text[4:]

        # Убираем завершающую точку
        text = text.rstrip(".")

        if not text:
            return None

        # Валидация
        if DOMAIN_RE.match(text):
            return text

        return None

    def get_stats(self):
        """
        Статистика по всем файлам списков.

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
                "description": DESCRIPTIONS.get(name, "Пользовательский список"),
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
        result = self.save_hostlist(name, defaults)

        if result:
            log.info(
                f"Список {name}.txt сброшен к дефолтам ({len(defaults)} доменов)",
                source="hostlists",
            )
        return result

    def import_from_url(self, name, url):
        """
        Скачать список доменов по URL и добавить в файл.

        Args:
            name: Имя списка
            url: URL для загрузки (текстовый файл, один домен на строку)

        Returns:
            int: Количество добавленных доменов (-1 при ошибке)
        """
        if not self._validate_name(name):
            return -1

        log.info(f"Импорт из URL: {url} → {name}.txt", source="hostlists")

        try:
            import urllib.request
            import ssl

            # Создаём SSL-контекст без проверки сертификата (для роутеров)
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
        """
        Импорт доменов из текста (один домен на строку).

        Args:
            name: Имя списка
            text: Текст с доменами

        Returns:
            int: Количество добавленных доменов
        """
        if not self._validate_name(name):
            return 0

        lines = text.strip().split("\n")
        domains = []
        for line in lines:
            line = line.strip()
            # Пропускаем комментарии и пустые строки
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


# ═══════════════════ Singleton ═══════════════════

_instance = None
_instance_lock = threading.Lock()


def get_hostlist_manager():
    """Получить singleton-экземпляр HostlistManager."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = HostlistManager()
    return _instance
