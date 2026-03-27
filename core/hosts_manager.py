# core/hosts_manager.py
"""
Менеджер файла /etc/hosts.

Управление DNS-перенаправлениями через /etc/hosts.
Используется для блокировки доменов (0.0.0.0) или
перенаправления трафика на конкретные IP (обход DNS-блокировок).

Записи GUI хранятся между маркерами:
  # === ZAPRET-GUI BEGIN ===
  0.0.0.0 blocked-domain.com
  162.159.128.233 discord.com
  # === ZAPRET-GUI END ===

Записи за пределами маркеров считаются системными и не редактируются.

Использование:
    from core.hosts_manager import get_hosts_manager
    hm = get_hosts_manager()
    entries = hm.get_entries()
    hm.add_entry("0.0.0.0", "ads.example.com")
    hm.add_block(["tracker1.com", "tracker2.com"])
    hm.apply_preset("discord_fix")
"""

import os
import re
import time
import shutil
import threading
import ipaddress

from core.log_buffer import log

# ═══════════════════ Константы ═══════════════════

HOSTS_PATH = "/etc/hosts"
BACKUP_DIR = "/tmp"
MAX_GUI_ENTRIES = 500

MARKER_BEGIN = "# === ZAPRET-GUI BEGIN ==="
MARKER_END = "# === ZAPRET-GUI END ==="

# Регулярка для валидации доменов
DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

# Системные домены — никогда не трогаем
SYSTEM_DOMAINS = frozenset([
    "localhost",
    "localhost.localdomain",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "broadcasthost",
])


# ═══════════════════ Пресеты ═══════════════════

PRESETS = {
    "block_ads": {
        "name": "Блокировка рекламы",
        "description": "Популярные рекламные домены → 0.0.0.0",
        "entries": [
            ("0.0.0.0", "ads.google.com"),
            ("0.0.0.0", "pagead2.googlesyndication.com"),
            ("0.0.0.0", "adservice.google.com"),
            ("0.0.0.0", "googleadservices.com"),
            ("0.0.0.0", "doubleclick.net"),
            ("0.0.0.0", "ad.doubleclick.net"),
            ("0.0.0.0", "stats.g.doubleclick.net"),
            ("0.0.0.0", "ads.youtube.com"),
            ("0.0.0.0", "static.ads-twitter.com"),
            ("0.0.0.0", "an.facebook.com"),
            ("0.0.0.0", "pixel.facebook.com"),
            ("0.0.0.0", "analytics.tiktok.com"),
            ("0.0.0.0", "ads-api.tiktok.com"),
            ("0.0.0.0", "mc.yandex.ru"),
            ("0.0.0.0", "an.yandex.ru"),
            ("0.0.0.0", "ad.mail.ru"),
            ("0.0.0.0", "top-fwz1.mail.ru"),
        ],
    },
    "block_telemetry": {
        "name": "Блокировка телеметрии",
        "description": "Домены телеметрии и трекинга → 0.0.0.0",
        "entries": [
            ("0.0.0.0", "metrics.icloud.com"),
            ("0.0.0.0", "telemetry.microsoft.com"),
            ("0.0.0.0", "settings-win.data.microsoft.com"),
            ("0.0.0.0", "vortex.data.microsoft.com"),
            ("0.0.0.0", "watson.telemetry.microsoft.com"),
            ("0.0.0.0", "incoming.telemetry.mozilla.org"),
            ("0.0.0.0", "crash-stats.mozilla.com"),
            ("0.0.0.0", "metrics.mzstatic.com"),
        ],
    },
    "discord_fix": {
        "name": "Discord Fix",
        "description": "Прямые IP для Discord (обход DNS-блокировок)",
        "entries": [
            ("162.159.128.233", "discord.com"),
            ("162.159.128.233", "www.discord.com"),
            ("162.159.128.233", "gateway.discord.gg"),
            ("162.159.128.233", "cdn.discordapp.com"),
            ("162.159.128.233", "media.discordapp.net"),
            ("162.159.128.233", "images-ext-1.discordapp.net"),
            ("162.159.128.233", "dl.discordapp.net"),
            ("162.159.136.232", "discord.gg"),
            ("162.159.136.232", "discordapp.com"),
        ],
    },
    "youtube_dns": {
        "name": "YouTube DNS",
        "description": "Перенаправление YouTube (укажите IP перед применением)",
        "entries": [
            ("216.239.38.120", "youtube.com"),
            ("216.239.38.120", "www.youtube.com"),
            ("216.239.38.120", "m.youtube.com"),
            ("216.239.38.120", "youtu.be"),
            ("216.239.38.120", "i.ytimg.com"),
            ("216.239.38.120", "yt3.ggpht.com"),
        ],
    },
    "unblock_ai": {
        "name": "Разблокировка AI",
        "description": "Прямые IP для AI-сервисов (могут устаревать)",
        "entries": [
            ("104.18.32.7", "chat.openai.com"),
            ("104.18.32.7", "chatgpt.com"),
            ("104.18.32.7", "api.openai.com"),
            ("104.18.37.228", "claude.ai"),
            ("104.18.37.228", "api.anthropic.com"),
        ],
    },
}


# ═══════════════════ Менеджер ═══════════════════

class HostsManager:
    """Менеджер файла /etc/hosts."""

    def __init__(self, hosts_path=None):
        self._hosts_path = hosts_path or HOSTS_PATH
        self._lock = threading.Lock()

    # ────────────── Чтение ──────────────

    def _read_file(self):
        """Прочитать файл hosts целиком."""
        try:
            with open(self._hosts_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            log.warning(f"Файл {self._hosts_path} не найден", source="hosts")
            return ""
        except PermissionError:
            log.error(f"Нет прав на чтение {self._hosts_path}", source="hosts")
            return ""

    def _write_file(self, content):
        """Записать файл hosts целиком."""
        try:
            with open(self._hosts_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except PermissionError:
            log.error(
                f"Нет прав на запись в {self._hosts_path}. "
                "На роутере /etc/hosts может быть read-only. "
                "Попробуйте: mount -o remount,rw /",
                source="hosts",
            )
            return False
        except OSError as e:
            log.error(f"Ошибка записи {self._hosts_path}: {e}", source="hosts")
            return False

    def _parse_lines(self, text):
        """
        Разобрать текст hosts на записи.
        Возвращает list[dict] с полями:
          ip, domain, comment, line_num, is_system, raw
        """
        entries = []
        in_gui_block = False

        for i, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()

            # Маркеры
            if line == MARKER_BEGIN:
                in_gui_block = True
                continue
            if line == MARKER_END:
                in_gui_block = False
                continue

            # Пустые строки и чистые комментарии
            if not line or line.startswith("#"):
                continue

            # Разбор: IP  domain  # comment
            comment = ""
            if "#" in line:
                line_part, comment = line.split("#", 1)
                comment = comment.strip()
                line = line_part.strip()

            parts = line.split()
            if len(parts) < 2:
                continue

            ip_str = parts[0]
            # Одна строка может содержать несколько доменов
            for domain in parts[1:]:
                domain = domain.lower().strip()
                if not domain:
                    continue

                entries.append({
                    "ip": ip_str,
                    "domain": domain,
                    "comment": comment,
                    "line_num": i,
                    "is_system": not in_gui_block,
                    "raw": raw_line,
                })

        return entries

    def _find_gui_block(self, text):
        """
        Найти позиции GUI-блока в тексте.
        Возвращает (begin_idx, end_idx) — индексы строк-маркеров,
        или (None, None) если маркеров нет.
        """
        lines = text.splitlines()
        begin_idx = None
        end_idx = None

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == MARKER_BEGIN:
                begin_idx = i
            elif stripped == MARKER_END:
                end_idx = i
                break

        return begin_idx, end_idx

    def _ensure_markers(self, text):
        """
        Гарантировать наличие маркеров в тексте.
        Если маркеров нет — добавить в конец файла.
        Возвращает обновлённый текст.
        """
        begin_idx, end_idx = self._find_gui_block(text)

        if begin_idx is not None and end_idx is not None:
            return text  # Маркеры уже есть

        # Добавляем маркеры в конец
        suffix = "\n" if text and not text.endswith("\n") else ""
        text += suffix + "\n" + MARKER_BEGIN + "\n" + MARKER_END + "\n"
        return text

    def _get_gui_entries_text(self, text):
        """Извлечь текст между маркерами."""
        begin_idx, end_idx = self._find_gui_block(text)
        if begin_idx is None or end_idx is None:
            return ""

        lines = text.splitlines()
        gui_lines = lines[begin_idx + 1:end_idx]
        return "\n".join(gui_lines)

    def _replace_gui_block(self, text, new_gui_lines):
        """
        Заменить содержимое между маркерами.
        new_gui_lines — список строк (без маркеров).
        Возвращает обновлённый полный текст.
        """
        text = self._ensure_markers(text)
        lines = text.splitlines()
        begin_idx, end_idx = self._find_gui_block(text)

        if begin_idx is None or end_idx is None:
            return text

        result = lines[:begin_idx + 1] + new_gui_lines + lines[end_idx:]
        return "\n".join(result) + "\n"

    # ────────────── Валидация ──────────────

    def _validate_ip(self, ip_str):
        """Валидация IP-адреса (v4/v6)."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _validate_domain(self, domain):
        """Валидация доменного имени."""
        if not domain or len(domain) > 253:
            return False
        domain = domain.lower().strip().rstrip(".")
        return bool(DOMAIN_RE.match(domain))

    def _normalize_domain(self, domain):
        """Нормализация домена: lowercase, trim, strip trailing dot."""
        if not domain:
            return ""
        domain = domain.lower().strip().rstrip(".")
        # Убираем протоколы
        for prefix in ("http://", "https://", "ftp://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        # Убираем пути
        if "/" in domain:
            domain = domain.split("/")[0]
        # Убираем порт
        if ":" in domain and not domain.startswith("["):
            domain = domain.split(":")[0]
        # Убираем www
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    # ────────────── Публичный API ──────────────

    def get_entries(self):
        """
        Все записи из /etc/hosts.
        Возвращает list[dict] с is_system=True/False.
        """
        with self._lock:
            text = self._read_file()
            return self._parse_lines(text)

    def get_custom_entries(self):
        """Только записи GUI (между маркерами)."""
        entries = self.get_entries()
        return [e for e in entries if not e["is_system"]]

    def get_stats(self):
        """Статистика записей."""
        entries = self.get_entries()
        total = len(entries)
        system = sum(1 for e in entries if e["is_system"])
        custom = total - system
        blocked = sum(1 for e in entries if not e["is_system"] and e["ip"] == "0.0.0.0")
        redirected = custom - blocked
        return {
            "total": total,
            "system": system,
            "custom": custom,
            "blocked": blocked,
            "redirected": redirected,
        }

    def add_entry(self, ip, domain):
        """
        Добавить запись в GUI-блок.
        Возвращает True при успехе.
        """
        domain = self._normalize_domain(domain)

        if not self._validate_ip(ip):
            log.error(f"Невалидный IP: {ip}", source="hosts")
            return False

        if not self._validate_domain(domain):
            log.error(f"Невалидный домен: {domain}", source="hosts")
            return False

        if domain in SYSTEM_DOMAINS:
            log.error(f"Нельзя изменять системный домен: {domain}", source="hosts")
            return False

        with self._lock:
            text = self._read_file()
            text = self._ensure_markers(text)

            # Проверяем лимит
            custom = [e for e in self._parse_lines(text) if not e["is_system"]]
            if len(custom) >= MAX_GUI_ENTRIES:
                log.error(
                    f"Достигнут лимит записей GUI: {MAX_GUI_ENTRIES}",
                    source="hosts",
                )
                return False

            # Проверяем дубли в GUI-блоке
            for e in custom:
                if e["domain"] == domain:
                    log.warning(
                        f"Домен {domain} уже есть в GUI-блоке, обновляем IP",
                        source="hosts",
                    )
                    return self._update_entry_ip(text, domain, ip)

            # Бэкап
            self.backup()

            # Добавляем строку перед MARKER_END
            gui_text = self._get_gui_entries_text(text)
            gui_lines = [l for l in gui_text.splitlines() if l.strip()]
            gui_lines.append(f"{ip} {domain}")

            new_text = self._replace_gui_block(text, gui_lines)
            if self._write_file(new_text):
                log.info(f"Добавлена запись: {ip} → {domain}", source="hosts")
                return True
            return False

    def _update_entry_ip(self, text, domain, new_ip):
        """Обновить IP для существующего домена в GUI-блоке."""
        self.backup()

        gui_text = self._get_gui_entries_text(text)
        new_lines = []
        for line in gui_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].lower() == domain:
                new_lines.append(f"{new_ip} {domain}")
            else:
                new_lines.append(line)

        new_text = self._replace_gui_block(text, new_lines)
        if self._write_file(new_text):
            log.info(f"Обновлена запись: {new_ip} → {domain}", source="hosts")
            return True
        return False

    def remove_entry(self, domain):
        """
        Удалить запись по домену из GUI-блока.
        Возвращает True при успехе.
        """
        domain = self._normalize_domain(domain)
        if not domain:
            return False

        with self._lock:
            text = self._read_file()
            text = self._ensure_markers(text)

            gui_text = self._get_gui_entries_text(text)
            new_lines = []
            found = False

            for line in gui_text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    new_lines.append(line)
                    continue

                parts = stripped.split()
                if len(parts) >= 2 and parts[1].lower() == domain:
                    found = True
                    continue  # Пропускаем — удаляем
                new_lines.append(line)

            if not found:
                log.warning(f"Домен {domain} не найден в GUI-блоке", source="hosts")
                return False

            self.backup()
            new_text = self._replace_gui_block(text, new_lines)
            if self._write_file(new_text):
                log.info(f"Удалена запись: {domain}", source="hosts")
                return True
            return False

    def add_block(self, domains):
        """
        Заблокировать домены (0.0.0.0 → domain).
        Возвращает количество добавленных записей.
        """
        count = 0
        for domain in domains:
            domain = self._normalize_domain(domain)
            if domain and self._validate_domain(domain) and domain not in SYSTEM_DOMAINS:
                if self.add_entry("0.0.0.0", domain):
                    count += 1
        return count

    def remove_block(self, domains):
        """
        Снять блокировку доменов (удалить из GUI-блока).
        Возвращает количество удалённых записей.
        """
        count = 0
        for domain in domains:
            domain = self._normalize_domain(domain)
            if domain and self.remove_entry(domain):
                count += 1
        return count

    def apply_preset(self, preset_name, custom_entries=None):
        """
        Применить пресет (добавить все записи пресета в GUI-блок).
        custom_entries — опционально, список (ip, domain) для переопределения IP.
        Возвращает количество добавленных записей.
        """
        preset = PRESETS.get(preset_name)
        if not preset:
            log.error(f"Пресет не найден: {preset_name}", source="hosts")
            return 0

        entries = custom_entries if custom_entries else preset["entries"]
        count = 0
        for ip, domain in entries:
            if self.add_entry(ip, domain):
                count += 1

        log.info(
            f"Пресет '{preset['name']}' применён: {count} записей",
            source="hosts",
        )
        return count

    def get_presets(self):
        """Список доступных пресетов."""
        result = []
        for key, p in PRESETS.items():
            result.append({
                "id": key,
                "name": p["name"],
                "description": p["description"],
                "count": len(p["entries"]),
                "entries": [
                    {"ip": ip, "domain": domain}
                    for ip, domain in p["entries"]
                ],
            })
        return result

    def get_raw(self):
        """Весь файл /etc/hosts как текст."""
        with self._lock:
            return self._read_file()

    def save_raw(self, text):
        """
        Сохранить весь файл /etc/hosts (raw-редактирование).
        Создаёт бэкап перед сохранением.
        Возвращает True при успехе.
        """
        with self._lock:
            self.backup()
            if self._write_file(text):
                log.info("Файл hosts сохранён (raw-режим)", source="hosts")
                return True
            return False

    def backup(self):
        """
        Создать бэкап /etc/hosts.
        Возвращает путь к бэкапу или пустую строку при ошибке.
        """
        timestamp = int(time.time())
        backup_path = os.path.join(BACKUP_DIR, f"hosts.bak.{timestamp}")

        try:
            # Читаем и пишем вместо shutil.copy — на случай если /etc/hosts не поддерживает cp
            content = self._read_file()
            if content:
                with open(backup_path, "w", encoding="utf-8") as f:
                    f.write(content)
                log.info(f"Бэкап создан: {backup_path}", source="hosts")
                return backup_path
            else:
                log.warning("Нечего бэкапить — файл hosts пуст или недоступен", source="hosts")
                return ""
        except OSError as e:
            log.error(f"Ошибка создания бэкапа: {e}", source="hosts")
            return ""

    def get_backups(self):
        """Список доступных бэкапов."""
        backups = []
        try:
            for fname in os.listdir(BACKUP_DIR):
                if fname.startswith("hosts.bak."):
                    path = os.path.join(BACKUP_DIR, fname)
                    try:
                        ts_str = fname.split(".")[-1]
                        ts = int(ts_str)
                    except (ValueError, IndexError):
                        ts = 0
                    try:
                        size = os.path.getsize(path)
                    except OSError:
                        size = 0
                    backups.append({
                        "path": path,
                        "filename": fname,
                        "timestamp": ts,
                        "size": size,
                    })
        except OSError:
            pass

        backups.sort(key=lambda x: x["timestamp"], reverse=True)
        return backups

    def restore(self, backup_path):
        """
        Восстановить /etc/hosts из бэкапа.
        Возвращает True при успехе.
        """
        if not backup_path or not os.path.isfile(backup_path):
            log.error(f"Бэкап не найден: {backup_path}", source="hosts")
            return False

        # Безопасность: только файлы из /tmp/
        if not backup_path.startswith(BACKUP_DIR + "/"):
            log.error(f"Восстановление разрешено только из {BACKUP_DIR}", source="hosts")
            return False

        with self._lock:
            try:
                with open(backup_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                # Бэкап текущей версии перед восстановлением
                self.backup()
                if self._write_file(content):
                    log.info(f"Восстановлено из бэкапа: {backup_path}", source="hosts")
                    return True
                return False
            except OSError as e:
                log.error(f"Ошибка восстановления: {e}", source="hosts")
                return False

    def clear_gui_entries(self):
        """
        Удалить все GUI-записи (очистить блок между маркерами).
        Возвращает True при успехе.
        """
        with self._lock:
            text = self._read_file()
            text = self._ensure_markers(text)
            self.backup()
            new_text = self._replace_gui_block(text, [])
            if self._write_file(new_text):
                log.info("Все GUI-записи удалены", source="hosts")
                return True
            return False


# ═══════════════════ Singleton ═══════════════════

_instance = None
_instance_lock = threading.Lock()


def get_hosts_manager(hosts_path=None):
    """Получить singleton экземпляр HostsManager."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = HostsManager(hosts_path)
    return _instance



