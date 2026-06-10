# core/log_buffer.py
"""
Кольцевой буфер логов в RAM.

Логи хранятся в памяти (collections.deque) и опционально пишутся
в /tmp/zapret-gui.log. Flash-память роутера не затрагивается.

Использование:
    from core.log_buffer import log, get_log_buffer

    log.info("nfqws2 запущен")
    log.error("Не удалось применить правила iptables")
    log.warning("Процесс не найден")
    log.success("Стратегия применена")
    log.debug("PID: 1234")

    # Получить последние записи
    entries = get_log_buffer().get_last(50)
"""

import time
import threading
import os
from collections import deque
from datetime import datetime


# Уровни логирования с цветовыми кодами для фронтенда
LEVELS = {
    "DEBUG":   {"priority": 0, "color": "#6b7280"},
    "INFO":    {"priority": 1, "color": "#9ca3af"},
    "SUCCESS": {"priority": 2, "color": "#34d399"},
    "WARNING": {"priority": 3, "color": "#fbbf24"},
    "ERROR":   {"priority": 4, "color": "#f87171"},
}

# Максимальное количество записей в буфере
MAX_ENTRIES = 2000

# Максимальный размер файла логов в /tmp/ (байт)
MAX_FILE_SIZE = 512 * 1024  # 512 KB

# Путь к файлу логов (RAM-диск)
LOG_FILE_PATH = "/tmp/zapret-gui.log"

# Персистентный лог критичных событий (на постоянном носителе рядом с
# settings.json) — переживает перезагрузку роутера.
PERSIST_MAX_FILE_SIZE = 128 * 1024   # 128 KB, с ротацией
PERSIST_MIN_PRIORITY_DEFAULT = 3      # WARNING и выше


class LogEntry:
    """Одна запись лога."""

    __slots__ = ("timestamp", "level", "message", "source")

    def __init__(self, level: str, message: str, source: str = ""):
        self.timestamp = time.time()
        self.level = level.upper()
        self.message = message
        self.source = source

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "time": datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S"),
            "date": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d"),
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "color": LEVELS.get(self.level, LEVELS["INFO"])["color"],
        }

    def format_line(self) -> str:
        ts = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        src = f" [{self.source}]" if self.source else ""
        return f"{ts} [{self.level:7s}]{src} {self.message}"


class LogBuffer:
    """
    Потокобезопасный кольцевой буфер логов.

    Хранит последние MAX_ENTRIES записей в памяти.
    Опционально дублирует в файл /tmp/zapret-gui.log.
    """

    def __init__(self, max_entries: int = MAX_ENTRIES, file_path: str = LOG_FILE_PATH):
        self._buffer = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._file_path = file_path
        self._file_enabled = True
        self._listeners = []  # Callbacks для SSE
        self._listeners_lock = threading.Lock()
        self._counter = 0  # Счётчик записей (для SSE event ID)
        # Персистентный лог критичных событий (переживает перезагрузку).
        self._persist_enabled = False
        self._persist_path = None
        self._persist_min_priority = PERSIST_MIN_PRIORITY_DEFAULT
        self._persist_max = PERSIST_MAX_FILE_SIZE

    def add(self, level: str, message: str, source: str = "") -> LogEntry:
        """Добавить запись в буфер."""
        entry = LogEntry(level, message, source)

        with self._lock:
            self._buffer.append(entry)
            self._counter += 1

        # Пишем в файл (вне lock чтобы не блокировать)
        if self._file_enabled:
            self._write_to_file(entry)

        # Персистентно — только критичные события (WARNING+), чтобы они
        # пережили перезагрузку (главный лог в /tmp при ребуте теряется).
        if self._persist_enabled and self._persist_path:
            prio = LEVELS.get(entry.level, LEVELS["INFO"])["priority"]
            if prio >= self._persist_min_priority:
                self._write_persistent(entry)

        # Уведомляем SSE-слушателей (снимок под локом, вызов — вне лока).
        with self._listeners_lock:
            listeners = self._listeners[:]
        broken = []
        for callback in listeners:
            try:
                callback(entry)
            except Exception:
                broken.append(callback)
        if broken:
            with self._listeners_lock:
                for cb in broken:
                    try:
                        self._listeners.remove(cb)
                    except ValueError:
                        pass

        return entry

    def get_last(self, n: int = 100) -> list:
        """Получить последние n записей."""
        with self._lock:
            entries = list(self._buffer)
        return [e.to_dict() for e in entries[-n:]]

    def get_since(self, since_timestamp: float) -> list:
        """Получить записи новее указанного timestamp."""
        with self._lock:
            entries = list(self._buffer)
        return [e.to_dict() for e in entries if e.timestamp > since_timestamp]

    def get_filtered(self, level: str = None, search: str = None,
                     n: int = 100) -> list:
        """Получить записи с фильтрацией по уровню и тексту."""
        with self._lock:
            entries = list(self._buffer)

        if level:
            min_priority = LEVELS.get(level.upper(), LEVELS["INFO"])["priority"]
            entries = [e for e in entries
                       if LEVELS.get(e.level, LEVELS["INFO"])["priority"] >= min_priority]

        if search:
            search_lower = search.lower()
            entries = [e for e in entries if search_lower in e.message.lower()]

        return [e.to_dict() for e in entries[-n:]]

    def clear(self):
        """Очистить буфер."""
        with self._lock:
            self._buffer.clear()
            self._counter = 0

    def get_count(self) -> int:
        """Количество записей в буфере."""
        return len(self._buffer)

    def get_counter(self) -> int:
        """Общий счётчик записей (для SSE)."""
        return self._counter

    def add_listener(self, callback):
        """Добавить SSE-слушателя."""
        with self._listeners_lock:
            self._listeners.append(callback)

    def remove_listener(self, callback):
        """Удалить SSE-слушателя."""
        with self._listeners_lock:
            try:
                self._listeners.remove(callback)
            except ValueError:
                pass

    # ─────── персистентный лог критичных событий ───────

    def set_persistent(self, enabled, path=None, min_level=None,
                       max_size=None):
        """
        Настроить персистентный лог (переживает перезагрузку). Вызывается
        из reconfigure_persistent_from_config() на старте и при смене
        настроек в GUI.
        """
        with self._lock:
            self._persist_enabled = bool(enabled)
            if path is not None:
                self._persist_path = path or None
            if min_level:
                self._persist_min_priority = LEVELS.get(
                    str(min_level).upper(), LEVELS["WARNING"])["priority"]
            if max_size:
                self._persist_max = int(max_size)

    def get_persistent_status(self) -> dict:
        return {
            "enabled":      self._persist_enabled,
            "path":         self._persist_path,
            "min_priority": self._persist_min_priority,
            "max_size":     self._persist_max,
        }

    def read_persistent(self, max_bytes: int = 64 * 1024) -> str:
        """Прочитать хвост персистентного лога (для показа в GUI)."""
        path = self._persist_path
        if not path or not os.path.exists(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            return data[-max_bytes:]
        except (OSError, IOError):
            return ""

    def _write_persistent(self, entry: "LogEntry"):
        path = self._persist_path
        if not path:
            return
        try:
            d = os.path.dirname(path)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            # Ротация по размеру: оставляем последнюю половину.
            if os.path.exists(path) and os.path.getsize(path) > self._persist_max:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    with open(path, "w", encoding="utf-8") as f:
                        f.writelines(lines[len(lines) // 2:])
                except (OSError, IOError):
                    pass
            with open(path, "a", encoding="utf-8") as f:
                f.write(entry.format_line() + "\n")
        except (OSError, IOError):
            # Путь недоступен — отключаем, чтобы не долбить вхолостую.
            self._persist_enabled = False

    def _write_to_file(self, entry: LogEntry):
        """Записать в файл с ротацией по размеру."""
        try:
            # Проверяем размер и ротируем если нужно
            if os.path.exists(self._file_path):
                size = os.path.getsize(self._file_path)
                if size > MAX_FILE_SIZE:
                    self._rotate_file()

            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(entry.format_line() + "\n")
        except (OSError, IOError):
            # /tmp/ может быть недоступен — не критично
            self._file_enabled = False

    def _rotate_file(self):
        """Ротация: оставляем последнюю половину файла."""
        try:
            with open(self._file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            # Оставляем последнюю половину строк
            half = len(lines) // 2
            with open(self._file_path, "w", encoding="utf-8") as f:
                f.writelines(lines[half:])
        except (OSError, IOError):
            pass


class Logger:
    """
    Удобный интерфейс для логирования.

    Использование:
        from core.log_buffer import log
        log.info("Сообщение")
        log.error("Ошибка", source="firewall")
    """

    def __init__(self, buffer: LogBuffer):
        self._buffer = buffer

    def debug(self, message: str, source: str = ""):
        return self._buffer.add("DEBUG", message, source)

    def info(self, message: str, source: str = ""):
        return self._buffer.add("INFO", message, source)

    def success(self, message: str, source: str = ""):
        return self._buffer.add("SUCCESS", message, source)

    def warning(self, message: str, source: str = ""):
        return self._buffer.add("WARNING", message, source)

    def error(self, message: str, source: str = ""):
        return self._buffer.add("ERROR", message, source)


# === Глобальные экземпляры ===

_log_buffer = LogBuffer()
log = Logger(_log_buffer)


def get_log_buffer() -> LogBuffer:
    """Получить глобальный буфер логов."""
    return _log_buffer


def reconfigure_persistent_from_config():
    """
    Прочитать настройки персистентного лога из settings.json и применить.

    Путь по умолчанию — рядом с settings.json (постоянный носитель), чтобы
    критичные события пережили перезагрузку. Вызывается на старте GUI и
    после изменения секции `logging` в настройках.
    """
    lg = {}
    cfg_dir = ""
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        lg = cm.get("logging") or {}
        cfg_dir = os.path.dirname(cm.path or "")
    except Exception:
        lg = {}
    if not isinstance(lg, dict):
        lg = {}

    enabled = lg.get("persist_critical", True)  # по умолчанию ВКЛ
    path = (lg.get("persist_path") or "").strip()
    if not path:
        path = os.path.join(cfg_dir or "/tmp", "critical.log")
    min_level = lg.get("persist_min_level") or "WARNING"
    _log_buffer.set_persistent(enabled, path=path, min_level=min_level)
    return _log_buffer.get_persistent_status()
