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

# Путь для критических ошибок (persistent, но с ограничением)
CRITICAL_LOG_PATH = None  # Устанавливается из конфига


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
        self._counter = 0  # Счётчик записей (для SSE event ID)

    def add(self, level: str, message: str, source: str = "") -> LogEntry:
        """Добавить запись в буфер."""
        entry = LogEntry(level, message, source)

        with self._lock:
            self._buffer.append(entry)
            self._counter += 1

        # Пишем в файл (вне lock чтобы не блокировать)
        if self._file_enabled:
            self._write_to_file(entry)

        # Уведомляем SSE-слушателей
        for callback in self._listeners[:]:
            try:
                callback(entry)
            except Exception:
                # Удаляем сломанных слушателей
                self._listeners.remove(callback)

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
        self._listeners.append(callback)

    def remove_listener(self, callback):
        """Удалить SSE-слушателя."""
        try:
            self._listeners.remove(callback)
        except ValueError:
            pass

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



