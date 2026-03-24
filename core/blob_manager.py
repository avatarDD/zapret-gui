# core/blob_manager.py
"""
Менеджер блобов (бинарные данные для fake-пакетов nfqws2).

Блобы хранятся в {zapret.base_path}/blobs/ (обычно /opt/zapret2/blobs/).
nfqws2 использует их через параметр --lua-desync=fake:blob=<имя_блоба>.

Встроенные имена (builtin): fake_default_http, fake_default_tls, fake_default_quic.
Пользовательские блобы — произвольные файлы в директории blobs/.

Использование:
    from core.blob_manager import get_blob_manager
    bm = get_blob_manager()
    blobs = bm.get_blobs()
    bm.save_blob("my_fake_tls", tls_bytes)
"""

import os
import struct
import threading

from core.log_buffer import log
from core.config_manager import get_config_manager

# ═══════════════════ Константы ═══════════════════

BUILTIN_PREFIX = "fake_default_"
BUILTIN_NAMES = ("fake_default_http", "fake_default_tls", "fake_default_quic")

# Максимальный размер блоба — 64 KB (fake-пакеты обычно 200-600 байт)
MAX_BLOB_SIZE = 65536

# Допустимые символы в имени блоба
VALID_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_-."
)


# ═══════════════════ Singleton ═══════════════════

_instance = None
_lock = threading.Lock()


def get_blob_manager():
    """Получить singleton-экземпляр BlobManager."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = BlobManager()
    return _instance


# ═══════════════════ BlobManager ═══════════════════

class BlobManager:
    """Управление блоб-файлами для nfqws2."""

    def __init__(self):
        cfg = get_config_manager()
        base_path = cfg.get("zapret", "base_path", default="/opt/zapret2")
        self.blobs_dir = os.path.join(base_path, "blobs")
        self._lock = threading.Lock()
        self._ensure_dir()
        log.info(f"BlobManager инициализирован: {self.blobs_dir}", source="blobs")

    def _ensure_dir(self):
        """Создать директорию блобов если не существует."""
        try:
            os.makedirs(self.blobs_dir, exist_ok=True)
        except OSError as e:
            log.error(f"Не удалось создать директорию блобов: {e}", source="blobs")

    # ─────────────── Валидация ───────────────

    @staticmethod
    def validate_name(name):
        """
        Валидировать имя блоба.
        Возвращает (is_valid, error_message).
        """
        if not name:
            return False, "Имя не может быть пустым"

        if len(name) > 128:
            return False, "Имя слишком длинное (макс. 128 символов)"

        if not all(c in VALID_NAME_CHARS for c in name):
            bad = [c for c in name if c not in VALID_NAME_CHARS]
            return False, "Недопустимые символы в имени: %s" % "".join(set(bad))

        # Запрет path traversal
        if ".." in name or "/" in name or "\\" in name:
            return False, "Имя содержит запрещённые последовательности"

        return True, ""

    @staticmethod
    def is_builtin(name):
        """Проверить, является ли блоб встроенным."""
        return name.startswith(BUILTIN_PREFIX)

    def _blob_path(self, name):
        """Полный путь к файлу блоба."""
        return os.path.join(self.blobs_dir, name)

    def _detect_type(self, name, data=None):
        """
        Определить тип блоба по имени и/или содержимому.
        Возвращает: 'tls', 'http', 'quic', 'unknown'.
        """
        name_lower = name.lower()

        # По имени
        if "tls" in name_lower or "clienthello" in name_lower:
            return "tls"
        if "http" in name_lower:
            return "http"
        if "quic" in name_lower:
            return "quic"

        # По содержимому
        if data and len(data) >= 3:
            # TLS Record Layer: Content Type = Handshake (0x16)
            if data[0] == 0x16 and data[1] == 0x03:
                return "tls"
            # HTTP: начинается с ASCII метода
            try:
                start = data[:16].decode("ascii", errors="strict")
                if start.startswith(("GET ", "POST ", "HEAD ", "PUT ",
                                     "HTTP/", "CONNECT ")):
                    return "http"
            except (UnicodeDecodeError, ValueError):
                pass
            # QUIC: Initial packet (первый бит = 1 для Long Header)
            if data[0] & 0x80:
                return "quic"

        return "unknown"

    # ─────────────── CRUD ───────────────

    def get_blobs(self):
        """
        Список всех блобов.
        Возвращает list[dict] с полями:
            name, size, type, is_builtin, path
        """
        self._ensure_dir()
        result = []

        try:
            entries = sorted(os.listdir(self.blobs_dir))
        except OSError as e:
            log.error(f"Ошибка чтения директории блобов: {e}", source="blobs")
            return result

        for entry in entries:
            full_path = os.path.join(self.blobs_dir, entry)

            # Только файлы
            if not os.path.isfile(full_path):
                continue

            # Пропускаем скрытые и служебные
            if entry.startswith("."):
                continue

            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0

            # Читаем начало для определения типа
            data_head = None
            try:
                with open(full_path, "rb") as f:
                    data_head = f.read(64)
            except OSError:
                pass

            result.append({
                "name": entry,
                "size": size,
                "type": self._detect_type(entry, data_head),
                "is_builtin": self.is_builtin(entry),
                "path": full_path,
            })

        return result

    def get_blob(self, name):
        """
        Информация о конкретном блобе.
        Возвращает dict или None.
        """
        valid, err = self.validate_name(name)
        if not valid:
            return None

        full_path = self._blob_path(name)
        if not os.path.isfile(full_path):
            return None

        try:
            size = os.path.getsize(full_path)
            with open(full_path, "rb") as f:
                data_head = f.read(64)
        except OSError:
            return None

        return {
            "name": name,
            "size": size,
            "type": self._detect_type(name, data_head),
            "is_builtin": self.is_builtin(name),
            "path": full_path,
        }

    def get_blob_content(self, name):
        """
        Прочитать содержимое блоба (raw bytes).
        Возвращает bytes или None.
        """
        valid, err = self.validate_name(name)
        if not valid:
            return None

        full_path = self._blob_path(name)
        if not os.path.isfile(full_path):
            return None

        try:
            with open(full_path, "rb") as f:
                data = f.read(MAX_BLOB_SIZE)
            return data
        except OSError as e:
            log.error(f"Ошибка чтения блоба {name}: {e}", source="blobs")
            return None

    def get_blob_hex(self, name):
        """
        Содержимое блоба в hex-формате.
        Возвращает строку вида "16 03 01 00 f1 ..." или None.
        """
        data = self.get_blob_content(name)
        if data is None:
            return None
        return " ".join(f"{b:02x}" for b in data)

    def save_blob(self, name, data):
        """
        Сохранить блоб из бинарных данных.
        Возвращает (success: bool, error: str|None).
        """
        valid, err = self.validate_name(name)
        if not valid:
            return False, err

        if not isinstance(data, (bytes, bytearray)):
            return False, "Данные должны быть bytes"

        if len(data) == 0:
            return False, "Данные не могут быть пустыми"

        if len(data) > MAX_BLOB_SIZE:
            return False, f"Размер превышает лимит ({MAX_BLOB_SIZE} байт)"

        self._ensure_dir()
        full_path = self._blob_path(name)

        try:
            with self._lock:
                with open(full_path, "wb") as f:
                    f.write(data)
            log.success(
                f"Блоб сохранён: {name} ({len(data)} байт)",
                source="blobs"
            )
            return True, None
        except OSError as e:
            msg = f"Ошибка записи блоба {name}: {e}"
            log.error(msg, source="blobs")
            return False, msg

    def save_blob_hex(self, name, hex_string):
        """
        Сохранить блоб из hex-строки.
        Принимает форматы: "16 03 01", "160301", "16:03:01", "0x16 0x03".
        Возвращает (success: bool, error: str|None).
        """
        try:
            data = self._parse_hex(hex_string)
        except ValueError as e:
            return False, f"Невалидный hex: {e}"

        return self.save_blob(name, data)

    def delete_blob(self, name):
        """
        Удалить блоб (только пользовательские).
        Возвращает (success: bool, error: str|None).
        """
        valid, err = self.validate_name(name)
        if not valid:
            return False, err

        if self.is_builtin(name):
            return False, "Нельзя удалить встроенный блоб"

        full_path = self._blob_path(name)
        if not os.path.isfile(full_path):
            return False, f"Блоб не найден: {name}"

        try:
            with self._lock:
                os.remove(full_path)
            log.success(f"Блоб удалён: {name}", source="blobs")
            return True, None
        except OSError as e:
            msg = f"Ошибка удаления блоба {name}: {e}"
            log.error(msg, source="blobs")
            return False, msg

    # ─────────────── Генерация fake-пакетов ───────────────

    def generate_fake_tls(self, domain="example.com"):
        """
        Сгенерировать минимальный fake TLS ClientHello с указанным SNI.

        Структура:
            Record Layer:  \\x16\\x03\\x01 + length(2 bytes)
            Handshake:     \\x01 + length(3 bytes)
            ClientHello:   \\x03\\x03 + random(32) + session_id + ciphers + compression + extensions
            Extensions:    SNI (type=0x0000) с указанным доменом

        Возвращает bytes.
        """
        domain_bytes = domain.encode("ascii")

        # ── SNI extension ──
        # SNI list entry: type(1) + length(2) + hostname
        sni_entry = (
            b"\x00"  # host name type = 0
            + struct.pack("!H", len(domain_bytes))
            + domain_bytes
        )

        # SNI list: length(2) + entries
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry

        # Extension: type(2) + length(2) + data
        ext_sni = (
            b"\x00\x00"  # extension type = server_name (0)
            + struct.pack("!H", len(sni_list))
            + sni_list
        )

        # ── Supported Versions extension (TLS 1.3 + 1.2) ──
        ext_supported_versions = (
            b"\x00\x2b"  # extension type = supported_versions (43)
            + b"\x00\x05"  # extension length = 5
            + b"\x04"  # versions list length = 4
            + b"\x03\x03"  # TLS 1.2
            + b"\x03\x04"  # TLS 1.3 (proposed)
        )

        # ── EC Point Formats extension ──
        ext_ec_point = (
            b"\x00\x0b"  # type = ec_point_formats (11)
            + b"\x00\x02"  # ext length = 2
            + b"\x01"  # formats length = 1
            + b"\x00"  # uncompressed
        )

        # ── Supported Groups extension ──
        ext_groups = (
            b"\x00\x0a"  # type = supported_groups (10)
            + b"\x00\x06"  # ext length = 6
            + b"\x00\x04"  # list length = 4
            + b"\x00\x17"  # secp256r1
            + b"\x00\x18"  # secp384r1
        )

        # ── Собираем все extensions ──
        all_extensions = ext_sni + ext_supported_versions + ext_ec_point + ext_groups
        extensions_block = struct.pack("!H", len(all_extensions)) + all_extensions

        # ── ClientHello body ──
        random_bytes = os.urandom(32)

        # Session ID: length(1) + id (32 bytes для совместимости)
        session_id = os.urandom(32)
        session_id_block = bytes([len(session_id)]) + session_id

        # Cipher suites: length(2) + suites
        cipher_suites = (
            b"\x13\x01"  # TLS_AES_128_GCM_SHA256
            + b"\x13\x02"  # TLS_AES_256_GCM_SHA384
            + b"\xc0\x2b"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            + b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            + b"\xc0\x2c"  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            + b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
        ciphers_block = struct.pack("!H", len(cipher_suites)) + cipher_suites

        # Compression methods: length(1) + null
        compression = b"\x01\x00"

        # Полное тело ClientHello
        client_hello_body = (
            b"\x03\x03"  # ClientHello version: TLS 1.2
            + random_bytes
            + session_id_block
            + ciphers_block
            + compression
            + extensions_block
        )

        # ── Handshake message ──
        # type(1) + length(3)
        handshake = (
            b"\x01"  # HandshakeType = ClientHello
            + struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
            + client_hello_body
        )

        # ── TLS Record Layer ──
        record = (
            b"\x16"  # Content Type = Handshake
            + b"\x03\x01"  # Version: TLS 1.0 (для совместимости с DPI)
            + struct.pack("!H", len(handshake))
            + handshake
        )

        log.info(
            f"Сгенерирован fake TLS ClientHello для {domain} ({len(record)} байт)",
            source="blobs"
        )
        return record

    def generate_fake_http(self, host="example.com"):
        """
        Сгенерировать минимальный fake HTTP GET запрос.

        Формат:
            GET / HTTP/1.1\\r\\n
            Host: <host>\\r\\n
            User-Agent: Mozilla/5.0\\r\\n
            Accept: */*\\r\\n
            Connection: keep-alive\\r\\n
            \\r\\n

        Возвращает bytes.
        """
        request_str = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            f"Accept: */*\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        data = request_str.encode("ascii")

        log.info(
            f"Сгенерирован fake HTTP GET для {host} ({len(data)} байт)",
            source="blobs"
        )
        return data

    # ─────────────── Статистика ───────────────

    def get_stats(self):
        """Общая статистика по блобам."""
        blobs = self.get_blobs()

        total_size = sum(b["size"] for b in blobs)
        builtin_count = sum(1 for b in blobs if b["is_builtin"])
        user_count = sum(1 for b in blobs if not b["is_builtin"])

        types_count = {}
        for b in blobs:
            t = b["type"]
            types_count[t] = types_count.get(t, 0) + 1

        return {
            "total": len(blobs),
            "builtin": builtin_count,
            "user": user_count,
            "total_size": total_size,
            "types": types_count,
            "blobs_dir": self.blobs_dir,
        }

    # ─────────────── Утилиты ───────────────

    @staticmethod
    def _parse_hex(hex_string):
        """
        Разобрать hex-строку в bytes.
        Поддерживает форматы:
            "16 03 01 00 f1"
            "160301"
            "16:03:01"
            "0x16 0x03 0x01"
            "\\x16\\x03\\x01"
        """
        if not hex_string or not hex_string.strip():
            raise ValueError("Пустая hex-строка")

        s = hex_string.strip()

        # Убираем префиксы 0x и \\x
        s = s.replace("0x", "").replace("0X", "")
        s = s.replace("\\x", "").replace("\\X", "")

        # Убираем разделители
        s = s.replace(" ", "").replace(":", "").replace("-", "")
        s = s.replace("\n", "").replace("\r", "").replace("\t", "")

        # Валидируем — только hex-символы
        if not all(c in "0123456789abcdefABCDEF" for c in s):
            bad = [c for c in s if c not in "0123456789abcdefABCDEF"]
            raise ValueError("Недопустимые символы: %s" % "".join(set(bad)))

        if len(s) % 2 != 0:
            raise ValueError("Нечётное количество hex-символов")

        if len(s) == 0:
            raise ValueError("Пустые данные после очистки")

        return bytes.fromhex(s)

    @staticmethod
    def format_hex(data, columns=16):
        """
        Форматировать bytes в hex-дамп для отображения.
        Возвращает строку с offset | hex | ascii.
        """
        lines = []
        for offset in range(0, len(data), columns):
            chunk = data[offset:offset + columns]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "." for b in chunk
            )
            lines.append(f"{offset:08x}  {hex_part:<{columns * 3}}  |{ascii_part}|")
        return "\n".join(lines)
