import os
import struct
import threading
from core.log_buffer import log
from core.config_manager import get_config_manager
BUILTIN_PREFIX = "fake_default_"
BUILTIN_NAMES = ("fake_default_http", "fake_default_tls", "fake_default_quic")
MAX_BLOB_SIZE = 65536
VALID_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_-."
)
_instance = None
_lock = threading.Lock()
def get_blob_manager():
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = BlobManager()
    return _instance
class BlobManager:
    def __init__(self):
        cfg = get_config_manager()
        base_path = cfg.get("zapret", "base_path", default="/opt/zapret2")
        self.blobs_dir = os.path.join(base_path, "blobs")
        self.system_blobs_dir = os.path.join(base_path, "files", "fake")
        self._lock = threading.Lock()
        self._ensure_dir()
        log.info(f"BlobManager инициализирован: {self.blobs_dir}", source="blobs")
    def _ensure_dir(self):
        try:
            os.makedirs(self.blobs_dir, exist_ok=True)
        except OSError as e:
            log.error(f"Не удалось создать директорию блобов: {e}", source="blobs")
    @staticmethod
    def validate_name(name):
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
        """Полный путь к файлу блоба (ищет в blobs/, затем в files/fake/)."""
        path = os.path.join(self.blobs_dir, name)
        if os.path.isfile(path):
            return path
        # Ищем в files/fake/ (системные .bin-файлы zapret2)
        sys_path = os.path.join(self.system_blobs_dir, name)
        if os.path.isfile(sys_path):
            return sys_path
        return path  # Возвращаем путь в blobs/ по умолчанию (для создания)
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
        if data and len(data) >= 3:
            if data[0] == 0x16 and data[1] == 0x03:
                return "tls"
            try:
                start = data[:16].decode("ascii", errors="strict")
                if start.startswith(("GET ", "POST ", "HEAD ", "PUT ",
                                     "HTTP/", "CONNECT ")):
                    return "http"
            except (UnicodeDecodeError, ValueError):
                pass
            if data[0] & 0x80:
                return "quic"
        return "unknown"
    def get_blobs(self):
        self._ensure_dir()
        result = []
        seen_names = set()
        self._scan_dir(self.blobs_dir, result, seen_names, force_builtin=False)
        self._scan_dir(self.system_blobs_dir, result, seen_names,
                       force_builtin=True, extension_filter=".bin")
        return result
    def _scan_dir(self, dir_path, result, seen_names,
                  force_builtin=False, extension_filter=None):
        if not os.path.isdir(dir_path):
            return
        try:
            entries = sorted(os.listdir(dir_path))
        except OSError as e:
            log.error(f"Ошибка чтения директории {dir_path}: {e}", source="blobs")
            return
        for entry in entries:
            full_path = os.path.join(dir_path, entry)
            if not os.path.isfile(full_path):
                continue
            if entry.startswith("."):
                continue
            if extension_filter and not entry.lower().endswith(extension_filter):
                continue
            if entry in seen_names:
                continue
            seen_names.add(entry)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            data_head = None
            try:
                with open(full_path, "rb") as f:
                    data_head = f.read(64)
            except OSError:
                pass
            is_builtin = force_builtin or self.is_builtin(entry)
            result.append({
                "name": entry,
                "size": size,
                "type": self._detect_type(entry, data_head),
                "is_builtin": is_builtin,
                "path": full_path,
            })
    def get_blob(self, name):
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
        is_builtin = self.is_builtin(name)
        if not is_builtin and self.system_blobs_dir and full_path.startswith(self.system_blobs_dir):
            is_builtin = True
        return {
            "name": name,
            "size": size,
            "type": self._detect_type(name, data_head),
            "is_builtin": is_builtin,
            "path": full_path,
        }
    def get_blob_content(self, name):
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
    def generate_fake_tls(self, domain="example.com"):
        domain_bytes = domain.encode("ascii")
        sni_entry = (
            b"\x00"
            + struct.pack("!H", len(domain_bytes))
            + domain_bytes
        )
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_sni = (
            b"\x00\x00"
            + struct.pack("!H", len(sni_list))
            + sni_list
        )
        ext_supported_versions = (
            b"\x00\x2b"
            + b"\x00\x05"
            + b"\x04"
            + b"\x03\x03"
            + b"\x03\x04"
        )
        ext_ec_point = (
            b"\x00\x0b"
            + b"\x00\x02"
            + b"\x01"
            + b"\x00"
        )
        ext_groups = (
            b"\x00\x0a"
            + b"\x00\x06"
            + b"\x00\x04"
            + b"\x00\x17"
            + b"\x00\x18"
        )
        all_extensions = ext_sni + ext_supported_versions + ext_ec_point + ext_groups
        extensions_block = struct.pack("!H", len(all_extensions)) + all_extensions
        random_bytes = os.urandom(32)
        session_id = os.urandom(32)
        session_id_block = bytes([len(session_id)]) + session_id
        cipher_suites = (
            b"\x13\x01"
            + b"\x13\x02"
            + b"\xc0\x2b"
            + b"\xc0\x2f"
            + b"\xc0\x2c"
            + b"\xc0\x30"
        )
        ciphers_block = struct.pack("!H", len(cipher_suites)) + cipher_suites
        compression = b"\x01\x00"
        client_hello_body = (
            b"\x03\x03"
            + random_bytes
            + session_id_block
            + ciphers_block
            + compression
            + extensions_block
        )
        handshake = (
            b"\x01"
            + struct.pack("!I", len(client_hello_body))[1:]
            + client_hello_body
        )
        record = (
            b"\x16"
            + b"\x03\x01"
            + struct.pack("!H", len(handshake))
            + handshake
        )
        log.info(
            f"Сгенерирован fake TLS ClientHello для {domain} ({len(record)} байт)",
            source="blobs"
        )
        return record
    def generate_fake_http(self, host="example.com"):
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
    def get_stats(self):
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
    @staticmethod
    def _parse_hex(hex_string):
        if not hex_string or not hex_string.strip():
            raise ValueError("Пустая hex-строка")
        s = hex_string.strip()
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
