# core/geosite_importer.py
"""
Импорт geosite.dat/geoip.dat категорий в named lists.

Парсит protobuf-файлы v2ray/xray формата и извлекает
домены/IP по категориям (youtube, telegram, discord, etc.).
"""

import os
import struct

from core.log_buffer import log


def parse_geosite(path: str) -> dict:
    """
    Парсинг geosite.dat (protobuf format v2fly).
    Возвращает {category_name: [domain1, domain2, ...]}.
    """
    if not os.path.isfile(path):
        return {}

    try:
        return _parse_protobuf_geosite(path)
    except Exception as e:
        log.warning("geosite parse error: %s" % e, source="geosite")
        return {}


def parse_geoip(path: str) -> dict:
    """
    Парсинг geoip.dat (protobuf format v2fly).
    Возвращает {country_code: [cidr1, cidr2, ...]}.
    """
    if not os.path.isfile(path):
        return {}

    try:
        return _parse_protobuf_geoip(path)
    except Exception as e:
        log.warning("geoip parse error: %s" % e, source="geosite")
        return {}


def list_categories(path: str) -> list:
    """Список категорий в geosite/geoip файле."""
    data = parse_geosite(path) if path.endswith("geosite") else parse_geoip(path)
    return sorted(data.keys())


def import_category(path: str, category: str, list_id: str = "") -> dict:
    """
    Импортировать категорию как named list.
    Если list_id не задан — создаёт новый список.
    """
    data = parse_geosite(path) if "geosite" in path else parse_geoip(path)
    entries = data.get(category, [])
    if not entries:
        return {"ok": False, "error": "Категория '%s' не найдена или пуста" % category}

    from core import named_lists

    if list_id:
        item = named_lists.get(list_id)
        if not item:
            return {"ok": False, "error": "Список %s не найден" % list_id}
        # Добавляем к существующему
        existing = set(item.get("domains") or [])
        new_entries = [e for e in entries if e not in existing]
        all_domains = list(existing) + new_entries
        named_lists.update_fields(list_id, {"domains": all_domains})
        return {"ok": True, "added": len(new_entries), "total": len(all_domains)}
    else:
        # Создаём новый список
        name = "geosite:%s" % category
        res = named_lists.create(name, description="Импорт из geosite: %s" % category)
        if not res.get("ok"):
            return res
        new_id = res["list"]["id"]
        named_lists.update_fields(new_id, {"domains": entries})
        return {"ok": True, "id": new_id, "domains": len(entries)}


# ─────── protobuf parsing (minimal) ───────

def _read_varint(data: bytes, offset: int) -> tuple:
    """Read a varint from protobuf data."""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, offset


def _read_field(data: bytes, offset: int) -> tuple:
    """Read a protobuf field (tag, wire_type, value)."""
    if offset >= len(data):
        return None, None, None, offset
    tag, offset = _read_varint(data, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07

    if wire_type == 0:  # varint
        value, offset = _read_varint(data, offset)
        return field_number, wire_type, value, offset
    elif wire_type == 2:  # length-delimited
        length, offset = _read_varint(data, offset)
        value = data[offset:offset + length]
        offset += length
        return field_number, wire_type, value, offset
    elif wire_type == 5:  # 32-bit
        value = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        return field_number, wire_type, value, offset
    elif wire_type == 1:  # 64-bit
        value = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8
        return field_number, wire_type, value, offset
    else:
        return field_number, wire_type, None, len(data)


def _parse_protobuf_geosite(path: str) -> dict:
    """Parse geosite.dat protobuf."""
    with open(path, "rb") as f:
        data = f.read()

    result = {}
    offset = 0
    while offset < len(data):
        fn, wt, val, offset = _read_field(data, offset)
        if fn is None:
            break
        if fn == 1 and wt == 2 and isinstance(val, bytes):
            # Entry message
            category = ""
            domains = []
            eo = 0
            while eo < len(val):
                efn, ewt, eval_, eo = _read_field(val, eo)
                if efn is None:
                    break
                if efn == 1 and ewt == 2:
                    # country_code or tag
                    category = eval_.decode("utf-8", errors="replace")
                elif efn == 2 and ewt == 2:
                    # domain entry
                    domain = _parse_domain_entry(eval_)
                    if domain:
                        domains.append(domain)
            if category and domains:
                result[category] = domains
    return result


def _parse_domain_entry(data: bytes) -> str:
    """Parse a single domain entry from geosite."""
    domain = ""
    typ = 0
    offset = 0
    while offset < len(data):
        fn, wt, val, offset = _read_field(data, offset)
        if fn is None:
            break
        if fn == 1 and wt == 0:
            typ = val
        elif fn == 2 and wt == 2:
            domain = val.decode("utf-8", errors="replace")
    # type 1 = plain, 2 = regex, 3 = domain, 4 = full
    if typ in (1, 3, 4) and domain:
        return domain.lower()
    return ""


def _parse_protobuf_geoip(path: str) -> dict:
    """Parse geoip.dat protobuf."""
    with open(path, "rb") as f:
        data = f.read()

    result = {}
    offset = 0
    while offset < len(data):
        fn, wt, val, offset = _read_field(data, offset)
        if fn is None:
            break
        if fn == 1 and wt == 2 and isinstance(val, bytes):
            # Entry message
            country = ""
            cidrs = []
            eo = 0
            while eo < len(val):
                efn, ewt, eval_, eo = _read_field(val, eo)
                if efn is None:
                    break
                if efn == 1 and ewt == 2:
                    country = eval_.decode("utf-8", errors="replace")
                elif efn == 2 and ewt == 2:
                    cidr = _parse_cidr_entry(eval_)
                    if cidr:
                        cidrs.append(cidr)
            if country and cidrs:
                result[country] = cidrs
    return result


def _parse_cidr_entry(data: bytes) -> str:
    """Parse a CIDR entry from geoip."""
    ip = ""
    prefix = 32
    offset = 0
    while offset < len(data):
        fn, wt, val, offset = _read_field(data, offset)
        if fn is None:
            break
        if fn == 1 and wt == 2 and isinstance(val, bytes):
            # IP address (4 bytes for IPv4, 16 for IPv6)
            if len(val) == 4:
                ip = "%d.%d.%d.%d" % (val[0], val[1], val[2], val[3])
            elif len(val) == 16:
                # IPv6 - simplified
                ip = ":".join("%02x%02x" % (val[i], val[i+1])
                              for i in range(0, 16, 2))
        elif fn == 2 and wt == 0:
            prefix = val
    if ip:
        return "%s/%d" % (ip, prefix)
    return ""
