# core/pcap_reader.py
"""
Разбор pcap-файла в поля: направление, флаги, TTL, длина, SNI.

Зачем свой разбор, а не текстовый вывод tcpdump. Строку
``21:03:11.442 IP 10.0.0.1.55632 > 1.2.3.4.443: Flags [S], seq …``
модель читает регулярками и ошибается: формат зависит от версии
tcpdump, от того, собрали ли его с ``-vv``, и от того, узнал ли он
протокол. Поля — не зависят. Плюс того, что нужно именно нам (TTL
после десинка, длина payload'а, SNI из ClientHello), в короткой строке
нет вовсе, а ``-vv -X`` превращает ответ в простыню шестнадцатеричных
байтов.

Поэтому tcpdump пишет ``-w <файл>``, а разбираем мы сами. Объём кода
того стоит: формат classic pcap — это 24-байтный заголовок файла и по
16 байт на пакет, а дальше обычный разбор IP/TCP/UDP.

Поддерживаются три канальных уровня, которые реально встречаются на
роутере: Ethernet (1), Linux SLL (113 — так выглядит захват с ``-i
any``) и RAW IP (101/12, так отдают TUN-интерфейсы). Незнакомый
linktype — не исключение, а честное «не разобрали»: пакет попадает в
ответ с полем ``error``.

Модуль **чистый**: ни одного побочного действия, ничего не запускает,
только читает байты. Поэтому и тестируется без роутера — байтами.
"""

import socket
import struct


# Сигнатуры classic pcap: порядок байтов и точность меток времени.
MAGIC_LE = 0xA1B2C3D4            # микросекунды, little-endian
MAGIC_BE = 0xD4C3B2A1
MAGIC_NS_LE = 0xA1B23C4D         # наносекунды
MAGIC_NS_BE = 0x4D3CB2A1

# Канальные уровни, которые мы понимаем.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101               # BSD/libpcap «просто IP»
LINKTYPE_RAW_ALT = 12            # то же, но другой номер в старых сборках
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

# Флаги TCP в порядке битов.
TCP_FLAGS = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
             ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80))

# Больше этого числа пакетов не разбираем ни при каких аргументах:
# защита от файла, который вырос не по плану.
MAX_PACKETS = 5000


class PcapError(ValueError):
    """Файл не похож на pcap (или обрезан на заголовке)."""


def read_file(path: str, limit: int = MAX_PACKETS,
              payloads: bool = False) -> dict:
    """Разобрать pcap-файл: ``{linktype, packets, total, truncated}``."""
    with open(path, "rb") as f:
        data = f.read()
    return read_bytes(data, limit=limit, payloads=payloads)


def read_bytes(data: bytes, limit: int = MAX_PACKETS,
               payloads: bool = False) -> dict:
    """Разобрать содержимое pcap-файла, уже прочитанное в память.

    Обрезанный файл — норма, а не ошибка: tcpdump прибивают по таймеру,
    и последний пакет может оказаться недописанным. Такой хвост просто
    не попадает в список.

    ``payloads=True`` кладёт в запись ещё и ``payload`` — байты L4 после
    заголовка TCP/UDP. Нужно повтору первых пакетов режима «Авто»
    geneva; наружу (MCP, UI) такие записи не отдаются.
    """
    if len(data) < 24:
        raise PcapError("файл короче заголовка pcap (%d байт)" % len(data))

    magic = struct.unpack("<I", data[:4])[0]
    if magic in (MAGIC_LE, MAGIC_NS_LE):
        order = "<"
    elif magic in (MAGIC_BE, MAGIC_NS_BE):
        order = ">"
    else:
        raise PcapError("не pcap: сигнатура %08x" % magic)
    nanos = magic in (MAGIC_NS_LE, MAGIC_NS_BE)

    linktype = struct.unpack(order + "I", data[20:24])[0]
    packets = []
    offset = 24
    total = 0
    limit = max(1, min(int(limit or MAX_PACKETS), MAX_PACKETS))
    while offset + 16 <= len(data):
        sec, frac, caplen, origlen = struct.unpack(
            order + "IIII", data[offset:offset + 16])
        offset += 16
        if caplen > len(data) - offset:
            break                       # недописанный хвост
        payload = data[offset:offset + caplen]
        offset += caplen
        total += 1
        if len(packets) >= limit:
            continue
        record = _packet(payload, linktype)
        record["ts"] = round(sec + frac / (1e9 if nanos else 1e6), 6)
        record["caplen"] = caplen
        record["wirelen"] = origlen
        # Снятый снапшот короче пакета — значит, часть payload'а не
        # записана, и «SNI не найден» может означать «не доехал».
        record["snapped"] = caplen < origlen
        if payloads and "error" not in record:
            record["payload"] = l4_payload(payload, linktype)
        packets.append(record)

    return {
        "linktype": linktype,
        "linktype_name": _LINKTYPES.get(linktype, "unknown"),
        "packets": packets,
        "total": total,
        "truncated": total > len(packets),
    }


def summarize(items) -> dict:
    """Сводка по разобранным пакетам: по чему видно, что происходило.

    Одна на два источника — дамп tcpdump (что ушло в сеть ПОСЛЕ
    движка, ``core/traffic_capture.py``) и lua-дамп самого движка (что
    он получил из очереди, ``core/lua_capture.py``). Разойдись они
    формой, сравнить «до» и «после» можно было бы только глазами.
    """
    out = {
        "packets": 0,
        "sni": [],
        "hosts": [],
        "ttl": {},
        "flags": {},
        "protocols": {},
    }
    for item in items or []:
        out["packets"] += 1
        name = item.get("sni") or item.get("host")
        if name:
            bucket = out["sni"] if item.get("sni") else out["hosts"]
            if name not in bucket:
                bucket.append(name)
        ttl = item.get("ttl")
        if ttl is not None:
            key = str(ttl)
            out["ttl"][key] = out["ttl"].get(key, 0) + 1
        for flag in item.get("flags") or []:
            out["flags"][flag] = out["flags"].get(flag, 0) + 1
        proto = item.get("l7") or item.get("proto")
        if proto:
            out["protocols"][proto] = out["protocols"].get(proto, 0) + 1
    out["sni"] = out["sni"][:20]
    out["hosts"] = out["hosts"][:20]
    return out


# ─────────────────────────── один пакет ─────────────────────────────

def _packet(raw: bytes, linktype: int) -> dict:
    """Пакет в полях; неразобранное честно помечается ``error``."""
    payload, error = _strip_link(raw, linktype)
    if error:
        return {"error": error}

    if not payload:
        return {"error": "пустой пакет"}
    version = payload[0] >> 4
    if version == 4:
        return _ipv4(payload)
    if version == 6:
        return _ipv6(payload)
    return {"error": "не IP-пакет (версия %d)" % version}


def l4_payload(raw: bytes, linktype: int) -> bytes:
    """Байты после заголовка TCP/UDP (без IPv6 extension-заголовков)."""
    data, error = _strip_link(raw, linktype)
    if error or not data:
        return b""
    version = data[0] >> 4
    if version == 4:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < 20 or ihl < 20:
            return b""
        total = struct.unpack(">H", data[2:4])[0]
        if struct.unpack(">H", data[6:8])[0] & 0x1FFF:
            return b""                  # не первый фрагмент
        proto, body = data[9], data[ihl:total if total >= ihl else None]
    elif version == 6:
        if len(data) < 40:
            return b""
        plen = struct.unpack(">H", data[4:6])[0]
        proto, body = data[6], data[40:40 + plen]
    else:
        return b""
    if proto == 6 and len(body) >= 20:
        off = (body[12] >> 4) * 4
        return bytes(body[off:]) if off >= 20 else b""
    if proto == 17 and len(body) >= 8:
        return bytes(body[8:])
    return b""


def _strip_link(raw: bytes, linktype: int):
    """Снять канальный заголовок; вернуть ``(ip-пакет, ошибка)``."""
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return b"", "кадр короче Ethernet-заголовка"
        ethertype = struct.unpack(">H", raw[12:14])[0]
        body = raw[14:]
        if ethertype == 0x8100:             # 802.1Q
            if len(body) < 4:
                return b"", "обрезанный VLAN-заголовок"
            ethertype = struct.unpack(">H", body[2:4])[0]
            body = body[4:]
        if ethertype not in (0x0800, 0x86DD):
            return b"", "не IP-кадр (ethertype 0x%04x)" % ethertype
        return body, ""
    if linktype == LINKTYPE_LINUX_SLL:
        if len(raw) < 16:
            return b"", "кадр короче SLL-заголовка"
        return raw[16:], ""
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(raw) < 20:
            return b"", "кадр короче SLL2-заголовка"
        return raw[20:], ""
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
        return raw, ""
    return b"", "неизвестный канальный уровень %d" % linktype


def _ipv4(data: bytes) -> dict:
    if len(data) < 20:
        return {"error": "обрезанный IPv4-заголовок"}
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return {"error": "битая длина IPv4-заголовка"}
    total_len = struct.unpack(">H", data[2:4])[0]
    flags_frag = struct.unpack(">H", data[6:8])[0]
    record = {
        "ip_version": 4,
        "src": socket.inet_ntop(socket.AF_INET, data[12:16]),
        "dst": socket.inet_ntop(socket.AF_INET, data[16:20]),
        # TTL — то, ради чего снифер и заводится: fake-пакеты десинка
        # уходят с укороченным TTL, и по нему видно, вышли ли они.
        "ttl": data[8],
        "proto": _PROTO.get(data[9], str(data[9])),
        "ip_len": total_len,
        "ip_id": struct.unpack(">H", data[4:6])[0],
        "df": bool(flags_frag & 0x4000),
        "mf": bool(flags_frag & 0x2000),
        "frag_offset": (flags_frag & 0x1FFF) * 8,
    }
    record.update(_l4(data[9], data[ihl:]))
    return record


def _ipv6(data: bytes) -> dict:
    if len(data) < 40:
        return {"error": "обрезанный IPv6-заголовок"}
    nxt = data[6]
    record = {
        "ip_version": 6,
        "src": socket.inet_ntop(socket.AF_INET6, data[8:24]),
        "dst": socket.inet_ntop(socket.AF_INET6, data[24:40]),
        # У IPv6 это Hop Limit, но роль та же — кладём в то же поле,
        # чтобы ответ читался одинаково для обеих версий.
        "ttl": data[7],
        "proto": _PROTO.get(nxt, str(nxt)),
        "ip_len": struct.unpack(">H", data[4:6])[0] + 40,
    }
    record.update(_l4(nxt, data[40:]))
    return record


def _l4(proto: int, data: bytes) -> dict:
    if proto == 6:
        return _tcp(data)
    if proto == 17:
        return _udp(data)
    return {}


def _tcp(data: bytes) -> dict:
    if len(data) < 20:
        return {"error": "обрезанный TCP-заголовок"}
    offset = (data[12] >> 4) * 4
    if offset < 20:
        return {"error": "битая длина TCP-заголовка"}
    bits = data[13]
    payload = data[offset:] if len(data) > offset else b""
    record = {
        "sport": struct.unpack(">H", data[0:2])[0],
        "dport": struct.unpack(">H", data[2:4])[0],
        "seq": struct.unpack(">I", data[4:8])[0],
        "ack": struct.unpack(">I", data[8:12])[0],
        "flags": [name for name, mask in TCP_FLAGS if bits & mask],
        "window": struct.unpack(">H", data[14:16])[0],
        "payload_len": len(payload),
    }
    record.update(_l7(payload))
    return record


def _udp(data: bytes) -> dict:
    if len(data) < 8:
        return {"error": "обрезанный UDP-заголовок"}
    payload = data[8:]
    record = {
        "sport": struct.unpack(">H", data[0:2])[0],
        "dport": struct.unpack(">H", data[2:4])[0],
        "payload_len": len(payload),
    }
    if payload[:1] and (payload[0] & 0x80) and record["dport"] == 443:
        # QUIC Initial: разбирать его пакет целиком (снятие защиты
        # заголовка, AEAD) здесь не будем — для обратной связи хватает
        # факта «ушёл QUIC», а не его содержимого.
        record["l7"] = "quic"
    record.update(_l7(payload, udp=True))
    return record


def _l7(payload: bytes, udp: bool = False) -> dict:
    """Что видно в payload'е: SNI из TLS ClientHello или Host из HTTP."""
    if not payload:
        return {}
    sni = tls_sni(payload)
    if sni:
        return {"l7": "tls", "sni": sni}
    if udp:
        return {}
    host, method = http_host(payload)
    if host:
        return {"l7": "http", "host": host, "http_method": method}
    if payload[:1] == b"\x16":
        # Рукопожатие есть, а имени в нём не нашлось: ровно так
        # выглядит разрезанный десинком ClientHello — первый сегмент
        # обрывается до extension'а с именем. Это не ошибка разбора.
        return {"l7": "tls", "sni": "",
                "note": "TLS-рукопожатие без читаемого SNI: вероятно, "
                        "ClientHello разрезан (split/disorder) или не "
                        "поместился в снапшот"}
    return {}


def tls_sni(payload: bytes) -> str:
    """Имя из TLS ClientHello или ``""``.

    Разбираем ровно столько, сколько нужно: запись handshake →
    ClientHello → extension 0 (server_name) → первое имя типа 0.
    Любая неожиданность — пустая строка, а не исключение: сюда приезжают
    куски разрезанных пакетов, и падать на них нельзя.
    """
    try:
        if len(payload) < 45 or payload[0] != 0x16:
            return ""
        # TLSPlaintext: type(1) version(2) length(2)
        pos = 5
        if payload[pos] != 0x01:                # HandshakeType: client_hello
            return ""
        pos += 4                                # msg_type(1) + length(3)
        pos += 2 + 32                           # version + random
        session_len = payload[pos]
        pos += 1 + session_len
        cipher_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
            pos += 4
            if ext_type != 0x0000:
                pos += ext_len
                continue
            # ServerNameList: length(2), затем [type(1) length(2) name]
            inner = payload[pos + 2:pos + ext_len]
            if len(inner) < 3 or inner[0] != 0x00:
                return ""
            name_len = struct.unpack(">H", inner[1:3])[0]
            return inner[3:3 + name_len].decode("ascii", "replace")
    except (IndexError, struct.error, ValueError):
        return ""
    return ""


def http_host(payload: bytes):
    """``(host, method)`` из заголовков HTTP-запроса или ``("", "")``."""
    if not payload[:1].isalpha():
        return "", ""
    try:
        head = payload[:1024].decode("latin-1")
    except (UnicodeDecodeError, ValueError):
        return "", ""
    lines = head.split("\r\n")
    first = lines[0].split(" ", 1)[0] if lines else ""
    if first not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
                     "PATCH", "CONNECT", "TRACE"):
        return "", ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "host":
            return value.strip()[:253], first
    return "", first


_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}

_LINKTYPES = {
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_RAW: "raw-ip",
    LINKTYPE_RAW_ALT: "raw-ip",
    LINKTYPE_LINUX_SLL: "linux-sll",
    LINKTYPE_LINUX_SLL2: "linux-sll2",
}
