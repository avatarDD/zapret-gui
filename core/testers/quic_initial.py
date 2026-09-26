# core/testers/quic_initial.py
"""
Настоящий QUIC Initial с ClientHello — проба, которую видит DPI.

Зачем, если есть ``quic_tester``. Тот шлёт пакет с «неизвестной»
версией и ждёт Version Negotiation: SNI в нём нет, и DPI, который режет
QUIC **по имени сайта** из ClientHello (так блокируют YouTube), такой
пакет пропускает. Для подбора стратегий это бесполезно — любая
стратегия «работает», потому что блокировать было нечего.

Здесь клиент собирает то же, что браузер: QUIC v1 Initial, внутри
CRYPTO-кадр с TLS 1.3 ClientHello (SNI, ALPN ``h3``, транспортные
параметры), шифрование Initial-ключами (RFC 9001 §5). Initial-ключи
выводятся из Destination Connection ID, поэтому DPI расшифровывает
такой пакет и видит SNI — ровно как у настоящего клиента.

Вердикт — по ответу сервера: пришёл QUIC-пакет, адресованный нашему
Source Connection ID (Initial с ServerHello, Retry или CONNECTION_CLOSE),
значит наш Initial дошёл и был разобран. Тишина — пакет дропнули.
Handshake мы не завершаем: для вопроса «пропускает ли DPI» это не нужно.

Никаких зависимостей: на роутере ``python3-light`` без ``cryptography``.
AES-128 (только шифрование — GCM и маска заголовка другого не требуют),
GCM и HKDF написаны здесь и сверены с тест-векторами FIPS-197, NIST GCM
и RFC 9001 Appendix A (``tests/test_quic_initial.py``). Один пакет —
около сотни блоков AES: скорость чистого Python тут не важна.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

# ───────────────────────────── AES-128 ──────────────────────────────

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _expand_key(key: bytes) -> list:
    """11 раундовых ключей AES-128 по 16 байт."""
    if len(key) != 16:
        raise ValueError("нужен ключ AES-128 (16 байт)")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(11)]


def _encrypt_block(round_keys: list, block: bytes) -> bytes:
    """Один блок AES-128 (FIPS-197), состояние — 16 байт по столбцам."""
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        # ShiftRows: байт (строка r, столбец c) лежит в s[4c + r].
        s = [s[(4 * ((i // 4 + i % 4) % 4)) + i % 4] for i in range(16)]
        if rnd != 10:
            mixed = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[j] ^ t ^ _xtime(a[j] ^ a[(j + 1) % 4])
                          for j in range(4)]
            s = mixed
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
    return bytes(s)


def aes128_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """AES-128 одного 16-байтового блока (для маски заголовка QUIC)."""
    return _encrypt_block(_expand_key(key), block)


# ────────────────────────────── AES-GCM ─────────────────────────────

_GCM_R = 0xE1000000000000000000000000000000


def _gf_mult(x: int, y: int) -> int:
    """Умножение в GF(2^128) по NIST SP 800-38D (битовый порядок GCM)."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
    return z


def _ghash(h: int, aad: bytes, data: bytes) -> int:
    y = 0
    for chunk in (aad, data):
        for i in range(0, len(chunk), 16):
            block = chunk[i:i + 16].ljust(16, b"\x00")
            y = _gf_mult(y ^ int.from_bytes(block, "big"), h)
    lengths = struct.pack(">QQ", len(aad) * 8, len(data) * 8)
    return _gf_mult(y ^ int.from_bytes(lengths, "big"), h)


def aes128_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                       aad: bytes) -> bytes:
    """AES-128-GCM с 96-битным nonce: шифротекст + 16-байтовый тег."""
    if len(nonce) != 12:
        raise ValueError("GCM здесь только с 12-байтовым nonce")
    rk = _expand_key(key)
    h = int.from_bytes(_encrypt_block(rk, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    out = bytearray()
    for n, i in enumerate(range(0, len(plaintext), 16)):
        counter = nonce + struct.pack(">I", 2 + n)
        stream = _encrypt_block(rk, counter)
        out += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], stream))
    tag = _ghash(h, aad, bytes(out)) ^ int.from_bytes(
        _encrypt_block(rk, j0), "big")
    return bytes(out) + tag.to_bytes(16, "big")


# ─────────────────────────── ключи Initial ──────────────────────────

# RFC 9001 §5.2: соль Initial для QUIC v1.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V1 = 0x00000001


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    """HKDF-Expand-Label из TLS 1.3 (RFC 8446 §7.1), пустой context."""
    full = b"tls13 " + label.encode("ascii")
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    out, block, n = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([n]),
                         hashlib.sha256).digest()
        out += block
        n += 1
    return out[:length]


def client_initial_keys(dcid: bytes) -> dict:
    """``{key, iv, hp}`` клиентского Initial для данного DCID."""
    initial = _hkdf_extract(INITIAL_SALT_V1, dcid)
    client = _hkdf_expand_label(initial, "client in", 32)
    return {"key": _hkdf_expand_label(client, "quic key", 16),
            "iv": _hkdf_expand_label(client, "quic iv", 12),
            "hp": _hkdf_expand_label(client, "quic hp", 16)}


# ──────────────────────────── ClientHello ───────────────────────────

def _varint(value: int) -> bytes:
    """Целое переменной длины QUIC (RFC 9000 §16)."""
    if value < 0x40:
        return struct.pack(">B", value)
    if value < 0x4000:
        return struct.pack(">H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack(">I", value | 0x80000000)
    return struct.pack(">Q", value | 0xC000000000000000)


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(body)) + body


def _transport_parameters(scid: bytes) -> bytes:
    """Минимальные параметры, с которыми сервер отвечает, а не рвёт.

    ``initial_source_connection_id`` обязателен (RFC 9000 §7.3): без
    него сервер закрывает соединение ошибкой транспортных параметров.
    """
    def param(pid: int, value: bytes) -> bytes:
        return _varint(pid) + _varint(len(value)) + value

    return b"".join((
        param(0x01, _varint(30000)),        # max_idle_timeout, мс
        param(0x04, _varint(1 << 20)),      # initial_max_data
        param(0x05, _varint(1 << 18)),      # ..._stream_data_bidi_local
        param(0x06, _varint(1 << 18)),      # ..._stream_data_bidi_remote
        param(0x07, _varint(1 << 18)),      # ..._stream_data_uni
        param(0x08, _varint(100)),          # initial_max_streams_bidi
        param(0x09, _varint(100)),          # initial_max_streams_uni
        param(0x0F, scid),                  # initial_source_connection_id
    ))


def build_client_hello(sni: str, scid: bytes, alpn: str = "h3") -> bytes:
    """TLS 1.3 ClientHello (сообщение Handshake) для QUIC."""
    host = sni.encode("idna")
    server_name = struct.pack(">HBH", len(host) + 3, 0, len(host)) + host
    alpn_raw = alpn.encode("ascii")
    alpn_list = struct.pack(">HB", len(alpn_raw) + 1, len(alpn_raw)) \
        + alpn_raw
    # Любые 32 байта — корректный открытый ключ X25519; завершать
    # обмен ключами мы не будем, серверу для ServerHello этого хватает.
    key_share = struct.pack(">HHH", 36, 0x001D, 32) + secrets.token_bytes(32)
    sig_algs = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601)
    groups = (0x001D, 0x0017, 0x0018)

    extensions = b"".join((
        _ext(0x0000, server_name),
        _ext(0x000A, struct.pack(">H", 2 * len(groups))
             + b"".join(struct.pack(">H", g) for g in groups)),
        _ext(0x000D, struct.pack(">H", 2 * len(sig_algs))
             + b"".join(struct.pack(">H", s) for s in sig_algs)),
        _ext(0x0010, alpn_list),
        _ext(0x002B, b"\x02\x03\x04"),        # supported_versions: TLS 1.3
        _ext(0x002D, b"\x01\x01"),            # psk_key_exchange_modes
        _ext(0x0033, key_share),
        _ext(0x0039, _transport_parameters(scid)),
    ))
    body = (b"\x03\x03" + secrets.token_bytes(32)
            + b"\x00"                                   # legacy_session_id
            + b"\x00\x06\x13\x01\x13\x02\x13\x03"       # cipher_suites
            + b"\x01\x00"                               # compression
            + struct.pack(">H", len(extensions)) + extensions)
    return b"\x01" + len(body).to_bytes(3, "big") + body


# ──────────────────────────── Initial-пакет ─────────────────────────

MIN_DATAGRAM = 1200     # RFC 9000 §14.1: Initial клиента — не короче
PN_LEN = 4


def protect_initial(dcid: bytes, scid: bytes, payload: bytes,
                    packet_number: int = 0, token: bytes = b"") -> bytes:
    """Зашифровать и защитить заголовок клиентского Initial (RFC 9001 §5).

    ``payload`` — уже собранные кадры (CRYPTO + PADDING); длина — такая,
    чтобы датаграмма вышла не короче ``MIN_DATAGRAM``.
    """
    keys = client_initial_keys(dcid)
    first = 0xC0 | (PN_LEN - 1)        # long header, Initial, 4 байта PN
    pn_bytes = packet_number.to_bytes(PN_LEN, "big")
    header = (bytes([first]) + struct.pack(">I", QUIC_V1)
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + _varint(len(token)) + token
              + _varint(PN_LEN + len(payload) + 16))
    pn_offset = len(header)
    header += pn_bytes

    nonce = bytes(a ^ b for a, b in zip(
        keys["iv"], packet_number.to_bytes(12, "big")))
    sealed = aes128_gcm_encrypt(keys["key"], nonce, payload, header)

    # Маска заголовка: образец — 16 байт шифротекста, начиная через
    # 4 байта после начала номера пакета (RFC 9001 §5.4.2).
    sample = sealed[4 - PN_LEN:4 - PN_LEN + 16]
    mask = aes128_ecb_encrypt(keys["hp"], sample)
    protected = bytearray(header)
    protected[0] ^= mask[0] & 0x0F
    for i in range(PN_LEN):
        protected[pn_offset + i] ^= mask[1 + i]
    return bytes(protected) + sealed


def build_initial(sni: str, alpn: str = "h3") -> tuple:
    """``(датаграмма, dcid, scid)`` — Initial с ClientHello для ``sni``."""
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)
    hello = build_client_hello(sni, scid, alpn=alpn)
    crypto = b"\x06" + _varint(0) + _varint(len(hello)) + hello

    # Заголовок: 1 + 4 + 1+8 + 1+8 + 1 (токен) + 2 (длина) + 4 (PN) = 30,
    # плюс 16 байт тега — остаток до 1200 добиваем кадрами PADDING.
    overhead = 30 + 16
    padding = max(0, MIN_DATAGRAM - overhead - len(crypto))
    return protect_initial(dcid, scid, crypto + b"\x00" * padding), dcid, scid


def parse_server_reply(data: bytes, scid: bytes) -> str:
    """Что прислал сервер в ответ на наш Initial.

    Возвращает ``initial``/``handshake``/``retry``/``version_negotiation``
    для long header, адресованного нашему SCID, или ``""`` — не наш
    пакет (случайная датаграмма на тот же порт).
    """
    if len(data) < 7 or not data[0] & 0x80:
        return ""
    version = struct.unpack(">I", data[1:5])[0]
    dcid_len = data[5]
    dcid = data[6:6 + dcid_len]
    if dcid != scid:
        return ""
    if version == 0:
        return "version_negotiation"
    kind = (data[0] >> 4) & 0x03
    return {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}[kind]
