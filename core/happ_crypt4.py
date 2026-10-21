# core/happ_crypt4.py
"""
Ссылки ``happ://crypt4/…``: зашифрованные подписки и ключи клиента Happ.

## Зачем

Российские панели (Remnawave и др.) раздают подписку для Happ не
открытым URL, а ``happ://crypt4/<base64>``: чтобы адрес подписки нельзя
было просто скопировать. Вставленная в GUI такая ссылка раньше давала
«не похоже на подписку». Формат (как его разбирает Tachyon,
``subscription/crypt4.uc``): base64 от ``IV (16 байт) + шифротекст``,
AES-CBC с PKCS#7; ключ — SHA-256 секрета (AES-256, либо первые 16 байт —
AES-128). Секреты перебираются по очереди: заданные пользователем, затем
стандартная соль ``HappDefaultSalt``. Удачная расшифровка — текст из
печатных символов с корректным дополнением.

## Без зависимостей

В стандартной библиотеке Python AES нет, а тянуть ``cryptography`` на
роутер (python3-light) нельзя. Поэтому здесь своя расшифровка AES по
FIPS-197 — только обратное направление и только CBC. Скорость не важна:
шифротекст — одна ссылка в сотни байт.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

DEFAULT_SALT = "HappDefaultSalt"
_PREFIX_RE = re.compile(r"^\s*(happ://)?crypt4/", re.I)


def is_crypt4(value: str) -> bool:
    return bool(_PREFIX_RE.match(value or ""))


# ─────────────────────────── AES (FIPS-197) ──────────────────────────

def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _make_sbox():
    # S-блок из определения: обратный элемент в GF(2^8) + аффинное
    # преобразование. Считается один раз при импорте.
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul(x, y) == 1:
                inv[x] = y
                break
    sbox = []
    for x in range(256):
        b = inv[x]
        s = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            s ^= b
        sbox.append(s ^ 0x63)
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _make_sbox()


def _expand_key(key: bytes) -> list:
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        words.append([words[i - nk][j] ^ t[j] for j in range(4)])
    # Ключи раундов как 16-байтовые списки (столбцы подряд).
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _inv_mix(col):
    a0, a1, a2, a3 = col
    return [_gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9),
            _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13),
            _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11),
            _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)]


def _decrypt_block(block: bytes, rounds: list) -> bytes:
    nr = len(rounds) - 1
    s = [b ^ k for b, k in zip(block, rounds[nr])]
    for r in range(nr - 1, -1, -1):
        # InvShiftRows: байт строки i столбца c — из столбца (c - i).
        s = [s[((c - i) % 4) * 4 + i] for c in range(4) for i in range(4)]
        s = [_INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rounds[r])]
        if r:
            s = sum((_inv_mix(s[4 * c:4 * c + 4]) for c in range(4)), [])
    return bytes(s)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровать AES-CBC (ключ 16/24/32 байта), без снятия дополнения."""
    if len(key) not in (16, 24, 32) or len(iv) != 16 or len(data) % 16:
        raise ValueError("неверная длина ключа, IV или шифротекста")
    rounds = _expand_key(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = _decrypt_block(block, rounds)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)


def _unpad(data: bytes):
    if not data:
        return None
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


def _plausible(text: str) -> bool:
    return bool(text) and all(c.isprintable() or c in "\r\n\t"
                              for c in text)


# ─────────────────────────── расшифровка ─────────────────────────────

def decrypt(value: str, secrets=()) -> str:
    """``happ://crypt4/…`` → открытый текст; ``""`` — ни один ключ не подошёл.

    ``secrets`` — свои ключи (например, HWID, к которому панель привязала
    ссылку); стандартная соль пробуется последней.
    """
    payload = _PREFIX_RE.sub("", value or "").strip()
    payload = re.sub(r"\s+", "", payload)
    payload += "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(payload.replace("-", "+").replace("_", "/"))
    except (binascii.Error, ValueError):
        return ""
    if len(raw) < 32 or (len(raw) - 16) % 16:
        return ""
    iv, cipher = raw[:16], raw[16:]
    keys, seen = [], set()
    for k in list(secrets or ()) + [DEFAULT_SALT]:
        k = str(k or "").strip()
        if k and k not in seen:
            seen.add(k)
            keys.append(k)
    for k in keys:
        digest = hashlib.sha256(k.encode("utf-8")).digest()
        for key in (digest, digest[:16]):
            plain = _unpad(aes_cbc_decrypt(cipher, key, iv))
            if plain is None:
                continue
            try:
                text = plain.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _plausible(text):
                return text
    return ""
