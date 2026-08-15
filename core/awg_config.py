# core/awg_config.py
"""
Парсер/генератор конфигов AmneziaWG (.conf) и генерация ключей.

Формат совместим с wg-quick + AmneziaWG расширениями:
  [Interface] PrivateKey, Address, ListenPort, DNS, MTU, Table,
              PreUp, PostUp, PreDown, PostDown,
              Jc, Jmin, Jmax, S1..S4, H1..H4, I1..I5, J1..J3, Itime
  [Peer]      PublicKey, PresharedKey, AllowedIPs,
              Endpoint, PersistentKeepalive

Использование:
    from core.awg_config import parse_conf, render_conf, validate, generate_keypair
    cfg = parse_conf(open("/opt/etc/amneziawg/awg0.conf").read())
    text = render_conf(cfg)
    errors = validate(cfg)
    priv, pub = generate_keypair()
"""

import base64
import ipaddress
import os
import re
import subprocess
import tempfile


# Поколение параметров AWG 3+ (README amneziawg-go v3.0.3, раздел
# «[AWG 3+]»). Секция устройства:
#   HeaderProtectionKey    — ключ шифрования полей заголовка (server-side,
#                            нонсом служит crypto-паддинг S1..S4, поэтому
#                            требует S1..S4 >= 12); генерится `awg genkey`;
#   ContentPaddingAddition — доп. паддинг содержимого (uint32/range);
#   Rekey*/RejectAfterTime/KeepaliveTimeout/MaxHandshakeAttempts —
#                            тайминги WireGuard (uint32/range, секунды).
# Тип `range` = "a-b" | "a" | "(off)", поэтому числами их не валидируем.
AWG3_INTERFACE_FIELDS = (
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
)

# Минимальное значение S1..S4, при котором работает защита заголовка
# (README: «Header protection requires S1-S4 value to be 12 at least»).
AWG3_HEADER_PROTECTION_MIN_S = 12

# Поля [Interface], которые применяются через `awg setconf`
# (всё остальное — wg-quick-расширения и обрабатывается нами).
WG_INTERFACE_FIELDS = (
    "PrivateKey",
    "ListenPort",
    "FwMark",
    # AmneziaWG-обфускация v1 (классический набор 1.0)
    "Jc", "Jmin", "Jmax",
    "S1", "S2",
    "H1", "H2", "H3", "H4",
    # NB: голого поля `I` в AmneziaWG НЕТ — signature-пакеты это I1..I5
    # (см. amneziawg-tools src/config.c: key_match только "I1".."I5").
    # Не добавлять "I" обратно: при наличии в конфиге оно ушло бы в
    # `awg setconf` как неизвестный ключ и тулза отбросила бы весь конфиг.
    # AmneziaWG-обфускация v2 (новые поля из свежих релизов
    # amneziawg-go/amneziawg-tools). Если их не передать в setconf,
    # демон работает в режиме v1, handshake проходит, а data-пакеты
    # сервером дропаются — ровно картина «92 B in / 20 KB out».
    "S3", "S4",
    "I1", "I2", "I3", "I4", "I5",
    "J1", "J2", "J3",
    "Itime",
    # Поколение AWG 3+ (ветка amneziawg-go v3.x). Парсером amneziawg-tools
    # ПОДДЕРЖИВАЮТСЯ (key_match в src/config.c, v3.0.20260730), поэтому в
    # setconf уходят наравне с остальной обфускацией. Без них демон
    # поднимается без защиты заголовка, а пир, который её ждёт, дропает
    # data-пакеты — та же картина «92 B in / 20 KB out».
    *AWG3_INTERFACE_FIELDS,
)

# Поля [Interface] для wg-quick-логики (не для setconf).
WGQUICK_INTERFACE_FIELDS = (
    "Address", "DNS", "MTU", "Table",
    "PreUp", "PostUp", "PreDown", "PostDown",
    "SaveConfig",
)

# Поля [Peer], принимаемые `awg setconf` (key_match секции [Peer] в
# amneziawg-tools src/config.c). `AdvancedSecurity` — per-peer флаг
# AmneziaWG: тулза его понимает, значит отбрасывать чужой профиль из-за
# него нельзя.
WG_PEER_FIELDS = (
    "PublicKey",
    "PresharedKey",
    "AllowedIPs",
    "Endpoint",
    "PersistentKeepalive",
    "AdvancedSecurity",
)

# Все известные поля интерфейса.
KNOWN_INTERFACE_FIELDS = set(WG_INTERFACE_FIELDS) | set(WGQUICK_INTERFACE_FIELDS)

# AmneziaWG-обфускация — числовые поля, валидируем как int.
AWG_OBFUSCATION_FIELDS = ("Jc", "Jmin", "Jmax", "S1", "S2",
                          "H1", "H2", "H3", "H4",
                          # AmneziaWG-v2 числовые
                          "S3", "S4", "Itime")

# AmneziaWG-v2 hex-blob поля (I1..I5, J1..J3) — НЕ числа, отдельно.
# Используются для упорядочивания и для render_setconf-логики.
AWG_V2_BLOB_FIELDS = ("I1", "I2", "I3", "I4", "I5",
                      "J1", "J2", "J3")

# Поля, которые amneziawg-tools НЕ понимает, сколько бы их ни описывала
# документация протокола. Проверено по `key_match` в src/config.c релизов
# v1.0.20260618-2 и v3.0.20260730: там есть Jc/Jmin/Jmax, S1..S4, H1..H4,
# I1..I5 — и НЕТ J1..J3 и Itime.
#
# Почему это нельзя просто отдать в setconf «на всякий случай»: на
# неизвестном ключе config.c делает `goto error` — печатает
# `Line unrecognized: '<строка>'` и отбрасывает КОНФИГ ЦЕЛИКОМ. То есть
# один лишний ключ из чужого .conf = интерфейс вообще не поднимается,
# причём в логе будет невнятное «Unable to modify interface».
#
# Разбирать и хранить их мы продолжаем: пользователь может импортировать
# .conf из клиента Amnezia, и терять поля молча при round-trip нельзя.
# Не отдаём только в `awg setconf` — см. `_setconf_skip_fields`.
AWG_FIELDS_UNSUPPORTED_BY_TOOLS = ("J1", "J2", "J3", "Itime")


def _is_base64_key(value: str) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) != 44 or not v.endswith("="):
        return False
    try:
        return len(base64.b64decode(v, validate=True)) == 32
    except (ValueError, TypeError):
        return False


# ───────────────────────── parser ───────────────────────────────────

_SECTION_RE = re.compile(r"^\[\s*([A-Za-z]+)\s*\]\s*$")


def parse_conf(text: str) -> dict:
    """
    Распарсить .conf-текст в структуру:
        {
          "interface": {<field>: <value>, ...},
          "peers": [{<field>: <value>, ...}, ...]
        }
    Поля с множественными значениями (Address, DNS, AllowedIPs, *Up/*Down)
    собираются в список при повторном задании.
    """
    # BOM в начале файла (issue #319): десктопный AmneziaVPN сохраняет
    # .conf в UTF-8 с сигнатурой, и первая строка приезжает как
    # "﻿[Interface]". Секция при этом не распознаётся, а
    # пользователь получает «Отсутствует секция [Interface]» на
    # совершенно корректном конфиге. Браузер (FileReader.readAsText)
    # BOM тоже не убирает, поэтому чистим здесь — через parse_conf
    # проходят и загрузка файлом, и вставка текстом, и импорт подписок.
    text = (text or "").lstrip("﻿")
    # Тот же BOM, прочитанный как latin-1/cp1251 (так его отдают часть
    # мессенджеров и файловых менеджеров при пересылке конфига).
    if text.startswith("ï»¿"):
        text = text[3:]

    result = {"interface": {}, "peers": []}
    current = None  # None | "interface" | "peer"
    current_peer = None

    # Состояние «накапливаем многострочный binary-blob» (AmneziaWG-v2)
    pending_key = None     # имя поля, которое сейчас добиваем
    pending_chunks = []    # hex-куски без 0x/whitespace
    pending_target = None  # куда положим результат (iface/peer-dict)

    def flush_pending():
        nonlocal pending_key, pending_chunks, pending_target
        if pending_key is not None and pending_target is not None:
            joined = "".join(pending_chunks).strip()
            pending_target[pending_key] = joined or "<b"
        pending_key = None
        pending_chunks = []
        pending_target = None

    for raw in (text or "").splitlines():
        line = raw.strip()

        # Пустая строка / комментарий → закрываем pending binary-blob
        # (внутри `<b ...` блока пустая строка завершает значение).
        if not line or line.startswith("#") or line.startswith(";"):
            flush_pending()
            continue

        m = _SECTION_RE.match(line)
        if m:
            flush_pending()
            section = m.group(1).lower()
            if section == "interface":
                current = "interface"
            elif section == "peer":
                current_peer = {}
                result["peers"].append(current_peer)
                current = "peer"
            else:
                current = None
            continue

        if "=" not in line:
            # Может быть продолжением binary-blob (hex-строки без `Key=`).
            if pending_key is not None:
                # Закрывающий `>` завершает значение
                if line.endswith(">"):
                    inner = line[:-1].strip()
                    if not inner or _is_hex_continuation(inner):
                        pending_chunks.append(_clean_hex(inner))
                        flush_pending()
                        continue
                if _is_hex_continuation(line):
                    pending_chunks.append(_clean_hex(line))
                    continue
            # Иначе — мусор. Закрываем pending, чтобы не залипало.
            flush_pending()
            continue

        # Новый `Key = …` → завершаем предыдущий binary-blob, если был.
        flush_pending()

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        target = None
        if current == "interface":
            target = result["interface"]
        elif current == "peer" and current_peer is not None:
            target = current_peer
        if target is None:
            continue

        # Маркер binary-blob (AmneziaWG-v2: I1/I2/…). Встречается в
        # двух формах:
        #   Single-line:  `I1 = <b 0xHEX...>`
        #   Multi-line:   `I1 = <b\n0xHEX\nHEX\n...\n` (закрывается
        #                 пустой строкой или новым `Key=`).
        # Без этой обработки парсер брал только `<b`, и I1 терялся
        # при render_setconf — handshake проходил, но data-пакеты
        # сервер дропал (это и было «92 B in / 20 KB out»).
        if value.startswith("<b"):
            tail = value[2:].strip()
            # Single-line форма закрывается `>` на этой же строке —
            # тогда blob готов сразу и pending не нужен.
            if tail.endswith(">"):
                clean = _clean_hex(tail[:-1])
                target[key] = clean
                continue
            pending_key = key
            pending_target = target
            pending_chunks = []
            if tail:
                pending_chunks.append(_clean_hex(tail))
            continue

        _set_field(target, key, value)

    # На EOF закрываем pending.
    flush_pending()

    # Нормализация: добавляем /32 и /128 голым адресам, чтобы wg/awg
    # их принял (и валидация ниже не ругалась).
    iface = result["interface"]
    if "Address" in iface:
        iface["Address"] = _normalize_cidr_field(iface["Address"])
    for peer in result["peers"]:
        if "AllowedIPs" in peer:
            peer["AllowedIPs"] = _normalize_cidr_field(peer["AllowedIPs"])

    return result


_LIST_KEYS = {"Address", "DNS", "AllowedIPs",
              "PreUp", "PostUp", "PreDown", "PostDown"}


_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")


def _is_hex_continuation(line: str) -> bool:
    """Похожа ли строка на продолжение AmneziaWG-v2 binary-blob'a?"""
    s = (line or "").strip().replace(" ", "")
    if not s:
        return False
    return bool(_HEX_RE.match(s))


def _clean_hex(s: str) -> str:
    """Убрать пробелы и префикс 0x, оставив только hex-символы."""
    s = (s or "").strip().replace(" ", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return s


def _add_cidr_suffix(addr: str) -> str:
    """
    Если строка — голый IPv4/IPv6 без префикса, добавить /32 или /128.
    Иначе вернуть как есть. WireGuard/AmneziaWG требуют CIDR в Address и
    AllowedIPs, но многие генераторы конфигов (в т. ч. Cloudflare WARP)
    пишут адреса без префикса — нормализуем тихо при импорте.
    """
    if not isinstance(addr, str):
        return addr
    s = addr.strip()
    if not s or "/" in s:
        return s
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return s
    return "%s/%d" % (s, 32 if ip.version == 4 else 128)


def _normalize_cidr_field(value):
    """Применить _add_cidr_suffix к строке или элементам списка."""
    if isinstance(value, list):
        return [_add_cidr_suffix(v) for v in value]
    return _add_cidr_suffix(value)


def _set_field(target: dict, key: str, value: str):
    """
    Записать значение. Для известных multi-value полей значения
    из нескольких строк объединяются в список. Запятые внутри
    одной строки также раскладываются в список.
    """
    if key in _LIST_KEYS:
        # PreUp/PostUp etc — каждая строка — отдельная команда (не делим по запятой)
        if key in ("PreUp", "PostUp", "PreDown", "PostDown"):
            parts = [value]
        else:
            parts = [p.strip() for p in value.split(",") if p.strip()]
        existing = target.get(key)
        if existing is None:
            target[key] = parts if len(parts) > 1 else (parts[0] if parts else "")
        else:
            if not isinstance(existing, list):
                existing = [existing]
            existing.extend(parts)
            target[key] = existing
    else:
        target[key] = value


# ───────────────────────── renderer ─────────────────────────────────

def render_conf(cfg: dict) -> str:
    """
    Сериализовать структуру обратно в .conf-текст.
    Сохраняет известный порядок полей, неизвестные поля остаются в конце.
    """
    cfg = cfg or {}
    iface = cfg.get("interface") or {}
    peers = cfg.get("peers") or []

    lines = ["[Interface]"]
    # Порядок: AWG ключевые → quick → обфускация → остальное
    iface_order = (
        ["PrivateKey", "ListenPort", "FwMark"] +
        list(WGQUICK_INTERFACE_FIELDS) +
        list(AWG_OBFUSCATION_FIELDS) +
        list(AWG_V2_BLOB_FIELDS)
    )
    seen = set()
    for key in iface_order:
        if key in iface:
            _emit(lines, key, iface[key])
            seen.add(key)
    for key, value in iface.items():
        if key not in seen:
            _emit(lines, key, value)

    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        peer_order = list(WG_PEER_FIELDS)
        seen_p = set()
        for key in peer_order:
            if key in peer:
                _emit(lines, key, peer[key])
                seen_p.add(key)
        for key, value in peer.items():
            if key not in seen_p:
                _emit(lines, key, value)

    return "\n".join(lines).rstrip() + "\n"


# Стандартный keepalive (как у официальных WARP/WireGuard-клиентов).
DEFAULT_PERSISTENT_KEEPALIVE = 25


def ensure_persistent_keepalive(cfg: dict,
                                default: int = DEFAULT_PERSISTENT_KEEPALIVE) -> bool:
    """
    Проставить `PersistentKeepalive` каждому [Peer], у которого он не задан.

    Зачем: без keepalive NAT-binding на роутере/у провайдера протухает за
    ~30–120с простоя — туннель «молча отваливается» (особенно за CGNAT и
    на мобильном интернете), handshake не обновляется до первого исходящего
    пакета. 25с — стандартное значение. Проставляется при создании/импорте
    конфигов (`AwgManager.save_config`), чтобы свежие конфиги были живучими
    из коробки. Явно заданное значение (в т.ч. `0` = выкл.) НЕ трогаем —
    уважаем выбор пользователя.

    Мутирует cfg на месте. Возвращает True, если что-то добавили.
    """
    cfg = cfg or {}
    changed = False
    for peer in (cfg.get("peers") or []):
        if not isinstance(peer, dict):
            continue
        if peer.get("PersistentKeepalive") in (None, ""):
            peer["PersistentKeepalive"] = int(default)
            changed = True
    return changed


_AWG_V2_BLOB_SET = frozenset(AWG_V2_BLOB_FIELDS)


def _emit(lines: list, key: str, value):
    """Вывести поле, разворачивая списки в несколько строк или одну с запятыми."""
    if value is None or value == "":
        return
    if isinstance(value, list):
        if key in ("PreUp", "PostUp", "PreDown", "PostDown"):
            for v in value:
                if v != "":
                    lines.append("%s = %s" % (key, v))
        else:
            joined = ", ".join(str(v) for v in value if v != "")
            if joined:
                lines.append("%s = %s" % (key, joined))
    else:
        if key in _AWG_V2_BLOB_SET and isinstance(value, str):
            v = value.strip()
            # `amneziawg-tools` ждёт binary-blob в нативном синтаксисе
            # `<b 0xHEX>`. Раньше я отдавал просто `0xHEX` — `awg show`
            # после этого показывал «похожие, но не те» байты: тулза
            # парсила их по другому правилу и в I1 уходил мусор. Теперь
            # эмитим в оригинальной обёртке.
            if v and v != "<b":
                inner = v
                if inner.lower().startswith("0x"):
                    inner = inner[2:]
                value = "<b 0x%s>" % inner
        lines.append("%s = %s" % (key, value))


# ───────────────────────── filtered conf for `awg setconf` ──────────

def _setconf_skip_fields(iface: dict) -> set:
    """
    Поля обфускации, которые НЕ нужно отдавать в `awg setconf`, потому
    что их нулевое значение демон трактует иначе, чем «как обычный
    WireGuard» (см. docs.amnezia.org: «все параметры = 0 → ванильный WG»):

      * Jc/Jmin/Jmax — amneziawg-go требует ПОЛОЖИТЕЛЬНЫХ значений
        ("jc must be a positive value"); явный 0 ⇒ setconf падает с
        "Unable to modify interface: Invalid argument". 0 = «junk
        выключен», поэтому группу пропускаем целиком, если хотя бы одно
        из значений не положительное.
      * H1..H4 = 0 — демон по умолчанию (когда заголовок не задан)
        использует стандартные типы сообщений 1/2/3/4; явный 0 сломал
        бы тип пакета. Поэтому H*=0 трактуем как «не задано» и опускаем.

    S1..S4 = 0 — корректны (паддинг нулевой длины), демон их принимает,
    поэтому НЕ трогаем.
    """
    skip = set()
    junk_ok = True
    for k in ("Jc", "Jmin", "Jmax"):
        raw = iface.get(k)
        if raw in ("", None):
            continue
        try:
            if int(str(raw).strip()) <= 0:
                junk_ok = False
        except (TypeError, ValueError):
            junk_ok = False
    if not junk_ok:
        skip.update(("Jc", "Jmin", "Jmax"))
    for k in ("H1", "H2", "H3", "H4"):
        if str(iface.get(k, "")).strip() == "0":
            skip.add(k)
    # Ключи, которых нет в парсере amneziawg-tools: один такой в setconf
    # роняет весь конфиг (`Line unrecognized`), см. комментарий у
    # AWG_FIELDS_UNSUPPORTED_BY_TOOLS.
    skip.update(AWG_FIELDS_UNSUPPORTED_BY_TOOLS)
    return skip


def render_setconf(cfg: dict) -> str:
    """
    Отрендерить только те поля, которые принимает `awg setconf`:
    PrivateKey, ListenPort, FwMark, AmneziaWG-обфускация, и поля [Peer].
    Используется при поднятии интерфейса (см. awg_manager).

    Поля, которых нет в парсере amneziawg-tools (`J1..J3`, `Itime`),
    сознательно НЕ выводятся: они остаются в разобранном конфиге и в
    `render_conf`, но в setconf уронили бы весь конфиг целиком. См.
    `AWG_FIELDS_UNSUPPORTED_BY_TOOLS`.
    """
    cfg = cfg or {}
    iface = cfg.get("interface") or {}
    peers = cfg.get("peers") or []

    skip = _setconf_skip_fields(iface)

    lines = ["[Interface]"]
    for key in WG_INTERFACE_FIELDS:
        if key in skip:
            continue
        if key in iface and iface[key] not in ("", None):
            _emit(lines, key, iface[key])

    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        for key in WG_PEER_FIELDS:
            if key in peer and peer[key] not in ("", None):
                _emit(lines, key, peer[key])

    return "\n".join(lines) + "\n"


# ───────────────────────── validation ───────────────────────────────

# H1..H4 в AmneziaWG: классически — одиночный uint, а в AmneziaWG 2.0 —
# ДИАПАЗОН `N-M` (значения выбираются случайно в окне). amneziawg-tools
# (src/config.c) хранит их как opaque-строки через parse_awg_string, поэтому
# на нашей стороне валидируем только формат: int ИЛИ `N-M` (N<=M).
_AWG_HEADER_FIELDS = frozenset(("H1", "H2", "H3", "H4"))
_AWG_HEADER_RE = re.compile(r"^\d+(?:-\d+)?$")


def _is_valid_awg_header(value) -> bool:
    """True, если значение H1..H4 — целое или диапазон `N-M` (N<=M)."""
    s = str(value).strip()
    if not _AWG_HEADER_RE.match(s):
        return False
    if "-" in s:
        lo, hi = s.split("-", 1)
        return int(lo) <= int(hi)
    return True


# Тип `range,x` из README amneziawg-go: "a-b", "a" либо "(off)". Так
# задаются тайминги AWG 3+, ContentPaddingAddition и PersistentKeepalive.
_AWG_RANGE_OFF = "(off)"

# AWG3-поля с типом `uint32,range` (HeaderProtectionKey — ключ, не число).
AWG3_RANGE_FIELDS = tuple(f for f in AWG3_INTERFACE_FIELDS
                          if f != "HeaderProtectionKey")


def _is_valid_awg_range(value) -> bool:
    """True, если значение — uint, диапазон `N-M` (N<=M) либо `(off)`."""
    s = str(value).strip()
    if s == _AWG_RANGE_OFF:
        return True
    return _is_valid_awg_header(s)


def _min_crypto_padding(iface: dict):
    """Минимум из заданных S1..S4 (None — ни одного не задано)."""
    vals = []
    for k in ("S1", "S2", "S3", "S4"):
        v = iface.get(k)
        if v in ("", None):
            continue
        try:
            vals.append(int(v))
        except (TypeError, ValueError):
            continue
    return min(vals) if vals else None


def validate(cfg: dict) -> list:
    """
    Проверить структуру конфига. Возвращает список строк-ошибок.
    Пустой список = всё ок.
    """
    errors = []
    cfg = cfg or {}
    iface = cfg.get("interface") or {}
    peers = cfg.get("peers") or []

    # [Interface] обязателен
    if not iface:
        errors.append("Отсутствует секция [Interface]")
        return errors

    pk = iface.get("PrivateKey", "")
    if not pk:
        errors.append("[Interface] PrivateKey обязателен")
    elif not _is_base64_key(pk):
        errors.append("[Interface] PrivateKey должен быть base64 ключом длиной 32 байта")

    if "ListenPort" in iface:
        try:
            port = int(iface["ListenPort"])
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            errors.append("[Interface] ListenPort должен быть числом 1..65535")

    if "MTU" in iface:
        try:
            mtu = int(iface["MTU"])
            if not 576 <= mtu <= 9000:
                errors.append("[Interface] MTU вне разумного диапазона (576..9000)")
        except (TypeError, ValueError):
            errors.append("[Interface] MTU должен быть числом")

    addrs = iface.get("Address")
    if addrs:
        for a in (addrs if isinstance(addrs, list) else [addrs]):
            # Принимаем как «1.2.3.4», так и «1.2.3.4/24» — parse_conf уже
            # дописывает /32 и /128 для голых адресов; проверяем только,
            # что значение действительно является IP/CIDR.
            try:
                ipaddress.ip_interface(a)
            except (ValueError, TypeError):
                errors.append(f"[Interface] Address — неверный адрес: {a}")

    # AWG-обфускация: числовые поля — строгий int; заголовки H1..H4 —
    # одиночный uint ИЛИ диапазон `N-M` (range-синтаксис AmneziaWG 2.0).
    for k in AWG_OBFUSCATION_FIELDS:
        if k not in iface or iface[k] in ("", None):
            continue
        if k in _AWG_HEADER_FIELDS:
            if not _is_valid_awg_header(iface[k]):
                errors.append(
                    f"[Interface] {k} должен быть числом или диапазоном N-M")
        else:
            try:
                int(iface[k])
            except (TypeError, ValueError):
                errors.append(f"[Interface] {k} должен быть числом")

    # AWG 3+: тайминги и паддинг — тип `uint32,range` («a-b» / «a» /
    # «(off)»), поэтому строгим int их проверять нельзя.
    for k in AWG3_RANGE_FIELDS:
        if k not in iface or iface[k] in ("", None):
            continue
        if not _is_valid_awg_range(iface[k]):
            errors.append(
                f"[Interface] {k} должен быть числом, диапазоном N-M "
                f"или (off)")

    hpk = iface.get("HeaderProtectionKey")
    if hpk not in ("", None):
        if not _is_base64_key(hpk):
            errors.append("[Interface] HeaderProtectionKey должен быть "
                          "base64 ключом длиной 32 байта (awg genkey)")
        else:
            # Паддинг S1..S4 служит нонсом шифра заголовка: ниже 12 связка
            # нерабочая (README amneziawg-go, «Header protection»).
            min_s = _min_crypto_padding(iface)
            if min_s is None or min_s < AWG3_HEADER_PROTECTION_MIN_S:
                errors.append(
                    "[Interface] HeaderProtectionKey требует S1–S4 не меньше "
                    f"{AWG3_HEADER_PROTECTION_MIN_S} (сейчас "
                    f"{'не заданы' if min_s is None else min_s})")

    # Peers
    for i, peer in enumerate(peers):
        prefix = f"[Peer #{i+1}]"
        pubk = peer.get("PublicKey", "")
        if not pubk:
            errors.append(f"{prefix} PublicKey обязателен")
        elif not _is_base64_key(pubk):
            errors.append(f"{prefix} PublicKey должен быть base64 ключом")

        psk = peer.get("PresharedKey", "")
        if psk and not _is_base64_key(psk):
            errors.append(f"{prefix} PresharedKey должен быть base64 ключом")

        ep = peer.get("Endpoint", "")
        if ep and ":" not in ep:
            errors.append(f"{prefix} Endpoint должен иметь формат host:port")

        # PersistentKeepalive в AWG 3+ — тип `range`: помимо числа валидны
        # «22-30» и «(off)» (README amneziawg-go, «Timings»).
        ka_raw = peer.get("PersistentKeepalive")
        if ka_raw not in ("", None):
            ka_s = str(ka_raw).strip()
            if not _is_valid_awg_range(ka_s):
                errors.append(f"{prefix} PersistentKeepalive должен быть "
                              f"числом 0..65535, диапазоном N-M или (off)")
            elif ka_s != _AWG_RANGE_OFF:
                bounds = [int(x) for x in ka_s.split("-")]
                if any(not 0 <= b <= 65535 for b in bounds):
                    errors.append(f"{prefix} PersistentKeepalive должен быть "
                                  f"числом 0..65535, диапазоном N-M или (off)")

        ips = peer.get("AllowedIPs")
        if ips:
            for a in (ips if isinstance(ips, list) else [ips]):
                try:
                    ipaddress.ip_network(a, strict=False)
                except (ValueError, TypeError):
                    errors.append(f"{prefix} AllowedIPs — неверный адрес: {a}")

    return errors


# ───────────────────────── keypair ──────────────────────────────────

def generate_keypair(awg_binary: str = None) -> tuple:
    """
    Сгенерировать пару ключей X25519. Возвращает (private_b64, public_b64).

    Стратегии (по приоритету):
      1) `<awg_binary> genkey | <awg_binary> pubkey` — если задан/найден awg
      2) то же через `wg`
      3) через openssl genpkey -algorithm X25519 + ручной парсинг

    Не вводит новых зависимостей.
    """
    candidates = []
    if awg_binary:
        candidates.append(awg_binary)
    candidates.extend(["awg", "wg"])

    for binary in candidates:
        priv = _run_simple([binary, "genkey"])
        if priv:
            pub = _run_pipe([binary, "pubkey"], priv + "\n")
            if pub:
                return priv, pub

    # openssl fallback
    priv, pub = _openssl_x25519_keypair()
    if priv and pub:
        return priv, pub

    raise RuntimeError(
        "Не найден ни awg/wg, ни openssl с поддержкой X25519. "
        "Сгенерируйте ключи вручную и вставьте в конфиг."
    )


def _run_simple(args, timeout=10) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return ""


def _run_pipe(args, stdin_text: str, timeout=10) -> str:
    try:
        r = subprocess.run(args, input=stdin_text, capture_output=True,
                           text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return ""


def _openssl_x25519_keypair() -> tuple:
    """
    Сгенерировать X25519 пару через openssl и распарсить ASN.1 DER,
    извлекая «сырые» 32 байта приватного и публичного ключа.
    """
    if not _run_simple(["openssl", "version"]):
        return "", ""

    with tempfile.TemporaryDirectory(prefix="awg-key-") as tmp:
        priv_pem = os.path.join(tmp, "priv.pem")
        pub_pem  = os.path.join(tmp, "pub.pem")
        if not _run_simple([
            "openssl", "genpkey", "-algorithm", "X25519",
            "-out", priv_pem,
        ]) and not os.path.isfile(priv_pem):
            return "", ""
        # извлекаем публичный
        if not _run_simple([
            "openssl", "pkey", "-in", priv_pem,
            "-pubout", "-out", pub_pem,
        ]) and not os.path.isfile(pub_pem):
            return "", ""

        priv_der = _pem_to_der(_read_text(priv_pem), "PRIVATE KEY")
        pub_der  = _pem_to_der(_read_text(pub_pem),  "PUBLIC KEY")
        if not priv_der or not pub_der:
            return "", ""

        # Приватный X25519 PKCS#8: последние 32 байта = OCTET STRING с ключом.
        # ASN.1: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING wrap }
        # внутри wrap — OCTET STRING длиной 32 байта.
        priv_raw = priv_der[-32:]

        # Публичный SubjectPublicKeyInfo: последние 32 байта — сырой ключ.
        pub_raw = pub_der[-32:]

        return (
            base64.b64encode(priv_raw).decode("ascii"),
            base64.b64encode(pub_raw).decode("ascii"),
        )


def _read_text(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except (IOError, OSError):
        return ""


def _pem_to_der(pem: str, label: str) -> bytes:
    """Очень простой PEM → DER декодер."""
    if not pem:
        return b""
    in_block = False
    body = []
    for line in pem.splitlines():
        if line.startswith("-----BEGIN") and label in line:
            in_block = True
            continue
        if line.startswith("-----END") and label in line:
            in_block = False
            break
        if in_block:
            body.append(line.strip())
    if not body:
        return b""
    try:
        return base64.b64decode("".join(body))
    except (ValueError, TypeError):
        return b""


def derive_public_key(private_key_b64: str, awg_binary: str = None) -> str:
    """Получить публичный из приватного: `awg pubkey` < private."""
    candidates = []
    if awg_binary:
        candidates.append(awg_binary)
    candidates.extend(["awg", "wg"])
    for binary in candidates:
        out = _run_pipe([binary, "pubkey"], private_key_b64 + "\n")
        if out:
            return out
    return ""
