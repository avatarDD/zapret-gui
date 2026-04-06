# core/testers/stun_tester.py
"""
STUN/UDP тестер — проверка UDP-связности (RFC 5389).

Отправляет STUN Binding Request и разбирает ответ.
Используется для проверки Discord/Telegram voice.

Использование:
    from core.testers.stun_tester import test_stun
    result = test_stun("stun.l.google.com", port=19302)  # → SingleTestResult
"""

from __future__ import annotations

import secrets
import socket
import struct
import time

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import STUN_TIMEOUT


# ---------------------------------------------------------------------------
# STUN protocol helpers
# ---------------------------------------------------------------------------

def build_stun_request() -> bytes:
    """Сборка STUN Binding Request (RFC 5389).

    Header (20 bytes):
    - 2B Message Type (0x0001 = Binding Request)
    - 2B Message Length (0)
    - 4B Magic Cookie (0x2112A442)
    - 12B Transaction ID (random)
    """
    msg_type = 0x0001
    msg_length = 0
    magic_cookie = 0x2112A442
    transaction_id = secrets.token_bytes(12)

    header = struct.pack(">HHI", msg_type, msg_length, magic_cookie)
    return header + transaction_id


def _parse_xor_mapped_address(
    value: bytes, magic_cookie: int, transaction_id: bytes,
) -> dict | None:
    """Разбор XOR-MAPPED-ADDRESS (IPv4/IPv6)."""
    if len(value) < 4:
        return None

    family = value[1]
    xor_port = struct.unpack(">H", value[2:4])[0]
    port = xor_port ^ (magic_cookie >> 16)

    if family == 0x01 and len(value) >= 8:  # IPv4
        xor_ip = struct.unpack(">I", value[4:8])[0]
        ip_int = xor_ip ^ magic_cookie
        ip = socket.inet_ntoa(struct.pack(">I", ip_int))
        return {"ip": ip, "port": port, "family": "IPv4"}

    if family == 0x02 and len(value) >= 20:  # IPv6
        xor_key = struct.pack(">I", magic_cookie) + transaction_id
        xored_ip = value[4:20]
        decoded_ip = bytes(b ^ xor_key[idx] for idx, b in enumerate(xored_ip))
        try:
            ip = socket.inet_ntop(socket.AF_INET6, decoded_ip)
        except OSError:
            return None
        return {"ip": ip, "port": port, "family": "IPv6"}

    return None


def _parse_mapped_address(value: bytes) -> dict | None:
    """Разбор MAPPED-ADDRESS (legacy fallback, IPv4/IPv6)."""
    if len(value) < 4:
        return None

    family = value[1]
    port = struct.unpack(">H", value[2:4])[0]

    if family == 0x01 and len(value) >= 8:
        return {
            "ip": socket.inet_ntoa(value[4:8]),
            "port": port,
            "family": "IPv4",
        }

    if family == 0x02 and len(value) >= 20:
        try:
            ip = socket.inet_ntop(socket.AF_INET6, value[4:20])
        except OSError:
            return None
        return {"ip": ip, "port": port, "family": "IPv6"}

    return None


def parse_stun_response(data: bytes) -> dict | None:
    """Разбор STUN Binding Success Response → {ip, port, family} или None."""
    if len(data) < 20:
        return None

    msg_type, msg_length, magic_cookie = struct.unpack(">HHI", data[:8])
    if msg_type != 0x0101:  # Binding Success Response
        return None

    transaction_id = data[8:20]
    body_end = min(len(data), 20 + msg_length)
    offset = 20

    while offset + 4 <= body_end:
        attr_type, attr_length = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4

        if offset + attr_length > body_end:
            break

        value = data[offset:offset + attr_length]
        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
            parsed = _parse_xor_mapped_address(value, magic_cookie, transaction_id)
            if parsed:
                return parsed
        elif attr_type == 0x0001:  # MAPPED-ADDRESS (fallback)
            parsed = _parse_mapped_address(value)
            if parsed:
                return parsed

        offset += attr_length
        # Padding to 4-byte boundary
        if attr_length % 4:
            offset += 4 - (attr_length % 4)

    return None


# ---------------------------------------------------------------------------
# DNS resolve helper
# ---------------------------------------------------------------------------

def _resolve_udp_addresses(
    host: str, port: int,
    family: socket.AddressFamily | None,
) -> list[tuple[int, int, int, tuple]]:
    """Резолвить хост в список UDP-адресов."""
    if family == socket.AF_INET:
        resolve_family = socket.AF_INET
    elif family == socket.AF_INET6:
        resolve_family = socket.AF_INET6
    else:
        resolve_family = socket.AF_UNSPEC

    infos = socket.getaddrinfo(
        host, port, resolve_family, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )

    resolved: list[tuple[int, int, int, tuple]] = []
    seen: set[tuple[int, str, int]] = set()
    for af, socktype, proto, _canonname, sockaddr in infos:
        if af not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = str(sockaddr[0])
        dst_port = int(sockaddr[1])
        key = (af, ip, dst_port)
        if key not in seen:
            seen.add(key)
            resolved.append((af, socktype, proto, sockaddr))

    return resolved


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def test_stun(
    host: str,
    port: int = 19302,
    timeout: int = STUN_TIMEOUT,
    retries: int = 2,
    family: socket.AddressFamily | None = None,
) -> SingleTestResult:
    """Тест STUN-сервера через UDP с ретраями.

    UDP «теряет» пакеты — один потерянный пакет не означает блокировку.
    Повторяем до `retries` раз перед вердиктом.

    Args:
        host: STUN hostname (напр. stun.l.google.com).
        port: STUN port (по умолчанию 19302).
        timeout: Общий бюджет таймаута в секундах.
        retries: Количество раундов повторов.
        family: Принудительное семейство адресов (AF_INET / AF_INET6).

    Returns:
        SingleTestResult.
    """
    start = time.monotonic()
    target_name = f"{host}:{port}"

    # --- DNS resolve ---
    try:
        addresses = _resolve_udp_addresses(host, port, family=family)
    except (socket.gaierror, OSError):
        return SingleTestResult(
            target=target_name, test_type=TestType.STUN.value,
            status=TestStatus.FAILED.value, error="DNS_ERR",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details=f"DNS resolution failed for {host}",
        )

    if not addresses:
        return SingleTestResult(
            target=target_name, test_type=TestType.STUN.value,
            status=TestStatus.FAILED.value, error="DNS_ERR",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details=f"No usable UDP address for {host}",
        )

    last_error = "UDP timeout"
    last_code = "TIMEOUT"
    last_status = TestStatus.TIMEOUT.value
    last_family = ""

    retry_rounds = max(1, int(retries))
    timeout_budget = max(float(timeout), 1.0)
    total_attempts = max(1, retry_rounds * len(addresses))
    per_attempt = max(timeout_budget / total_attempts, 1.0)
    deadline = start + timeout_budget

    stop_scan = False

    for retry_idx in range(1, retry_rounds + 1):
        for af, socktype, proto, target_addr in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            family_label = "IPv6" if af == socket.AF_INET6 else "IPv4"
            last_family = family_label
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(min(per_attempt, max(0.5, remaining)))

                request = build_stun_request()
                sock.sendto(request, target_addr)

                response, _addr = sock.recvfrom(1024)
                elapsed = (time.monotonic() - start) * 1000
                parsed = parse_stun_response(response)

                if parsed:
                    parsed.setdefault("resolved_ip", str(target_addr[0]))
                    parsed.setdefault("resolved_family", family_label)
                    return SingleTestResult(
                        target=target_name,
                        test_type=TestType.STUN.value,
                        status=TestStatus.SUCCESS.value,
                        latency_ms=round(elapsed, 2),
                        details=f"Public IP: {parsed['ip']}:{parsed['port']} ({family_label})",
                        raw_data=parsed,
                    )

                last_error = f"Failed to parse STUN response ({family_label})"
                last_code = "PARSE_ERR"
                last_status = TestStatus.FAILED.value
                stop_scan = True
                break

            except socket.timeout:
                last_error = (
                    f"UDP timeout ({family_label}, "
                    f"attempt {retry_idx}/{retry_rounds})"
                )
                last_code = "TIMEOUT"
                last_status = TestStatus.TIMEOUT.value
            except ConnectionResetError:
                last_error = f"Connection reset (ICMP unreachable, {family_label})"
                last_code = "RESET"
                last_status = TestStatus.FAILED.value
                stop_scan = True
                break
            except OSError as e:
                last_error = f"{e} ({family_label})"
                last_code = "ERROR"
                last_status = TestStatus.ERROR.value
                stop_scan = True
                break
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        if stop_scan:
            break

    return SingleTestResult(
        target=target_name, test_type=TestType.STUN.value,
        status=last_status, error=last_code,
        latency_ms=round((time.monotonic() - start) * 1000, 2),
        details=last_error,
        raw_data={"family": last_family} if last_family else {},
    )
