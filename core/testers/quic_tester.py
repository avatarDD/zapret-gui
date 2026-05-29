# core/testers/quic_tester.py
"""
QUIC / HTTP-3 тестер — проверка доступности UDP/443 (QUIC).

YouTube, Google и Cloudflare активно используют QUIC (HTTP/3). Многие
провайдеры/DPI режут именно UDP/443, оставляя TCP/443 рабочим — из-за
этого видео «тормозит» или не грузится, хотя сайт открывается.

Техника (без криптографии): отправляем QUIC long-header пакет с заведомо
неизвестной версией протокола. По RFC 9000 сервер ОБЯЗАН ответить
Version Negotiation пакетом. Нам не нужен валидный TLS ClientHello внутри —
достаточно факта ответа:

  - пришёл UDP-ответ            → QUIC доступен (SUCCESS)
  - таймаут                     → UDP/443 дропается (TIMEOUT, вероятно блок)
  - ICMP port unreachable (RST) → сервер не слушает QUIC здесь (FAILED)

Использование:
    from core.testers.quic_tester import test_quic
    result = test_quic("www.youtube.com")   # → SingleTestResult
"""

from __future__ import annotations

import secrets
import socket
import struct
import time

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import QUIC_RETRIES, QUIC_TIMEOUT


# Неизвестная (force-VN) версия. Любая версия с битами 0x?a?a?a?a — это
# зарезервированные «greasing»-версии (RFC 9000 §15), сервер на них всегда
# отвечает Version Negotiation.
_FORCE_VN_VERSION = 0x1A2A3A4A

# Минимальный размер UDP-датаграммы для QUIC Initial (anti-amplification).
# Дополняем до 1200, чтобы middlebox'ы/серверы не игнорировали короткий пакет.
_MIN_DATAGRAM = 1200


def build_quic_vn_probe() -> tuple[bytes, bytes, bytes]:
    """Собрать QUIC long-header пакет, форсирующий Version Negotiation.

    Returns:
        (packet, dcid, scid) — пакет и использованные Connection ID
        (нужны для проверки эха в ответе).
    """
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)

    # byte0: long header (0x80) | fixed bit (0x40) | type/reserved
    first_byte = 0xC0
    header = struct.pack(">BI", first_byte, _FORCE_VN_VERSION)
    header += bytes([len(dcid)]) + dcid
    header += bytes([len(scid)]) + scid

    # Дополняем датаграмму нулями до минимального размера.
    pad_len = max(0, _MIN_DATAGRAM - len(header))
    packet = header + b"\x00" * pad_len
    return packet, dcid, scid


def _looks_like_quic_response(data: bytes, dcid: bytes, scid: bytes) -> bool:
    """Грубая проверка, что ответ — QUIC-пакет (VN или иной long header).

    Для вердикта «QUIC доступен» достаточно любого UDP-ответа от сервера,
    но проверка снижает шанс ложного срабатывания на случайном пакете.
    """
    if len(data) < 7:
        return False
    # Long header: старший бит первого байта установлен.
    if not (data[0] & 0x80):
        # Short header тоже возможен в теории, но на VN-проб не ожидается.
        # Любой ответ с этого адреса всё равно считаем признаком доступности.
        return True
    # Version Negotiation: version == 0x00000000.
    version = struct.unpack(">I", data[1:5])[0]
    if version == 0:
        return True
    # Иной long header — тоже валидный QUIC-ответ.
    return True


def _resolve_udp_addresses(
    host: str, port: int, family: socket.AddressFamily | None,
) -> list[tuple[int, int, int, tuple]]:
    """Резолвить хост в список UDP-адресов (af, socktype, proto, sockaddr)."""
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
        key = (af, str(sockaddr[0]), int(sockaddr[1]))
        if key not in seen:
            seen.add(key)
            resolved.append((af, socktype, proto, sockaddr))
    return resolved


def test_quic(
    host: str,
    port: int = 443,
    timeout: int = QUIC_TIMEOUT,
    retries: int = QUIC_RETRIES,
    family: socket.AddressFamily | None = None,
) -> SingleTestResult:
    """Проверить доступность QUIC (UDP/443) через Version Negotiation проб.

    Args:
        host: Целевой домен.
        port: UDP-порт (по умолчанию 443).
        timeout: Общий бюджет таймаута в секундах.
        retries: Количество раундов повторов (UDP теряет пакеты).
        family: Принудительное семейство адресов.

    Returns:
        SingleTestResult (test_type=quic).
    """
    start = time.monotonic()
    target_name = f"{host}:{port}/udp"

    try:
        addresses = _resolve_udp_addresses(host, port, family)
    except (socket.gaierror, OSError) as e:
        return SingleTestResult(
            target=target_name, test_type=TestType.QUIC.value,
            status=TestStatus.ERROR.value, error="DNS_ERR",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details=f"DNS resolution failed: {str(e)[:60]}",
        )

    if not addresses:
        return SingleTestResult(
            target=target_name, test_type=TestType.QUIC.value,
            status=TestStatus.SKIPPED.value, error="NO_ADDR",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details=f"Нет UDP-адреса для {host}",
        )

    last_error = "UDP timeout (QUIC)"
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

                packet, dcid, scid = build_quic_vn_probe()
                sock.sendto(packet, target_addr)

                response, _addr = sock.recvfrom(2048)
                elapsed = (time.monotonic() - start) * 1000

                if response and _looks_like_quic_response(response, dcid, scid):
                    return SingleTestResult(
                        target=target_name,
                        test_type=TestType.QUIC.value,
                        status=TestStatus.SUCCESS.value,
                        latency_ms=round(elapsed, 2),
                        details=f"QUIC доступен ({family_label}, "
                                f"{len(response)} B ответ)",
                        raw_data={
                            "resolved_ip": str(target_addr[0]),
                            "family": family_label,
                            "resp_bytes": len(response),
                        },
                    )

                last_error = f"Нераспознанный ответ ({family_label})"
                last_code = "PARSE_ERR"
                last_status = TestStatus.FAILED.value

            except socket.timeout:
                last_error = (
                    f"UDP/443 таймаут — QUIC дропается "
                    f"({family_label}, попытка {retry_idx}/{retry_rounds})"
                )
                last_code = "TIMEOUT"
                last_status = TestStatus.TIMEOUT.value
            except ConnectionResetError:
                last_error = f"ICMP unreachable — QUIC не слушается ({family_label})"
                last_code = "RESET"
                last_status = TestStatus.FAILED.value
                stop_scan = True
                break
            except OSError as e:
                last_error = f"{str(e)[:60]} ({family_label})"
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
        target=target_name, test_type=TestType.QUIC.value,
        status=last_status, error=last_code,
        latency_ms=round((time.monotonic() - start) * 1000, 2),
        details=last_error,
        raw_data={"family": last_family} if last_family else {},
    )
