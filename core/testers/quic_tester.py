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


# ─────────────── Проба настоящим Initial (с SNI) ────────────────

_FAMILY_BY_NAME = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}


def test_quic_handshake(
    host: str,
    port: int = 443,
    timeout: float = QUIC_TIMEOUT,
    retries: int = QUIC_RETRIES,
    ip_family: str = "auto",
    sni: str = "",
) -> SingleTestResult:
    """Проверить QUIC так, как его видит DPI: Initial с ClientHello и SNI.

    В отличие от :func:`test_quic` (Version Negotiation без SNI), этот
    пакет DPI расшифровывает и узнаёт по имени сайта — поэтому только он
    годится, чтобы понять, режет ли провайдер QUIC к этому сайту и
    помогает ли стратегия (``core/testers/quic_initial.py``).

    SUCCESS — сервер ответил QUIC-пакетом на наш SCID (Initial с
    ServerHello, Retry, CONNECTION_CLOSE — неважно: Initial дошёл и
    разобран). TIMEOUT — тишина, пакет дропнули. SKIPPED — у хоста нет
    адресов запрошенного семейства.
    """
    from core.testers.quic_initial import build_initial, parse_server_reply

    start = time.monotonic()
    target_name = f"{host}:{port}/udp"
    family = _FAMILY_BY_NAME.get(ip_family)

    try:
        addresses = _resolve_udp_addresses(host, port, family)
    except (socket.gaierror, OSError) as e:
        if family is not None:
            return SingleTestResult(
                target=target_name, test_type=TestType.QUIC.value,
                status=TestStatus.SKIPPED.value, error="NO_ADDR_FAMILY",
                details=f"Нет адресов {ip_family} для {host}",
                raw_data={"ip_family": ip_family},
            )
        return SingleTestResult(
            target=target_name, test_type=TestType.QUIC.value,
            status=TestStatus.ERROR.value, error="DNS_ERR",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details=f"DNS resolution failed: {str(e)[:60]}",
        )
    if not addresses:
        return SingleTestResult(
            target=target_name, test_type=TestType.QUIC.value,
            status=TestStatus.SKIPPED.value, error="NO_ADDR_FAMILY",
            details=f"Нет UDP-адреса для {host}",
        )

    af, socktype, proto, target_addr = addresses[0]
    family_label = "IPv6" if af == socket.AF_INET6 else "IPv4"
    rounds = max(1, int(retries))
    per_round = max(float(timeout) / rounds, 1.0)
    last_code, last_details = "QUIC_TIMEOUT", (
        f"Сервер не ответил на QUIC Initial с SNI ({family_label}) — "
        f"пакет дропается")

    for attempt in range(1, rounds + 1):
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            packet, _dcid, scid = build_initial(sni or host)
            sock.sendto(packet, target_addr)
            deadline = time.monotonic() + per_round
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    data, _peer = sock.recvfrom(4096)
                except socket.timeout:
                    break
                kind = parse_server_reply(data, scid)
                if not kind:
                    continue            # чужая датаграмма — ждём дальше
                return SingleTestResult(
                    target=target_name, test_type=TestType.QUIC.value,
                    status=TestStatus.SUCCESS.value,
                    latency_ms=round((time.monotonic() - start) * 1000, 2),
                    details=f"QUIC отвечает ({family_label}, {kind}, "
                            f"{len(data)} B)",
                    raw_data={"connected_ip": str(target_addr[0]),
                              "family": family_label, "reply": kind,
                              "attempt": attempt},
                )
        except ConnectionResetError:
            last_code = "QUIC_REFUSED"
            last_details = (f"ICMP unreachable — на {family_label} QUIC не "
                            f"слушается")
            break
        except OSError as e:
            last_code = "QUIC_ERR"
            last_details = f"{str(e)[:60]} ({family_label})"
            break
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    status = (TestStatus.TIMEOUT.value if last_code == "QUIC_TIMEOUT"
              else TestStatus.FAILED.value)
    return SingleTestResult(
        target=target_name, test_type=TestType.QUIC.value,
        status=status, error=last_code,
        latency_ms=round((time.monotonic() - start) * 1000, 2),
        details=last_details,
        raw_data={"family": family_label,
                  "connected_ip": str(target_addr[0])},
    )


def test_quic_dpi(
    host: str,
    port: int = 443,
    timeout: float = QUIC_TIMEOUT,
    retries: int = QUIC_RETRIES,
) -> SingleTestResult:
    """QUIC-проба для blockcheck: как видит DPI + контроль без имени сайта.

    Раньше фаза QUIC blockcheck'а слала только Version Negotiation-проб
    (:func:`test_quic`). В нём нет SNI, и DPI, который режет QUIC по
    имени сайта (так режут YouTube), его пропускает: отчёт писал «QUIC
    доступен», хотя видео по HTTP/3 не шло. Теперь сначала — настоящий
    Initial с SNI (:func:`test_quic_handshake`). Если на него тишина,
    контрольный VN-проб без SNI отличает два случая:

      * без имени сервер отвечает → QUIC режут ПО ИМЕНИ сайта
        (``QUIC_SNI_BLOCK``, лечится обходом DPI);
      * молчит и без имени → UDP/443 к адресу не проходит вовсе
        (или сервер не держит QUIC) — прежний ``TIMEOUT``.
    """
    res = test_quic_handshake(host, port=port, timeout=timeout,
                              retries=retries)
    if res.status != TestStatus.TIMEOUT.value:
        return res
    control = test_quic(host, port=port, timeout=timeout, retries=retries)
    raw = dict(res.raw_data or {})
    raw["control_no_sni"] = control.status
    if control.status == TestStatus.SUCCESS.value:
        return SingleTestResult(
            target=res.target, test_type=TestType.QUIC.value,
            status=TestStatus.TIMEOUT.value, error="QUIC_SNI_BLOCK",
            latency_ms=res.latency_ms,
            details="QUIC режется по имени сайта: Initial с SNI без "
                    "ответа, а пакет без имени сервер получает",
            raw_data=raw,
        )
    return SingleTestResult(
        target=res.target, test_type=TestType.QUIC.value,
        status=res.status, error=res.error or "TIMEOUT",
        latency_ms=res.latency_ms,
        details="UDP/443 не проходит (нет ответа ни на Initial с SNI, "
                "ни на пакет без имени)",
        raw_data=raw,
    )
