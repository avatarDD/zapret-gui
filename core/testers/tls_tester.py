# core/testers/tls_tester.py
"""
HTTPS/TLS тестер — низкоуровневая проверка через socket + ssl (stdlib).

Дополняет существующий core/diagnostics.check_http() (curl/wget):
- Проверяет установление TLS-соединения (handshake)
- Определяет тип ошибки: timeout, connection reset, SSL error
- Поддерживает пинг TLS 1.2 / TLS 1.3 отдельно
- Классифицирует ошибки для DPI-детекции

Использование:
    from core.testers.tls_tester import test_tls
    result = test_tls("youtube.com")                    # → SingleTestResult
    result = test_tls("discord.com", tls_version="1.3") # TLS 1.3 only
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import struct
import time

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import BIGHELLO_PAD_TARGET, HTTPS_TIMEOUT
from core.testers.dpi_classifier import classify_connect_error, classify_ssl_error
from core.testers.proxy import ProxyError, open_proxied_socket, proxy_label


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_ip_family(ip_family: str | None) -> str:
    """Нормализовать строку семейства IP."""
    family = str(ip_family or "auto").strip().lower()
    if family in ("ipv4", "ip4", "v4", "4"):
        return "ipv4"
    if family in ("ipv6", "ip6", "v6", "6"):
        return "ipv6"
    return "auto"


def _resolve_connect_addrs(
    host: str, port: int, ip_family: str,
) -> list[tuple[int, tuple]]:
    """Резолвить хост в список (af, sockaddr) для подключения."""
    if ip_family == "ipv4":
        family = socket.AF_INET
    elif ip_family == "ipv6":
        family = socket.AF_INET6
    else:
        family = socket.AF_UNSPEC

    infos = socket.getaddrinfo(
        host, port, family=family,
        type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
    )
    addrs: list[tuple[int, tuple]] = []
    seen: set[str] = set()
    for af, _socktype, _proto, _canonname, sockaddr in infos:
        key = f"{af}:{sockaddr[0]}:{sockaddr[1]}"
        if key not in seen:
            seen.add(key)
            addrs.append((af, sockaddr))
    return addrs


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def _make_context(tls_version: str | None) -> ssl.SSLContext:
    """Создать SSL-контекст с фиксацией версии TLS (или любой)."""
    context = ssl.create_default_context()
    if tls_version == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def test_tls(
    host: str,
    port: int = 443,
    timeout: int = HTTPS_TIMEOUT,
    tls_version: str | None = None,
    ip_family: str = "auto",
    proxy: dict | None = None,
) -> SingleTestResult:
    """Тест HTTPS/TLS-соединения с классификацией DPI-ошибок.

    Args:
        host: Целевой домен.
        port: Порт (по умолчанию 443).
        timeout: Таймаут соединения в секундах.
        tls_version: "1.2" или "1.3" для фиксации версии, None — любая.
        ip_family: "ipv4", "ipv6" или "auto".
        proxy: dict прокси (см. core.testers.proxy.parse_proxy) или None.

    Returns:
        SingleTestResult с DPI-классификацией ошибки.
    """
    # Определяем тип теста
    test_type = TestType.HTTP.value
    if tls_version == "1.2":
        test_type = TestType.TLS_12.value
    elif tls_version == "1.3":
        test_type = TestType.TLS_13.value

    # Через прокси работаем отдельной веткой (DNS-резолв — на стороне прокси).
    if proxy:
        return _test_tls_via_proxy(host, port, timeout, tls_version,
                                   test_type, proxy)

    start = time.time()
    bytes_read = 0
    family = _normalize_ip_family(ip_family)

    # --- DNS resolve ---
    try:
        connect_addrs = _resolve_connect_addrs(host, port, family)
    except socket.gaierror as e:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="DNS_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"DNS resolution failed: {str(e)[:80]}",
            raw_data={"ip_family": family},
        )
    except Exception as e:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="RESOLVE_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Resolve error: {str(e)[:80]}",
            raw_data={"ip_family": family},
        )

    if not connect_addrs:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.SKIPPED.value, error="NO_ADDR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"No addresses for requested family: {family}",
            raw_data={"ip_family": family},
        )

    last_exception: Exception | None = None

    # Общий deadline — не больше timeout*2 секунд на все адреса суммарно
    deadline = start + timeout * 2

    # --- Пробуем каждый адрес ---
    for addr_family, sockaddr in connect_addrs:
        remaining = deadline - time.time()
        if remaining <= 1:
            # Время вышло — не пробуем оставшиеся адреса
            if last_exception is None:
                last_exception = socket.timeout("total deadline exceeded")
            break

        sock = None
        ssock = None
        try:
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, remaining))

            # Создаём SSL-контекст
            context = _make_context(tls_version)

            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.connect(sockaddr)

            actual_tls = ssock.version()

            # Отправляем HTTP-запрос для проверки полной связности
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            )
            ssock.send(request.encode())

            response = b""
            try:
                while len(response) < 2048:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except (socket.timeout, ssl.SSLError):
                pass  # Частичный ответ — не критично
            bytes_read = len(response)

            elapsed = (time.time() - start) * 1000

            # Парсим HTTP-статус
            status_code = None
            if response:
                first_line = response.decode("utf-8", errors="ignore").split("\r\n")[0]
                match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", first_line)
                if match:
                    status_code = int(match.group(1))

            resolved_family = "ipv6" if addr_family == socket.AF_INET6 else "ipv4"
            connected_ip = str(sockaddr[0]) if sockaddr else ""

            return SingleTestResult(
                target=host, test_type=test_type,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed, 2),
                details=f"{actual_tls} HTTP {status_code or '?'}",
                raw_data={
                    "tls_version": actual_tls,
                    "status_code": status_code,
                    "bytes_read": bytes_read,
                    "ip_family": resolved_family,
                    "connected_ip": connected_ip,
                },
            )

        except ssl.SSLError as e:
            last_exception = e
            continue
        except socket.timeout as e:
            last_exception = e
            continue
        except (ConnectionResetError, ConnectionRefusedError, OSError) as e:
            last_exception = e
            continue
        except Exception as e:
            last_exception = e
            continue
        finally:
            for s in (ssock, sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

    # --- Все адреса упали — классифицируем последнюю ошибку ---
    elapsed = (time.time() - start) * 1000

    if isinstance(last_exception, ssl.SSLError):
        label, detail, _ = classify_ssl_error(last_exception, bytes_read)

        # TLS version unsupported — не сбой, а пропуск
        if label == "TLS_UNSUPPORTED":
            return SingleTestResult(
                target=host, test_type=test_type,
                status=TestStatus.SKIPPED.value, error=label,
                latency_ms=round(elapsed, 2), details=detail,
                raw_data={"ip_family": family},
            )

        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.FAILED.value, error=label,
            latency_ms=round(elapsed, 2), details=detail,
            raw_data={"ip_family": family},
        )

    if isinstance(last_exception, socket.timeout):
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.TIMEOUT.value, error="TIMEOUT",
            latency_ms=round(elapsed, 2),
            details="Connection timeout",
            raw_data={"ip_family": family},
        )

    if isinstance(last_exception, (ConnectionResetError, ConnectionRefusedError, OSError)):
        label, detail, _ = classify_connect_error(last_exception, bytes_read)
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.FAILED.value, error=label,
            latency_ms=round(elapsed, 2), details=detail,
            raw_data={"ip_family": family},
        )

    if last_exception is not None:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="ERROR",
            latency_ms=round(elapsed, 2),
            details=str(last_exception)[:100],
            raw_data={"ip_family": family},
        )

    return SingleTestResult(
        target=host, test_type=test_type,
        status=TestStatus.ERROR.value, error="NO_RESULT",
        latency_ms=round(elapsed, 2),
        details="No connection attempts completed",
        raw_data={"ip_family": family},
    )


def _test_tls_via_proxy(
    host: str, port: int, timeout: int, tls_version: str | None,
    test_type: str, proxy: dict,
) -> SingleTestResult:
    """Тест TLS через SOCKS5/HTTP-прокси (TCP CONNECT + handshake)."""
    start = time.time()
    plabel = proxy_label(proxy)
    sock = None
    ssock = None
    try:
        sock = open_proxied_socket(proxy, host, port, timeout=timeout)
        context = _make_context(tls_version)
        ssock = context.wrap_socket(sock, server_hostname=host,
                                    do_handshake_on_connect=False)
        ssock.settimeout(timeout)
        ssock.do_handshake()
        actual_tls = ssock.version()
        elapsed = (time.time() - start) * 1000
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.SUCCESS.value,
            latency_ms=round(elapsed, 2),
            details=f"{actual_tls} через {plabel}",
            raw_data={"tls_version": actual_tls, "proxy": plabel},
        )
    except ProxyError as e:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="PROXY_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Прокси: {str(e)[:90]}",
            raw_data={"proxy": plabel},
        )
    except ssl.SSLError as e:
        label, detail, _ = classify_ssl_error(e, 0)
        status = (TestStatus.SKIPPED.value if label == "TLS_UNSUPPORTED"
                  else TestStatus.FAILED.value)
        return SingleTestResult(
            target=host, test_type=test_type, status=status, error=label,
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"{detail} (через {plabel})",
            raw_data={"proxy": plabel},
        )
    except socket.timeout:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.TIMEOUT.value, error="TIMEOUT",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Таймаут через {plabel}",
            raw_data={"proxy": plabel},
        )
    except (ConnectionResetError, OSError) as e:
        label, detail, _ = classify_connect_error(e, 0)
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.FAILED.value, error=label,
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"{detail} (через {plabel})",
            raw_data={"proxy": plabel},
        )
    finally:
        for s in (ssock, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Большой / post-quantum ClientHello (детекция size-based DPI)
# ---------------------------------------------------------------------------

# Кодпоинты TLS-расширений и групп.
_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIG_ALGS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033
_EXT_PADDING = 0x0015

_GRP_X25519 = 0x001D
_GRP_SECP256R1 = 0x0017
# X25519MLKEM768 (post-quantum, RFC 9370 / draft) — клиентский key_share 1216 B.
_GRP_X25519MLKEM768 = 0x11EC
_MLKEM_SHARE_LEN = 1216


def _ext(ext_type: int, body: bytes) -> bytes:
    """Обернуть тело расширения в TLV."""
    return struct.pack(">HH", ext_type, len(body)) + body


def build_client_hello(
    host: str,
    with_pq: bool = True,
    pad_to: int = BIGHELLO_PAD_TARGET,
) -> bytes:
    """Собрать TLS 1.3 ClientHello (опц. с PQ key_share и паддингом).

    Большой ClientHello (с Kyber/MLKEM key_share ~1.2 КБ или паддингом)
    перестаёт умещаться в один TCP-сегмент. Некоторые DPI рвут именно такие
    пакеты — этим и проверяем size-based фильтрацию.

    Returns:
        Полная TLS-запись (record layer + handshake) готовая к отправке.
    """
    try:
        sni = host.encode("idna")
    except Exception:
        sni = host.encode("utf-8", errors="ignore")

    # server_name
    name_entry = b"\x00" + struct.pack(">H", len(sni)) + sni
    ext_sni = _ext(_EXT_SERVER_NAME,
                   struct.pack(">H", len(name_entry)) + name_entry)

    # supported_versions: TLS 1.3 + 1.2
    sv = b"\x03\x04\x03\x03"
    ext_sv = _ext(_EXT_SUPPORTED_VERSIONS, bytes([len(sv)]) + sv)

    # supported_groups
    groups = struct.pack(">H", _GRP_X25519)
    if with_pq:
        groups += struct.pack(">H", _GRP_X25519MLKEM768)
    groups += struct.pack(">H", _GRP_SECP256R1)
    ext_groups = _ext(_EXT_SUPPORTED_GROUPS,
                      struct.pack(">H", len(groups)) + groups)

    # signature_algorithms
    sigs = struct.pack(">HHHH", 0x0403, 0x0804, 0x0401, 0x0503)
    ext_sig = _ext(_EXT_SIG_ALGS, struct.pack(">H", len(sigs)) + sigs)

    # key_share: x25519 (32B) + опц. X25519MLKEM768 (1216B)
    ks = struct.pack(">HH", _GRP_X25519, 32) + os.urandom(32)
    if with_pq:
        ks += (struct.pack(">HH", _GRP_X25519MLKEM768, _MLKEM_SHARE_LEN)
               + os.urandom(_MLKEM_SHARE_LEN))
    ext_ks = _ext(_EXT_KEY_SHARE, struct.pack(">H", len(ks)) + ks)

    base_ext = ext_sni + ext_sv + ext_groups + ext_sig + ext_ks

    client_version = b"\x03\x03"
    random = os.urandom(32)
    session_id = os.urandom(32)            # TLS1.3 middlebox-compat
    sess = bytes([len(session_id)]) + session_id
    ciphers = struct.pack(">HHH", 0x1301, 0x1302, 0x1303)
    cs = struct.pack(">H", len(ciphers)) + ciphers
    comp = b"\x01\x00"                      # 1 method: null

    def _wrap(exts: bytes) -> bytes:
        ext_block = struct.pack(">H", len(exts)) + exts
        body = client_version + random + sess + cs + comp + ext_block
        hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    draft = _wrap(base_ext)
    if pad_to and len(draft) < pad_to:
        need = pad_to - len(draft) - 4  # минус заголовок padding-расширения
        if need < 0:
            need = 0
        base_ext += _ext(_EXT_PADDING, b"\x00" * need)

    return _wrap(base_ext)


def probe_clienthello(
    host: str,
    port: int = 443,
    timeout: int = HTTPS_TIMEOUT,
    with_pq: bool = True,
    pad_to: int = BIGHELLO_PAD_TARGET,
    proxy: dict | None = None,
) -> SingleTestResult:
    """Отправить большой/PQ ClientHello и проверить, дошёл ли он до сервера.

    Не завершает handshake — достаточно факта, что сервер начал отвечать
    (ServerHello/HelloRetryRequest/Alert = байты 0x16/0x15). Обрыв (RST/EOF/
    timeout) при рабочем обычном TLS = size-based DPI на ClientHello.

    Returns:
        SingleTestResult (test_type=tls_bighello).
    """
    start = time.time()
    tt = TestType.TLS_BIGHELLO.value
    ch = build_client_hello(host, with_pq=with_pq, pad_to=pad_to)
    ch_size = len(ch)

    sock = None
    try:
        if proxy:
            sock = open_proxied_socket(proxy, host, port, timeout=timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(ch)

        resp = sock.recv(16)
        elapsed = round((time.time() - start) * 1000, 2)

        if not resp:
            return SingleTestResult(
                target=host, test_type=tt, status=TestStatus.FAILED.value,
                error="TLS_EOF_EARLY", latency_ms=elapsed,
                details=f"EOF на большой ClientHello ({ch_size} B) — "
                        "возможен size-based DPI",
                raw_data={"ch_size": ch_size, "with_pq": with_pq},
            )

        ctype = resp[0]
        if ctype in (0x16, 0x15, 0x14):  # Handshake / Alert / ChangeCipherSpec
            label = "ServerHello" if ctype == 0x16 else (
                "Alert" if ctype == 0x15 else "CCS")
            return SingleTestResult(
                target=host, test_type=tt, status=TestStatus.SUCCESS.value,
                latency_ms=elapsed,
                details=f"Сервер ответил ({label}) на ClientHello {ch_size} B"
                        + (" с PQ" if with_pq else ""),
                raw_data={"ch_size": ch_size, "with_pq": with_pq,
                          "resp_type": ctype},
            )

        # Непонятный ответ — но что-то пришло, значит дошло до сервера.
        return SingleTestResult(
            target=host, test_type=tt, status=TestStatus.SUCCESS.value,
            latency_ms=elapsed,
            details=f"Ответ получен ({ch_size} B ClientHello)",
            raw_data={"ch_size": ch_size, "with_pq": with_pq,
                      "resp_type": ctype},
        )

    except ProxyError as e:
        return SingleTestResult(
            target=host, test_type=tt, status=TestStatus.ERROR.value,
            error="PROXY_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Прокси: {str(e)[:80]}",
            raw_data={"ch_size": ch_size, "with_pq": with_pq},
        )
    except socket.timeout:
        return SingleTestResult(
            target=host, test_type=tt, status=TestStatus.TIMEOUT.value,
            error="TIMEOUT",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Таймаут на большой ClientHello ({ch_size} B) — "
                    "возможен size-based DPI",
            raw_data={"ch_size": ch_size, "with_pq": with_pq},
        )
    except (ConnectionResetError, OSError) as e:
        label, detail, _ = classify_connect_error(e, 0)
        return SingleTestResult(
            target=host, test_type=tt, status=TestStatus.FAILED.value,
            error=label,
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"{detail} на ClientHello {ch_size} B",
            raw_data={"ch_size": ch_size, "with_pq": with_pq},
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
