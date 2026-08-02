# core/testers/probe.py
"""
Единая быстрая проба домена: DNS → TCP → TLS → HTTP.

Общий примитив для двух разделов GUI, которые до этого проверяли домены
каждый по-своему:
  - core/block_detector.py — фоновой мониторинг (пробует найденные домены);
  - core/blockcheck.py     — разовый прогон (полный набор фаз).

Зачем понадобилось: детектор нёс собственную копию probe-логики со своим
словарём кодов (``tls_rst`` / ``http_cutoff`` / …), не пересекавшимся с
``DPIClassification`` из blockcheck. Один и тот же обрыв два раздела
называли по-разному, рекомендация по обходу (remediation) у детектора не
считалась вовсе, а часть кодов (``dns_hijack``, ``http_timeout``,
``throttled``) была недостижима — объявлена и никогда не возвращалась.

Здесь один словарь на всех:
  probe-код   — детальный, для таблицы («что именно сломалось»);
  dpi         — значение DPIClassification (общая таксономия blockcheck);
  remediation — zapret / tunnel / dns / none / unknown (из models.remediation_for).

Проба намеренно лёгкая (одно соединение на 443, чтение до 32 КБ) — она
рассчитана на фоновый прогон по сотням доменов, а не на замену полному
blockcheck с его QUIC/STUN/ping/traceroute.

Использование:
    from core.testers.probe import probe_domain
    res = probe_domain("youtube.com", timeout=5)
    res.code          # "tls_rst"
    res.dpi           # "tls_dpi"
    res.remediation   # "zapret"
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

from core.models import DPIClassification, remediation_for
from core.testers.config import (
    ISP_BODY_MARKERS,
    KNOWN_BLOCK_IPS,
    TCP_BLOCK_RANGE_MAX,
    TCP_BLOCK_RANGE_MIN,
    TCP_BLOCK_RANGE_WIDE_MAX,
    TCP_BLOCK_RANGE_WIDE_MIN,
    THROTTLE_MIN_KBPS,
)
from core.testers.dpi_classifier import (
    classify_connect_error,
    classify_read_error,
    classify_ssl_error,
)


# ---------------------------------------------------------------------------
# Параметры пробы
# ---------------------------------------------------------------------------

# Сколько тела читаем. 32 КБ выбраны не случайно: классический DPI-обрыв
# приходится на 16-20 КБ (см. TCP_BLOCK_RANGE_*), и без чтения ЗА этот
# предел такой блок неотличим от рабочего соединения.
PROBE_MAX_BODY = 32_768

# Порог достоверности замера скорости внутри пробы. Он ниже, чем
# THROTTLE_MIN_BYTES (40 КБ) у CDN-теста blockcheck: там качают специально
# подобранный крупный файл, здесь — первые килобайты произвольной главной
# страницы. 16 КБ хватает на грубую оценку полосы и укладывается в
# PROBE_MAX_BODY.
PROBE_THROTTLE_MIN_BYTES = 16_384

# Сколько адресов домена пробуем, если первый не отвечает (CDN отдаёт
# несколько A-записей, одна может быть мёртвой).
PROBE_MAX_ADDRS = 2


# ---------------------------------------------------------------------------
# Словарь кодов: подпись + место в общей таксономии DPIClassification
# ---------------------------------------------------------------------------

# code → человекочитаемая подпись (RU, для таблиц GUI)
PROBE_CODES: dict[str, str] = {
    "ok": "Доступен",
    "dns_block": "DNS-блокировка",
    "dns_hijack": "DNS-подмена",
    "tcp_refused": "TCP отклонён",
    "tcp_reset": "TCP RST",
    "tcp_timeout": "TCP таймаут",
    "tls_rst": "TLS RST",
    "tls_mitm": "Подмена сертификата",
    "tls_timeout": "TLS таймаут",
    "tls_garbage": "TLS-ошибка",
    "isp_page": "Заглушка провайдера",
    "tcp_16_20": "Обрыв на 16-20 КБ",
    "http_cutoff": "HTTP обрезан",
    "http_timeout": "HTTP таймаут",
    "throttled": "Замедлен",
    "rate_limited": "Слишком часто (лимит запросов)",
    "unknown": "Неизвестная ошибка",
}

# code → DPIClassification.value. Отсюда же берётся remediation:
# remediation_for(dpi) → zapret / tunnel / dns / none / unknown.
DPI_BY_PROBE_CODE: dict[str, str] = {
    "ok": DPIClassification.NONE.value,
    # DNS-слой: и NXDOMAIN, и подменённый ответ лечатся одинаково (DoH/hosts).
    "dns_block": DPIClassification.DNS_FAKE.value,
    "dns_hijack": DPIClassification.DNS_FAKE.value,
    # TCP не устанавливается вовсе → блок по IP, обход DPI не поможет.
    "tcp_refused": DPIClassification.IP_BLOCK.value,
    "tcp_reset": DPIClassification.TCP_RESET.value,
    # Чистый таймаут НЕ считаем IP-блоком: silent-drop от DPI выглядит так же,
    # а он обходится nfqws2 (та же логика, что в DPIClassifier.classify).
    "tcp_timeout": DPIClassification.TIMEOUT_DROP.value,
    "tls_rst": DPIClassification.TLS_DPI.value,
    "tls_mitm": DPIClassification.TLS_MITM.value,
    "tls_timeout": DPIClassification.TLS_DPI.value,
    # Ошибка TLS без DPI-подписи (версия/шифр/alert сервера) — это не блок,
    # а особенность узла. Не помечаем как обходимую, иначе домен уедет в
    # авто-список и потянет за собой лишние правила.
    "tls_garbage": DPIClassification.UNKNOWN.value,
    "isp_page": DPIClassification.ISP_PAGE.value,
    "tcp_16_20": DPIClassification.TCP_16_20.value,
    "http_cutoff": DPIClassification.TCP_RESET.value,
    "http_timeout": DPIClassification.TIMEOUT_DROP.value,
    "throttled": DPIClassification.THROTTLED.value,
    "rate_limited": DPIClassification.UNKNOWN.value,
    "unknown": DPIClassification.UNKNOWN.value,
}


def dpi_for_code(code: str) -> str:
    """DPIClassification.value для probe-кода."""
    return DPI_BY_PROBE_CODE.get(code, DPIClassification.UNKNOWN.value)


def describe_code(code: str) -> str:
    """Человекочитаемая подпись probe-кода."""
    return PROBE_CODES.get(code, PROBE_CODES["unknown"])


# ---------------------------------------------------------------------------
# Признаки подменённого DNS-ответа (общие для пробы и для DNS-фазы blockcheck)
# ---------------------------------------------------------------------------

def has_non_public_ip(ips: Any) -> bool:
    """Есть ли среди адресов непубличный (private/loopback/reserved/…).

    Сильный, но НЕ самодостаточный признак перехвата: у домена может быть
    легитимный внутренний адрес (split-horizon DNS). Поэтому blockcheck
    использует эту проверку только вместе со сверкой с DoH.
    """
    for ip in ips or []:
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_link_local or addr.is_unspecified):
            return True
    return False


def known_block_ip(ips: Any) -> str:
    """Первый адрес из списка известных IP блок-страниц провайдеров, либо ""."""
    for ip in ips or []:
        if str(ip).strip() in KNOWN_BLOCK_IPS:
            return str(ip).strip()
    return ""


def looks_hijacked(ips: Any) -> tuple[bool, str]:
    """Однозначные признаки DNS-подмены → (флаг, причина).

    Однозначными считаем только два случая — их не даёт ни CDN, ни
    split-horizon DNS:
      1) адрес совпадает с известным IP блок-страницы провайдера;
      2) ВСЕ адреса — loopback/0.0.0.0 (классическая заглушка РКН).
    Прочие непубличные адреса тут не флагим, чтобы не ловить внутренние
    домены (nas.lan и т.п.).
    """
    ip_list = [str(ip).strip() for ip in (ips or []) if str(ip).strip()]
    if not ip_list:
        return False, ""

    blocked = known_block_ip(ip_list)
    if blocked:
        return True, "резолвится в IP блок-страницы провайдера (%s)" % blocked

    def _is_stub(raw: str) -> bool:
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return False
        return addr.is_loopback or addr.is_unspecified

    if all(_is_stub(ip) for ip in ip_list):
        return True, "резолвится в заглушку (%s)" % ", ".join(ip_list[:3])

    return False, ""


# ---------------------------------------------------------------------------
# Результат пробы
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Вердикт быстрой пробы одного домена."""

    domain: str
    code: str = "unknown"
    detail: str = ""
    latency_ms: float = 0.0
    bytes_read: int = 0
    resolved_ips: list[str] = field(default_factory=list)
    connected_ip: str = ""

    @property
    def ok(self) -> bool:
        return self.code == "ok"

    @property
    def dpi(self) -> str:
        """Значение DPIClassification."""
        return dpi_for_code(self.code)

    @property
    def remediation(self) -> str:
        """zapret / tunnel / dns / none / unknown."""
        return remediation_for(self.dpi)

    @property
    def actionable(self) -> bool:
        """Есть ли внятный способ обхода — т.е. это настоящая блокировка.

        Отсекает «шум» (unknown / ошибки сертификата / сервер лежит), который
        не нужно автоматически тащить в списки для nfqws2 и маршрутизации.
        """
        return self.remediation in ("zapret", "tunnel", "dns")

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "block_code": self.code,          # историческое имя поля в API
            "code": self.code,
            "block_desc": describe_code(self.code),
            "detail": self.detail,
            "dpi": self.dpi,
            "remediation": self.remediation,
            "latency_ms": round(self.latency_ms, 1),
            "bytes_read": self.bytes_read,
            "resolved_ips": list(self.resolved_ips),
            "connected_ip": self.connected_ip,
        }


# ---------------------------------------------------------------------------
# Маппинг меток классификаторов → probe-коды
# ---------------------------------------------------------------------------

_CONNECT_CODE: dict[str, str] = {
    "TCP_RESET": "tcp_reset",
    "TCP_REFUSED": "tcp_refused",
    "HOST_UNREACH": "tcp_refused",
    "NET_UNREACH": "tcp_refused",
    "TCP_TIMEOUT": "tcp_timeout",
    "TCP_ABORT": "tcp_reset",
    "CONNECT_ERR": "unknown",
}

_SSL_CODE: dict[str, str] = {
    "TLS_RESET": "tls_rst",
    "TLS_EOF_EARLY": "tls_rst",
    "TLS_EOF_DATA": "tls_rst",
    "TLS_MITM_SELF": "tls_mitm",
    "TLS_MITM_UNKNOWN_CA": "tls_mitm",
    "TLS_TIMEOUT": "tls_timeout",
    # Ниже — не DPI, а особенности узла: просроченный серт, отказ по SNI,
    # неподдерживаемая версия. Отдельным кодом, без рекомендации по обходу.
    "TLS_CERT_ERR": "tls_garbage",
    "TLS_UNSUPPORTED": "tls_garbage",
    "TLS_VERSION": "tls_garbage",
    "TLS_HANDSHAKE": "tls_garbage",
    "TLS_ALERT": "tls_garbage",
    "TLS_ALERT_INTERNAL": "tls_garbage",
    "TLS_SNI_REJECT": "tls_garbage",
    "TLS_ERR": "tls_garbage",
}

_READ_CODE: dict[str, str] = {
    "READ_RESET": "http_cutoff",
    "READ_BROKEN": "http_cutoff",
    "READ_TIMEOUT": "http_timeout",
    "READ_ERR": "http_cutoff",
}


# ---------------------------------------------------------------------------
# Сама проба
# ---------------------------------------------------------------------------

def _ssl_context(verify_cert: bool) -> ssl.SSLContext:
    """Контекст TLS для пробы.

    Проверка сертификата ВКЛЮЧЕНА по умолчанию: без неё MITM-перехват
    (подменённый серт провайдера) неотличим от рабочего соединения —
    ровно этим и грешила старая проба детектора (CERT_NONE).
    """
    ctx = ssl.create_default_context()
    if not verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _resolve(domain: str, port: int) -> list[str]:
    """Все IPv4/IPv6-адреса домена (порядок системного резолвера)."""
    infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM,
                               proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for _af, _st, _pr, _cn, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip not in ips:
            ips.append(ip)
    return ips


def _http_request(domain: str) -> bytes:
    """GET / — именно GET, а не HEAD.

    HEAD не даёт ни тела для маркеров ISP-заглушки, ни объёма для детекции
    обрыва на 16-20 КБ, ради которых проба и существует.
    """
    return (
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n" % domain
    ).encode("utf-8", errors="ignore")


def _looks_like_isp_page(body: bytes) -> str:
    """Найти маркер провайдерской заглушки в теле ответа."""
    try:
        text = body.decode("utf-8", errors="ignore").lower()
    except Exception:
        return ""
    for marker in ISP_BODY_MARKERS:
        if marker.lower() in text:
            return marker
    return ""


def _classify_cutoff(bytes_read: int, label: str) -> tuple[str, str]:
    """Обрыв чтения → (code, уточнение).

    Обрыв в окне 16-20 КБ — отдельный, самый узнаваемый почерк DPI, ради
    которого в blockcheck есть целый тестер (core/testers/tcp_test.py).
    """
    code = _READ_CODE.get(label, "http_cutoff")
    if code == "http_timeout":
        return code, ""
    if TCP_BLOCK_RANGE_MIN <= bytes_read <= TCP_BLOCK_RANGE_MAX:
        return "tcp_16_20", "обрыв на %d B — окно 16-20 КБ" % bytes_read
    if TCP_BLOCK_RANGE_WIDE_MIN <= bytes_read <= TCP_BLOCK_RANGE_WIDE_MAX:
        return "tcp_16_20", "обрыв на %d B — расширенное окно 10-25 КБ" % bytes_read
    return code, ""


def probe_domain(
    domain: str,
    timeout: int = 5,
    port: int = 443,
    max_body: int = PROBE_MAX_BODY,
    verify_cert: bool = True,
) -> ProbeResult:
    """Проба домена по цепочке DNS → TCP → TLS → HTTP.

    Args:
        domain: имя хоста (без схемы).
        timeout: таймаут на каждую сетевую операцию, сек.
        port: порт (по умолчанию 443).
        max_body: сколько байт тела читать (для детекции обрыва на 16-20 КБ).
        verify_cert: проверять сертификат (нужно для детекции MITM).

    Returns:
        ProbeResult — код, подпись, DPI-классификация и remediation.
    """
    domain = (domain or "").strip().rstrip(".")
    start = time.monotonic()

    def _done(code: str, detail: str = "", **kw) -> ProbeResult:
        return ProbeResult(
            domain=domain, code=code, detail=detail,
            latency_ms=(time.monotonic() - start) * 1000.0, **kw,
        )

    if not domain:
        return _done("unknown", "пустое имя домена")

    # ─── Stage 1: DNS ───
    try:
        ips = _resolve(domain, port)
    except socket.gaierror as e:
        return _done("dns_block", "не резолвится: %s" % str(e)[:80])
    except Exception as e:
        return _done("dns_block", "ошибка резолва: %s" % str(e)[:80])

    if not ips:
        return _done("dns_block", "нет A/AAAA-записей")

    hijacked, reason = looks_hijacked(ips)
    if hijacked:
        return _done("dns_hijack", reason, resolved_ips=ips)

    # ─── Stage 2: TCP ───
    sock = None
    connected_ip = ""
    last_err: Exception | None = None
    for ip in ips[:PROBE_MAX_ADDRS]:
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            connected_ip = ip
            break
        except Exception as e:      # socket.timeout — подкласс OSError
            last_err = e
            sock = None

    if sock is None:
        label, detail, _ = classify_connect_error(
            last_err or OSError("connect failed"), 0)
        return _done(_CONNECT_CODE.get(label, "unknown"), detail,
                     resolved_ips=ips)

    # ─── Stage 3: TLS + Stage 4: HTTP ───
    tls = None
    bytes_read = 0
    try:
        sock.settimeout(timeout)
        ctx = _ssl_context(verify_cert)
        try:
            tls = ctx.wrap_socket(sock, server_hostname=domain)
        except ssl.SSLError as e:
            label, detail, _ = classify_ssl_error(e, 0)
            return _done(_SSL_CODE.get(label, "tls_garbage"), detail,
                         resolved_ips=ips, connected_ip=connected_ip)
        except socket.timeout:
            return _done("tls_timeout", "таймаут TLS-handshake",
                         resolved_ips=ips, connected_ip=connected_ip)
        except (ConnectionResetError, OSError) as e:
            label, detail, _ = classify_connect_error(e, 0)
            # RST именно на handshake — почерк DPI по SNI, а не блок по IP.
            code = "tls_rst" if label in ("TCP_RESET", "TCP_ABORT") \
                else _CONNECT_CODE.get(label, "unknown")
            return _done(code, detail, resolved_ips=ips,
                         connected_ip=connected_ip)

        tls_version = tls.version() or ""
        body_start = time.monotonic()
        tls.sendall(_http_request(domain))

        chunks: list[bytes] = []
        read_error: Exception | None = None
        try:
            while bytes_read < max_body:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
        except Exception as e:
            read_error = e

        body = b"".join(chunks)
        elapsed_body = max(time.monotonic() - body_start, 0.001)

        if read_error is not None:
            label, detail, _ = classify_read_error(read_error, bytes_read)
            code, extra = _classify_cutoff(bytes_read, label)
            return _done(code, (extra or detail), resolved_ips=ips,
                         connected_ip=connected_ip, bytes_read=bytes_read)

        if not body:
            return _done("http_cutoff", "соединение закрыто без ответа",
                         resolved_ips=ips, connected_ip=connected_ip)

        marker = _looks_like_isp_page(body)
        if marker:
            return _done("isp_page", "маркер заглушки: %s" % marker,
                         resolved_ips=ips, connected_ip=connected_ip,
                         bytes_read=bytes_read)

        if not body.startswith(b"HTTP/"):
            return _done("http_cutoff", "ответ не похож на HTTP (%d B)" % bytes_read,
                         resolved_ips=ips, connected_ip=connected_ip,
                         bytes_read=bytes_read)

        # Замедление: считаем только на достоверном объёме, иначе крошечная
        # главная страница выглядела бы как «медленная».
        kbps = (bytes_read / 1024.0) / elapsed_body
        if bytes_read >= PROBE_THROTTLE_MIN_BYTES and kbps < THROTTLE_MIN_KBPS:
            return _done("throttled",
                         "%.1f КБ/с на %d B (порог %.0f КБ/с)"
                         % (kbps, bytes_read, THROTTLE_MIN_KBPS),
                         resolved_ips=ips, connected_ip=connected_ip,
                         bytes_read=bytes_read)

        status_line = body.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")
        detail = status_line[:60]
        if tls_version:
            detail = "%s, %s" % (tls_version, detail)
        return _done("ok", detail, resolved_ips=ips,
                     connected_ip=connected_ip, bytes_read=bytes_read)

    except ssl.SSLError as e:
        label, detail, _ = classify_ssl_error(e, bytes_read)
        return _done(_SSL_CODE.get(label, "tls_garbage"), detail,
                     resolved_ips=ips, connected_ip=connected_ip,
                     bytes_read=bytes_read)
    except socket.timeout:
        return _done("http_timeout", "таймаут чтения ответа",
                     resolved_ips=ips, connected_ip=connected_ip,
                     bytes_read=bytes_read)
    except Exception as e:
        return _done("unknown", str(e)[:100], resolved_ips=ips,
                     connected_ip=connected_ip, bytes_read=bytes_read)
    finally:
        for s in (tls, sock):
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
