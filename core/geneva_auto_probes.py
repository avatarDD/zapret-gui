# core/geneva_auto_probes.py
"""
Режим «Авто» geneva: пробы с роутера (перенос ``AutoProbes`` AutoTuner).

Зачем. Подозрение из наблюдения (:mod:`core.geneva_auto_observer`) — ещё
не блокировка: сервер мог лежать, клиент — оборвать сам. Перед подбором
обязательна **проба без обхода** (baseline): открылось — не блокировка,
нет TCP-соединения — блокировка по адресу (пакетами не обойти), иначе —
блокировка, ищем стратегию. Та же проба с обходом проверяет ослабевший
(``degraded``) сервис, а её вариант с заданного локального порта — оценка
стратегии в подборе geneva (fitness по шкале ``docs/EVAL.md`` geneva_c).

Что пробуем:

* **сайт** (``web``) — полная загрузка страницы (уровень «тело»: ответ
  HTTP и ≥ 64 КБ тела или весь ответ, без зависания) с увиденного IP с
  его именем в SNI и Host. Не resolve: у провайдера DNS может врать, а
  блокируют ровно тот адрес, куда ходит клиент. Таймаут соединения или
  «нет маршрута» → ``ip_blocked``;
* **остальное** — повтор первых пакетов клиента (``replay`` из захвата)
  UDP- или TCP-сокетом, две попытки, любой ответ — успех; нет TCP-
  соединения → ``ip_blocked``. STUN — свежий Binding Request (как
  ``core/testers/stun_tester``), резолвер без повтора — свежий запрос
  ``A`` (отличие: в эталоне такой DNS-сервис уходил в «неизвестно»,
  хотя считался проверяемым). WireGuard, DHT, ICE, Discord не
  повторяются: :func:`check` отвечает ``unknown``, книга признаёт их по
  двум срезам подряд.

Мимо очередей. Проба без обхода метится ``SO_MARK``: метка проб nfqws2
(``nfqws.desync_mark_probe``, connmark-исключение в правилах nfqws2) и
метка geneva ``0x20000000`` (её пропускают правила ``geneva run`` и групп
«Авто»). Проба с обходом идёт без метки — через правила группы. Обе —
с исходных портов блока ``AUTO_PROBE_PORTS``, который наблюдение не
считает трафиком пользователя. Оценка для подбора — с порта, который дал
geneva (его правила оценщика ловят этот порт), без метки.

Чистые функции (вердикт и fitness по итогу пробы, разбор ответа HTTP,
сборка запросов) отделены от сокетов и покрыты тестами; сами сокеты —
:func:`probe_page` и :func:`probe_replay`, класс :class:`AutoProbes`
подменяется в тестах менеджера.
"""

from __future__ import annotations

import errno
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass

from core import geneva_auto as ga
from core.geneva_auto_observer import AUTO_PROBE_PORTS

# ───────────────────────────── пороги ───────────────────────────────

PAGE_TIME = 12.0                  # вся загрузка страницы (AutoProbes.PageTime)
CONNECT_TIMEOUT = 5.0
STALL = 4.0                       # данных нет столько — зависло
MIN_BODY = 64 * 1024              # уровень «тело»: столько или весь ответ
REPLAY_TIMEOUT = 3.0              # ReplayProbeOptions.Timeout
REPLAY_ROUNDS = 4                 # UDP: детектору нужно ≥ 4 датаграмм
REPLAY_GAP = 0.25
REPLAY_TRIES = 2                  # одна потерянная датаграмма — не блок
GENEVA_MARK = 0x20000000
FRESH_DNS_NAME = "example.com"    # свежий запрос резолверу без replay

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Исходы загрузки страницы (ProbeError).
P_OK = ""
P_CONNECT_TIMEOUT = "connect_timeout"
P_CONNECT_REFUSED = "connect_refused"
P_UNREACHABLE = "unreachable"
P_TLS_TIMEOUT = "tls_timeout"
P_TLS_RESET = "tls_reset"
P_TLS_CLOSED = "tls_closed"
P_TLS_FAILED = "tls_failed"
P_HTTP_TIMEOUT = "http_timeout"
P_HTTP_RESET = "http_reset"
P_STALLED = "stalled"
P_TRUNCATED = "truncated"
P_BAD_RESPONSE = "bad_response"
P_TIME_LIMIT = "time_limit"
P_OTHER = "other"

# Исходы повтора (ReplayError).
R_OK = ""
R_NOTHING = "nothing_to_send"
R_NO_ANSWER = "no_answer"
R_NO_CONNECTION = "no_connection"
R_RESET = "reset"
R_CLOSED = "server_closed"
R_SOCKET = "socket"

TEXT = {
    P_CONNECT_TIMEOUT: "соединение не установилось",
    P_CONNECT_REFUSED: "сброс в ответ на SYN",
    P_UNREACHABLE: "нет маршрута",
    P_TLS_TIMEOUT: "TLS: нет ответа на ClientHello",
    P_TLS_RESET: "TLS: сброс (RST)",
    P_TLS_CLOSED: "TLS: соединение закрыто",
    P_TLS_FAILED: "TLS: ошибка рукопожатия",
    P_HTTP_TIMEOUT: "нет ответа HTTP",
    P_HTTP_RESET: "сброс после рукопожатия",
    P_STALLED: "данные встали",
    P_TRUNCATED: "ответ оборван",
    P_BAD_RESPONSE: "ответ не HTTP",
    P_TIME_LIMIT: "загрузка не уложилась во время",
    P_OTHER: "ошибка пробы",
    R_NOTHING: "нечего отправить: нет первых пакетов",
    R_NO_ANSWER: "нет ответа",
    R_NO_CONNECTION: "нет соединения",
    R_RESET: "сброс (RST)",
    R_CLOSED: "сервер закрыл соединение",
    R_SOCKET: "ошибка сокета",
}

# ───────────────────────────── итоги ────────────────────────────────


@dataclass
class PageResult:
    """Загрузка страницы (ProbeResult AutoTuner, нужные поля)."""
    connect_ok: bool = False
    tls: bool = True
    tls_ok: bool = False
    cert_valid: bool = True
    status: int = None            # код HTTP; None — ответа не было
    body: int = 0                 # байт тела
    complete: bool = False        # весь ответ (длина, chunked, EOF)
    stalled_at: int = None
    error: str = P_OK
    detail: str = ""
    port_unavailable: bool = False

    def passes(self, min_bytes: int = MIN_BODY) -> bool:
        """Уровень «тело»: сервер ответил (и 4xx/5xx — ответ), тело
        ≥ ``min_bytes`` или весь ответ, без зависания."""
        l1 = self.connect_ok and self.status is not None and (
            not self.tls or (self.tls_ok and self.cert_valid))
        return l1 and self.stalled_at is None and (
            self.body >= min_bytes or self.complete)

    def text(self) -> str:
        if self.passes():
            return "HTTP %s, %d Б" % (self.status, self.body)
        if self.error == P_OK and self.tls_ok and not self.cert_valid:
            return "чужой сертификат (страница блокировки)"
        what = TEXT.get(self.error, self.error or "ответ неполный")
        if self.stalled_at is not None:
            what += " на %d Б" % self.stalled_at
        return what + (" (%s)" % self.detail if self.detail else "")


@dataclass
class ReplayResult:
    """Повтор первых пакетов (ReplayProbeResult)."""
    ok: bool = False
    sent: int = 0
    received: int = 0
    bytes_in: int = 0
    error: str = R_OK
    detail: str = ""

    @property
    def port_unavailable(self) -> bool:
        """Не занялся локальный порт: это не ответ сети, другой порт
        блока может подойти."""
        return self.error == R_SOCKET and self.sent == 0 and \
            self.detail.startswith("local port")

    def text(self) -> str:
        if self.ok:
            return "ответ %d Б" % self.bytes_in
        return TEXT.get(self.error, self.error) + (
            " (%s)" % self.detail if self.detail else "")


# ───────────────────────────── вердикты (чистые) ────────────────────

def page_confirm(r: PageResult) -> str:
    """Проба сайта без обхода → ``AutoConfirm``."""
    if r.passes():
        return ga.C_NOT_BLOCKED
    if r.error in (P_CONNECT_TIMEOUT, P_UNREACHABLE):
        return ga.C_IP_BLOCKED
    if r.error == P_OTHER and not r.connect_ok:
        return ga.C_UNKNOWN           # проба сама не смогла (метка, сокет)
    return ga.C_BLOCKED


def replay_confirm(results) -> str:
    """Попытки повтора → ``AutoConfirm``: успех любой — открыт; иначе по
    последней: нет соединения — блок по адресу."""
    results = list(results or [])
    if not results:
        return ga.C_UNKNOWN
    if any(r.ok for r in results):
        return ga.C_NOT_BLOCKED
    last = results[-1]
    if last.error == R_NO_CONNECTION:
        return ga.C_IP_BLOCKED
    if last.error in (R_NOTHING, R_SOCKET):
        return ga.C_UNKNOWN
    return ga.C_BLOCKED


def page_fitness(r: PageResult):
    """``(fitness, outcome)`` загрузки по шкале geneva (GenevaFitness)."""
    if r.passes():
        return ga.FIT_OK, "ok"
    e = r.error
    if e in (P_CONNECT_TIMEOUT, P_UNREACHABLE):
        return ga.FIT_NO_CONNECTION, "connect_timeout"
    if e in (P_CONNECT_REFUSED, P_TLS_RESET, P_HTTP_RESET):
        return ga.FIT_RESET, "reset"
    if e in (P_TLS_TIMEOUT, P_HTTP_TIMEOUT, P_STALLED):
        return ga.FIT_CLOSED, "timeout"
    if e in (P_TRUNCATED, P_BAD_RESPONSE, P_TLS_CLOSED, P_TIME_LIMIT):
        return ga.FIT_CLOSED, "broken"
    if e == P_OK and r.tls and r.tls_ok and not r.cert_valid:
        # сертификат на другое имя — страница блокировки или подмена
        return ga.FIT_RESET, "injected"
    if e == P_OK:
        return ga.FIT_CLOSED, "broken"
    return ga.FIT_NO_ANSWER, "failed"


def replay_fitness(r: ReplayResult):
    """``(fitness, outcome)`` повтора (AutoProbes.Fitness): ответ — весь
    обмен этих протоколов."""
    if r.ok:
        return ga.FIT_OK, "ok: answer"
    return {
        R_RESET: (ga.FIT_RESET, "reset"),
        R_NO_CONNECTION: (ga.FIT_NO_CONNECTION, "connect_timeout"),
        R_NO_ANSWER: (ga.FIT_NO_ANSWER, "timeout: no answer"),
        R_CLOSED: (ga.FIT_CLOSED, "broken: closed"),
    }.get(r.error, (ga.FIT_NO_ANSWER, "failed: %s" % (r.detail or r.error)))


# ───────────────────────────── запросы (чистые) ─────────────────────

def stun_binding_request() -> bytes:
    """STUN Binding Request (RFC 5389) со свежим transaction id."""
    from core.testers.stun_tester import build_stun_request
    return build_stun_request()


def dns_query(name: str = FRESH_DNS_NAME, tcp: bool = False) -> bytes:
    """Запрос ``A`` с рекурсией; по TCP — с двухбайтовой длиной."""
    qname = b"".join(bytes([len(x)]) + x.encode("ascii")
                     for x in name.strip(".").split(".") if x) + b"\0"
    msg = struct.pack(">HHHHHH", int.from_bytes(os.urandom(2), "big"),
                      0x0100, 1, 0, 0, 0) + qname + b"\0\1\0\1"
    return struct.pack(">H", len(msg)) + msg if tcp else msg


def replay_plan(s: ga.Service):
    """Что слать сервису: ``(payloads, udp, fresh)`` или ``None``.

    ``fresh`` — каждая отправка — новый запрос (STUN, DNS без replay):
    повтор того же transaction id сервер может счесть дублем.
    """
    udp = s.transport == "udp"
    if s.app == "stun":
        return [], udp, "stun"
    payloads = ga.from_base64(s.replay) if s.app in ga.REPLAYABLE_APPS \
        else []
    if payloads:
        return payloads, udp, ""
    if s.kind == ga.DNS:
        return [], udp, "dns"
    return None


def _fresh(kind: str, udp: bool) -> bytes:
    if kind == "stun":
        return stun_binding_request()
    return dns_query(tcp=not udp)


def build_request(host: str, path: str = "/") -> bytes:
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n" % (path, host, USER_AGENT)) \
        .encode("ascii", "replace")


class _Body:
    """Разбор ответа HTTP/1.x по мере прихода байт: код, длина тела,
    конец ответа (Content-Length, chunked, EOF)."""

    def __init__(self):
        self.head = b""
        self.status = None
        self.bad = False
        self.length = None
        self.chunked = False
        self.body = 0
        self.complete = False
        self._chunk_buf = b""
        self._chunk_left = 0
        self._head_done = False

    def feed(self, data: bytes) -> None:
        if not self._head_done:
            self.head += data
            end = self.head.find(b"\r\n\r\n")
            if end < 0:
                if len(self.head) > 64 * 1024 or (
                        len(self.head) >= 5 and
                        not self.head.startswith(b"HTTP/")):
                    self.bad = True
                return
            head, rest = self.head[:end], self.head[end + 4:]
            self._head_done = True
            self._parse_head(head)
            data = rest
            if self.bad:
                return
            if self.status in (204, 304) or 100 <= (self.status or 0) < 200:
                self.complete = True
                return
            if self.length == 0:
                self.complete = True
                return
        if not data:
            return
        if self.chunked:
            self._feed_chunked(data)
        else:
            self.body += len(data)
            if self.length is not None and self.body >= self.length:
                self.complete = True

    def _parse_head(self, head: bytes) -> None:
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ", 2)
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
            self.bad = True
            return
        try:
            self.status = int(parts[1])
        except ValueError:
            self.bad = True
            return
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            name = name.strip().lower()
            value = value.strip().lower()
            if name == b"content-length":
                try:
                    self.length = int(value)
                except ValueError:
                    pass
            elif name == b"transfer-encoding" and b"chunked" in value:
                self.chunked = True
        if self.chunked:
            self.length = None

    def _feed_chunked(self, data: bytes) -> None:
        buf = self._chunk_buf + data
        while buf:
            if self._chunk_left > 0:
                take = min(self._chunk_left, len(buf))
                self.body += take
                self._chunk_left -= take
                buf = buf[take:]
                if self._chunk_left == 0:
                    self._chunk_left = -2        # ждём CRLF после куска
                continue
            if self._chunk_left == -2:
                if len(buf) < 2:
                    break
                buf = buf[2:]
                self._chunk_left = 0
                continue
            end = buf.find(b"\r\n")
            if end < 0:
                break
            try:
                size = int(buf[:end].split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                self.bad = True
                return
            buf = buf[end + 2:]
            if size == 0:
                self.complete = True
                buf = b""
                break
            self._chunk_left = size
        self._chunk_buf = buf

    def eof(self) -> None:
        """Сервер закрыл: без длины и chunked это и есть конец ответа."""
        if self._head_done and not self.bad and not self.chunked and \
                self.length is None:
            self.complete = True


# ───────────────────────────── сокеты ───────────────────────────────

def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _bind_exact(sock, port: int) -> str:
    """Занять порт, выданный geneva; ``""`` или причина отказа."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::" if sock.family == socket.AF_INET6 else "0.0.0.0",
                   int(port)))
        return ""
    except OSError as e:
        return "local port unavailable: %d %s" % (port, e.strerror or e)


def _bind(sock, local_port: int, ports) -> str:
    """Исходный порт: ровно выданный geneva или по кругу из блока проб
    «Авто» (без SO_REUSEADDR: порт в TIME_WAIT пропускается)."""
    if local_port:
        return _bind_exact(sock, local_port)
    if ports:
        from core import probe_mark
        try:
            probe_mark._bind_port(sock, tuple(ports))
        except OSError as e:
            return "local port unavailable: %s" % e
    return ""


def _connect_error(e: BaseException) -> str:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return P_CONNECT_TIMEOUT
    if isinstance(e, ConnectionRefusedError):
        return P_CONNECT_REFUSED
    if isinstance(e, OSError) and e.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EHOSTDOWN,
            errno.ENETDOWN):
        return P_UNREACHABLE
    return P_OTHER


_ctx = None


def _ssl_context():
    """Проверка сертификата включена: чужой сертификат — подмена. На
    роутере без пакета ca-certificates проверять нечем — тогда без неё
    (иначе любой сайт выглядел бы заблокированным). Контекст один на
    процесс: загрузка CA на роутере — заметная доля пробы."""
    global _ctx
    if _ctx is None:
        _ctx = _new_ssl_context()
    return _ctx


def _new_ssl_context():
    ctx = ssl.create_default_context()
    try:
        has_ca = ctx.cert_store_stats().get("x509_ca", 0) > 0
    except Exception:                           # noqa: BLE001
        has_ca = True
    if not has_ca:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_page(ip: str, port: int, host: str, *, tls: bool = True,
               local_port: int = 0, ports=None, timeout: float = PAGE_TIME,
               stall: float = STALL, min_bytes: int = MIN_BODY,
               ctx=None) -> PageResult:
    """Загрузить страницу ``host`` с адреса ``ip`` (уровень «тело»).

    ``local_port`` — исходный порт от geneva (оценка стратегии),
    ``ports`` — блок, из которого брать порт. Метку ставит вызывающий
    (:func:`probe_mark.marking`).
    """
    r = PageResult(tls=tls)
    deadline = time.monotonic() + timeout
    try:
        sock = socket.socket(_family(ip), socket.SOCK_STREAM)
    except OSError as e:
        r.error, r.detail = P_OTHER, str(e)
        return r
    try:
        why = _bind(sock, local_port, ports)
        if why:
            r.error, r.detail, r.port_unavailable = P_OTHER, why, True
            return r
        sock.settimeout(min(CONNECT_TIMEOUT, timeout))
        try:
            sock.connect((ip, int(port)))
        except OSError as e:
            r.error, r.detail = _connect_error(e), str(e)
            return r
        r.connect_ok = True
        conn = sock
        if tls:
            ctx = ctx or _ssl_context()
            sock.settimeout(max(0.5, min(stall * 2,
                                         deadline - time.monotonic())))
            try:
                conn = ctx.wrap_socket(sock, server_hostname=host)
                r.tls_ok = True
            except ssl.SSLCertVerificationError as e:
                # рукопожатие прошло, сертификат не тот
                r.tls_ok, r.cert_valid, r.detail = True, False, str(e)
                return r
            except (socket.timeout, TimeoutError):
                r.error = P_TLS_TIMEOUT
                return r
            except ConnectionResetError:
                r.error = P_TLS_RESET
                return r
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError,
                    ConnectionAbortedError, BrokenPipeError):
                r.error = P_TLS_CLOSED
                return r
            except ssl.SSLError as e:
                r.error, r.detail = P_TLS_FAILED, str(e)
                return r
            except OSError as e:
                r.error, r.detail = P_TLS_RESET if e.errno == \
                    errno.ECONNRESET else P_OTHER, str(e)
                return r
        try:
            conn.sendall(build_request(host))
        except OSError as e:
            r.error, r.detail = P_HTTP_RESET, str(e)
            return r
        _read_page(conn, r, deadline, stall, min_bytes)
        try:
            conn.close()
        except OSError:
            pass
        return r
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _read_page(conn, r: PageResult, deadline: float, stall: float,
               min_bytes: int) -> None:
    body = _Body()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            r.error = P_TIME_LIMIT if body.status is not None \
                else P_HTTP_TIMEOUT
            break
        conn.settimeout(min(stall, left))
        try:
            data = conn.recv(65536)
        except (socket.timeout, TimeoutError):
            if time.monotonic() >= deadline - 0.01 and \
                    body.status is not None:
                r.error = P_TIME_LIMIT
            elif body.status is None:
                r.error = P_HTTP_TIMEOUT
            else:
                r.error, r.stalled_at = P_STALLED, body.body
            break
        except (ConnectionResetError, ssl.SSLError, OSError) as e:
            if isinstance(e, ssl.SSLError) and "EOF" in str(e) and \
                    body.status is not None:
                body.eof()
                if not body.complete:
                    r.error = P_TRUNCATED
            else:
                r.error, r.detail = P_HTTP_RESET, str(e)
            break
        if not data:
            body.eof()
            if body.status is None:
                r.error = P_BAD_RESPONSE if body.head else P_HTTP_RESET
            elif not body.complete:
                r.error = P_TRUNCATED
            break
        body.feed(data)
        if body.bad:
            r.error = P_BAD_RESPONSE
            break
        if body.complete or body.body >= min_bytes:
            break
    r.status = body.status
    r.body = body.body
    r.complete = body.complete
    if r.stalled_at is not None and r.body >= min_bytes:
        r.stalled_at = None


def probe_replay(ip: str, port: int, payloads, *, udp: bool,
                 fresh: str = "", local_port: int = 0, ports=None,
                 timeout: float = REPLAY_TIMEOUT,
                 rounds: int = REPLAY_ROUNDS) -> ReplayResult:
    """Послать первые пакеты клиента и ждать любой ответ
    (ReplayProbe.RunAsync). ``fresh`` — ``stun``/``dns``: каждый раз
    свежий запрос вместо ``payloads``."""
    payloads = [bytes(p) for p in payloads or [] if p]
    if not payloads and not fresh:
        return ReplayResult(error=R_NOTHING)
    if fresh:
        payloads = [b""]                   # одна отправка за раунд
    try:
        sock = socket.socket(_family(ip), socket.SOCK_DGRAM if udp
                             else socket.SOCK_STREAM)
    except OSError as e:
        return ReplayResult(error=R_SOCKET, detail=str(e))
    try:
        why = _bind(sock, local_port, ports)
        if why:
            return ReplayResult(error=R_SOCKET, detail=why)
        if udp:
            return _replay_udp(sock, ip, port, payloads, fresh, timeout,
                               rounds)
        return _replay_tcp(sock, ip, port, payloads, fresh, timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _replay_udp(sock, ip, port, payloads, fresh, timeout, rounds):
    r = ReplayResult()
    deadline = time.monotonic() + timeout
    try:
        sock.connect((ip, int(port)))
    except OSError as e:
        r.error, r.detail = R_SOCKET, str(e)
        return r
    for _ in range(max(1, rounds)):
        for p in payloads:
            try:
                sock.send(_fresh(fresh, True) if fresh else p)
                r.sent += 1
            except OSError as e:
                # ICMP port unreachable прошлой отправки — на connected
                # UDP-сокете это ECONNREFUSED; ответа так и нет
                if e.errno != errno.ECONNREFUSED:
                    r.error, r.detail = R_SOCKET, str(e)
                    return r
        wait_until = min(deadline, time.monotonic() + REPLAY_GAP)
        if _udp_wait(sock, r, wait_until):
            return r
        if time.monotonic() >= deadline:
            break
    _udp_wait(sock, r, deadline)
    if not r.ok:
        r.error = R_NO_ANSWER
    return r


def _udp_wait(sock, r: ReplayResult, until: float) -> bool:
    while True:
        left = until - time.monotonic()
        if left <= 0:
            return False
        sock.settimeout(left)
        try:
            data = sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return False
        except OSError:
            continue                    # ICMP unreachable: ждём дальше
        r.received += 1
        r.bytes_in += len(data)
        r.ok = True
        r.error = R_OK
        return True


def _replay_tcp(sock, ip, port, payloads, fresh, timeout):
    r = ReplayResult()
    sock.settimeout(timeout)
    try:
        sock.connect((ip, int(port)))
    except (socket.timeout, TimeoutError):
        r.error = R_NO_CONNECTION
        return r
    except OSError as e:
        why = _connect_error(e)
        r.error = R_NO_CONNECTION if why != P_OTHER else R_SOCKET
        r.detail = str(e)
        return r
    try:
        for p in payloads:
            sock.sendall(_fresh(fresh, False) if fresh else p)
            r.sent += 1
        data = sock.recv(65536)
    except (socket.timeout, TimeoutError):
        r.error = R_NO_ANSWER
        return r
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        r.error = R_RESET
        return r
    except OSError as e:
        r.error, r.detail = (R_RESET if e.errno == errno.ECONNRESET
                             else R_SOCKET), str(e)
        return r
    if not data:
        r.error = R_CLOSED
        return r
    r.ok, r.received, r.bytes_in = True, 1, len(data)
    return r


# ───────────────────────────── пробы режима ─────────────────────────

def baseline_mark() -> int:
    """Метка пробы без обхода: метка проб nfqws2 и метка geneva."""
    from core import probe_mark
    return probe_mark.configured() | GENEVA_MARK


class AutoProbes:
    """Пробы режима «Авто» (IAutoProbes). Подменяется в тестах."""

    def __init__(self, *, page=probe_page, replay=probe_replay,
                 mark=baseline_mark, ports=AUTO_PROBE_PORTS):
        self._page = page
        self._replay = replay
        self._mark = mark
        self._ports = ports

    def check(self, s: ga.Service, through_bypass: bool = False):
        """Сервис сейчас: ``(AutoConfirm, текст)``.

        ``through_bypass=False`` — без обхода (baseline, перед подбором),
        мимо всех очередей; ``True`` — через применённую стратегию
        (проверка ``degraded``). Только для ``s.probeable``; остальное —
        ``unknown``.
        """
        address = s.address
        if not address:
            return ga.C_UNKNOWN, "нет адреса"
        from core import probe_mark
        mark = 0 if through_bypass else self._mark()
        try:
            # Метка — только без обхода (marking(0) ничего не делает);
            # исходный порт из блока проб «Авто» — всегда.
            with probe_mark.marking(mark):
                if s.kind == ga.WEB:
                    r = self._page(address, s.port, s.host or s.name,
                                   tls=s.port != 80, ports=self._ports)
                    return page_confirm(r), r.text()
                plan = replay_plan(s)
                if plan is None:
                    return ga.C_UNKNOWN, "повтор невозможен (%s)" % (
                        ga.app_title(s.app))
                payloads, udp, fresh = plan
                results = []
                for _ in range(REPLAY_TRIES):
                    r = self._replay(address, s.port, payloads, udp=udp,
                                     fresh=fresh, ports=self._ports)
                    results.append(r)
                    if r.ok:
                        break
                return replay_confirm(results), results[-1].text()
        except probe_mark.MarkError as e:
            return ga.C_UNKNOWN, "метка пробы не встала: %s" % e
        except OSError as e:
            return ga.C_UNKNOWN, "проба не запустилась: %s" % e

    def judge(self, s: ga.Service):
        """Оценка стратегии с локального порта geneva: функция
        ``(port) → (fitness, outcome, port_unavailable)`` или ``None`` —
        у сервиса нет пробы. Сайт оценивается загрузкой страницы
        (в эталоне — встроенной пробой geneva), остальное — повтором.
        Снимок сервиса берётся сейчас: подбор идёт минутами."""
        snap = s.clone()
        address = snap.address
        if not address:
            return None
        if snap.kind == ga.WEB:
            def run(port):
                r = self._page(address, snap.port, snap.host or snap.name,
                               tls=snap.port != 80, local_port=port)
                if r.port_unavailable:
                    return 0, r.detail, True
                fit, outcome = page_fitness(r)
                return fit, outcome, False
            return run
        plan = replay_plan(snap)
        if plan is None:
            return None
        payloads, udp, fresh = plan

        def run(port):
            r = self._replay(address, snap.port, payloads, udp=udp,
                             fresh=fresh, local_port=port)
            if r.port_unavailable:
                return 0, r.detail, True
            fit, outcome = replay_fitness(r)
            return fit, outcome, False
        return run


_probes = None


def get_auto_probes() -> AutoProbes:
    global _probes
    if _probes is None:
        _probes = AutoProbes()
    return _probes
