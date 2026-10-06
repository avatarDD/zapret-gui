# core/testers/dpi_differential.py
"""
Дифференциальный классификатор DPI: ЧЕМ режут, а не только «режут ли».

Приём d2k (necronicle/d2k, ``core/include/d2k_verdict.h``, перенос
``z2k-detect/internal/classify``). DPI — функция «байты соединения →
пропустить или убить», и её зондируют напрямую: меняется ТОЛЬКО способ
записи одного и того же ClientHello, а из формы ответа читается
устройство матчера. Порядок вопросов несущий, каждый отсекает половину:

1. **база** — ClientHello целиком. Прошёл (ServerHello) — обходить
   нечего: ``clear``;
2. **разрез на первом байте** — самый агрессивный разрез из возможных
   (в первом сегменте один байт). Помог — DPI смотрит только первый
   сегмент и не собирает поток: ``prefix``, лечится multisplit /
   multidisorder. Не помог — не поможет ни один разрез правее;
3. **контроль чужим именем на тот же адрес**. Без него шаг 2 не
   отличить от «молчит вся линия»: контроль ответил — режут по
   содержимому (SNI), разрезом не взять, нужен фейк/seqovl: ``opaque``;
   контроль тоже молчит — режут адрес: ``address``, поможет туннель.

Плюс два класса «планов не предлагать», которые симптоматический
классификатор сливал с блокировкой:

* ``local_address`` — имя разрешается в приватный адрес: подменяет
  роутер, AdGuard или собственный редирект, провайдер ни при чём;
* ``response`` — запрос проходит, режут ОТВЕТ: в TLS 1.2 сертификат
  едет открытым текстом, и DPI убивает поток после ServerHello.

## Чему верим, а чему нет

* Проход триггера — только **ServerHello** (handshake type 2). Коробка,
  убившая байты, обычно не молчит: инжектирует алерт или страницу, и
  на счёте «вернулось хоть что-то» такой ответ неотличим от чистой
  линии. У контроля — любая запись TLS, включая алерт: сервер вправе
  не знать чужое имя, важно, что он ответил.
* Повторы обязаны совпасть. Разошлись — ``flaky``, а не вердикт.
* **Непомеченная база не даёт ``clear``**, если движок работает: такая
  проба идёт СКВОЗЬ наш обход, и «обходить нечего» было бы
  самоподтверждением. Поэтому пробы метятся ``SO_MARK`` мимо очереди
  (``core/probe_mark.py``); нельзя — ``inconclusive`` с причиной.
* Вывод о разрезе называет паузу, на которой он снят: на другой
  паузе он может не повториться.

Разбор ответа — чистые функции (:func:`parse_server_flight`,
:func:`decide`), сеть — :func:`classify`.
"""

from __future__ import annotations

import socket
import ssl
import time

from core.log_buffer import log
from core.models import DPIClassification, remediation_for


# ─────────────────────────── вердикты ───────────────────────────────

CLEAR = "clear"
PREFIX = "prefix"
OPAQUE = "opaque"
ADDRESS = "address"
RESPONSE = "response"
LOCAL_ADDRESS = "local_address"
UNREACHABLE = "unreachable"
FLAKY = "flaky"
INCONCLUSIVE = "inconclusive"

VERDICTS = {
    CLEAR: "ClientHello целиком проходит — обходить нечего",
    PREFIX: "помогает разрез на первом байте: DPI не собирает сегменты — "
            "хватит multisplit/multidisorder",
    OPAQUE: "разрез не помогает, контроль чужим именем на тот же адрес "
            "проходит: режут по содержимому (SNI) — нужен фейк/seqovl",
    ADDRESS: "молчит и контроль чужим именем: режут адрес или сеть — "
             "десинк не поможет, нужен туннель",
    RESPONSE: "запрос проходит, режут ответ (сертификат TLS 1.2 едет "
              "открытым текстом) — разрезом запроса не лечится",
    LOCAL_ADDRESS: "имя разрешается в приватный адрес: подменяет роутер, "
                   "AdGuard или локальный редирект — провайдер ни при чём",
    UNREACHABLE: "до адреса нет даже TCP",
    FLAKY: "повторы разошлись — измерению верить нельзя",
    INCONCLUSIVE: "вердикта нет: данных не хватило",
}

# Вердикт → общий тип блокировки (core.models) — им живут отчёт
# blockcheck, рекомендация «zapret / туннель» и единый слой.
DPI_BY_VERDICT = {
    CLEAR: DPIClassification.NONE,
    PREFIX: DPIClassification.TLS_DPI,
    OPAQUE: DPIClassification.TLS_DPI,
    RESPONSE: DPIClassification.TLS_DPI,
    ADDRESS: DPIClassification.IP_BLOCK,
    UNREACHABLE: DPIClassification.IP_BLOCK,
    LOCAL_ADDRESS: DPIClassification.DNS_FAKE,
    FLAKY: DPIClassification.UNKNOWN,
    INCONCLUSIVE: DPIClassification.UNKNOWN,
}

# Имя-контроль: заведомо не блокируемое, которое сервер цели почти
# наверняка не обслуживает (ответит алертом или чужим сертификатом —
# для контроля это ответ).
CONTROL_SNI = "example.com"

# Пауза между первым байтом и остальным ClientHello. Без неё два
# send() уходят одним сегментом (Nagle выключен, но стек всё равно
# вправе склеить), и разреза на проводе нет.
SPLIT_GAP_SEC = 0.02

READ_CAP = 32 * 1024

TLS_HANDSHAKE = 0x16
TLS_ALERT = 0x15
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_HELLO_DONE = 14


# ─────────────────────── разбор ответа сервера ──────────────────────

def parse_server_flight(data: bytes) -> dict:
    """Что прислал сервер: записи TLS и сообщения рукопожатия.

    Returns:
        dict: ``first_record`` (тип первой записи или ``None``),
        ``tls`` (ответ похож на TLS), ``alert`` (была запись-алерт),
        ``server_hello``, ``certificate``, ``hello_done`` (видели
        соответствующие сообщения рукопожатия; TLS 1.3 после ServerHello
        шифрует остальное — там видно только ServerHello).
    """
    out = {"first_record": None, "tls": False, "alert": False,
           "server_hello": False, "certificate": False,
           "hello_done": False}
    data = bytes(data or b"")
    stream = b""
    pos = 0
    while pos + 5 <= len(data):
        kind = data[pos]
        major = data[pos + 1]
        length = (data[pos + 3] << 8) | data[pos + 4]
        if major != 3 or kind not in (0x14, 0x15, 0x16, 0x17):
            break
        if out["first_record"] is None:
            out["first_record"] = kind
            out["tls"] = True
        payload = data[pos + 5:pos + 5 + length]
        if kind == TLS_ALERT:
            out["alert"] = True
        elif kind == TLS_HANDSHAKE:
            stream += payload
        pos += 5 + length

    # Сообщения рукопожатия: тип (1) + длина (3). Последнее может быть
    # неполным — тип виден и так, а «целиком пришёл» нам важен только у
    # сертификата и ServerHelloDone, которые проверяются по концу.
    index = 0
    while index + 4 <= len(stream):
        msg = stream[index]
        size = int.from_bytes(stream[index + 1:index + 4], "big")
        complete = index + 4 + size <= len(stream)
        if msg == HS_SERVER_HELLO:
            out["server_hello"] = True
        elif msg == HS_CERTIFICATE and complete:
            out["certificate"] = True
        elif msg == HS_SERVER_HELLO_DONE and complete:
            out["hello_done"] = True
        index += 4 + size
    return out


def trigger_passed(flight: dict, tls12: bool = False) -> bool:
    """Прошёл ли наш ClientHello: ServerHello (у TLS 1.2 — весь ответ)."""
    if tls12:
        return bool(flight.get("hello_done"))
    return bool(flight.get("server_hello"))


def control_passed(flight: dict) -> bool:
    """Ответил ли сервер контролю: любая запись TLS, алерт тоже."""
    return bool(flight.get("tls"))


def _consensus(results):
    """``True``/``False`` — все повторы согласны; ``None`` — разошлись."""
    values = [bool(r) for r in results]
    if not values:
        return None
    if all(values):
        return True
    if not any(values):
        return False
    return None


def decide(steps: dict, marked: bool = True,
           split_gap_ms: int = int(SPLIT_GAP_SEC * 1000)) -> tuple:
    """Вердикт по результатам шагов — чистая функция.

    Args:
        steps: ``{"connect": [bool…], "base": [bool…], "split": [bool…],
            "control": [bool…], "tls12": {"server_hello": bool,
            "complete": [bool…]} | None}``; шага нет — ключа нет.
        marked: пробы шли мимо очереди (или обхода нет вовсе).

    Returns:
        (verdict, reason)
    """
    connect = steps.get("connect") or []
    if connect and not any(connect):
        return UNREACHABLE, "TCP не устанавливается ни в одном повторе"

    base = _consensus(steps.get("base") or [])
    if base is None:
        return FLAKY, "база: повторы разошлись — то проходит, то нет"
    if base:
        if not marked:
            return INCONCLUSIVE, (
                "база прошла, но пробы шли сквозь работающий обход (метки "
                "проб нет) — «обходить нечего» здесь было бы "
                "самоподтверждением")
        tls12 = steps.get("tls12") or {}
        complete = list(tls12.get("complete") or [])
        if tls12.get("server_hello") and complete and not any(complete):
            return RESPONSE, ("TLS 1.3 проходит; TLS 1.2 получает "
                              "ServerHello, а сертификат обрывается")
        reason = "ClientHello целиком получает ServerHello"
        if not tls12:
            reason += "; TLS 1.2 не проверялся — обратное направление " \
                      "(сертификат открытым текстом) не измерено"
        elif not tls12.get("server_hello"):
            reason += "; TLS 1.2: ServerHello не пришёл (сервер без " \
                      "TLS 1.2 или режут именно 1.2)"
        elif not all(complete):
            reason += "; TLS 1.2: ответ то доходит, то обрывается"
        return CLEAR, reason

    split = _consensus(steps.get("split") or [])
    if split is None:
        return FLAKY, "разрез на 1 байте: повторы разошлись"
    if split:
        return PREFIX, ("целиком режут, с разрезом после первого байта "
                        "(пауза %d мс) проходит" % split_gap_ms)

    control = _consensus(steps.get("control") or [])
    if control is None:
        return FLAKY, "контроль чужим именем: повторы разошлись"
    if control:
        return OPAQUE, ("ни целиком, ни с разрезом на 1 байте (пауза %d "
                        "мс) не проходит, а чужое имя на тот же адрес "
                        "получает ответ" % split_gap_ms)
    return ADDRESS, ("молчит и чужое имя на тот же адрес (сервер мог и "
                     "сам не ответить на чужое имя — проверьте другим "
                     "контролем)")


# ─────────────────────────── сеть ───────────────────────────────────

def build_client_hello(sni: str, tls12: bool = False) -> bytes:
    """ClientHello стандартного стека Python для ``sni`` (без отправки)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def exchange(ip: str, port: int, hello: bytes, timeout: float,
             split_at: int = 0, mark: int = 0, until=None) -> dict:
    """Отправить ClientHello (целиком или с разрезом) и прочитать ответ.

    Returns:
        dict: ``connected`` (bool), ``flight`` (разбор ответа),
        ``error`` (что оборвало чтение, или ``""``), ``bytes``.
    """
    from core import probe_mark

    out = {"connected": False, "flight": parse_server_flight(b""),
           "error": "", "bytes": 0}
    try:
        sock = probe_mark.create_connection((ip, port), timeout=timeout,
                                            mark=mark)
    except probe_mark.MarkError:
        raise
    except OSError as e:
        out["error"] = type(e).__name__
        return out
    out["connected"] = True
    data = b""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        if 0 < split_at < len(hello):
            sock.sendall(hello[:split_at])
            time.sleep(SPLIT_GAP_SEC)
            sock.sendall(hello[split_at:])
        else:
            sock.sendall(hello)
        deadline = time.monotonic() + timeout
        while len(data) < READ_CAP and time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                out["error"] = "closed"
                break
            data += chunk
            flight = parse_server_flight(data)
            if until and until(flight):
                break
    except socket.timeout:
        out["error"] = "timeout"
    except ConnectionResetError:
        out["error"] = "reset"
    except OSError as e:
        out["error"] = type(e).__name__
    finally:
        try:
            sock.close()
        except OSError:
            pass
    out["flight"] = parse_server_flight(data)
    out["bytes"] = len(data)
    return out


def _pick_ip(domain: str, port: int):
    """Адреса цели (IPv4 первыми) и признак «все приватные»."""
    from core.testers.probe import has_non_public_ip
    infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    ips = []
    for family, _, _, _, sockaddr in infos:
        if sockaddr[0] not in ips:
            ips.append(sockaddr[0])
    ips.sort(key=lambda ip: ":" in ip)
    local = bool(ips) and all(has_non_public_ip([ip]) for ip in ips)
    return ips, local


def classify(domain: str, port: int = 443, timeout: float = 5.0,
             repeats: int = 2, control_sni: str = CONTROL_SNI,
             mark=None, check_tls12: bool = True) -> dict:
    """Задать цели вопросы по порядку и вернуть вердикт.

    Args:
        mark: SO_MARK проб. ``None`` — решить самим
            (``probe_mark.baseline_mode``): пометить, если можно; если
            нельзя и движок работает — вердикт ``clear`` невозможен.
        check_tls12: при проходе базы проверить TLS 1.2 на обрыв ответа.

    Returns:
        dict: ``verdict``, ``verdict_text``, ``reason``,
        ``dpi_classification``, ``remediation``, ``ip``, ``steps``
        (что ответил каждый повтор), ``marked``, ``elapsed_sec``.
    """
    started = time.monotonic()
    domain = (domain or "").strip().rstrip(".").lower()
    repeats = max(1, min(int(repeats or 1), 5))
    steps = {}
    trace = {}

    marked = True
    mark_value = 0
    if mark is None:
        from core import nfqws_control, probe_mark
        mode = probe_mark.baseline_mode()
        if mode["marked"]:
            mark_value = mode["mark"]
        else:
            try:
                marked = not nfqws_control.running()
            except Exception:                   # noqa: BLE001 — граница
                marked = False
    else:
        mark_value = int(mark or 0)

    def _result(verdict, reason, ip=""):
        dpi = DPI_BY_VERDICT[verdict]
        return {
            "target": domain,
            "verdict": verdict,
            "verdict_text": VERDICTS[verdict],
            "reason": reason,
            "dpi_classification": dpi.value,
            "remediation": remediation_for(dpi.value),
            "ip": ip,
            "control_sni": control_sni,
            "steps": trace,
            "marked": bool(mark_value) or marked,
            "elapsed_sec": round(time.monotonic() - started, 2),
        }

    try:
        ips, local = _pick_ip(domain, port)
    except (socket.gaierror, OSError) as e:
        return _result(INCONCLUSIVE, "имя не разрешается: %s" % e)
    if not ips:
        return _result(INCONCLUSIVE, "нет адресов")
    if local:
        return _result(LOCAL_ADDRESS, "все адреса приватные: %s"
                       % ", ".join(ips[:3]), ips[0])
    ip = ips[0]

    def _ask(name, hello, split_at=0, passed=trigger_passed, tls12=False):
        rows = []
        for _ in range(repeats):
            res = exchange(ip, port, hello, timeout, split_at=split_at,
                           mark=mark_value,
                           until=lambda f: passed(f) if not tls12
                           else f.get("hello_done"))
            rows.append(res)
        trace[name] = [{"connected": r["connected"],
                        "passed": passed(r["flight"]) if not tls12
                        else trigger_passed(r["flight"], tls12=True),
                        "server_hello": r["flight"]["server_hello"],
                        "alert": r["flight"]["alert"],
                        "error": r["error"], "bytes": r["bytes"]}
                       for r in rows]
        return rows

    hello = build_client_hello(domain)
    base = _ask("base", hello)
    steps["connect"] = [r["connected"] for r in base]
    steps["base"] = [trigger_passed(r["flight"]) for r in base]

    if steps["base"] and all(steps["base"]) and check_tls12:
        rows = _ask("tls12", build_client_hello(domain, tls12=True),
                    tls12=True)
        steps["tls12"] = {
            "server_hello": all(r["flight"]["server_hello"] for r in rows),
            "complete": [r["flight"]["hello_done"] for r in rows],
        }
    elif any(steps["connect"]) and not any(steps["base"]):
        split = _ask("split", hello, split_at=1)
        steps["split"] = [trigger_passed(r["flight"]) for r in split]
        if not any(steps["split"]):
            control = _ask("control", build_client_hello(control_sni),
                           passed=control_passed)
            steps["control"] = [control_passed(r["flight"])
                                for r in control]

    verdict, reason = decide(steps, marked=bool(mark_value) or marked)
    if verdict not in (CLEAR, INCONCLUSIVE):
        log.info("DPI %s (%s): %s — %s" % (domain, ip, verdict, reason),
                 source="blockcheck")
    return _result(verdict, reason, ip)
