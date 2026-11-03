# core/traffic_capture.py
"""
Снять короткий дамп трафика и разобрать его в поля.

Зачем. После nfqws2 пакет уже не тот, что был: его разрезали, подменили
TTL, дописали fake. Что именно ушло в сеть, изнутри GUI не видно
вовсе — а без этого подбор стратегии остаётся угадыванием («не
работает» против «не работает, потому что fake ушёл с TTL 3 и умер на
втором хопе»). Посмотреть это можно было ровно одним способом: выдать
модели ``shell_full`` (root на роутере) и позволить ей запустить
tcpdump. Несоразмерная цена за обратную связь.

Поэтому — отдельный слой с жёсткими рамками:

* **argv фиксирован.** Ни одной строки от модели в командной строке:
  интерфейс проверяется по ``/sys/class/net``, фильтр собирается ЗДЕСЬ
  из разобранных полей (``host``/``port``/``proto``), и всё это уезжает
  списком, без оболочки. Произвольное BPF-выражение не принимается: оно
  же и способ дописать ``-z`` с посторонней командой;
* **потолки** на число пакетов и время (``mcp.capture``). Число
  пакетов уезжает самому tcpdump (``-c``), то есть прогон кончится сам,
  даже если наш поток не доживёт; время держим мы — по его истечении
  процессу идёт TERM, и снятое всё равно разбирается;
* **снапшот короткий** (``-s``, по умолчанию 256 байт). Нам нужны
  заголовки и начало ClientHello, а не содержимое чужих соединений;
* **файл удаляется** сразу после разбора. На диске остаётся ноль
  (``mcp.capture.keep_file`` меняет это осознанно);
* наружу уезжает **разбор в поля**, а не дамп: направление, флаги, TTL,
  длина, SNI (см. :mod:`core.pcap_reader`).

Один прогон за раз. Дамп — это не то, что стоит запускать пачкой: два
tcpdump на одном интерфейсе роутера со 128 МБ RAM кончаются нехваткой
памяти, а не двумя дампами.
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from core.log_buffer import log


# Где искать tcpdump. Entware ставит его в /opt/sbin, OpenWrt — в
# /usr/sbin; PATH у GUI бывает урезанным, поэтому проверяем руками.
TCPDUMP_CANDIDATES = ("tcpdump", "/opt/sbin/tcpdump", "/usr/sbin/tcpdump",
                      "/usr/bin/tcpdump", "/opt/bin/tcpdump")

# Имя интерфейса: то же ограничение, что в core/routing/rules.py.
IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")

# Потолки, которые не поднимаются настройкой. Настройка может только
# опустить их: «снять 10 000 пакетов» — это уже не диагностика.
HARD_MAX_PACKETS = 1000
HARD_MAX_SECONDS = 120
HARD_MAX_SNAPLEN = 1500

# Сколько прогонов помним. Как у `_jobs.py`: завершённая задача обязана
# отвечать своим результатом, а не молчанием.
KEEP = 4


class CaptureError(ValueError):
    """Аргументы прогона не годятся — это ответ, а не исключение."""


class _Run:
    """Один прогон: параметры, процесс, результат разбора."""

    __slots__ = ("id", "params", "started_at", "finished_at", "running",
                 "error", "report", "argv", "proc", "stderr")

    def __init__(self, run_id, params, argv):
        self.id = run_id
        self.params = params
        self.argv = argv
        self.started_at = round(time.time(), 3)
        self.finished_at = 0.0
        self.running = True
        self.error = ""
        self.report = {}
        self.proc = None
        self.stderr = ""

    def snapshot(self) -> dict:
        return {
            "run_id": self.id,
            "running": self.running,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_sec": round((self.finished_at or time.time())
                                 - self.started_at, 2),
            "params": dict(self.params),
            "command": " ".join(self.argv),
            "error": self.error,
            "packets_captured": len(self.report.get("packets") or []),
        }


_lock = threading.Lock()
_runs = []                        # новые в конце


# ──────────────────────────── доступность ───────────────────────────

def binary() -> str:
    """Путь к tcpdump или ``""``."""
    for candidate in TCPDUMP_CANDIDATES:
        found = shutil.which(candidate) if "/" not in candidate else (
            candidate if os.access(candidate, os.X_OK) else "")
        if found:
            return found
    return ""


def available() -> dict:
    """Можно ли вообще снимать дамп на этом устройстве."""
    path = binary()
    if not path:
        return {
            "available": False,
            "reason": "tcpdump на устройстве нет",
            "hint": "поставьте его: package_install(name=\"tcpdump-mini\") "
                    "на Entware или \"tcpdump\" на OpenWrt",
        }
    return {"available": True, "binary": path}


def interfaces() -> list:
    """Сетевые интерфейсы устройства (по ``/sys/class/net``)."""
    try:
        return sorted(name for name in os.listdir("/sys/class/net")
                      if IFACE_RE.match(name))
    except OSError:
        return []


def default_iface() -> str:
    """Интерфейс default route — по нему уходит то, что нас интересует."""
    from core.firewall import _detect_wan_from_routes

    try:
        found = _detect_wan_from_routes()
    except Exception:                           # noqa: BLE001 — граница
        found = []
    return found[0] if found else ""


def limits() -> dict:
    """Потолки прогона: настройка, ужатая в жёсткие рамки модуля."""
    from core.mcp import auth

    try:
        cfg = auth.settings().get("capture") or {}
    except Exception:                           # noqa: BLE001 — граница
        cfg = {}
    return {
        "max_packets": _clamp(cfg.get("max_packets"), 200,
                              HARD_MAX_PACKETS),
        "max_seconds": _clamp(cfg.get("max_seconds"), 30, HARD_MAX_SECONDS),
        "snaplen": _clamp(cfg.get("snaplen"), 256, HARD_MAX_SNAPLEN),
        "keep_file": bool(cfg.get("keep_file")),
    }


# ───────────────────────────── прогон ───────────────────────────────

def start(*, iface: str = "", host: str = "", port=None, proto: str = "",
          packets: int = 0, seconds: int = 0) -> dict:
    """Запустить дамп фоном и вернуть его состояние.

    Возвращается сразу: дамп идёт секунды или десятки секунд, а
    синхронный вызов такой длины упирается в таймаут клиента. Результат
    забирают :func:`status` и :func:`result`.
    """
    info = available()
    if not info.get("available"):
        raise CaptureError(info.get("reason", "tcpdump недоступен"))

    current = latest()
    if current and current.running:
        raise CaptureError("дамп уже идёт (%s): дождитесь его или "
                           "остановите" % current.id)

    caps = limits()
    iface = _iface(iface)
    packets = _clamp(packets, caps["max_packets"], caps["max_packets"])
    seconds = _clamp(seconds, caps["max_seconds"], caps["max_seconds"])
    expression = _filter(host, port, proto)

    handle, path = tempfile.mkstemp(prefix="zapret-capture-", suffix=".pcap")
    os.close(handle)
    argv = [info["binary"], "-i", iface, "-nn", "-p",
            "-s", str(caps["snaplen"]), "-c", str(packets),
            "-U", "-w", path] + expression
    params = {
        "iface": iface, "host": host, "port": port, "proto": proto,
        "packets": packets, "seconds": seconds,
        "snaplen": caps["snaplen"],
        "filter": " ".join(expression),
    }

    run = _Run("capture-%s" % os.urandom(4).hex(), params, argv)
    with _lock:
        _runs.append(run)
        del _runs[:-KEEP]
    log.info("traffic_capture: %s" % " ".join(argv), source="capture")
    threading.Thread(target=_run, args=(run, path, seconds, caps),
                     name="traffic-capture", daemon=True).start()
    return run.snapshot()


def _run(run, path, seconds, caps):
    """Тело прогона: запустить tcpdump, дождаться, разобрать, убрать."""
    try:
        run.proc = subprocess.Popen(run.argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
    except OSError as e:
        run.error = "tcpdump не запустился: %s" % e
        run.running = False
        run.finished_at = round(time.time(), 3)
        _unlink(path)
        return

    try:
        _, stderr = run.proc.communicate(timeout=seconds)
        run.stderr = (stderr or b"").decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        # Истёк бюджет времени — это нормальный конец прогона, а не
        # сбой: сколько пакетов успели, столько и разберём.
        run.proc.terminate()
        try:
            _, stderr = run.proc.communicate(timeout=5)
            run.stderr = (stderr or b"").decode("utf-8", "replace").strip()
        except subprocess.TimeoutExpired:
            run.proc.kill()
    except Exception as e:                      # noqa: BLE001 — граница
        run.error = "%s: %s" % (type(e).__name__, e)

    # Ненулевой код возврата при НЕПУСТОМ файле — это обычный конец
    # прогона, прибитого по таймеру: пакеты сняты, разбирать есть что.
    # Ошибкой он становится, только когда снять ничего не удалось.
    code = run.proc.poll()
    size = os.path.getsize(path) if os.path.exists(path) else 0
    if code not in (0, None) and size <= 24:
        run.error = run.error or _tcpdump_error(run.stderr, code)

    try:
        from core import pcap_reader
        run.report = pcap_reader.read_file(
            path, limit=HARD_MAX_PACKETS,
            payloads=bool(caps.get("payloads")))
    except FileNotFoundError:
        run.error = run.error or "tcpdump не создал файл дампа"
    except Exception as e:                      # noqa: BLE001 — граница
        run.error = run.error or ("дамп не разобран: %s: %s"
                                  % (type(e).__name__, e))
    finally:
        if caps["keep_file"]:
            run.report["file"] = path
        else:
            _unlink(path)
        run.running = False
        run.finished_at = round(time.time(), 3)

    log.info("traffic_capture: %s — %d пакетов%s"
             % (run.id, len(run.report.get("packets") or []),
                (", ошибка: " + run.error) if run.error else ""),
             source="capture")


def capture_first(*, host: str, port: int, proto: str, packets: int = 16,
                  seconds: int = 20, iface: str = "any") -> dict:
    """Синхронно снять первые пакеты одного сервиса, с payload'ами.

    Для режима «Авто» geneva (``core/geneva_auto_observer``): протокол
    по первому пакету (WireGuard, OpenVPN, DHT, STUN, QUIC) и ``replay``
    conntrack не даёт. argv тот же фиксированный, что у :func:`start`;
    фильтр — адрес, порт и протокол из разобранных полей. Снапшот полный
    (QUIC Initial — 1200+ байт), потолки — жёсткие потолки модуля, а не
    настройки MCP. Файл удаляется всегда. Возвращает ``{"packets": […],
    "error": ""}``; занятый снифер — ``CaptureError``.
    """
    info = available()
    if not info.get("available"):
        raise CaptureError(info.get("reason", "tcpdump недоступен"))
    current = latest()
    if current and current.running:
        raise CaptureError("дамп уже идёт (%s)" % current.id)
    if not host or not _is_address(host) or "/" in host:
        raise CaptureError("host: нужен один IP")
    iface = "any" if iface == "any" else _iface(iface)
    packets = _clamp(packets, 16, 64)
    seconds = _clamp(seconds, 20, 60)
    expression = _filter(host, port, proto)
    caps = {"keep_file": False, "payloads": True,
            "snaplen": HARD_MAX_SNAPLEN}
    handle, path = tempfile.mkstemp(prefix="zapret-auto-", suffix=".pcap")
    os.close(handle)
    argv = [info["binary"], "-i", iface, "-nn", "-p",
            "-s", str(HARD_MAX_SNAPLEN), "-c", str(packets),
            "-U", "-w", path] + expression
    params = {"iface": iface, "host": host, "port": port, "proto": proto,
              "packets": packets, "seconds": seconds,
              "snaplen": HARD_MAX_SNAPLEN, "filter": " ".join(expression),
              "purpose": "geneva-auto"}
    run = _Run("capture-%s" % os.urandom(4).hex(), params, argv)
    with _lock:
        _runs.append(run)
        del _runs[:-KEEP]
    _run(run, path, seconds, caps)
    out = {"packets": packets_of(run), "error": run.error}
    # payload'ы чужих соединений не остаются в памяти прогона: его
    # снимок виден через MCP (capture_status).
    for item in (run.report or {}).get("packets") or []:
        item.pop("payload", None)
    return out


def packets_of(run) -> list:
    """Пакеты прогона копиями (с payload'ами, если их снимали)."""
    return [dict(p) for p in (run.report or {}).get("packets") or []]


def stop() -> dict:
    """Прибить идущий дамп; собранное остаётся читаемым."""
    run = latest()
    if run is None:
        raise CaptureError("дампов не запускалось")
    if not run.running:
        return dict(run.snapshot(), stopped=False,
                    note="этот дамп уже завершился")
    if run.proc is not None:
        run.proc.terminate()
    # Не ждём здесь: разбор доделает фоновый поток, а вызов обязан
    # вернуться сразу.
    return dict(run.snapshot(), stopped=True)


def latest():
    """Последний прогон или ``None``."""
    with _lock:
        return _runs[-1] if _runs else None


def get(run_id: str):
    """Прогон по id или ``None``."""
    with _lock:
        for run in _runs:
            if run.id == run_id:
                return run
    return None


def known_ids() -> list:
    with _lock:
        return [run.id for run in _runs]


def reset():
    """Забыть прогоны (нужно тестам)."""
    with _lock:
        _runs.clear()


def packets(run) -> list:
    """Разобранные пакеты прогона."""
    return list((run.report or {}).get("packets") or [])


def summary(run) -> dict:
    """Короткая сводка: по чему видно, что происходило.

    Считается здесь, а не в инструменте: то же самое понадобится UI,
    когда на странице появится кнопка «посмотреть трафик».
    """
    from core import pcap_reader

    out = pcap_reader.summarize(packets(run))
    out["captured_total"] = (run.report or {}).get("total", 0)
    return out


# ───────────────────────────── частности ────────────────────────────

def _filter(host: str, port, proto: str) -> list:
    """Собрать BPF-выражение из РАЗОБРАННЫХ полей, а не из строки.

    Каждый кусок проверен по своему шаблону, и в argv уезжают отдельные
    слова: ни кавычек, ни подстановки, ни способа дописать ``-z``.
    """
    parts = []
    proto = (proto or "").strip().lower()
    if proto:
        if proto not in ("tcp", "udp", "icmp"):
            raise CaptureError("proto: только tcp, udp или icmp")
        parts.append(proto)

    host = (host or "").strip()
    if host:
        if not _is_address(host):
            raise CaptureError(
                "host: нужен IP или подсеть (домен сначала разрешите — "
                "probe_targets покажет его адреса): «%s»" % host)
        parts.extend(["net" if "/" in host else "host", host])

    if port not in (None, "", 0):
        try:
            number = int(port)
        except (TypeError, ValueError):
            raise CaptureError("port: нужно число")
        if not 1 <= number <= 65535:
            raise CaptureError("port: 1..65535")
        parts.append("port")
        parts.append(str(number))

    # Склеиваем «and» между разнородными кусками — tcpdump ждёт
    # выражение, а не список условий.
    out = []
    for token in parts:
        if out and token in ("tcp", "udp", "icmp", "host", "net", "port"):
            out.append("and")
        out.append(token)
    return out


def _is_address(value: str) -> bool:
    import ipaddress

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _iface(name: str) -> str:
    """Интерфейс: проверенный по ``/sys/class/net``, иначе — default route."""
    value = (name or "").strip() or default_iface()
    if not value:
        raise CaptureError("не удалось определить интерфейс: задайте его "
                           "явно (какие есть — в поле interfaces)")
    if not IFACE_RE.match(value):
        raise CaptureError("недопустимое имя интерфейса «%s»" % name)
    known = interfaces()
    if known and value not in known:
        raise CaptureError("интерфейса «%s» нет; есть: %s"
                           % (value, ", ".join(known)))
    return value


def _clamp(value, default: int, maximum: int) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        number = 0
    if number <= 0:
        number = default
    return max(1, min(number, maximum))


def _tcpdump_error(stderr: str, code) -> str:
    """Понятная причина вместо кода возврата."""
    text = (stderr or "").strip().splitlines()
    last = text[-1] if text else ""
    if "permission" in last.lower() or "operation not permitted" in \
            last.lower():
        return ("tcpdump не пустили к интерфейсу: нужен root "
                "(%s)" % last)
    if "No such device" in last:
        return "интерфейса нет: %s" % last
    return last or "tcpdump вышел с кодом %s" % code


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass
