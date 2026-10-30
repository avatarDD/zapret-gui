# core/geneva_manager.py
"""
Менеджер geneva_c — второго движка обхода DPI на самом роутере.

geneva_c (avatarDD/geneva_c) — порт Geneva (Genetic Evasion) на C: один
статический бинарник ``geneva`` без зависимостей. Он умеет две вещи,
которые здесь и обёрнуты:

* ``geneva run`` — исполнять стратегию Geneva на живом трафике
  (NFQUEUE 310, свои правила nft/iptables, управляющий сокет);
* ``geneva evolve`` / ``geneva eval`` — подбирать стратегию генетическим
  алгоритмом или проверять готовые, с сохранением поиска (checkpoint) и
  базой оценок (JSONL).

Стратегии Geneva — свой язык (``[TCP:flags:PA]-fragment{...}-| \\/``), не
аргументы nfqws2: они не переводятся в ``--lua-desync`` и исполняются
только этим движком. Поэтому geneva — отдельный движок рядом с nfqws2, а
какой из двух обходит блокировки, решает ``core/bypass_engine``.

Где что лежит:

* настройки и рабочая стратегия — секция ``geneva`` в settings.json;
* постоянное состояние — ``<каталог конфига>/state/geneva/``: файл
  стратегии для ``run -f``, checkpoint поиска, база оценок и
  ``search.json`` (параметры и прогресс последнего поиска — по нему
  «Продолжить» работает и после перезагрузки роутера);
* живое — в ОЗУ (``/tmp/zapret-gui/geneva``): pid-файлы, управляющий
  сокет, события JSON Lines и лог. После перезагрузки процесса всё равно
  нет, а писать каждое событие на flash незачем.

Контракт с бинарником — ``docs/PROTOCOL.md`` geneva_c, версия ``proto`` 1.
Бинарник с другой версией протокола менеджер не запускает: гадать о
формате событий хуже, чем честно сказать «обновите geneva».

Правила firewall ставит и снимает сам geneva (SIGTERM — снять, SIGKILL —
оставить). Поэтому остановка — SIGTERM с ожиданием, а SIGKILL —
только если процесс не вышел, и после него ``geneva fw down`` с теми же
очередью и портами.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from collections import deque

from core.log_buffer import log


# Версия протокола событий и управляющего сокета, которую мы понимаем.
PROTO = 1

# Очереди NFQUEUE: nfqws2 держит 300–303, geneva run — 310, оценщик
# (evolve/eval) — 311. Так движки не делят одну очередь.
RUN_QUEUE = 310
EVAL_QUEUE = 311

# Метка пакетов, которые geneva отправляет сама: та же, что zapret-gui
# исключает из правил nfqws2 (docs/INTEGRATION.md geneva_c).
MARK = "0x20000000"

BINARY_CANDIDATES = (
    "/opt/usr/bin/geneva",
    "/opt/bin/geneva",
    "/opt/sbin/geneva",
    "/usr/bin/geneva",
    "/usr/sbin/geneva",
    "/usr/local/bin/geneva",
)

DEFAULT_RUNTIME_DIR = "/tmp/zapret-gui/geneva"

# Потолки файлов в ОЗУ: события и лог движка урезаются, когда вырастают
# больше этого (geneva открывает их с O_APPEND, обрезка безопасна).
MAX_EVENTS_BYTES = 512 * 1024
MAX_LOG_BYTES = 256 * 1024

# Сколько последних событий держать для ленты телеметрии.
FEED_SIZE = 200
# Сколько последних оценок стратегий показывать в поиске.
EVALS_SIZE = 30

# Коды возврата geneva (docs/PROTOCOL.md) человеческим языком.
EXIT_CODES = {
    0: "успешно",
    1: "ни одна стратегия не прошла",
    2: "неверные аргументы",
    3: "стратегия не разбирается",
    4: "нет прав или модулей ядра (NFQUEUE, raw-сокеты)",
    5: "правила firewall не применились",
    6: "ошибка ввода-вывода (файл, сокет)",
    7: "ресурс открывается и без обхода — подбирать нечего",
}

# Исходы пробы (docs/EVAL.md) человеческим языком.
OUTCOMES = {
    "ok": "прошла",
    "reset": "сброс соединения (RST)",
    "injected": "подмена ответа или страница блокировки",
    "connect_timeout": "соединение не установилось",
    "timeout": "соединение есть, ответа нет",
    "broken": "ответ неполный или не тот",
    "failed": "ошибка пробы",
}

# Пробы, которые предлагаем в интерфейсе. https — полная загрузка
# страницы curl'ом с локальных портов воркера (docs/EVAL.md: TLS-проба
# geneva не завершает рукопожатие, а успех должен быть полным обменом).
PROBES = ("tls", "http", "https")

LOG_LEVELS = ("error", "warn", "info", "debug", "trace")
FIREWALLS = ("auto", "nft", "iptables")
PROTOS = ("tcp", "udp", "tcp,udp")

# Границы параметров поиска: на слабом роутере большая популяция — это
# часы и сотни килобайт checkpoint'а.
SEARCH_LIMITS = {
    "population": (4, 500),
    "generations": (1, 500),
    "workers": (1, 8),
    "runs": (1, 5),
    "timeout": (2, 60),
}

SEARCH_DEFAULTS = {
    "probe": "tls",
    "host": "",
    "port": 0,
    "population": 30,
    "generations": 15,
    "workers": 1,
    "runs": 1,
    "timeout": 5,
    "pause_bypass": True,
}

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9._@-]{1,15}$")

MAX_STRATEGY_LEN = 4096


# ───────────────────────────── пути ─────────────────────────────────

def state_dir() -> str:
    """Постоянное состояние geneva: рядом с settings.json."""
    from core.platform_dirs import config_dir
    return os.path.join(config_dir(), "state", "geneva")


def runtime_dir() -> str:
    """Живое состояние в ОЗУ (сокет, pid, события, лог)."""
    return os.environ.get("ZAPRET_GUI_GENEVA_RUNTIME") or DEFAULT_RUNTIME_DIR


def paths() -> dict:
    """Все файлы движка одним словарём — для аргументов и для тестов."""
    st, rt = state_dir(), runtime_dir()
    return {
        "state": st,
        "runtime": rt,
        "strategy": os.path.join(st, "strategy.txt"),
        "checkpoint": os.path.join(st, "search.ckpt"),
        "db": os.path.join(st, "db.jsonl"),
        "search": os.path.join(st, "search.json"),
        "candidates": os.path.join(st, "candidates.txt"),
        "socket": os.path.join(rt, "geneva.sock"),
        "run_pid": os.path.join(rt, "run.pid"),
        "run_events": os.path.join(rt, "run-events.jsonl"),
        "run_log": os.path.join(rt, "run.log"),
        "run_args": os.path.join(rt, "run.args.json"),
        "job_pid": os.path.join(rt, "job.pid"),
        "job_events": os.path.join(rt, "job-events.jsonl"),
        "job_log": os.path.join(rt, "job.log"),
    }


def _write_atomic(path: str, text: str) -> None:
    """tmp + fsync + rename: на роутере питание пропадает когда угодно."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# ─────────────────────── проверка настроек ──────────────────────────

def _as_bool(value, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off", ""):
            return False
    raise ValueError("%s: ожидается true/false" % field)


def _as_int(value, field: str, lo: int, hi: int) -> int:
    if isinstance(value, bool):
        raise ValueError("%s: ожидается целое число" % field)
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("%s: ожидается целое число" % field)
    if not lo <= n <= hi:
        raise ValueError("%s: допустимо %d..%d" % (field, lo, hi))
    return n


def normalize_ports(value) -> str:
    """``80, 443`` → ``80,443``; диапазоны ``8000-8100``; порт 1..65535."""
    s = re.sub(r"\s+", "", str(value or ""))
    if not s or not _PORTS_RE.match(s):
        raise ValueError("Порты: ожидается список вида 80,443 или "
                         "8000-8100")
    for part in s.split(","):
        bounds = [int(x) for x in part.split("-")]
        if any(not 1 <= p <= 65535 for p in bounds):
            raise ValueError("Порты: допустимо 1..65535")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError("Порты: диапазон %s задом наперёд" % part)
    return s


def check_strategy_text(text) -> str:
    """Первичная проверка строки стратегии до вызова ``geneva check``.

    Стратегия — одна строка: перевод строки в файле стратегии сделал бы
    из неё две, а geneva читает только первую.
    """
    s = str(text or "").strip()
    if not s:
        raise ValueError("Стратегия не задана")
    if "\n" in s or "\r" in s:
        raise ValueError("Стратегия — одна строка")
    if len(s) > MAX_STRATEGY_LEN:
        raise ValueError("Стратегия длиннее %d символов" % MAX_STRATEGY_LEN)
    # Разделитель лесов «\/» необязателен: в библиотеке Geneva стратегии
    # без входящего леса записаны и без него, geneva check его допишет.
    if not s.startswith("[") and not s.startswith("\\/"):
        raise ValueError("Стратегия Geneva начинается с триггера "
                         "«[TCP:flags:PA]…»")
    return s


def validate_settings(data: dict) -> dict:
    """Проверить и нормализовать настройки ``geneva`` (частичный PUT).

    Возвращает только переданные ключи. ``ValueError`` — с текстом для
    человека: кривые порты иначе всплыли бы только кодом 2 при запуске.
    """
    clean = {}
    if "ports" in data:
        clean["ports"] = normalize_ports(data["ports"])
    if "proto" in data:
        proto = str(data["proto"] or "").strip().lower().replace(" ", "")
        if proto not in PROTOS:
            raise ValueError("Протокол: tcp, udp или tcp,udp")
        clean["proto"] = proto
    if "iface" in data:
        iface = str(data["iface"] or "").strip()
        if iface and not _IFACE_RE.match(iface):
            raise ValueError("Некорректное имя интерфейса: %s" % iface)
        clean["iface"] = iface
    if "firewall" in data:
        fw = str(data["firewall"] or "").strip().lower()
        if fw not in FIREWALLS:
            raise ValueError("Firewall: auto, nft или iptables")
        clean["firewall"] = fw
    if "log_level" in data:
        lvl = str(data["log_level"] or "").strip().lower()
        if lvl not in LOG_LEVELS:
            raise ValueError("Уровень лога: %s" % ", ".join(LOG_LEVELS))
        clean["log_level"] = lvl
    if "first" in data:
        clean["first"] = _as_int(data["first"], "Первые N пакетов", 0, 1000)
    if "autostart" in data:
        clean["autostart"] = _as_bool(data["autostart"], "autostart")
    # ``binary`` сюда намеренно не входит: путь к программе, которую GUI
    # запускает от root, не меняется по HTTP — только в settings.json.
    return clean


def validate_search(data: dict, base: dict = None) -> dict:
    """Параметры поиска поверх сохранённых (``geneva.search``)."""
    out = dict(SEARCH_DEFAULTS)
    out.update(base or {})
    data = data or {}
    if "probe" in data:
        out["probe"] = str(data["probe"] or "").strip().lower()
    if out["probe"] not in PROBES:
        raise ValueError("Проба: %s" % ", ".join(PROBES))
    if "host" in data:
        out["host"] = str(data["host"] or "").strip().lower()
    host = out["host"]
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/", 1)[0].rstrip(".")
    if not host or not _HOST_RE.match(host) or ".." in host:
        raise ValueError("Укажите заблокированный сайт (домен), "
                         "например rutracker.org")
    out["host"] = host
    if "port" in data:
        out["port"] = data["port"]
    port = out.get("port") or 0
    out["port"] = 0 if port in ("", None, 0, "0") else \
        _as_int(port, "Порт", 1, 65535)
    for key, (lo, hi) in SEARCH_LIMITS.items():
        if key in data:
            out[key] = data[key]
        out[key] = _as_int(out[key], key, lo, hi)
    if "pause_bypass" in data:
        out["pause_bypass"] = data["pause_bypass"]
    out["pause_bypass"] = _as_bool(out["pause_bypass"], "pause_bypass")
    return out


def search_target(params: dict) -> str:
    """Профиль цели в базе оценок: результаты разных сайтов не мешаются."""
    return "%s:%s" % (params.get("probe", "tls"), params.get("host", ""))


# ─────────────────────── сборка аргументов ──────────────────────────

def build_run_args(binary: str, settings: dict, p: dict) -> list:
    """argv ``geneva run`` из настроек: один источник для UI, MCP и boot."""
    args = [binary, "run",
            "-f", p["strategy"],
            "-p", normalize_ports(settings.get("ports") or "80,443"),
            "--proto", settings.get("proto") or "tcp",
            "-q", str(int(settings.get("queue") or RUN_QUEUE)),
            "--mark", MARK,
            "--firewall", settings.get("firewall") or "auto",
            "-c", "unix:" + p["socket"],
            "-e", p["run_events"],
            "--stats-interval", "30",
            "-l", settings.get("log_level") or "info",
            "--log-file", p["run_log"],
            "--quiet"]
    iface = (settings.get("iface") or "").strip()
    if iface:
        args += ["-i", iface]
    first = int(settings.get("first") or 0)
    if first > 0:
        args += ["--first", str(first)]
    return args


def fw_down_args(binary: str, run_args: list) -> list:
    """``geneva fw down`` с теми же очередью, портами и firewall, что у run.

    Нужен только после SIGKILL: geneva снимает правила сам на любом
    выходе, кроме убийства.
    """
    keep = {"-p", "--proto", "-q", "--firewall", "-i", "--mark"}
    out = [binary, "fw", "down"]
    i = 2
    while i < len(run_args):
        a = run_args[i]
        if a in keep and i + 1 < len(run_args):
            out += [a, run_args[i + 1]]
            i += 2
            continue
        i += 1
    return out


def _probe_args(params: dict) -> list:
    probe = params["probe"]
    host = params["host"]
    port = int(params.get("port") or 0)
    if probe == "https":
        url = "https://%s%s/" % (host, (":%d" % port) if port else "")
        cmd = ("curl -sf -o /dev/null --max-time %d --local-port {lports} %s"
               % (int(params["timeout"]) + 5, url))
        return ["--probe", "exec", "--cmd", cmd,
                "--timeout", str(int(params["timeout"]) + 10)]
    args = ["--probe", probe, "--host", host,
            "--timeout", str(int(params["timeout"]))]
    if port:
        args += ["--port", str(port)]
    return args


def build_evolve_args(binary: str, params: dict, p: dict,
                      resume: bool = False) -> list:
    """argv ``geneva evolve`` с checkpoint и базой в постоянном каталоге."""
    args = [binary, "evolve"] + _probe_args(params) + [
        "--population", str(params["population"]),
        "--generations", str(params["generations"]),
        "--workers", str(params["workers"]),
        "--runs", str(params["runs"]),
        "-q", str(EVAL_QUEUE),
        "--mark", MARK,
        "--checkpoint", p["checkpoint"],
        "--db", p["db"],
        "--target", search_target(params),
        "-e", p["job_events"],
        "--log-file", p["job_log"],
        "--quiet"]
    if resume:
        args.append("--resume")
    return args


def build_eval_args(binary: str, params: dict, p: dict) -> list:
    """argv ``geneva eval`` для списка стратегий (файл ``candidates``)."""
    return [binary, "eval"] + _probe_args(params) + [
        "-f", p["candidates"],
        "--workers", str(params["workers"]),
        "--runs", str(params["runs"]),
        "-q", str(EVAL_QUEUE),
        "--mark", MARK,
        "-e", p["job_events"],
        "--log-file", p["job_log"],
        "--quiet"]


# ─────────────────────── события и телеметрия ───────────────────────

def parse_event(line: str):
    """Строка JSON Lines → событие или ``None`` (мусор и чужие строки)."""
    line = (line or "").strip()
    if not line.startswith("{"):
        return None
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    if not isinstance(ev, dict) or not isinstance(ev.get("ev"), str):
        return None
    return ev


def outcome_text(outcome: str) -> str:
    return OUTCOMES.get(outcome or "", outcome or "—")


def exit_text(code) -> str:
    try:
        return EXIT_CODES.get(int(code), "код %s" % code)
    except (TypeError, ValueError):
        return "код %s" % code


def _short(strategy: str, limit: int = 90) -> str:
    s = str(strategy or "")
    return s if len(s) <= limit else s[:limit - 1] + "…"


def describe_event(ev: dict, total_generations: int = 0):
    """Событие → ``(уровень, текст)`` для ленты телеметрии или ``None``.

    Уровни — как у остальной ленты GUI: ``info``, ``ok``, ``warn``,
    ``error``. ``stats`` и ``eval`` в ленту не идут: первые — это
    счётчики карточки, вторые — таблица оценок, иначе они бы заслонили
    всё остальное.
    """
    kind = ev.get("ev")
    if kind == "start":
        mode = ev.get("mode")
        if mode == "run":
            return ("info", "Движок запущен: очередь %s, порты %s"
                    % (ev.get("queue", "?"), ev.get("ports", "?")))
        if mode == "evolve":
            if ev.get("resume"):
                return ("info", "Подбор продолжен с сохранённого места")
            return ("info", "Подбор запущен: популяция %s, поколений %s"
                    % (ev.get("population", "?"),
                       ev.get("generations", "?")))
        return ("info", "Запуск geneva (%s)" % (mode or "?"))
    if kind == "ready":
        fw = ev.get("firewall") or "?"
        return ("ok", "Перехват включён: правила %s стоят, пакеты идут "
                      "через geneva" % fw)
    if kind == "strategy":
        return ("info", "Стратегия установлена: %s"
                % _short(ev.get("strategy")))
    if kind == "state":
        return ("warn" if ev.get("state") == "paused" else "info",
                "Движок на паузе: пакеты идут без изменений"
                if ev.get("state") == "paused" else "Движок снят с паузы")
    if kind == "baseline":
        if ev.get("blocked"):
            return ("info", "Проверка без обхода: ресурс заблокирован (%s)"
                    " — ищем стратегию" % outcome_text(ev.get("outcome")))
        return ("warn", "Проверка без обхода: ресурс открывается — "
                        "подбирать нечего")
    if kind == "generation":
        gen = int(ev.get("gen", 0)) + 1
        of = (" из %d" % total_generations) if total_generations else ""
        best = ev.get("best_fitness")
        return ("ok" if (best or 0) > 0 else "info",
                "Поколение %d%s: лучший фитнес %s, средний %s, "
                "уникальных стратегий %s"
                % (gen, of, best, ev.get("avg_fitness"),
                   ev.get("unique")))
    if kind == "result":
        best = [b for b in (ev.get("best") or [])
                if (b.get("avg_fitness") or 0) > 0]
        if best:
            return ("ok", "Подбор закончен: рабочих стратегий — %d, лучшая "
                          "с фитнесом %s" % (len(best),
                                              best[0].get("avg_fitness")))
        return ("warn", "Подбор закончен: рабочих стратегий не нашлось")
    if kind == "error":
        return ("error", "Ошибка (%s): %s" % (ev.get("where", "?"),
                                             ev.get("message", "")))
    if kind == "exit":
        code = ev.get("code", 0)
        reason = ev.get("reason", "")
        reasons = {"signal": "остановлен", "control": "остановлен командой",
                   "duration": "истекло время", "error": "ошибка",
                   "done": "закончил", "not_blocked": "ресурс не "
                   "заблокирован"}
        level = "info" if code in (0, None) or reason in (
            "signal", "control") else "warn"
        return (level, "geneva завершился: %s (%s)"
                % (reasons.get(reason, reason or "—"), exit_text(code)))
    if kind == "dropped":
        return ("warn", "Потеряно событий: %s" % ev.get("count"))
    return None


def fitness_verdict(fitness) -> str:
    """Фитнес — число, а человеку нужно «работает или нет»."""
    try:
        f = float(fitness)
    except (TypeError, ValueError):
        return "unknown"
    return "works" if f > 0 else "fails"


class EventReader:
    """Инкрементальное чтение файла событий с запоминанием смещения.

    Файл в ОЗУ урезается (geneva пишет с O_APPEND), поэтому смещение
    больше размера означает «файл начали заново» — читаем с нуля.
    """

    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self._partial = ""

    def reset(self):
        self.offset = 0
        self._partial = ""

    def read_new(self) -> list:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.offset:
            self.reset()
        if size == self.offset:
            return []
        try:
            with open(self.path, "r", encoding="utf-8",
                      errors="replace") as f:
                f.seek(self.offset)
                chunk = f.read()
                self.offset = f.tell()
        except OSError:
            return []
        text = self._partial + chunk
        lines = text.split("\n")
        self._partial = lines.pop()       # недописанная строка — потом
        out = []
        for line in lines:
            ev = parse_event(line)
            if ev is not None:
                out.append(ev)
        return out


def trim_file(path: str, limit: int) -> bool:
    """Обнулить файл в ОЗУ, если он перерос ``limit`` (O_APPEND у писателя)."""
    try:
        if os.path.getsize(path) > limit:
            with open(path, "r+b") as f:
                f.truncate(0)
            return True
    except OSError:
        pass
    return False


def tail_lines(path: str, lines: int = 100) -> list:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    return data.splitlines()[-max(1, lines):]


# ─────────────────────── управляющий сокет ──────────────────────────

class ControlError(RuntimeError):
    """Сокет недоступен или ответ не пришёл."""


def control_request(sock_path: str, cmd: str, timeout: float = 2.0,
                    **params) -> dict:
    """Один запрос в управляющий сокет ``geneva run`` (построчный JSON).

    Ответ отличается от события полем ``ok``; события (если кто-то
    подписал это соединение) пропускаем, сверяя ``id``.
    """
    if not hasattr(socket, "AF_UNIX"):
        raise ControlError("unix-сокеты недоступны на этой платформе")
    req = dict(params)
    req["id"] = 1
    req["cmd"] = cmd
    payload = (json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(sock_path)
            s.sendall(payload)
        except OSError as e:
            raise ControlError("сокет %s: %s" % (sock_path, e))
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            except OSError as e:
                raise ControlError("чтение ответа: %s" % e)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if isinstance(msg, dict) and "ok" in msg and \
                        msg.get("id") in (1, None):
                    return msg
        raise ControlError("geneva не ответил на «%s»" % cmd)
    finally:
        try:
            s.close()
        except OSError:
            pass


# ─────────────────────────── процессы ───────────────────────────────

def _read_pid(path: str):
    try:
        with open(path) as f:
            v = f.read().strip()
        return int(v) if v.isdigit() else None
    except OSError:
        return None


def _write_pid(path: str, pid: int) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(str(pid))
    except OSError:
        pass


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _pid_cmdline(pid: int) -> str:
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def pid_alive(pid, subcommand: str = "") -> bool:
    """Жив ли процесс и наш ли он (geneva с нужной подкомандой).

    Без сверки cmdline pid-файл из ОЗУ мог бы указать на чужой процесс,
    получивший тот же номер после падения geneva.
    """
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError:
        return False
    # Зомби (наш же потомок, ещё не прибранный) — уже не работает.
    try:
        with open("/proc/%d/stat" % pid) as f:
            if ") Z" in f.read(512):
                return False
    except OSError:
        pass
    cmd = _pid_cmdline(pid)
    if not cmd.strip():
        return True                      # /proc нет — верим pid'у
    words = cmd.split()
    if not words or "geneva" not in os.path.basename(words[0]):
        return False
    return not subcommand or (len(words) > 1 and words[1] == subcommand)


def _spawn(args: list, log_path: str) -> subprocess.Popen:
    """Запустить отдельным сеансом: процесс переживает перезапуск GUI."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    out = open(log_path, "ab")
    try:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out,
                                stderr=subprocess.STDOUT,
                                start_new_session=True, close_fds=True)
    finally:
        out.close()


def _terminate(pid: int, subcommand: str, wait: float = 10.0) -> bool:
    """SIGTERM и ожидание; True — процесс вышел сам (правила сняты)."""
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.time() + wait
    while time.time() < deadline:
        _reap(pid)
        if not pid_alive(pid, subcommand):
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _reap(pid)
    return False


def _reap(pid: int) -> None:
    """Прибрать зомби своего потомка (после перезапуска GUI — не наш)."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass


# ─────────────────────────── менеджер ───────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def run_settings(cfg=None) -> dict:
    """Настройки ``geneva run`` из settings.json с умолчаниями."""
    cfg = cfg or _cfg()

    def g(key, default):
        return cfg.get("geneva", key, default=default)

    return {
        "binary": g("binary", ""),
        "strategy": g("strategy", ""),
        "strategy_source": g("strategy_source", ""),
        "ports": g("ports", "80,443"),
        "proto": g("proto", "tcp"),
        "iface": g("iface", ""),
        "queue": g("queue", RUN_QUEUE),
        "firewall": g("firewall", "auto"),
        "first": g("first", 0),
        "log_level": g("log_level", "info"),
        "autostart": g("autostart", False),
    }


class GenevaManager:
    """Синглтон: движок ``geneva run`` и задачи подбора/проверки."""

    def __init__(self):
        self._lock = threading.RLock()
        self._version_cache = {}
        self._library_cache = None
        self._run_proc = None
        self._job_proc = None
        self._run_reader = None
        self._run_feed = deque(maxlen=FEED_SIZE)
        self._run_last_stats = {}
        self._job_reader = None
        self._job_feed = deque(maxlen=FEED_SIZE)
        self._job_evals = deque(maxlen=EVALS_SIZE)
        self._job_state = {}
        self._monitor = None
        self._monitor_stop = threading.Event()
        self._fw_checked = 0.0
        # Правила видели хоть раз с этого запуска: только тогда их
        # пропажа — повод перезапускать (иначе вечный перезапуск там,
        # где проверить правила нельзя).
        self._fw_seen = False

    # ─────── бинарник ───────

    def find_binary(self) -> str:
        configured = str(_cfg().get("geneva", "binary", default="") or "")
        for p in ((configured,) if configured else ()) + BINARY_CANDIDATES:
            if p and os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        found = shutil.which("geneva")
        return found or ""

    def version_info(self, binary: str = "") -> dict:
        """``geneva version --json`` с кэшем по mtime/размеру файла."""
        binary = binary or self.find_binary()
        if not binary:
            return {}
        try:
            st = os.stat(binary)
            key = (binary, int(st.st_mtime), st.st_size)
        except OSError:
            key = (binary, 0, 0)
        cached = self._version_cache.get(key)
        if cached is not None:
            return cached
        try:
            r = subprocess.run([binary, "version", "--json"],
                               capture_output=True, text=True, timeout=5,
                               stdin=subprocess.DEVNULL)
            info = json.loads((r.stdout or "").strip() or "{}")
        except (OSError, subprocess.SubprocessError, ValueError):
            return {}
        if not isinstance(info, dict) or "proto" not in info:
            return {}
        self._version_cache = {key: info}
        return info

    def detect(self) -> dict:
        binary = self.find_binary()
        if not binary:
            return {"installed": False, "binary": "", "version": "",
                    "proto_ok": False,
                    "hint": "geneva не установлен: кнопка «Установить» "
                            "скачает сборку из релиза avatarDD/geneva_c"}
        info = self.version_info(binary)
        proto = info.get("proto")
        out = {"installed": True, "binary": binary,
               "version": info.get("version", ""), "proto": proto,
               "arch": info.get("arch", ""),
               "features": info.get("features") or [],
               "proto_ok": proto == PROTO}
        if not info:
            out["hint"] = "бинарник не отвечает на «geneva version --json»"
        elif proto != PROTO:
            out["hint"] = ("версия протокола %s, а zapret-gui понимает %d: "
                           "обновите geneva или zapret-gui" % (proto, PROTO))
        elif "nfqueue" not in out["features"]:
            out["hint"] = "сборка без NFQUEUE: движок на этой системе не "\
                          "заработает"
        return out

    def _ready_binary(self):
        """(binary, error): бинарник, с которым можно работать."""
        det = self.detect()
        if not det["installed"]:
            return "", "geneva не установлен"
        if not det["proto_ok"]:
            return "", det.get("hint") or "несовместимый geneva"
        return det["binary"], ""

    # ─────── разовые команды ───────

    def _run_cmd(self, args: list, timeout: int = 20, stdin: str = None):
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=timeout, input=stdin,
                                  stdin=None if stdin is not None
                                  else subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return None
        except OSError as e:
            log.warning("geneva: %s" % e, source="geneva")
            return None

    def check_strategy(self, strategy: str) -> dict:
        """``geneva check --json``: разбор и каноническая форма."""
        try:
            s = check_strategy_text(strategy)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        binary, err = self._ready_binary()
        if not binary:
            return {"ok": False, "error": err}
        r = self._run_cmd([binary, "check", "--json", s], timeout=10)
        if r is None:
            return {"ok": False, "error": "geneva check не ответил"}
        try:
            data = json.loads((r.stdout or "").strip() or "{}")
        except ValueError:
            data = {}
        if r.returncode == 0 and data.get("ok"):
            return {"ok": True, "strategy": data.get("strategy", s),
                    "actions": data.get("actions", 0)}
        msg = data.get("error") or (r.stderr or r.stdout or "").strip()
        return {"ok": False, "error": "Стратегия не разбирается: %s"
                                      % (msg.splitlines()[-1][:300]
                                         if msg else exit_text(r.returncode))}

    def library(self, refresh: bool = False) -> dict:
        """Готовые стратегии Geneva (``geneva library --json``)."""
        if self._library_cache is not None and not refresh:
            return {"ok": True, "items": self._library_cache}
        binary, err = self._ready_binary()
        if not binary:
            return {"ok": False, "error": err, "items": []}
        r = self._run_cmd([binary, "library", "--json"], timeout=10)
        try:
            items = json.loads(r.stdout) if r and r.returncode == 0 else None
        except ValueError:
            items = None
        if not isinstance(items, list):
            return {"ok": False, "error": "geneva library не ответил",
                    "items": []}
        # «Без стратегии» (\/) — эталон из статьи, применять его нечего.
        items = [i for i in items if isinstance(i, dict)
                 and str(i.get("strategy", "")).strip() not in ("\\/", "")]
        self._library_cache = items
        return {"ok": True, "items": items}

    def db_top(self, target: str = "", limit: int = 10) -> dict:
        """Лучшие стратегии из базы оценок (``geneva db top --json``)."""
        p = paths()
        if not os.path.isfile(p["db"]):
            return {"ok": True, "items": []}
        binary, err = self._ready_binary()
        if not binary:
            return {"ok": False, "error": err, "items": []}
        args = [binary, "db", "--db", p["db"], "top", "-n",
                str(max(1, min(int(limit or 10), 50))), "--json"]
        if target:
            args += ["--target", target]
        r = self._run_cmd(args, timeout=15)
        if r is None or r.returncode != 0:
            return {"ok": False, "items": [],
                    "error": "geneva db не ответил"}
        return {"ok": True, "items": parse_db_lines(r.stdout)}

    # ─────── движок geneva run ───────

    def _run_pid(self):
        pid = _read_pid(paths()["run_pid"])
        if pid and pid_alive(pid, "run"):
            return pid
        return None

    def is_running(self) -> bool:
        return self._run_pid() is not None

    def start(self, strategy: str = "") -> dict:
        """Поднять ``geneva run`` с рабочей (или переданной) стратегией."""
        with self._lock:
            if self.is_running():
                return {"ok": False, "error": "geneva уже запущен",
                        "running": True}
            if self.job_running():
                return {"ok": False, "error": "идёт подбор или проверка "
                        "стратегий — дождитесь окончания или остановите"}
            # Рядом с работающим nfqws2 не поднимаемся: каждый пакет
            # прошёл бы через оба движка. Выбор движка — core/bypass_engine
            # (он ставит geneva активным ДО вызова start).
            from core.bypass_engine import is_geneva_active
            if not is_geneva_active():
                return {"ok": False, "error_code": "engine_nfqws2",
                        "error": "Обход сейчас идёт через nfqws2",
                        "hint": "выберите geneva_c движком обхода — "
                                "nfqws2 при этом остановится"}
            binary, err = self._ready_binary()
            if not binary:
                return {"ok": False, "error": err}
            settings = run_settings()
            strategy = strategy or settings["strategy"]
            if not strategy:
                return {"ok": False, "error": "Не выбрана стратегия: "
                        "возьмите её из библиотеки или найдите подбором"}
            chk = self.check_strategy(strategy)
            if not chk.get("ok"):
                return chk
            p = paths()
            try:
                _write_atomic(p["strategy"], chk["strategy"] + "\n")
                os.makedirs(p["runtime"], exist_ok=True)
            except OSError as e:
                return {"ok": False, "error": "Файл стратегии: %s" % e}
            try:
                args = build_run_args(binary, settings, p)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
            # Правила от убитого процесса (SIGKILL, обрыв питания при
            # живом /tmp не бывает, но kill -9 — бывает) убираем заранее.
            self._fw_down(binary, args)
            for path in (p["run_events"],):
                trim_file(path, 0)
            self._run_reader = EventReader(p["run_events"])
            self._run_feed.clear()
            self._run_last_stats = {}
            self._fw_seen = False
            self._fw_checked = 0.0
            try:
                proc = _spawn(args, p["run_log"])
            except OSError as e:
                return {"ok": False, "error": "Запуск geneva: %s" % e}
            self._run_proc = proc
            _write_pid(p["run_pid"], proc.pid)
            try:
                _write_atomic(p["run_args"], json.dumps(args))
            except OSError:
                pass
            ready = self._wait_ready(proc, timeout=6.0)
            if proc.poll() is not None:
                _remove(p["run_pid"])
                tail = " | ".join(tail_lines(p["run_log"], 3))
                return {"ok": False,
                        "error": "geneva завершился при запуске: %s%s"
                                 % (exit_text(proc.returncode),
                                    (" — " + tail) if tail else "")}
            log.success("geneva: движок запущен (pid %d)" % proc.pid,
                        source="geneva")
            self._ensure_monitor()
            return {"ok": True, "pid": proc.pid, "ready": ready,
                    "strategy": chk["strategy"]}

    def _wait_ready(self, proc, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._pump_run()
            if any(e.get("ev") == "ready" for e in self._run_feed_raw()):
                return True
            if proc.poll() is not None:
                return False
            time.sleep(0.2)
        return False

    def _run_feed_raw(self):
        return [item["raw"] for item in self._run_feed if "raw" in item]

    def _fw_down(self, binary: str, run_args: list) -> None:
        r = self._run_cmd(fw_down_args(binary, run_args), timeout=15)
        if r is not None and r.returncode not in (0,):
            log.debug("geneva fw down: %s" % (r.stderr or "").strip(),
                      source="geneva")

    def stop(self) -> dict:
        """SIGTERM: geneva снимает свои правила сам. SIGKILL — fw down."""
        with self._lock:
            p = paths()
            pid = self._run_pid()
            if not pid:
                _remove(p["run_pid"])
                return {"ok": True, "running": False, "note": "не был запущен"}
            clean = _terminate(pid, "run")
            if not clean:
                binary = self.find_binary()
                try:
                    with open(p["run_args"]) as f:
                        run_args = json.load(f)
                except (OSError, ValueError):
                    run_args = []
                if binary and run_args:
                    self._fw_down(binary, run_args)
                log.warning("geneva не вышел по SIGTERM — убит, правила "
                            "сняты через geneva fw down", source="geneva")
            _remove(p["run_pid"])
            self._run_proc = None
            self._pump_run()
            log.info("geneva: движок остановлен", source="geneva")
            return {"ok": True, "running": False, "forced": not clean}

    def restart(self) -> dict:
        # Под замком: иначе между stop и start успеет чужой start/switch.
        with self._lock:
            self.stop()
            return self.start()

    def control(self, cmd: str, **params) -> dict:
        """Команда в управляющий сокет живого движка."""
        if not self.is_running():
            return {"ok": False, "error": "geneva не запущен"}
        try:
            return control_request(paths()["socket"], cmd, **params)
        except ControlError as e:
            return {"ok": False, "error": str(e)}

    def set_strategy(self, strategy: str, source: str = "manual",
                     apply: bool = True) -> dict:
        """Сохранить рабочую стратегию; у живого движка — без перезапуска.

        ``set_strategy`` в сокет меняет стратегию, не роняя соединений;
        ошибка разбора оставляет прежнюю — тогда и в настройки не пишем.
        """
        chk = self.check_strategy(strategy)
        if not chk.get("ok"):
            return chk
        canon = chk["strategy"]
        applied = False
        if apply and self.is_running():
            res = self.control("set_strategy", strategy=canon)
            if not res.get("ok"):
                return {"ok": False, "error": "geneva не принял стратегию: "
                        "%s" % res.get("error", "?")}
            applied = True
        cfg = _cfg()
        cfg.set("geneva", "strategy", canon)
        cfg.set("geneva", "strategy_source", str(source or "manual")[:40])
        cfg.save()
        try:
            _write_atomic(paths()["strategy"], canon + "\n")
        except OSError:
            pass
        return {"ok": True, "strategy": canon, "applied_live": applied}

    def _pump_run(self) -> None:
        """Дочитать события движка в ленту и запомнить последние stats."""
        p = paths()
        if self._run_reader is None:
            self._run_reader = EventReader(p["run_events"])
        for ev in self._run_reader.read_new():
            if ev.get("ev") == "stats":
                self._run_last_stats = ev
                continue
            d = describe_event(ev)
            if d:
                self._run_feed.append({"ts": ev.get("ts"), "level": d[0],
                                       "text": d[1], "raw": ev})
        if trim_file(p["run_events"], MAX_EVENTS_BYTES):
            self._run_reader.reset()
        trim_file(p["run_log"], MAX_LOG_BYTES)

    def status(self) -> dict:
        """Карточка движка: процесс, стратегия, счётчики, лента событий."""
        with self._lock:
            self._pump_run()
            settings = run_settings()
            pid = self._run_pid()
            out = {
                "running": bool(pid),
                "pid": pid,
                "strategy": settings["strategy"],
                "strategy_source": settings["strategy_source"],
                "ports": settings["ports"],
                "proto": settings["proto"],
                "queue": settings["queue"],
                "autostart": bool(settings["autostart"]),
                "events": [{"ts": e["ts"], "level": e["level"],
                            "text": e["text"]}
                           for e in list(self._run_feed)[-40:]],
            }
            stats = {}
            if pid:
                st = self.control("status", timeout=1.5)
                if st.get("ok"):
                    out["state"] = st.get("state")
                    out["firewall"] = st.get("firewall")
                    out["uptime_ms"] = st.get("uptime_ms")
                    out["live_strategy"] = st.get("strategy")
                    sres = self.control("stats", timeout=1.5)
                    if sres.get("ok"):
                        stats = sres
                else:
                    out["control_error"] = st.get("error")
            if not stats and self._run_last_stats:
                stats = self._run_last_stats
            if stats:
                out["stats"] = summarize_stats(stats)
            return out

    def read_log(self, lines: int = 200, which: str = "run") -> dict:
        p = paths()
        path = p["job_log"] if which == "job" else p["run_log"]
        return {"ok": True, "lines": tail_lines(path, max(1, min(lines,
                                                                 2000)))}

    # ─────── подбор и проверка (evolve / eval) ───────

    def _job_pid(self):
        pid = _read_pid(paths()["job_pid"])
        if pid and (pid_alive(pid, "evolve") or pid_alive(pid, "eval")):
            return pid
        return None

    def job_running(self) -> bool:
        return self._job_pid() is not None

    def search_state(self) -> dict:
        """``search.json``: параметры и итог последнего поиска."""
        return _read_json(paths()["search"])

    def _save_search_state(self, state: dict) -> None:
        try:
            _write_atomic(paths()["search"],
                          json.dumps(state, ensure_ascii=False, indent=1))
        except OSError as e:
            log.warning("geneva: search.json не записан: %s" % e,
                        source="geneva")

    def can_resume(self) -> bool:
        st = self.search_state()
        return (st.get("kind") == "evolve"
                and st.get("status") in ("interrupted", "stopped")
                and os.path.isfile(paths()["checkpoint"])
                and bool(st.get("params")))

    def can_extend(self) -> bool:
        """Законченный поиск можно продлить: ``--generations`` при
        ``--resume`` разрешено увеличивать (docs/EVOLVE.md), в хэш
        параметров checkpoint'а число поколений не входит."""
        st = self.search_state()
        return (st.get("kind") == "evolve" and st.get("status") == "done"
                and os.path.isfile(paths()["checkpoint"])
                and bool(st.get("params")))

    def start_search(self, params: dict = None, resume: bool = False,
                     more_generations: int = 0) -> dict:
        """Запустить ``geneva evolve`` (или продолжить сохранённый поиск)."""
        with self._lock:
            if self.job_running():
                return {"ok": False, "error": "подбор уже идёт"}
            saved = self.search_state()
            if resume:
                extend = more_generations > 0 and self.can_extend()
                if not self.can_resume() and not extend:
                    return {"ok": False, "error": "нечего продолжать: "
                            "сохранённого поиска нет или он закончен "
                            "(законченный можно продлить more_generations)"}
                params = dict(saved["params"])
                if more_generations:
                    params["generations"] = min(
                        SEARCH_LIMITS["generations"][1],
                        int(params["generations"]) + int(more_generations))
            else:
                try:
                    base = _cfg().get("geneva", "search", default={}) or {}
                    params = validate_search(params or {}, base)
                except ValueError as e:
                    return {"ok": False, "error": str(e)}
            binary, err = self._ready_binary()
            if not binary:
                return {"ok": False, "error": err}
            if params["probe"] == "https" and not shutil.which("curl"):
                return {"ok": False, "error": "для пробы https нужен curl "
                        "(opkg install curl) — или выберите tls"}
            p = paths()
            if not resume:
                # Новый поиск — новый checkpoint; база оценок остаётся:
                # она засевает популяцию лучшими находками той же цели.
                _remove(p["checkpoint"])
                cfg = _cfg()
                cfg.set("geneva", "search", {k: params[k]
                                             for k in SEARCH_DEFAULTS})
                cfg.save()
            args = build_evolve_args(binary, params, p, resume=resume)
            state = {
                "kind": "evolve", "status": "running", "params": params,
                "started_at": time.time(), "finished_at": None,
                "resumed": bool(resume), "gen": saved.get("gen", -1)
                if resume else -1,
                "best_fitness": saved.get("best_fitness") if resume else None,
                "best": saved.get("best", "") if resume else "",
                "results": [], "exit_code": None,
                "target": search_target(params),
                # Обход, остановленный прошлым прогоном, к этому времени
                # уже возвращён (_finish_job/recover_on_boot): ставим
                # паузу заново.
                "paused_engine": "",
            }
            return self._launch_job(args, state, params)

    def start_eval(self, strategies: list, params: dict = None) -> dict:
        """Проверить список готовых стратегий (``geneva eval -f``)."""
        with self._lock:
            if self.job_running():
                return {"ok": False, "error": "подбор или проверка уже идёт"}
            items = []
            for s in strategies or []:
                try:
                    items.append(check_strategy_text(s))
                except ValueError:
                    continue
            if not items:
                return {"ok": False, "error": "нет стратегий для проверки"}
            items = items[:64]
            try:
                base = _cfg().get("geneva", "search", default={}) or {}
                params = validate_search(params or {}, base)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
            binary, err = self._ready_binary()
            if not binary:
                return {"ok": False, "error": err}
            if params["probe"] == "https" and not shutil.which("curl"):
                return {"ok": False, "error": "для пробы https нужен curl "
                        "(opkg install curl) — или выберите tls"}
            p = paths()
            try:
                _write_atomic(p["candidates"], "\n".join(items) + "\n")
            except OSError as e:
                return {"ok": False, "error": "Список стратегий: %s" % e}
            args = build_eval_args(binary, params, p)
            state = {"kind": "eval", "status": "running", "params": params,
                     "started_at": time.time(), "finished_at": None,
                     "total": len(items), "results": [], "exit_code": None,
                     "target": search_target(params), "paused_engine": ""}
            return self._launch_job(args, state, params)

    def _launch_job(self, args: list, state: dict, params: dict) -> dict:
        p = paths()
        paused = ""
        if params.get("pause_bypass", True) and not state.get(
                "paused_engine"):
            try:
                from core.bypass_engine import pause_for_search
                paused = pause_for_search()
            except Exception as e:                  # noqa: BLE001
                log.warning("geneva: обход не приостановлен: %s" % e,
                            source="geneva")
                paused = ""
            if paused == "busy":
                return {"ok": False, "error": "движок nfqws2 занят другой "
                        "операцией (подбор, blockcheck) — дождитесь её"}
            state["paused_engine"] = paused
        trim_file(p["job_events"], 0)
        trim_file(p["job_log"], 0)
        self._job_reader = EventReader(p["job_events"])
        self._job_feed.clear()
        self._job_evals.clear()
        try:
            proc = _spawn(args, p["job_log"])
        except OSError as e:
            self._restore_paused(state)
            return {"ok": False, "error": "Запуск geneva: %s" % e}
        self._job_proc = proc
        _write_pid(p["job_pid"], proc.pid)
        state["pid"] = proc.pid
        self._job_state = state
        self._save_search_state(state)
        log.info("geneva: %s запущен (pid %d), цель %s"
                 % ("подбор" if state["kind"] == "evolve" else "проверка",
                    proc.pid, state["target"]), source="geneva")
        self._ensure_monitor()
        return {"ok": True, "pid": proc.pid, "kind": state["kind"],
                "paused_engine": state.get("paused_engine", ""),
                "params": params}

    def stop_search(self) -> dict:
        """SIGTERM: evolve сохраняет checkpoint и выходит после шага."""
        with self._lock:
            pid = self._job_pid()
            if not pid:
                return {"ok": True, "note": "подбор не идёт"}
            sub = "evolve" if pid_alive(pid, "evolve") else "eval"
            st = self._job_state or self.search_state()
            # Ставим «остановлен» до сигнала: монитор, увидевший выход,
            # не должен принять его за прерывание.
            st["stop_requested"] = True
            self._job_state = st
            self._save_search_state(st)
        # Ждём выхода (до 30 с) без замка: иначе опрос статуса страницы
        # и MCP висит дольше своего таймаута.
        clean = _terminate(pid, sub, wait=30.0)
        with self._lock:
            # Монитор мог уже дописать итог (или запустили новую задачу):
            # повторный _finish_job превратил бы «остановлен» в «готово».
            if self._job_state is st and st.get("status") == "running":
                self._finish_job(None if clean else -9)
            return {"ok": True, "forced": not clean,
                    "can_resume": self.can_resume()}

    def _pump_job(self) -> None:
        if self._job_reader is None:
            self._job_reader = EventReader(paths()["job_events"])
        st = self._job_state
        changed = False
        total = int((st.get("params") or {}).get("generations") or 0)
        for ev in self._job_reader.read_new():
            kind = ev.get("ev")
            if kind == "eval":
                self._job_evals.append({
                    "strategy": ev.get("strategy", ""),
                    "fitness": ev.get("fitness"),
                    "outcome": ev.get("outcome", ""),
                    "outcome_text": outcome_text(ev.get("outcome")),
                    "detail": str(ev.get("detail") or "")[:200],
                    "verdict": fitness_verdict(ev.get("fitness")),
                })
                if st.get("kind") == "eval":
                    st.setdefault("results", []).append({
                        "strategy": ev.get("strategy", ""),
                        "avg_fitness": ev.get("fitness"),
                        "runs": ev.get("runs", 1),
                        "outcome": ev.get("outcome", "")})
                    st["done"] = len(st["results"])
                    changed = True
                continue
            if kind == "generation":
                st["gen"] = int(ev.get("gen", 0))
                st["best_fitness"] = ev.get("best_fitness")
                st["avg_fitness"] = ev.get("avg_fitness")
                st["best"] = ev.get("best", "")
                changed = True
            elif kind == "baseline":
                st["baseline"] = {"blocked": bool(ev.get("blocked")),
                                  "outcome": ev.get("outcome", ""),
                                  "detail": str(ev.get("detail") or "")[:200]}
                changed = True
            elif kind == "result":
                st["results"] = [
                    {"strategy": b.get("strategy", ""),
                     "avg_fitness": b.get("avg_fitness"),
                     "runs": b.get("runs")}
                    for b in (ev.get("best") or [])][:20]
                changed = True
            elif kind == "exit":
                st["exit_code"] = ev.get("code")
                st["exit_reason"] = ev.get("reason", "")
            d = describe_event(ev, total)
            if d:
                self._job_feed.append({"ts": ev.get("ts"), "level": d[0],
                                       "text": d[1]})
        if changed and st:
            self._save_search_state(st)

    def _finish_job(self, rc) -> None:
        """Процесс задачи вышел: итог в search.json, обход — обратно."""
        p = paths()
        self._pump_job()
        st = self._job_state or self.search_state()
        if not st:
            return
        code = st.get("exit_code")
        if code is None:
            code = rc
        st["exit_code"] = code
        st["finished_at"] = time.time()
        if st.get("stop_requested"):
            st["status"] = "stopped"
        elif code == 0:
            st["status"] = "done"
        elif code == 7:
            st["status"] = "not_blocked"
        elif code == 1:
            # Ни одна стратегия не прошла — прогон закончен честно.
            st["status"] = "done"
        elif code is None or code == -9:
            st["status"] = "interrupted"
        else:
            st["status"] = "error"
            # Код выхода говорит «что», последняя строка лога — «почему»
            # («cannot resolve host», «no NFQUEUE support»…).
            tail = [line for line in tail_lines(p["job_log"], 5)
                    if line.strip()]
            st["error"] = exit_text(code) + (
                " — " + tail[-1].strip()[:300] if tail else "")
        st.pop("stop_requested", None)
        st.pop("pid", None)
        self._restore_paused(st)
        self._save_search_state(st)
        _remove(p["job_pid"])
        self._job_proc = None
        log.info("geneva: %s закончен — %s"
                 % ("подбор" if st.get("kind") == "evolve" else "проверка",
                    st["status"]), source="geneva")

    def _restore_paused(self, st: dict) -> None:
        engine = st.get("paused_engine")
        if not engine or st.get("restored"):
            return
        try:
            from core.bypass_engine import resume_after_search
            resume_after_search(engine)
            st["restored"] = True
        except Exception as e:                      # noqa: BLE001
            log.warning("geneva: обход не возвращён после подбора: %s" % e,
                        source="geneva")

    def search_status(self) -> dict:
        """Прогресс поиска для страницы и MCP."""
        with self._lock:
            pid = self._job_pid()
            if not self._job_state:
                self._job_state = self.search_state()
            if pid:
                self._pump_job()
            elif self._job_state.get("status") == "running":
                # GUI перезапускали, а процесс за это время закончил (или
                # роутер перезагрузили): итог дочитываем из событий.
                self._finish_job(None)
            st = dict(self._job_state)
            params = st.get("params") or {}
            gens = int(params.get("generations") or 0)
            gen_done = int(st.get("gen", -1)) + 1
            out = {
                "running": bool(pid),
                "kind": st.get("kind", ""),
                "status": st.get("status", "idle") if st else "idle",
                "params": params,
                "target": st.get("target", ""),
                "started_at": st.get("started_at"),
                "finished_at": st.get("finished_at"),
                "generation": gen_done,
                "generations": gens,
                "percent": int(100 * gen_done / gens) if gens and
                st.get("kind") == "evolve" else (
                    int(100 * int(st.get("done") or 0) /
                        max(1, int(st.get("total") or 1)))
                    if st.get("kind") == "eval" else 0),
                "best_fitness": st.get("best_fitness"),
                "best": st.get("best", ""),
                "baseline": st.get("baseline"),
                "results": st.get("results") or [],
                "exit_code": st.get("exit_code"),
                "exit_text": exit_text(st["exit_code"])
                if st.get("exit_code") is not None else "",
                "error": st.get("error", ""),
                "paused_engine": st.get("paused_engine", ""),
                "can_resume": self.can_resume() and not pid,
                "can_extend": self.can_extend() and not pid,
                "events": list(self._job_feed)[-40:],
                "evals": list(self._job_evals),
            }
            if st.get("kind") == "eval":
                out["done"] = int(st.get("done") or 0)
                out["total"] = int(st.get("total") or 0)
            return out

    def forget_search(self) -> dict:
        """Забыть сохранённый поиск (checkpoint и search.json)."""
        with self._lock:
            if self.job_running():
                return {"ok": False, "error": "сначала остановите подбор"}
            p = paths()
            for key in ("checkpoint", "search", "candidates"):
                _remove(p[key])
            self._job_state = {}
            self._job_feed.clear()
            self._job_evals.clear()
            return {"ok": True}

    # ─────── фоновый присмотр ───────

    def _ensure_monitor(self) -> None:
        if self._monitor and self._monitor.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor = threading.Thread(target=self._monitor_loop,
                                         daemon=True, name="geneva-monitor")
        self._monitor.start()

    def _monitor_loop(self) -> None:
        """Пока что-то работает: события, конец задачи, правила firewall."""
        while not self._monitor_stop.wait(2.0):
            try:
                with self._lock:
                    job_pid = self._job_pid()
                    if job_pid:
                        self._pump_job()
                    elif self._job_state.get("status") == "running":
                        rc = self._job_proc.poll() if self._job_proc else None
                        self._finish_job(rc)
                    run_pid = self._run_pid()
                    if run_pid:
                        self._pump_run()
                        self._check_firewall()
                    if not job_pid and not run_pid:
                        return
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva monitor: %s" % e, source="geneva")

    def _check_firewall(self) -> None:
        """Keenetic и fw3/fw4 сносят чужие правила — тогда перезапуск.

        Раз в 30 с: правила geneva видны по таблице ``inet geneva_<q>``
        (nft) или переходу в цепочку ``GENEVA_<q>_OUT`` (iptables).
        Перезапуск — то же, что делает хук ``010-geneva.sh`` апстрима.
        """
        now = time.time()
        if now - self._fw_checked < 30:
            return
        self._fw_checked = now
        present = rules_present(int(run_settings().get("queue") or RUN_QUEUE))
        if present:
            self._fw_seen = True
            return
        if present is None or not self._fw_seen:
            return
        log.warning("geneva: правила перехвата пропали (пересборка "
                    "firewall системой) — перезапускаю движок",
                    source="geneva")
        self.stop()
        self.start()

    def recover_on_boot(self) -> None:
        """Старт GUI: подхватить живые процессы и дописать итог поиска."""
        with self._lock:
            st = self.search_state()
            if st:
                self._job_state = st
            if self.job_running() or self.is_running():
                self._ensure_monitor()
            elif st.get("status") == "running":
                self._finish_job(None)
            elif st.get("paused_engine") and not st.get("restored"):
                self._restore_paused(st)
                self._save_search_state(st)


def summarize_stats(stats: dict) -> dict:
    """Счётчики ``stats`` → карточка: что видно человеку сразу."""
    keys = ("uptime_ms", "paused", "pkts_out", "pkts_in", "triggered",
            "accepted", "modified", "dropped", "injected", "delayed",
            "pending", "send_errors", "verdict_errors", "parse_errors",
            "overruns")
    out = {k: stats.get(k) for k in keys if k in stats}
    errors = sum(int(stats.get(k) or 0) for k in (
        "send_errors", "verdict_errors", "parse_errors", "overruns"))
    out["errors"] = errors
    trees = []
    for direction in ("out_trees", "in_trees"):
        for t in stats.get(direction) or []:
            if isinstance(t, dict):
                trees.append({"dir": "out" if direction == "out_trees"
                              else "in", "tree": t.get("tree", ""),
                              "fired": int(t.get("fired") or 0)})
    out["trees"] = trees
    pkts = int(stats.get("pkts_out") or 0) + int(stats.get("pkts_in") or 0)
    if not pkts:
        out["verdict"] = "no_traffic"
    elif not int(stats.get("triggered") or 0):
        out["verdict"] = "not_firing"
    else:
        out["verdict"] = "working"
    return out


def parse_db_lines(text: str) -> list:
    """Вывод ``geneva db top --json`` (JSONL) → строки для таблицы."""
    items = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not row.get("s"):
            continue
        runs = int(row.get("runs") or 0)
        ok = int(row.get("ok") or 0)
        items.append({
            "strategy": row["s"],
            "target": row.get("t", ""),
            "runs": runs,
            "ok": ok,
            "success_rate": round(ok / runs, 3) if runs else 0.0,
            "avg_fitness": round(float(row.get("fit_sum") or 0) / runs, 1)
            if runs else 0.0,
            "best_fitness": row.get("fit_best"),
            "last_ok": row.get("last_ok"),
        })
    return items


def rules_present(queue: int):
    """Стоят ли правила geneva: True / False / None (не проверить)."""
    if shutil.which("nft"):
        try:
            r = subprocess.run(["nft", "list", "table", "inet",
                                "geneva_%d" % queue], capture_output=True,
                               timeout=5, stdin=subprocess.DEVNULL)
            if r.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("iptables"):
        try:
            r = subprocess.run(["iptables", "-t", "mangle", "-C",
                                "POSTROUTING", "-j",
                                "GENEVA_%d_OUT" % queue],
                               capture_output=True, timeout=5,
                               stdin=subprocess.DEVNULL)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return None
    return None if not shutil.which("nft") else False


_instance = None
_instance_lock = threading.Lock()


def get_geneva_manager() -> GenevaManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = GenevaManager()
    return _instance
