# core/blockcheck2.py
"""
Запуск штатного blockcheck из zapret2 (blockcheck2.sh / blockcheck.sh) с
потоковой телеметрией в GUI.

В отличие от core/blockcheck.py (наша Python-реализация проб), здесь мы
запускаем ОРИГИНАЛЬНЫЙ скрипт bol-van как подпроцесс и стримим его вывод
в лог-буфер и в кольцевой буфер строк, который UI забирает инкрементально
(GET /api/blockcheck2/output?offset=N).

Скрипт делается неинтерактивным через переменные окружения:
  BATCH=1, DOMAINS=..., IPVS=4|6|46, SCANLEVEL=quick|standard|force,
  ENABLE_HTTP, ENABLE_HTTPS_TLS12, ENABLE_HTTPS_TLS13, ENABLE_HTTP3,
  REPEATS, PARALLEL, SKIP_TPWS, SKIP_PKTWS, CURL_VERBOSE, …
stdin перенаправлен в /dev/null — оставшиеся `read` получают EOF и берут
значения по умолчанию.

Безопасность: подпроцесс запускается списком argv (без shell=True), env
передаётся словарём — shell-инъекция невозможна. Ключи/значения env и
домены дополнительно валидируются.

Использование:
    from core.blockcheck2 import get_blockcheck2_runner
    r = get_blockcheck2_runner()
    r.start(domains=["rutracker.org"], params={"IPVS": "4"})
    r.get_status()
    r.get_output(offset=0)
    r.stop()
"""

from __future__ import annotations

import os
import pty
import re
import signal
import subprocess
import threading
import time
from typing import Any, Optional

from core.log_buffer import log


# Кандидаты на скрипт (если не задан явно в конфиге).
_SCRIPT_CANDIDATES = ("blockcheck2.sh", "blockcheck.sh")

# Лимиты буфера вывода (строк) — телеметрия может быть многословной.
_MAX_OUTPUT_LINES = 5000

# Разрешённые имена env-переменных параметров (UPPER_SNAKE).
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

# Домен/хост (как в api/diagnostics._validate_host).
_HOST_RE = re.compile(r"^[a-zA-Z0-9.:_-]+$")

# Строки-«итоги» для приморозки сверху телеметрии. Примораживаем ТОЛЬКО
# найденные рабочие стратегии и заголовки секций итогов — а НЕ каждую попытку
# AVAILABLE/UNAVAILABLE (их сотни; вдобавок "AVAILABLE" — подстрока
# "UNAVAILABLE", из-за чего старый фильтр ловил мусор). blockcheck печатает
# найденную стратегию строкой вида:
#   !!!!! curl_test_http: working strategy found for ipv4 host : nfqws ... !!!!!
# и финальные секции «* SUMMARY» / «* COMMON» (стратегии, рабочие для всех целей).
_HIGHLIGHT_RE = re.compile(
    r"working\s+strategy\s+found|^\s*\*\s*(?:SUMMARY|COMMON)\b", re.I
)

# Структурный разбор строки найденной стратегии для бейджей в GUI. Формат
# (после чистки «!!!!!»):
#   <test>: working strategy found for ipv<N> <domain> : <engine> <strategy...>
# например: curl_test_https_tls13: working strategy found for ipv4 youtube.com
#           : nfqws2 --payload=tls_client_hello --lua-desync=fake:...
_FOUND_RE = re.compile(
    r"(?P<test>[\w.]+):\s*working\s+strategy\s+found\s+for\s+ipv(?P<ipv>[46])\s+"
    r"(?P<domain>\S+)\s*:\s*(?P<rest>.+)$",
    re.I,
)


def _classify_test(test: str) -> dict:
    """Тип теста blockcheck2 → протокол/порт/l7/payload (как ScanTarget) + метка.

    Используется для реконструкции стратегии из найденного приёма по конвенции
    проекта (SKILL §3): фильтр выводится из протокола/порта, который тест
    реально проверял.
    """
    t = test.lower()
    if "http3" in t or "quic" in t:
        return {"proto": "udp", "port": "443", "l7": "quic",
                "payload": "quic_initial", "label": "QUIC"}
    if "tls13" in t:
        return {"proto": "tcp", "port": "443", "l7": "tls",
                "payload": "tls_client_hello", "label": "TLS1.3"}
    if "tls12" in t:
        return {"proto": "tcp", "port": "443", "l7": "tls",
                "payload": "tls_client_hello", "label": "TLS1.2"}
    if "https" in t or "tls" in t:
        return {"proto": "tcp", "port": "443", "l7": "tls",
                "payload": "tls_client_hello", "label": "HTTPS"}
    # http / прочее
    return {"proto": "tcp", "port": "80", "l7": "http",
            "payload": "http_req", "label": "HTTP"}


def parse_found_strategy(clean_line: str) -> Optional[dict]:
    """Разобрать «working strategy found»-строку в структуру для GUI-бейджа.

    Возвращает None, если строка не подходит или в ней нет приёма (--…).
    `strategy` — дословный приём из blockcheck2 (payload + lua-desync) без
    ведущего токена-движка; фильтр/порт/l7 — из типа теста (`_classify_test`).
    """
    m = _FOUND_RE.search(clean_line)
    if not m:
        return None
    rest = m.group("rest").strip()
    idx = rest.find("--")
    if idx < 0:
        return None  # нет аргументов приёма — нечего реконструировать
    engine = rest[:idx].strip()
    strategy = rest[idx:].strip()
    if not strategy:
        return None
    info = _classify_test(m.group("test"))
    return {
        "ipv": int(m.group("ipv")),
        "test": m.group("test"),
        "domain": m.group("domain"),
        "engine": engine,
        "strategy": strategy,
        "proto": info["proto"],
        "port": info["port"],
        "l7": info["l7"],
        "payload": info["payload"],
        "label": info["label"],
    }


class Blockcheck2Runner:
    """Singleton-обёртка над оригинальным blockcheck-скриптом zapret2."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._master_fd: Optional[int] = None
        self._reader: Optional[threading.Thread] = None

        self._lines: list[str] = []
        self._highlights: list[str] = []
        self._highlight_seen: set[str] = set()
        self._found: list[dict] = []
        self._found_seen: set[tuple] = set()
        self._started_at: float = 0.0
        self._finished_at: float = 0.0
        self._exit_code: Optional[int] = None
        self._cmd: list[str] = []
        self._script: str = ""
        self._error: str = ""

    # ─────────────────── script discovery ───────────────────

    @staticmethod
    def find_script() -> Optional[str]:
        """Найти путь к blockcheck-скрипту: конфиг → кандидаты в base_path."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        explicit = cfg.get("zapret", "blockcheck2_path", default="")
        if explicit and os.path.isfile(explicit):
            return explicit

        base = cfg.get("zapret", "base_path", default="/opt/zapret2")
        search_dirs = [base, "/opt/zapret2", "/opt/zapret"]
        seen = set()
        for d in search_dirs:
            if not d or d in seen:
                continue
            seen.add(d)
            for name in _SCRIPT_CANDIDATES:
                cand = os.path.join(d, name)
                if os.path.isfile(cand):
                    return cand
        return None

    # ─────────────────── public API ───────────────────

    def is_running(self) -> bool:
        with self._lock:
            return self._is_running_locked()

    def _is_running_locked(self) -> bool:
        if self._proc is None:
            return False
        if self._proc.poll() is not None:
            return False
        return True

    def start(
        self,
        domains: Optional[list[str]] = None,
        params: Optional[dict[str, Any]] = None,
        extra_args: Optional[list[str]] = None,
        scanlevel: Optional[str] = None,
    ) -> dict[str, Any]:
        """Запустить blockcheck-скрипт.

        Args:
            domains:    домены для проверки (→ env DOMAINS, через пробел).
            params:     прочие env-переменные (IPVS, ENABLE_HTTP, REPEATS…).
            extra_args: дополнительные позиционные аргументы скрипта.
            scanlevel:  quick|standard|force (→ env SCANLEVEL).

        Returns:
            dict: { ok, error?, script?, cmd? }.
        """
        with self._lock:
            if self._is_running_locked():
                return {"ok": False, "error": "blockcheck уже выполняется"}

            script = self.find_script()
            if not script:
                return {
                    "ok": False,
                    "error": "Скрипт blockcheck не найден. Установите zapret2 "
                             "или задайте zapret.blockcheck2_path в конфиге.",
                }

            # Сборка env (неинтерактивный режим).
            env = dict(os.environ)
            env["BATCH"] = "1"
            # ZAPRET_BASE — каталог скрипта (он сам так делает, но зафиксируем).
            env.setdefault("ZAPRET_BASE", os.path.dirname(script))

            if scanlevel:
                sl = str(scanlevel).strip().lower()
                if sl not in ("quick", "standard", "force"):
                    return {"ok": False,
                            "error": "scanlevel: quick|standard|force"}
                env["SCANLEVEL"] = sl

            dom_list = self._clean_domains(domains)
            if dom_list:
                env["DOMAINS"] = " ".join(dom_list)

            if params:
                ok, err = self._apply_params(env, params)
                if not ok:
                    return {"ok": False, "error": err}

            # Команда: исполняемый скрипт (по shebang) либо через sh.
            if os.access(script, os.X_OK):
                cmd = [script]
            else:
                cmd = ["sh", script]

            clean_args = self._clean_extra_args(extra_args)
            cmd.extend(clean_args)

            # Старт. Вывод направляем в PTY, а не в обычный pipe: когда
            # stdout — не tty, libc в самом скрипте и его детях (curl,
            # nfqws2) переключается на блочную буферизацию, и строки
            # «working strategy found» доходят до нас только под конец —
            # список найденных стратегий в GUI наполняется лишь по
            # завершении всех тестов. PTY даёт isatty()==true →
            # построчная буферизация → находки стримятся в реальном
            # времени (issue: «выводить рабочую стратегию сразу же»).
            master_fd = None
            try:
                master_fd, slave_fd = pty.openpty()
                proc = subprocess.Popen(
                    cmd,
                    cwd=os.path.dirname(script),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid,  # своя группа — корректный kill
                    close_fds=True,
                )
                os.close(slave_fd)  # slave остаётся открытым у ребёнка
            except (OSError, ValueError) as e:
                # PTY недоступен — закрываем мастер и откатываемся на pipe.
                if master_fd is not None:
                    try:
                        os.close(master_fd)
                    except OSError:
                        pass
                    master_fd = None
                log.warning(
                    "PTY недоступен (%s), вывод blockcheck через pipe "
                    "(находки могут появляться с задержкой)" % e,
                    source="blockcheck2",
                )
                try:
                    proc = subprocess.Popen(
                        cmd,
                        cwd=os.path.dirname(script),
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        preexec_fn=os.setsid,
                        bufsize=1,
                        universal_newlines=True,
                    )
                except (OSError, ValueError) as e2:
                    self._error = str(e2)
                    log.error("Не удалось запустить blockcheck: %s" % e2,
                              source="blockcheck2")
                    return {"ok": False, "error": str(e2)}

            # Сброс состояния.
            self._proc = proc
            self._master_fd = master_fd
            self._lines = []
            self._highlights = []
            self._highlight_seen = set()
            self._found = []
            self._found_seen = set()
            self._started_at = time.time()
            self._finished_at = 0.0
            self._exit_code = None
            self._cmd = cmd
            self._script = script
            self._error = ""

            self._reader = threading.Thread(
                target=self._read_output, args=(proc, master_fd),
                daemon=True, name="blockcheck2-reader",
            )
            self._reader.start()

        log.info("Запущен blockcheck: %s (DOMAINS=%s, SCANLEVEL=%s)"
                 % (script, env.get("DOMAINS", "—"),
                    env.get("SCANLEVEL", "default")),
                 source="blockcheck2")
        return {"ok": True, "script": script, "cmd": cmd}

    def stop(self) -> bool:
        """Остановить выполняющийся blockcheck (SIGTERM группе, затем SIGKILL)."""
        with self._lock:
            if not self._is_running_locked():
                return False
            proc = self._proc

        log.info("Остановка blockcheck...", source="blockcheck2")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            return True

        for _ in range(30):
            if proc.poll() is not None:
                return True
            time.sleep(0.1)

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        return True

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            running = self._is_running_locked()
            if not running and self._proc is not None and self._exit_code is None:
                # Процесс завершился, но reader ещё не зафиксировал код.
                self._exit_code = self._proc.poll()
                if self._finished_at == 0.0:
                    self._finished_at = time.time()

            if running:
                elapsed = time.time() - self._started_at
            elif self._started_at:
                end = self._finished_at or time.time()
                elapsed = end - self._started_at
            else:
                elapsed = 0.0

            return {
                "running": running,
                "started": self._started_at > 0,
                "script": self._script,
                "cmd": list(self._cmd),
                "line_count": len(self._lines),
                "exit_code": self._exit_code,
                "elapsed_seconds": round(elapsed, 1),
                "error": self._error,
                "highlights": list(self._highlights[-50:]),
                "found": list(self._found[-50:]),
            }

    def get_output(self, offset: int = 0) -> dict[str, Any]:
        """Строки телеметрии начиная с offset (для инкрементального polling)."""
        with self._lock:
            total = len(self._lines)
            if offset < 0:
                offset = 0
            if offset > total:
                offset = total
            chunk = self._lines[offset:]
            return {
                "lines": chunk,
                "offset": offset,
                "next_offset": total,
                "running": self._is_running_locked(),
                "exit_code": self._exit_code,
            }

    # ─────────────────── internals ───────────────────

    def _read_output(self, proc: subprocess.Popen,
                     master_fd: Optional[int] = None) -> None:
        """Фоновое чтение вывода → лог-буфер + кольцевой буфер строк.

        master_fd != None → читаем из PTY-мастера (построчная буферизация,
        находки появляются в реальном времени). Иначе — фолбэк на
        proc.stdout (обычный pipe).
        """
        try:
            if master_fd is not None:
                self._read_from_fd(master_fd)
            else:
                for raw in proc.stdout:
                    self._handle_line(raw.rstrip("\n"))
        except Exception:
            pass
        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass
            else:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            rc = proc.wait()
            with self._lock:
                self._exit_code = rc
                self._finished_at = time.time()
            if rc == 0:
                log.success("blockcheck завершён (exit=0)", source="blockcheck2")
            else:
                log.warning("blockcheck завершён (exit=%s)" % rc,
                            source="blockcheck2")

    def _read_from_fd(self, fd: int) -> None:
        """Построчное чтение из PTY-мастера до EOF/EIO."""
        buf = b""
        while True:
            try:
                data = os.read(fd, 4096)
            except OSError:
                # На Linux чтение из мастера после закрытия slave даёт EIO.
                break
            if not data:
                break
            buf += data
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                line = buf[:nl].decode("utf-8", "replace").rstrip("\r")
                buf = buf[nl + 1:]
                self._handle_line(line)
        if buf:
            self._handle_line(buf.decode("utf-8", "replace").rstrip("\r"))

    def _handle_line(self, line: str) -> None:
        """Обработать одну строку вывода: буфер + highlight + found-разбор."""
        with self._lock:
            self._lines.append(line)
            if len(self._lines) > _MAX_OUTPUT_LINES:
                # Держим хвост; offset у клиента может «съехать», но
                # это лучше, чем неограниченный рост памяти.
                drop = len(self._lines) - _MAX_OUTPUT_LINES
                del self._lines[:drop]
            if line and _HIGHLIGHT_RE.search(line):
                # Чистим декоративные «!!!!!» и пробелы по краям, и
                # дедупим: одна и та же стратегия печатается и при
                # находке, и в секции SUMMARY/COMMON — в «примороженном»
                # списке нужна по разу.
                clean = line.strip().strip("!").strip()
                if clean and clean not in self._highlight_seen:
                    self._highlight_seen.add(clean)
                    self._highlights.append(clean)
                # Структурный разбор для кликабельных бейджей в GUI.
                found = parse_found_strategy(clean)
                if found:
                    key = (found["ipv"], found["test"],
                           found["domain"], found["strategy"])
                    if key not in self._found_seen:
                        self._found_seen.add(key)
                        self._found.append(found)
        if line:
            log.info(line, source="blockcheck2")

    @staticmethod
    def _clean_domains(domains) -> list[str]:
        """Отфильтровать/валидировать домены (защита, хотя shell не задействован)."""
        out: list[str] = []
        if not domains:
            return out
        if isinstance(domains, str):
            domains = re.split(r"[\s,]+", domains)
        for d in domains:
            d = str(d).strip()
            if d and len(d) <= 253 and _HOST_RE.match(d):
                out.append(d)
        return out

    @staticmethod
    def _apply_params(env: dict, params: dict) -> tuple[bool, str]:
        """Влить params в env с валидацией ключей/значений."""
        for key, val in params.items():
            k = str(key).strip()
            if not _ENV_KEY_RE.match(k):
                return False, "Недопустимое имя параметра: %r" % key
            if k in ("ZAPRET_BASE", "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
                     "IFS"):
                # Не даём переопределять чувствительное окружение.
                return False, "Параметр %s запрещён" % k
            v = "" if val is None else str(val)
            if "\x00" in v or len(v) > 1024:
                return False, "Недопустимое значение параметра %s" % k
            env[k] = v
        return True, ""

    @staticmethod
    def _clean_extra_args(extra_args) -> list[str]:
        """Привести extra_args к списку безопасных строк (без NUL)."""
        out: list[str] = []
        if not extra_args:
            return out
        for a in extra_args:
            s = str(a)
            if "\x00" in s or len(s) > 512:
                continue
            out.append(s)
        return out


# ─────────────────── singleton ───────────────────

_runner: Optional[Blockcheck2Runner] = None
_runner_lock = threading.Lock()


def get_blockcheck2_runner() -> Blockcheck2Runner:
    global _runner
    if _runner is None:
        with _runner_lock:
            if _runner is None:
                _runner = Blockcheck2Runner()
    return _runner
