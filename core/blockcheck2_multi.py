# core/blockcheck2_multi.py
"""
Мульти-доменный blockcheck2: несколько доменов параллельно, ранняя
остановка по числу рабочих стратегий и сборка общей стратегии.

Вкладка «Подбор стратегий → Несколько доменов». Работает на клоне
штатного blockcheck2.sh (``core/blockcheck2_patch``), а не на нашей
Python-реализации проб: тесты, приёмы и вердикты — те же, что у
официальной вкладки.

Отличия от ``core/blockcheck2`` (официальная вкладка, один процесс):

* Домены идут не по очереди внутри одного скрипта, а копиями скрипта —
  по одной на группу доменов, до ``concurrency`` одновременно.
  Копии не мешают друг другу: цепочки iptables, таблицы nft, номера
  NFQUEUE и временные файлы в blockcheck2.sh уникальны по ``$$``, а
  iptables в клоне ждёт xtables-лок (``-w``).
* Домены с общими IP-адресами в одну группу: правила перехвата
  blockcheck2 матчат по адресу назначения, и две копии на одном IP
  делили бы трафик — стратегия одной проверялась бы трафиком другой.
  Группа идёт одной копией, домены в ней — по очереди, как в оригинале.
* ``stop_after`` (GUI_STOP_AFTER): набрав N рабочих стратегий на тест,
  копия бросает оставшиеся варианты этого теста. «Рабочая» — успешны
  все попытки REPEATS (при REPEATS=3 — 3/3).
* На время проверки обход GUI снимается (``core/nfqws_session``,
  владелец ``blockcheck``) и затем возвращается «как было»: трафик
  самого роутера идёт через те же POSTROUTING-правила, и проверка шла
  бы поверх уже работающей стратегии.

Использование:
    from core.blockcheck2_multi import get_multi_runner
    r = get_multi_runner()
    r.start(domains=["a.com", "b.com"], concurrency=2, stop_after=3)
    r.get_status(); r.get_output("a.com", offset=0); r.stop()
"""

from __future__ import annotations

import os
import pty
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Optional

from core.log_buffer import log
from core.blockcheck2 import (Blockcheck2Runner, _ENV_KEY_RE, _HOST_RE,
                              parse_found_strategy)


MAX_DOMAINS = 32
MAX_CONCURRENCY = 4
DEFAULT_CONCURRENCY = 2
MAX_STOP_AFTER = 20
_MAX_JOB_LINES = 3000

# Анонс проверяемой стратегии (как в web/js/pages/blockcheck2.js):
#   - curl_test_https_tls12 ipv4 youtube.com : nfqws2 --payload=… --lua-desync=…
_ANNOUNCE_RE = re.compile(
    r"^-\s+(?P<test>\S+)\s+ipv(?P<ipv>[46])\s+(?P<domain>\S+)\s*:\s*"
    r"(?P<engine>\S+)\s+(?P<strategy>--.+)$")
_ATTEMPT_RE = re.compile(r"^\[attempt\s+(\d+)\]", re.I)
# «* zapret-gui: <test> ipvN <domain> : набрано … — … пропущены»
_SKIP_RE = re.compile(
    r"^\*\s*zapret-gui:\s+(?P<test>\S+)\s+ipv(?P<ipv>[46])\s+"
    r"(?P<domain>\S+)\s*:.*пропущены")

# Параметры, которыми вкладка управляет сама.
_RESERVED_ENV = ("DOMAINS", "BATCH", "GUI_STOP_AFTER", "ZAPRET_BASE",
                 "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "IFS")


# ─────────────────────── чистые функции ───────────────────────

def split_domains(raw) -> list:
    """Домены из текста (по строкам/пробелам/запятым) или списка.

    Нормализует регистр, отбрасывает схему/путь (вставили URL) и мусор,
    убирает повторы, сохраняя порядок.
    """
    if isinstance(raw, (list, tuple)):
        tokens = []
        for x in raw:
            tokens.extend(re.split(r"[\s,;]+", str(x or "")))
    else:
        tokens = re.split(r"[\s,;]+", str(raw or ""))
    out = []
    for t in tokens:
        t = t.strip().lower()
        t = re.sub(r"^[a-z]+://", "", t).split("/", 1)[0].strip(".")
        if t and len(t) <= 253 and _HOST_RE.match(t) and t not in out:
            out.append(t)
    return out


def group_by_ips(domains, ips: dict) -> list:
    """Сгруппировать домены с пересекающимися IP (union-find).

    ``ips`` — {домен: set(адресов)}. Домен без адресов — сам по себе
    (blockcheck2 ему всё равно скажет «does not resolve»). Порядок групп и
    доменов внутри — как во входном списке.
    """
    parent = {d: d for d in domains}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner = {}
    for d in domains:
        for ip in ips.get(d) or ():
            if ip in owner:
                ra, rb = find(owner[ip]), find(d)
                if ra != rb:
                    parent[rb] = ra
            else:
                owner[ip] = d
    groups = {}
    order = []
    for d in domains:
        r = find(d)
        if r not in groups:
            groups[r] = []
            order.append(r)
        groups[r].append(d)
    return [groups[r] for r in order]


def resolve_ips(domain: str, timeout: float = 3.0) -> set:
    """Адреса домена системным резолвером (для группировки)."""
    out = set()
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        for info in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP):
            out.add(info[4][0])
    except (OSError, UnicodeError):
        pass
    finally:
        socket.setdefaulttimeout(old)
    return out


class LineParser:
    """Разбор потокового вывода одной копии blockcheck2 в находки.

    Блок стратегии: анонс «- test ipvN domain : nfqws2 …», затем попытки
    «[attempt N] AVAILABLE|…» и вердикт «!!!!! AVAILABLE !!!!!» или
    «UNAVAILABLE…». Находка — блок хотя бы с одной удачной попыткой;
    ``full`` — успешны все (тот же расчёт, что у бейджей официальной
    вкладки). Так видна и частичная успешность (2/3), которую сам
    blockcheck2 рабочей не считает.
    """

    def __init__(self):
        self.cur = None
        self.found = []
        self._seen = set()
        self.tests = {}          # test -> {"domain","ipv","tried","skipped"}
        self.current = ""

    def feed(self, line: str) -> Optional[dict]:
        """Обработать строку; вернуть новую находку или None."""
        s = str(line or "").rstrip()
        m = _ANNOUNCE_RE.match(s)
        if m:
            added = self._finalize()
            self.cur = {
                "test": m.group("test"), "ipv": int(m.group("ipv")),
                "domain": m.group("domain").lower(),
                "engine": m.group("engine"),
                "strategy": _norm(m.group("strategy")),
                "attempt_max": 0, "ok": 0, "full": False,
            }
            key = (self.cur["test"], self.cur["ipv"], self.cur["domain"])
            t = self.tests.setdefault(key, {"tried": 0, "skipped": False})
            t["tried"] += 1
            self.current = "%s ipv%d %s" % key
            return added
        sk = _SKIP_RE.match(s)
        if sk:
            key = (sk.group("test"), int(sk.group("ipv")),
                   sk.group("domain").lower())
            self.tests.setdefault(key, {"tried": 0, "skipped": False})
            self.tests[key]["skipped"] = True
            return None
        if not self.cur:
            # «working strategy found» вне блока — итоговая строка; блоки
            # её уже дали, но страхуемся (REPEATS=1 и т.п.).
            f = parse_found_strategy(s.strip().strip("!").strip())
            if f:
                f.update(ok=1, total=1, full=True)
                return self._add(f)
            return None
        if "working strategy found" in s:
            # Пропатченный скрипт печатает её сразу после вердикта блока —
            # вердикт мог быть не «AVAILABLE» (SIMULATE=1 печатает
            # «SUCCESS»): строка сама по себе означает полный успех.
            f = parse_found_strategy(s.strip().strip("!").strip())
            if (f and f["test"] == self.cur["test"]
                    and f["domain"].lower() == self.cur["domain"]):
                self.cur["full"] = True
                return self._finalize()
        at = _ATTEMPT_RE.match(s)
        if at:
            self.cur["attempt_max"] = max(self.cur["attempt_max"],
                                          int(at.group(1)))
        if (re.search(r"\bAVAILABLE\b", s) and "UNAVAILABLE" not in s
                and "!!!!!" not in s):
            self.cur["ok"] += 1
        if re.search(r"!!!!!\s*AVAILABLE\s*!!!!!", s):
            self.cur["full"] = True
            return self._finalize()
        if s.strip().startswith("UNAVAILABLE"):
            return self._finalize()
        return None

    def close(self) -> Optional[dict]:
        return self._finalize()

    def _finalize(self) -> Optional[dict]:
        b, self.cur = self.cur, None
        if not b:
            return None
        total = b["attempt_max"] or 1
        ok = b["ok"]
        if not b["attempt_max"]:
            ok = 1 if b["full"] else 0
        if ok <= 0 and not b["full"]:
            return None
        if ok <= 0:
            ok = total
        info = _classify(b["test"])
        f = {
            "test": b["test"], "ipv": b["ipv"], "domain": b["domain"],
            "engine": b["engine"], "strategy": b["strategy"],
            "ok": ok, "total": total, "full": bool(b["full"]) or ok >= total,
        }
        f.update(info)
        return self._add(f)

    def _add(self, f: dict) -> Optional[dict]:
        f["strategy"] = _norm(f["strategy"])
        f["domain"] = str(f["domain"]).lower()
        key = (f["ipv"], f["test"], f["domain"], f["strategy"])
        if key in self._seen:
            return None
        self._seen.add(key)
        self.found.append(f)
        return f


def _norm(strategy: str) -> str:
    return " ".join(str(strategy or "").split())


def _classify(test: str) -> dict:
    from core.blockcheck2 import _classify_test
    return _classify_test(test)


# ─────────────────────────── раннер ───────────────────────────

class _Job:
    """Одна копия скрипта на группу доменов."""

    def __init__(self, domains):
        self.domains = list(domains)
        self.state = "pending"        # pending|running|done|error|stopped
        self.proc: Optional[subprocess.Popen] = None
        self.lines: list = []
        self.parser = LineParser()
        self.started = 0.0
        self.finished = 0.0
        self.exit_code: Optional[int] = None
        self.error = ""


class Blockcheck2MultiRunner:
    """Параллельные копии пропатченного blockcheck2.sh."""

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: list = []
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._started_at = 0.0
        self._finished_at = 0.0
        self._settings: dict = {}
        self._error = ""
        self._script = ""
        self._clone = ""
        self._hold = None
        self._snapshot = None
        self._bypass_paused = False

    # ─────────── public API ───────────

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    def start(self, domains, params: Optional[dict] = None,
              scanlevel: Optional[str] = None,
              concurrency: int = DEFAULT_CONCURRENCY,
              stop_after: int = 3, pause_bypass: bool = True,
              group_shared_ips: bool = True) -> dict:
        """Запустить проверку списка доменов.

        Args:
            domains: домены (текст через \\r\\n/пробелы или список).
            params: env blockcheck2 (IPVS, REPEATS, ENABLE_*, …).
            scanlevel: quick|standard|force.
            concurrency: сколько копий одновременно (1 — по очереди).
            stop_after: N рабочих стратегий на тест, 0 — без остановки.
            pause_bypass: снять обход GUI на время проверки.
            group_shared_ips: домены с общими IP — в одну копию.
        """
        doms = split_domains(domains)
        if not doms:
            return {"ok": False, "error": "Укажите хотя бы один домен"}
        if len(doms) > MAX_DOMAINS:
            return {"ok": False,
                    "error": "Слишком много доменов (максимум %d)"
                             % MAX_DOMAINS}
        try:
            concurrency = max(1, min(int(concurrency), MAX_CONCURRENCY))
            stop_after = max(0, min(int(stop_after), MAX_STOP_AFTER))
        except (TypeError, ValueError):
            return {"ok": False, "error": "concurrency/stop_after — числа"}
        if scanlevel:
            scanlevel = str(scanlevel).strip().lower()
            if scanlevel not in ("quick", "standard", "force"):
                return {"ok": False, "error": "scanlevel: quick|standard|force"}
        env_extra = {}
        for k, v in (params or {}).items():
            k = str(k).strip()
            if not _ENV_KEY_RE.match(k):
                return {"ok": False, "error": "Недопустимое имя параметра: %r" % k}
            if k in _RESERVED_ENV:
                return {"ok": False, "error": "Параметр %s задаёт вкладка" % k}
            v = "" if v is None else str(v)
            if "\x00" in v or len(v) > 1024:
                return {"ok": False, "error": "Недопустимое значение %s" % k}
            env_extra[k] = v

        # Соседа — до своего лока (см. Blockcheck2Runner.start).
        if _official_running():
            return {"ok": False,
                    "error": "Идёт официальный blockcheck2 — дождитесь "
                             "его окончания"}
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {"ok": False, "error": "Проверка уже выполняется"}
            script = Blockcheck2Runner.find_script()
            if not script:
                return {"ok": False,
                        "error": "Скрипт blockcheck2 не найден. Установите "
                                 "zapret2 или задайте zapret.blockcheck2_path."}
            try:
                clone = _write_clone(script)
            except Exception as e:      # noqa: BLE001 — текст в GUI
                return {"ok": False, "error": str(e)}

            self._jobs = []
            self._stop.clear()
            self._started_at = time.time()
            self._finished_at = 0.0
            self._error = ""
            self._script = script
            self._clone = clone
            self._settings = {
                "domains": doms, "concurrency": concurrency,
                "stop_after": stop_after, "scanlevel": scanlevel or "",
                "params": dict(env_extra), "pause_bypass": bool(pause_bypass),
                "group_shared_ips": bool(group_shared_ips),
            }
            self._thread = threading.Thread(
                target=self._run, name="blockcheck2-multi", daemon=True)
            self._thread.start()
        log.info("blockcheck2 (мульти): %d домен(ов), параллельно %d, "
                 "стоп после %s" % (len(doms), concurrency,
                                    stop_after or "—"),
                 source="blockcheck2")
        return {"ok": True, "domains": doms, "clone": clone}

    def stop(self) -> bool:
        with self._lock:
            if not (self._thread and self._thread.is_alive()):
                return False
            self._stop.set()
            procs = [j.proc for j in self._jobs
                     if j.proc is not None and j.proc.poll() is None]
        for p in procs:
            _kill_group(p, signal.SIGTERM)
        log.info("blockcheck2 (мульти): остановка", source="blockcheck2")
        return True

    def get_status(self) -> dict:
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            end = self._finished_at or time.time()
            jobs = []
            found = []
            for j in self._jobs:
                tests = []
                for (test, ipv, dom), t in j.parser.tests.items():
                    tests.append({"test": test, "ipv": ipv, "domain": dom,
                                  "tried": t["tried"],
                                  "skipped": t["skipped"]})
                jobs.append({
                    "domains": list(j.domains), "state": j.state,
                    "exit_code": j.exit_code, "error": j.error,
                    "line_count": len(j.lines),
                    "current": j.parser.current if j.state == "running" else "",
                    "elapsed_seconds": round(
                        ((j.finished or time.time()) - j.started)
                        if j.started else 0.0, 1),
                    "found_full": sum(1 for f in j.parser.found if f["full"]),
                    "found_total": len(j.parser.found),
                    "tests": tests,
                })
                found.extend(j.parser.found)
            return {
                "running": running,
                "started": self._started_at > 0,
                "elapsed_seconds": round(
                    (end - self._started_at) if self._started_at else 0.0, 1),
                "script": self._script,
                "clone": self._clone,
                "settings": dict(self._settings),
                "bypass_paused": self._bypass_paused,
                "error": self._error,
                "jobs": jobs,
                "found": found,
            }

    def get_output(self, domain: str, offset: int = 0) -> dict:
        """Вывод копии, проверяющей ``domain`` (с offset)."""
        domain = str(domain or "").lower()
        with self._lock:
            job = next((j for j in self._jobs if domain in j.domains), None)
            if not job:
                return {"lines": [], "offset": 0, "next_offset": 0,
                        "found": False}
            total = len(job.lines)
            offset = max(0, min(int(offset or 0), total))
            return {"lines": job.lines[offset:], "offset": offset,
                    "next_offset": total, "found": True,
                    "state": job.state}

    def found(self) -> list:
        with self._lock:
            out = []
            for j in self._jobs:
                out.extend(j.parser.found)
            return out

    # ─────────── internals ───────────

    def _run(self) -> None:
        st = self._settings
        try:
            if st["group_shared_ips"] and len(st["domains"]) > 1:
                ips = {d: resolve_ips(d) for d in st["domains"]}
                groups = group_by_ips(st["domains"], ips)
            else:
                groups = [[d] for d in st["domains"]]
            with self._lock:
                self._jobs = [_Job(g) for g in groups]
            for g in groups:
                if len(g) > 1:
                    log.info("blockcheck2 (мульти): у %s общие IP — "
                             "проверяются одной копией по очереди"
                             % ", ".join(g), source="blockcheck2")

            if st["pause_bypass"]:
                self._pause_bypass()

            sem = threading.Semaphore(st["concurrency"])
            workers = []
            for job in list(self._jobs):
                if self._stop.is_set():
                    break
                sem.acquire()
                if self._stop.is_set():
                    sem.release()
                    break
                t = threading.Thread(target=self._run_job, args=(job, sem),
                                     daemon=True, name="bc2-multi-job")
                workers.append(t)
                t.start()
            for t in workers:
                t.join()
            with self._lock:
                for j in self._jobs:
                    if j.state == "pending":
                        j.state = "stopped"
        except Exception as e:          # noqa: BLE001 — граница потока
            self._error = "%s: %s" % (type(e).__name__, e)
            log.error("blockcheck2 (мульти): %s" % e, source="blockcheck2")
        finally:
            self._resume_bypass()
            with self._lock:
                self._finished_at = time.time()
            full = sum(1 for f in self.found() if f.get("full"))
            log.info("blockcheck2 (мульти): завершено, рабочих стратегий "
                     "(все попытки) — %d" % full, source="blockcheck2")

    def _run_job(self, job: _Job, sem) -> None:
        st = self._settings
        try:
            env = dict(os.environ)
            env.update(st["params"])
            env["BATCH"] = "1"
            env["DOMAINS"] = " ".join(job.domains)
            env["ZAPRET_BASE"] = os.path.dirname(self._script)
            env["GUI_STOP_AFTER"] = str(st["stop_after"])
            if st["scanlevel"]:
                env["SCANLEVEL"] = st["scanlevel"]
            cmd = ["sh", self._clone]
            cwd = os.path.dirname(self._script)
            # PTY — чтобы скрипт и curl писали построчно (находки видны
            # сразу, см. core/blockcheck2). Нет PTY — обычный pipe.
            try:
                master, slave = pty.openpty()
            except OSError:
                master = slave = None
            if slave is not None:
                try:
                    proc = subprocess.Popen(
                        cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                        stdout=slave, stderr=slave,
                        preexec_fn=os.setsid, close_fds=True)
                finally:
                    os.close(slave)
            else:
                proc = subprocess.Popen(
                    cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid, close_fds=True)
                master = os.dup(proc.stdout.fileno())
                proc.stdout.close()
            with self._lock:
                job.proc = proc
                job.state = "running"
                job.started = time.time()
            if self._stop.is_set():
                _kill_group(proc, signal.SIGTERM)
            self._read(job, master)
            rc = proc.wait()
            with self._lock:
                job.exit_code = rc
                job.finished = time.time()
                job.state = ("stopped" if self._stop.is_set()
                             else ("done" if rc == 0 else "error"))
        except Exception as e:          # noqa: BLE001 — граница потока
            with self._lock:
                job.state = "error"
                job.error = str(e)
                job.finished = time.time()
        finally:
            sem.release()

    def _read(self, job: _Job, fd: int) -> None:
        buf = b""
        tag = ",".join(job.domains)
        try:
            while True:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    self._line(job, tag,
                               raw.decode("utf-8", "replace").rstrip("\r"))
            if buf:
                self._line(job, tag, buf.decode("utf-8", "replace"))
            with self._lock:
                job.parser.close()
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def _line(self, job: _Job, tag: str, line: str) -> None:
        with self._lock:
            job.lines.append(line)
            if len(job.lines) > _MAX_JOB_LINES:
                del job.lines[:len(job.lines) - _MAX_JOB_LINES]
            f = job.parser.feed(line)
        if f and f.get("full"):
            log.success("[%s] %s: %s" % (tag, f.get("label"),
                                         f.get("strategy")),
                        source="blockcheck2")

    def _pause_bypass(self) -> None:
        """Снять обход GUI на время проверки (со снимком «как было»)."""
        from core.nfqws_session import (OWNER_BLOCKCHECK, SessionBusy,
                                        get_nfqws_session)
        session = get_nfqws_session()
        try:
            self._hold = session.claim(
                OWNER_BLOCKCHECK, timeout=0,
                reason="мульти-доменный blockcheck2")
        except SessionBusy as e:
            log.warning("Обход не снят: %s — проверка идёт поверх него"
                        % e, source="blockcheck2")
            self._hold = None
            return
        snap = session.snapshot(source="blockcheck2")
        if not (snap.get("nfqws_running") or snap.get("firewall_applied")):
            return
        self._snapshot = snap
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        try:
            if get_nfqws_manager().is_running():
                get_nfqws_manager().stop()
            fw = get_firewall_manager()
            if fw.is_applied():
                fw.remove_rules()
            self._bypass_paused = True
            log.info("Обход nfqws2 снят на время blockcheck2 — вернётся "
                     "после проверки", source="blockcheck2")
        except Exception as e:          # noqa: BLE001
            log.warning("Не удалось снять обход: %s" % e,
                        source="blockcheck2")

    def _resume_bypass(self) -> None:
        try:
            if self._snapshot is not None:
                from core.nfqws_session import get_nfqws_session
                get_nfqws_session().restore(self._snapshot,
                                            source="blockcheck2")
        finally:
            self._snapshot = None
            self._bypass_paused = False
            if self._hold is not None:
                self._hold.release()
                self._hold = None


def _kill_group(proc, sig) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, OSError):
        pass


def _official_running() -> bool:
    try:
        from core.blockcheck2 import get_blockcheck2_runner
        return get_blockcheck2_runner().is_running()
    except Exception:                   # noqa: BLE001
        return False


def _clone_dir() -> str:
    """Каталог для клона: рядом с настройками GUI, иначе /tmp."""
    try:
        from core.config_manager import get_config_dir
        d = get_config_dir()
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            return d
    except Exception:                   # noqa: BLE001
        pass
    return tempfile.gettempdir()


def _write_clone(script: str) -> str:
    """Клонировать и пропатчить blockcheck2.sh; путь к клону."""
    from core.blockcheck2_patch import patch_script
    with open(script, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    patched = patch_script(text, source=script)
    dst = os.path.join(_clone_dir(), "blockcheck2-gui.sh")
    tmp = dst + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(patched)
    os.chmod(tmp, 0o700)
    os.replace(tmp, dst)
    return dst


# ─────────────────── singleton ───────────────────

_runner: Optional[Blockcheck2MultiRunner] = None
_runner_lock = threading.Lock()


def get_multi_runner() -> Blockcheck2MultiRunner:
    global _runner
    if _runner is None:
        with _runner_lock:
            if _runner is None:
                _runner = Blockcheck2MultiRunner()
    return _runner
