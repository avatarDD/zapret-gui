# core/geneva_auto_search.py
"""
Режим «Авто» geneva: подбор и проверка стратегий для одного сервиса.

Перенос подбора ``GenevaAuto`` из AutoTuner, переделанный под скорость на
роутере. Сервис один за раз (очередь выбирает книга,
:meth:`core.geneva_auto.Book.next_to_search`), работа — в своём потоке,
менеджер режима только забирает итог (:meth:`AutoSearch.result`).

Сервис с пробой (сайт, DNS, повторяемый протокол):

1. **быстрые кандидаты** — до 12 стратегий (стратегии работающих групп,
   найденные раньше для этой цели в базе оценок ``db_top``, шаблоны
   ``AUTO_CANDIDATES_*``) одним ``geneva eval`` с ``--workers N``:
   кандидаты оцениваются **параллельно**, каждый воркер со своего блока
   локальных портов. Отличие от эталона: там кандидаты шли по одному
   через применение группы (кандидат × (применение + 1 с + проба)), здесь
   все разом за одну-две пробы по времени, а применением проверяется
   только прошедший;
2. если никто не прошёл — **``geneva evolve``** (популяция 20, 10
   поколений, ``--protos`` по транспорту, тоже с ``--workers N``). Свой
   checkpoint на сервис: следующий подбор продолжает его ``--resume`` с
   +5 поколений. База оценок общая, цель — ``https:<host>`` или
   ``replay:<ip>:<port>``: найденное засевает следующий поиск;
3. **проверка на трафике сервиса**: лучшие (до 3) прошедшие стратегии по
   очереди применяются к сервису пробной группой (``trial``, п. 5 —
   ``geneva run`` на адреса сервиса), через 1 с — проба с обходом. Первая
   рабочая — итог ``applied``.

Обе задачи geneva идут пробой ``exec``: команда
:mod:`core.geneva_auto_probe_cli` делает ту же пробу, что подтверждение
(:mod:`core.geneva_auto_probes`), с порта воркера.

Сервис без пробы (WireGuard, DHT, ICE/Discord): кандидаты по одному
применяются пробной группой, успех — успешный поток самого клиента
(наблюдение) за 50 с. Подбор ``evolve`` для них невозможен: оценивать
нечем.

Ручной подбор на странице занимает тот же слот задачи geneva: тогда итог
``busy``, менеджер вернёт сервис в ``blocked`` и попробует позже.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import threading
import time
from dataclasses import dataclass, field

from core import geneva_auto as ga
from core.log_buffer import log

TRIAL_SETTLE = 1.0            # после применения пробной группы
UNPROBED_WAIT = 50.0          # сервис без пробы: успешный поток клиента
VERIFY_TOP = 3                # сколько прошедших проверять на трафике
JOB_POLL = 2.0
EXEC_TIMEOUT_WEB = 16         # страница — 12 с, с запасом на запуск python
EXEC_TIMEOUT_REPLAY = 10
DEFAULT_WORKERS = 4
MAX_WORKERS = 8
# Имя хоста уходит в команду ``sh -c`` (в кавычках shlex) — и всё равно
# только такое: оно пришло из DNS-ответа или SNI, то есть от чужих.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

# Итоги подбора.
APPLIED = "applied"
NOT_FOUND = "not_found"
NOT_BLOCKED = "not_blocked"   # evolve: без стратегии открылось (код 7)
BUSY = "busy"                 # слот geneva занят ручным подбором
CANCELLED = "cancelled"
ERROR = "error"


@dataclass
class SearchResult:
    key: str
    outcome: str
    strategy: str = ""
    fitness: float = 0.0
    detail: str = ""
    tried: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"key": self.key, "outcome": self.outcome,
                "strategy": self.strategy, "fitness": self.fitness,
                "detail": self.detail, "tried": list(self.tried)}


# ───────────────────────────── чистые функции ───────────────────────

def slug(key: str) -> str:
    """Имя файла сервиса: ключ содержит «:» и адреса IPv6."""
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def probe_script() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "geneva_auto_probe_cli.py")


def probe_argv(s: ga.Service, *, python: str, script: str,
               replay_file: str = ""):
    """argv пробы ``exec`` для сервиса или ``None`` — пробы нет.

    ``{lports}`` подставит geneva. Адреса — новейший адрес сервиса.
    """
    from core import geneva_auto_probes as pr
    if not s.address:
        return None
    argv = [python, script, "--ip", s.address, "--port", str(s.port),
            "--lports", "{lports}"]
    if s.kind == ga.WEB:
        host = s.host or s.name
        if not _HOST_RE.match(host or ""):
            return None
        return argv + ["--kind", "web", "--host", host,
                       "--tls", "0" if s.port == 80 else "1"]
    plan = pr.replay_plan(s)
    if plan is None:
        return None
    payloads, udp, fresh = plan
    argv += ["--kind", "replay"]
    if udp:
        argv.append("--udp")
    if fresh:
        argv += ["--fresh", fresh]
    elif payloads:
        if not replay_file:
            return None
        argv += ["--replay-file", replay_file]
    return argv


def command_text(argv) -> str:
    """argv → строка для ``sh -c``; ``{lports}`` geneva подставит внутри
    кавычек, это всё равно одно слово."""
    return " ".join(shlex.quote(a) for a in argv)


def job_params(s: ga.Service, *, cmd: str, workers: int,
               checkpoint: str = "", generations: int = ga.GENERATIONS,
               key: str = "") -> dict:
    return {
        "cmd": cmd,
        "target": ga.search_target(s),
        "protos": ga.protos_for(s),
        "population": ga.POPULATION,
        "generations": generations,
        "workers": max(1, min(int(workers or 1), MAX_WORKERS)),
        "timeout": EXEC_TIMEOUT_WEB if s.kind == ga.WEB
        else EXEC_TIMEOUT_REPLAY,
        "checkpoint": checkpoint,
        "key": key or s.key,
    }


def passing(results, limit: int = VERIFY_TOP, skip=()) -> list:
    """Прошедшие (fitness > 0) стратегии, лучшие первыми:
    ``[(strategy, fitness)]``. geneva вычитает штрафы из +400, поэтому
    порог — ноль, а не 400."""
    best = {}
    for r in results or []:
        strat = str(r.get("strategy") or "").strip()
        try:
            fit = float(r.get("avg_fitness", r.get("fitness")))
        except (TypeError, ValueError):
            continue
        if not strat or fit <= 0 or strat in skip:
            continue
        if fit > best.get(strat, float("-inf")):
            best[strat] = fit
    out = sorted(best.items(), key=lambda kv: -kv[1])
    return out[:limit]


def next_generations(memo: dict, checkpoint_exists: bool):
    """``(generations, resume)``: продолжение — +5 поколений к прошлым."""
    done = int((memo or {}).get("generations") or 0)
    if checkpoint_exists and done > 0:
        return min(200, done + ga.MORE_GENERATIONS), True
    return ga.GENERATIONS, False


# ───────────────────────────── подбор ───────────────────────────────

class AutoSearch:
    """Подбор одного сервиса в своём потоке.

    Зависимости подменяются в тестах:

    * ``geneva`` — :class:`core.geneva_manager.GenevaManager`
      (``start_auto_job``, ``auto_job_status``, ``stop_search``,
      ``db_top``);
    * ``probes`` — :class:`core.geneva_auto_probes.AutoProbes`;
    * ``trial(service, strategy)`` — применить пробную группу (``None``
      — снять); ``False`` — не применилась. Нет функции — проверка на
      трафике пропускается, прошедшая оценку стратегия принимается;
    * ``ok_since(key, t)`` — был ли с момента ``t`` успешный поток
      клиента этого сервиса (наблюдение).
    """

    def __init__(self, *, geneva=None, probes=None, trial=None,
                 ok_since=None, workers=DEFAULT_WORKERS,
                 python: str = sys.executable, script: str = "",
                 clock=time.time, paths=None):
        self._geneva = geneva
        self._probes = probes
        self._trial = trial
        self._ok_since = ok_since
        self.workers = workers
        self._python = python
        self._script = script or probe_script()
        self._clock = clock
        self._paths = paths
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._result = None
        self._progress = {}

    # ── зависимости по умолчанию ──

    def _gm(self):
        if self._geneva is None:
            from core.geneva_manager import get_geneva_manager
            self._geneva = get_geneva_manager()
        return self._geneva

    def _pr(self):
        if self._probes is None:
            from core.geneva_auto_probes import get_auto_probes
            self._probes = get_auto_probes()
        return self._probes

    def _p(self) -> dict:
        if self._paths is None:
            from core.geneva_manager import paths
            return paths()
        return self._paths

    # ── снаружи ──

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self, s: ga.Service, running=()) -> bool:
        """Начать подбор ``s`` фоном. ``False`` — уже идёт другой."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop = threading.Event()
            self._result = None
            snap = s.clone()
            self._progress = {"key": snap.key, "name": snap.name,
                              "phase": "start", "strategy": "",
                              "started_at": self._clock()}
            self._thread = threading.Thread(
                target=self._main, args=(snap, list(running or ())),
                name="geneva-auto-search", daemon=True)
            self._thread.start()
            return True

    def progress(self) -> dict:
        with self._lock:
            return dict(self._progress)

    def result(self):
        """Итог законченного подбора (забирается один раз) или ``None``."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return None
            out, self._result = self._result, None
            return out

    def cancel(self, wait: float = 30.0) -> None:
        """Прервать: задание geneva останавливается (checkpoint
        сохраняется), пробная группа снимается."""
        self._stop.set()
        try:
            if self._gm().auto_job_running():
                self._gm().stop_search()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: стоп подбора: %s" % e, source="geneva")
        t = self._thread
        if t is not None:
            t.join(wait)

    # ── поток ──

    def _set(self, **kw) -> None:
        with self._lock:
            self._progress.update(kw)

    def _main(self, s: ga.Service, running: list) -> None:
        try:
            res = self._run(s, running)
        except Exception as e:                      # noqa: BLE001
            log.warning("geneva-auto: подбор %s: %s" % (s.name, e),
                        source="geneva")
            res = SearchResult(s.key, ERROR, detail=str(e)[:300])
        if self._stop.is_set() and res.outcome not in (APPLIED,):
            res.outcome = CANCELLED
        with self._lock:
            self._result = res
            self._progress["phase"] = "done"

    def _run(self, s: ga.Service, running: list) -> SearchResult:
        found = self._found(s)
        cands = self._checked(ga.candidates_for(s, running, found))
        if self._pr().judge(s) is None:
            return self._by_traffic(s, cands)
        argv = probe_argv(s, python=self._python, script=self._script,
                          replay_file=self._replay_file(s))
        if argv is None:
            return self._by_traffic(s, cands)
        cmd = command_text(argv)
        tried = []

        # 1. быстрые кандидаты — параллельно
        if cands:
            self._set(phase="quick", total=len(cands))
            st = self._job("eval", s, cmd, strategies=cands)
            if st is None:
                return SearchResult(s.key, CANCELLED)
            if st.get("busy"):
                return SearchResult(s.key, BUSY, detail=st.get("error", ""))
            if st.get("status") == "error":
                return SearchResult(s.key, ERROR,
                                    detail=st.get("error") or "eval")
            if st.get("status") == "stopped":
                # остановили со страницы ручного подбора: не «не найдено»
                return SearchResult(s.key, BUSY, detail="подбор остановлен")
            good = passing(st.get("results"))
            tried += [x for x, _ in good]
            win = self._verify(s, good)
            if win is not None:
                return win
            if self._stop.is_set():
                return SearchResult(s.key, CANCELLED)

        # 2. генетический подбор — с прошлого места
        ckpt = os.path.join(self._p()["auto"], slug(s.key) + ".ckpt")
        memo_path = os.path.join(self._p()["auto"], slug(s.key) + ".json")
        memo = _read_json(memo_path)
        gens, resume = next_generations(memo, os.path.isfile(ckpt))
        self._set(phase="evolve", generations=gens)
        st = self._job("evolve", s, cmd, checkpoint=ckpt, generations=gens,
                       resume=resume)
        if st is not None and resume and st.get("status") == "error":
            # checkpoint не подошёл (другой бинарник, другие параметры):
            # заново, а не «не найдено»
            gens, resume = ga.GENERATIONS, False
            st = self._job("evolve", s, cmd, checkpoint=ckpt,
                           generations=gens, resume=False)
        if st is None or (not st.get("busy") and
                          st.get("status") != "error"):
            # checkpoint соответствует прогону до gens поколений: и после
            # прерывания следующий подбор продолжит его, а не начнёт
            # заново
            _write_json(memo_path, {"generations": gens,
                                    "at": self._clock()})
        if st is None:
            return SearchResult(s.key, CANCELLED, tried=tried)
        if st.get("busy"):
            return SearchResult(s.key, BUSY, detail=st.get("error", ""))
        if st.get("status") in ("stopped", "interrupted"):
            return SearchResult(s.key, BUSY, tried=tried,
                                detail="подбор остановлен, продолжу")
        if st.get("status") == "not_blocked":
            return SearchResult(s.key, NOT_BLOCKED,
                                detail="без стратегии открылось")
        if st.get("status") == "error":
            return SearchResult(s.key, ERROR,
                                detail=st.get("error") or "evolve",
                                tried=tried)
        good = passing(st.get("results"), skip=tried)
        tried += [x for x, _ in good]
        win = self._verify(s, good)
        if win is not None:
            win.tried = tried
            return win
        return SearchResult(s.key, NOT_FOUND, tried=tried,
                            detail="ни одна стратегия не прошла")

    def _checked(self, cands: list) -> list:
        """Только то, что разбирает установленный geneva (``geneva
        check``): одна неразбираемая строка уронила бы весь ``eval -f``
        кодом 3. Канонический вид — как его напечатает geneva."""
        check = getattr(self._gm(), "check_strategy", None)
        if check is None:
            return cands
        out = []
        for c in cands:
            try:
                r = check(c)
            except Exception:                       # noqa: BLE001
                r = {"ok": True, "strategy": c}
            if r.get("ok"):
                canon = r.get("strategy") or c
                if canon not in out:
                    out.append(canon)
            else:
                log.info("geneva-auto: кандидат пропущен (%s): %s"
                         % (r.get("error", ""), c[:120]), source="geneva")
        return out

    def _found(self, s: ga.Service) -> list:
        try:
            top = self._gm().db_top(ga.search_target(s), 10) or {}
        except Exception:                           # noqa: BLE001
            return []
        if not top.get("ok"):
            return []
        # Только с успехами: стратегии, которые уже проваливались на этой
        # цели, быстрый круг не ускорят.
        return [i.get("strategy") for i in top.get("items") or []
                if i.get("strategy") and int(i.get("ok") or 0) > 0]

    def _replay_file(self, s: ga.Service) -> str:
        if not s.replay:
            return ""
        path = os.path.join(self._p()["auto_runtime"],
                            slug(s.key) + ".b64")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="ascii") as f:
                f.write(s.replay)
        except OSError as e:
            log.warning("geneva-auto: replay не записан: %s" % e,
                        source="geneva")
            return ""
        return path

    def _job(self, kind, s, cmd, *, strategies=None, checkpoint="",
             generations=ga.GENERATIONS, resume=False):
        """Задание geneva до конца; ``None`` — прервано, ``{"busy"}`` —
        слот занят."""
        params = job_params(s, cmd=cmd, checkpoint=checkpoint,
                            generations=generations,
                            workers=min(self.workers, len(strategies))
                            if strategies else self.workers)
        gm = self._gm()
        r = gm.start_auto_job(kind, params, strategies=strategies,
                              resume=resume)
        if not r.get("ok"):
            if r.get("busy"):
                return {"busy": True, "error": r.get("error", "")}
            return {"status": "error", "error": r.get("error", "")}
        while not self._stop.wait(JOB_POLL):
            st = gm.auto_job_status()
            self._set(generation=st.get("generation"),
                      done=st.get("done"), best=st.get("best", ""),
                      best_fitness=st.get("best_fitness"))
            if not st.get("running"):
                return st
        return None

    def _verify(self, s: ga.Service, good: list):
        """Проверить прошедшие на трафике сервиса: пробная группа и
        проба с обходом. Первая рабочая — итог."""
        if not good:
            return None
        if self._trial is None:
            strat, fit = good[0]
            return SearchResult(s.key, APPLIED, strategy=strat, fitness=fit,
                                detail="прошла оценку geneva")
        for strat, fit in good[:VERIFY_TOP]:
            if self._stop.is_set():
                return None
            self._set(phase="verify", strategy=strat)
            if not self._trial(s, strat):
                continue
            if self._stop.wait(TRIAL_SETTLE):
                break
            confirm, text = self._pr().check(s, through_bypass=True)
            if confirm == ga.C_NOT_BLOCKED:
                return SearchResult(s.key, APPLIED, strategy=strat,
                                    fitness=fit, detail=text)
            log.info("geneva-auto: %s — стратегия не подтвердилась на "
                     "трафике (%s)" % (s.name, text), source="geneva")
        self._trial(s, None)
        return None

    def _by_traffic(self, s: ga.Service, cands: list) -> SearchResult:
        """Сервис без пробы: кандидат за кандидатом, успех — успешный
        поток самого клиента."""
        if self._trial is None or self._ok_since is None:
            return SearchResult(s.key, NOT_FOUND,
                                detail="без пробы проверять нечем")
        tried = []
        for strat in cands:
            if self._stop.is_set():
                break
            self._set(phase="trial", strategy=strat)
            if not self._trial(s, strat):
                continue
            tried.append(strat)
            t0 = self._clock()
            deadline = t0 + UNPROBED_WAIT
            while not self._stop.wait(JOB_POLL):
                if self._ok_since(s.key, t0):
                    return SearchResult(s.key, APPLIED, strategy=strat,
                                        fitness=ga.FIT_OK, tried=tried,
                                        detail="поток клиента прошёл")
                if self._clock() >= deadline:
                    break
        self._trial(s, None)
        if self._stop.is_set():
            return SearchResult(s.key, CANCELLED, tried=tried)
        return SearchResult(s.key, NOT_FOUND, tried=tried,
                            detail="ни с одной стратегией поток не прошёл")


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: str, data: dict) -> None:
    try:
        from core.geneva_manager import _write_atomic
        _write_atomic(path, json.dumps(data))
    except OSError as e:
        log.warning("geneva-auto: %s не записан: %s" % (path, e),
                    source="geneva")
