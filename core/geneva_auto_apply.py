# core/geneva_auto_apply.py
"""
Режим «Авто» geneva: применение групп (процессы + правила) и телеметрия.

План групп строит ядро (:func:`core.geneva_auto.plan_groups`: активные
сервисы по стратегии, пробуемая стратегия первой, пара «адрес +
транспорт» — только одной группе). Здесь он становится реальностью
(``GenevaAuto.AutoApplyAsync`` / ``GenevaManager.AutoApplyAsync``
AutoTuner):

* **очереди** — :func:`assign_queues`: стратегия, у которой уже есть
  процесс, остаётся на своей очереди (процесс не трогается, меняется
  только набор адресов); новой — свободная очередь 340..340+N-1;
* **процессы** — :meth:`GenevaManager.auto_apply` (пуск, ``set_strategy``
  на лету, подъём упавшего, остановка лишних);
* **правила** — :mod:`core.geneva_auto_fw` для групп, чей процесс жив:
  очередь без процесса пропускается (``bypass``), но и правил на неё не
  ставим;
* **пробная стратегия** считается применённой, только если её группа
  действительно запущена (``requested`` в AutoTuner): иначе подбор
  проверял бы трафик без обхода и «находил» несуществующее;
* **телеметрия** — ``stats`` каждой группы через управляющий сокет и
  скорость пакетов между опросами.
"""

from __future__ import annotations

import threading
import time

from core import geneva_auto as ga
from core.log_buffer import log


def assign_queues(groups, current: dict, max_groups: int = ga.MAX_GROUPS,
                  base: int = ga.QUEUE_BASE) -> dict:
    """``[ga.Group]`` → ``{очередь: ga.Group}``.

    ``current`` — ``{очередь: стратегия}`` живых процессов. Стратегия с
    процессом сохраняет очередь, остальные занимают свободные по
    порядку групп (пробная — первая в плане, она и получит первую
    свободную). Сверх ``max_groups`` групп не бывает (план уже урезан).
    """
    max_groups = max(1, min(int(max_groups or ga.MAX_GROUPS),
                            ga.MAX_GROUPS_LIMIT))
    allowed = list(range(base, base + max_groups))
    by_strategy = {}
    for q, strat in sorted(current.items()):
        if q in allowed and strat and strat not in by_strategy:
            by_strategy[strat] = q
    out = {}
    pending = []
    for g in list(groups)[:max_groups]:
        q = by_strategy.get(g.strategy)
        if q is not None and q not in out:
            out[q] = g
        else:
            pending.append(g)
    free = [q for q in allowed if q not in out and q not in current]
    free += [q for q in allowed if q not in out and q not in free]
    for g in pending:
        if not free:
            break
        out[free.pop(0)] = g
    return out


def rates(prev: dict, cur: dict, dt: float) -> dict:
    """Скорость пакетов (в секунду) между двумя ``stats``."""
    out = {}
    if dt <= 0:
        return out
    for key in ("pkts_out", "pkts_in", "triggered", "modified", "injected",
                "dropped"):
        if key not in cur:
            continue
        try:
            d = float(cur.get(key, 0)) - float(prev.get(key, 0))
        except (TypeError, ValueError):
            continue
        out[key] = round(max(0.0, d) / dt, 2)
    return out


class Applier:
    """Группы «Авто» на роутере. Зависимости подменяются в тестах."""

    def __init__(self, *, geneva=None, fw=None,
                 max_groups: int = ga.MAX_GROUPS, clock=time.time):
        self._geneva = geneva
        self._fw = fw
        self.max_groups = max_groups
        self._clock = clock
        self._lock = threading.RLock()
        self.queues = {}             # {q: ga.Group} — применено сейчас
        self.last = {}               # итог последнего apply
        self._stats = {}             # {q: (t, stats)}

    def _gm(self):
        if self._geneva is None:
            from core.geneva_manager import get_geneva_manager
            self._geneva = get_geneva_manager()
        return self._geneva

    def _fwm(self):
        if self._fw is None:
            from core import geneva_auto_fw
            self._fw = geneva_auto_fw
        return self._fw

    # ── применение ──

    def apply(self, groups) -> dict:
        """Привести процессы и правила к ``groups``.

        ``{"ok", "queues": {q: {strategy, services, pid, action,
        error}}, "error", "hint", "backend"}``.
        """
        with self._lock:
            gm = self._gm()
            current = {q: info.get("strategy", "")
                       for q, info in gm.auto_groups().items()}
            queues = assign_queues(groups, current, self.max_groups)
            res = gm.auto_apply({q: g.strategy for q, g in queues.items()})
            procs = res.get("queues") or {}
            live = {q: g for q, g in queues.items()
                    if (procs.get(q) or {}).get("pid")}
            fw = self._fwm().apply(live)
            if not fw.get("ok"):
                # правила не встали: процессы без правил бесполезны, а
                # пробная стратегия не должна считаться применённой
                live = {}
            self.queues = live
            for q in list(self._stats):
                if q not in live:
                    del self._stats[q]
            out = {"ok": bool(res.get("ok", True)) and bool(fw.get("ok")),
                   "backend": fw.get("backend", ""),
                   "error": fw.get("error") or res.get("error", ""),
                   "hint": fw.get("hint", ""), "queues": {}}
            for q, g in queues.items():
                info = procs.get(q) or {}
                out["queues"][q] = {
                    "strategy": g.strategy, "services": list(g.services),
                    "targets": [ga.describe_target(t) for t in g.targets],
                    "pid": info.get("pid"), "action": info.get("action", ""),
                    "error": info.get("error", ""), "live": q in live}
            if out["error"]:
                log.warning("geneva-auto: применение: %s" % out["error"],
                            source="geneva")
            self.last = out
            return out

    def apply_services(self, services, trial=None) -> dict:
        """План из сервисов книги (и пробной стратегии) и применение.

        ``trial`` — ``(Service, strategy)``. В ответе ``trial_ok``:
        группа пробной стратегии с этим сервисом запущена и под
        правилами.
        """
        groups = ga.plan_groups(services, trial=trial,
                                max_groups=self.max_groups)
        out = self.apply(groups)
        if trial:
            s, strat = trial
            out["trial_ok"] = any(
                g.strategy == strat and s.key in g.services
                for g in self.queues.values())
        return out

    def clear(self) -> None:
        """Снять правила и остановить все группы (правила — первыми:
        пакеты не должны ждать в очереди, которой уже нет)."""
        with self._lock:
            try:
                self._fwm().remove()
            finally:
                self._gm().auto_stop_all()
                self.queues = {}
                self._stats = {}

    # ── телеметрия ──

    def stats(self) -> dict:
        """``{q: {stats, rate, strategy, services}}`` по живым группам."""
        with self._lock:
            out = {}
            now = self._clock()
            for q, g in self.queues.items():
                r = self._gm().auto_stats(q)
                item = {"strategy": g.strategy,
                        "services": list(g.services), "ok": bool(r.get("ok"))}
                if r.get("ok"):
                    prev = self._stats.get(q)
                    if prev:
                        item["rate"] = rates(prev[1], r, now - prev[0])
                    self._stats[q] = (now, r)
                    try:
                        from core.geneva_manager import summarize_stats
                        item["stats"] = summarize_stats(r)
                    except Exception:               # noqa: BLE001
                        item["stats"] = dict(r)
                else:
                    item["error"] = r.get("error", "")
                out[q] = item
            return out
