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
                 max_groups: int = ga.MAX_GROUPS, workers: int = 4,
                 clock=time.time):
        self._geneva = geneva
        self._fw = fw
        self.max_groups = max_groups
        # потоков процессу профилей (он же диапазон очередей 340..340+N-1)
        self.workers = workers
        self._clock = clock
        self._lock = threading.RLock()
        self.queues = {}             # {q: ga.Group} — группы (старый путь)
        self.profiles = []           # [ga.Profile] — применено сейчас
        self.mode = ""               # "profiles" | "groups"
        self.rules = []              # пары (очередь, группа) + «по имени»
        self.host = {}               # итог процесса «по имени»
        self.last = {}               # итог последнего apply
        self._stats = {}             # {q|имя профиля: (t, stats)}

    def _gm(self):
        if self._geneva is None:
            from core.geneva_manager import get_geneva_manager
            self._geneva = get_geneva_manager()
        return self._geneva

    def _fw_apply(self, rules, span: int) -> dict:
        """Правила с диапазоном очередей; двойник без ``span`` (старые
        тесты) получает только правила."""
        apply = self._fwm().apply
        try:
            return apply(rules, span=span)
        except TypeError:
            return apply(rules)

    def _fwm(self):
        if self._fw is None:
            from core import geneva_auto_fw
            self._fw = geneva_auto_fw
        return self._fw

    # ── применение ──

    def running(self) -> list:
        """Стратегии, которые сейчас под правилами (группы или профили)."""
        if self.mode == "profiles":
            return [p.strategy for p in self.profiles]
        return [g.strategy for g in self.queues.values()]

    def _span(self) -> int:
        """Очередей у процесса профилей (он же ``span`` правил): предел
        движка 1–64, а очередь «по имени» и детектор стоят сразу за
        диапазоном профилей (340..403)."""
        return max(1, min(int(self.workers or 1), ga.ENGINE_WORKERS_MAX))

    def profiles_ok(self) -> bool:
        """Стратегии сейчас — профили одного процесса?"""
        return self._profiles_ok(self._gm())

    def _profiles_ok(self, gm) -> bool:
        """Движок умеет профили (``ext_profile`` geneva_c 2.0): тогда
        стратегий может быть больше восьми, и группы не нужны."""
        if not hasattr(gm, "auto_engine_apply"):
            return False
        try:
            return ga.PROFILE_FEATURE in (gm.features() or ())
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: профили: %s" % e, source="geneva")
            return False

    def apply(self, groups, hosts=None) -> dict:
        """Привести процессы и правила к ``groups``.

        ``hosts`` — процесс «по имени» (geneva_c 2.0): ``{"profiles",
        "exclude_ips", "exclude_domains"}`` или ``None`` (выключен).

        ``{"ok", "queues": {q: {strategy, services, pid, action,
        error}}, "host": {…}, "error", "hint", "backend"}``.
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
            host = self._apply_host(gm, self._targets(live), hosts)
            rules = sorted(live.items())
            if host.get("pid"):
                rules.append((ga.HOST_QUEUE,
                              self._fwm().HostRule(host.get("udp"))))
            fw = self._fw_apply(rules, 1)
            if not fw.get("ok"):
                # правила не встали: процессы без правил бесполезны, а
                # пробная стратегия не должна считаться применённой
                live, rules = {}, []
                host = dict(host, pid=None, live=False)
            self.queues = live
            self.profiles = []
            self.mode = "groups"
            self.rules = rules
            self.host = host
            for q in list(self._stats):
                if q not in live:
                    del self._stats[q]
            out = {"ok": bool(res.get("ok", True)) and bool(fw.get("ok")),
                   "backend": fw.get("backend", ""),
                   "error": fw.get("error") or res.get("error", "") or
                   host.get("error", ""),
                   "hint": fw.get("hint", ""), "queues": {}, "host": host}
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

    @staticmethod
    def _targets(live) -> list:
        """Все цели применённого: их адреса — исключения «по имени»."""
        out = []
        for g in list(live.values()) if isinstance(live, dict) \
                else list(live or ()):
            out.extend(getattr(g, "targets", None) or ())
        return out

    def _apply_host(self, gm, live, hosts) -> dict:
        """Процесс «по имени»: его исключения — адреса живых групп и
        профилей (их правила стоят раньше) и «Не трогать».

        ``live`` — цели (``ga.Target``) уже применённого обхода.
        """
        apply_host = getattr(gm, "auto_host_apply", None)
        if apply_host is None:
            return {}
        if not hosts or not hosts.get("profiles"):
            if gm.auto_host_pid():
                gm.auto_host_stop()
            return {}
        ips = set(hosts.get("exclude_ips") or ())
        for tg in live or ():
            ips.update(str(a) for a in getattr(tg, "addresses", None) or ())
        try:
            r = apply_host(hosts["profiles"], sorted(ips),
                           list(hosts.get("exclude_domains") or ()))
        except Exception as e:                      # noqa: BLE001
            log.warning("geneva-auto: «по имени»: %s" % e, source="geneva")
            return {"pid": None, "error": str(e)}
        if not isinstance(r, dict):
            return {}
        for why in r.get("problems") or ():
            log.info("geneva-auto: «по имени»: %s" % why, source="geneva")
        return r

    def apply_profiles(self, profiles, hosts=None) -> dict:
        """Один процесс на все стратегии (geneva_c 2.0, ``ext_profile``).

        ``profiles`` — :func:`core.geneva_auto.plan_profiles`. Правила:
        по одному правилу на профиль в порядке файла профилей, все — на
        диапазон очередей процесса (``span = workers``).

        ``{"ok", "mode": "profiles", "profiles": [{name, strategy,
        services, targets, live}], "queues": {}, "host", …}``.
        """
        with self._lock:
            gm = self._gm()
            profiles = list(profiles or ())
            span = self._span()
            res = gm.auto_engine_apply(profiles, span)
            live = bool(res.get("pid"))
            host = self._apply_host(gm, self._targets(profiles) if live
                                    else (), hosts)
            rules = []
            if live:
                q = ga.QUEUE_BASE
                for p in profiles:
                    g = ga.Group(strategy=p.strategy,
                                 services=list(p.services),
                                 targets=list(p.targets))
                    rules.append((q, g))
            if host.get("pid"):
                rules.append((ga.HOST_QUEUE,
                              self._fwm().HostRule(host.get("udp"))))
            fw = self._fw_apply(rules, span)
            if not fw.get("ok"):
                # правила не встали: процесс без правил бесполезен, а
                # пробная стратегия не должна считаться применённой
                live, rules = False, []
                host = dict(host, pid=None, live=False)
            self.queues = {}
            self.profiles = profiles if live else []
            self.mode = "profiles"
            self.rules = rules
            self.host = host
            for key in list(self._stats):
                if key not in {p.name for p in self.profiles}:
                    del self._stats[key]
            out = {"ok": bool(res.get("ok", True)) and bool(fw.get("ok")),
                   "mode": "profiles", "backend": fw.get("backend", ""),
                   "error": fw.get("error") or res.get("error", "") or
                   host.get("error", ""),
                   "hint": fw.get("hint", ""), "queues": {}, "host": host,
                   "profiles": [], "action": res.get("action", "")}
            for p in profiles:
                out["profiles"].append({
                    "name": p.name, "strategy": p.strategy,
                    "services": list(p.services), "trial": bool(p.trial),
                    "targets": [ga.describe_target(t) for t in p.targets],
                    "live": live})
            if out["error"]:
                log.warning("geneva-auto: применение профилей: %s"
                            % out["error"], source="geneva")
            self.last = out
            return out

    def apply_services(self, services, trial=None, trials=None,
                       hosts=None) -> dict:
        """План из сервисов книги (и пробных стратегий) и применение.

        ``trial`` — ``(Service, strategy)``, ``trials`` — несколько таких
        (подборы рядом). В ответе ``trial_ok`` (для ``trial``) и
        ``trials_ok`` (``{ключ сервиса: bool}``): группа пробной стратегии
        с этим сервисом запущена и под правилами.
        """
        all_trials = list(trials or ()) + ([trial] if trial else [])
        if self._profiles_ok(self._gm()):
            # geneva_c 2.0: одна стратегия — профиль, а не процесс с
            # очередью: восьми стратегий больше нет
            out = self.apply_profiles(
                ga.plan_profiles(services, trials=all_trials), hosts)
        else:
            groups = ga.plan_groups(services, trial=trial,
                                    max_groups=self.max_groups,
                                    trials=trials)
            out = self.apply(groups, hosts)

        def live(s, strat):
            return any(p.strategy == strat and s.key in p.services
                       for p in (self.profiles if self.mode == "profiles"
                                 else [])) or any(
                g.strategy == strat and s.key in g.services
                for g in self.queues.values())
        if trial:
            out["trial_ok"] = live(*trial)
        if trials:
            out["trials_ok"] = {s.key: live(s, strat)
                                for s, strat in trials}
        return out

    def missing(self) -> list:
        """Чего из правил живых групп (профилей) нет — снесла прошивка;
        пусто — всё на месте или обхода нет."""
        with self._lock:
            rules = getattr(self, "rules", None) or []
            if not rules:
                return []
            check = getattr(self._fwm(), "present", None)
            if not check:
                return []
            try:
                return list(check(rules, span=self._span()
                                  if self.mode == "profiles" else 1) or [])
            except TypeError:               # старый тестовый двойник
                return list(check(rules) or [])

    def clear(self) -> None:
        """Снять правила и остановить все группы (правила — первыми:
        пакеты не должны ждать в очереди, которой уже нет)."""
        with self._lock:
            gm = self._gm()
            try:
                self._fwm().remove()
            finally:
                gm.auto_stop_all()
                stop = getattr(gm, "auto_engine_stop", None)
                if stop is not None:
                    try:
                        stop()
                    except Exception as e:          # noqa: BLE001
                        log.debug("geneva-auto: стоп профилей: %s" % e,
                                  source="geneva")
                self.queues = {}
                self.profiles = []
                self.mode = ""
                self.rules = []
                self.host = {}
                self._stats = {}

    # ── телеметрия ──

    def _profile_stats(self) -> dict:
        """Телеметрия профилей: потоки по профилям (``ext_flows``) и
        общие счётчики процесса (``stats``)."""
        gm = self._gm()
        with self._lock:
            now = self._clock()
            flows = {}
            getter = getattr(gm, "auto_engine_flows", None)
            if getter is not None:
                try:
                    flows = getter() or {}
                except Exception as e:              # noqa: BLE001
                    log.debug("geneva-auto: ext_flows: %s" % e,
                              source="geneva")
            per = self._flow_counts(flows)
            total = {}
            try:
                total = gm.auto_engine_stats() or {}
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: stats профилей: %s" % e,
                          source="geneva")
            out = {}
            for p in self.profiles:
                item = {"strategy": p.strategy,
                        "services": list(p.services), "ok": bool(
                            total.get("ok")),
                        "profile": p.name}
                cnt = per.get(p.name) or {}
                item["stats"] = {"flows": cnt.get("flows", 0),
                                 "pkts_out": cnt.get("pkts_out", 0),
                                 "pkts_in": cnt.get("pkts_in", 0)}
                prev = self._stats.get(p.name)
                if prev:
                    item["rate"] = rates(prev[1], item["stats"],
                                         now - prev[0])
                self._stats[p.name] = (now, dict(item["stats"]))
                if total.get("ok"):
                    # общее по процессу: сумма по воркерам, а не по
                    # стратегиям — профили делят один счётчик
                    item["engine"] = {"pkts_out": total.get("pkts_out", 0),
                                      "pkts_in": total.get("pkts_in", 0),
                                      "triggered": total.get("triggered", 0),
                                      "workers": total.get("workers", 0)}
                elif total.get("error"):
                    item["error"] = total["error"]
                out[p.name] = item
            return out

    @staticmethod
    def _flow_counts(flows) -> dict:
        """Счётчики по профилям из ``ctl ext_flows``: у каждого потока
        есть имя профиля. ``{имя профиля: {"flows", "pkts_out",
        "pkts_in"}}`` — дешёвая замена счётчикам: ``stats`` у процесса
        общие на все профили."""
        out = {}
        for f in (flows or {}).get("flows") or ():
            name = str(f.get("profile") or "")
            if not name:
                continue
            item = out.setdefault(name, {"flows": 0, "pkts_out": 0,
                                         "pkts_in": 0})
            item["flows"] += 1
            item["pkts_out"] += int((f.get("out") or {}).get("n") or 0)
            item["pkts_in"] += int((f.get("in") or {}).get("n") or 0)
        return out

    def stats(self) -> dict:
        """``{q: {stats, rate, strategy, services}}`` по живым группам, а
        у профилей — ``{имя профиля: {…}}`` плюс общий ``stats`` процесса.
        """
        if self.mode == "profiles":
            return self._profile_stats()
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
