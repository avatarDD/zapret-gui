# core/geneva_auto_manager.py
"""
Режим «Авто» geneva: менеджер (цикл, состояние, включение и выключение).

Перенос цикла ``GenevaAuto`` из AutoTuner. Поток ``geneva-auto``, раз в
срез (15 с):

1. **срез** наблюдения (:mod:`core.geneva_auto_observer`) → книга
   (:class:`core.geneva_auto.Book`): ``feed`` и ``evaluate``; ошибка среза
   не убивает поток — повтор с растущей паузой до 5 мин;
2. **протокол** подозрительного сервиса без узнанного протокола —
   короткий захват его первых пакетов фоном (``identify_async``), итог —
   ``Book.learn`` (протокол, ``replay``, имя из SNI);
3. **подтверждение** одного подозрительного: проба без обхода
   (:mod:`core.geneva_auto_probes`), у ``degraded`` — с обходом;
4. **подбор**, если пора: один сервис за раз (:mod:`core.geneva_auto_search`)
   в своём потоке, итог забирается здесь;
5. **применение** групп (:mod:`core.geneva_auto_apply`) — при изменении
   плана и раз в 2 мин (так же поднимается упавший процесс);
6. **телеметрия** групп (``stats``);
7. **сохранение** состояния — при каждом переходе и не чаще раза в минуту
   иначе (flash роутера).

Состояние — ``<config>/state/geneva/auto.json`` (атомарная запись),
включённость — ``geneva.auto.enabled``. После загрузки поток
``geneva-boot`` (``core/bypass_engine.boot_apply``) поднимает режим, если
он был включён; если выключен — снимает то, что могло остаться после
сбоя (правила и процессы групп).

Взаимоисключения: «Авто» требует движок geneva (``bypass.engine``),
выключенный одиночный ``geneva run`` и свободный nfqws2. Пока он работает,
одиночный ``geneva run`` и ручной подбор отказывают (``error_code
geneva_auto``), переключение на nfqws2 выключает режим, а операции
nfqws2 на живой сети (сканер, blockcheck) ставят его на паузу
(:meth:`suspend`/:meth:`resume`).
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque

from core import geneva_auto as ga
from core.log_buffer import log

SLICE = 15.0
APPLY_EVERY = 120.0
SAVE_EVERY = 60.0
MAX_BACKOFF = 300.0
# Предупреждение об учёте пакетов: ставится и снимается по срезу.
ACCT_PROBLEM = "в таблице conntrack нет счётчиков пакетов"
JOURNAL_SIZE = 300
IDENTIFY_RETRY = 3600.0
SEARCH_WAIT_BUSY = 60.0         # слот geneva занят ручным подбором
SEARCH_WAIT_ERROR = 300.0
UNKNOWN_APPS = ("", "tcp", "udp", "p2p")

PHASES = ("off", "starting", "watching", "confirming", "searching",
          "suspended", "error")


def state_path() -> str:
    from core.geneva_manager import state_dir
    return os.path.join(state_dir(), "auto.json")


def auto_settings(cfg=None) -> dict:
    """``geneva.auto`` с пределами (``max_groups`` 1–8, ``workers`` 1–8)."""
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    raw = cfg.get("geneva", "auto", default={}) or {}

    def num(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(raw.get(key, default))))
        except (TypeError, ValueError):
            return default

    excl = raw.get("exclude") or []
    return {"enabled": bool(raw.get("enabled", False)),
            "help_tunnels": bool(raw.get("help_tunnels", True)),
            "max_groups": num("max_groups", ga.MAX_GROUPS, 1,
                              ga.MAX_GROUPS_LIMIT),
            "workers": num("workers", 4, 1, 8),
            "exclude": [str(x) for x in excl if x][:256]
            if isinstance(excl, list) else []}


class GenevaAutoManager:
    """Режим «Авто». Зависимости подменяются в тестах."""

    def __init__(self, *, observer=None, probes=None, search=None,
                 applier=None, geneva=None, cfg=None, clock=time.time,
                 path: str = "", nat=None):
        self._observer = observer
        self._probes = probes
        self._search = search
        self._applier = applier
        self._geneva = geneva
        self._cfg = cfg
        self._clock = clock
        self._path = path
        self._lock = threading.RLock()
        self._thread = None
        self._stop = threading.Event()
        self.book = ga.Book()
        self.journal = deque(maxlen=JOURNAL_SIZE)
        self.phase = "off"
        self.problems = []
        self._acct_write_failed = False
        self._acct_missing = False
        self.slices = 0
        self.last_slice = {}
        self._trial = None
        self._ok_times = {}
        self._identify_at = {}
        self._applied_sig = None
        self.offload = False
        self._offload_checked = 0
        self._nat = nat
        self._applied_at = 0.0
        self._saved_at = 0.0
        self._dirty = False
        self._search_wait = 0.0
        self._backoff = 0.0
        self._suspended = ""
        self.group_stats = {}

    # ── зависимости ──

    def cfg(self):
        if self._cfg is None:
            from core.config_manager import get_config_manager
            self._cfg = get_config_manager()
        return self._cfg

    def settings(self) -> dict:
        return auto_settings(self.cfg())

    def gm(self):
        if self._geneva is None:
            from core.geneva_manager import get_geneva_manager
            self._geneva = get_geneva_manager()
        return self._geneva

    def observer(self):
        if self._observer is None:
            from core.geneva_auto_observer import Observer
            from core.name_sniffer import get_name_sniffer
            self._observer = Observer(sniffer=get_name_sniffer())
        return self._observer

    def probes(self):
        if self._probes is None:
            from core.geneva_auto_probes import get_auto_probes
            self._probes = get_auto_probes()
        return self._probes

    def applier(self):
        if self._applier is None:
            from core.geneva_auto_apply import Applier
            self._applier = Applier(geneva=self._geneva)
        self._applier.max_groups = self.settings()["max_groups"]
        return self._applier

    def search(self):
        if self._search is None:
            from core.geneva_auto_search import AutoSearch
            self._search = AutoSearch(geneva=self._geneva,
                                      probes=self._probes,
                                      trial=self._trial_cb,
                                      ok_since=self._ok_since)
        self._search.workers = self.settings()["workers"]
        return self._search

    def _path_or_default(self) -> str:
        return self._path or state_path()

    # ── журнал ──

    def note(self, text: str, level: str = "info", en: str = "") -> None:
        item = {"ts": self._clock(), "level": level, "text": text}
        if en:
            item["en"] = en
        self.journal.append(item)
        getattr(log, level if level in ("info", "warning", "error")
                else "info")("geneva-auto: " + text, source="geneva")

    # ── состояние ──

    def load(self) -> None:
        try:
            with open(self._path_or_default(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        items = data.get("services") if isinstance(data, dict) else None
        self.book = ga.Book(items or [], now=self._clock())

    def save(self, force: bool = False) -> None:
        now = self._clock()
        if not force and not self._dirty:
            return
        if not force and now - self._saved_at < SAVE_EVERY:
            return
        data = {"version": 1, "saved_at": now,
                "services": self.book.to_list()}
        try:
            from core.geneva_manager import _write_atomic
            _write_atomic(self._path_or_default(),
                          json.dumps(data, ensure_ascii=False,
                                     separators=(",", ":")))
            self._saved_at = now
            self._dirty = False
        except OSError as e:
            log.warning("geneva-auto: auto.json не записан: %s" % e,
                        source="geneva")

    def _statuses(self) -> dict:
        return {s.key: s.status for s in self.book.services}

    # ── включение ──

    @property
    def running(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive()

    def enable(self, confirm: bool = False) -> dict:
        """Включить режим. Без ``confirm`` — только проверки: если для
        включения нужно переключить движок на geneva или остановить
        одиночный ``geneva run``, ответ ``need_confirm`` с текстом."""
        with self._lock:
            if self.running:
                return {"ok": True, "already": True}
            from core import bypass_engine as be
            gm = self.gm()
            det = gm.detect()
            if not det.get("installed") or not det.get("proto_ok"):
                return {"ok": False, "error_code": "geneva_missing",
                        "error": det.get("hint") or "geneva не установлен"}
            busy = be._nfqws_busy()
            if busy:
                return {"ok": False, "error_code": "busy",
                        "error": "nfqws2 занят: %s" % busy.get("reason", ""),
                        "hint": busy.get("hint", "")}
            try:
                self.observer().check()
            except Exception as e:              # noqa: BLE001
                return {"ok": False,
                        "error_code": getattr(e, "code", "observer"),
                        "error": str(e), "hint": getattr(e, "hint", "")}
            need = []
            if not be.is_geneva_active():
                need.append("engine")
            if gm.is_running():
                need.append("geneva_run")
            if need and not confirm:
                return {"ok": False, "error_code": "need_confirm",
                        "need_confirm": need,
                        "error": "Для режима «Авто» обход переключится на "
                                 "geneva_c: nfqws2 и одиночный geneva run "
                                 "будут остановлены",
                        "error_en": "Auto mode switches bypass to "
                                    "geneva_c: nfqws2 and the single "
                                    "geneva run will be stopped"}
            if "geneva_run" in need:
                gm.stop()
            if "engine" in need:
                res = be.switch("geneva", start=False)
                if not res.get("ok"):
                    return {"ok": False, "error_code": "switch_failed",
                            "error": res.get("error", "")}
            cfg = self.cfg()
            auto = dict(cfg.get("geneva", "auto", default={}) or {})
            auto["enabled"] = True
            cfg.set("geneva", "auto", auto)
            cfg.save()
            self._start()
            self.note("режим включён", en="mode enabled")
            return {"ok": True, "enabled": True}

    def disable(self, reason: str = "") -> dict:
        with self._lock:
            cfg = self.cfg()
            auto = dict(cfg.get("geneva", "auto", default={}) or {})
            auto["enabled"] = False
            cfg.set("geneva", "auto", auto)
            cfg.save()
        self._halt()
        self.note("режим выключен" + (": " + reason if reason else ""),
                  en="mode disabled")
        return {"ok": True, "enabled": False}

    def shutdown(self) -> None:
        """Выход GUI: снять правила и группы, включённость сохранить."""
        if self.running:
            self._halt()

    def boot(self) -> None:
        """Загрузка GUI: поднять режим или снять остатки после сбоя."""
        st = self.settings()
        from core import bypass_engine as be
        if st["enabled"] and be.is_geneva_active():
            try:
                self.observer().check()
            except Exception as e:              # noqa: BLE001
                self.problems = [str(e)]
                self.phase = "error"
                self.note("не поднялся после загрузки: %s" % e, "warning")
                self._cleanup()
                return
            with self._lock:
                self._start()
            self.note("режим поднят после загрузки",
                      en="mode restored after boot")
            return
        self._cleanup()

    def _cleanup(self) -> None:
        """Правила и процессы групп, оставшиеся от прошлого запуска."""
        try:
            from core import geneva_auto_fw
            geneva_auto_fw.remove()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: снятие правил: %s" % e, source="geneva")
        try:
            self.gm().auto_stop_all()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: остановка групп: %s" % e,
                      source="geneva")

    def _start(self) -> None:
        self.load()
        obs = self.observer()
        obs.set_exclude(self.settings()["exclude"])
        obs.help_tunnels = self.settings()["help_tunnels"]
        acct = obs.enable_accounting()
        # Предупреждение — только по данным среза (_check_accounting):
        # на Keenetic NDMS 14.x sysctl нет, а счётчики в таблице есть.
        self._acct_write_failed = acct.get("nf_conntrack_acct") is False
        self._acct_missing = False
        self.problems = []
        obs.seed_keys(s.key for s in self.book.services)
        self.phase = "starting"
        self._applied_sig = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop,
                                        args=(self._stop,),
                                        name="geneva-auto", daemon=True)
        self._thread.start()

    def _halt(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(SLICE + 20)
        try:
            if self._search is not None:
                self._search.cancel()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: отмена подбора: %s" % e, source="geneva")
        with self._lock:
            for s in self.book.services:
                if s.status == ga.SEARCHING:
                    self.book.interrupted(s.key, self._clock())
            self._trial = None
            try:
                self.applier().clear()
            except Exception as e:                  # noqa: BLE001
                log.warning("geneva-auto: снятие групп: %s" % e,
                            source="geneva")
            try:
                self.observer().restore()
            except Exception:                       # noqa: BLE001
                pass
            self.save(force=True)
            self.phase = "off"
            self._thread = None

    # ── пауза на время чужих операций nfqws2 ──

    def suspend(self, owner: str) -> bool:
        """nfqws2 идёт по живой сети: группы снимаются, подбор прерван,
        наблюдение продолжается. ``True`` — режим работал."""
        if not self.running or self._suspended:
            return False
        self._suspended = owner or "?"
        if self._search is not None:
            self._search.cancel()
        with self._lock:
            for s in self.book.services:
                if s.status == ga.SEARCHING:
                    self.book.interrupted(s.key, self._clock())
            self._trial = None
            self.applier().clear()
            self._applied_sig = None
        self.note("пауза: %s" % owner, en="paused: %s" % owner)
        return True

    def resume(self, owner: str = "") -> None:
        if not self._suspended:
            return
        self._suspended = ""
        self._applied_sig = None
        self.note("пауза снята", en="resumed")

    @property
    def suspended(self) -> str:
        return self._suspended

    # ── обратные вызовы подбора ──

    def _ok_since(self, key: str, t: float) -> bool:
        return self._ok_times.get(key, 0.0) >= t

    def _trial_cb(self, service, strategy) -> bool:
        """Пробная группа для подбора (из потока подбора)."""
        with self._lock:
            if self._stop.is_set() or self._suspended:
                # режим выключается или на паузе: прерванный подбор
                # снимает пробную группу — заново применять нельзя,
                # иначе правила пережили бы выключение
                self._trial = None
                return False
            self._trial = (service, strategy) if strategy else None
            services = [s.clone() for s in self.book.services]
            res = self.applier().apply_services(services, trial=self._trial)
            self._applied_sig = self._plan_sig(
                services, self._trial, self.applier().max_groups)
            self._applied_at = self._clock()
            return bool(res.get("trial_ok")) if strategy else True

    # ── цикл ──

    def _loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            wait = SLICE
            try:
                self.tick()
                self._backoff = 0.0
            except Exception as e:                  # noqa: BLE001
                self._backoff = min(MAX_BACKOFF,
                                    max(SLICE, self._backoff * 2 or SLICE))
                wait = self._backoff
                self.phase = "error"
                msg = "срез не удался: %s (повтор через %d с)" % (
                    e, int(wait))
                with self._lock:
                    repeat = bool(self.problems) and self.problems[-1] == msg
                    self.problems = [msg]
                if not repeat:
                    self.note(msg, "warning")
            stop.wait(wait)

    def _check_accounting(self, stats: dict) -> None:
        """Есть ли учёт пакетов — по срезу, а не по sysctl. Предупреждение,
        когда в таблице есть соединения, но ни у одного нет ``packets=``;
        снимается, как только счётчики появились."""
        total = int(stats.get("connections", 0) or 0)
        if not total or "counted" not in stats:
            return
        missing = int(stats.get("counted", 0) or 0) == 0
        msg = ACCT_PROBLEM + (" (запись nf_conntrack_acct=1 не прошла)"
                              if self._acct_write_failed else "") + \
            ": зависания соединений не видны"
        with self._lock:
            rest = [p for p in self.problems
                    if not p.startswith(ACCT_PROBLEM)]
            self.problems = rest + [msg] if missing else rest
            became = missing and not self._acct_missing
            self._acct_missing = missing
        if became:
            self.note(msg, "warning",
                      en="conntrack has no packet counters: stalled "
                         "connections are not visible")

    def tick(self, now: float = None) -> None:
        """Одна итерация цикла (тесты зовут её напрямую)."""
        now = self._clock() if now is None else now
        obs = self.observer()
        samples = obs.slice(now)
        with self._lock:
            before = self._statuses()
            self.slices += 1
            self.last_slice = dict(obs.last_stats or {})
            for x in samples:
                if x.health == ga.OK:
                    self._ok_times[x.key] = max(
                        self._ok_times.get(x.key, 0.0), x.time)
            self.book.feed(samples, now)
            for line in self.book.evaluate(now):
                self.note(line)
            if len(self._ok_times) > 4 * ga.MAX_SERVICES:
                keep = {s.key for s in self.book.services}
                self._ok_times = {k: v for k, v in self._ok_times.items()
                                  if k in keep}
                self._identify_at = {k: v for k, v in
                                     self._identify_at.items() if k in keep}
            self._learn(obs, now)
        self._check_accounting(obs.last_stats or {})
        # вне замка: на Keenetic это запуск ndmc
        self._check_offload()
        if self.phase in ("starting", "error"):
            self.phase = "watching"
            with self._lock:
                self.problems = [p for p in self.problems
                                 if not p.startswith("срез не удался")]
        if not self._suspended:
            self._confirm(now)
            self._searching(now)
            self._apply(now)
            self._poll_stats()
        else:
            self.phase = "suspended"
        with self._lock:
            if self._statuses() != before:
                self._dirty = True
                self.save(force=True)
            else:
                # счётчики и адреса поменялись — запись не чаще раза в
                # минуту; пустой срез флеш не трогает
                self._dirty = self._dirty or bool(samples)
                self.save()

    def _learn(self, obs, now: float) -> None:
        for res in obs.identified():
            key = res.get("key", "")
            if res.get("app"):
                s = self.book.find(key)
                self.book.learn(key, app=res["app"],
                                replay=res.get("replay") or None,
                                host=res.get("host", ""))
                if s is not None:
                    self.note("%s: протокол %s" % (s.name,
                                                   ga.app_title(res["app"])))
        if obs.busy:
            return
        cands = [s for s in self.book.services
                 if s.status in (ga.SUSPECTED, ga.BLOCKED)
                 and s.kind in (ga.ENDPOINT, ga.LOCAL_PORT)
                 and s.app in UNKNOWN_APPS
                 and (s.key not in self._identify_at or
                      now - self._identify_at[s.key] > IDENTIFY_RETRY)]
        if not cands:
            return
        s = cands[0]
        self._identify_at[s.key] = now
        obs.identify_async(s.key, s.address, s.port, s.transport,
                           local_port=s.local_port
                           if s.kind == ga.LOCAL_PORT else 0,
                           client=s.client)

    def _confirm(self, now: float) -> None:
        with self._lock:
            s = self.book.next_to_confirm(now)
            s = s.clone() if s is not None else None
        if s is None:
            return
        self.phase = "confirming"
        if s.probeable:
            result, text = self.probes().check(
                s, through_bypass=s.status == ga.DEGRADED)
        else:
            result, text = ga.C_UNKNOWN, "проверить пробой нельзя"
        with self._lock:
            line = self.book.confirmed(s.key, result, now)
        if line:
            self.note("%s (%s)" % (line, text) if text else line)
        self.phase = "watching"

    def _searching(self, now: float) -> None:
        search = self.search()
        if search.busy:
            self.phase = "searching"
            return
        res = search.result()
        with self._lock:
            if res is not None:
                self._trial = None
                self._take(res, now)
            if now < self._search_wait:
                return
            s = self.book.next_to_search(now)
            if s is None:
                return
            running = [g.strategy for g in self.applier().queues.values()]
            proven = self._proven(s.key)
            snap = s.clone()
            self.book.searching(s.key, now)
            self._dirty = True
        if search.start(snap, running, proven):
            self.phase = "searching"
            self.note("%s: подбор стратегии" % snap.name,
                      en="%s: searching" % snap.name)
        else:
            with self._lock:
                self.book.interrupted(snap.key, now)

    def _take(self, res, now: float) -> None:
        from core import geneva_auto_search as gs
        s = self.book.find(res.key)
        name = s.name if s else res.key
        if res.outcome == gs.APPLIED:
            self.book.applied(res.key, res.strategy, res.fitness, now)
            self.note("%s: обход найден: %s" % (name, res.strategy), "info",
                      en="%s: bypass found" % name)
            self._applied_sig = None
            woken = self.book.wake_not_found(res.strategy, now)
            if woken:
                self.note("новая рабочая стратегия: повторный подбор для "
                          "«не найдено» без ожидания (%d)" % woken,
                          en="new working strategy: retrying %d not-found "
                          "services now" % woken)
        elif res.outcome == gs.NOT_FOUND:
            self.book.not_found(res.key, now)
            self.note("%s: обход не найден (%s)" % (name, res.detail),
                      "warning", en="%s: no bypass yet" % name)
        elif res.outcome == gs.NOT_BLOCKED:
            self.book.confirmed(res.key, ga.C_NOT_BLOCKED, now)
            self.note("%s: без стратегии открылось" % name)
        else:
            self.book.interrupted(res.key, now)
            self._search_wait = now + (
                SEARCH_WAIT_BUSY if res.outcome == gs.BUSY
                else SEARCH_WAIT_ERROR if res.outcome == gs.ERROR else 0)
            if res.outcome == gs.ERROR:
                self.note("%s: подбор не удался: %s" % (name, res.detail),
                          "warning")
            elif res.outcome == gs.BUSY:
                self.note("%s: подбор ждёт (%s)" % (name, res.detail))
        self._dirty = True

    @staticmethod
    def _plan_sig(services, trial=None, max_groups=ga.MAX_GROUPS) -> str:
        # С пробной группой: план без неё и план с ней — разные правила,
        # и смена пробы без смены книги должна применяться сразу. Предел
        # групп — как у Applier: иначе группы сверх 4 не попадали в
        # подпись, и их смена ждала повтора раз в 120 с.
        groups = ga.plan_groups(services, trial=trial, max_groups=max_groups)
        return json.dumps([g.to_dict() for g in groups], sort_keys=True)

    def _check_offload(self) -> None:
        """Ускорение NAT: раз в 20 срезов (и сразу, если в срезе есть
        потоки ``[OFFLOAD]``) — предупреждение в ``problems`` и журнал."""
        seen = int(self.last_slice.get("offload", 0) or 0) > 0
        if not seen and self.slices - self._offload_checked < 20 and \
                self._offload_checked:
            return
        self._offload_checked = self.slices or 1
        try:
            from core.geneva_auto_observer import offload_enabled
            on = offload_enabled(self.last_slice) if seen else \
                self._offload_config()
        except Exception:                           # noqa: BLE001
            on = False
        if on and not self.offload:
            from core.geneva_auto_observer import (OFFLOAD_TEXT,
                                                   OFFLOAD_TEXT_EN)
            self.note(OFFLOAD_TEXT, "warning", en=OFFLOAD_TEXT_EN)
        self.offload = on

    def _offload_config(self) -> bool:
        """Ускорение включено в настройках роутера (OpenWrt/Keenetic)."""
        if self._nat is None:
            from core.nat_offload import get_nat_offload
            self._nat = get_nat_offload()
        return bool(self._nat.status().get("enabled"))

    def recheck_offload(self) -> None:
        """После переключения на странице: без ожидания 20 срезов."""
        self._offload_checked = 0
        if self.running:
            self._check_offload()
        else:
            self.offload = False

    def _apply(self, now: float) -> None:
        with self._lock:
            services = [s.clone() for s in self.book.services]
            sig = self._plan_sig(services, self._trial,
                                 self.applier().max_groups)
            if sig == self._applied_sig and \
                    now - self._applied_at < APPLY_EVERY:
                return
            res = self.applier().apply_services(services, trial=self._trial)
            self._applied_sig = sig
            self._applied_at = now
        if not res.get("ok") and res.get("hint"):
            # Нет ipset/connbytes/nft — это не пройдёт само: режим
            # выключается с понятной причиной, а не повторяет попытку.
            msg = "%s — %s" % (res.get("error", ""), res.get("hint", ""))
            with self._lock:
                self.problems = [msg]
            self.note("правила firewall не встали: %s" % msg, "error")
            threading.Thread(target=self.disable, args=(msg,),
                             daemon=True).start()
        elif not res.get("ok") and res.get("error"):
            with self._lock:
                self.problems = [res["error"]]

    def _poll_stats(self) -> None:
        try:
            self.group_stats = self.applier().stats()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: stats: %s" % e, source="geneva")

    # ── снаружи ──

    def reset(self, key: str) -> dict:
        with self._lock:
            s = self.book.find(key)
            if s is None:
                return {"ok": False, "error_code": "not_found",
                        "error": "сервиса нет: %s" % key}
            if s.status == ga.SEARCHING and self._search is not None:
                self._search.cancel()
            self.book.reset(key, self._clock())
            self._applied_sig = None
            self._dirty = True
            self.save(force=True)
        self.note("%s: сброшен вручную" % s.name, en="%s: reset" % s.name)
        return {"ok": True, "key": key}

    def status(self, all_services: bool = False) -> dict:
        with self._lock:
            st = self.settings()
            items = []
            for s in self.book.snapshot():
                if not all_services and s.status in (ga.WATCHING,
                                                     ga.NOT_BLOCKED):
                    continue
                d = s.to_dict()
                d.pop("replay", None)
                d.pop("fails", None)
                d.pop("oks", None)
                d.pop("no_connections", None)
                d["fails_count"] = len(s.fails) + len(s.no_connections)
                d["oks_count"] = len(s.oks)
                d["status_text"], d["status_text_en"] = \
                    ga.STATUS_TEXT.get(s.status, (s.status, s.status))
                items.append(d)
            groups = []
            last = (self._applier.last if self._applier else {}) or {}
            for q, info in sorted((last.get("queues") or {}).items()):
                g = dict(info, queue=q)
                g.update({k: v for k, v in
                          (self.group_stats.get(q) or {}).items()
                          if k in ("stats", "rate")})
                groups.append(g)
            search = {}
            if self._search is not None:
                search = self._search.progress()
                search["running"] = self._search.busy
            return {
                "enabled": st["enabled"], "running": self.running,
                "phase": self.phase, "suspended": self._suspended,
                "slices": self.slices,
                "connections": int(self.last_slice.get("connections", 0)),
                "observed": int(self.last_slice.get("observed", 0)),
                "counts": self.book.counts(),
                "total": len(self.book.services),
                "services": items, "groups": groups, "search": search,
                "problems": list(self.problems),
                "offload": self.offload,
                "max_groups": st["max_groups"], "workers": st["workers"],
                "journal": list(self.journal)[-100:],
            }

    def services_snapshot(self) -> list:
        """Сервисы книги: из памяти, если режим работает, иначе из
        ``auto.json`` (страница «Стратегии» видна и при выключенном
        режиме — найденное не пропадает)."""
        with self._lock:
            if self.running or self.book.services:
                return [s.clone() for s in self.book.services]
        try:
            with open(self._path_or_default(), "r",
                      encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        items = data.get("services") if isinstance(data, dict) else None
        return [ga.Service.from_dict(x) for x in items or []
                if isinstance(x, dict)]

    def found(self) -> dict:
        """Рабочие стратегии этой сети: «Авто» + ручной подбор."""
        db = {}
        try:
            db = self.gm().db_top("", 50) or {}
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: db_top: %s" % e, source="geneva")
        working = str(self.cfg().get("geneva", "strategy",
                                     default="") or "")
        items = ga.found_strategies(self.services_snapshot(),
                                    db.get("items") or [], working)
        have = {r["strategy"] for r in items}
        for imp in self.imports().load():
            if imp["strategy"] in have:
                continue
            items.append({"strategy": imp["strategy"], "imported": True,
                          "services": [{"name": n} for n in
                                       imp.get("services") or []],
                          "targets": [], "auto": False, "degraded": 0,
                          "fitness": None,
                          "last": float(imp.get("imported_at") or 0),
                          "working": imp["strategy"] == working.strip()})
        return {"ok": True, "items": items, "working": working,
                "auto_enabled": self.settings()["enabled"]}

    # ── обмен найденными стратегиями ──

    def _proven(self, skip_key: str = "") -> list:
        """Проверенные кандидаты по рангу: работающие у других сервисов
        (больше сервисов — раньше), затем импортированные."""
        services = [s for s in self.book.services if s.key != skip_key]
        out = [r["strategy"] for r in ga.found_strategies(services, [], "")]
        out += [i["strategy"] for i in self.imports().load()
                if i["strategy"] not in out]
        return out

    def imports(self):
        from core.geneva_share import ImportStore
        path = os.path.join(os.path.dirname(self._path_or_default()),
                            "auto", "imported.json")
        return ImportStore(path, clock=self._clock)

    def export_found(self) -> dict:
        from core.geneva_share import build_export
        rows = [r for r in self.found()["items"] if not r.get("imported")]
        return build_export(rows, self._clock())

    def import_strategies(self, payload) -> dict:
        from core.geneva_share import parse_import
        rows, errors = parse_import(payload)
        if not rows:
            return {"ok": False, "error_code": "nothing_to_import",
                    "error": "; ".join(errors[:5]) or
                    "в файле нет стратегий", "errors": errors}
        res = self.imports().add(rows)
        self.note("импортировано стратегий: %d (новых %d)"
                  % (len(rows), res["added"]),
                  en="imported strategies: %d (new %d)"
                  % (len(rows), res["added"]))
        return {"ok": True, "accepted": len(rows), "added": res["added"],
                "total": res["total"], "errors": errors}

    def remove_imported(self, strategy: str) -> dict:
        if not self.imports().remove(str(strategy or "").strip()):
            return {"ok": False, "error_code": "not_found",
                    "error": "такой импортированной стратегии нет"}
        return {"ok": True}

    def summary(self) -> dict:
        """Коротко для ``bypass_engine.overview``."""
        counts = self.book.counts()
        return {"enabled": self.settings()["enabled"],
                "running": self.running, "phase": self.phase,
                "applied": counts.get(ga.APPLIED, 0) +
                counts.get(ga.DEGRADED, 0),
                "searching": counts.get(ga.SEARCHING, 0),
                "blocked": counts.get(ga.BLOCKED, 0)}


_instance = None
_instance_lock = threading.Lock()


def get_geneva_auto_manager() -> GenevaAutoManager:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = GenevaAutoManager()
        return _instance


def auto_enabled() -> bool:
    """Включён ли режим (для отказов одиночного run и ручного подбора)."""
    try:
        return auto_settings()["enabled"]
    except Exception:                               # noqa: BLE001
        return False
