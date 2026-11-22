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
import math
import os
import threading
import time
from collections import deque

from core import geneva_auto as ga
from core import geneva_auto_lists as gal
from core.log_buffer import log

SLICE = 15.0
APPLY_EVERY = 120.0
SAVE_EVERY = 60.0
MAX_BACKOFF = 300.0
LOST_NOTE_EVERY = 1800.0        # «правила снесены» в журнал — не чаще
# Предупреждение об учёте пакетов: ставится и снимается по срезу.
ACCT_PROBLEM = "в таблице conntrack нет счётчиков пакетов"
# Детектору geneva нужен NFLOG (nfnetlink_log); его нет — режим работает
# без подозрений по потокам. Строка в problems одна на сеанс режима.
DETECTOR_PROBLEM_NO_NFLOG = ("детектор geneva не работает: в ядре нет "
                             "модуля NFLOG (nfnetlink_log)")
# Повторная попытка поднять упавший детектор — не чаще раза в 5 минут:
# срез каждые 15 с, а «не запустился» — это не одно и то же событие.
DETECTOR_RETRY = 300.0
JOURNAL_SIZE = 300
IDENTIFY_RETRY = 3600.0
SEARCH_WAIT_BUSY = 60.0         # слот geneva занят ручным подбором
SEARCH_WAIT_ERROR = 300.0
BASELINE_FRESH = 300.0          # «заблокирован» без обхода свежее этого
UNKNOWN_APPS = ("", "tcp", "udp", "p2p")
ASN_CHECK_EVERY = 6 * 3600.0    # сети AS: проверка свежести раз в 6 ч
MAX_SEARCHES = 4                # подборов рядом (GenevaArgv.MaxSearches)

PHASES = ("off", "starting", "watching", "confirming", "searching",
          "suspended", "error")


def state_path() -> str:
    from core.geneva_manager import state_dir
    return os.path.join(state_dir(), "auto.json")


def auto_settings(cfg=None) -> dict:
    """``geneva.auto`` с пределами (``max_groups`` 1–8, ``workers`` 1–64)."""
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
    lists = raw.get("lists") if isinstance(raw.get("lists"), dict) else {}
    return {"enabled": bool(raw.get("enabled", False)),
            "help_tunnels": bool(raw.get("help_tunnels", True)),
            "max_groups": num("max_groups", ga.MAX_GROUPS, 1,
                              ga.MAX_GROUPS_LIMIT),
            # --ext-workers geneva_c: 1–64 (у eval свой предел, 32)
            "workers": num("workers", 4, 1, ga.ENGINE_WORKERS_MAX),
            # «Как делить потоки»: выкл — один сервис за раз со всеми
            # потоками, вкл — до 4 сервисов рядом, потоки делятся
            "split_workers": bool(raw.get("split_workers", False)),
            # стратегии сайтов ещё и по имени (geneva_c 2.0)
            "by_name": bool(raw.get("by_name", True)),
            # итоговая проверка (связанные ресурсы сайта) — общая с
            # ручным подбором: geneva.final_check
            "final_check": final_check_enabled(cfg),
            "exclude": [str(x) for x in excl if x][:gal.MAX_ENTRIES]
            if isinstance(excl, list) else [],
            "lists": {
                "important": _str_list(lists.get("important")),
                "unimportant": _str_list(lists.get("unimportant")),
                "no_search": _str_list(lists.get("no_search")),
                "known_important": bool(lists.get("known_important",
                                                  True))}}


def final_check_enabled(cfg=None) -> bool:
    """Итоговая проверка найденного (``geneva.final_check``, по
    умолчанию включена): «Авто» — связанные ресурсы сайта, ручной
    подбор — лучшие найденные на сайте и его ресурсах."""
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    v = cfg.get("geneva", "final_check", default=True)
    return v if isinstance(v, bool) else True


def _str_list(v) -> list:
    return [str(x) for x in v if x][:gal.MAX_ENTRIES] \
        if isinstance(v, list) else []


def _addresses(entries) -> list:
    """Голые адреса из «Не трогать» — наблюдателю (подсети и домены
    отсеивает книга)."""
    import ipaddress
    out = []
    for e in entries or []:
        try:
            out.append(str(ipaddress.ip_address(str(e).strip())))
        except ValueError:
            continue
    return out


def asn_path() -> str:
    from core.geneva_manager import state_dir
    return os.path.join(state_dir(), "auto", "asn.json")


def slot_workers(workers: int, split: bool) -> int:
    """Потоков одному подбору: при делении ``потоки / мест`` (мест —
    ``min(потоки, 4)``), сумма не больше заданного, когда бы подбор ни
    начался. Не больше 2: блок портов слота — 128."""
    workers = max(1, int(workers or 1))
    if not split:
        return workers
    return max(1, min(2, workers // min(workers, MAX_SEARCHES)))


def _nflog_fix() -> dict:
    """Подсказка «как включить NFLOG» для карточки «Авто».

    Ленивая и молчаливая: на платформах, где модуль ядра пакетом не
    ставится (Keenetic, ПК), кнопки не будет — там ответ
    ``can_auto_install: False`` и текстовая инструкция.
    """
    try:
        from core.kmod_manager import nflog_fix_hint
        return nflog_fix_hint()
    except Exception:                               # noqa: BLE001
        return {}


class GenevaAutoManager:
    """Режим «Авто». Зависимости подменяются в тестах."""

    def __init__(self, *, observer=None, probes=None, search=None,
                 applier=None, geneva=None, cfg=None, clock=time.time,
                 path: str = "", nat=None, search_factory=None,
                 asn_fetch=None):
        self._observer = observer
        self._probes = probes
        self._search = search
        self._search_factory = search_factory
        self._searches = {}          # слот → AutoSearch
        self._works = {}             # ключ сервиса → {"slot", "split", "custom"}
        self._trials = {}            # ключ сервиса → (Service, стратегия)
        # пробы, у которых идёт итоговая проверка связанных ресурсов, и
        # домены, ушедшие процессу «по имени» с последним применением
        self._related = set()
        self._related_sent = {}
        self._asn_fetch = asn_fetch
        self._asn = None             # {"prefixes": {n: [...]}, "fetched": {n: t}}
        self._asn_thread = None
        self._asn_checked = 0.0
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
        self._apply_failures = 0
        self.rules_lost = 0              # сколько раз правила сносили извне
        self._lost_noted_at = None
        self._lost_unnoted = 0
        self.host_state = {}             # процесс «по имени» (HOST_QUEUE)
        self.detector = {}               # детектор geneva (OBSERVE_QUEUE)
        self._detector_error = ""
        self._detector_retry = 0.0       # раньше этого времени не перезапускаем
        self._nflog_noted = False        # «нет NFLOG» в журнал — один раз

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
        st = self.settings()
        self._applier.max_groups = st["max_groups"]
        # у профилей «потоков» столько же, сколько потоков у процесса
        self._applier.workers = st["workers"]
        return self._applier

    def search(self, slot: int = 0):
        """Подбор слота (0 — общий с ручным подбором)."""
        st = self.settings()
        if slot == 0 and self._search is not None:
            obj = self._search
        else:
            obj = self._searches.get(slot)
            if obj is None:
                if self._search_factory is not None:
                    obj = self._search_factory(slot)
                else:
                    from core.geneva_auto_search import AutoSearch
                    obj = AutoSearch(geneva=self._geneva,
                                     probes=self._probes,
                                     trial=self._trial_cb,
                                     ok_since=self._ok_since, slot=slot,
                                     related=self._related_cb)
                if slot == 0:
                    self._search = obj
                else:
                    self._searches[slot] = obj
        # деление потоков и число воркеров — на весь подбор: на лету
        # блоки портов идущих подборов разъехались бы и пересеклись
        if not getattr(obj, "busy", False):
            obj.workers = slot_workers(st["workers"], st["split_workers"])
            if hasattr(obj, "split"):
                obj.split = st["split_workers"]
        if hasattr(obj, "final_check"):
            obj.final_check = st["final_check"]
        return obj

    def _retune_searches(self) -> None:
        """Новые «потоки» и «делить потоки» — свободным слотам; идущий
        подбор доживает с прежними (иначе блоки портов пересекутся),
        :meth:`search` обновит его, когда он закончит."""
        for slot in [0] + sorted(self._searches):
            if slot == 0 and self._search is None:
                continue
            self.search(slot)

    def _all_searches(self) -> list:
        out = [self._search] if self._search is not None else []
        return out + [x for _, x in sorted(self._searches.items())]

    def _cancel_all(self) -> None:
        for x in self._all_searches():
            try:
                x.cancel()
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: отмена подбора: %s" % e,
                          source="geneva")
        self._works = {}

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
        self.book = ga.Book(items or [], now=self._clock(),
                            lists=self.lists())

    # ── списки пользователя ──

    def _asn_store(self) -> dict:
        if self._asn is None:
            try:
                with open(self._asn_file(), "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                data = {}
            data = data if isinstance(data, dict) else {}
            pre = data.get("prefixes")
            fet = data.get("fetched")
            self._asn = {"prefixes": pre if isinstance(pre, dict) else {},
                         "fetched": fet if isinstance(fet, dict) else {}}
        return self._asn

    def _asn_file(self) -> str:
        if self._path:
            return os.path.join(os.path.dirname(self._path), "asn.json")
        return asn_path()

    def lists(self) -> gal.Lists:
        """Списки из настроек и сети AS (``asn.json``)."""
        st = self.settings()
        raw = dict(st["lists"], exclude=st["exclude"])
        return gal.Lists(raw, self._asn_store()["prefixes"])

    def _apply_lists(self, why: str = "") -> None:
        """Новые списки — в книгу и наблюдателю; ушедшие — в журнал,
        подборы ушедших отменяются."""
        lists = self.lists()
        with self._lock:
            gone, skipped = self.book.set_lists(lists)
            stop = [k for k in self._works
                    if self.book.find(k) is None or
                    lists.no_search.matches(self.book.find(k)) or
                    lists.exclude.matches(self.book.find(k))]
            self._applied_sig = None
            self._dirty = True
        if self._observer is not None or self.running:
            self.observer().set_exclude(_addresses(lists.raw["exclude"]))
        for key in stop:
            self._cancel_work(key)
        if gone:
            self.note("«Не трогать»: убраны из режима — %s"
                      % ", ".join(gone[:10]),
                      en="never touch: removed from the mode — %s"
                      % ", ".join(gone[:10]))
        if skipped:
            self.note("«Не подбирать»: убраны из проблем — %s"
                      % ", ".join(skipped[:10]),
                      en="do not search: removed from problems — %s"
                      % ", ".join(skipped[:10]))

    def _refresh_asn(self, force: bool = False) -> bool:
        """Сети AS из списков, которых нет или они старше недели, —
        фоном (сеть). ``True`` — загрузка началась."""
        t = self._asn_thread
        if t is not None and t.is_alive():
            return False
        lists = self.lists()
        now = self._clock()
        todo = gal.stale_asns(lists, self._asn_store()["fetched"], now)
        if not todo:
            return False
        self._asn_thread = threading.Thread(
            target=self._fetch_asns, args=(todo,), daemon=True,
            name="geneva-auto-asn")
        self._asn_thread.start()
        return True

    def _fetch_asns(self, todo) -> None:
        fetch = self._asn_fetch or gal.fetch_asn
        got = {}
        for n in todo[:20]:
            try:
                got[str(n)] = fetch(n)
            except Exception as e:                  # noqa: BLE001
                self.note("сети AS%d не загружены: %s" % (n, e), "warning",
                          en="AS%d networks not loaded" % n)
        if not got:
            return
        with self._lock:
            store = self._asn_store()
            now = self._clock()
            # слить с тем, что за время загрузки поменялось
            for n, nets in got.items():
                store["prefixes"][n] = list(nets)
                store["fetched"][n] = now
            keep = {str(n) for n in self.lists().asns()}
            for k in list(store["prefixes"]):
                if k not in keep:
                    store["prefixes"].pop(k, None)
                    store["fetched"].pop(k, None)
            try:
                from core.geneva_manager import _write_atomic
                _write_atomic(self._asn_file(), json.dumps(
                    store, separators=(",", ":")))
            except OSError as e:
                log.warning("geneva-auto: asn.json не записан: %s" % e,
                            source="geneva")
        self.note("сети AS загружены: %s" % ", ".join(
            "AS%s (%d)" % (n, len(v)) for n, v in got.items()),
            en="AS networks loaded: %s" % ", ".join(
                "AS%s (%d)" % (n, len(v)) for n, v in got.items()))
        self._apply_lists()

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
            if be._jobs_busy(gm) and not gm.job_running():
                return {"ok": False, "error_code": "geneva_final",
                        "error": "идёт итоговая проверка найденного — "
                                 "подождите минуту-две"}
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
            from core.geneva_manager import stop_slot_leftovers
            stop_slot_leftovers()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: слоты подбора: %s" % e, source="geneva")
        try:
            self.gm().auto_stop_all()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: остановка групп: %s" % e,
                      source="geneva")
        self._stop_detector()

    def _stop_detector(self) -> None:
        stop = getattr(self.gm(), "auto_observer_stop", None)
        if stop is None:
            return
        try:
            stop()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: детектор: %s" % e, source="geneva")
        self.detector = {}

    def _start(self) -> None:
        self.load()
        obs = self.observer()
        obs.set_exclude(_addresses(self.settings()["exclude"]))
        obs.help_tunnels = self.settings()["help_tunnels"]
        acct = obs.enable_accounting()
        # Предупреждение — только по данным среза (_check_accounting):
        # на Keenetic NDMS 14.x sysctl нет, а счётчики в таблице есть.
        self._acct_write_failed = acct.get("nf_conntrack_acct") is False
        self._acct_missing = False
        self._detector_error = ""
        self._detector_retry = 0.0
        self._nflog_noted = False
        self.problems = []
        # «Детектор недоступен» помнится до конца сеанса режима: смотрим
        # только на этот сеанс, а не на то, что было в прошлом.
        reset = getattr(self.gm(), "auto_observer_reset", None)
        if reset is not None:
            try:
                reset()
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: сброс детектора: %s" % e,
                          source="geneva")
        obs.seed_keys(s.key for s in self.book.services)
        self._refresh_asn()
        self.phase = "starting"
        self._applied_sig = None
        self._works = {}
        self._trials = {}
        self._related = set()
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
        self._cancel_all()
        with self._lock:
            for s in self.book.services:
                if s.status == ga.SEARCHING:
                    self.book.interrupted(s.key, self._clock())
            self._trial = None
            self._trials = {}
            self._related = set()
            try:
                self.applier().clear()
            except Exception as e:                  # noqa: BLE001
                log.warning("geneva-auto: снятие групп: %s" % e,
                            source="geneva")
            try:
                self.observer().restore()
            except Exception:                       # noqa: BLE001
                pass
            self._stop_detector()
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
        self._cancel_all()
        with self._lock:
            for s in self.book.services:
                if s.status == ga.SEARCHING:
                    self.book.interrupted(s.key, self._clock())
            self._trial = None
            self._trials = {}
            self._related = set()
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
        """Пробная группа для подбора (из потока подбора). Подборы рядом
        держат каждый свою пробу: все они в плане первыми."""
        with self._lock:
            if self._stop.is_set() or self._suspended:
                # режим выключается или на паузе: прерванный подбор
                # снимает пробную группу — заново применять нельзя,
                # иначе правила пережили бы выключение
                self._trials.pop(service.key, None)
                self._related.discard(service.key)
                self._trial = None
                return False
            if strategy:
                self._trials[service.key] = (service, strategy)
            else:
                self._trials.pop(service.key, None)
                self._related.discard(service.key)
            self._trial = next(iter(self._trials.values()), None)
            trials = list(self._trials.values())
            services = [s.clone() for s in self.book.services]
            res = self._apply_plan(services, trials, self._clock())
            if not strategy:
                return True
            return bool((res.get("trials_ok") or {}).get(service.key))

    def _related_cb(self, service, strategy):
        """Итоговая проверка связанных ресурсов (из потока подбора):
        пробная стратегия ``strategy`` по имени и на семейство сайта
        (:func:`core.geneva_related.trial_families`). Ответ — имена для
        проверки и pid процесса «по имени»; ``None`` — процесса нет или
        домены не ушли. ``strategy=None`` снимает и отвечает pid до
        снятия и номер запуска процесса ``gen`` (перезапуск за время
        проверки — не вина стратегии)."""
        from core import geneva_related as grel
        with self._lock:
            if not strategy:
                pid, gen = None, None
                try:
                    pid = self.gm().auto_host_pid()
                    gen = self.gm().auto_host_generation()
                except Exception:                   # noqa: BLE001
                    pass
                if service.key in self._related:
                    self._related.discard(service.key)
                    if not self._stop.is_set() and not self._suspended:
                        services = [s.clone() for s in self.book.services]
                        self._apply_plan(services,
                                         list(self._trials.values()),
                                         self._clock())
                return {"pid": pid, "gen": gen}
            if self._stop.is_set() or self._suspended or \
                    service.key not in self._trials:
                return None
            self._related.add(service.key)
            services = [s.clone() for s in self.book.services]
            try:
                res = self._apply_plan(services,
                                       list(self._trials.values()),
                                       self._clock())
            except Exception:
                # проба на семейство не осталась бы до конца подбора
                self._related.discard(service.key)
                raise
            domains = list(self._related_sent.get(service.key) or ())
            pid = (res.get("host") or {}).get("pid")
            try:
                gen = self.gm().auto_host_generation()
            except Exception:                       # noqa: BLE001
                gen = None
            if not domains or not pid:
                return {"pid": pid, "gen": gen, "hosts": []}
            host = service.host or service.name
            hosts = grel.hosts_to_check(domains, grel.seen_hosts(services),
                                        own=host)
            return {"pid": pid, "gen": gen, "hosts": hosts,
                    "exclude": self.book.lists.exclude}

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
        if now - self._asn_checked >= ASN_CHECK_EVERY:
            self._asn_checked = now
            self._refresh_asn()
        if not self._suspended:
            self._detector(now)
            self._check_rules(now)
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

    def _drop_problem(self, prefix: str) -> None:
        """Убрать из ``problems`` строки, начинающиеся с ``prefix``."""
        with self._lock:
            rest = [p for p in self.problems if not p.startswith(prefix)]
            changed = len(rest) != len(self.problems)
            self.problems = rest
        if changed:
            self._dirty = True

    def _detector_off(self, r: dict, now: float) -> None:
        """Детектор не поднялся (или поднимать нечего) — что сообщить.

        Три разных случая, и путать их нельзя:
          • ``unsupported`` — движок geneva 1.x без фичи ``ext_auto``:
            детектора нет вовсе, это норма, молчим;
          • ``no_nflog`` — ядро без ``nfnetlink_log``: одной строкой в
            журнал и в ``problems``, с повтором только при следующем
            включении режима (повторный запуск каждые 15 с ничего не
            изменит — подсистема ядра не появится сама);
          • ``crash`` и прочее — настоящая беда: в журнал при смене
            вида отказа, перезапуск не чаще раза в ``DETECTOR_RETRY``.
        """
        reason = r.get("reason") or ("unsupported"
                                     if r.get("action") == "unsupported"
                                     else "crash")
        supported = reason != "unsupported"
        self.detector = {"running": False, "supported": supported,
                         "reason": reason}
        if not supported:
            return
        if reason == "no_nflog":
            self.detector["problem"] = DETECTOR_PROBLEM_NO_NFLOG
            # Про кнопку говорим только там, где она есть: на Keenetic и
            # на ПК модуль пакетом не ставится, и «нажмите кнопку» было бы
            # ложью. Инструкцию для таких платформ рисует карточка.
            hint = _nflog_fix()
            tail = (" — модуль ставится кнопкой на этой странице"
                    if hint.get("can_auto_install") else "")
            text = (DETECTOR_PROBLEM_NO_NFLOG +
                    " — режим работает без подозрений по потокам" + tail)
            with self._lock:
                if text not in self.problems:
                    self.problems = self.problems + [text]
                    self._dirty = True
            if not self._nflog_noted:
                self._nflog_noted = True
                self.note(text, "warning",
                          en="geneva's detector is off: the kernel has no "
                             "NFLOG (nfnetlink_log) module")
            return
        # Ключ дедупликации — причина, а не хвост лога: в хвосте метки
        # времени, и с ними каждая строка выглядит новой.
        key = "%s: %s" % (reason, self._detector_reason_text(r))
        if key != self._detector_error:
            self._detector_error = key
            tail = self._detector_reason_text(r)
            self.note("детектор geneva не запустился: %s" % tail,
                      "warning")
        self._detector_retry = now + DETECTOR_RETRY

    def _detector_reason_text(self, r: dict) -> str:
        """Причина отказа без меток времени из хвоста лога geneva."""
        text = str(r.get("error") or "")
        if not text:
            return "неизвестно"
        parts = []
        for line in text.split(" | "):
            line = line.strip()
            if not line:
                continue
            # «2026-11-21 17:25:13.768 error engine: …» → «error engine: …»
            bits = line.split(None, 3)
            if len(bits) == 4 and bits[0][:2] == "20" and ":" in bits[1]:
                line = bits[2] + " " + bits[3]
            parts.append(line)
        return " | ".join(parts[-2:])

    def _detector(self, now: float) -> None:
        """Детектор geneva (``--ext-auto observe``, фича ``ext_auto``):
        раз в срез ``ext_status``. ``THROTTLE`` и ``FREEZE_N`` у имени
        или адреса — подозрение сервиса; ``capacity`` — ёмкость канала
        для полки шейпера; ``DNS_POISON`` у имени — совет включить DoH
        (раз в час на имя). Трафик детектор не меняет.

        Недоступен — это одно событие, а не поток: «нет модуля NFLOG»
        пишется в журнал и в ``problems`` ОДИН раз (ключ дедупликации —
        вид отказа, без хвоста лога с его метками времени)."""
        gm = self.gm()
        ensure = getattr(gm, "auto_observer_ensure", None)
        if ensure is None:
            return
        pid_of = getattr(gm, "auto_observer_pid", None)
        pid = pid_of() if pid_of is not None else None
        if pid is None and self._detector_retry and now < self._detector_retry:
            return
        try:
            r = ensure()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: детектор: %s" % e, source="geneva")
            return
        if not isinstance(r, dict):
            return
        if not r.get("pid"):
            self._detector_off(r, now)
            return
        self._detector_error = ""
        self._detector_retry = 0.0
        if self._nflog_noted:
            # Модуль поставили кнопкой — детектор поднялся: снимаем строку
            # проблемы и готовы сообщить снова, если он опять упадёт.
            self._nflog_noted = False
            self._drop_problem("детектор geneva не работает")
        try:
            st = gm.auto_observer_status()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: ext_status: %s" % e, source="geneva")
            return
        if not isinstance(st, dict) or (not st.get("ok", True) and
                                        st.get("error")):
            return
        from core import geneva_rate as gr
        try:
            cap = float(st.get("capacity") or 0)
        except (TypeError, ValueError, OverflowError):
            cap = 0.0
        if not math.isfinite(cap) or cap < 0:
            cap = 0.0
        if cap > 0:
            gr.SHARED.observe(cap, now)
        hits, dns = [], []
        with self._lock:
            for k in st.get("impaired") or []:
                if not isinstance(k, dict) or not k.get("impaired", True):
                    continue
                cls, level = str(k.get("class") or ""), k.get("level")
                key = str(k.get("key") or "")
                if cls == "DNS_POISON" and level == "host":
                    if self.book.dns_poisoned(key, now):
                        dns.append(key)
                    continue
                if level in ("host", "ip"):
                    hits += self.book.detect(level, key, cls, now)
            if hits:
                self._dirty = True
        self.detector = {"running": True, "supported": True,
                         "capacity": int(cap),
                         "impaired": len(st.get("impaired") or [])}
        for name in hits:
            self.note("%s: детектор geneva — подозрение блокировки" % name,
                      en="%s: geneva's detector suspects a block" % name)
        for name in dns:
            self.note("%s: детектор geneva видит подмену DNS — стратегия "
                      "не поможет, включите DoH (раздел DNS)" % name,
                      "warning",
                      en="%s: geneva's detector sees a forged DNS answer — "
                         "a strategy will not help, turn on DoH" % name)

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
            s = self.book.next_to_confirm(
                now, allowed=lambda x: x.key not in self._works)
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
            self._keep_criteria(s)
            line = self.book.confirmed(s.key, result, now)
        if line:
            self.note("%s (%s)" % (line, text) if text else line)
        self.phase = "watching"

    def _keep_criteria(self, s) -> None:
        """Критерий страницы, найденный пробой (шейпер, обрыв 16 КБ), —
        в книгу. Под замком."""
        cur = self.book.find(s.key)
        if cur is not None and s.criteria != cur.criteria:
            cur.criteria = dict(s.criteria)
            self._dirty = True

    def _search_slots(self) -> int:
        """Сколько подборов может идти рядом: без деления — один; с
        делением ``min(потоки, 4)``, но не больше свободных групп (у
        каждого подбора своя пробная группа)."""
        st = self.settings()
        if not st["split_workers"]:
            return 1
        working = {s.strategy for s in self.book.services if s.is_active
                   and s.key not in self._trials}
        free = st["max_groups"] - len(working)
        return max(1, min(st["workers"], MAX_SEARCHES, free))

    def _free_slot(self):
        """Свободный слот подбора. Без деления потоков — только слот 0:
        у слотов 1–3 блок портов на 2 воркера, а без деления подбор
        берёт все потоки."""
        used = {w["slot"] for w in self._works.values()}
        split = self.settings()["split_workers"]
        if any(x.busy and getattr(x, "split", split) != split
               for x in self._all_searches()):
            # деление переключили, пока шли подборы: блоки портов старых
            # и новых подборов пересеклись бы — ждём, пока старые закончат
            return None
        n = MAX_SEARCHES if split else 1
        for k in range(n):
            if k not in used and not self.search(k).busy:
                return k
        return None

    def _cancel_work(self, key: str) -> None:
        w = self._works.get(key)
        if w is None:
            return
        if w.get("starting"):
            # подбор ещё не запущен (проба без обхода, start): отмену
            # увидит :meth:`_launch` — start() завёл бы новый _stop
            w["cancelled"] = True
            return
        try:
            self.search(w["slot"]).cancel()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: отмена подбора: %s" % e, source="geneva")

    def _collect(self, now: float) -> None:
        """Итоги законченных подборов."""
        for key, w in list(self._works.items()):
            if w.get("starting"):
                continue                # ещё запускается в другом потоке
            x = self.search(w["slot"])
            if x.busy:
                continue
            res = x.result()
            with self._lock:
                self._works.pop(key, None)
                self._trials.pop(key, None)
                self._related.discard(key)
                self._trial = next(iter(self._trials.values()), None)
                if res is not None:
                    self._take(res, now, custom=w.get("custom", ""))
                elif not w.get("custom"):
                    self.book.interrupted(key, now)

    def _searching(self, now: float) -> None:
        self._collect(now)
        if now < self._search_wait:
            self.phase = "searching" if self._works else self.phase
            return
        with self._lock:
            self._preempt(now)
        while True:
            with self._lock:
                if len(self._works) >= self._search_slots():
                    break
                # подбор без деления держит весь блок портов: рядом нельзя
                if any(not w["split"] for w in self._works.values()):
                    break
                busy = [self.book.find(k) for k in self._works]
                busy = [b for b in busy if b is not None]
                s = self.book.next_to_search(
                    now, lambda c: not any(ga.overlap(c, b) for b in busy))
                if s is None:
                    break
                slot = self._free_slot()
                if slot is None:
                    break
                fam = self.book.family_strategy(s)
                running = self.applier().running()
                proven = self._proven(s.key)
                snap = s.clone()
                self.book.searching(s.key, now)
                split = self.settings()["split_workers"]
                self._works[s.key] = {"slot": slot, "split": split,
                                      "custom": "", "starting": True}
                self._dirty = True
            if self._stale_baseline(snap, now):
                continue
            launched = self._launch(snap.key, slot, lambda: self.search(
                slot).start(snap, running, proven,
                            first=[fam] if fam else ()))
            if launched is None:
                with self._lock:        # отменили, пока запускался
                    self.book.interrupted(snap.key, now)
                continue
            if launched:
                self.phase = "searching"
                self.note("%s: подбор стратегии" % snap.name,
                          en="%s: searching" % snap.name)
            else:
                with self._lock:
                    self._works.pop(snap.key, None)
                    self.book.interrupted(snap.key, now)
                break
        if self._works:
            self.phase = "searching"

    def _launch(self, key: str, slot: int, start):
        """Запуск подбора работы ``key``, заведённой с ``starting``:
        ``True`` — запущен, ``False`` — слот не принял, ``None`` — работу
        отменили или убрали, пока шла проба без обхода (тогда её уже нет
        в :attr:`_works`)."""
        with self._lock:
            w = self._works.get(key)
            if w is None or w.get("cancelled"):
                self._works.pop(key, None)
                return None
        ok = bool(start())
        with self._lock:
            w = self._works.get(key)
            if w is not None:
                w.pop("starting", None)
            cancelled = w is None or w.pop("cancelled", False)
        if ok and cancelled:
            try:
                self.search(slot).cancel()
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: отмена подбора: %s" % e,
                          source="geneva")
        return ok

    def _stale_baseline(self, s, now: float) -> bool:
        """Подбор начинается позже :data:`BASELINE_FRESH` после последнего
        «заблокирован» без обхода (повтор через часы, перезапуск,
        сломавшийся обход): сначала ещё раз без обхода — открывающийся
        сервис не подбирается. ``True`` — подбор не нужен."""
        if s.baseline_at is None or now - s.baseline_at <= BASELINE_FRESH \
                or not s.probeable:
            return False
        try:
            result, text = self.probes().check(s, through_bypass=False)
        except Exception:                           # noqa: BLE001
            return False
        with self._lock:
            self._keep_criteria(s)
            if result == ga.C_BLOCKED:
                cur = self.book.find(s.key)
                if cur is not None:
                    cur.baseline_at = now
                return False
            if result != ga.C_NOT_BLOCKED:
                return False
            self._works.pop(s.key, None)
            cur = self.book.find(s.key)
            if cur is not None and cur.status == ga.SEARCHING:
                ga._move(cur, ga.BLOCKED, now, "")
            line = self.book.confirmed(s.key, ga.C_NOT_BLOCKED, now)
            self._dirty = True
        self.note("%s: перед подбором открылся без обхода, подбор не нужен"
                  % s.name,
                  en="%s: opens without a bypass now, no search" % s.name)
        return True

    def _preempt(self, now: float) -> None:
        """Важный заблокированный прерывает подбор менее важного: если
        его держат подборы на тех же адресах — уступают они, иначе, когда
        все места заняты, — наименее важный."""
        if not self._works:
            return
        if any(w.get("preempted") for w in self._works.values()):
            return              # прошлое прерывание ещё не закончилось
        custom = [self.book.find(k) for k, w in self._works.items()
                  if w.get("custom")]
        custom = [c for c in custom if c is not None]
        # тот, кто сам не сможет начать (уже в работе или рядом с
        # проверкой своей стратегии), никого не прерывает
        top = self.book.next_to_search(
            now, lambda s: s.key not in self._works and
            not any(ga.overlap(s, c) for c in custom))
        if top is None or top.priority == gal.BACKGROUND:
            return
        mine = gal.effective(top, now)
        cur = [(self.book.find(k), w) for k, w in self._works.items()
               if not w.get("custom")]
        cur = [(b, w) for b, w in cur if b is not None]
        blockers = [b for b, _ in cur if ga.overlap(top, b)]
        full = len(self._works) >= self._search_slots() or any(
            not w["split"] for w in self._works.values())
        if blockers:
            victims = blockers
        elif full and cur:
            victims = [max((b for b, _ in cur),
                           key=lambda b: gal.effective(b, now))]
        else:
            return
        if not all(gal.effective(v, now) > mine for v in victims):
            return
        for v in victims:
            self.note("%s: подбор прерван ради более важного — %s"
                      % (v.name, top.name),
                      en="%s: search interrupted for %s" % (v.name,
                                                            top.name))
            w = self._works.get(v.key)
            if w is not None:
                w["preempted"] = True
            threading.Thread(target=self._cancel_work, args=(v.key,),
                             daemon=True).start()

    def _take(self, res, now: float, custom: str = "") -> None:
        from core import geneva_auto_search as gs
        s = self.book.find(res.key)
        name = s.name if s else res.key
        if custom:
            # стратегия пользователя: при успехе — применить и закрепить,
            # иначе сервис остаётся как был
            if res.outcome == gs.APPLIED:
                self.book.applied(res.key, res.strategy, res.fitness, now)
                self.book.pin(res.key, True)
                self.note("%s: стратегия пользователя работает — применена "
                          "и закреплена" % name,
                          en="%s: your strategy works — applied and pinned"
                          % name)
                self._applied_sig = None
            elif res.outcome in (gs.CANCELLED, gs.BUSY):
                self.note("%s: проверка стратегии пользователя прервана"
                          % name,
                          en="%s: the check of your strategy was "
                             "interrupted" % name)
            else:
                self.note("%s: стратегия пользователя не прошла проверку "
                          "(%s)" % (name, res.detail), "warning",
                          en="%s: your strategy failed the check" % name)
            self._dirty = True
            return
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

    def _plan_sig(self, services, trial=None, max_groups=ga.MAX_GROUPS,
                  trials=None) -> str:
        # С пробной стратегией: план без неё и план с ней — разные
        # правила, и смена пробы без смены книги должна применяться сразу.
        # Предел групп — как у Applier: иначе группы сверх 4 не попадали в
        # подпись, и их смена ждала повтора раз в 120 с. У профилей
        # (geneva_c 2.0) в подпись идут имена и стратегии: адреса
        # перечитываются перечитыванием ipset-файлов.
        if self._profiles_mode():
            all_trials = list(trials or ()) + ([trial] if trial else [])
            profs = ga.plan_profiles(services, trials=all_trials)
            # Адреса и порты тоже: новый адрес CDN попадёт в ipset-файл
            # на следующем срезе, а не через APPLY_EVERY. Перезапуска не
            # будет — подпись процесса считает только имена и стратегии,
            # и процесс перечитает файлы (``reload_lists``).
            return json.dumps([[p.name, p.strategy, sorted(p.addresses),
                                p.tcp_ports, p.udp_ports] for p in profs],
                              sort_keys=True)
        groups = ga.plan_groups(services, trial=trial, max_groups=max_groups,
                                trials=trials)
        return json.dumps([g.to_dict() for g in groups], sort_keys=True)

    def _profiles_mode(self) -> bool:
        """Стратегии — профили одного процесса (geneva_c 2.0)?"""
        try:
            return bool(getattr(self.applier(), "mode") == "profiles" or
                        self.applier().profiles_ok())
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: профили: %s" % e, source="geneva")
            return False

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

    def _hosts(self, services, trials):
        """Процесс «по имени» (``by_name``): профили и исключения, или
        ``None`` — выключен или нечего применять."""
        st = self.settings()
        if not st["by_name"]:
            return None
        from core import geneva_related as grel
        lists = self.book.lists
        profs = ga.host_profiles(services, [s.key for s, _ in trials or ()],
                                 quic=True, families=True)
        # проба на итоговой проверке: её семейство — тоже по имени, если
        # это не вытеснит применённые профили (первый совпавший — их)
        related = grel.trial_families(
            services, [(s, x) for s, x in trials or ()
                       if s.key in self._related], profs) \
            if self._related else []
        if len(profs) + len(related) > ga.MAX_HOST_PROFILES:
            related = []
        profs = profs + [p for _, p in related]
        if not profs:
            return None
        return {"profiles": profs,
                "related": {k: list(p["domains"]) for k, p in related},
                "exclude_ips": lists.exclude.subnets(),
                "exclude_domains": lists.exclude.plain_domains()}

    def _sig(self, services, trials) -> str:
        return self._plan_sig(services, None, self.applier().max_groups,
                              trials) + json.dumps(
            self._hosts(services, trials), sort_keys=True)

    def _apply_plan(self, services, trials, now: float) -> dict:
        """Группы, пробы и «по имени» — на роутер. Под замком."""
        hosts = self._hosts(services, trials)
        res = self.applier().apply_services(services, trials=trials,
                                            hosts=hosts)
        self._applied_sig = self._sig(services, trials)
        self._applied_at = now
        host = res.get("host") or {}
        sent = dict(hosts.get("related") or {}) \
            if hosts and host.get("pid") else {}
        if "domains" in host:
            # только домены профилей, которые процесс правда загрузил
            loaded = set(host.get("domains") or ())
            sent = {k: [d for d in v if d in loaded]
                    for k, v in sent.items()}
        self._related_sent = {k: v for k, v in sent.items() if v}
        # Сайты, которые покрывает «по имени»: провал на их новом адресе —
        # ослабление стратегии (адрес и так под обходом).
        # Только профили, которые процесс загрузил: отброшенные (нет
        # ext_crypto, фейк не найден, нет годных имён) сайт не покрывают.
        covers = ga.by_name_covers(services, hosts["profiles"]) \
            if hosts and host.get("pid") else set()
        if "services" in host:
            covers &= set(host.get("services") or ())
        self.book.by_name = covers
        self.host_state = {"pid": host.get("pid"),
                           "action": host.get("action", ""),
                           "profiles": len(hosts["profiles"])
                           if hosts and host.get("pid") else 0,
                           "error": host.get("error", "")}
        return res

    def _apply(self, now: float) -> None:
        with self._lock:
            services = [s.clone() for s in self.book.services]
            trials = list(self._trials.values())
            if self._sig(services, trials) == self._applied_sig and \
                    now - self._applied_at < APPLY_EVERY:
                return
            res = self._apply_plan(services, trials, now)
            if res.get("ok"):
                self._apply_failures = 0
            elif not res.get("hint"):
                # Сбой без подсказки — чаще всего гонка с прошивкой: первый
                # повтор на следующем срезе, а не через APPLY_EVERY (всё это
                # время группы жили бы без правил).
                if not self._apply_failures:
                    self._applied_sig = None
                self._apply_failures += 1
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

    def _check_rules(self, now: float) -> bool:
        """Правила групп снесены извне (Keenetic NDMS пересобирает
        таблицы и вместе со своими правилами удаляет наши цепочки и
        наборы) — поставить заново сразу, не ждать ``APPLY_EVERY``.
        Провалы за время без правил не идут в счёт стратегии
        (:meth:`ga.Book.rules_restored`). ``True`` — правила пропадали."""
        try:
            lost = self.applier().missing()
        except Exception as e:                      # noqa: BLE001
            log.debug("geneva-auto: проверка правил: %s" % e,
                      source="geneva")
            return False
        if not lost:
            return False
        with self._lock:
            self._applied_sig = None
        self._apply(now)
        ok = bool((getattr(self.applier(), "last", None) or {}).get("ok"))
        with self._lock:
            back = self.book.rules_restored(now) if ok else 0
            self.rules_lost += 1
            self._dirty = self._dirty or bool(back)
            self._lost_unnoted += 1
            if self._lost_noted_at is not None and \
                    now - self._lost_noted_at < LOST_NOTE_EVERY:
                return True
            times, self._lost_unnoted = self._lost_unnoted, 0
            self._lost_noted_at = now
        what = ", ".join(lost[:3]) + (" …" if len(lost) > 3 else "")
        more = " (за полчаса — %d раз)" % times if times > 1 else ""
        if ok:
            self.note("правила обхода сняты извне (%s) — поставлены заново"
                      "%s" % (what, more), "warning",
                      en="bypass rules were removed by the firmware — "
                         "restored")
        else:
            self.note("правила обхода сняты извне (%s), заново не встали"
                      "%s" % (what, more), "warning",
                      en="bypass rules were removed by the firmware — "
                         "restore failed")
        return True

    def reassert_rules(self) -> bool:
        """Из сторожа маршрутизации (хук netfilter.d прошивки): проверить
        и вернуть правила групп, не дожидаясь среза."""
        if not self.running or self._suspended or self._stop.is_set():
            return False
        return self._check_rules(self._clock())

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
            searching = key in self._works
        if searching:
            self._cancel_work(key)
        with self._lock:
            self.book.reset(key, self._clock())
            self._applied_sig = None
            self._dirty = True
            self.save(force=True)
        self.note("%s: сброшен вручную" % s.name, en="%s: reset" % s.name)
        return {"ok": True, "key": key}

    # ── действия над сервисом ──

    def _service_or_error(self, key: str):
        s = self.book.find(key)
        if s is None:
            return None, {"ok": False, "error_code": "not_found",
                          "error": "сервиса нет: %s" % key}
        return s, None

    def check_now(self, key: str) -> dict:
        """«Проверить сейчас» — вне очереди."""
        with self._lock:
            s, err = self._service_or_error(key)
            if err:
                return err
            line = self.book.check_now(key, self._clock())
            self._dirty = True
        if line:
            self.note(line)
        return {"ok": True, "key": key, "status": s.status}

    def set_priority(self, key: str, value: str) -> dict:
        """Важность сервиса словом пользователя: ``important``,
        ``unimportant`` или ``""`` (по умолчанию)."""
        value = "" if value in (None, "auto", "default") else str(value)
        if value not in gal.USER_PRIORITIES:
            return {"ok": False, "error_code": "bad_value",
                    "error": "важность: important, unimportant или default"}
        with self._lock:
            s, err = self._service_or_error(key)
            if err:
                return err
            self.book.set_user_priority(key, value)
            self._dirty = True
            self.save(force=True)
            pr = gal.PRIORITY_NAMES[s.priority]
        self.note("%s: важность — %s" % (s.name, gal.PRIORITY_TEXT[
            s.priority][0]), en="%s: priority — %s" % (s.name, pr))
        return {"ok": True, "key": key, "priority": pr,
                "user_priority": value}

    def pin(self, key: str, pinned: bool = True) -> dict:
        """Закрепить стратегию сервиса: провалы не ведут к новому подбору."""
        with self._lock:
            s, err = self._service_or_error(key)
            if err:
                return err
            if not self.book.pin(key, bool(pinned)):
                return {"ok": False, "error_code": "no_strategy",
                        "error": "у сервиса нет применённой стратегии"}
            self._dirty = True
            self.save(force=True)
        self.note("%s: стратегия %s" % (s.name, "закреплена" if pinned
                                        else "откреплена"),
                  en="%s: strategy %s" % (s.name, "pinned" if pinned
                                          else "unpinned"))
        return {"ok": True, "key": key, "pinned": bool(pinned)}

    def try_strategy(self, key: str, strategy: str) -> dict:
        """«Проверить свою стратегию»: пробная группа на трафике сервиса;
        прошла — применяется и закрепляется (итог — в журнале)."""
        from core.geneva_manager import check_strategy_text
        try:
            strategy = check_strategy_text(strategy)
        except ValueError as e:
            return {"ok": False, "error_code": "bad_strategy",
                    "error": str(e)}
        if not self.running:
            return {"ok": False, "error_code": "off",
                    "error": "режим «Авто» выключен"}
        try:
            chk = self.gm().check_strategy(strategy)
        except Exception as e:                      # noqa: BLE001
            chk = {"ok": False, "error": str(e)}
        if not chk.get("ok"):
            return {"ok": False, "error_code": "bad_strategy",
                    "error": chk.get("error") or "стратегия не разбирается"}
        strategy = chk.get("strategy") or strategy
        with self._lock:
            s, err = self._service_or_error(key)
            if err:
                return err
            if key in self._works:
                return {"ok": False, "error_code": "busy",
                        "error": "для сервиса идёт подбор: попробуйте "
                                 "после него"}
            busy = [self.book.find(k) for k in self._works]
            if any(b is not None and ga.overlap(s, b) for b in busy):
                return {"ok": False, "error_code": "busy",
                        "error": "идёт подбор для сервиса на тех же "
                                 "адресах: попробуйте после него"}
            if not ga._fits(s, strategy):
                return {"ok": False, "error_code": "bad_transport",
                        "error": "стратегия не для этого транспорта "
                                 "(TCP/UDP)"}
            # Только там, где проба без обхода видела блокировку:
            # открывающийся сервис пропустил бы любую стратегию, и
            # закрепление оставило бы её навсегда.
            if s.status not in (ga.BLOCKED, ga.NOT_FOUND, ga.DEGRADED,
                                ga.APPLIED):
                return {"ok": False, "error_code": "not_confirmed",
                        "error": "блокировка не подтверждена: сначала "
                                 "«Проверить сейчас»"}
            full = self._works and (
                len(self._works) >= self._search_slots() or
                any(not w["split"] for w in self._works.values()))
            slot = None if full else self._free_slot()
            if slot is None:
                return {"ok": False, "error_code": "busy",
                        "error": "идёт подбор: попробуйте после него"}
            snap = s.clone()
            self._works[key] = {"slot": slot, "split": True,
                                "custom": strategy, "starting": True}
        launched = self._launch(key, slot, lambda: self.search(slot).start(
            snap, only=strategy))
        if not launched:
            with self._lock:
                if launched is not None:
                    self._works.pop(key, None)
            return {"ok": False, "error_code": "busy",
                    "error": "слот подбора занят" if launched is not None
                    else "сервис убран, пока проверка запускалась"}
        self.note("%s: пробую стратегию пользователя: %s"
                  % (s.name, strategy),
                  en="%s: trying your strategy" % s.name)
        return {"ok": True, "key": key, "strategy": strategy,
                "started": True}

    def no_search_for(self, key: str) -> dict:
        """«Не подбирать для этого сервиса»: его сайт (или адрес) — в
        список «Не подбирать»."""
        with self._lock:
            s, err = self._service_or_error(key)
            if err:
                return err
            entry = gal.site_of(s) if s.kind in (ga.WEB, ga.QUIC) else \
                (s.host if s.host and s.kind == ga.ENDPOINT else s.address)
        if not entry:
            return {"ok": False, "error_code": "no_entry",
                    "error": "у сервиса нет имени и адреса"}
        lists = dict(self.settings()["lists"])
        if entry not in lists["no_search"]:
            lists["no_search"] = lists["no_search"] + [entry]
        res = self.update_lists({"no_search": lists["no_search"]})
        if res.get("ok"):
            res["entry"] = entry
        return res

    def lists_view(self) -> dict:
        st = self.settings()
        store = self._asn_store()
        lists = self.lists()
        marked = {"important": [], "unimportant": []}
        # Через snapshot: при выключенном режиме книга в памяти пуста
        # (``load()`` зовёт только ``_start``), а отметки лежат в
        # ``auto.json`` — иначе форма показала бы пустоту при живых
        # отметках в таблице.
        for s in self.services_snapshot():
            up = getattr(s, "user_priority", "") or ""
            if up in marked:
                marked[up].append({"service": s.key, "name": s.name})
        marked["important"].sort(key=lambda x: x["name"])
        marked["unimportant"].sort(key=lambda x: x["name"])
        return {"ok": True, "important": st["lists"]["important"],
                "unimportant": st["lists"]["unimportant"],
                "no_search": st["lists"]["no_search"],
                "exclude": st["exclude"],
                # Отметки отдельных сервисов из меню строки (⋯): живут в
                # книге, а не в списках. Одно имя «Важно» на два разных
                # механизма путает: список — маски и AS, отметка — один
                # сервис. Страница показывает и то, и другое.
                "marked": marked,
                "known_important": st["lists"]["known_important"],
                "split_workers": st["split_workers"],
                "by_name": st["by_name"],
                "final_check": st["final_check"],
                "families": {k: list(v) for k, v in gal.FAMILIES.items()},
                "asn": {("AS" + str(n)): {
                    "prefixes": len(store["prefixes"].get(str(n)) or []),
                    "fetched": store["fetched"].get(str(n))}
                    for n in lists.asns()}}

    def update_lists(self, values: dict) -> dict:
        """Списки «Важно», «Не важно», «Не подбирать» (маски и AS),
        «Не трогать» (домены, адреса, подсети), ``known_important``,
        ``split_workers``, ``by_name``, ``final_check`` (общая с ручным
        подбором ``geneva.final_check``). Неверная строка — 400 со всеми
        причинами, ничего не сохраняется."""
        values = values if isinstance(values, dict) else {}
        cfg = self.cfg()
        raw = dict(cfg.get("geneva", "auto", default={}) or {})
        lists = dict(raw.get("lists") or {}) \
            if isinstance(raw.get("lists"), dict) else {}
        errors = []
        for key in ("important", "unimportant", "no_search", "exclude"):
            if key not in values:
                continue
            out, errs = gal.clean_entries(values[key],
                                          strict=key == "exclude")
            errors += ["%s: %s" % (key, e) for e in errs]
            if key == "exclude":
                raw["exclude"] = out
            else:
                lists[key] = out
        for key in ("known_important", "split_workers", "by_name",
                    "final_check"):
            if key in values and not isinstance(values[key], bool):
                errors.append("%s: true или false" % key)
        if errors:
            return {"ok": False, "error_code": "bad_value",
                    "error": "; ".join(errors[:5]), "errors": errors}
        if "known_important" in values:
            lists["known_important"] = values["known_important"]
        for key in ("split_workers", "by_name"):
            if key in values:
                raw[key] = values[key]
        raw["lists"] = lists
        cfg.set("geneva", "auto", raw)
        if "final_check" in values:
            cfg.set("geneva", "final_check", values["final_check"])
        cfg.save()
        self._apply_lists()
        with self._lock:
            self._retune_searches()
        self._refresh_asn()
        self.note("списки «Авто» сохранены", en="Auto lists saved")
        return self.lists_view()

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
                d.pop("detected", None)
                d["address"] = s.address
                d["priority_name"] = gal.PRIORITY_NAMES[
                    gal.effective(s, self._clock())]
                d["family"] = gal.service_family(s) or ""
                items.append(d)
            groups = []
            last = (self._applier.last if self._applier else {}) or {}
            if last.get("mode") == "profiles":
                # Один процесс, много профилей: «группа» для страницы —
                # профиль (очередь у всех одна, диапазон процесса).
                for info in last.get("profiles") or ():
                    g = dict(info, queue=ga.QUEUE_BASE,
                             profile=info.get("name", ""))
                    g.update({k: v for k, v in
                              (self.group_stats.get(info.get("name")) or {}
                               ).items() if k in ("stats", "rate")})
                    groups.append(g)
            else:
                for q, info in sorted((last.get("queues") or {}).items()):
                    g = dict(info, queue=q)
                    g.update({k: v for k, v in
                              (self.group_stats.get(q) or {}).items()
                              if k in ("stats", "rate")})
                    groups.append(g)
            searches = []
            for key, w in self._works.items():
                x = self.search(w["slot"])
                pr = dict(x.progress() or {})
                pr.setdefault("key", key)
                pr["running"] = x.busy
                pr["slot"] = w["slot"]
                pr["custom"] = bool(w.get("custom"))
                searches.append(pr)
            search = searches[0] if searches else {}
            return {
                "enabled": st["enabled"], "running": self.running,
                "phase": self.phase, "suspended": self._suspended,
                "slices": self.slices,
                "rules_lost": self.rules_lost,
                "connections": int(self.last_slice.get("connections", 0)),
                "observed": int(self.last_slice.get("observed", 0)),
                "counts": self.book.counts(),
                "total": len(self.book.services),
                "services": items, "groups": groups, "search": search,
                "problems": list(self.problems),
                "offload": self.offload,
                "max_groups": st["max_groups"], "workers": st["workers"],
                "help_tunnels": st["help_tunnels"],
                "exclude": st["exclude"],
                "split_workers": st["split_workers"],
                "by_name": st["by_name"],
                "search_slots": self._search_slots() if self.running else 0,
                # сколько подборов выбрано («Как делить потоки»): меньше
                # идёт, когда группы заняты работающими стратегиями
                "search_slots_wanted": min(st["workers"], MAX_SEARCHES)
                if st["split_workers"] else 1,
                "final_check": st["final_check"],
                "searches": searches,
                "host": dict(self.host_state) if self.running else {},
                "detector": dict(self.detector) if self.running else {},
                # Может ли эта платформа поставить NFLOG кнопкой: без
                # модуля детектор geneva отключается, и починить это должен
                # интерфейс, а не консоль (иначе кнопка бесполезна).
                "nflog_fix": _nflog_fix() if self.running else {},
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
        # вердикт итоговой проверки ручного подбора (сайт и его ресурсы)
        try:
            from core.geneva_manager import final_verdicts
            verdicts = final_verdicts()
        except Exception:                           # noqa: BLE001
            verdicts = {}
        for r in items:
            v = verdicts.get(r["strategy"])
            if v:
                r["final"] = {"ok": v.get("ok"), "detail": v.get("detail",
                                                                 ""),
                              "at": v.get("at")}
        return {"ok": True, "items": items, "working": working,
                "auto_enabled": self.settings()["enabled"]}

    # ── настройки со страницы ──

    def update_settings(self, values: dict) -> dict:
        """Настройки с карточки «Авто»: ``workers`` (1–64), ``max_groups``
        (1–8), ``help_tunnels`` (bool) и ``exclude`` (адреса серверов,
        списком или текстом через пробел, запятую или строку). Новое
        число воркеров действует со следующего круга подбора, число
        групп — со следующего применения, исключения — со следующего
        среза."""
        import ipaddress
        values = values if isinstance(values, dict) else {}
        cfg = self.cfg()
        raw = dict(cfg.get("geneva", "auto", default={}) or {})

        def bad(text):
            return {"ok": False, "error_code": "bad_value", "error": text}

        limits = {"workers": (1, ga.ENGINE_WORKERS_MAX),
                  "max_groups": (1, ga.MAX_GROUPS_LIMIT)}
        for key, (lo, hi) in limits.items():
            if key not in values:
                continue
            v = values[key]
            if isinstance(v, bool) or not isinstance(v, int) or \
                    not lo <= v <= hi:
                return bad("%s: целое от %d до %d" % (key, lo, hi))
            raw[key] = v
        if "help_tunnels" in values:
            if not isinstance(values["help_tunnels"], bool):
                return bad("help_tunnels: true или false")
            raw["help_tunnels"] = values["help_tunnels"]
        for key in ("split_workers", "by_name"):
            if key in values:
                if not isinstance(values[key], bool):
                    return bad("%s: true или false" % key)
                raw[key] = values[key]
        if "final_check" in values and \
                not isinstance(values["final_check"], bool):
            return bad("final_check: true или false")
        if "exclude" in values:
            # «Не трогать»: домены, адреса и подсети (geneva берёт их как
            # есть — без масок и AS)
            v = values["exclude"]
            if isinstance(v, str):
                v = v.replace(",", " ").split()
            if not isinstance(v, list):
                return bad("exclude: список адресов и доменов")
            out, errors = gal.clean_entries(v, strict=True)
            if errors:
                return bad("exclude: " + errors[0])
            raw["exclude"] = out
        cfg.set("geneva", "auto", raw)
        if "final_check" in values:
            cfg.set("geneva", "final_check", values["final_check"])
        cfg.save()
        st = self.settings()
        with self._lock:
            if self._applier is not None:
                self._applier.max_groups = st["max_groups"]
            self._retune_searches()
            if self._observer is not None:
                self._observer.help_tunnels = st["help_tunnels"]
            self._applied_sig = None        # число групп могло смениться
        if "exclude" in values:
            self._apply_lists()
        self.note("настройки: проверок одновременно %d, стратегий "
                  "одновременно %d, туннели %s, исключено адресов %d"
                  % (st["workers"], st["max_groups"],
                     "под защитой" if st["help_tunnels"] else "не трогать",
                     len(st["exclude"])),
                  en="settings: %d parallel checks, %d strategies at once, "
                  "tunnels %s, %d excluded addresses"
                  % (st["workers"], st["max_groups"],
                     "protected" if st["help_tunnels"] else "left alone",
                     len(st["exclude"])))
        return {"ok": True, "workers": st["workers"],
                "max_groups": st["max_groups"],
                "help_tunnels": st["help_tunnels"],
                "exclude": st["exclude"],
                "split_workers": st["split_workers"],
                "by_name": st["by_name"]}

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
        # x-стратегии сохраняются, даже если этой geneva их не запустить
        # (geneva_c 1.x, нет фейка zapret2): подбор их пропустит, пока не
        # обновятся geneva или zapret2. Человеку — почему.
        try:
            _, bad = self.gm().runnable(
                [r["strategy"] for r in rows if r.get("ext")])
            bad = list(bad)
        except Exception:                           # noqa: BLE001
            bad = []
        for s, why in bad:
            errors.append("%s: сохранена, но пока не пробуется — %s"
                          % (s[:80], why))
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
