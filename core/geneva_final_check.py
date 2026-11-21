# core/geneva_final_check.py
"""
Итоговая проверка найденного ручным подбором geneva (AutoTuner 1.5).

В AutoTuner после подбора до трёх лучших стратегий по очереди
включаются коротким ``run`` на порту сайта, и встроенный браузер
открывает сайт через каждую; на 443 должны загрузиться и связанные
ресурсы (другие имена сайта и его семейство). Вердикт виден в
«Найденных».

Отличия на роутере (браузера нет):

* стратегии проверяет ``geneva eval --probe external`` в своём слоте
  оценщика (очередь и блок портов слота :data:`SLOT`): стратегия
  действует только на соединения пробы, а не на весь порт сайта, и
  проверка не мешает ни обходу, ни другим устройствам;
* страницу сайта грузит проба «Авто» (уровень «тело»), связанные
  ресурсы — проба TLS и ответа HTTP (:mod:`core.geneva_related`), с
  того же блока портов, то есть через ту же стратегию;
* пауза обхода на время подбора (``pause_bypass``) держится до конца
  проверки: проверка идёт в тех же условиях, что подбор.

Вердикт стратегии: ``True`` — сайт и его ресурсы загрузились, ``False``
— нет, ``None`` — сказать нечего (корень Минцифры, которого нет в
бандле роутера, или ресурс без соединения: у него своя блокировка).
"""

from __future__ import annotations

import threading
import time

from core.log_buffer import log

MAX_STRATEGIES = 3            # лучших найденных (GenevaBrowserCheck.MaxManual)
SLOT = 1                      # слот оценщика (при ручном подборе «Авто» выключен)
POLL = 2.0
# Связанных ресурсов на стратегию: страница (12 с, с повтором «по имени»
# — 24 с) и два ресурса (по 8 с и DNS) укладываются в таймаут ответа
# geneva eval (60 с).
RELATED_HOSTS = 2
LIMIT = 75.0 * MAX_STRATEGIES + 30.0   # вся проверка, с запуском geneva


def _fitness(r: dict) -> float:
    try:
        return float(r.get("avg_fitness") or 0)
    except (TypeError, ValueError):
        return 0.0


def pick(results, limit: int = MAX_STRATEGIES) -> list:
    """Лучшие прошедшие оценку (фитнес > 0) стратегии итога подбора."""
    out = []
    for r in sorted((r for r in results or () if isinstance(r, dict)),
                    key=lambda r: -_fitness(r)):
        s = str(r.get("strategy") or "").strip()
        if not s or s in out or _fitness(r) <= 0:
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def target_of(params: dict) -> tuple:
    """``(host, port, tls)`` сайта ручного подбора."""
    host = str((params or {}).get("host") or "")
    probe = (params or {}).get("probe") or "tls"
    tls = probe != "http"
    port = int((params or {}).get("port") or 0) or (443 if tls else 80)
    return host, port, tls


def measure(host: str, port: int, tls: bool, address: str, ports,
            related=(), page=None, related_check=None,
            exclude=None) -> tuple:
    """Одна проверка стратегии с блока портов ``ports``: ``(ok, текст)``.

    Страница сайта — проба «Авто» (тело); на 443 — и связанные ресурсы
    ``related`` (``[(имя, адрес)]``), кроме «Не трогать» ``exclude``.
    ``ok`` — ``True``, ``False`` или ``None`` (без вердикта: корень
    Минцифры)."""
    from core import geneva_auto_probes as pr
    from core import geneva_related as grel
    page = page or pr.probe_page
    r = page(address, port, host, tls=tls, ports=ports)
    if r.untrusted_root and not r.passes():
        r2 = page(address, port, host, tls=tls, ports=ports, name_only=True)
        if r2.national:
            r = r2
        else:
            return None, "сертификат от корня, которого нет на роутере"
    if not r.passes():
        return False, "сайт не открылся: %s" % r.text()
    if not related or not tls or port != 443:
        return True, "сайт открылся: %s" % r.text()
    check = related_check or (
        lambda hosts: pr.get_auto_probes().check_related(
            hosts, through_bypass=True, ports=ports, exclude=exclude))
    ok, text = grel.summary(check(list(related)))
    if ok is False:
        return False, "сайт открылся, но не загрузились связанные " \
            "ресурсы: %s" % text
    if ok:
        return True, "сайт и связанные ресурсы открылись: %s" % text
    return True, "сайт открылся: %s" % r.text()


class FinalCheck:
    """Итоговая проверка одного подбора: свой поток, ``geneva eval`` в
    слоте :data:`SLOT`. Итог — ``done(verdicts)``, где ``verdicts`` —
    ``{стратегия: {"ok", "detail"}}``."""

    def __init__(self, gm, strategies, params: dict, done, address="",
                 related=(), clock=time.time):
        self._gm = gm
        self.strategies = list(strategies)
        self.params = dict(params or {})
        self._done = done
        self._address = address
        self._related = list(related)[:RELATED_HOSTS]
        self._exclude = None
        self._clock = clock
        self.verdicts = {}
        self._lock = threading.Lock()
        self._thread = None
        self._cancel = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._main, daemon=True,
                                        name="geneva-final-check")
        self._thread.start()

    def cancel(self) -> None:
        """Остановить (кнопкой «Стоп» подбора): ещё не запущенная
        проверка не запустится, идущую остановит менеджер."""
        self._cancel.set()

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _probe(self, lports: str, strategy: str):
        from core.geneva_auto_probe_cli import parse_lports
        host, port, tls = target_of(self.params)
        ok, text = measure(host, port, tls, self._address,
                           parse_lports(lports), self._related,
                           exclude=self._exclude)
        with self._lock:
            self.verdicts[strategy] = {"ok": ok, "detail": text[:300]}
        # geneva нужен фитнес: «нет вердикта» — не провал
        return (400 if ok is not False else -400), text

    def _main(self) -> None:
        try:
            self._run()
        except Exception as e:                      # noqa: BLE001
            log.warning("geneva: итоговая проверка: %s" % e, source="geneva")
        finally:
            with self._lock:
                verdicts = dict(self.verdicts)
            try:
                self._done(verdicts)
            except Exception as e:                  # noqa: BLE001
                log.warning("geneva: итог проверки не записан: %s" % e,
                            source="geneva")

    def _prepare(self) -> bool:
        """Адрес сайта и его связанные ресурсы (имена, которые уже
        открывали устройства сети, — из книги «Авто»; «Не трогать»
        «Авто» — и здесь не трогается)."""
        host, _, _ = target_of(self.params)
        if not self._address:
            self._address = resolve(host)
        if not self._address:
            log.info("geneva: итоговая проверка: %s не разрешился" % host,
                     source="geneva")
            return False
        seen = []
        try:
            from core import geneva_related as grel
            from core.geneva_auto_manager import get_geneva_auto_manager
            am = get_geneva_auto_manager()
            self._exclude = am.lists().exclude
            if not self._related:
                seen = grel.seen_hosts(am.services_snapshot())
        except Exception:                           # noqa: BLE001
            seen = []
        if not self._related:
            self._related = related_for(host, seen)[:RELATED_HOSTS]
        return True

    def _run(self) -> None:
        if not self._prepare() or self._cancel.is_set():
            return
        r = self._gm.start_final_job(self.strategies, self._probe)
        if not r.get("ok"):
            log.info("geneva: итоговая проверка не запустилась: %s"
                     % r.get("error", ""), source="geneva")
            return
        until = self._clock() + LIMIT
        while True:
            st = self._gm.final_job_status()
            if not st.get("running"):
                return
            if self._clock() > until or self._cancel.is_set():
                self._gm.stop_final_job()
                return
            self._cancel.wait(POLL)


def resolve(host: str) -> str:
    """Адрес сайта (как у проб «Авто»)."""
    from core.geneva_auto_probes import _resolve
    return _resolve(host)


def related_for(host: str, seen=()) -> list:
    """Связанные ресурсы сайта для проверки: ``[(имя, адрес)]``."""
    from core import geneva_related as grel
    return grel.hosts_to_check(grel.site_and_family(host), seen, own=host)
