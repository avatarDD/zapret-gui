# core/healthcheck.py
"""
Healthcheck-демон: фоновый watchdog для autocircular.

Идея — пользователь не должен ловить «отвалилось» вручную:

  1. Каждые N минут демон curl'ом дёргает референс-домены каждой включённой
     службы (YouTube, Discord, Telegram — из core/diagnostics.SERVICES).
  2. Если служба упала consecutive_failures раз подряд — мы сбрасываем
     записи в state.tsv по её хостам (через core/strategy_state.clear_host).
     В результате при следующем соединении z2k-state-persist начнёт круг с
     первой стратегии в circular, а не пытается долбиться выученной (которая
     теперь явно не работает).
  3. История последних проверок хранится в ring-буфере (HEALTHCHECK_HISTORY_SIZE)
     и отдаётся через API. Это и журнал работы автопочинки, и подсветка в GUI.

ПО УМОЛЧАНИЮ ВЫКЛЮЧЕН (`healthcheck.enabled = false`). Создаёт фоновый
трафик роутера наружу — это пользовательский выбор. Включается в GUI.

Использование (`app.py` при boot):

    from core.healthcheck import get_healthcheck
    hc = get_healthcheck()
    hc.start()             # ничего не делает если cfg.healthcheck.enabled = false

API:
    hc.get_status()  → состояние демона + последняя пачка результатов
    hc.run_now()     → запустить проверку сразу (для кнопки в GUI)
    hc.stop()        → остановить демон
    hc.reload()      → перечитать конфиг (если включили в GUI)
"""

import os
import threading
import time
from collections import deque

from core.log_buffer import log


_instance = None
_instance_lock = threading.Lock()


def get_healthcheck():
    """Singleton-аксессор."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = HealthcheckDaemon()
        return _instance


class HealthcheckDaemon:
    """Фоновый поток: проверяет сервисы периодически и чинит autocircular."""

    def __init__(self):
        self._thread = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()

        # История последних проверок (newest first после append → правым).
        # Каждая запись: {ts, results: [{service, ok, response_time, error,
        #                                 url, hosts_reset:[...]}], ...}
        self._history = deque(maxlen=50)

        # Состояние «подряд провалов» по сервисам, чтобы триггерить reset
        # после consecutive_failures штук, а не на одном случайном.
        self._fail_streak = {}     # service_name → int

        # Идёт ли прямо сейчас проверка (для индикатора в GUI и защиты от
        # параллельных run_now). Отдельный поток для неблокирующего run_now.
        self._checking = False
        self._check_thread = None

        # Дата запуска / последней проверки.
        self._started_at = None
        self._last_check_at = None
        self._last_check_summary = None
        self._next_check_at = None

    # ──────────────────────── Public API ────────────────────────

    def start(self):
        """Запустить фоновый поток (если включено в конфиге)."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not bool(cfg.get("healthcheck", "enabled", default=False)):
            log.info("Healthcheck: выключен в конфиге, не запускаем",
                     source="healthcheck")
            return False

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop_evt.clear()
            self._thread = threading.Thread(
                target=self._loop, name="HealthcheckDaemon", daemon=True)
            self._thread.start()
            self._started_at = time.time()
        log.success("Healthcheck-демон запущен", source="healthcheck")
        return True

    def stop(self):
        """Остановить фоновый поток."""
        with self._lock:
            self._stop_evt.set()
            t = self._thread
            self._thread = None
        if t is not None and t.is_alive():
            t.join(timeout=2)
        self._started_at = None
        self._next_check_at = None
        log.info("Healthcheck-демон остановлен", source="healthcheck")
        return True

    def reload(self):
        """Перечитать конфиг — пере-стартовать демон с новыми параметрами.

        Вызывается из API когда юзер меняет enabled/interval в GUI."""
        running = self.is_running()
        self.stop()
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if bool(cfg.get("healthcheck", "enabled", default=False)):
            self.start()
            return {"ok": True, "running": True}
        return {"ok": True, "running": False, "was_running": running}

    def is_running(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive()

    def get_status(self) -> dict:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        with self._lock:
            history = list(self._history)
        return {
            "running": self.is_running(),
            "enabled": bool(cfg.get("healthcheck", "enabled", default=False)),
            "interval_min": int(cfg.get("healthcheck", "interval_min",
                                        default=5)),
            "services": list(cfg.get("healthcheck", "services",
                                     default=[])),
            "auto_reset": bool(cfg.get("healthcheck", "auto_reset",
                                       default=True)),
            "consecutive_failures": int(cfg.get(
                "healthcheck", "consecutive_failures", default=2)),
            "custom_domains": list(cfg.get("healthcheck", "custom_domains",
                                           default=[]) or []),
            "control_domain": cfg.get("healthcheck", "control_domain",
                                      default="") or "",
            "outage_guard": bool(cfg.get("healthcheck", "outage_guard",
                                         default=True)),
            "started_at": self._started_at,
            "last_check_at": self._last_check_at,
            "next_check_at": self._next_check_at,
            "last_summary": self._last_check_summary,
            "fail_streak": dict(self._fail_streak),
            "checking": self._checking,
            "history": history,
        }

    def run_now(self, blocking: bool = True) -> dict:
        """Принудительный прогон проверки (кнопка «Проверить сейчас»).

        blocking=True (дефолт, для тестов/CLI) — выполнить синхронно и
        вернуть summary прогона.

        blocking=False (для API/GUI) — запустить проверку в фоне и сразу
        вернуть {started, busy}. Каждый сервис проверяется до 8с с
        фолбэками, итого до ~30с на 3 сервиса — синхронный HTTP-ответ
        столько ждать нельзя, поэтому GUI триггерит фон и опрашивает
        /status, показывая спиннер.
        """
        if blocking:
            return self._run_guarded()

        with self._lock:
            if self._checking:
                return {"started": False, "busy": True}
            self._checking = True
            self._check_thread = threading.Thread(
                target=self._run_guarded, name="HealthcheckRunNow",
                daemon=True)
            self._check_thread.start()
        return {"started": True, "busy": False}

    def _run_guarded(self) -> dict:
        """Обёртка _tick с гарантированным сбросом флага _checking."""
        with self._lock:
            self._checking = True
        try:
            return self._tick()
        finally:
            with self._lock:
                self._checking = False

    # ──────────────────────── Internal ────────────────────────

    def _loop(self):
        """Главный цикл демона."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        # Начальная задержка перед первым тиком — чтобы nfqws2 успел
        # подняться и применить стратегию. Без неё демон может «провалить»
        # первый тик ещё до того, как обход заработает, и сбросить state.tsv
        # на пустом месте.
        if self._stop_evt.wait(30):
            return

        try:
            self._tick()
        except Exception as e:
            log.error("Healthcheck tick: %s" % e, source="healthcheck")

        while not self._stop_evt.is_set():
            interval = max(60, int(cfg.get("healthcheck", "interval_min",
                                           default=5)) * 60)
            self._next_check_at = time.time() + interval
            # wait() даёт реактивный stop без sleep-цикла.
            if self._stop_evt.wait(interval):
                break
            try:
                self._tick()
            except Exception as e:
                log.error("Healthcheck tick: %s" % e, source="healthcheck")

    @staticmethod
    def _build_targets(cfg):
        """Собрать список целей проверки: известные сервисы + кастомные домены.

        Каждая цель: {key, display, icon, url, hosts:[...]}.
          - известные сервисы — из core.diagnostics.SERVICES;
          - кастомные домены — пользовательские, хост выводится из URL.
        """
        from core.diagnostics import SERVICES
        from urllib.parse import urlparse

        targets = []
        for name in (cfg.get("healthcheck", "services", default=[]) or []):
            svc = SERVICES.get(name)
            if not svc:
                continue
            urls = svc.get("urls") or []
            hosts = svc.get("hosts") or []
            if not urls or not hosts:
                continue
            targets.append({
                "key": name,
                "display": svc.get("name", name),
                "icon": svc.get("icon", ""),
                "url": urls[0],
                "hosts": list(hosts),
            })

        for dom in (cfg.get("healthcheck", "custom_domains", default=[]) or []):
            dom = (dom or "").strip()
            if not dom:
                continue
            url = dom if dom.startswith(("http://", "https://")) \
                else "https://" + dom
            host = urlparse(url).hostname or dom
            targets.append({
                "key": "custom:" + host,
                "display": host,
                "icon": "🌐",
                "url": url,
                "hosts": [host],
            })
        return targets

    def _tick(self) -> dict:
        """Один прогон проверки — для всех включённых целей.

        Возвращает summary текущего прогона. При обнаружении провала
        (consecutive >= threshold) сбрасывает state.tsv по затронутым
        хостам, если auto_reset включён.
        """
        from core.config_manager import get_config_manager
        from core.diagnostics import check_http
        from core import strategy_state

        cfg = get_config_manager()
        threshold = max(1, int(cfg.get("healthcheck", "consecutive_failures",
                                       default=2)))
        auto_reset = bool(cfg.get("healthcheck", "auto_reset", default=True))
        outage_guard = bool(cfg.get("healthcheck", "outage_guard",
                                    default=True))
        control_domain = (cfg.get("healthcheck", "control_domain",
                                  default="") or "").strip()

        targets = self._build_targets(cfg)

        # ── Фаза 1: пробы всех целей ──
        results = []
        ts = time.time()
        for tgt in targets:
            # Берём URL цели. timeout — короткий: 8с. Cache check_http ставит
            # TTL 30с, поэтому повторные тики не задавят сеть лишним curl'ом.
            r = check_http(tgt["url"], timeout=8)
            results.append({
                "service": tgt["key"],
                "display": tgt["display"],
                "icon": tgt["icon"],
                "url": tgt["url"],
                "hosts": tgt["hosts"],
                "ok": bool(r.get("ok")),
                "status_code": r.get("status_code") or 0,
                "response_time": r.get("response_time"),
                "error": r.get("error"),
                "hosts_reset": [],
                "fail_streak": 0,
            })

        total = len(results)
        ok = sum(1 for r in results if r["ok"])
        failed = total - ok

        # ── Защита от «глобального обвала» ──
        # Если упали ВСЕ цели — это МОЖЕТ быть общая проблема (нет интернета,
        # не запущен nfqws2, лёг DNS/WAN), а не отказ стратегий. Но это же
        # бывает и когда DPI реально блокирует все цели сразу — тогда сброс
        # как раз нужен. Различаем по «контрольному» сайту (control_domain),
        # который НЕ блокируется: если он открывается — связь есть, провал
        # всех целей = DPI, сброс ВЫПОЛНЯЕТСЯ. Если control тоже недоступен —
        # это реальный обвал, сброс пропускаем.
        all_failed = (total >= 1 and ok == 0)
        global_outage = False
        control_ok = None
        if outage_guard and all_failed:
            if control_domain:
                curl = control_domain if control_domain.startswith(
                    ("http://", "https://")) else "https://" + control_domain
                cr = check_http(curl, timeout=8)
                control_ok = bool(cr.get("ok"))
                # Контрольный открылся → связь есть → это DPI, НЕ обвал.
                global_outage = not control_ok
            else:
                # Без контрольного сайта — старая эвристика: ≥2 целей и все
                # упали ⇒ считаем обвалом (консервативно, не трэшим).
                global_outage = (total >= 2)

        # ── Фаза 2: решение о сбросе (по-сервисно, с учётом streak) ──
        for entry in results:
            name = entry["service"]
            if entry["ok"]:
                self._fail_streak[name] = 0
                entry["fail_streak"] = 0
                continue

            if global_outage:
                # Не виним конкретную стратегию — держим streak как есть,
                # ничего не сбрасываем.
                entry["fail_streak"] = self._fail_streak.get(name, 0)
                continue

            self._fail_streak[name] = self._fail_streak.get(name, 0) + 1
            entry["fail_streak"] = self._fail_streak[name]

            if auto_reset and self._fail_streak[name] >= threshold:
                for host in entry["hosts"]:
                    try:
                        res = strategy_state.clear_host(host)
                        removed = (res or {}).get("removed", 0)
                        if removed > 0:
                            entry["hosts_reset"].append(
                                {"host": host, "removed": removed})
                    except Exception as e:
                        log.warning("Healthcheck reset %s: %s" % (host, e),
                                    source="healthcheck")
                # SIGHUP nfqws2 — чтобы Lua перечитал хостлисты и не
                # перезаписал state из своего in-RAM кэша до того, как
                # circular подберёт новую стратегию.
                try:
                    strategy_state.reload_nfqws()
                except Exception:
                    pass
                log.warning(
                    "Healthcheck: %s провален %d раз подряд → сбросили "
                    "state по %d хостам" % (
                        name, self._fail_streak[name],
                        len(entry["hosts_reset"])),
                    source="healthcheck")
                # Сбрасываем счётчик чтобы не зацикливаться на reset —
                # circular должен успеть подобрать.
                self._fail_streak[name] = 0
                entry["fail_streak"] = 0

        # Убираем служебное поле hosts из результата (в API не нужно).
        for entry in results:
            entry.pop("hosts", None)

        summary = {
            "ts": ts,
            "results": results,
            "total": total,
            "ok": ok,
            "failed": failed,
            "global_outage": global_outage,
            "control_domain": control_domain,
            "control_ok": control_ok,
        }
        with self._lock:
            self._history.append(summary)
            self._last_check_at = ts
            self._last_check_summary = {
                "ts": ts, "total": total, "ok": ok, "failed": failed,
                "global_outage": global_outage,
                "control_domain": control_domain, "control_ok": control_ok,
            }

        if global_outage:
            log.warning(
                "Healthcheck: упали ВСЕ %d цели%s — похоже на отсутствие "
                "связи или не запущен nfqws2. Сброс стратегий пропущен "
                "(не трэшим выученное)." % (
                    total,
                    (" и контрольный %s" % control_domain)
                    if control_domain else ""),
                source="healthcheck")
        elif total > 0:
            log.info(
                "Healthcheck: %d/%d целей доступны%s" % (
                    ok, total,
                    (" (контрольный %s открылся → провалы трактуем как DPI)"
                     % control_domain) if (all_failed and control_ok) else ""),
                source="healthcheck")
        return summary
