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
            "started_at": self._started_at,
            "last_check_at": self._last_check_at,
            "next_check_at": self._next_check_at,
            "last_summary": self._last_check_summary,
            "fail_streak": dict(self._fail_streak),
            "history": history,
        }

    def run_now(self) -> dict:
        """Принудительный прогон проверки (кнопка «Проверить связь сейчас»).

        Возвращает результат сразу. НЕ требует, чтобы демон был запущен —
        работает как одноразовая проверка из GUI.
        """
        return self._tick()

    # ──────────────────────── Internal ────────────────────────

    def _loop(self):
        """Главный цикл демона."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        # Сразу — первый прогон, чтобы юзер увидел в логах что демон жив.
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

    def _tick(self) -> dict:
        """Один прогон проверки — для всех включённых сервисов.

        Возвращает summary текущего прогона. При обнаружении провала
        (consecutive >= threshold) сбрасывает state.tsv по затронутым
        хостам, если auto_reset включён.
        """
        from core.config_manager import get_config_manager
        from core.diagnostics import SERVICES, check_http
        from core import strategy_state

        cfg = get_config_manager()
        wanted = cfg.get("healthcheck", "services", default=[]) or []
        threshold = max(1, int(cfg.get("healthcheck", "consecutive_failures",
                                       default=2)))
        auto_reset = bool(cfg.get("healthcheck", "auto_reset", default=True))

        results = []
        ts = time.time()
        for name in wanted:
            svc = SERVICES.get(name)
            if not svc:
                continue
            urls = svc.get("urls") or []
            hosts = svc.get("hosts") or []
            if not urls or not hosts:
                continue

            # Берём первый URL — Diagnostics уже его проверяет в общем UI.
            # timeout — короткий: 8с. Cache check_http ставит TTL 30с,
            # поэтому повторные тики не задавят сеть лишним curl'ом.
            r = check_http(urls[0], timeout=8)
            entry = {
                "service": name,
                "display": svc.get("name", name),
                "icon": svc.get("icon", ""),
                "url": urls[0],
                "ok": bool(r.get("ok")),
                "status_code": r.get("status_code") or 0,
                "response_time": r.get("response_time"),
                "error": r.get("error"),
                "hosts_reset": [],
            }

            if entry["ok"]:
                self._fail_streak[name] = 0
            else:
                self._fail_streak[name] = self._fail_streak.get(name, 0) + 1
                if (auto_reset
                        and self._fail_streak[name] >= threshold):
                    # Сброс state.tsv по всем известным хостам службы.
                    for host in hosts:
                        try:
                            res = strategy_state.clear_host(host)
                            removed = (res or {}).get("removed", 0)
                            if removed > 0:
                                entry["hosts_reset"].append(
                                    {"host": host, "removed": removed})
                        except Exception as e:
                            log.warning(
                                "Healthcheck reset %s: %s" % (host, e),
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

            results.append(entry)

        total = len(results)
        ok = sum(1 for r in results if r["ok"])
        summary = {
            "ts": ts,
            "results": results,
            "total": total,
            "ok": ok,
            "failed": total - ok,
        }
        with self._lock:
            self._history.append(summary)
            self._last_check_at = ts
            self._last_check_summary = {
                "ts": ts, "total": total, "ok": ok, "failed": total - ok,
            }

        if total > 0:
            log.info(
                "Healthcheck: %d/%d сервисов доступны" % (ok, total),
                source="healthcheck")
        return summary
