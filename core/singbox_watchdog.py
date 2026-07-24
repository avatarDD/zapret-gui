# core/singbox_watchdog.py
"""
Watchdog для sing-box: автоматически перезапускает инстанс, если прокси
«завис» — соединение через него перестало проходить (сайты тормозят, потом
отваливаются), хотя процесс ещё жив.

Аналог core/awg_watchdog.py, но критерий другой. У AWG сигнал — handshake/
счётчики rx; у sing-box есть Clash API (`experimental.clash_api`), через
который можно честно проверить связь:

    GET /proxies/<tag>/delay?url=<target>&timeout=<ms>

— движок РЕАЛЬНО открывает соединение к облаку (Cloudflare) ЧЕРЕЗ активный
outbound и возвращает задержку. Это нельзя «обойти» (в отличие от
SO_BINDTODEVICE-пробы у AWG): если прокси не работает — проба не пройдёт.
Заодно ловит и зависший движок: если сам Clash API не отвечает, проба тоже
падает → рестарт.

Watchdog опциональный, по умолчанию выключен. Включается через settings.json
(`singbox.watchdog.enabled`) или API. Следим только за ЗАПУЩЕННЫМИ конфигами,
у которых настроен clash_api (наш routing-флоу добавляет его автоматически).
"""

import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


# ─────── defaults ───────

DEFAULT_ENABLED              = False
DEFAULT_CHECK_INTERVAL_SEC   = 60     # частота проверки
DEFAULT_COOLDOWN_SEC         = 300    # пауза после рестарта — не дёргать снова
DEFAULT_MAX_RESTARTS_PER_HOUR = 6     # защита от петли
DEFAULT_PROBE_TARGET         = "cloudflare"   # пресет proxy_tester / URL
DEFAULT_PROBE_TIMEOUT_MS     = 5000   # таймаут одного delay-замера
DEFAULT_PROBE_FAIL_THRESHOLD = 2      # подряд неудач → рестарт


# ─────── probe ───────

def probe_outbound(ep: dict, tag: str, target_url: str,
                   timeout_ms: int) -> bool:
    """
    Проверить связь через outbound `tag` Clash API'ем `ep`
    ({host,port,secret}). True — задержка получена (облако открылось через
    прокси). Падение Clash API (движок завис) тоже → False.
    """
    from core.proxy_tester import parse_delay
    if not ep or not tag:
        return False
    q = urllib.request.quote(target_url, safe="")
    path = "/proxies/%s/delay?timeout=%d&url=%s" % (
        urllib.request.quote(tag, safe=""), int(timeout_ms), q)
    url = "http://%s:%d%s" % (ep.get("host") or "127.0.0.1",
                              int(ep["port"]), path)
    headers = {}
    if ep.get("secret"):
        headers["Authorization"] = "Bearer %s" % ep["secret"]
    req = urllib.request.Request(url, headers=headers)
    http_to = (int(timeout_ms) / 1000.0) + 3.0
    try:
        with urllib.request.urlopen(req, timeout=http_to) as r:
            return parse_delay(r.getcode(),
                               r.read().decode("utf-8", "replace")).get("ok")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return parse_delay(e.code, body).get("ok", False)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return False


def decide_restart(*, probe_fails: int, probe_threshold: int) -> tuple:
    """
    Чистое решение «рестартить ли инстанс». Возвращает (bool, reason).
    Рестарт, если проба через прокси не прошла `probe_threshold` раз подряд.
    """
    if probe_fails >= max(1, probe_threshold):
        return (True, "проба через прокси не прошла %d раз подряд"
                % probe_fails)
    return (False, "")


# ─────── settings ───────

def _get_settings() -> dict:
    """Настройки watchdog'а из settings.json (`singbox.watchdog`)."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load()
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    sb = cfg.get("singbox") or {}
    wd = sb.get("watchdog") or {}
    if not isinstance(wd, dict):
        wd = {}
    return {
        "enabled":              bool(wd.get("enabled", DEFAULT_ENABLED)),
        "check_interval_sec":   int(wd.get(
            "check_interval_sec", DEFAULT_CHECK_INTERVAL_SEC)),
        "cooldown_sec":         int(wd.get(
            "cooldown_sec", DEFAULT_COOLDOWN_SEC)),
        "max_restarts_per_hour": int(wd.get(
            "max_restarts_per_hour", DEFAULT_MAX_RESTARTS_PER_HOUR)),
        "probe_target":         str(wd.get(
            "probe_target", DEFAULT_PROBE_TARGET) or DEFAULT_PROBE_TARGET),
        "probe_timeout_ms":     int(wd.get(
            "probe_timeout_ms", DEFAULT_PROBE_TIMEOUT_MS)),
        "probe_fail_threshold": int(wd.get(
            "probe_fail_threshold", DEFAULT_PROBE_FAIL_THRESHOLD)),
    }


def set_settings(**kwargs) -> dict:
    """Обновить настройки watchdog'а (персистентно). Возвращает актуальные."""
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        for k, v in kwargs.items():
            if v is None:
                continue
            cm.set("singbox", "watchdog", k, v)
        cm.save()
    except Exception as e:
        log.warning("singbox_watchdog: save settings: %s" % e,
                    source="singbox")
    get_watchdog().reconfigure()
    return _get_settings()


# ─────── watchdog ───────

class SingboxWatchdog:
    """Фоновой watchdog по health-пробе через Clash API."""

    def __init__(self):
        self._lock     = threading.Lock()
        self._thread   = None
        self._stop_evt = threading.Event()
        self._restart_log  = {}   # {name: [ts, ...]} за последний час
        self._last_restart = {}   # {name: ts}
        self._probe_fails  = {}   # {name: int}

    # ─── lifecycle ───

    def reconfigure(self):
        if _get_settings()["enabled"]:
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="singbox-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("singbox-watchdog: запущен", source="singbox")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("singbox-watchdog: остановлен", source="singbox")

    # ─── main loop ───

    def _run_loop(self):
        while not self._stop_evt.wait(_get_settings()["check_interval_sec"]):
            try:
                self._tick()
            except Exception as e:
                log.warning("singbox-watchdog tick: %s" % e, source="singbox")

    def _tick(self):
        settings = _get_settings()
        if not settings["enabled"]:
            self._stop()
            return
        try:
            from core.singbox_manager import get_singbox_manager
            mgr = get_singbox_manager()
            configs = mgr.list_configs()
        except Exception as e:
            log.warning("singbox-watchdog: список конфигов: %s" % e,
                        source="singbox")
            return

        now = time.time()

        def check_one(entry):
            name = (entry or {}).get("name", "")
            if not name:
                return
            try:
                if not mgr.is_running(name):
                    with self._lock:
                        self._probe_fails.pop(name, None)
                    return
                self._maybe_restart(mgr, name, settings, now)
            except Exception as e:
                log.warning("singbox-watchdog: %s: %s" % (name, e),
                            source="singbox")

        # Entware python3-light без python3-logging: concurrent.futures
        # тянет logging на верхнем уровне (_base.py) и не импортируется —
        # «No module named 'logging'». Без fallback watchdog молча ничего
        # не делал бы на таких системах (в main цикл был последовательным).
        try:
            from concurrent.futures import ThreadPoolExecutor
        except ImportError:
            for entry in configs:
                check_one(entry)
            return

        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(check_one, configs)

    def _maybe_restart(self, mgr, name: str, settings: dict, now: float):
        # Cooldown — даём прокси установиться после рестарта.
        with self._lock:
            last_restart_time = self._last_restart.get(name, 0)
        if (now - last_restart_time) < settings["cooldown_sec"]:
            return

        from core.singbox_config import (
            clash_api_endpoint, active_outbound_tag)
        from core.proxy_tester import resolve_target
        cfg_resp = mgr.get_config(name)
        cfg = (cfg_resp.get("parsed") or {}) \
            if isinstance(cfg_resp, dict) else {}
        ep = clash_api_endpoint(cfg)
        tag = active_outbound_tag(cfg)
        if not ep or not tag:
            # Нечем проверять (нет clash_api) — не вмешиваемся.
            return

        ok = probe_outbound(ep, tag, resolve_target(settings["probe_target"]),
                            settings["probe_timeout_ms"])
        with self._lock:
            fails = 0 if ok else self._probe_fails.get(name, 0) + 1
            self._probe_fails[name] = fails

        should, reason = decide_restart(
            probe_fails=fails,
            probe_threshold=settings["probe_fail_threshold"])
        if not should:
            return

        # Rate limit.
        with self._lock:
            history = self._restart_log.setdefault(name, [])
            history[:] = [ts for ts in history if (now - ts) < 3600]
            num_restarts = len(history)

        if num_restarts >= settings["max_restarts_per_hour"]:
            log.warning(
                "singbox-watchdog: %s — %s, но лимит рестартов исчерпан"
                " (%d/час). Прокси нездоров — смените сервер/подписку."
                % (name, reason, settings["max_restarts_per_hour"]),
                source="singbox")
            return

        log.warning("singbox-watchdog: %s — %s; рестартую" % (name, reason),
                    source="singbox")
        try:
            mgr.restart(name)
        except Exception as e:
            log.warning("singbox-watchdog: restart %s: %s" % (name, e),
                        source="singbox")
            return
        with self._lock:
            self._last_restart[name] = now
            self._probe_fails[name] = 0
            self._restart_log.setdefault(name, []).append(now)

    def _cleanup_restart_log(self, now: float):
        """Очистить старые таймстампы (>1 часа) и удалить пустые логи интерфейсов."""
        to_delete = []
        for k, v in list(self._restart_log.items()):
            cleaned = [ts for ts in v if (now - ts) < 3600]
            if not cleaned:
                to_delete.append(k)
            else:
                self._restart_log[k] = cleaned
        for k in to_delete:
            self._restart_log.pop(k, None)

    # ─── status (для UI) ───

    def get_status(self) -> dict:
        settings = _get_settings()
        now = time.time()
        with self._lock:
            self._cleanup_restart_log(now)
            running = (self._thread is not None and self._thread.is_alive())
            history_view = {
                k: len(v)
                for k, v in self._restart_log.items()
            }
        return {
            "enabled":  settings["enabled"],
            "running":  running,
            "settings": settings,
            "restarts_last_hour": history_view,
        }


# ─────── singleton ───────

_watchdog = None
_watchdog_lock = threading.Lock()


def get_watchdog() -> SingboxWatchdog:
    global _watchdog
    if _watchdog is None:
        with _watchdog_lock:
            if _watchdog is None:
                _watchdog = SingboxWatchdog()
                _watchdog.reconfigure()
    return _watchdog
