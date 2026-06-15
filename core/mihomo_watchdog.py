# core/mihomo_watchdog.py
"""
Watchdog для mihomo: автоматически перезапускает инстанс, если прокси «завис» —
соединение через него перестало проходить, хотя процесс ещё жив.

Зеркало core/singbox_watchdog.py. У mihomo (как у sing-box) есть RESTful Clash
API (`external-controller`), через который можно честно проверить связь:

    GET /proxies/<group>/delay?url=<target>&timeout=<ms>

— mihomo РЕАЛЬНО открывает соединение к облаку (Cloudflare) ЧЕРЕЗ активный узел
выбранной proxy-group и возвращает задержку. Это нельзя «обойти»: не работает
прокси — проба не пройдёт. Заодно ловит зависший движок (Clash API не отвечает
→ проба падает → рестарт).

Watchdog опциональный, по умолчанию выключен. Включается через settings.json
(`mihomo.watchdog.enabled`) или API. Следим только за ЗАПУЩЕННЫМИ конфигами, у
которых есть `external-controller` и proxy-group (наш routing-флоу добавляет их
автоматически).
"""

import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


# ─────── defaults ───────

DEFAULT_ENABLED               = False
DEFAULT_CHECK_INTERVAL_SEC    = 60     # частота проверки
DEFAULT_COOLDOWN_SEC          = 300    # пауза после рестарта
DEFAULT_MAX_RESTARTS_PER_HOUR = 6      # защита от петли
DEFAULT_PROBE_TARGET          = "cloudflare"   # пресет proxy_tester / URL
DEFAULT_PROBE_TIMEOUT_MS      = 5000   # таймаут одного delay-замера
DEFAULT_PROBE_FAIL_THRESHOLD  = 2      # подряд неудач → рестарт


# ─────── probe ───────

def probe_proxy(ep: dict, group: str, target_url: str,
                timeout_ms: int) -> bool:
    """
    Проверить связь через proxy-group `group` Clash API'ем `ep`
    ({host,port,secret}). True — задержка получена (облако открылось через
    активный узел группы). Падение Clash API (движок завис) → False.
    """
    from core.proxy_tester import parse_delay
    if not ep or not group:
        return False
    q = urllib.request.quote(target_url, safe="")
    path = "/proxies/%s/delay?timeout=%d&url=%s" % (
        urllib.request.quote(group, safe=""), int(timeout_ms), q)
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
    """Чистое решение «рестартить ли инстанс» (bool, reason)."""
    if probe_fails >= max(1, probe_threshold):
        return (True, "проба через прокси не прошла %d раз подряд"
                % probe_fails)
    return (False, "")


# ─────── settings ───────

def _get_settings() -> dict:
    """Настройки watchdog'а из settings.json (`mihomo.watchdog`)."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load()
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    mh = cfg.get("mihomo") or {}
    wd = mh.get("watchdog") or {}
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
            cm.set("mihomo", "watchdog", k, v)
        cm.save()
    except Exception as e:
        log.warning("mihomo_watchdog: save settings: %s" % e, source="mihomo")
    get_watchdog().reconfigure()
    return _get_settings()


# ─────── watchdog ───────

class MihomoWatchdog:
    """Фоновой watchdog по health-пробе через external-controller."""

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
                                 name="mihomo-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("mihomo-watchdog: запущен", source="mihomo")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("mihomo-watchdog: остановлен", source="mihomo")

    # ─── main loop ───

    def _run_loop(self):
        while not self._stop_evt.wait(_get_settings()["check_interval_sec"]):
            try:
                self._tick()
            except Exception as e:
                log.warning("mihomo-watchdog tick: %s" % e, source="mihomo")

    def _tick(self):
        settings = _get_settings()
        if not settings["enabled"]:
            self._stop()
            return
        try:
            from core.mihomo_manager import get_mihomo_manager
            mgr = get_mihomo_manager()
            configs = mgr.list_configs()
        except Exception as e:
            log.warning("mihomo-watchdog: список конфигов: %s" % e,
                        source="mihomo")
            return

        now = time.time()
        for entry in configs:
            name = (entry or {}).get("name", "")
            if not name:
                continue
            try:
                if not mgr.is_running(name):
                    self._probe_fails.pop(name, None)
                    continue
                self._maybe_restart(mgr, name, settings, now)
            except Exception as e:
                log.warning("mihomo-watchdog: %s: %s" % (name, e),
                            source="mihomo")

    def _maybe_restart(self, mgr, name: str, settings: dict, now: float):
        # Cooldown — даём прокси установиться после рестарта.
        if (now - self._last_restart.get(name, 0)) < settings["cooldown_sec"]:
            return

        from core.clash_yaml import parse_yaml
        from core.mihomo_config import active_proxy_group
        from core.mihomo_proxies import external_controller_endpoint
        from core.proxy_tester import resolve_target

        cfg_resp = mgr.get_config(name)
        cfg = {}
        if isinstance(cfg_resp, dict) and cfg_resp.get("ok"):
            try:
                cfg = parse_yaml(cfg_resp.get("text") or "") or {}
            except Exception:
                cfg = {}
        ep = external_controller_endpoint(cfg)
        group = active_proxy_group(cfg)
        if not ep or not group:
            # Нечем проверять (нет external-controller/proxy-group) — не лезем.
            return

        ok = probe_proxy(ep, group, resolve_target(settings["probe_target"]),
                         settings["probe_timeout_ms"])
        fails = 0 if ok else self._probe_fails.get(name, 0) + 1
        self._probe_fails[name] = fails

        should, reason = decide_restart(
            probe_fails=fails,
            probe_threshold=settings["probe_fail_threshold"])
        if not should:
            return

        # Rate limit.
        history = self._restart_log.setdefault(name, [])
        history[:] = [ts for ts in history if (now - ts) < 3600]
        if len(history) >= settings["max_restarts_per_hour"]:
            log.warning(
                "mihomo-watchdog: %s — %s, но лимит рестартов исчерпан"
                " (%d/час). Прокси нездоров — смените сервер/подписку."
                % (name, reason, settings["max_restarts_per_hour"]),
                source="mihomo")
            return

        log.warning("mihomo-watchdog: %s — %s; рестартую" % (name, reason),
                    source="mihomo")
        try:
            mgr.restart(name)
        except Exception as e:
            log.warning("mihomo-watchdog: restart %s: %s" % (name, e),
                        source="mihomo")
            return
        self._last_restart[name] = now
        self._probe_fails[name] = 0
        history.append(now)

    # ─── status (для UI) ───

    def get_status(self) -> dict:
        settings = _get_settings()
        with self._lock:
            running = (self._thread is not None and self._thread.is_alive())
            history_view = {
                k: len([ts for ts in v if (time.time() - ts) < 3600])
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


def get_watchdog() -> MihomoWatchdog:
    global _watchdog
    if _watchdog is None:
        with _watchdog_lock:
            if _watchdog is None:
                _watchdog = MihomoWatchdog()
                _watchdog.reconfigure()
    return _watchdog
