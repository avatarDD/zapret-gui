# core/awg_watchdog.py
"""
Watchdog для amneziawg-go: автоматически рестартит туннель, если
handshake устарел дольше порога.

Зачем нужен:
  - amneziawg-go в userspace иногда «зависает»: процесс жив, TUN
    цел, но WireGuard handshake перестаёт обновляться (типичный
    сценарий — поплыла сеть на 30+ секунд, NAT-binding истёк,
    keepalive из настроенных 25с не помогает).
  - Без watchdog'а пользователь видит «всё работает, но интернета
    нет» и идёт перезагружать роутер.
  - С watchdog'ом мы сами замечаем, что handshake не обновлялся
    дольше N секунд (default 180), и делаем тихий `down/up`.

Идея взята из `core/nfqws_manager.py` (там watchdog следит за процессом
nfqws2). Здесь критерий не «процесс живой?», а «свежий ли handshake?».

Watchdog опциональный, по умолчанию выключен. Включается через
settings.json (`awg.watchdog.enabled`) или API.

Не запускаем поток на не-AWG платформах — модуль безопасен в import'е.
"""

import threading
import time

from core.log_buffer import log


# ─────── defaults ───────

DEFAULT_HANDSHAKE_TIMEOUT_SEC = 180   # 3 минуты без handshake → рестарт
DEFAULT_CHECK_INTERVAL_SEC    = 30    # частота проверки
DEFAULT_COOLDOWN_SEC          = 300   # пауза после рестарта — не дёргать снова
DEFAULT_MAX_RESTARTS_PER_HOUR = 6     # защита от петли


# ─────── settings ───────

def _get_settings() -> dict:
    """
    Прочитать настройки watchdog'а из settings.json (`awg.watchdog`).

    Все поля опциональны — мы подсовываем разумные дефолты.
    """
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load()
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    awg = cfg.get("awg") or {}
    wd = awg.get("watchdog") or {}
    if not isinstance(wd, dict):
        wd = {}
    return {
        "enabled":                  bool(wd.get("enabled", False)),
        "handshake_timeout_sec":    int(wd.get(
            "handshake_timeout_sec", DEFAULT_HANDSHAKE_TIMEOUT_SEC)),
        "check_interval_sec":       int(wd.get(
            "check_interval_sec", DEFAULT_CHECK_INTERVAL_SEC)),
        "cooldown_sec":             int(wd.get(
            "cooldown_sec", DEFAULT_COOLDOWN_SEC)),
        "max_restarts_per_hour":    int(wd.get(
            "max_restarts_per_hour", DEFAULT_MAX_RESTARTS_PER_HOUR)),
    }


def set_settings(**kwargs) -> dict:
    """Обновить настройки watchdog'а. Возвращает актуальные."""
    try:
        from core.config_manager import get_config_manager, save_config
    except Exception as e:
        log.warning("awg_watchdog: settings unavailable: %s" % e,
                    source="awg")
        return _get_settings()

    cfg = get_config_manager().load()
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("awg", {}).setdefault("watchdog", {})
    sec = cfg["awg"]["watchdog"]
    for k, v in kwargs.items():
        if v is None:
            continue
        sec[k] = v
    try:
        save_config()
    except Exception as e:
        log.warning("awg_watchdog: save_config: %s" % e, source="awg")

    # При смене enabled-флага дёрнем синглтон, чтобы он стартанул/
    # остановил поток.
    wd = get_watchdog()
    wd.reconfigure()
    return _get_settings()


# ─────── watchdog ───────

class AwgWatchdog:
    """Фоновой watchdog по handshake-age."""

    def __init__(self):
        self._lock     = threading.Lock()
        self._thread   = None
        self._stop_evt = threading.Event()
        # История рестартов: {iface: [ts, ts, ...]} (только за последний час)
        self._restart_log  = {}
        # Cooldown'ы: {iface: ts_last_restart}
        self._last_restart = {}

    # ─── lifecycle ───

    def reconfigure(self):
        """
        Перечитать настройки и запустить/остановить поток.

        Вызывается при первом импорте и после set_settings().
        """
        settings = _get_settings()
        if settings["enabled"]:
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(
                target=self._run_loop,
                name="awg-watchdog",
                daemon=True,
            )
            t.start()
            self._thread = t
            log.info("awg-watchdog: запущен", source="awg")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("awg-watchdog: остановлен", source="awg")

    # ─── main loop ───

    def _run_loop(self):
        # Сразу не дёргаем — пусть туннель устаканится после старта.
        while not self._stop_evt.wait(_get_settings()["check_interval_sec"]):
            try:
                self._tick()
            except Exception as e:
                log.warning("awg-watchdog tick: %s" % e, source="awg")

    def _tick(self):
        """Один проход — проверить все наши туннели."""
        settings = _get_settings()
        if not settings["enabled"]:
            self._stop()
            return

        try:
            from core.awg_manager import AwgManager
            mgr = AwgManager()
            ifaces = mgr.list_interfaces()
        except Exception as e:
            log.warning("awg-watchdog: список интерфейсов: %s" % e,
                        source="awg")
            return

        now = time.time()
        for entry in ifaces:
            name = (entry or {}).get("name", "")
            if not name:
                continue
            # Нативные Keenetic-WG: их перезапускает сам Keenetic
            # (через ping-check); вмешиваться вредно.
            if entry.get("source") == "ndms" or entry.get("native"):
                continue
            if not entry.get("active"):
                # Туннель уже не поднят — пользователь сам решил, не лезем.
                continue

            self._maybe_restart(mgr, name, entry, settings, now)

    def _maybe_restart(self, mgr, iface: str, status: dict,
                        settings: dict, now: float):
        """Принять решение по одному интерфейсу."""
        # Cooldown — даём время туннелю установить handshake после рестарта.
        last = self._last_restart.get(iface, 0)
        if (now - last) < settings["cooldown_sec"]:
            return

        # Самый свежий handshake по peer'ам.
        peers = status.get("peers") or []
        if not peers:
            # Если peer'ов вообще не видно — туннель в странном состоянии.
            # Не рестартуем: возможно конфиг странный, либо ещё подключается.
            return
        latest = 0
        for p in peers:
            try:
                latest = max(latest, int(p.get("latest_handshake") or 0))
            except (TypeError, ValueError):
                continue
        if latest == 0:
            # Handshake ещё ни разу не случился. Это часто на первом
            # подъёме туннеля — не нервничаем.
            return

        age = int(now) - latest
        if age < settings["handshake_timeout_sec"]:
            return

        # Rate limit: не больше N рестартов в час.
        history = self._restart_log.setdefault(iface, [])
        history[:] = [ts for ts in history if (now - ts) < 3600]
        if len(history) >= settings["max_restarts_per_hour"]:
            log.warning(
                "awg-watchdog: %s — handshake %dс назад, но лимит"
                " рестартов исчерпан (%d/час); ничего не делаем"
                % (iface, age, settings["max_restarts_per_hour"]),
                source="awg")
            return

        log.warning(
            "awg-watchdog: %s handshake %dс назад (>%dс) — рестартую"
            % (iface, age, settings["handshake_timeout_sec"]),
            source="awg")
        try:
            mgr.restart(iface)
        except Exception as e:
            log.warning("awg-watchdog: restart %s: %s" % (iface, e),
                        source="awg")
            return
        self._last_restart[iface] = now
        history.append(now)

    # ─── status (для UI) ───

    def get_status(self) -> dict:
        settings = _get_settings()
        with self._lock:
            running = (self._thread is not None and
                       self._thread.is_alive())
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


def get_watchdog() -> AwgWatchdog:
    """Глобальный экземпляр. Лениво подхватывает настройки."""
    global _watchdog
    if _watchdog is None:
        with _watchdog_lock:
            if _watchdog is None:
                _watchdog = AwgWatchdog()
                _watchdog.reconfigure()
    return _watchdog
