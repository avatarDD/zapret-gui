# core/usque_watchdog.py
"""
Watchdog для WARP/MASQUE (usque): автоматически рестартит туннель,
если probe через него не проходит.

Логика:
  1. Каждые N секунд (default 60) проверяем каждый активный usque-туннель.
  2. TCP-проба через туннельный интерфейс (SO_BINDTODEVICE).
  3. Если probe не проходит consecutive_failures раз подряд → restart.
  4. После рестарта — cooldown (не дёргаем снова N секунд).
  5. Защита от петли: максимум max_restarts_per_hour рестартов.
  6. Туннель, который watchdog остановил и не смог поднять, остаётся на
     его попечении: повторы идут на следующих тиках, пока туннель не
     поднимется или его не остановят руками (UsqueManager.stop_seq).
  7. Туннели WARP-in-WARP не трогаем: ими владеет свой watchdog
     (core/warp_in_warp_watchdog.py), а рестарт одного слоя в обход
     менеджера WARP-in-WARP рвёт закреплённый через outer маршрут.

По умолчанию ВЫКЛЮЧЕН (usque.watchdog.enabled = false).
"""

import socket
import subprocess
import threading
import time

from core.log_buffer import log


_DEFAULT_CHECK_INTERVAL = 60
_DEFAULT_PROBE_HOST = "1.1.1.1"
_DEFAULT_PROBE_PORT = 443
_DEFAULT_PROBE_TIMEOUT = 4
_DEFAULT_CONSECUTIVE_FAILURES = 3
_DEFAULT_COOLDOWN_SEC = 120
_DEFAULT_MAX_RESTARTS = 6

_SO_BINDTODEVICE = 25


def _probe_via_iface(host, port, iface, timeout=4.0):
    """TCP-проба через интерфейс."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if iface:
            try:
                s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE,
                             (iface + "\0").encode())
            except (OSError, AttributeError):
                return None
            try:
                got = s.getsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, 256)
                bound = got.split(b"\0", 1)[0].decode(errors="ignore")
            except (OSError, AttributeError):
                bound = ""
            if bound != iface:
                return None
        s.connect((host, int(port)))
        s.close()
        return True
    except OSError:
        return False
    except Exception:
        return None


class UsqueWatchdog:
    """Фоновый watchdog для usque WARP туннелей."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._fail_counts = {}  # iface -> consecutive fails
        self._restart_times = []  # timestamps of restarts
        self._last_restart = {}  # iface -> timestamp
        # iface -> {"path", "name", "seq"}: туннели, которые МЫ остановили и
        # не смогли поднять. seq — UsqueManager.stop_seq() сразу после
        # нашего stop(): вырос — значит, туннель останавливали снова, уже
        # не мы, и поднимать его против воли пользователя нельзя.
        self._pending = {}
        # iface -> транспорт последнего рестарта (для чередования в auto).
        self._last_profile = {}

    def reconfigure(self):
        """Перечитать конфиг и запустить/остановить watchdog."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("usque", "watchdog", "enabled", default=False):
            self._stop()
            return
        if not cfg.get("usque", "enabled", default=False):
            self._stop()
            return
        self._start()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            # Своё событие на каждый запуск. С общим на всех получалась
            # гонка: _stop() выставлял флаг, но не дожидался потока, а
            # следующий _start() сразу его сбрасывал — старый цикл
            # просыпался с уже чистым флагом и продолжал работать рядом
            # с новым (двойные пробы и рестарты одного туннеля).
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            t = threading.Thread(target=self._run_loop, args=(stop_evt,),
                                 name="usque-watchdog", daemon=True)
            t.start()
            self._thread = t
            log.info("usque-watchdog: запущен", source="usque")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("usque-watchdog: остановлен", source="usque")

    def _run_loop(self, stop_evt=None):
        from core.config_manager import get_config_manager
        if stop_evt is None:
            stop_evt = self._stop_evt
        while not stop_evt.is_set():
            interval = _DEFAULT_CHECK_INTERVAL
            try:
                cfg = get_config_manager()
                interval = _clamp_interval(cfg.get(
                    "usque", "watchdog", "interval_sec",
                    default=_DEFAULT_CHECK_INTERVAL))
                self._tick()
            except Exception as e:
                log.warning("usque-watchdog tick: %s" % e, source="usque")
            # Учитываем настроенный interval_sec, а не хардкод.
            stop_evt.wait(interval)

    def _tick(self):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        wiw = _warp_in_warp_ifaces()
        configs = mgr.list_configs()
        self._retry_pending(mgr, configs, wiw)
        for c in configs:
            if not c.get("active"):
                continue
            iface = c.get("iface", "")
            if not iface or iface in wiw:
                continue

            # Cooldown check
            last = self._last_restart.get(iface, 0)
            if (time.time() - last) < _DEFAULT_COOLDOWN_SEC:
                continue

            # Probe
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            host = cfg.get("usque", "watchdog", "probe_host",
                           default=_DEFAULT_PROBE_HOST)
            port = cfg.get("usque", "watchdog", "probe_port",
                           default=_DEFAULT_PROBE_PORT)

            result = _probe_via_iface(host, port, iface,
                                      timeout=_DEFAULT_PROBE_TIMEOUT)

            if result is True:
                # Probe прошёл — сбрасываем счётчик
                self._fail_counts.pop(iface, None)
                continue

            if result is None:
                # Недостоверно (нет root) — пропускаем
                continue

            # Probe не прошёл
            fails = self._fail_counts.get(iface, 0) + 1
            self._fail_counts[iface] = fails

            if fails >= _DEFAULT_CONSECUTIVE_FAILURES:
                from core import reachability
                if reachability.hold_restart("usque", iface):
                    continue
                self._do_restart(mgr, iface, c.get("name", ""))

    def _rate_limited(self, iface, now):
        recent = [t for t in self._restart_times if (now - t) < 3600]
        if len(recent) >= _DEFAULT_MAX_RESTARTS:
            log.warning("usque-watchdog: лимит рестартов (%d/час) — %s пропущен"
                        % (_DEFAULT_MAX_RESTARTS, iface), source="usque")
            return True
        return False

    def _note_restart(self, iface, now):
        self._last_restart[iface] = now
        self._restart_times.append(now)
        self._restart_times = [t for t in self._restart_times
                               if (now - t) < 7200]
        self._fail_counts.pop(iface, None)

    def _next_profile(self, iface):
        """Транспорт для рестарта.

        Профиль "auto" на старте переключиться не может: usque подключается
        лениво, поэтому при зарезанном UDP/443 процесс жив и интерфейс
        создан — start() возвращает успех, а H3-дозвон падает уже потом.
        Отказ транспорта наблюдаем только здесь (проба не прошла N раз
        подряд), поэтому auto чередует транспорт: первый рестарт — H2/TCP,
        следующий — снова H3. Раньше auto понижался до H2 навсегда, и
        туннель, однажды переживший сбой UDP, больше на H3 не возвращался.
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if cfg.get("usque", "http2_enable", default=False):
            return "restricted"
        profile = cfg.get("usque", "transport_profile", default="auto")
        if profile != "auto":
            return profile
        if self._last_profile.get(iface) == "restricted":
            log.info("usque-watchdog: %s — H2/TCP тоже не отвечает, пробуем"
                     " снова H3 (transport_profile=auto)" % iface,
                     source="usque")
            return "performance"
        log.info("usque-watchdog: %s — H3 не отвечает, поднимаем в"
                 " H2/TCP (transport_profile=auto)" % iface, source="usque")
        return "restricted"

    def _start_tunnel(self, mgr, iface, config_path):
        from core.config_manager import get_config_manager
        sni = get_config_manager().get("usque", "default_sni", default="")
        profile = self._next_profile(iface)
        self._last_profile[iface] = profile
        return mgr.start(iface, config_path, sni=sni,
                         transport_profile=profile)

    def _do_restart(self, mgr, iface, name):
        now = time.time()
        if self._rate_limited(iface, now):
            return

        from core import notify
        notify.event("tunnel", "🔁 WARP/MASQUE %s: перезапускаю (%s)"
                     % (iface, name))
        log.info("usque-watchdog: рестарт %s (%s)" % (iface, name),
                 source="usque")

        target = next((c for c in mgr.list_configs()
                       if c.get("iface") == iface or c.get("name") == name), None)
        config_path = target.get("path") if target else ""
        mgr.stop(iface)
        self._stop_evt.wait(1.0)

        if config_path:
            res = self._start_tunnel(mgr, iface, config_path)
            if res.get("ok"):
                self._pending.pop(iface, None)
            else:
                # Без этого туннель оставался лежать навсегда: в _tick()
                # проверяются только активные туннели, а этот после stop()
                # уже не активен. Запоминаем его и повторяем на следующих
                # тиках (с тем же cooldown и лимитом в час).
                self._pending[iface] = {"path": config_path, "name": name,
                                        "seq": mgr.stop_seq(iface)}
                log.warning("usque-watchdog: %s не поднялся после рестарта:"
                            " %s — повторим" % (iface,
                                                res.get("error", "неизвестно")),
                            source="usque")
        else:
            log.warning("usque-watchdog: конфиг для %s не найден — туннель"
                        " остановлен и не поднят" % iface, source="usque")

        self._note_restart(iface, now)

    def _retry_pending(self, mgr, configs, wiw=frozenset()):
        """Повторить подъём туннелей, которые мы остановили и не подняли."""
        by_iface = {c.get("iface"): c for c in configs if c.get("iface")}
        for iface, item in list(self._pending.items()):
            c = by_iface.get(iface)
            if (c is None or c.get("path") != item["path"]
                    or iface in wiw):
                # Профиль удалили, переименовали или забрал WARP-in-WARP.
                self._pending.pop(iface, None)
                continue
            if c.get("active"):
                # Подняли без нас (вручную или прошлый повтор) — дальше
                # туннель проверяется обычной пробой.
                self._pending.pop(iface, None)
                continue
            if mgr.stop_seq(iface) != item["seq"]:
                log.info("usque-watchdog: %s остановлен вручную — повторы"
                         " подъёма прекращены" % iface, source="usque")
                self._pending.pop(iface, None)
                continue
            now = time.time()
            if (now - self._last_restart.get(iface, 0)) < _DEFAULT_COOLDOWN_SEC:
                continue
            if self._rate_limited(iface, now):
                continue
            res = self._start_tunnel(mgr, iface, item["path"])
            self._note_restart(iface, now)
            if res.get("ok"):
                log.info("usque-watchdog: %s поднят повторно" % iface,
                         source="usque")
                self._pending.pop(iface, None)
            else:
                log.warning("usque-watchdog: %s снова не поднялся: %s"
                            % (iface, res.get("error", "неизвестно")),
                            source="usque")

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {
            "running": running,
            "fail_counts": dict(self._fail_counts),
            "recent_restarts": len([t for t in self._restart_times
                                    if (time.time() - t) < 3600]),
            "pending": sorted(self._pending),
        }


def _clamp_interval(value):
    """interval_sec из конфига → число секунд в 10..3600.

    API зажимает значение при записи, но в settings.json его могут
    положить и мимо API (ручная правка, config_set из MCP). Строка в
    stop_evt.wait() бросала TypeError вне try — и поток watchdog'а умирал
    молча; 0 превращал цикл в busy-loop.
    """
    try:
        value = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_CHECK_INTERVAL
    return max(10, min(value, 3600))


def _warp_in_warp_ifaces():
    """usque-интерфейсы, которыми сейчас владеет WARP-in-WARP."""
    try:
        from core.warp_in_warp import get_warp_in_warp_manager
        return get_warp_in_warp_manager().usque_ifaces()
    except Exception:
        return frozenset()


_instance = None
_instance_lock = threading.Lock()


def get_usque_watchdog():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = UsqueWatchdog()
    return _instance
