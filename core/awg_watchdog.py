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

import socket
import threading
import time

from core.log_buffer import log


# ─────── defaults ───────

DEFAULT_HANDSHAKE_TIMEOUT_SEC = 180   # 3 минуты без handshake → рестарт
DEFAULT_CHECK_INTERVAL_SEC    = 30    # частота проверки
DEFAULT_COOLDOWN_SEC          = 300   # пауза после рестарта — не дёргать снова
DEFAULT_MAX_RESTARTS_PER_HOUR = 6     # защита от петли

# Активная проба «качества» через туннель (опц.). Ловит случай, когда
# handshake ещё «свежий», но трафик через туннель уже не идёт (сайты
# тормозят → сеть отваливается; помогает рестарт). Проба делается с
# привязкой к интерфейсу туннеля (SO_BINDTODEVICE), т.е. реально через него.
#
# ВАЖНО: на роутере SO_BINDTODEVICE может молча не сработать (нужен root/
# capability, особенности musl/uclibc) — тогда проба уйдёт мимо туннеля по
# обычному WAN и даст ложный «жив». Поэтому она НЕ главный сигнал; основной
# детектор «данные не идут» — пассивный rx-stall ниже (счётчики самого
# демона, обойти их нельзя).
DEFAULT_PROBE_ENABLED       = False
DEFAULT_PROBE_HOST          = "1.1.1.1"
DEFAULT_PROBE_PORT          = 443
DEFAULT_PROBE_TIMEOUT_SEC   = 4
DEFAULT_PROBE_FAIL_THRESHOLD = 2      # подряд неудач → рестарт

# Пассивный детектор застоя приёма. Туннель ШЛЁТ (tx растёт), но НИЧЕГО не
# ПРИНИМАЕТ (rx стоит) дольше порога — классическое «92 B in / 20 KB out»:
# handshake может оставаться свежим (control-plane жив), а данные сервер
# дропает. Считаем по счётчикам `awg show` (rx_bytes/tx_bytes) — это правда
# от самого демона, без лишнего трафика и без обхода туннеля. Включён по
# умолчанию: на простое (tx тоже стоит) не срабатывает, а keepalive-шум
# отсекается порогом min_tx, поэтому ложных рестартов не даёт.
DEFAULT_RX_STALL_ENABLED      = True
DEFAULT_RX_STALL_TIMEOUT_SEC  = 120   # сек без единого принятого байта → рестарт
DEFAULT_RX_STALL_MIN_TX_BYTES = 4096  # столько надо отправить «в пустоту»,
                                      # чтобы это считалось застоем, а не
                                      # тишиной keepalive (~десятки байт/мин)


def probe_via_iface(host: str, port: int = 443, iface: str = "",
                    timeout: float = 4.0) -> bool:
    """
    TCP-проба host:port С ПРИВЯЗКОЙ к интерфейсу `iface` (через
    SO_BINDTODEVICE) — пакет уходит именно через туннель. True, если
    соединение установилось. Требует root (на роутере он есть); если
    bind не удался — проба всё равно выполняется (но уже не гарантирует
    маршрут через туннель).
    """
    if not host:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if iface:
            try:
                s.setsockopt(socket.SOL_SOCKET, 25,  # SO_BINDTODEVICE
                             (iface + "\0").encode())
            except (OSError, AttributeError):
                pass
        s.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def eval_rx_stall(state, rx_bytes, tx_bytes, now: float, *,
                  timeout: int, min_tx: int) -> tuple:
    """
    Пассивный детектор «приём встал»: туннель ШЛЁТ (tx растёт), но НИЧЕГО
    не ПРИНИМАЕТ (rx стоит) дольше `timeout`, отправив при этом не меньше
    `min_tx` байт «в пустоту». Это ровно картина зависания (handshake может
    быть свежим, а data-пакеты сервер дропает).

    Чистая функция: состояние НЕ хранит, принимает и возвращает его явно
    (удобно для юнит-тестов). Возвращает (new_state, stalled: bool).

      state — {"rx", "tx_at_rx", "rx_ts"} с прошлого замера или None.
      now   — текущее время (сек).

    Логика без ложных срабатываний:
      * первый замер или сброс счётчиков (после рестарта rx/tx обнуляются)
        — ре-базируемся, решения не принимаем;
      * любой прирост rx → что-то приняли, туннель жив → сброс отсчёта;
      * rx стоит → считаем, сколько отправили и сколько ждём С МОМЕНТА
        последнего приёма; застой = (tx_since >= min_tx) И (age >= timeout).
        На простое (tx тоже стоит) tx_since=0 < min_tx → не срабатывает;
        keepalive-шум (десятки байт) ниже min_tx → тоже не срабатывает.
    """
    rx = int(rx_bytes or 0)
    tx = int(tx_bytes or 0)
    prev_rx = int((state or {}).get("rx", 0))
    prev_tx_at_rx = int((state or {}).get("tx_at_rx", 0))
    # Первый замер / сброс счётчиков (rx или tx «откатились» — рестарт демона).
    if state is None or rx < prev_rx or tx < prev_tx_at_rx:
        return ({"rx": rx, "tx_at_rx": tx, "rx_ts": now}, False)
    # Приняли новые байты — туннель жив, перезапускаем отсчёт от текущего tx.
    if rx > prev_rx:
        return ({"rx": rx, "tx_at_rx": tx, "rx_ts": now}, False)
    # rx стоит: сохраняем точку последнего приёма (tx_at_rx/rx_ts), копим.
    rx_ts = float((state or {}).get("rx_ts", now))
    new_state = {"rx": rx, "tx_at_rx": prev_tx_at_rx, "rx_ts": rx_ts}
    tx_since = tx - prev_tx_at_rx
    age = now - rx_ts
    stalled = (tx_since >= max(0, min_tx)) and (age >= timeout)
    return (new_state, stalled)


def decide_restart(*, handshake_age, handshake_timeout: int,
                   probe_enabled: bool, probe_consecutive_fails: int,
                   probe_threshold: int, rx_stalled: bool = False) -> tuple:
    """
    Чистое решение «рестартить ли туннель». Возвращает (bool, reason).

      handshake_age — секунд с последнего handshake (или None, если его
                      ещё не было / нет peer'ов);
      probe_*    — активная проба через туннель (опц., может обходить туннель);
      rx_stalled — пассивный детектор «приём встал» (главный сигнал «данные
                   не идут», см. eval_rx_stall).
    """
    if probe_enabled and probe_consecutive_fails >= max(1, probe_threshold):
        return (True, "проба через туннель не прошла %d раз подряд"
                % probe_consecutive_fails)
    if rx_stalled:
        return (True, "туннель шлёт, но не принимает (данные не идут)")
    if handshake_age is not None and handshake_age >= handshake_timeout:
        return (True, "handshake %dс назад (>%dс)"
                % (handshake_age, handshake_timeout))
    return (False, "")


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
        "probe_enabled":            bool(wd.get(
            "probe_enabled", DEFAULT_PROBE_ENABLED)),
        "probe_host":               str(wd.get(
            "probe_host", DEFAULT_PROBE_HOST) or DEFAULT_PROBE_HOST),
        "probe_port":               int(wd.get(
            "probe_port", DEFAULT_PROBE_PORT)),
        "probe_timeout_sec":        int(wd.get(
            "probe_timeout_sec", DEFAULT_PROBE_TIMEOUT_SEC)),
        "probe_fail_threshold":     int(wd.get(
            "probe_fail_threshold", DEFAULT_PROBE_FAIL_THRESHOLD)),
        "rx_stall_enabled":         bool(wd.get(
            "rx_stall_enabled", DEFAULT_RX_STALL_ENABLED)),
        "rx_stall_timeout_sec":     int(wd.get(
            "rx_stall_timeout_sec", DEFAULT_RX_STALL_TIMEOUT_SEC)),
        "rx_stall_min_tx_bytes":    int(wd.get(
            "rx_stall_min_tx_bytes", DEFAULT_RX_STALL_MIN_TX_BYTES)),
    }


def set_settings(**kwargs) -> dict:
    """Обновить настройки watchdog'а (персистентно). Возвращает актуальные."""
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        for k, v in kwargs.items():
            if v is None:
                continue
            cm.set("awg", "watchdog", k, v)
        cm.save()
    except Exception as e:
        log.warning("awg_watchdog: save settings: %s" % e, source="awg")

    # При смене enabled-флага дёрнем синглтон, чтобы он стартанул/
    # остановил поток.
    get_watchdog().reconfigure()
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
        # Счётчик подряд-неудачных проб: {iface: int}
        self._probe_fails  = {}
        # Состояние пассивного rx-stall детектора: {iface: {rx, tx_at_rx, rx_ts}}
        self._rx_state     = {}

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
            # Синглтон: общий лок с интерактивными up/down/restart, иначе
            # рестарт watchdog'ом может гоняться с действием пользователя.
            from core.awg_manager import get_awg_manager
            mgr = get_awg_manager()
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

        # Воскрешение упавших интерфейсов: если включено авто-переподключение,
        # а autostart-туннель (тот, что ДОЛЖЕН быть поднят) лежит — поднять
        # его заново. Ловит случай, когда демон/интерфейс умер целиком (а не
        # просто протух handshake): в list_interfaces его уже нет, обычная
        # ветка рестарта не сработает.
        self._resurrect_down_autostart(mgr, settings, now)

    def _maybe_restart(self, mgr, iface: str, status: dict,
                        settings: dict, now: float):
        """Принять решение по одному интерфейсу."""
        # Cooldown — даём время туннелю установить handshake после рестарта.
        last = self._last_restart.get(iface, 0)
        if (now - last) < settings["cooldown_sec"]:
            return

        # Возраст самого свежего handshake по peer'ам (None — если ещё
        # не было / нет peer'ов: на первом подъёме не нервничаем). Заодно
        # копим суммарные счётчики rx/tx для пассивного детектора застоя.
        peers = status.get("peers") or []
        latest = 0
        rx_total = 0
        tx_total = 0
        for p in peers:
            try:
                latest = max(latest, int(p.get("latest_handshake") or 0))
            except (TypeError, ValueError):
                pass
            try:
                rx_total += int(p.get("rx_bytes") or 0)
                tx_total += int(p.get("tx_bytes") or 0)
            except (TypeError, ValueError):
                pass
        age = (int(now) - latest) if latest > 0 else None

        # Пассивный детектор «приём встал» (главный сигнал «данные не идут»;
        # ловит зависание даже при свежем handshake, без лишнего трафика).
        rx_stalled = False
        if settings.get("rx_stall_enabled", DEFAULT_RX_STALL_ENABLED) and peers:
            new_rx_state, rx_stalled = eval_rx_stall(
                self._rx_state.get(iface), rx_total, tx_total, now,
                timeout=settings.get("rx_stall_timeout_sec",
                                     DEFAULT_RX_STALL_TIMEOUT_SEC),
                min_tx=settings.get("rx_stall_min_tx_bytes",
                                    DEFAULT_RX_STALL_MIN_TX_BYTES))
            self._rx_state[iface] = new_rx_state

        # Активная проба через туннель (если включена).
        probe_enabled = bool(settings.get("probe_enabled", False))
        probe_fails = self._probe_fails.get(iface, 0)
        if probe_enabled:
            ok = probe_via_iface(
                settings.get("probe_host", DEFAULT_PROBE_HOST),
                settings.get("probe_port", DEFAULT_PROBE_PORT), iface,
                settings.get("probe_timeout_sec", DEFAULT_PROBE_TIMEOUT_SEC))
            probe_fails = 0 if ok else probe_fails + 1
            self._probe_fails[iface] = probe_fails

        should, reason = decide_restart(
            handshake_age=age,
            handshake_timeout=settings["handshake_timeout_sec"],
            probe_enabled=probe_enabled,
            probe_consecutive_fails=probe_fails,
            probe_threshold=settings.get("probe_fail_threshold",
                                         DEFAULT_PROBE_FAIL_THRESHOLD),
            rx_stalled=rx_stalled)
        if not should:
            return

        # Rate limit: не больше N рестартов в час.
        history = self._restart_log.setdefault(iface, [])
        history[:] = [ts for ts in history if (now - ts) < 3600]
        if len(history) >= settings["max_restarts_per_hour"]:
            log.warning(
                "awg-watchdog: %s — %s, но лимит рестартов исчерпан"
                " (%d/час). Туннель нездоров — рассмотрите смену"
                " конфига/прокси или метод nfqws2 (failover в"
                " «Маршрутизации»)."
                % (iface, reason, settings["max_restarts_per_hour"]),
                source="awg")
            return

        log.warning("awg-watchdog: %s — %s; рестартую" % (iface, reason),
                    source="awg")
        try:
            mgr.restart(iface)
        except Exception as e:
            log.warning("awg-watchdog: restart %s: %s" % (iface, e),
                        source="awg")
            return
        self._last_restart[iface] = now
        self._probe_fails[iface] = 0
        # После рестарта счётчики обнулятся — забываем прошлый rx-snapshot,
        # чтобы следующий тик ре-базировался, а не считал «откат» застоем.
        self._rx_state.pop(iface, None)
        history.append(now)

    def _resurrect_down_autostart(self, mgr, settings: dict, now: float):
        """
        Поднять заново autostart-интерфейсы, которые сейчас лежат.

        Гейтится autostart-флагом (а не «видели поднятым»), чтобы НЕ
        воскрешать туннели, которые пользователь остановил сам: autostart =
        явное «этот туннель должен быть поднят». Cooldown и rate-limit —
        общие с рестартами (тот же _last_restart/_restart_log по имени),
        поэтому конфиг, который не поднимается, не уходит в цикл.
        """
        try:
            from core.awg_autostart_manager import get_awg_autostart_manager
            wanted = get_awg_autostart_manager().get_enabled_interfaces()
        except Exception as e:
            log.warning("awg-watchdog: список autostart: %s" % e, source="awg")
            return
        if not wanted:
            return

        try:
            existing = {c["name"] for c in mgr.list_configs()}
        except Exception:
            existing = set(wanted)

        for name in wanted:
            if name not in existing:
                continue  # конфиг удалён — поднимать нечего
            try:
                if mgr.is_running(name):
                    continue
            except Exception:
                continue

            # Cooldown — не дёргаем чаще, чем туннелю нужно на подъём.
            last = self._last_restart.get(name, 0)
            if (now - last) < settings["cooldown_sec"]:
                continue
            # Rate limit — общий с рестартами: не больше N/час.
            history = self._restart_log.setdefault(name, [])
            history[:] = [ts for ts in history if (now - ts) < 3600]
            if len(history) >= settings["max_restarts_per_hour"]:
                log.warning(
                    "awg-watchdog: %s (autostart) лежит, но лимит подъёмов"
                    " исчерпан (%d/час) — конфиг не поднимается, проверьте его"
                    % (name, settings["max_restarts_per_hour"]),
                    source="awg")
                continue

            log.warning("awg-watchdog: %s (autostart) не поднят — поднимаю"
                        % name, source="awg")
            try:
                r = mgr.up(name)
            except Exception as e:
                log.warning("awg-watchdog: up %s: %s" % (name, e), source="awg")
                history.append(now)
                self._last_restart[name] = now
                continue
            self._last_restart[name] = now
            self._rx_state.pop(name, None)
            history.append(now)
            if not r.get("ok"):
                log.warning("awg-watchdog: не удалось поднять %s: %s"
                            % (name, r.get("message", "ошибка")), source="awg")

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
