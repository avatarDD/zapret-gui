# core/tunnels_overview.py
"""
Одна картина по всем туннельным движкам сразу.

Зачем отдельный модуль. Шесть движков (sing-box, mihomo, AmneziaWG,
MASQUE/usque, Telegram-прокси, Opera Proxy) отвечают о себе шестью
разными способами: где-то ``list_configs()`` + ``status(name)``, где-то
``get_status()`` без аргументов, где-то ``detect()`` отдельно от
состояния. Пока каждый потребитель собирает эту мозаику сам, вопрос «что
вообще поднято на роутере» стоит шесть вызовов и шесть разборов формата —
и один упавший движок роняет весь ответ.

Здесь мозаика собирается **один раз**, в общую форму записи (см.
:func:`engine_record`), и каждый движок опрашивается под своим ``try``:
на устройстве без половины движков ответ всё равно собирается.

Модуль ничего не запускает и не меняет — только читает состояние.

Про трафик отдельно. Движки считают его по-разному: у TUN-интерфейсов
байты лежат в ``/sys/class/net``, у AmneziaWG их отдаёт ``awg show`` по
пирам, у нативного Keenetic-WG — NDMS, а у Telegram- и Opera-прокси
интерфейса нет вовсе и считать нечего. Поэтому число сопровождается
полем ``traffic_source``, а там, где честного источника нет, стоит
``traffic: None`` — «неизвестно» полезнее красивого нуля, который читается
как «трафика не было».
"""

import re
import time

from core.log_buffer import log
from core.tunnel_monitor import iface_counters


# Движки в порядке, в котором их показывает GUI.
ENGINES = ("singbox", "mihomo", "awg", "usque", "tgproxy", "opera")

# Человеческие названия — чтобы модель не гадала, что такое `usque`.
TITLES = {
    "singbox": "sing-box",
    "mihomo":  "mihomo (Clash.Meta)",
    "awg":     "AmneziaWG",
    "usque":   "MASQUE / usque (WARP)",
    "tgproxy": "Telegram-прокси",
    "opera":   "Opera Proxy",
}

# Сколько строк лога просматриваем в поисках последней ошибки.
LOG_LINES = 60

# Маркеры строки лога, по которым она считается сообщением об ошибке.
# Список намеренно короткий: нам нужна последняя понятная жалоба движка,
# а не классификация всего, что он написал.
_ERROR_MARKERS = re.compile(
    r"(?i)\b(error|fatal|panic|failed|failure|refused|timeout|denied|"
    r"ошибка|не удалось)\b")

# Длиннее этого строку лога наружу не отдаём: «последняя ошибка» — это
# подсказка, а не журнал (за журналом идут в read_log движка).
MAX_ERROR_LEN = 300


def overview(engine: str = "", logs: bool = True) -> dict:
    """Состояние всех движков (или одного, если задан ``engine``).

    Args:
        engine: ключ из :data:`ENGINES`; пусто — все.
        logs:   искать ли последнюю ошибку в логе движка. Чтение хвоста
                лога стоит заметно дороже остального, и вызывающему
                бывает нужен только «поднят/не поднят».

    Returns:
        ``{"engines": [запись, …], "total", "installed", "running",
        "known": [имена], "timestamp"}``. Неизвестное имя движка —
        ``{"ok": False, "error", "known"}``.
    """
    wanted = (engine or "").strip().lower()
    if wanted and wanted not in ENGINES:
        return {
            "ok": False,
            "error": "неизвестный движок: %s" % wanted,
            "known": list(ENGINES),
            "hint": "движок nfqws2 сюда не входит — он в nfqws_status",
        }

    names = [wanted] if wanted else list(ENGINES)
    records = [_collect(name, logs) for name in names]
    return {
        "ok": True,
        "engines": records,
        "total": len(records),
        "installed": sum(1 for r in records if r["installed"]),
        "running": sum(1 for r in records if r["running"]),
        "known": list(ENGINES),
        "timestamp": int(time.time()),
    }


def engine_record(name: str, *, installed=False, running=False, version="",
                  binary="", instances=None, reason="", error="",
                  **extra) -> dict:
    """Общая форма записи движка — на неё опираются MCP, UI и CLI.

    Поля одинаковы у всех шести движков, даже когда часть из них пуста:
    разнобой здесь означает, что потребителю нужно помнить, у кого есть
    ``iface``, а у кого ``bind``, — и он неизбежно ошибётся.
    """
    items = list(instances or [])
    record = {
        "engine": name,
        "title": TITLES.get(name, name),
        "installed": bool(installed),
        "running": bool(running),
        "version": version or "",
        "binary": binary or "",
        "instances": items,
        "instances_count": len(items),
        "running_count": sum(1 for i in items if i.get("running")),
        "reason": reason or "",
        "error": error or "",
    }
    record.update(extra)
    return record


def instance_record(name: str, *, running=False, pid=None, iface="",
                    config="", traffic=None, traffic_source="",
                    last_error="", **extra) -> dict:
    """Общая форма записи инстанса (конфиг, интерфейс или подпроцесс)."""
    item = {
        "name": name,
        "running": bool(running),
        "pid": pid if running else None,
        "iface": iface or "",
        "config": config or "",
        "traffic": traffic,
        "traffic_source": traffic_source or "",
        "last_error": last_error or "",
    }
    item.update(extra)
    return item


# ─────────────────────────── сбор по движкам ────────────────────────

def _collect(name: str, logs: bool) -> dict:
    """Опросить один движок, не дав ему уронить остальные."""
    collector = _COLLECTORS[name]
    try:
        return collector(logs)
    except Exception as e:                      # noqa: BLE001 — граница
        log.warning("tunnels_overview: %s не опрошен: %s: %s"
                    % (name, type(e).__name__, e), source="mcp")
        return engine_record(
            name, error="%s: %s" % (type(e).__name__, e),
            reason="движок не удалось опросить — подробности в error")


def _collect_singbox(logs: bool) -> dict:
    from core.singbox_detector import get_singbox_detector
    from core.singbox_manager import get_singbox_manager

    info = get_singbox_detector().detect_binary()
    if not info.get("installed"):
        return engine_record("singbox", reason="бинарник sing-box не найден")

    manager = get_singbox_manager()
    instances = []
    for cfg in manager.list_configs() or []:
        iface = cfg.get("tun_iface") or ""
        running = bool(cfg.get("running"))
        instances.append(instance_record(
            cfg.get("name", ""),
            running=running,
            pid=(manager.status(cfg.get("name", "")) or {}).get("pid"),
            iface=iface,
            config=cfg.get("path", ""),
            last_error=_log_error(logs and running,
                                  manager.read_log, cfg.get("name", ""),
                                  LOG_LINES),
            **_traffic(iface if running else "")))
    return engine_record(
        "singbox", installed=True, version=info.get("version", ""),
        binary=info.get("path", ""), instances=instances,
        running=any(i["running"] for i in instances),
        reason=_why_idle(instances, "конфигов sing-box нет"))


def _collect_mihomo(logs: bool) -> dict:
    from core.mihomo_detector import get_mihomo_detector
    from core.mihomo_manager import get_mihomo_manager

    info = get_mihomo_detector().detect_binary()
    if not info.get("installed"):
        return engine_record("mihomo", reason="бинарник mihomo не найден")

    manager = get_mihomo_manager()
    instances = []
    for cfg in manager.list_configs() or []:
        iface = cfg.get("tun_iface") or ""
        running = bool(cfg.get("running"))
        instances.append(instance_record(
            cfg.get("name", ""),
            running=running,
            pid=(manager.status(cfg.get("name", "")) or {}).get("pid"),
            iface=iface,
            config=cfg.get("path", ""),
            # Конфиг без TUN — не поломка, а «mihomo как прокси на
            # порту». Без флага это читается как пропавший интерфейс.
            tun_enabled=bool(cfg.get("tun_enabled", bool(iface))),
            last_error=_log_error(logs and running,
                                  manager.read_log, cfg.get("name", ""),
                                  LOG_LINES),
            **_traffic(iface if running else "")))
    return engine_record(
        "mihomo", installed=True, version=info.get("version", ""),
        binary=info.get("path", ""), instances=instances,
        running=any(i["running"] for i in instances),
        reason=_why_idle(instances, "конфигов mihomo нет"))


def _collect_awg(logs: bool) -> dict:
    from core.awg_installer import get_awg_installer
    from core.awg_manager import get_awg_manager

    info = get_awg_installer().get_installed_version()
    if not info.get("installed"):
        return engine_record(
            "awg", reason="бинарники amneziawg-go/awg не найдены")

    manager = get_awg_manager()
    instances = []
    for cfg in manager.list_configs() or []:
        iface = cfg.get("iface") or cfg.get("name", "")
        running = bool(cfg.get("active"))
        state = manager.status(iface) if running else {}
        instances.append(instance_record(
            cfg.get("name", ""),
            running=running,
            pid=state.get("pid"),
            iface=iface,
            config=cfg.get("path", ""),
            peers=len(state.get("peers") or []),
            last_handshake=_last_handshake(state),
            native=bool(state.get("native")),
            **_awg_traffic(state, iface, running)))
    return engine_record(
        "awg", installed=True,
        version=info.get("go_version", "") or info.get("tools_version", ""),
        binary=info.get("amneziawg_go", ""), instances=instances,
        running=any(i["running"] for i in instances),
        external=bool(info.get("external")),
        reason=_why_idle(instances, "конфигов AmneziaWG нет"))


def _collect_usque(logs: bool) -> dict:
    from core.usque_manager import get_usque_manager

    manager = get_usque_manager()
    info = manager.detect()
    if not info.get("installed"):
        return engine_record("usque", reason="бинарник usque не найден")

    instances = []
    for cfg in manager.list_configs() or []:
        iface = cfg.get("iface") or ""
        running = bool(cfg.get("active"))
        state = manager.status(iface) if (running and iface) else {}
        instances.append(instance_record(
            cfg.get("name", ""),
            running=running,
            pid=state.get("pid"),
            iface=iface,
            config=cfg.get("path", ""),
            # «Интерфейс есть» и «link поднят» — разные вещи: во втором
            # случае usque отработал, а адреса не доехали, и трафика не
            # будет (см. UsqueManager.status).
            iface_exists=bool(state.get("iface_exists")),
            link_up=bool(state.get("link_up")),
            last_error=_log_error(logs and running and bool(iface),
                                  manager.read_log, iface, LOG_LINES),
            **_traffic(iface if running else "")))
    # Туннели usque, поднятые не GUI (init.d S51usque из Entware и т.п.):
    # в instances их нет — управлять ими мы не можем, — но и молчать о них
    # нельзя: они держат интерфейс и память, а «running: false» про свои
    # профили читался как «usque на роутере не работает».
    external = []
    for ext in info.get("external") or []:
        iface = ext.get("iface") or ""
        traffic = _traffic(iface)
        external.append(instance_record(
            iface or ("pid %s" % ext.get("pid")),
            running=True, pid=ext.get("pid"), iface=iface,
            config=ext.get("config", ""), cmdline=ext.get("cmdline", ""),
            **traffic))
    reason = _why_idle(instances, "конфигов usque нет")
    if external and not any(i["running"] for i in instances):
        reason = ("свои профили не запущены, но работает usque, поднятый "
                  "не GUI (%s) — им управляет его init-скрипт"
                  % ", ".join(e["iface"] or e["name"] for e in external))
    return engine_record(
        "usque", installed=True, version=info.get("version", ""),
        binary=info.get("binary", ""), instances=instances,
        running=any(i["running"] for i in instances),
        external_instances=external,
        reason=reason)


def _collect_tgproxy(logs: bool) -> dict:
    """Telegram-прокси — это два движка под одной страницей GUI.

    Основной (tg-ws-proxy-go) и резервный (tg-mtproxy-client) ставятся и
    запускаются независимо, поэтому каждый — отдельный инстанс. Два
    запущенных сразу — это две разные ссылки ``tg://proxy``, и приложение
    воспользуется только одной.
    """
    from core import tgproxy_manager as tg

    instances = []
    installed = False

    ws = tg.get_tgwsproxy_manager()
    ws_detect = ws.detect()
    ws_status = ws.get_status()
    if ws_detect.get("installed"):
        installed = True
        instances.append(instance_record(
            "tgwsproxy", running=bool(ws_status.get("running")),
            config=ws_detect.get("config_dir", ""),
            bind=_bind(ws_status.get("host"), ws_status.get("port")),
            version=ws_detect.get("version", ""),
            package=ws_detect.get("package", ""),
            traffic_source=""))

    mt = tg.get_mtproxy_client_manager()
    mt_detect = mt.detect()
    mt_status = mt.get_status()
    if mt_detect.get("installed"):
        installed = True
        instances.append(instance_record(
            "mtproto", running=bool(mt_status.get("running")),
            bind=_bind(mt_status.get("host"), mt_status.get("port")),
            version=mt_detect.get("version", ""),
            # Форвардер без правила REDIRECT бесполезен: трафик на его
            # порт никто не заворачивает, и «running» ничего не значит.
            redirect_active=bool(mt_status.get("redirect_active")),
            traffic_source=""))

    if not installed:
        return engine_record(
            "tgproxy", reason="ни tg-ws-proxy, ни tg-mtproxy-client не "
                              "установлены")
    return engine_record(
        "tgproxy", installed=True, instances=instances,
        running=any(i["running"] for i in instances),
        version=instances[0].get("version", ""),
        reason=_why_idle(instances, "движки Telegram-прокси не запущены"))


def _collect_opera(logs: bool) -> dict:
    from core.opera_proxy_manager import get_opera_proxy_manager

    manager = get_opera_proxy_manager()
    info = manager.detect()
    if not info.get("installed"):
        return engine_record("opera", reason="бинарник opera-proxy не найден")

    # probe=False: статус зовут из сводки, а проба открывает соединение
    # на bind-адрес. Слушает ли порт — вопрос healthcheck'а (S8), не
    # инвентаризации.
    status = manager.status(probe=False)
    running = bool(status.get("running"))
    instance = instance_record(
        "opera-proxy", running=running, pid=status.get("pid"),
        bind=status.get("bind", ""),
        last_error=_log_error(logs and running, manager.read_log,
                              LOG_LINES),
        traffic_source="")
    return engine_record(
        "opera", installed=True, version=info.get("version", ""),
        binary=info.get("binary", ""), instances=[instance],
        running=running,
        country=_opera_country(),
        reason="" if running else "opera-proxy установлен, но не запущен")


_COLLECTORS = {
    "singbox": _collect_singbox,
    "mihomo":  _collect_mihomo,
    "awg":     _collect_awg,
    "usque":   _collect_usque,
    "tgproxy": _collect_tgproxy,
    "opera":   _collect_opera,
}


# ───────────────────────────── частности ────────────────────────────

def _traffic(iface: str) -> dict:
    """Счётчики TUN-интерфейса из ``/sys/class/net``, если они есть."""
    counters = iface_counters(iface) if iface else None
    if not counters:
        return {"traffic": None, "traffic_source": ""}
    return {"traffic": counters, "traffic_source": "/sys/class/net"}


def _awg_traffic(state: dict, iface: str, running: bool) -> dict:
    """Байты AmneziaWG: сумма по пирам, а не счётчики интерфейса.

    У userspace-туннеля счётчики ``/sys/class/net`` считают и служебный
    трафик, а ``awg show`` отдаёт ровно то, что прошло через пиров, — и
    заодно работает для нативного Keenetic-WG, которого в
    ``/sys/class/net`` может не быть под тем же именем.
    """
    if not running:
        return {"traffic": None, "traffic_source": ""}
    if state.get("native"):
        return {"traffic": {"rx_bytes": int(state.get("rx_bytes") or 0),
                            "tx_bytes": int(state.get("tx_bytes") or 0)},
                "traffic_source": "ndms"}
    peers = state.get("peers") or []
    if peers:
        return {"traffic": {
            "rx_bytes": sum(int(p.get("rx_bytes") or 0) for p in peers),
            "tx_bytes": sum(int(p.get("tx_bytes") or 0) for p in peers)},
            "traffic_source": "awg show"}
    return _traffic(iface)


def _last_handshake(state: dict) -> int:
    """Самый свежий handshake среди пиров (0 — не было ни одного)."""
    if state.get("last_handshake"):
        return int(state["last_handshake"])
    peers = state.get("peers") or []
    stamps = [int(p.get("latest_handshake") or 0) for p in peers]
    return max(stamps) if stamps else 0


def _log_error(enabled, reader, *args) -> str:
    """Последняя строка-жалоба из лога движка, если он её оставил."""
    if not enabled:
        return ""
    try:
        payload = reader(*args)
    except Exception:                           # noqa: BLE001 — граница
        return ""
    if not isinstance(payload, dict):
        return ""
    return last_error(payload.get("log") or "")


def last_error(text: str) -> str:
    """Последняя строка текста, похожая на сообщение об ошибке.

    Именно последняя: движок, упавший на старте, пишет причину один раз,
    а дальше повторяет попытки — первая строка устареет, последняя нет.
    """
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line and _ERROR_MARKERS.search(line):
            return line[:MAX_ERROR_LEN]
    return ""


def _why_idle(instances: list, empty_reason: str) -> str:
    """Почему движок установлен, но ничего не поднято."""
    if not instances:
        return empty_reason
    if any(i.get("running") for i in instances):
        return ""
    return "конфиги есть (%d), но ни один не запущен" % len(instances)


def _bind(host, port) -> str:
    """``host:port`` в одну строку; пустые части не выдумываем."""
    if not port:
        return ""
    return "%s:%s" % (host or "0.0.0.0", port)


def _opera_country() -> str:
    try:
        from core.config_manager import get_config_manager
        return get_config_manager().get("opera_proxy", "country",
                                        default="") or ""
    except Exception:                           # noqa: BLE001 — граница
        return ""


def known_engines() -> list:
    """Ключи движков и их названия — для UI и подсказок модели."""
    return [{"engine": name, "title": TITLES[name]} for name in ENGINES]
