# core/awg_warp_in_warp.py
"""
WARP-in-WARP: двойной туннель.

Идея:
  * outer — первый AWG-WARP интерфейс. Его endpoint доступен через
    физический WAN (обычное поведение).
  * inner — второй AWG-WARP интерфейс. Его endpoint мы принудительно
    маршрутизируем через outer, чтобы handshake/keepalive пакеты
    inner'а проходили внутри outer-туннеля.
  * Пользовательский трафик идёт через inner.

Технически:
  1) Поднимаем outer. AwgManager._add_default_via() кладёт default
     маршрут в отдельную таблицу T_outer и добавляет ip rule
     «not fwmark T_outer → T_outer».
  2) Резолвим IP endpoint'а inner-конфига.
  3) В main-таблицу добавляем /32 route на inner_endpoint_ip через
     dev <outer>. Это гарантирует, что handshake-пакеты inner'а,
     помеченные его fwmark и потому не попадающие в его собственную
     таблицу, всё равно находят дорогу — через outer.
  4) Поднимаем inner. Его ip rule имеет более высокий приоритет
     (добавлен позже) — весь незамаркированный трафик уходит через
     inner.

Состояние сохраняем в settings.json (config["awg"]["warp_in_warp"]):
  {
    "active":               bool,
    "outer":                "<имя>",
    "inner":                "<имя>",
    "inner_endpoint_ip":    "1.2.3.4",
    "inner_endpoint_v6":    "" | "...",
    "outer_started_by_us":  bool,
    "inner_started_by_us":  bool,
    "started_at":           int,
  }
"""

import ipaddress
import socket
import subprocess
import threading
import time

from core.awg_config import parse_conf
from core.awg_manager import get_awg_manager
from core.config_manager import get_config_manager
from core.log_buffer import log


# ───────────────────────── helpers ──────────────────────────────────

def _run(args, timeout=10):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _split_endpoint(endpoint: str):
    """'host:port' / '[ipv6]:port' → (host, port)."""
    if not endpoint:
        return "", ""
    s = str(endpoint).strip()
    if s.startswith("["):
        rb = s.find("]")
        if rb > 0 and len(s) > rb + 1 and s[rb + 1] == ":":
            return s[1:rb], s[rb + 2:]
        return "", ""
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, port
    return s, ""


def _resolve_endpoint(host: str):
    """
    Резолвим хост → (ipv4 или None, ipv6 или None). Если уже IP —
    возвращаем сам IP в соответствующее поле.
    """
    if not host:
        return None, None
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return host, None
        return None, host
    except ValueError:
        pass

    v4 = None
    v6 = None
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except (socket.gaierror, OSError):
        return None, None

    for fam, _t, _p, _c, sa in infos:
        if fam == socket.AF_INET and v4 is None:
            v4 = sa[0]
        elif fam == socket.AF_INET6 and v6 is None:
            v6 = sa[0]
    return v4, v6


def _read_inner_endpoint(name: str):
    """
    Прочитать endpoint первого peer'а из конфига. Возвращает
    (host, port_str). Бросает ValueError если конфиг невалиден.
    """
    mgr = get_awg_manager()
    cfg = mgr.get_config(name)  # бросит FileNotFoundError если нет
    parsed = cfg.get("parsed") or parse_conf(cfg.get("text") or "")
    peers = parsed.get("peers") or []
    if not peers:
        raise ValueError("В конфиге %s нет [Peer]" % name)
    endpoint = (peers[0] or {}).get("Endpoint") or ""
    host, port = _split_endpoint(endpoint)
    if not host:
        raise ValueError("Не удалось разобрать Endpoint конфига %s" % name)
    return host, port


def _route_exists(family: str, dest: str, dev: str) -> bool:
    rc, out, _ = _run(["ip", family, "route", "show", dest], timeout=5)
    if rc != 0 or not out:
        return False
    for line in out.splitlines():
        # строка вида: "1.2.3.4 dev awg-outer scope link"
        parts = line.split()
        if "dev" in parts:
            i = parts.index("dev")
            if i + 1 < len(parts) and parts[i + 1] == dev:
                return True
    return False


# ───────────────────────── state ────────────────────────────────────

DEFAULT_STATE = {
    "active":              False,
    "outer":               "",
    "inner":               "",
    "inner_endpoint_ip":   "",
    "inner_endpoint_v6":   "",
    "outer_started_by_us": False,
    "inner_started_by_us": False,
    "started_at":          0,
}


def _state() -> dict:
    cm = get_config_manager()
    raw = cm.get("awg", "warp_in_warp") or {}
    out = dict(DEFAULT_STATE)
    if isinstance(raw, dict):
        for k, v in raw.items():
            out[k] = v
    return out


def _save_state(st: dict):
    cm = get_config_manager()
    cm.set("awg", "warp_in_warp", st)
    cm.save()


def _clear_state():
    _save_state(dict(DEFAULT_STATE))


# ───────────────────────── core API ─────────────────────────────────

_lock = threading.Lock()


def setup(outer: str, inner: str) -> dict:
    """
    Сконфигурировать WARP-in-WARP. Если оба интерфейса уже
    подняты — мы только пины маршрут и фиксируем состояние.
    """
    with _lock:
        return _do_setup(outer, inner)


def teardown() -> dict:
    """
    Разобрать WARP-in-WARP: убрать /32 route, опустить интерфейсы
    (только те, которые мы поднимали).
    """
    with _lock:
        return _do_teardown()


def status() -> dict:
    """Текущий статус (state + проверка интерфейсов и маршрута)."""
    with _lock:
        return _do_status()


# ───────────────────────── implementation ───────────────────────────

def _do_setup(outer: str, inner: str) -> dict:
    if not outer or not inner:
        return {"ok": False, "error": "Нужно указать outer и inner"}
    if outer == inner:
        return {"ok": False, "error": "outer и inner должны различаться"}

    cur = _state()
    if cur["active"]:
        return {"ok": False, "error":
                "WARP-in-WARP уже активен (%s → %s). "
                "Сначала отключите." % (cur.get("outer"), cur.get("inner"))}

    mgr = get_awg_manager()

    # Проверим, что оба конфига существуют
    try:
        outer_cfg = mgr.get_config(outer)
        inner_cfg = mgr.get_config(inner)
    except FileNotFoundError as e:
        return {"ok": False,
                "error": "Конфиг %s не найден" % e.args[0]}
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    if outer_cfg.get("errors"):
        return {"ok": False, "error":
                "Outer-конфиг содержит ошибки: " +
                "; ".join(outer_cfg["errors"])}
    if inner_cfg.get("errors"):
        return {"ok": False, "error":
                "Inner-конфиг содержит ошибки: " +
                "; ".join(inner_cfg["errors"])}

    # Резолвим endpoint inner ДО поднятия чего-либо: если outer
    # перехватит DNS — резолв может оказаться сложнее.
    try:
        host, _port = _read_inner_endpoint(inner)
    except (ValueError, FileNotFoundError) as e:
        return {"ok": False, "error": str(e)}

    inner_v4, inner_v6 = _resolve_endpoint(host)
    if not inner_v4 and not inner_v6:
        return {"ok": False, "error":
                "Не удалось резолвить endpoint inner (%s)" % host}

    log.info("WiW: inner endpoint %s → v4=%s v6=%s" %
             (host, inner_v4, inner_v6), source="awg_wiw")

    # 1) Поднять outer (если ещё не поднят)
    outer_was_up = mgr.is_running(outer)
    outer_started_by_us = False
    if not outer_was_up:
        res_o = mgr.up(outer)
        if not res_o.get("ok"):
            return {"ok": False, "error":
                    "Не удалось поднять outer: %s" %
                    res_o.get("message", "ошибка")}
        outer_started_by_us = True
        # дать туннелю установиться
        time.sleep(0.5)

    # 2) /32 route на inner endpoint через outer iface
    pinned = []
    if inner_v4:
        rc, _o, err = _run(["ip", "-4", "route", "add",
                            "%s/32" % inner_v4, "dev", outer])
        if rc == 0:
            pinned.append(("v4", "%s/32" % inner_v4))
        else:
            # Возможно маршрут уже есть (например, после неудачного
            # предыдущего setup) — попробуем replace.
            rc2, _o2, err2 = _run(["ip", "-4", "route", "replace",
                                   "%s/32" % inner_v4, "dev", outer])
            if rc2 != 0:
                _rollback_setup(outer, outer_started_by_us, pinned)
                return {"ok": False, "error":
                        "Не удалось добавить маршрут %s через %s: %s" %
                        (inner_v4, outer, (err2 or err).strip())}
            pinned.append(("v4", "%s/32" % inner_v4))

    if inner_v6:
        rc, _o, err = _run(["ip", "-6", "route", "add",
                            "%s/128" % inner_v6, "dev", outer])
        if rc == 0:
            pinned.append(("v6", "%s/128" % inner_v6))
        else:
            rc2, _o2, err2 = _run(["ip", "-6", "route", "replace",
                                   "%s/128" % inner_v6, "dev", outer])
            if rc2 == 0:
                pinned.append(("v6", "%s/128" % inner_v6))
            # IPv6 — не критично, не откатываемся

    # 3) Поднять inner
    inner_was_up = mgr.is_running(inner)
    inner_started_by_us = False
    if not inner_was_up:
        res_i = mgr.up(inner)
        if not res_i.get("ok"):
            # откат: убрать маршрут, опустить outer (если поднимали мы)
            for fam, dest in pinned:
                _run(["ip", "-4" if fam == "v4" else "-6",
                      "route", "del", dest, "dev", outer])
            if outer_started_by_us:
                mgr.down(outer)
            return {"ok": False, "error":
                    "Не удалось поднять inner: %s" %
                    res_i.get("message", "ошибка")}
        inner_started_by_us = True

    # 4) Сохранить state
    new_state = {
        "active":              True,
        "outer":               outer,
        "inner":               inner,
        "inner_endpoint_ip":   inner_v4 or "",
        "inner_endpoint_v6":   inner_v6 or "",
        "outer_started_by_us": outer_started_by_us,
        "inner_started_by_us": inner_started_by_us,
        "started_at":          int(time.time()),
    }
    _save_state(new_state)

    log.success("WARP-in-WARP активен: %s → %s" % (outer, inner),
                source="awg_wiw")
    return {
        "ok":      True,
        "message": "WARP-in-WARP активен",
        "state":   new_state,
    }


def _rollback_setup(outer: str, outer_started_by_us: bool,
                    pinned: list):
    """Откат части setup при ошибке между шагами."""
    for fam, dest in pinned:
        _run(["ip", "-4" if fam == "v4" else "-6",
              "route", "del", dest, "dev", outer])
    if outer_started_by_us:
        try:
            get_awg_manager().down(outer)
        except Exception:
            pass


def _do_teardown() -> dict:
    cur = _state()
    if not cur.get("active"):
        return {"ok": True, "message": "WARP-in-WARP не активен"}

    outer = cur.get("outer") or ""
    inner = cur.get("inner") or ""
    mgr = get_awg_manager()

    errors = []

    # 1) Опустить inner (если поднимали мы)
    if inner and cur.get("inner_started_by_us"):
        res = mgr.down(inner)
        if not res.get("ok"):
            errors.append("inner: %s" % res.get("message", "ошибка"))

    # 2) Убрать /32 route. dev может уже не существовать — просто
    # пробуем оба варианта.
    v4 = cur.get("inner_endpoint_ip") or ""
    v6 = cur.get("inner_endpoint_v6") or ""
    if outer:
        if v4:
            _run(["ip", "-4", "route", "del",
                  "%s/32" % v4, "dev", outer])
        if v6:
            _run(["ip", "-6", "route", "del",
                  "%s/128" % v6, "dev", outer])

    # 3) Опустить outer (если поднимали мы)
    if outer and cur.get("outer_started_by_us"):
        res = mgr.down(outer)
        if not res.get("ok"):
            errors.append("outer: %s" % res.get("message", "ошибка"))

    _clear_state()

    log.info("WARP-in-WARP отключён", source="awg_wiw")
    if errors:
        return {"ok": False, "error": "; ".join(errors),
                "message": "Отключено с ошибками"}
    return {"ok": True, "message": "WARP-in-WARP отключён"}


def _do_status() -> dict:
    cur = _state()
    out = {
        "ok":     True,
        "active": bool(cur.get("active")),
        "state":  cur,
    }

    if not cur.get("active"):
        return out

    mgr = get_awg_manager()
    outer = cur.get("outer") or ""
    inner = cur.get("inner") or ""

    outer_running = bool(outer) and mgr.is_running(outer)
    inner_running = bool(inner) and mgr.is_running(inner)

    v4 = cur.get("inner_endpoint_ip") or ""
    v6 = cur.get("inner_endpoint_v6") or ""
    route_v4_ok = bool(v4 and outer and _route_exists("-4", v4, outer))
    route_v6_ok = bool(v6 and outer and _route_exists("-6", v6, outer))

    healthy = outer_running and inner_running and (
        route_v4_ok if v4 else (route_v6_ok if v6 else False)
    )

    # Дополнительная инфа: статусы peer'ов и handshake
    try:
        outer_status = mgr.status(outer) if outer else {}
    except Exception:
        outer_status = {}
    try:
        inner_status = mgr.status(inner) if inner else {}
    except Exception:
        inner_status = {}

    out.update({
        "outer_running": outer_running,
        "inner_running": inner_running,
        "route_v4_ok":   route_v4_ok,
        "route_v6_ok":   route_v6_ok,
        "healthy":       healthy,
        "outer_status":  outer_status,
        "inner_status":  inner_status,
    })
    return out


# ───────────────────────── public helpers ───────────────────────────

def get_state() -> dict:
    """Текущее сохранённое состояние без проверок."""
    return _state()
