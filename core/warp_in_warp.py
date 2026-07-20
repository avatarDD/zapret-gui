# core/warp_in_warp.py
"""
WARP-in-WARP для MASQUE: двойной туннель через usque-keenetic и/или AWG.

Три режима (плюс AWG+AWG, реализованный отдельно в core/awg_warp_in_warp.py):
  masque_masque — оба туннеля через usque (H3/QUIC по умолчанию;
                    H2/TCP:443 — отдельный профиль)
  masque_awg    — внешний MASQUE (usque), внутренний AmneziaWG
  awg_masque    — внешний AmneziaWG, внутренний MASQUE (usque)

Схема:
  Клиент → inner → outer → интернет

Идея: внешний туннель маскирует внутренний — DPI сложнее детектировать
два разных протокола подряд, чем один.

──────────────────────────────────────────────────────────────────────
Это исправленная версия. Что было не так в исходной реализации и как
это исправлено здесь — см. ISSUE-020 / ISSUE-021 / ISSUE-001 в отчётах
аудита (claude-sonnet-5_review_zapretgui.md,
claude-sonnet-5_review_zapretgui_pass2.md):

1. ISSUE-020 (critical, AttributeError): было `self._outer_proc =
   mgr._process` — у UsqueManager нет атрибута `_process` (есть
   словарь `_processes`, приватный). Здесь вместо хранения "сырого"
   Popen-объекта мы всегда спрашиваем статус через публичный
   `usque_mgr.status(iface)["running"]` — это то же самое, что делает
   сам UsqueManager внутри, и не зависит от его внутреннего состояния.

2. ISSUE-020 (critical, TypeError): было `awg_mgr.up(iface, awg_conf)`
   — реальная сигнатура `AwgManager.up(name: str)` принимает ОДИН
   аргумент — имя УЖЕ ЗАРЕГИСТРИРОВАННОГO конфига (файл
   `<name>.conf` должен существовать в одном из конфиг-каталогов
   AWG). Здесь `awg_conf` — это имя такого конфига (как в
   core/awg_warp_in_warp.py, который эту же AWG API использует
   корректно), а не путь/содержимое произвольного файла. Раньше
   реализованная здесь же функция `_extract_awg_iface()` вообще
   всегда возвращала жёстко зашитую строку `"awg0"`, независимо от
   содержимого конфига, — она полностью удалена, интерфейсом теперь
   всегда является имя конфига (так работает AwgManager: `ifname =
   name`).

   ВАЖНО: это требует правки фронтенда и API — см. примечание в
   конце файла ("Что ещё нужно поправить снаружи").

3. ISSUE-021 (high): watchdog не мог перезапустить туннель, потому
   что WarpInWarpManager не сохранял параметры последнего успешного
   запуска. Здесь параметры сохраняются через config_manager
   (`warp_in_warp.last_start`) при каждом успешном `start()` и
   стираются при `stop()` — см. `warp_in_warp_watchdog.FIXED.py`,
   который теперь реально может вызвать `mgr.start(**saved_params)`.

4. Добавлена блокировка (`self._lock`) вокруг всего start()/stop() —
   в оригинале `self._lock` объявлялся в `__init__`, но нигде не
   использовался, то есть два одновременных запроса на запуск могли
   гоняться друг за другом.

5. Маршрутизация inner→outer переписана. Было:
   `ip rule add oif <inner_iface> lookup main` — эта команда ничего
   полезного не делает (генерирует правило policy-routing, которое
   почти всегда совпадает с уже существующим маршрутом по умолчанию,
   и не привязывает handshake-пакеты inner-туннеля к outer-туннелю).
   Правильный подход — тот же, что уже реализован и проверен в
   core/awg_warp_in_warp.py: закрепить /32 (или /128) маршрут до
   IP-адреса, на который стучится inner-туннель, через интерфейс
   outer. Для AWG-стороны (masque_awg/awg_masque) endpoint читается
   из [Peer]/Endpoint конфига — так же, как в awg_warp_in_warp.py, и
   переиспользует его вспомогательные функции. Для стороны usque
   (MASQUE) в этом репозитории нет ни задокументированного формата
   session-конфига usque, ни спецификации, куда именно стучится
   usque (это решает сам бинарник usque-keenetic по данным из своего
   session-файла) — поэтому для режима masque_masque закрепление
   маршрута выполняется только если явно передан
   `inner_endpoint_host` (см. параметры start()); если он не передан,
   функция явно логирует ограничение вместо того, чтобы делать вид,
   что что-то настроено (как это было в оригинале).
"""

import ipaddress
import shlex
import socket
import subprocess
import threading
from typing import Any, Optional

from core.log_buffer import log


# ─────── endpoint-резолвинг (общая логика с awg_warp_in_warp.py) ───────


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    """'host:port' / '[ipv6]:port' → (host, port)."""
    if not endpoint:
        return "", ""
    s = str(endpoint).strip()
    if s.startswith("["):
        rb = s.find("]")
        if rb > 0 and len(s) > rb + 1 and s[rb + 1] == ":":
            return s[1:rb], s[rb + 2 :]
        return "", ""
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, port
    return s, ""


def _resolve_host(host: str) -> tuple[Optional[str], Optional[str]]:
    """host → (ipv4 или None, ipv6 или None)."""
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


def _read_awg_endpoint(name: str) -> tuple[str, str]:
    """Endpoint первого peer'а AWG-конфига `name`. ValueError при проблеме."""
    from core.awg_manager import get_awg_manager
    from core.awg_config import parse_conf

    mgr = get_awg_manager()
    cfg = mgr.get_config(name)  # FileNotFoundError если конфига нет
    parsed = cfg.get("parsed") or parse_conf(cfg.get("text") or "")
    peers = parsed.get("peers") or []
    if not peers:
        raise ValueError("В AWG-конфиге %s нет [Peer]" % name)
    endpoint = (peers[0] or {}).get("Endpoint") or ""
    host, port = _split_endpoint(endpoint)
    if not host:
        raise ValueError("Не удалось разобрать Endpoint конфига %s" % name)
    return host, port


def _run(args: list[str], timeout: float = 10) -> tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _pin_route(dst_ip: str, via_iface: str, v6: bool = False) -> bool:
    """Закрепить /32 (или /128) маршрут на dst_ip через via_iface.

    Идемпотентно: если маршрут уже есть — просто заменяем (replace).
    """
    fam = "-6" if v6 else "-4"
    mask = "/128" if v6 else "/32"
    dest = dst_ip + mask
    rc, _o, err = _run(["ip", fam, "route", "add", dest, "dev", via_iface])
    if rc == 0:
        return True
    rc2, _o2, err2 = _run(["ip", fam, "route", "replace", dest, "dev", via_iface])
    if rc2 != 0:
        log.warning(
            "warp-in-warp: не удалось закрепить маршрут %s через %s: %s"
            % (dest, via_iface, (err2 or err).strip()),
            source="warp_in_warp",
        )
        return False
    return True


def _route_snapshot(dst_ip: str, v6: bool = False) -> str:
    fam = "-6" if v6 else "-4"
    mask = "/128" if v6 else "/32"
    rc, out, _err = _run(["ip", fam, "route", "show", "exact",
                           dst_ip + mask])
    return out.strip() if rc == 0 else ""


def _pin_route_owned(dst_ip: str, via_iface: str,
                     v6: bool = False) -> tuple[bool, str]:
    """Pin an endpoint and return the pre-existing route for restoration."""
    previous = _route_snapshot(dst_ip, v6)
    if previous and (" dev %s" % via_iface) in previous:
        return True, previous
    return _pin_route(dst_ip, via_iface, v6), previous


def _restore_route(dst_ip: str, via_iface: str, v6: bool,
                   previous: str) -> None:
    if previous:
        line = previous.splitlines()[0].strip()
        words = shlex.split(line)
        fam = "-6" if v6 else "-4"
        _run(["ip", fam, "route", "replace", *words])
    else:
        _unpin_route(dst_ip, via_iface, v6)


def _unpin_route(dst_ip: str, via_iface: str, v6: bool = False) -> None:
    if not dst_ip:
        return
    fam = "-6" if v6 else "-4"
    mask = "/128" if v6 else "/32"
    _run(["ip", fam, "route", "del", dst_ip + mask, "dev", via_iface])


# ─────── персистентное состояние (для watchdog'а) ───────


def _save_last_start(params: dict[str, Any]) -> None:
    """Сохранить параметры успешного запуска — нужно watchdog'у для
    реального рестарта (ISSUE-021)."""
    try:
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        cfg.set("warp_in_warp", "last_start", params)
        cfg.save()
    except Exception as e:
        log.warning(
            "warp-in-warp: не удалось сохранить last_start: %s" % e,
            source="warp_in_warp",
        )


def _load_last_start() -> dict:
    try:
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        return cfg.get("warp_in_warp", "last_start", default={}) or {}
    except Exception:
        return {}


def _clear_last_start() -> None:
    _save_last_start({})


# ─────────────────────────── manager ───────────────────────────────


class WarpInWarpManager:
    """Управление WARP-in-WARP (MASQUE-based: masque_masque / masque_awg /
    awg_masque). Потокобезопасен — все мутации состояния идут под
    self._lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self._outer_iface = ""
        self._inner_iface = ""
        self._mode = ""
        # какие /32-маршруты мы закрепили сами, чтобы снять их же при stop()
        self._pinned_routes = []  # list[(dst_ip, via_iface, v6_bool, previous)]
        self._owned_awg_outer = False
        self._owned_awg_inner = False

    def detect(self) -> dict[str, Any]:
        """Проверить доступность компонентов."""
        from core.usque_manager import get_usque_manager

        usque_mgr = get_usque_manager()
        usque_env: dict[str, Any] = usque_mgr.detect()

        awg_available = False
        for p in ["/opt/usr/sbin/amneziawg-go", "/usr/local/bin/amneziawg-go"]:
            import os

            if os.path.isfile(p) and os.access(p, os.X_OK):
                awg_available = True
                break

        return {
            "usque_installed": usque_env.get("installed", False),
            "awg_available": awg_available,
            "arch": usque_env.get("arch", ""),
        }

    def get_status(self) -> dict[str, Any]:
        """Статус WARP-in-WARP — реальная проверка через менеджеры, а не
        через хранимые Popen-объекты (см. ISSUE-020)."""
        with self._lock:
            return self._get_status_locked()

    def _get_status_locked(self) -> dict[str, Any]:
        """То же самое, но без захвата self._lock — для вызова из мест,
        которые уже держат self._lock (например, start()). self._lock —
        обычный threading.Lock(), не реентерабельный: повторный `with
        self._lock:` в том же потоке — гарантированный deadlock. Именно
        так и произошло при первом прогоне smoke-теста этого файла —
        start() дергал self.get_status() изнутри своего же `with
        self._lock:`."""
        mode, outer_iface, inner_iface = (
            self._mode,
            self._outer_iface,
            self._inner_iface,
        )

        outer_running = self._iface_running(outer_iface, mode, side="outer")
        inner_running = self._iface_running(inner_iface, mode, side="inner")

        return {
            "active": bool(mode) and outer_running and inner_running,
            "mode": mode,
            "outer_iface": outer_iface if outer_running else "",
            "inner_iface": inner_iface if inner_running else "",
            "outer_running": outer_running,
            "inner_running": inner_running,
        }

    def _iface_running(self, iface: str, mode: str, side: str) -> bool:
        """Проверить, активен ли интерфейс."""
        # side: "outer" | "inner"
        if not iface:
            return False
        is_awg_side = (side == "outer" and mode == "awg_masque") or (
            side == "inner" and mode == "masque_awg"
        )
        try:
            if is_awg_side:
                from core.awg_manager import get_awg_manager

                return get_awg_manager().is_running(iface)
            else:
                from core.usque_manager import get_usque_manager

                return bool(get_usque_manager().status(iface).get("running"))
        except Exception:
            return False

    # ─────────────────────────── start ───────────────────────────

    def start(
        self,
        mode: str = "masque_masque",
        outer_sni: str = "",
        inner_sni: str = "",
        outer_config: str = "",
        inner_config: str = "",
        awg_conf: str = "",
        inner_endpoint_host: str = "",
    ) -> dict[str, Any]:
        """
        Запустить WARP-in-WARP (MASQUE-based).

        outer_config / inner_config — путь к usque-сессии (.toml/.conf,
            как отдаёт UsqueManager.list_configs()).
        awg_conf — ИМЯ уже сохранённого AWG-конфига (не путь и не
            содержимое) — используется в masque_awg (inner) и
            awg_masque (outer).
        inner_endpoint_host — опционально: хост/IP, на который реально
            стучится inner usque-туннель (например, известный
            MASQUE-relay). Нужен только для режима masque_masque, чтобы
            закрепить его /32-маршрут через outer — без этого параметра
            для masque_masque маршрутизация между двумя MASQUE-туннелями
            не настраивается автоматически (см. docstring файла).
        """
        with self._lock:
            if self._get_status_locked().get("active"):
                return {"ok": False, "error": "WARP-in-WARP уже запущен"}

            if mode == "masque_masque":
                result = self._start_masque_masque(
                    outer_sni,
                    inner_sni,
                    outer_config,
                    inner_config,
                    inner_endpoint_host,
                )
            elif mode == "masque_awg":
                result = self._start_masque_awg(outer_sni, outer_config, awg_conf)
            elif mode == "awg_masque":
                result = self._start_awg_masque(awg_conf, inner_sni, inner_config)
            else:
                return {"ok": False, "error": "Неизвестный режим: %s" % mode}

            if result.get("ok"):
                _save_last_start(
                    {
                        "mode": mode,
                        "outer_sni": outer_sni,
                        "inner_sni": inner_sni,
                        "outer_config": outer_config,
                        "inner_config": inner_config,
                        "awg_conf": awg_conf,
                        "inner_endpoint_host": inner_endpoint_host,
                    }
                )
            return result

    def _start_masque_masque(
        self,
        outer_sni: str,
        inner_sni: str,
        outer_config: str,
        inner_config: str,
        inner_endpoint_host: str,
    ) -> dict[str, Any]:
        """MASQUE + MASQUE: оба туннеля через usque."""
        from core.usque_manager import get_usque_manager

        mgr = get_usque_manager()

        if not outer_config:
            return {"ok": False, "error": "Нужен outer usque конфиг"}
        if not inner_config:
            return {"ok": False, "error": "Нужен inner usque конфиг"}

        outer_iface = "opkgtun100"
        inner_iface = "opkgtun101"

        result = mgr.start(outer_iface, outer_config, sni=outer_sni)
        if not result.get("ok"):
            return {"ok": False, "error": "Outer: %s" % result.get("error")}

        # /32-маршрут inner-endpoint через outer — только если явно
        # передан хост. Без него намеренно ничего не закрепляем (см.
        # docstring файла) — оставлять фиктивный `ip rule` как раньше
        # хуже, чем честно ничего не делать.
        pinned = []
        if inner_endpoint_host:
            v4, v6 = _resolve_host(inner_endpoint_host)
            if v4:
                ok, previous = _pin_route_owned(v4, outer_iface, v6=False)
                if ok:
                    pinned.append((v4, outer_iface, False, previous))
            if v6:
                ok, previous = _pin_route_owned(v6, outer_iface, v6=True)
                if ok:
                    pinned.append((v6, outer_iface, True, previous))
        else:
            log.warning(
                "warp-in-warp: inner_endpoint_host не задан — маршрут "
                "inner-туннеля через outer НЕ закреплён, порядок default "
                "route между двумя MASQUE-сессиями не гарантирован",
                source="warp_in_warp",
            )

        result = mgr.start(inner_iface, inner_config, sni=inner_sni)
        if not result.get("ok"):
            for dst, via, v6, previous in pinned:
                _restore_route(dst, via, v6, previous)
            mgr.stop(outer_iface)
            return {"ok": False, "error": "Inner: %s" % result.get("error")}

        self._outer_iface = outer_iface
        self._inner_iface = inner_iface
        self._mode = "masque_masque"
        self._pinned_routes = pinned

        self._apply_optimizations(outer_iface, inner_iface, "warp", "warp")

        log.success(
            "warp-in-warp: MASQUE+MASQUE запущен (%s → %s)"
            % (inner_iface, outer_iface),
            source="warp_in_warp",
        )
        return {
            "ok": True,
            "mode": "masque_masque",
            "outer": outer_iface,
            "inner": inner_iface,
        }

    def _start_masque_awg(
        self, outer_sni: str, outer_config: str, awg_conf: str
    ) -> dict[str, Any]:
        """MASQUE + AWG: внешний MASQUE (usque), внутренний AmneziaWG."""
        from core.usque_manager import get_usque_manager
        from core.awg_manager import get_awg_manager

        usque_mgr = get_usque_manager()
        awg_mgr = get_awg_manager()

        if not outer_config:
            return {"ok": False, "error": "Нужен outer usque конфиг"}
        if not awg_conf:
            return {"ok": False, "error": "Нужно указать имя AWG-конфига для inner"}

        # Резолвим endpoint AWG ДО поднятия outer — если outer перехватит
        # DNS/маршруты, резолв может стать сложнее или дать другой ответ.
        try:
            host, _port = _read_awg_endpoint(awg_conf)
        except (ValueError, FileNotFoundError) as e:
            return {
                "ok": False,
                "error": "Не удалось прочитать endpoint AWG-конфига %s: %s"
                % (awg_conf, e),
            }
        v4, v6 = _resolve_host(host)
        if not v4 and not v6:
            return {
                "ok": False,
                "error": "Не удалось резолвить endpoint AWG-конфига (%s)" % host,
            }

        outer_iface = "opkgtun100"
        result = usque_mgr.start(outer_iface, outer_config, sni=outer_sni)
        if not result.get("ok"):
            return {"ok": False, "error": "Outer MASQUE: %s" % result.get("error")}

        pinned = []
        if v4:
            ok, previous = _pin_route_owned(v4, outer_iface, v6=False)
            if ok:
                pinned.append((v4, outer_iface, False, previous))
        if v6:
            ok, previous = _pin_route_owned(v6, outer_iface, v6=True)
            if ok:
                pinned.append((v6, outer_iface, True, previous))

        # AwgManager.up() принимает ИМЯ конфига; интерфейсом станет само
        # это имя (см. AwgManager._do_up: ifname = name).
        inner_was_up = awg_mgr.is_running(awg_conf)
        result = {"ok": True} if inner_was_up else awg_mgr.up(awg_conf)
        if not result.get("ok"):
            for dst, via, v6f, previous in pinned:
                _restore_route(dst, via, v6f, previous)
            usque_mgr.stop(outer_iface)
            return {
                "ok": False,
                "error": "Inner AWG: %s" % result.get("message", "ошибка"),
            }

        inner_iface = awg_conf
        self._outer_iface = outer_iface
        self._inner_iface = inner_iface
        self._mode = "masque_awg"
        self._pinned_routes = pinned
        self._owned_awg_inner = not inner_was_up
        self._owned_awg_outer = False

        self._apply_optimizations(outer_iface, inner_iface, "warp", "awg")

        log.success(
            "warp-in-warp: MASQUE+AWG запущен (%s → %s)" % (inner_iface, outer_iface),
            source="warp_in_warp",
        )
        return {
            "ok": True,
            "mode": "masque_awg",
            "outer": outer_iface,
            "inner": inner_iface,
        }

    def _start_awg_masque(
        self, awg_conf: str, inner_sni: str, inner_config: str
    ) -> dict[str, Any]:
        """AWG + MASQUE: внешний AmneziaWG, внутренний MASQUE (usque)."""
        from core.usque_manager import get_usque_manager
        from core.awg_manager import get_awg_manager

        usque_mgr = get_usque_manager()
        awg_mgr = get_awg_manager()

        if not awg_conf:
            return {"ok": False, "error": "Нужно указать имя AWG-конфига для outer"}
        if not inner_config:
            return {"ok": False, "error": "Нужен inner usque конфиг"}

        outer_iface = awg_conf
        outer_was_up = awg_mgr.is_running(outer_iface)
        result = {"ok": True} if outer_was_up else awg_mgr.up(outer_iface)
        if not result.get("ok"):
            return {
                "ok": False,
                "error": "Outer AWG: %s" % result.get("message", "ошибка"),
            }

        # For AWG outer, the usque endpoint must be pinned to the AWG
        # interface. Without this, usque may handshake through the default
        # WAN route and the two layers are not actually nested.
        pinned = []
        try:
            host, _port = _read_awg_endpoint(awg_conf)
            v4, v6 = _resolve_host(host)
            if v4:
                ok, previous = _pin_route_owned(v4, outer_iface, v6=False)
                if ok:
                    pinned.append((v4, outer_iface, False, previous))
            if v6:
                ok, previous = _pin_route_owned(v6, outer_iface, v6=True)
                if ok:
                    pinned.append((v6, outer_iface, True, previous))
        except (ValueError, FileNotFoundError) as e:
            if not outer_was_up:
                awg_mgr.down(outer_iface)
            return {"ok": False, "error": "Inner endpoint AWG: %s" % e}

        inner_iface = "opkgtun101"
        result = usque_mgr.start(inner_iface, inner_config, sni=inner_sni)
        if not result.get("ok"):
            for dst, via, v6f, previous in pinned:
                _restore_route(dst, via, v6f, previous)
            if not outer_was_up:
                awg_mgr.down(outer_iface)
            return {"ok": False, "error": "Inner MASQUE: %s" % result.get("error")}

        self._outer_iface = outer_iface
        self._inner_iface = inner_iface
        self._mode = "awg_masque"

        self._pinned_routes = pinned
        self._owned_awg_outer = not outer_was_up
        self._owned_awg_inner = False

        self._apply_optimizations(outer_iface, inner_iface, "awg", "warp")

        log.success(
            "warp-in-warp: AWG+MASQUE запущен (%s → %s)" % (inner_iface, outer_iface),
            source="warp_in_warp",
        )
        return {
            "ok": True,
            "mode": "awg_masque",
            "outer": outer_iface,
            "inner": inner_iface,
        }

    def _apply_optimizations(self, outer_iface: str, inner_iface: str,
                             outer_kind: str, inner_kind: str) -> None:
        try:
            from core.tunnel_optimizer import optimize_nested_tunnel

            result = optimize_nested_tunnel(
                outer_iface, outer_kind, inner_iface, inner_kind, "balanced")
            if not result.get("ok"):
                log.warning("warp-in-warp: nested optimization failed: %s"
                            % result.get("errors", result), source="warp_in_warp")
        except Exception as e:
            log.warning("warp-in-warp: nested optimization: %s" % e,
                        source="warp_in_warp")

    # ─────────────────────────── stop ───────────────────────────

    def stop(self) -> dict[str, Any]:
        """Остановить WARP-in-WARP."""
        with self._lock:
            mode = self._mode
            outer_iface = self._outer_iface
            inner_iface = self._inner_iface
            pinned = list(self._pinned_routes)

            if not mode:
                return {"ok": True, "message": "уже остановлен"}

            # inner
            if mode == "masque_awg":
                try:
                    from core.awg_manager import get_awg_manager

                    if self._owned_awg_inner:
                        get_awg_manager().down(inner_iface)
                except Exception as e:
                    log.warning(
                        "warp-in-warp stop inner(awg): %s" % e, source="warp_in_warp"
                    )
            else:
                try:
                    from core.usque_manager import get_usque_manager

                    get_usque_manager().stop(inner_iface)
                except Exception as e:
                    log.warning(
                        "warp-in-warp stop inner(usque): %s" % e, source="warp_in_warp"
                    )

            # маршруты
            for dst, via, v6, previous in pinned:
                _restore_route(dst, via, v6, previous)

            # outer
            if mode == "awg_masque":
                try:
                    from core.awg_manager import get_awg_manager

                    if self._owned_awg_outer:
                        get_awg_manager().down(outer_iface)
                except Exception as e:
                    log.warning(
                        "warp-in-warp stop outer(awg): %s" % e, source="warp_in_warp"
                    )
            else:
                try:
                    from core.usque_manager import get_usque_manager

                    get_usque_manager().stop(outer_iface)
                except Exception as e:
                    log.warning(
                        "warp-in-warp stop outer(usque): %s" % e, source="warp_in_warp"
                    )

            self._outer_iface = ""
            self._inner_iface = ""
            self._mode = ""
            self._pinned_routes = []
            self._owned_awg_outer = False
            self._owned_awg_inner = False

        _clear_last_start()

        # MR-05: Восстанавливаем системные defaults, если нет других активных туннелей
        try:
            from core.tunnel_optimizer import restore_system_defaults

            restore_system_defaults(only_if_idle=True)
        except Exception:
            pass

        log.info("warp-in-warp: остановлен", source="warp_in_warp")
        return {"ok": True}


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_warp_in_warp_manager() -> WarpInWarpManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = WarpInWarpManager()
    return _instance


# ──────────────────────────────────────────────────────────────────────
# Что ещё нужно поправить СНАРУЖИ этого файла, чтобы всё заработало
# целиком (не относится к самому warp_in_warp.py, но без этого
# masque_awg/awg_masque по-прежнему не будут доступны из GUI):
#
# 1. web/js/pages/warp_in_warp.js — сейчас выпадающие списки outer/inner
#    заполняются ИСКЛЮЧИТЕЛЬНО usque-конфигами (`GET /api/usque/configs`),
#    с комментарием в коде "AWG добавим позже". Для masque_awg/awg_masque
#    нужен отдельный `<select>`, заполняемый из `GET /api/awg/configs`
#    (или как называется существующий эндпоинт списка AWG-конфигов), и
#    именно ЕГО значение (имя конфига) нужно отправлять как `awg_conf` —
#    сейчас туда подставляется значение usque-селектора
#    (`awg_conf: mode === "awg_masque" ? outerConfig : ""`), что
#    гарантированно не совпадает с AWG-конфигом ни по формату, ни по
#    содержимому.
#
# 2. api/warp_in_warp.py — тело `wiw_up()` сейчас без try/except; учитывая,
#    что `start()` в этой версии сам всё чистит при частичном сбое,
#    обёртка на API-уровне не обязательна, но не помешает как последний
#    рубеж (на случай неожиданного исключения в самих usque_manager/
#    awg_manager, вне контроля этого файла):
#
#      def wiw_up():
#          try:
#              ...
#              return mgr.start(...)
#          except Exception as e:
#              return {"ok": False, "error": str(e)}
#
# 3. Для режима masque_masque рекомендуется добавить в GUI необязательное
#    поле "Известный endpoint inner-сессии" (host или IP), которое пойдёт
#    в новый параметр `inner_endpoint_host` — без него маршрутизация
#    между двумя MASQUE-сессиями не настраивается автоматически (см.
#    комментарий в начале файла и в _start_masque_masque). Если в
#    session-файле usque такой адрес не хранится в читаемом виде — этот
#    пункт стоит обсудить отдельно с тем, кто знает формат usque-сессий,
#    прежде чем полагаться на автоматическое закрепление маршрута.
# ──────────────────────────────────────────────────────────────────────
