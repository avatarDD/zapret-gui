# core/routing/guardian.py
"""
Сторож маршрутизации: правила возвращаются сами — после перезаписи
netfilter прошивкой и при появлении интерфейса.

## Перезапись netfilter (Keenetic NDMS, OpenWrt fw3)

NDMS пересобирает таблицы iptables при переподключении WAN, смене
политик, правке firewall в веб-интерфейсе Keenetic — и вместе со своими
правилами сносит наши: цепочки маркировки доменных маршрутов
(AWG_ROUTING_PRE/OUT), masquerade (AWG_ROUTING_NAT), FORWARD-accept,
DSCP-цепочки и REDIRECT перехвата DNS. Хук netfilter.d возвращал
только правила nfqws2 — маршрут по доменам «переставал работать» до
перезапуска GUI.

Как у MagiTrickle (хук netfilter.d → его API → ForceCommit): свой хук
(:data:`NDM_HOOK_PATH`, :data:`HOTPLUG_HOOK_PATH`) шлёт GUI сигнал
SIGUSR2, GUI через паузу (NDMS зовёт хуки пачкой — на каждую таблицу и
семейство) восстанавливает своё (:func:`restore_firewall`). Хук отдельный
от хука nfqws2: выключение автозапуска nfqws2 его не снимает.

PID получателя — свой файл (:data:`PID_FILE`), хук проверяет, что за
PID действительно наш процесс: SIGUSR2 по умолчанию завершает процесс,
и чужой процесс с переиспользованным PID пострадал бы.

## Появление интерфейса

Раньше переприменение по подъёму интерфейса было подключено только к
AwgManager.up: отложенные (deferred) маршруты через sing-box, mihomo и
WARP ждали ручного «Переприменить». Теперь сторож слушает netlink
(RTMGRP_LINK + адреса, как MagiTrickle) и для интерфейса, на который
ссылается хоть одно правило, зовёт applier.apply_all_on_interface_up —
когда интерфейс поднялся и когда на нём появился адрес (у TUN sing-box
адрес приходит позже link up, и v6-нога без него пропускалась).

Настройки (settings.json → routing.guardian):
    enabled — по умолчанию true.
"""

import os
import socket
import struct
import threading
import time

from core.log_buffer import log


PID_FILE = "/var/run/zapret-gui-routing.pid"
PID_FALLBACK = "/tmp/zapret-gui-routing.pid"

NDM_HOOK_PATH = "/opt/etc/ndm/netfilter.d/101-zapret-gui-routing.sh"
HOTPLUG_HOOK_PATH = "/etc/hotplug.d/firewall/91-zapret-gui-routing"

RESTORE_DELAY = 3.0       # сек: дождаться конца пачки вызовов хука
LINK_DELAY = 2.0          # сек: склеить up + адреса в одно применение

# netlink (linux/rtnetlink.h, linux/if.h)
NETLINK_ROUTE = 0
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100
RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR = 16, 17, 20
IFLA_IFNAME = 3
IFF_UP = 0x1

_lock = threading.Lock()
_restore_event = threading.Event()
_pending_links = {}           # ifname → когда применять (time.time())
_threads = []
_pid_path = ""


def _settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        sec = get_config_manager().get("routing", "guardian",
                                       default={}) or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:
        return {}


def is_enabled() -> bool:
    return bool(_settings().get("enabled", True))


# ─────────────────────── хук ─────────────────────────────────────────

def build_hook(pid_files=(PID_FILE, PID_FALLBACK), ndm: bool = True) -> str:
    """Хук netfilter.d / hotplug.d: SIGUSR2 живому GUI (чистая)."""
    guard = ('[ "$table" = "mangle" ] || [ "$table" = "nat" ] || '
             '[ "$table" = "filter" ] || exit 0\n' if ndm
             else '[ "$ACTION" = "add" ] || exit 0\n')
    return (
        "#!/bin/sh\n"
        "# zapret-gui: вернуть правила маршрутизации после перезаписи\n"
        "# netfilter (сигнал GUI, сам GUI восстановит своё). Сгенерировано\n"
        "# zapret-gui — не редактируйте.\n"
        + guard
        + "for pf in %s; do\n" % " ".join(pid_files)
        + '    [ -f "$pf" ] || continue\n'
        + '    pid="$(cat "$pf" 2>/dev/null)"\n'
        + '    [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] || continue\n'
        # SIGUSR2 по умолчанию убивает процесс — шлём только нашему.
        + '    tr "\\000" " " < "/proc/$pid/cmdline" 2>/dev/null | '
          'grep -q "app.py\\|zapret-gui" || continue\n'
        + '    kill -USR2 "$pid" 2>/dev/null\n'
        + "done\n"
        + "exit 0\n"
    )


def _write_exec(path: str, content: str) -> bool:
    try:
        try:
            with open(path, encoding="utf-8") as f:
                if f.read() == content:
                    return True
        except OSError:
            pass
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o755)
        return True
    except OSError as e:
        log.debug("guardian: хук %s не записан: %s" % (path, e),
                  source="routing")
        return False


def install_hooks() -> list:
    """Записать хук там, где есть механизм (Keenetic / OpenWrt)."""
    done = []
    if os.path.isdir(os.path.dirname(NDM_HOOK_PATH)):
        if _write_exec(NDM_HOOK_PATH, build_hook(ndm=True)):
            done.append(NDM_HOOK_PATH)
    if os.path.isdir("/etc/hotplug.d"):
        if _write_exec(HOTPLUG_HOOK_PATH, build_hook(ndm=False)):
            done.append(HOTPLUG_HOOK_PATH)
    return done


def remove_hooks() -> list:
    removed = []
    for path in (NDM_HOOK_PATH, HOTPLUG_HOOK_PATH):
        try:
            os.remove(path)
            removed.append(path)
        except OSError:
            pass
    return removed


def _write_pid() -> str:
    for path in (PID_FILE, PID_FALLBACK):
        try:
            with open(path, "w") as f:
                f.write("%d\n" % os.getpid())
            return path
        except OSError:
            continue
    return ""


def _remove_pid():
    if not _pid_path:
        return
    try:
        with open(_pid_path) as f:
            if f.read().strip() == str(os.getpid()):
                os.remove(_pid_path)
    except OSError:
        pass


# ─────────────────────── восстановление ──────────────────────────────

def _enabled_rules():
    from core.routing import storage
    return [r for r in storage.load_rules() if r.enabled]


def _existing_ipsets() -> set:
    from core.routing import ipset_backend
    rc, out, _e = ipset_backend._run(["ipset", "list", "-n"], timeout=10)
    return set(out.split()) if rc == 0 else set()


def mark_entries_for(rules, existing_sets: set) -> dict:
    """{'v4': [(set, mark, mask)], 'v6': [...]} — какие записи ДОЛЖНЫ
    стоять в iptables-цепочках маркировки (чистая при данных входах)."""
    from core.routing import domain_rule, ipset_backend, marks
    from core.routing.rules import DomainRoutingRule
    out = {"v4": [], "v6": []}
    for rule in rules:
        if not isinstance(rule, DomainRoutingRule):
            continue
        base = ipset_backend.set_name_for(rule.id)
        mark = domain_rule._mark_for(rule.id)
        for fam, name in (("v4", base), ("v6", base + "6")):
            if name in existing_sets:
                out[fam].append((name, mark, marks.MASK))
    return out


def restore_firewall() -> dict:
    """Вернуть наши правила netfilter (идемпотентно, дёшево).

    Только netfilter: `ip rule`, таблицы маршрутизации и сами наборы
    перезапись firewall не трогает. nft-таблицы (OpenWrt fw4) прошивка
    тоже не трогает — правим только iptables-сторону.
    """
    from core.routing import ipset_backend, masquerade
    from core.routing.rules import DscpRoutingRule
    done = {"marks": 0, "ifaces": [], "dscp": 0, "dns": False,
            "errors": []}
    try:
        rules = _enabled_rules()
    except Exception as e:
        return {"ok": False, "errors": [str(e)]}

    if ipset_backend.available():
        # Под замком доменных правил: apply/remove правила меняет и
        # storage, и цепочку — снимок «что должно стоять» иначе мог бы
        # устареть между чтением и записью и потерять (или воскресить)
        # запись соседнего правила.
        from core.routing import domain_rule
        with domain_rule._lock:
            try:
                rules = _enabled_rules()
            except Exception as e:
                return {"ok": False, "errors": [str(e)]}
            sets = _existing_ipsets()
            entries = mark_entries_for(rules, sets)
            for fam in ("v4", "v6"):
                if not entries[fam]:
                    continue
                res = ipset_backend.sync_mark_entries(entries[fam], fam)
                done["marks"] += len(entries[fam])
                done["errors"] += res.get("errors") or []

    from core.routing.manager import _is_ndms_native_iface
    ifaces = sorted({r.target_iface for r in rules
                     if getattr(r, "target_iface", "")})
    for ifname in ifaces:
        # Нативные интерфейсы Keenetic ведёт сам NDMS (без нашего NAT).
        if not _iface_exists(ifname) or _is_ndms_native_iface(ifname):
            continue
        try:
            mq = masquerade.ensure_for_iface(ifname)
            if mq.get("ok"):
                done["ifaces"].append(ifname)
        except Exception as e:
            done["errors"].append("masquerade %s: %s" % (ifname, e))

    for rule in rules:
        if isinstance(rule, DscpRoutingRule):
            try:
                from core.routing import dscp_rule
                dscp_rule.apply_dscp_rule(rule)
                done["dscp"] += 1
            except Exception as e:
                done["errors"].append("dscp %s: %s" % (rule.id, e))

    try:
        from core.routing import dns_intercept
        red = dns_intercept.get_dns_intercept().reassert()
        done["dns"] = bool(red.get("ok")) and not red.get("noop")
    except Exception as e:
        done["errors"].append("dns_intercept: %s" % e)

    done["ok"] = not done["errors"]
    return done


def request_restore():
    """Попросить восстановление (из обработчика сигнала — без работы)."""
    _restore_event.set()


def _iface_exists(ifname: str) -> bool:
    return os.path.exists("/sys/class/net/%s" % ifname)


def _restore_loop():
    while True:
        _restore_event.wait()
        time.sleep(RESTORE_DELAY)
        _restore_event.clear()
        try:
            res = restore_firewall()
            log.info("routing: правила возвращены после перезаписи "
                     "netfilter (маркировка: %d, интерфейсов: %d, DSCP: %d"
                     "%s)%s"
                     % (res.get("marks", 0), len(res.get("ifaces") or []),
                        res.get("dscp", 0),
                        ", перехват DNS" if res.get("dns") else "",
                        (" — ошибки: %s" % "; ".join(res["errors"][:3]))
                        if res.get("errors") else ""),
                     source="routing")
        except Exception as e:
            log.warning("routing: восстановление после netfilter: %s" % e,
                        source="routing")


# ─────────────────────── netlink ─────────────────────────────────────

def parse_netlink(data: bytes) -> list:
    """Сообщения netlink → [(event, ifindex, ifname, up)]. Чистая.

    event: 'link' (RTM_NEWLINK), 'gone' (RTM_DELLINK), 'addr'
    (RTM_NEWADDR). ifname есть только у link-событий (IFLA_IFNAME);
    для 'addr' имя берём по индексу.
    """
    out = []
    off = 0
    while off + 16 <= len(data):
        length, mtype, _flags, _seq, _pid = struct.unpack_from(
            "=IHHII", data, off)
        if length < 16 or off + length > len(data):
            break
        body = data[off + 16:off + length]
        if mtype in (RTM_NEWLINK, RTM_DELLINK) and len(body) >= 16:
            _fam, _pad, _type, index, flags, _chg = struct.unpack_from(
                "=BBHiII", body, 0)
            name = ""
            aoff = 16
            while aoff + 4 <= len(body):
                alen, atype = struct.unpack_from("=HH", body, aoff)
                if alen < 4:
                    break
                if atype == IFLA_IFNAME:
                    name = body[aoff + 4:aoff + alen].split(b"\0")[0] \
                        .decode("ascii", "replace")
                aoff += (alen + 3) & ~3
            out.append(("gone" if mtype == RTM_DELLINK else "link",
                        index, name, bool(flags & IFF_UP)))
        elif mtype == RTM_NEWADDR and len(body) >= 8:
            _fam, _plen, _fl, _scope, index = struct.unpack_from(
                "=BBBBi", body, 0)
            out.append(("addr", index, "", True))
        off += (length + 3) & ~3
    return out


def _managed_ifaces() -> set:
    try:
        return {r.target_iface for r in _enabled_rules()
                if getattr(r, "target_iface", "")}
    except Exception:
        return set()


def _netlink_loop(sock):
    import errno
    known_up = set()
    while True:
        try:
            data = sock.recv(65536)
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                # Пачка событий переполнила буфер сокета — часть потеряна.
                # Не умираем: перепроверим все наши интерфейсы разом.
                now = time.time()
                with _lock:
                    for name in _managed_ifaces():
                        if _iface_exists(name):
                            _pending_links[name] = now + LINK_DELAY
                continue
            log.warning("routing: netlink: %s — слежение за интерфейсами "
                        "остановлено" % e, source="routing")
            return
        events = parse_netlink(data)
        if not events:
            continue
        managed = _managed_ifaces()
        now = time.time()
        for event, index, name, up in events:
            if not name:
                try:
                    name = socket.if_indextoname(index)
                except OSError:
                    continue
            if name not in managed:
                continue
            if event == "gone" or (event == "link" and not up):
                known_up.discard(name)
                continue
            if event == "link":
                if name in known_up:
                    continue        # повторный NEWLINK без смены up
                known_up.add(name)
            with _lock:
                _pending_links[name] = now + LINK_DELAY


def _link_apply_loop():
    from core.routing import applier
    while True:
        time.sleep(0.5)
        now = time.time()
        due = []
        with _lock:
            for name, when in list(_pending_links.items()):
                if when <= now:
                    due.append(name)
                    del _pending_links[name]
        for name in due:
            if not _iface_exists(name) or applier.applied_recently(name):
                continue
            res = applier.apply_all_on_interface_up(name)
            log.info("routing: интерфейс %s поднялся — правила применены "
                     "(%s)" % (name, "ok" if res.get("ok", True)
                               else res.get("error", "с ошибками")),
                     source="routing")


def _open_netlink():
    groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    sock.bind((0, groups))
    return sock


# ─────────────────────── запуск ──────────────────────────────────────

def _on_sigusr2(_signum, _frame):
    request_restore()


def start() -> dict:
    """Запустить сторожа (из create_app, в главном потоке). Идемпотентно."""
    global _pid_path
    if not is_enabled():
        return {"ok": True, "disabled": True}
    with _lock:
        if _threads:
            return {"ok": True, "already": True}
        result = {"ok": True, "signal": False, "netlink": False,
                  "hooks": []}
        try:
            import signal
            signal.signal(signal.SIGUSR2, _on_sigusr2)
            _pid_path = _write_pid()
            result["signal"] = bool(_pid_path)
        except (ValueError, OSError, AttributeError) as e:
            # не главный поток / нет SIGUSR2 — без хука, но netlink живёт
            log.debug("guardian: SIGUSR2 не установлен: %s" % e,
                      source="routing")
        if result["signal"]:
            import atexit
            atexit.register(_remove_pid)
            result["hooks"] = install_hooks()
            t = threading.Thread(target=_restore_loop, daemon=True,
                                 name="routing-restore")
            t.start()
            _threads.append(t)
        try:
            sock = _open_netlink()
            for target, args, name in ((_netlink_loop, (sock,), "routing-nl"),
                                       (_link_apply_loop, (), "routing-up")):
                t = threading.Thread(target=target, args=args, daemon=True,
                                     name=name)
                t.start()
                _threads.append(t)
            result["netlink"] = True
        except (OSError, AttributeError) as e:
            log.info("routing: netlink недоступен (%s) — интерфейсы "
                     "отслеживаются только при up AWG" % e, source="routing")
        return result
