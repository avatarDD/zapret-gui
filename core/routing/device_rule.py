# core/routing/device_rule.py
"""
Логика применения и снятия per-device routing-правил.

Подход — source-IP based rule:
    ip rule add from <source_ip>/32 lookup <table_for(iface)> priority N

Универсально работает на любой платформе с iproute2 (Keenetic с
OpkgTun, OpenWrt, обычный Linux), не требует iptables/nftables и
не зависит от ipset/fwmark.

При наличии iptables MARK на платформе и явном выборе пользователем
маркировки (`use_fwmark=True` в самом правиле) — переключаемся на
mangle PREROUTING + fwmark. Реализация fwmark-варианта оставлена
на будущее (флаг учитывается, но в текущей версии используется
только source-IP rule, т.к. он покрывает все целевые платформы).

Идемпотентность: перед `ip rule add` всегда делаем `ip rule del`
с теми же параметрами (best-effort) — повторное применение не
плодит дубликатов.
"""

import ipaddress
import threading

from core.log_buffer import log
from core.routing.rules import DeviceRoutingRule


# Базовый приоритет для per-device правил. В policy-db ядро проверяет
# правила по ВОЗРАСТАНИЮ номера, поэтому 10200 стоит ПОСЛЕ CIDR (10000),
# доменных (10100) и DSCP (10150): точечное правило по назначению
# перебивает «весь трафик устройства». Устройство → туннель A, а
# CIDR Telegram → туннель B — трафик устройства к Telegram уйдёт в B.
# (Раньше комментарий здесь утверждал обратное; поведение всегда было
# таким, и менять его — значит молча перестроить маршруты пользователей.)
DEVICE_PRIORITY = 10200

# Правило-источник можно задать не только одним IP, но и ПОДСЕТЬЮ
# (`192.168.0.0/24` — «все устройства этой сети в туннель»). В лоб это
# кладёт роутер (issue #333): `ip rule from 192.168.0.0/24 lookup <table>`
# перехватывает и трафик МЕЖДУ клиентами LAN, и трафик самого роутера (его
# LAN-адрес тоже внутри подсети) — а в таблице туннеля из маршрутов только
# `default dev <tun>`. Ответы роутера клиентам, DNS, DHCP-обмен и веб-GUI
# уезжают в туннель, и роутер пропадает из сети.
#
# Лечится двумя исключениями с МЕНЬШИМ номером приоритета (а значит, более
# ранней проверкой), оба смотрят в main:
#   * трафик из подсети К локальным сетям роутера — остаётся локальным;
#   * трафик с собственных адресов роутера — вообще не наше дело.
LOCAL_EXEMPT_PRIORITY = DEVICE_PRIORITY - 10     # LAN ↔ LAN
SELF_EXEMPT_PRIORITY = DEVICE_PRIORITY - 20      # сам роутер

# Исключения по портам (приём Tachyon: Wi-Fi Calling и торренты мимо
# туннеля). «Весь трафик устройства в туннель» ломает две вещи:
#   * Wi-Fi Calling — IKE/IPsec к ePDG оператора (UDP 500/4500): оператор
#     ждёт абонента из своей страны, звонок через туннель не поднимается;
#   * торрент-клиент — входящие пиры приходят через проброс порта на WAN,
#     а ответ с порта клиента по `from <ip>` уезжает в туннель; uTP шлёт
#     с того же порта. Плюс торренты съедают канал туннеля.
# `ip rule from <ip> ipproto <p> dport|sport <n> lookup main` с приоритетом
# раньше основного правила устройства. Нужны ядро 4.17+ и iproute2 с
# этими селекторами: на старых прошивках правило не встаёт — основное
# правило от этого не страдает, а в ответе остаётся предупреждение.
PORT_EXEMPT_PRIORITY = DEVICE_PRIORITY - 5


_lock = threading.Lock()


# ───────────────────────── helpers ──────────────────────────────────

def port_exemption_args(src: str, item: str) -> list:
    """argv-хвост ``ip rule`` для одного исключения ``proto:dir:ports``
    (без add/del и приоритета): ``from <src> ipproto udp dport 500``."""
    proto, direction, ports = item.split(":")
    return ["from", src, "ipproto", proto, direction, ports,
            "lookup", "main"]


def _apply_port_exemptions(src: str, family: str, items: list) -> tuple:
    """Поставить исключения по портам. → (поставленные, ошибки)."""
    done, errors = [], []
    for item in items or []:
        tail = port_exemption_args(src, item)
        _run(["ip", family, "rule", "del"] + tail)
        rc, _o, err = _run(["ip", family, "rule", "add"] + tail
                           + ["priority", str(PORT_EXEMPT_PRIORITY)])
        if rc == 0:
            done.append(item)
        else:
            errors.append("%s: %s" % (item, err.strip() or rc))
    return done, errors


def _remove_port_exemptions(src: str, family: str, items: list) -> None:
    for item in items or []:
        for _ in range(4):          # дубли от прошлых сбоев
            rc, _o, _e = _run(["ip", family, "rule", "del"]
                              + port_exemption_args(src, item))
            if rc != 0:
                break


def _run(args, timeout=5):
    import subprocess
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


def _iface_exists(ifname: str) -> bool:
    rc, _o, _e = _run(["ip", "link", "show", "dev", ifname])
    return rc == 0


def _table_id_for(ifname: str) -> int:
    """Тот же алгоритм, что и в manager.table_id_for / awg_manager."""
    from core.routing.manager import table_id_for
    return table_id_for(ifname)


def _detect_family_and_normalize(ip: str):
    """
    Вернуть ('v4'|'v6', '<ip>/<prefix>') либо (None, None) если IP
    некорректный.
    """
    s = (ip or "").strip()
    if not s:
        return None, None
    # Может быть с маской или без.
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            fam = "v6" if net.version == 6 else "v4"
            return fam, str(net)
        addr = ipaddress.ip_address(s)
        fam = "v6" if addr.version == 6 else "v4"
        prefix = 128 if addr.version == 6 else 32
        return fam, "%s/%d" % (str(addr), prefix)
    except (ValueError, TypeError):
        return None, None


def _unusable_source(src: str) -> str:
    """
    Почему source нельзя ставить в `ip rule from` ('' — можно).

    `from 0.0.0.0` — не «мёртвое» правило, а перехват всего роутера: у
    локального сокета без bind первый route lookup идёт с saddr 0.0.0.0,
    и /32 на 0.0.0.0 с ним совпадает. Так устройство, чей IP не
    разрешился (NDM отдаёт 0.0.0.0 офлайн-хостам), уводило в туннель DNS
    роутера, его пробы WAN и `ip route get` — сайты по имени переставали
    открываться, WAN «падал», а WAN IP показывал адрес туннеля.
    """
    try:
        net = ipaddress.ip_network(src, strict=False)
    except (ValueError, TypeError):
        return "некорректный адрес"
    addr = net.network_address
    if net.prefixlen == 0 or addr.is_unspecified:
        return "неразрешённый адрес (%s)" % src
    if addr.is_loopback or addr.is_multicast or addr.is_link_local:
        return "служебный адрес (%s)" % src
    return ""


def _is_subnet(src: str) -> bool:
    """`src` — это подсеть (шире одного хоста), а не один адрес?"""
    try:
        net = ipaddress.ip_network(src, strict=False)
    except (ValueError, TypeError):
        return False
    return net.prefixlen < net.max_prefixlen


def _connected_networks(family: str) -> list:
    """Сети, до которых у роутера прямой маршрут (LAN, guest, br0 и т.п.).

    Берём из main то, что ядро само завело под интерфейсы
    (`proto kernel` / `scope link`) — именно эти сети обязаны остаться
    локальными, что бы ни было написано в правиле на подсеть.
    """
    rc, out, _e = _run(["ip", family, "route", "show", "table", "main"])
    if rc != 0:
        return []
    nets = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        dst = parts[0]
        if dst in ("default", "unreachable", "blackhole", "prohibit"):
            continue
        if "proto kernel" not in line and "scope link" not in line:
            continue
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except (ValueError, TypeError):
            continue
        if net.prefixlen >= net.max_prefixlen:
            continue                      # одиночный адрес — не сеть
        val = str(net)
        if val not in nets:
            nets.append(val)
    return nets


def _own_addresses(family: str) -> list:
    """Собственные глобальные адреса роутера (без масок)."""
    rc, out, _e = _run(["ip", family, "-o", "addr", "show", "scope", "global"])
    if rc != 0:
        return []
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok in ("inet", "inet6") and i + 1 < len(parts):
                try:
                    iface = ipaddress.ip_interface(parts[i + 1])
                except (ValueError, TypeError):
                    break
                val = str(iface.ip)
                if val not in addrs:
                    addrs.append(val)
                break
    return addrs


def _exempt_targets(src: str, family: str):
    """(локальные сети, свои адреса внутри `src`) для правила на подсеть."""
    try:
        net = ipaddress.ip_network(src, strict=False)
    except (ValueError, TypeError):
        return [], []
    own = []
    for addr in _own_addresses(family):
        try:
            ip = ipaddress.ip_address(addr)
        except (ValueError, TypeError):
            continue
        if ip.version == net.version and ip in net:
            own.append("%s/%d" % (str(ip), net.max_prefixlen))
    return _connected_networks(family), own


def _apply_subnet_exemptions(src: str, family: str) -> list:
    """Поставить исключения для правила на подсеть. Идемпотентно."""
    nets, own = _exempt_targets(src, family)
    added = []
    for net in nets:
        _run(["ip", family, "rule", "del", "from", src, "to", net,
              "lookup", "main"])
        rc, _o, err = _run(["ip", family, "rule", "add", "from", src,
                            "to", net, "lookup", "main",
                            "priority", str(LOCAL_EXEMPT_PRIORITY)])
        if rc == 0:
            added.append("from %s to %s" % (src, net))
        else:
            log.warning("routing: исключение LAN %s → %s не поставлено: %s"
                        % (src, net, (err or "").strip()), source="routing")
    for addr in own:
        _run(["ip", family, "rule", "del", "from", addr, "lookup", "main"])
        rc, _o, err = _run(["ip", family, "rule", "add", "from", addr,
                            "lookup", "main",
                            "priority", str(SELF_EXEMPT_PRIORITY)])
        if rc == 0:
            added.append("from %s (роутер)" % addr)
        else:
            log.warning("routing: исключение для своего адреса %s не "
                        "поставлено: %s" % (addr, (err or "").strip()),
                        source="routing")
    return added


def _other_subnet_sources(excluding_id: str) -> list:
    """Источники-подсети остальных ВКЛЮЧЁННЫХ device-правил."""
    try:
        from core.routing import storage
        out = []
        for r in storage.load_rules():
            if not isinstance(r, DeviceRoutingRule) or not r.enabled:
                continue
            if r.id == excluding_id:
                continue
            _fam, src = _detect_family_and_normalize(r.source_ip)
            if src and _is_subnet(src):
                out.append(src)
        return out
    except Exception as e:                            # noqa: BLE001
        log.warning("routing: не прочитать соседние device-правила: %s" % e,
                    source="routing")
        return []


def _remove_subnet_exemptions(src: str, family: str, rule_id: str) -> None:
    """Снять исключения правила на подсеть.

    Правила вида `from <src> to <net>` привязаны к этому src — снимаем
    всегда. Исключение для собственного адреса роутера общее, поэтому
    убираем его, только если такой же адрес не накрыт подсетью другого
    живого правила.
    """
    nets, own = _exempt_targets(src, family)
    for net in nets:
        _run(["ip", family, "rule", "del", "from", src, "to", net,
              "lookup", "main"])
    if not own:
        return
    others = _other_subnet_sources(rule_id)
    for addr in own:
        still_needed = False
        for other in others:
            try:
                if (ipaddress.ip_address(addr.split("/")[0])
                        in ipaddress.ip_network(other, strict=False)):
                    still_needed = True
                    break
            except (ValueError, TypeError):
                continue
        if not still_needed:
            _run(["ip", family, "rule", "del", "from", addr, "lookup", "main"])


def _ensure_table_default(ifname: str, table: int, family: str) -> bool:
    rc, out, _e = _run(["ip", family, "route", "show", "table", str(table),
                        "default"])
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                i = parts.index("dev")
                if i + 1 < len(parts) and parts[i + 1] == ifname:
                    return True
    rc, _o, err = _run(["ip", family, "route", "add", "default",
                        "dev", ifname, "table", str(table)])
    if rc == 0 or "File exists" in (err or ""):
        return True
    return False


# ───────────────────────── public API ───────────────────────────────

def apply_device_rule(rule: DeviceRoutingRule) -> dict:
    """Применить одно device-правило."""
    if not isinstance(rule, DeviceRoutingRule):
        return {"ok": False, "error": "Не DeviceRoutingRule"}

    fam, src = _detect_family_and_normalize(rule.source_ip)
    if fam is None:
        return {"ok": False,
                "error": "Некорректный source_ip: %s" % rule.source_ip}

    bad = _unusable_source(src)
    if bad:
        log.warning("routing: device-правило %s пропущено: %s — устройство"
                    " не в сети или его адрес не определился"
                    % (rule.id, bad), source="routing")
        return {"ok": False, "skipped": True,
                "error": "Адрес устройства не определён: %s" % bad}

    ifname = rule.target_iface
    table = _table_id_for(ifname)

    with _lock:
        if not _iface_exists(ifname):
            return {"ok": False, "deferred": True,
                    "message": "Интерфейс %s ещё не поднят — правило"
                               " будет применено при старте" % ifname}

        family = "-6" if fam == "v6" else "-4"

        if not _ensure_table_default(ifname, table, family):
            return {"ok": False,
                    "error": "default-route %s в table %d не создан"
                             % (family, table)}

        # Правило на ПОДСЕТЬ обязано пропускать локальный трафик и трафик
        # самого роутера мимо туннеля — иначе роутер уезжает в туннель
        # вместе с клиентами и пропадает из сети (issue #333). Ставим
        # исключения ДО основного правила: приоритет у них меньше, но
        # порядок применения тоже важен — между add и add не должно быть
        # окна, в котором подсеть уже перехвачена, а исключений ещё нет.
        exemptions = []
        if _is_subnet(src):
            exemptions = _apply_subnet_exemptions(src, family)

        # Сначала чистим возможный дубликат, чтобы apply был идемпотентным
        _run(["ip", family, "rule", "del", "from", src,
              "lookup", str(table)])

        rc, _o, err = _run(["ip", family, "rule", "add", "from", src,
                            "lookup", str(table),
                            "priority", str(DEVICE_PRIORITY)])
        if rc != 0:
            log.warning("routing: device-правило %s: ip rule add from %s: %s"
                        % (rule.id, src, err.strip()),
                        source="routing")
            # Основное правило не встало — исключения без него бессмысленны.
            if exemptions:
                _remove_subnet_exemptions(src, family, rule.id)
            return {"ok": False,
                    "error": "ip rule add from %s: %s" % (src, err.strip())}

        ports_done, ports_err = _apply_port_exemptions(
            src, family, getattr(rule, "bypass_ports", []))
        if ports_err:
            log.warning("routing: device-правило %s: исключения по портам "
                        "не встали (нужно ядро 4.17+ и iproute2 с ipproto/"
                        "dport): %s" % (rule.id, "; ".join(ports_err)),
                        source="routing")

        # MASQUERADE + FORWARD-accept на AWG-iface (общий helper):
        # device-правило ловит forwarded-трафик LAN-клиента, которому
        # ip rule from перекидывает руль на AWG-таблицу. Без MASQUERADE
        # пакет уходит с чужим src и сервер его дропает; без FORWARD-accept
        # роутер с FORWARD-policy DROP режет форвард к нашему туннелю
        # (штатный firewall не знает AWG-iface).
        from core.routing import masquerade
        mq = masquerade.ensure_for_iface(ifname, families=(fam,))
        masq_status = "ok" if mq.get("ok") else (
            "error: %s" % mq.get("error"))

        # Kill-switch (по умолчанию выключен, см. core/routing/killswitch):
        # без него в момент, когда туннель лежит, таблица пуста, правило
        # ничего не решает и трафик устройства уходит через провайдера.
        from core.routing import killswitch
        ks = killswitch.ensure(table, families=(fam,))
        ks_status = ("" if ks.get("skipped")
                     else (", kill-switch=ok" if ks.get("ok")
                           else ", kill-switch=error: %s" % ks.get("error")))

        log.info("routing: device-правило %s применено (src=%s → %s"
                 " table %d, masquerade=%s%s%s)"
                 % (rule.id, src, ifname, table, masq_status, ks_status,
                    (", исключений для локальной сети: %d" % len(exemptions))
                    if exemptions else ""),
                 source="routing")

        return {
            "ok":     True,
            "added":  [{"family": fam, "source": src, "table": table,
                        "iface": ifname, "masquerade": masq_status}],
            "exemptions": exemptions,
            "bypass_ports": ports_done,
            "bypass_ports_errors": ports_err,
        }


def remove_device_rule(rule: DeviceRoutingRule) -> dict:
    """Снять одно device-правило (без удаления из storage)."""
    if not isinstance(rule, DeviceRoutingRule):
        return {"ok": False, "error": "Не DeviceRoutingRule"}

    fam, src = _detect_family_and_normalize(rule.source_ip)
    if fam is None:
        return {"ok": True, "skipped": True}

    family = "-6" if fam == "v6" else "-4"
    table = _table_id_for(rule.target_iface)

    with _lock:
        rc, _o, _e = _run(["ip", family, "rule", "del", "from", src,
                           "lookup", str(table)])

        _remove_port_exemptions(src, family,
                                getattr(rule, "bypass_ports", []))

        # Исключения ставились только у правил на подсеть — и снимаются
        # вместе с ними (issue #333).
        if _is_subnet(src):
            _remove_subnet_exemptions(src, family, rule.id)

        # MASQUERADE убираем только если на этот iface не осталось
        # никаких других включённых routing-rules (cidr/device/domain),
        # которым он нужен.
        #
        # Blackhole kill-switch'а здесь НЕ трогаем: он принадлежит таблице
        # интерфейса, а не правилу. Пока туннель перезапускается
        # (AwgManager.restart, watchdog) или лежит после падения демона,
        # правила вообще не снимаются, и blackhole держит их трафик —
        # restart возвращает его в таблицу после flush, sweeper его не
        # трогает. Снимается он в killswitch.ensure() — как только опция
        # выключена — и при явном `down` вместе с таблицей интерфейса.
        try:
            from core.routing import masquerade
            masquerade.remove_if_unused(rule.target_iface,
                                        excluding_id=rule.id)
        except Exception as e:
            log.warning("routing: cleanup masquerade %s: %s"
                        % (rule.target_iface, e),
                        source="routing")

        log.info("routing: device-правило %s снято (src=%s)"
                 % (rule.id, src), source="routing")
        return {"ok": True, "removed": (rc == 0)}
