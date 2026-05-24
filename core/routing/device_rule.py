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
from core.routing import ipset_backend, nftset_backend
from core.routing.rules import DeviceRoutingRule


# Базовый приоритет для per-device правил. Выше CIDR (10000) и выше
# fwmark domain-rule (10100) — устройство имеет приоритет: если
# пользователь явно сказал «весь трафик с этого IP в туннель», это
# должно перебить overlap по CIDR.
DEVICE_PRIORITY = 10200


_lock = threading.Lock()


# ───────────────────────── helpers ──────────────────────────────────

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
    h = 0
    for ch in ifname:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 100 + (h % 900)


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
            return {"ok": False,
                    "error": "ip rule add from %s: %s" % (src, err.strip())}

        # MASQUERADE на AWG-iface: device-правило ловит обычно forwarded-
        # трафик от LAN-клиента (src=192.168.x.y), которому ip rule from
        # выкручивает руль на AWG-таблицу. Пакет уходит через AWG, но src
        # остаётся 192.168.x.y — AWG-сервер дропает его по AllowedIPs
        # клиента (там туннельный 10.x). Без MASQUERADE device-routing
        # «работает на бумаге»: пакеты уходят, ответов нет. Маскарадим
        # nft-бэкендом если доступен (он покрывает v4+v6 одной inet-
        # цепочкой), иначе через iptables. Для CIDR-rules аналогичная
        # проблема не стоит — там src чаще локальный, и пакет берёт
        # src=AWG_IP на первой маршрутной выборке.
        masq_status = "skipped"
        if nftset_backend.available():
            mq = nftset_backend.ensure_iface_masquerade(ifname)
            masq_status = "nft ok" if mq.get("ok") else (
                "nft error: %s" % mq.get("error"))
        elif ipset_backend.available():
            mq = ipset_backend.ensure_iface_masquerade(ifname, family=fam)
            masq_status = "iptables ok" if mq.get("ok") else (
                "iptables error: %s" % mq.get("error"))

        log.info("routing: device-правило %s применено (src=%s → %s"
                 " table %d, masquerade=%s)"
                 % (rule.id, src, ifname, table, masq_status),
                 source="routing")

        return {
            "ok":     True,
            "added":  [{"family": fam, "source": src, "table": table,
                        "iface": ifname, "masquerade": masq_status}],
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

        # MASQUERADE убираем только если на этот iface не осталось
        # никаких других routing-rules (ни domain, ни device).
        # Проверяем через storage: загружаем правила и смотрим,
        # ссылается ли кто-то ещё на target_iface.
        try:
            from core.routing import storage
            from core.routing.rules import DomainRoutingRule
            others = []
            for r in storage.load_rules():
                if not r.enabled or r.id == rule.id:
                    continue
                if r.target_iface != rule.target_iface:
                    continue
                if isinstance(r, (DeviceRoutingRule, DomainRoutingRule)):
                    others.append(r)
                    break
            if not others:
                if nftset_backend.available():
                    nftset_backend.remove_iface_masquerade(rule.target_iface)
                elif ipset_backend.available():
                    for f in ("v4", "v6"):
                        ipset_backend.remove_iface_masquerade(
                            rule.target_iface, family=f)
        except Exception as e:
            log.warning("routing: cleanup masquerade %s: %s"
                        % (rule.target_iface, e),
                        source="routing")

        log.info("routing: device-правило %s снято (src=%s)"
                 % (rule.id, src), source="routing")
        return {"ok": True, "removed": (rc == 0)}
