# core/routing/dscp_rule.py
"""
Применение/снятие DSCP-based routing-правил (QoS). Заимствовано из XKeen.

Схема (fwmark-based, как domain-rule):
    1. mangle PREROUTING: -m dscp --dscp <N> -j MARK --set-mark <mark>
       (опц. OUTPUT — для трафика самого роутера, proxy_self=True).
    2. ip rule add fwmark <mark> lookup <table_for(iface)>.
    3. default-route в этой таблице → target_iface (ставит manager/
       awg_manager). + masquerade на исходящий iface.

fwmark = table_id_for(iface) — у каждого интерфейса уже свой
стабильный номер таблицы (100..999), используем его же как метку,
чтобы DSCP-правила на разные туннели не пересекались.

Свои именованные цепочки (как в ipset_backend) — чужие правила не
трогаем. Идемпотентно: перед add делаем del.
"""

import subprocess
import threading

from core.log_buffer import log
from core.routing.rules import DscpRoutingRule


PREROUTING_CHAIN = "DSCP_ROUTING_PRE"
OUTPUT_CHAIN     = "DSCP_ROUTING_OUT"

# Приоритет ip rule fwmark для DSCP. Ниже device(10200)/domain(10100)/
# cidr(10000) по «силе»? Берём 10150 — между domain и device: явная
# QoS-метка важнее общего CIDR-overlap, но устройство всё равно главнее.
DSCP_PRIORITY = 10150

_lock = threading.Lock()


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


def _table_id_for(ifname: str) -> int:
    h = 0
    for ch in ifname:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 100 + (h % 900)


def _iface_exists(ifname: str) -> bool:
    rc, _o, _e = _run(["ip", "link", "show", "dev", ifname])
    return rc == 0


def _backend() -> str:
    """iptables приоритетнее (Keenetic/Entware), иначе nft (OpenWrt 22+).

    Но если `iptables` — это nft-compat shim (вывод `-V` содержит
    'nf_tables', как на OpenWrt 22+), предпочитаем НАТИВНЫЙ nft: иначе
    DSCP-правила легли бы в iptables-nft chain'ы, несогласованные с
    nftset/masquerade-таблицами проекта, и маршрутизация по DSCP молча
    не срабатывала бы.
    """
    rc, out, _e = _run(["iptables", "-V"], timeout=3)
    if rc == 0 and "nf_tables" not in (out or "").lower():
        return "iptables"
    rc2, _o, _e = _run(["nft", "--version"], timeout=3)
    if rc2 == 0:
        return "nftables"
    return "iptables" if rc == 0 else "none"


def build_nft_dscp_fragment(dscp: int, mark: int) -> str:
    """nft rule-фрагмент маркировки по DSCP (чистая функция)."""
    return "ip dscp 0x%02x meta mark set %d" % (dscp, mark)


def _ensure_chain(chain: str):
    _run(["iptables", "-t", "mangle", "-N", chain])


def _ensure_jump(parent: str, chain: str):
    rc, out, _e = _run(["iptables", "-t", "mangle", "-S", parent])
    if rc == 0 and ("-A %s -j %s" % (parent, chain)) in out:
        return
    _run(["iptables", "-t", "mangle", "-A", parent, "-j", chain])


# ─────────────────────── pure builder ────────────────────────────────

def build_mark_rules(chain: str, dscp: int, mark: int) -> list:
    """argv для маркировки пакетов с заданным DSCP (чистая функция)."""
    return [[
        "iptables", "-t", "mangle", "-A", chain,
        "-m", "dscp", "--dscp", str(dscp),
        "-j", "MARK", "--set-mark", str(mark),
    ]]


# ─────────────────────── apply / remove ──────────────────────────────

def apply_dscp_rule(rule: DscpRoutingRule) -> dict:
    if not isinstance(rule, DscpRoutingRule):
        return {"ok": False, "error": "Не DscpRoutingRule"}
    if _backend() == "nftables":
        return _apply_dscp_nft(rule)

    ifname = rule.target_iface
    table = _table_id_for(ifname)
    mark = table

    with _lock:
        if not _iface_exists(ifname):
            return {"ok": False, "deferred": True,
                    "message": "Интерфейс %s ещё не поднят — правило"
                               " будет применено при старте" % ifname}

        # default-route в таблицу iface (v4; DSCP-маршрутизация чаще
        # всего про v4-трафик, v6 — отдельным правилом при надобности).
        rc, out, _e = _run(["ip", "-4", "route", "show", "table",
                            str(table), "default"])
        has_default = rc == 0 and ("dev %s" % ifname) in (out or "")
        if not has_default:
            rc, _o, err = _run(["ip", "-4", "route", "add", "default",
                                "dev", ifname, "table", str(table)])
            if rc != 0 and "File exists" not in (err or ""):
                return {"ok": False,
                        "error": "default-route в table %d: %s"
                                 % (table, err.strip())}

        _ensure_chain(PREROUTING_CHAIN)
        _ensure_jump("PREROUTING", PREROUTING_CHAIN)
        chains = [PREROUTING_CHAIN]
        if rule.proxy_self:
            _ensure_chain(OUTPUT_CHAIN)
            _ensure_jump("OUTPUT", OUTPUT_CHAIN)
            chains.append(OUTPUT_CHAIN)

        errors = []
        for chain in chains:
            for argv in build_mark_rules(chain, rule.dscp, mark):
                # идемпотентно: чистим дубликат (та же команда с -D).
                del_argv = list(argv)
                del_argv[3] = "-D"
                _run(del_argv)
                rc, _o, err = _run(argv)
                if rc != 0:
                    errors.append("%s: %s" % (chain, err.strip()))

        # ip rule fwmark → table
        _run(["ip", "-4", "rule", "del", "fwmark", str(mark),
              "lookup", str(table)])
        rc, _o, err = _run(["ip", "-4", "rule", "add", "fwmark", str(mark),
                            "lookup", str(table),
                            "priority", str(DSCP_PRIORITY)])
        if rc != 0:
            errors.append("ip rule fwmark: %s" % err.strip())

        # masquerade на исходящий iface (как у device/cidr).
        try:
            from core.routing import masquerade
            mq = masquerade.ensure_for_iface(ifname, families=("v4",))
            if not mq.get("ok"):
                log.warning("routing(dscp): masquerade %s: %s"
                            % (ifname, mq.get("error")), source="routing")
        except Exception as e:
            log.warning("routing(dscp): masquerade %s: %s" % (ifname, e),
                        source="routing")

        if errors:
            log.warning("routing: DSCP-правило %s с ошибками: %s"
                        % (rule.id, "; ".join(errors)), source="routing")
            return {"ok": False, "errors": errors}
        log.info("routing: DSCP-правило %s применено (dscp=%d → %s table %d)"
                 % (rule.id, rule.dscp, ifname, table), source="routing")
        return {"ok": True, "added": [{"dscp": rule.dscp, "mark": mark,
                                       "table": table, "iface": ifname}]}


def _apply_dscp_nft(rule: DscpRoutingRule) -> dict:
    """nft-вариант: правило в таблице awg_routing (общая с domain-routing)."""
    from core.routing import nftset_backend as nfb
    ifname = rule.target_iface
    table = _table_id_for(ifname)
    mark = table
    with _lock:
        if not _iface_exists(ifname):
            return {"ok": False, "deferred": True,
                    "message": "Интерфейс %s ещё не поднят" % ifname}
        # default route в таблицу iface
        rc, out, _e = _run(["ip", "-4", "route", "show", "table",
                            str(table), "default"])
        if not (rc == 0 and ("dev %s" % ifname) in (out or "")):
            rc, _o, err = _run(["ip", "-4", "route", "add", "default",
                                "dev", ifname, "table", str(table)])
            if rc != 0 and "File exists" not in (err or ""):
                return {"ok": False, "error": "default-route: %s" % err.strip()}

        nfb._ensure_table_and_chains()
        frag = build_nft_dscp_fragment(rule.dscp, mark)
        errors = []
        chains = ["prerouting"] + (["output"] if rule.proxy_self else [])
        for chain in chains:
            rc, out, _e = _run(["nft", "list", "chain", "inet",
                               nfb.TABLE_NAME, chain])
            if rc == 0 and frag in out:
                continue
            rc, _o, err = _run(["nft", "add", "rule", "inet", nfb.TABLE_NAME,
                               chain] + frag.split())
            if rc != 0:
                errors.append("%s: %s" % (chain, err.strip()))
        nfb.add_ip_rule_fwmark(mark, table, family="v4", priority=DSCP_PRIORITY)
        try:
            from core.routing import masquerade
            masquerade.ensure_for_iface(ifname, families=("v4",))
        except Exception:
            pass
        if errors:
            return {"ok": False, "errors": errors}
        log.info("routing(dscp/nft): правило %s (dscp=%d → %s)"
                 % (rule.id, rule.dscp, ifname), source="routing")
        return {"ok": True, "added": [{"dscp": rule.dscp, "mark": mark,
                                       "iface": ifname, "backend": "nftables"}]}


def _remove_dscp_nft(rule: DscpRoutingRule) -> dict:
    from core.routing import nftset_backend as nfb
    ifname = rule.target_iface
    table = _table_id_for(ifname)
    mark = table
    frag = build_nft_dscp_fragment(rule.dscp, mark)
    with _lock:
        for chain in ("prerouting", "output"):
            rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                               nfb.TABLE_NAME, chain])
            if rc != 0:
                continue
            for line in out.splitlines():
                if frag in line and "handle" in line:
                    h = line.rsplit("handle", 1)[1].strip().split()[0]
                    if h.isdigit():
                        _run(["nft", "delete", "rule", "inet", nfb.TABLE_NAME,
                              chain, "handle", h])
        nfb.del_ip_rule_fwmark(mark, table, family="v4")
        try:
            from core.routing import masquerade
            masquerade.remove_if_unused(ifname, excluding_id=rule.id)
        except Exception:
            pass
        log.info("routing(dscp/nft): правило %s снято" % rule.id,
                 source="routing")
        return {"ok": True}


def remove_dscp_rule(rule: DscpRoutingRule) -> dict:
    if not isinstance(rule, DscpRoutingRule):
        return {"ok": False, "error": "Не DscpRoutingRule"}
    if _backend() == "nftables":
        return _remove_dscp_nft(rule)
    ifname = rule.target_iface
    table = _table_id_for(ifname)
    mark = table
    with _lock:
        for chain in (PREROUTING_CHAIN, OUTPUT_CHAIN):
            for argv in build_mark_rules(chain, rule.dscp, mark):
                del_argv = list(argv)
                del_argv[3] = "-D"
                _run(del_argv)
        _run(["ip", "-4", "rule", "del", "fwmark", str(mark),
              "lookup", str(table)])
        try:
            from core.routing import masquerade
            masquerade.remove_if_unused(ifname, excluding_id=rule.id)
        except Exception:
            pass
        log.info("routing: DSCP-правило %s снято" % rule.id, source="routing")
        return {"ok": True}
