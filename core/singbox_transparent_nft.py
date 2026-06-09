# core/singbox_transparent_nft.py
"""
nftables-вариант прозрачного проксирования (для OpenWrt 22.03+ и
современного Linux, где iptables заменён на nft).

Парная реализация к core/singbox_transparent.py (iptables). Высокоуровневый
apply()/remove() в основном модуле выбирает бэкенд по доступности:
есть iptables → iptables-путь (Keenetic/Entware), иначе nft-путь.

Наша таблица — `inet sbtproxy` (никогда не трогаем чужие). Идемпотентность
простая и надёжная: при apply сносим свою таблицу целиком и создаём
заново; remove — просто удаляет таблицу.

Режимы как у iptables-варианта:
  • redirect — nat prerouting/output, REDIRECT TCP на порт движка;
  • tproxy   — mangle prerouting (TCP+UDP) tproxy + mark, ip rule/route;
  • hybrid   — redirect для TCP + tproxy для UDP.

Builder'ы (`build_*`) — чистые, возвращают список nft-argv и тестируются
без рута.
"""

import subprocess

from core.log_buffer import log
from core.singbox_transparent import (
    DEFAULT_TPROXY_MARK, DEFAULT_TPROXY_TABLE,
    DEFAULT_BYPASS_V4, DEFAULT_BYPASS_V6,
)

TABLE = "sbtproxy"


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


def available() -> bool:
    rc, _o, _e = _run(["nft", "--version"], timeout=3)
    return rc == 0


# ─────────────────────── pure builders ───────────────────────────────
#
# Каждый возвращает список «rule-фрагментов» (то, что идёт после
# `nft add rule inet sbtproxy <chain>`), в виде строк. apply() сам
# подставляет префикс. Так тесты компактны и независимы от имени таблицы.


def _daddr(family: str) -> str:
    return "ip6 daddr" if family == "v6" else "ip daddr"


def _bypass_set(family: str, extra: list) -> str:
    nets = list(DEFAULT_BYPASS_V4 if family == "v4" else DEFAULT_BYPASS_V6)
    nets += [n for n in (extra or [])]
    return "{ " + ", ".join(nets) + " }"


def build_redirect_fragments(*, family: str, tcp_port: int,
                             lan_ifaces: list = None,
                             server_ips: list = None,
                             bypass: list = None,
                             proxy_self: bool = False) -> dict:
    """
    Вернуть {"prerouting": [...], "output": [...]} фрагментов nft-правил
    для redirect-режима.
    """
    daddr = _daddr(family)
    pre = ["%s %s return" % (daddr, _bypass_set(family, bypass))]
    for ip in (server_ips or []):
        pre.append("%s %s return" % (daddr, ip))
    if lan_ifaces:
        for ifn in lan_ifaces:
            pre.append('iifname "%s" meta l4proto tcp redirect to :%d'
                       % (ifn, tcp_port))
    else:
        pre.append("meta l4proto tcp redirect to :%d" % tcp_port)

    out = []
    if proxy_self:
        out.append("%s %s return" % (daddr, _bypass_set(family, bypass)))
        for ip in (server_ips or []):
            out.append("%s %s return" % (daddr, ip))
        out.append("meta mark %d return" % DEFAULT_TPROXY_MARK)
        out.append("meta l4proto tcp redirect to :%d" % tcp_port)
    return {"prerouting": pre, "output": out}


def build_tproxy_fragments(*, family: str, port: int,
                           mark: int = DEFAULT_TPROXY_MARK,
                           protocols: tuple = ("tcp", "udp"),
                           lan_ifaces: list = None,
                           server_ips: list = None,
                           bypass: list = None,
                           proxy_self: bool = False) -> dict:
    """
    Вернуть {"prerouting": [...], "output": [...]} фрагментов для tproxy.
    """
    daddr = _daddr(family)
    tp_ip = "ip6" if family == "v6" else "ip"
    protoset = "{ %s }" % ", ".join(protocols)

    pre = ["%s %s return" % (daddr, _bypass_set(family, bypass))]
    for ip in (server_ips or []):
        pre.append("%s %s return" % (daddr, ip))
    if lan_ifaces:
        for ifn in lan_ifaces:
            pre.append('iifname "%s" meta l4proto %s tproxy %s to :%d '
                       'meta mark set %d'
                       % (ifn, protoset, tp_ip, port, mark))
    else:
        pre.append("meta l4proto %s tproxy %s to :%d meta mark set %d"
                   % (protoset, tp_ip, port, mark))

    out = []
    if proxy_self:
        out.append("%s %s return" % (daddr, _bypass_set(family, bypass)))
        for ip in (server_ips or []):
            out.append("%s %s return" % (daddr, ip))
        out.append("meta mark %d return" % mark)
        out.append("meta l4proto %s meta mark set %d" % (protoset, mark))
    return {"prerouting": pre, "output": out}


def build_dns_hijack_fragments(*, family: str, dns_port: int,
                               lan_ifaces: list = None,
                               via: str = "tproxy",
                               mark: int = DEFAULT_TPROXY_MARK) -> list:
    """
    Фрагменты перехвата DNS форвард-трафика (udp/tcp dport 53) на DNS-порт
    движка — защита от DNS-leak мимо туннеля. Парно к build_dns_hijack_rules
    из iptables-ветки.

      via='redirect' → `redirect to :dns_port` (ставится в nat-цепочку predr);
      via='tproxy'   → `tproxy … meta mark set` (в mangle-цепочку pretp).

    `th dport 53` (transport-header dport) ловит и tcp, и udp. Возвращает
    список фрагментов-строк (по одному на интерфейс).
    """
    tp_ip = "ip6" if family == "v6" else "ip"
    ifaces = lan_ifaces or [None]
    frags = []
    for ifn in ifaces:
        prefix = ('iifname "%s" ' % ifn) if ifn else ""
        if via == "redirect":
            frags.append("%smeta l4proto { tcp, udp } th dport 53 "
                         "redirect to :%d" % (prefix, dns_port))
        else:
            frags.append("%smeta l4proto { tcp, udp } th dport 53 "
                         "tproxy %s to :%d meta mark set %d"
                         % (prefix, tp_ip, dns_port, mark))
    return frags


def build_ipv6_block_fragment() -> str:
    """
    Anti-leak: дроп всего форвард-IPv6, когда проксируем только v4 (иначе
    IPv6-клиенты ходят мимо туннеля). В inet-таблице семейство различаем
    через `meta nfproto ipv6` — аналог `ip6tables -A FORWARD -j DROP`.
    """
    return "meta nfproto ipv6 drop"


# ─────────────────────── ip rule/route (shared с iptables) ───────────

def _add_tproxy_route(family: str, mark: int, table: int) -> list:
    fam = "-6" if family == "v6" else "-4"
    errors = []
    _run(["ip", fam, "rule", "del", "fwmark", str(mark), "lookup", str(table)])
    rc, _o, err = _run(["ip", fam, "rule", "add", "fwmark", str(mark),
                        "lookup", str(table)])
    if rc != 0 and "exists" not in (err or "").lower():
        errors.append("ip rule fwmark: %s" % err.strip())
    rc, _o, err = _run(["ip", fam, "route", "replace", "local", "default",
                        "dev", "lo", "table", str(table)])
    if rc != 0:
        errors.append("ip route local default: %s" % err.strip())
    return errors


def _del_tproxy_route(family: str, mark: int, table: int):
    fam = "-6" if family == "v6" else "-4"
    _run(["ip", fam, "rule", "del", "fwmark", str(mark), "lookup", str(table)])
    _run(["ip", fam, "route", "del", "local", "default", "dev", "lo",
          "table", str(table)])


# ─────────────────────── apply / remove ──────────────────────────────

def _nft_add_rule(chain: str, fragment: str) -> list:
    return ["nft", "add", "rule", "inet", TABLE, chain] + fragment.split()


def apply(*, mode: str,
          tcp_port: int = 0, udp_port: int = 0,
          mark: int = DEFAULT_TPROXY_MARK, table: int = DEFAULT_TPROXY_TABLE,
          families: tuple = ("v4",),
          lan_ifaces: list = None, server_ips: list = None,
          bypass: list = None, proxy_self: bool = False,
          dns_hijack_port: int = 0, ipv6_policy: str = "allow") -> dict:
    if not available():
        return {"ok": False, "error": "nft недоступен"}
    if mode not in ("redirect", "tproxy", "hybrid"):
        return {"ok": False, "error": "Неизвестный режим: %s" % mode}

    errors = []
    # Сносим свою таблицу и создаём заново — простая идемпотентность.
    _run(["nft", "delete", "table", "inet", TABLE])
    rc, _o, err = _run(["nft", "add", "table", "inet", TABLE])
    if rc != 0:
        return {"ok": False, "error": "nft add table: %s" % err.strip()}

    need_nat = mode in ("redirect", "hybrid")
    need_mangle = mode in ("tproxy", "hybrid")

    def _chain(name, spec):
        rc, _o, e = _run(["nft", "add", "chain", "inet", TABLE, name, spec])
        if rc != 0 and "exists" not in (e or "").lower():
            errors.append("chain %s: %s" % (name, e.strip()))

    if need_nat:
        _chain("predr", "{ type nat hook prerouting priority dstnat; policy accept; }")
        if proxy_self:
            _chain("outdr", "{ type nat hook output priority dstnat; policy accept; }")
    if need_mangle:
        _chain("pretp", "{ type filter hook prerouting priority mangle; policy accept; }")
        if proxy_self:
            _chain("outtp", "{ type route hook output priority mangle; policy accept; }")

    rule_count = 0
    for family in families:
        if need_nat:
            frags = build_redirect_fragments(
                family=family, tcp_port=tcp_port, lan_ifaces=lan_ifaces,
                server_ips=server_ips, bypass=bypass, proxy_self=proxy_self)
            for fr in frags["prerouting"]:
                rc, _o, e = _run(_nft_add_rule("predr", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("predr: %s" % e.strip())
            for fr in frags["output"]:
                rc, _o, e = _run(_nft_add_rule("outdr", fr))
                if rc != 0:
                    errors.append("outdr: %s" % e.strip())

        if need_mangle:
            protocols = ("udp",) if mode == "hybrid" else ("tcp", "udp")
            tp_port = udp_port if mode == "hybrid" else tcp_port
            frags = build_tproxy_fragments(
                family=family, port=tp_port, mark=mark, protocols=protocols,
                lan_ifaces=lan_ifaces, server_ips=server_ips, bypass=bypass,
                proxy_self=proxy_self)
            for fr in frags["prerouting"]:
                rc, _o, e = _run(_nft_add_rule("pretp", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("pretp: %s" % e.strip())
            for fr in frags["output"]:
                rc, _o, e = _run(_nft_add_rule("outtp", fr))
                if rc != 0:
                    errors.append("outtp: %s" % e.strip())
            errors.extend(_add_tproxy_route(family, mark, table))

        # Перехват DNS (как в iptables-ветке): redirect-режим → в nat-
        # цепочку, иначе → tproxy в mangle-цепочку.
        if dns_hijack_port:
            via = "redirect" if mode == "redirect" else "tproxy"
            dns_chain = "predr" if via == "redirect" else "pretp"
            for fr in build_dns_hijack_fragments(
                    family=family, dns_port=dns_hijack_port,
                    lan_ifaces=lan_ifaces, via=via, mark=mark):
                rc, _o, e = _run(_nft_add_rule(dns_chain, fr))
                rule_count += 1
                if rc != 0:
                    errors.append("%s(dns): %s" % (dns_chain, e.strip()))

    # IPv6 anti-leak: дропнуть весь форвард-IPv6, если v6 не проксируем и
    # политика drop (parity с iptables build_ipv6_block_rules).
    if "v6" not in families and ipv6_policy == "drop":
        _chain("fwd6", "{ type filter hook forward priority 0; policy accept; }")
        rc, _o, e = _run(_nft_add_rule("fwd6", build_ipv6_block_fragment()))
        rule_count += 1
        if rc != 0:
            errors.append("fwd6: %s" % e.strip())

    ok = not errors
    if ok:
        log.info("singbox transparent (nft): режим '%s' (%s)"
                 % (mode, ",".join(families)), source="singbox")
    else:
        log.warning("singbox transparent (nft): '%s' с ошибками: %s"
                    % (mode, "; ".join(errors)), source="singbox")
    return {"ok": ok, "mode": mode, "backend": "nftables",
            "errors": errors, "rule_count": rule_count}


def remove(*, mark: int = DEFAULT_TPROXY_MARK,
           table: int = DEFAULT_TPROXY_TABLE,
           families: tuple = ("v4", "v6")) -> dict:
    if not available():
        return {"ok": True, "noop": True}
    _run(["nft", "delete", "table", "inet", TABLE])
    for family in families:
        _del_tproxy_route(family, mark, table)
    log.info("singbox transparent (nft): таблица снята", source="singbox")
    return {"ok": True, "backend": "nftables"}
