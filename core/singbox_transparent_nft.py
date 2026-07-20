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

scope='self' — локальный режим (ПК/VPS с одной NIC, парно iptables-
варианту): только OUTPUT самой машины, без перехвата форварда; анти-петля
через mark движка / `fib daddr type local` / `ct direction reply`.

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
                             proxy_self: bool = False,
                             scope: str = "forward",
                             mark: int = DEFAULT_TPROXY_MARK) -> dict:
    """
    Вернуть {"prerouting": [...], "output": [...]} фрагментов nft-правил
    для redirect-режима. scope='self' — локальный режим: prerouting пуст
    (входящие соединения к машине не трогаем), всё в output.
    """
    daddr = _daddr(family)
    if scope == "self":
        out = ["meta mark %d return" % mark,
               # свои адреса машины (вкл. публичный IP) — мимо
               "fib daddr type local return",
               "%s %s return" % (daddr, _bypass_set(family, bypass))]
        for ip in (server_ips or []):
            out.append("%s %s return" % (daddr, ip))
        out.append("meta l4proto tcp redirect to :%d" % tcp_port)
        return {"prerouting": [], "output": out}

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
        out.append("meta mark %d return" % mark)
        out.append("meta l4proto tcp redirect to :%d" % tcp_port)
    return {"prerouting": pre, "output": out}


def build_tproxy_fragments(*, family: str, port: int,
                           mark: int = DEFAULT_TPROXY_MARK,
                           protocols: tuple = ("tcp", "udp"),
                           lan_ifaces: list = None,
                           server_ips: list = None,
                           bypass: list = None,
                           proxy_self: bool = False,
                           scope: str = "forward") -> dict:
    """
    Вернуть {"prerouting": [...], "output": [...]} фрагментов для tproxy.
    scope='self' — локальный режим: output метит исходящий трафик машины
    (анти-петля: mark движка, свои адреса через fib, ответы на входящие
    через ct direction reply), prerouting ловит TPROXY'ем только
    собственные помеченные пакеты с lo.
    """
    daddr = _daddr(family)
    tp_ip = "ip6" if family == "v6" else "ip"
    protoset = "{ %s }" % ", ".join(protocols)

    if scope == "self":
        out = ["meta mark %d return" % mark,
               "fib daddr type local return",
               "ct direction reply return",
               "%s %s return" % (daddr, _bypass_set(family, bypass))]
        for ip in (server_ips or []):
            out.append("%s %s return" % (daddr, ip))
        out.append("meta l4proto %s meta mark set %d" % (protoset, mark))
        pre = ["%s %s return" % (daddr, _bypass_set(family, bypass))]
        for ip in (server_ips or []):
            pre.append("%s %s return" % (daddr, ip))
        pre.append('iifname "lo" meta l4proto %s meta mark %d '
                   'tproxy %s to :%d' % (protoset, mark, tp_ip, port))
        return {"prerouting": pre, "output": out}

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
                               mark: int = DEFAULT_TPROXY_MARK,
                               scope: str = "forward") -> list:
    """
    Фрагменты перехвата DNS (udp/tcp dport 53) на DNS-порт движка —
    защита от DNS-leak мимо туннеля. Парно к build_dns_hijack_rules
    из iptables-ветки.

      via='redirect' → `redirect to :dns_port` (nat-цепочка: predr,
                       в scope='self' — outdr);
      via='tproxy'   → `tproxy … meta mark set` (mangle-цепочка pretp;
                       в scope='self' — только свои пакеты с lo).

    `th dport 53` (transport-header dport) ловит и tcp, и udp. Возвращает
    список фрагментов-строк (по одному на интерфейс).
    """
    tp_ip = "ip6" if family == "v6" else "ip"
    if scope == "self":
        if via == "redirect":
            return ["meta l4proto { tcp, udp } th dport 53 "
                    "redirect to :%d" % dns_port]
        return ['iifname "lo" meta l4proto { tcp, udp } th dport 53 '
                "meta mark %d tproxy %s to :%d" % (mark, tp_ip, dns_port)]
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


def build_ipv6_forward_block_fragments() -> list:
    """
    Anti-leak: дроп форвард-IPv6, когда проксируем только v4 (иначе
    IPv6-клиенты ходят мимо туннеля). Исключения: IPv4, локальные и
    ULA/Link-local адреса (не глушим локалку).
    """
    return [
        "meta nfproto ipv4 return",
        "ip6 daddr %s return" % _bypass_set("v6", []),
        "meta nfproto ipv6 drop",
    ]


def build_ipv6_self_block_fragments(mark: int = DEFAULT_TPROXY_MARK) -> list:
    """
    Anti-leak IPv6 локального режима: на ПК FORWARD пуст — глушим
    ИСХОДЯЩИЙ v6 самой машины (цепочка out6, hook output). Исключения:
    v4 целиком, трафик движка (mark), ответы на входящие соединения
    (не рвём v6-SSH к машине) и локальные назначения.
    """
    return [
        "meta nfproto ipv4 return",
        "meta mark %d return" % mark,
        "ct direction reply return",
        "ip6 daddr %s return" % _bypass_set("v6", []),
        "meta nfproto ipv6 drop",
    ]


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
          dns_hijack_port: int = 0, ipv6_policy: str = "allow",
          scope: str = "forward") -> dict:
    if not available():
        return {"ok": False, "error": "nft недоступен"}
    if mode not in ("redirect", "tproxy", "hybrid"):
        return {"ok": False, "error": "Неизвестный режим: %s" % mode}
    if scope not in ("forward", "self"):
        return {"ok": False, "error": "Неизвестная область: %s" % scope}

    errors = []
    # Сносим свою таблицу и создаём заново — простая идемпотентность.
    _run(["nft", "delete", "table", "inet", TABLE])
    rc, _o, err = _run(["nft", "add", "table", "inet", TABLE])
    if rc != 0:
        return {"ok": False, "error": "nft add table: %s" % err.strip()}

    self_scope = (scope == "self")
    need_nat = mode in ("redirect", "hybrid")
    need_mangle = mode in ("tproxy", "hybrid")

    def _chain(name, spec):
        rc, _o, e = _run(["nft", "add", "chain", "inet", TABLE, name, spec])
        if rc != 0 and "exists" not in (e or "").lower():
            errors.append("chain %s: %s" % (name, e.strip()))

    if need_nat:
        if not self_scope:
            _chain("predr", "{ type nat hook prerouting priority dstnat; policy accept; }")
        if self_scope or proxy_self:
            _chain("outdr", "{ type nat hook output priority dstnat; policy accept; }")
    if need_mangle:
        # pretp нужен и в self-режиме: возврат своих помеченных пакетов с lo.
        _chain("pretp", "{ type filter hook prerouting priority mangle; policy accept; }")
        if self_scope or proxy_self:
            _chain("outtp", "{ type route hook output priority mangle; policy accept; }")

    rule_count = 0
    for family in families:
        if need_nat:
            frags = build_redirect_fragments(
                family=family, tcp_port=tcp_port, lan_ifaces=lan_ifaces,
                server_ips=server_ips, bypass=bypass, proxy_self=proxy_self,
                scope=scope, mark=mark)
            for fr in frags["prerouting"]:
                rc, _o, e = _run(_nft_add_rule("predr", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("predr: %s" % e.strip())
            for fr in frags["output"]:
                rc, _o, e = _run(_nft_add_rule("outdr", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("outdr: %s" % e.strip())

        if need_mangle:
            protocols = ("udp",) if mode == "hybrid" else ("tcp", "udp")
            tp_port = udp_port if mode == "hybrid" else tcp_port
            frags = build_tproxy_fragments(
                family=family, port=tp_port, mark=mark, protocols=protocols,
                lan_ifaces=lan_ifaces, server_ips=server_ips, bypass=bypass,
                proxy_self=proxy_self, scope=scope)
            for fr in frags["prerouting"]:
                rc, _o, e = _run(_nft_add_rule("pretp", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("pretp: %s" % e.strip())
            for fr in frags["output"]:
                rc, _o, e = _run(_nft_add_rule("outtp", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("outtp: %s" % e.strip())
            errors.extend(_add_tproxy_route(family, mark, table))

        # Перехват DNS (как в iptables-ветке): redirect-режим → в nat-
        # цепочку (self → outdr), иначе → tproxy в mangle-цепочку.
        if dns_hijack_port:
            via = "redirect" if mode == "redirect" else "tproxy"
            if via == "redirect":
                dns_chain = "outdr" if self_scope else "predr"
            else:
                dns_chain = "pretp"
            for fr in build_dns_hijack_fragments(
                    family=family, dns_port=dns_hijack_port,
                    lan_ifaces=lan_ifaces, via=via, mark=mark, scope=scope):
                rc, _o, e = _run(_nft_add_rule(dns_chain, fr))
                rule_count += 1
                if rc != 0:
                    errors.append("%s(dns): %s" % (dns_chain, e.strip()))

    # IPv6 anti-leak: если v6 не проксируем и политика drop — глушим
    # форвард-IPv6 (роутер) либо исходящий v6 машины (локальный режим).
    if "v6" not in families and ipv6_policy == "drop":
        if self_scope:
            _chain("out6", "{ type filter hook output priority 0; policy accept; }")
            for fr in build_ipv6_self_block_fragments(mark):
                rc, _o, e = _run(_nft_add_rule("out6", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("out6: %s" % e.strip())
        else:
            _chain("fwd6", "{ type filter hook forward priority 0; policy accept; }")
            for fr in build_ipv6_forward_block_fragments():
                rc, _o, e = _run(_nft_add_rule("fwd6", fr))
                rule_count += 1
                if rc != 0:
                    errors.append("fwd6: %s" % e.strip())

    ok = not errors
    if ok:
        log.info("singbox transparent (nft): режим '%s' (%s%s)"
                 % (mode, ",".join(families),
                    ", локальный режим" if self_scope else ""),
                 source="singbox")
    else:
        log.warning("singbox transparent (nft): '%s' с ошибками: %s"
                    % (mode, "; ".join(errors)), source="singbox")
    return {"ok": ok, "mode": mode, "scope": scope, "backend": "nftables",
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
