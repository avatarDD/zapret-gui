# core/singbox_transparent.py
"""
Прозрачное проксирование трафика через sing-box (и совместимые движки).

Идея заимствована из XKeen (TProxy / Redirect / Hybrid режимы): вместо
того чтобы заставлять пользователя руками настраивать tun-интерфейс и
firewall, мы умеем сами:

  1. сгенерить нужный inbound в конфиге движка
     (`make_transparent_inbounds` в core/singbox_config.py);
  2. поднять firewall-правила, которые заворачивают трафик
     LAN-клиентов (и опционально самого роутера) в этот inbound.

Режимы (как в XKeen):

  • redirect — TCP через `iptables -t nat REDIRECT` на порт движка.
               Самый совместимый: работает везде, где есть nat-таблица,
               не требует TPROXY-модуля ядра. Минус — только TCP
               (UDP/QUIC так не завернуть, уходит напрямую).

  • tproxy   — TCP+UDP через `iptables -t mangle TPROXY`. Прозрачно
               проксирует и UDP (нужно для QUIC/HTTP3). Требует модуль
               ядра `xt_TPROXY` и `ip rule`/`ip route local`.

  • hybrid   — TCP через redirect, UDP через tproxy. Компромисс: TCP
               по самому совместимому пути, UDP — только там, где есть
               TPROXY. Движок слушает оба inbound'а.

Дополнительно (тоже из XKeen):

  • proxy_self — заворачивать трафик, исходящий от самого роутера
                 (цепочка OUTPUT), а не только forward от LAN. Полезно
                 чтобы пакеты Entware/служб роутера тоже шли в прокси.

  • dns_hijack — перехват DNS (udp/tcp :53) форвард-трафика на порт
                 движка (DNS-проксирование XKeen): защищает от DNS-leak
                 в обход туннеля.

  • ipv6 policy — `drop`: глушим весь форвард-IPv6 (anti-leak, когда
                  прокси только v4), `allow`: не трогаем, `proxy`:
                  заворачиваем v6 теми же правилами (ip6tables).

Архитектура firewall-обвязки повторяет core/routing/ipset_backend.py:
свои именованные цепочки, идемпотентное «create → flush → fill»,
никогда не трогаем чужие правила.

ВАЖНО: builder-функции (`build_*`) — чистые, возвращают список argv
(list[list[str]]) и юнит-тестируются без рута. Применение (`apply` /
`remove`) — тонкий слой, прогоняющий argv через идемпотентный `_run`.
"""

import subprocess

from core.log_buffer import log


# ─────────────────────── константы ───────────────────────────────────

# Наши цепочки. Префикс SBT_ = sing-box transparent. Имена короткие
# (iptables ограничивает 28 символами).
NAT_PRE   = "SBT_REDIR_PRE"    # nat PREROUTING: forward-трафик LAN
NAT_OUT   = "SBT_REDIR_OUT"    # nat OUTPUT: трафик самого роутера
MANGLE_PRE = "SBT_TP_PRE"      # mangle PREROUTING: tproxy forward
MANGLE_OUT = "SBT_TP_OUT"      # mangle OUTPUT: tproxy для self (через DIVERT/mark)
MANGLE_DIV = "SBT_TP_DIV"      # mangle: пометка уже-established tproxy-сокетов

# fwmark и таблица для TPROXY (как в большинстве sing-box/xray мануалов).
DEFAULT_TPROXY_MARK = 1
DEFAULT_TPROXY_TABLE = 100

# Сети, которые НИКОГДА не заворачиваем (приватные + спец-назначения).
# Иначе завернём сам прокси-трафик движка к серверу и получим петлю.
DEFAULT_BYPASS_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]
DEFAULT_BYPASS_V6 = [
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]


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


def _ipt(family: str) -> str:
    return "ip6tables" if family == "v6" else "iptables"


# ─────────────────────── pure builders ───────────────────────────────
#
# Каждый возвращает список argv БЕЗ ведущего "iptables" — первый
# элемент это таблица-операция, чтобы тесты были компактны? Нет: для
# читабельности и прямого исполнения возвращаем ПОЛНЫЙ argv, начиная с
# бинаря (iptables/ip6tables). Так apply() просто прогоняет их через _run.


def build_bypass_rules(chain: str, family: str, bypass: list,
                       table: str) -> list:
    """
    RETURN-правила для bypass-сетей в начале нашей цепочки: пакеты к
    приватным/локальным адресам не заворачиваем.

    `table` ОБЯЗАТЕЛЕН: наши цепочки живут в nat (redirect) или mangle
    (tproxy), и `-A` без `-t <table>` ушёл бы в filter, где цепочки нет
    → «No chain/target/match by that name».
    """
    cmd = _ipt(family)
    out = []
    for net in bypass:
        out.append([cmd, "-t", table, "-A", chain, "-d", net, "-j", "RETURN"])
    return out


def build_redirect_rules(*, family: str = "v4",
                         tcp_port: int,
                         lan_ifaces: list = None,
                         server_ips: list = None,
                         bypass: list = None,
                         proxy_self: bool = False,
                         dns_hijack: bool = False) -> list:
    """
    Построить argv для redirect-режима (TCP через nat REDIRECT).

      tcp_port    — порт redirect-inbound'а движка.
      lan_ifaces  — список входных интерфейсов LAN (br0, br-lan…).
                    Пусто → заворачиваем форвард с любого -i.
      server_ips  — IP прокси-серверов (исключаем, чтобы не зациклить).
      bypass      — дополнительные dst-сети, которые не трогаем
                    (к DEFAULT_BYPASS_* добавляются).
      proxy_self  — также заворачивать OUTPUT (трафик роутера).
      dns_hijack  — заворачивать DNS (udp/tcp :53) на tcp_port? Нет:
                    DNS — отдельный механизм (build_dns_hijack_rules),
                    здесь флаг не используется (оставлен для симметрии
                    сигнатур). DNS-перехват требует udp → у redirect
                    его нет, поэтому делается через tproxy/dnat-блок.
    """
    cmd = _ipt(family)
    bypass = list(DEFAULT_BYPASS_V4 if family == "v4" else DEFAULT_BYPASS_V6) \
        + list(bypass or [])
    rules = []

    # bypass-сети + сами прокси-сервера → RETURN
    rules += build_bypass_rules(NAT_PRE, family, bypass, "nat")
    for ip in (server_ips or []):
        rules.append([cmd, "-t", "nat", "-A", NAT_PRE, "-d", ip, "-j", "RETURN"])

    # Основное правило: TCP → REDIRECT на порт движка.
    if lan_ifaces:
        for ifn in lan_ifaces:
            rules.append([cmd, "-t", "nat", "-A", NAT_PRE, "-i", ifn,
                          "-p", "tcp", "-j", "REDIRECT",
                          "--to-ports", str(tcp_port)])
    else:
        rules.append([cmd, "-t", "nat", "-A", NAT_PRE, "-p", "tcp",
                      "-j", "REDIRECT", "--to-ports", str(tcp_port)])

    if proxy_self:
        rules += build_bypass_rules(NAT_OUT, family, bypass, "nat")
        for ip in (server_ips or []):
            rules.append([cmd, "-t", "nat", "-A", NAT_OUT, "-d", ip,
                          "-j", "RETURN"])
        # Не заворачиваем трафик, который движок сам шлёт наружу — он
        # помечает свои сокеты собственным fwmark'ом? Для redirect это
        # не нужно: REDIRECT в OUTPUT не трогает локально-сгенерённый
        # трафик от процесса с uid root, если движок бежит под root.
        # Чтобы избежать петли — исключаем владельца по mark, который
        # движок ставит через routing_mark/so_mark (см. конфиг).
        rules.append([cmd, "-t", "nat", "-A", NAT_OUT, "-m", "mark",
                      "--mark", str(DEFAULT_TPROXY_MARK), "-j", "RETURN"])
        rules.append([cmd, "-t", "nat", "-A", NAT_OUT, "-p", "tcp",
                      "-j", "REDIRECT", "--to-ports", str(tcp_port)])
    return rules


def build_tproxy_rules(*, family: str = "v4",
                       port: int,
                       mark: int = DEFAULT_TPROXY_MARK,
                       protocols: tuple = ("tcp", "udp"),
                       lan_ifaces: list = None,
                       server_ips: list = None,
                       bypass: list = None,
                       proxy_self: bool = False) -> list:
    """
    Построить argv для tproxy-режима (mangle TPROXY, TCP+UDP).

      port       — порт tproxy-inbound'а движка.
      mark       — fwmark, который ставим завёрнутым пакетам.
      protocols  — какие протоколы заворачивать ('tcp','udp').
      proxy_self — заворачивать OUTPUT роутера: помечаем пакеты mark'ом
                   в OUTPUT, ядро их реректит в PREROUTING через
                   ip rule fwmark → lookup table local.

    Для tproxy нужны ещё `ip rule add fwmark <mark> lookup <table>` и
    `ip route add local default dev lo table <table>` — их ставит
    apply(), здесь только iptables-часть.
    """
    cmd = _ipt(family)
    bypass = list(DEFAULT_BYPASS_V4 if family == "v4" else DEFAULT_BYPASS_V6) \
        + list(bypass or [])
    rules = []

    # PREROUTING (forward от LAN) ----------------------------------------
    rules += build_bypass_rules(MANGLE_PRE, family, bypass, "mangle")
    for ip in (server_ips or []):
        rules.append([cmd, "-t", "mangle", "-A", MANGLE_PRE, "-d", ip,
                      "-j", "RETURN"])

    for proto in protocols:
        base = [cmd, "-t", "mangle", "-A", MANGLE_PRE]
        if lan_ifaces:
            for ifn in lan_ifaces:
                rules.append(base + ["-i", ifn, "-p", proto,
                                     "-j", "TPROXY",
                                     "--on-port", str(port),
                                     "--tproxy-mark", str(mark)])
        else:
            rules.append(base + ["-p", proto, "-j", "TPROXY",
                                 "--on-port", str(port),
                                 "--tproxy-mark", str(mark)])

    # OUTPUT (трафик самого роутера) -------------------------------------
    if proxy_self:
        rules += build_bypass_rules(MANGLE_OUT, family, bypass, "mangle")
        for ip in (server_ips or []):
            rules.append([cmd, "-t", "mangle", "-A", MANGLE_OUT, "-d", ip,
                          "-j", "RETURN"])
        # Не зацикливаем сам движок: его сокеты помечены mark.
        rules.append([cmd, "-t", "mangle", "-A", MANGLE_OUT, "-m", "mark",
                      "--mark", str(mark), "-j", "RETURN"])
        for proto in protocols:
            rules.append([cmd, "-t", "mangle", "-A", MANGLE_OUT, "-p", proto,
                          "-j", "MARK", "--set-mark", str(mark)])
    return rules


def build_ipv6_block_rules() -> list:
    """
    Anti-leak: дропнуть весь форвард-IPv6, когда прокси только v4.
    Иначе клиенты с IPv6 ходят в обход прокси напрямую.

    Ставится в нашу цепочку SBT_TP_PRE? Нет — это filter/FORWARD.
    Возвращаем ip6tables-правила (вешаются в FORWARD).
    """
    return [
        ["ip6tables", "-A", "FORWARD", "-j", "DROP"],
    ]


def build_dns_hijack_rules(*, family: str = "v4",
                           dns_port: int,
                           lan_ifaces: list = None,
                           via: str = "tproxy",
                           mark: int = DEFAULT_TPROXY_MARK) -> list:
    """
    Перехват DNS форвард-трафика (udp/tcp :53) на DNS-inbound движка
    (dns_port). Защита от DNS-leak в обход туннеля.

      via='redirect' → nat REDIRECT (только если движок слушает DNS на
                       локальном порту; UDP REDIRECT работает в nat).
      via='tproxy'   → mangle TPROXY (для прозрачного UDP/TCP DNS).
    """
    cmd = _ipt(family)
    rules = []
    ifaces = lan_ifaces or [None]
    for proto in ("udp", "tcp"):
        for ifn in ifaces:
            if via == "redirect":
                r = [cmd, "-t", "nat", "-A", NAT_PRE]
                if ifn:
                    r += ["-i", ifn]
                r += ["-p", proto, "--dport", "53",
                      "-j", "REDIRECT", "--to-ports", str(dns_port)]
            else:
                r = [cmd, "-t", "mangle", "-A", MANGLE_PRE]
                if ifn:
                    r += ["-i", ifn]
                r += ["-p", proto, "--dport", "53",
                      "-j", "TPROXY", "--on-port", str(dns_port),
                      "--tproxy-mark", str(mark)]
            rules.append(r)
    return rules


# ─────────────────────── chain plumbing ──────────────────────────────

def _ensure_chain(family: str, table: str, chain: str) -> bool:
    cmd = _ipt(family)
    rc, _o, err = _run([cmd, "-t", table, "-N", chain])
    return rc == 0 or "already exists" in (err or "").lower()


def _flush_chain(family: str, table: str, chain: str):
    cmd = _ipt(family)
    _run([cmd, "-t", table, "-F", chain])


def _ensure_jump(family: str, table: str, parent: str, chain: str,
                 at_top: bool = True):
    """Идемпотентно вставить -j chain в parent (в начало, если at_top)."""
    cmd = _ipt(family)
    rc, out, _e = _run([cmd, "-t", table, "-S", parent])
    if rc == 0:
        needle = "-A %s -j %s" % (parent, chain)
        if needle in out:
            return True
    # Чистим дубликаты, затем ставим.
    for _ in range(4):
        rc_d, _o, _e = _run([cmd, "-t", table, "-D", parent, "-j", chain])
        if rc_d != 0:
            break
    if at_top:
        _run([cmd, "-t", table, "-I", parent, "1", "-j", chain])
    else:
        _run([cmd, "-t", table, "-A", parent, "-j", chain])
    return True


def _del_jump(family: str, table: str, parent: str, chain: str):
    cmd = _ipt(family)
    for _ in range(4):
        rc, _o, _e = _run([cmd, "-t", table, "-D", parent, "-j", chain])
        if rc != 0:
            break


def _del_chain(family: str, table: str, chain: str):
    cmd = _ipt(family)
    _run([cmd, "-t", table, "-F", chain])
    _run([cmd, "-t", table, "-X", chain])


# ─────────────────────── ip rule/route (tproxy) ──────────────────────

def _add_tproxy_route(family: str, mark: int, table: int) -> dict:
    fam = "-6" if family == "v6" else "-4"
    errors = []
    _run(["ip", fam, "rule", "del", "fwmark", str(mark), "lookup", str(table)])
    rc, _o, err = _run(["ip", fam, "rule", "add", "fwmark", str(mark),
                        "lookup", str(table)])
    if rc != 0 and "exists" not in (err or "").lower():
        errors.append("ip rule fwmark: %s" % err.strip())
    # local default → завёрнутые TPROXY-пакеты доставляются в локальный
    # сокет движка, а не форвардятся дальше.
    rc, _o, err = _run(["ip", fam, "route", "replace", "local", "default",
                        "dev", "lo", "table", str(table)])
    if rc != 0:
        errors.append("ip route local default: %s" % err.strip())
    return {"ok": not errors, "errors": errors}


def _del_tproxy_route(family: str, mark: int, table: int):
    fam = "-6" if family == "v6" else "-4"
    _run(["ip", fam, "rule", "del", "fwmark", str(mark), "lookup", str(table)])
    _run(["ip", fam, "route", "del", "local", "default", "dev", "lo",
          "table", str(table)])


# ─────────────────────── high-level apply/remove ─────────────────────

def available(family: str = "v4") -> bool:
    cmd = _ipt(family)
    rc, _o, _e = _run([cmd, "-V"], timeout=3)
    return rc == 0


def choose_backend(prefer: str = "auto") -> str:
    """
    Выбрать firewall-бэкенд: 'iptables' | 'nftables' | 'none'.

    prefer='auto': iptables приоритетнее (Keenetic/Entware), т.к. там
    наш iptables-путь основной и проверен; nft — для систем без iptables
    (OpenWrt 22.03+). prefer='iptables'/'nftables' — принудительно.
    """
    if prefer == "iptables":
        return "iptables" if available("v4") else "none"
    if prefer == "nftables":
        from core import singbox_transparent_nft as nft
        return "nftables" if nft.available() else "none"
    # auto
    if available("v4"):
        return "iptables"
    from core import singbox_transparent_nft as nft
    if nft.available():
        return "nftables"
    return "none"


def apply(*, mode: str,
          tcp_port: int = 0,
          udp_port: int = 0,
          mark: int = DEFAULT_TPROXY_MARK,
          table: int = DEFAULT_TPROXY_TABLE,
          families: tuple = ("v4",),
          lan_ifaces: list = None,
          server_ips: list = None,
          bypass: list = None,
          proxy_self: bool = False,
          dns_hijack_port: int = 0,
          ipv6_policy: str = "allow",
          backend: str = "auto") -> dict:
    """
    Применить прозрачное проксирование.

      mode: 'redirect' | 'tproxy' | 'hybrid'.
        redirect → TCP nat REDIRECT на tcp_port.
        tproxy   → TCP+UDP mangle TPROXY на tcp_port (udp_port игнор —
                   sing-box tproxy inbound слушает один порт).
        hybrid   → TCP redirect на tcp_port + UDP tproxy на udp_port.

      families: какие IP-семейства обрабатывать ('v4','v6').
      ipv6_policy: 'allow' | 'drop' | 'proxy' — что делать с IPv6
                   когда 'v6' не в families.
      backend: 'auto' | 'iptables' | 'nftables'.
    """
    if mode not in ("redirect", "tproxy", "hybrid"):
        return {"ok": False, "error": "Неизвестный режим: %s" % mode}

    chosen = choose_backend(backend)
    if chosen == "none":
        return {"ok": False, "error": "Нет ни iptables, ни nft"}
    if chosen == "nftables":
        from core import singbox_transparent_nft as nft
        return nft.apply(
            mode=mode, tcp_port=tcp_port, udp_port=udp_port, mark=mark,
            table=table, families=tuple(families), lan_ifaces=lan_ifaces,
            server_ips=server_ips, bypass=bypass, proxy_self=proxy_self,
            dns_hijack_port=dns_hijack_port, ipv6_policy=ipv6_policy)

    cmds = []   # (family, table, [argv...]) — для лога/отладки
    errors = []

    def _exec(argv):
        rc, _o, err = _run(argv)
        if rc != 0:
            errors.append("%s: %s" % (" ".join(argv), err.strip()))
        cmds.append(argv)

    for family in families:
        if not available(family):
            errors.append("%s недоступен" % _ipt(family))
            continue

        if mode in ("redirect", "hybrid"):
            _ensure_chain(family, "nat", NAT_PRE)
            _flush_chain(family, "nat", NAT_PRE)
            if proxy_self:
                _ensure_chain(family, "nat", NAT_OUT)
                _flush_chain(family, "nat", NAT_OUT)
            for argv in build_redirect_rules(
                    family=family, tcp_port=tcp_port,
                    lan_ifaces=lan_ifaces, server_ips=server_ips,
                    bypass=bypass, proxy_self=proxy_self):
                _exec(argv)
            _ensure_jump(family, "nat", "PREROUTING", NAT_PRE)
            if proxy_self:
                _ensure_jump(family, "nat", "OUTPUT", NAT_OUT)

        if mode in ("tproxy", "hybrid"):
            protocols = ("udp",) if mode == "hybrid" else ("tcp", "udp")
            tp_port = udp_port if mode == "hybrid" else tcp_port
            _ensure_chain(family, "mangle", MANGLE_PRE)
            _flush_chain(family, "mangle", MANGLE_PRE)
            if proxy_self:
                _ensure_chain(family, "mangle", MANGLE_OUT)
                _flush_chain(family, "mangle", MANGLE_OUT)
            for argv in build_tproxy_rules(
                    family=family, port=tp_port, mark=mark,
                    protocols=protocols, lan_ifaces=lan_ifaces,
                    server_ips=server_ips, bypass=bypass,
                    proxy_self=proxy_self):
                _exec(argv)
            _ensure_jump(family, "mangle", "PREROUTING", MANGLE_PRE)
            if proxy_self:
                _ensure_jump(family, "mangle", "OUTPUT", MANGLE_OUT)
            r = _add_tproxy_route(family, mark, table)
            errors.extend(r.get("errors", []))

        if dns_hijack_port:
            via = "redirect" if mode == "redirect" else "tproxy"
            for argv in build_dns_hijack_rules(
                    family=family, dns_port=dns_hijack_port,
                    lan_ifaces=lan_ifaces, via=via, mark=mark):
                _exec(argv)

    # IPv6 anti-leak: если v6 не проксируем и политика drop — глушим
    # форвард-IPv6, чтобы клиенты не ходили мимо.
    if "v6" not in families and ipv6_policy == "drop":
        if available("v6"):
            for argv in build_ipv6_block_rules():
                # Идемпотентно: сначала -D, потом -A.
                _run([argv[0], "-D"] + argv[2:])
                _exec(argv)

    ok = not errors
    if ok:
        log.info("singbox transparent: применён режим '%s' (%s)"
                 % (mode, ",".join(families)), source="singbox")
    else:
        log.warning("singbox transparent: режим '%s' с ошибками: %s"
                    % (mode, "; ".join(errors)), source="singbox")
    return {"ok": ok, "mode": mode, "errors": errors,
            "rule_count": len(cmds)}


def remove(*, mark: int = DEFAULT_TPROXY_MARK,
           table: int = DEFAULT_TPROXY_TABLE,
           families: tuple = ("v4", "v6"),
           backend: str = "auto") -> dict:
    """Снять все наши правила прозрачного проксирования (идемпотентно).

    Снимаем на ОБОИХ бэкендах (если присутствуют) — на случай, если
    режим применялся одним, а снимается в другой конфигурации.
    """
    from core import singbox_transparent_nft as nft
    if nft.available():
        nft.remove(mark=mark, table=table, families=families)
    if not available("v4") and not available("v6"):
        return {"ok": True}
    for family in families:
        if not available(family):
            continue
        # nat
        _del_jump(family, "nat", "PREROUTING", NAT_PRE)
        _del_jump(family, "nat", "OUTPUT", NAT_OUT)
        _del_chain(family, "nat", NAT_PRE)
        _del_chain(family, "nat", NAT_OUT)
        # mangle
        _del_jump(family, "mangle", "PREROUTING", MANGLE_PRE)
        _del_jump(family, "mangle", "OUTPUT", MANGLE_OUT)
        _del_chain(family, "mangle", MANGLE_PRE)
        _del_chain(family, "mangle", MANGLE_OUT)
        _del_tproxy_route(family, mark, table)
    # Снять возможный IPv6-block.
    if available("v6"):
        for argv in build_ipv6_block_rules():
            for _ in range(4):
                rc, _o, _e = _run([argv[0], "-D"] + argv[2:])
                if rc != 0:
                    break
    log.info("singbox transparent: правила сняты", source="singbox")
    return {"ok": True}


def reapply_saved() -> dict:
    """
    Переприменить прозрачное проксирование из сохранённых настроек
    (`singbox.transparent` в settings.json). Вызывается при apply-now /
    автозапуске — firewall-правила не переживают перезагрузку, поэтому
    их нужно поднять заново вместе с движком.

    Если настроек нет — no-op.
    """
    try:
        from core.config_manager import get_config_manager
        saved = get_config_manager().get("singbox", "transparent",
                                         default={}) or {}
    except Exception:
        saved = {}
    if not saved or not saved.get("mode"):
        return {"ok": True, "noop": True}
    params = dict(saved)
    params["families"] = tuple(params.get("families") or ["v4"])
    # Отбрасываем неизвестные ключи на случай старого формата.
    allowed = {"mode", "tcp_port", "udp_port", "mark", "table", "families",
               "lan_ifaces", "server_ips", "bypass", "proxy_self",
               "dns_hijack_port", "ipv6_policy"}
    params = {k: v for k, v in params.items() if k in allowed}
    return apply(**params)
