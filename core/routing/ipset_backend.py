# core/routing/ipset_backend.py
"""
Бэкенд kernel-ipset для domain-based routing.

Работает на системах с iptables + ipset (Keenetic с OpkgTun + Entware,
старые OpenWrt, Linux с установленным ipset).

Связка такая:
  1. dnsmasq резолвит домены и складывает IP в ipset SETNAME.
  2. iptables -t mangle -A PREROUTING/OUTPUT
       -m set --match-set SETNAME dst -j MARK --set-mark <mark>
  3. ip rule add fwmark <mark> lookup <table>
     (правило в основной таблице уже добавлено RoutingManager'ом).

Имена ipset ограничены 31 символом. Используем префикс awgr_<short>.
"""

import subprocess

from core.log_buffer import log


# Имя цепочек, которые мы создаём в mangle (никогда не трогаем уже
# существующие правила пользователя).
PREROUTING_CHAIN = "AWG_ROUTING_PRE"
OUTPUT_CHAIN     = "AWG_ROUTING_OUT"
# Цепочка в таблице nat для MASQUERADE на исходящий AWG-iface
# (без неё domain-routing уходит с src=WAN_IP и сервер дропает
# по AllowedIPs — подробности в ensure_iface_masquerade).
NAT_CHAIN        = "AWG_ROUTING_NAT"


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


# ─────────────────────── availability ────────────────────────────────

def available():
    """ipset + iptables присутствуют."""
    rc1, _o, _e = _run(["ipset", "-v"], timeout=3)
    rc2, _o2, _e2 = _run(["iptables", "-V"], timeout=3)
    return rc1 == 0 and rc2 == 0


# ─────────────────────── set ops ────────────────────────────────────

def set_name_for(rule_id: str) -> str:
    """Стабильное имя ipset для правила, влезающее в 31 символ."""
    short = rule_id.replace("-", "_")
    name = "awgr_" + short
    return name[:31]


def create_set(name: str, family: str = "v4") -> dict:
    """
    Создаёт ipset, если его нет. Возвращает {ok, created}.
    family: 'v4' → inet, 'v6' → inet6.
    """
    fam = "inet6" if family == "v6" else "inet"
    rc, out, err = _run(["ipset", "list", "-name"])
    if rc == 0 and name in out.split():
        return {"ok": True, "created": False, "name": name}

    rc, _o, err = _run(["ipset", "create", name, "hash:ip",
                        "family", fam, "hashsize", "1024", "timeout", "0"])
    if rc != 0 and "already exists" not in (err or ""):
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "created": True, "name": name}


def destroy_set(name: str) -> dict:
    rc, _o, err = _run(["ipset", "destroy", name])
    if rc != 0 and "set with the given name does not exist" not in (err or "").lower():
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "name": name}


def flush_set(name: str) -> dict:
    rc, _o, err = _run(["ipset", "flush", name])
    return {"ok": rc == 0, "error": err.strip() if rc else "", "name": name}


# ─────────────────────── iptables wiring ────────────────────────────

def _ensure_chain(table: str, chain: str):
    """Создать цепочку, если её нет, и вызвать её из table-PREROUTING/OUTPUT."""
    # iptables -t mangle -N AWG_ROUTING_PRE
    rc, _o, err = _run(["iptables", "-t", table, "-N", chain])
    chain_existed = (rc != 0 and "already exists" in (err or "").lower())

    return chain_existed or rc == 0


def _ensure_jump(table: str, parent: str, chain: str):
    """В parent-цепочке добавляем -j chain один раз."""
    rc, out, _e = _run(["iptables", "-t", table, "-S", parent])
    if rc == 0:
        for line in out.splitlines():
            if line.strip() == "-A %s -j %s" % (parent, chain):
                return True
    rc, _o, err = _run(["iptables", "-t", table, "-A", parent, "-j", chain])
    if rc != 0:
        log.warning("iptables jump %s→%s: %s" % (parent, chain, err.strip()),
                    source="routing")
        return False
    return True


def setup_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    """
    Добавить (идемпотентно) iptables-правила, маркирующие пакеты,
    чьи dst-адреса входят в set_name.

    Возвращает {ok, errors, mark}.
    """
    cmd = "iptables" if family == "v4" else "ip6tables"

    # Цепочки и jump'ы создаём один раз — повторные вызовы тихо ок.
    _ensure_chain("mangle", PREROUTING_CHAIN)
    _ensure_chain("mangle", OUTPUT_CHAIN)
    _ensure_jump("mangle", "PREROUTING", PREROUTING_CHAIN)
    _ensure_jump("mangle", "OUTPUT",     OUTPUT_CHAIN)

    errors = []
    rules = [
        ("mangle", PREROUTING_CHAIN),
        ("mangle", OUTPUT_CHAIN),
    ]

    for table, chain in rules:
        match = ["-m", "set", "--match-set", set_name, "dst",
                 "-j", "MARK", "--set-mark", str(mark)]

        # Сначала чистим возможный дубликат
        _run([cmd, "-t", table, "-D", chain] + match)

        rc, _o, err = _run([cmd, "-t", table, "-A", chain] + match)
        if rc != 0:
            errors.append("%s -t %s -A %s: %s" % (cmd, table, chain, err.strip()))

    return {"ok": not errors, "mark": mark, "errors": errors}


def teardown_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    cmd = "iptables" if family == "v4" else "ip6tables"
    rules = [
        ("mangle", PREROUTING_CHAIN),
        ("mangle", OUTPUT_CHAIN),
    ]
    for table, chain in rules:
        match = ["-m", "set", "--match-set", set_name, "dst",
                 "-j", "MARK", "--set-mark", str(mark)]
        _run([cmd, "-t", table, "-D", chain] + match)
    return {"ok": True}


# ─────────────────────── masquerade (nat) ──────────────────────────

def ensure_iface_masquerade(ifname: str, family: str = "v4") -> dict:
    """
    Идемпотентно повесить MASQUERADE на исходящий ifname в нашей
    nat-цепочке.

    Зачем: для fwmark-routing (domain-rules) src IP пакета выбирается
    при ПЕРВОМ route lookup'е (mark=0 → main-таблица → src=WAN_IP).
    После того как OUTPUT mangle поставит метку и ядро переректит
    пакет через AWG-таблицу, src в IP-заголовке УЖЕ зафиксирован —
    ядро его не пересчитывает. В итоге пакет уходит через AWG с
    src=WAN_IP, и AWG-сервер дропает его по AllowedIPs клиента.
    Поэтому маскарадим всё, что физически выходит через AWG — src
    перепишется на интерфейсный IP. На CIDR-routing это no-op:
    там src уже корректный.
    """
    cmd = "iptables" if family == "v4" else "ip6tables"
    # Цепочка в nat
    rc, _o, err = _run([cmd, "-t", "nat", "-N", NAT_CHAIN])
    if rc != 0 and "already exists" not in (err or "").lower():
        return {"ok": False, "error": err.strip()}
    # Прыжок POSTROUTING → NAT_CHAIN ОБЯЗАН стоять в начале цепочки.
    # На роутерах (Keenetic/ndm) есть собственные SNAT/MASQUERADE-правила
    # в POSTROUTING. Если наш прыжок добавлен в конец (как было раньше,
    # через -A), ndm успевает переписать src на WAN-адрес РАНЬШЕ нас —
    # пакет уходит в AWG с WAN-src, и сервер дропает его по AllowedIPs
    # (туннель ждёт src=AWG_IP). Поэтому удаляем все наши прыжки (на
    # случай дубликатов/старого -A) и вставляем один в позицию 1. Для
    # всех не-AWG интерфейсов наша цепочка пустая → это no-op.
    for _ in range(8):
        rc_d, _o, _e = _run([cmd, "-t", "nat", "-D", "POSTROUTING",
                             "-j", NAT_CHAIN])
        if rc_d != 0:
            break
    _run([cmd, "-t", "nat", "-I", "POSTROUTING", "1", "-j", NAT_CHAIN])
    # Само правило: -o <ifname> -j MASQUERADE (идемпотентно)
    rc, out, _e = _run([cmd, "-t", "nat", "-S", NAT_CHAIN])
    if rc == 0:
        needle = "-A %s -o %s -j MASQUERADE" % (NAT_CHAIN, ifname)
        if needle in out:
            return {"ok": True, "added": False, "ifname": ifname}
    rc, _o, err = _run([cmd, "-t", "nat", "-A", NAT_CHAIN,
                        "-o", ifname, "-j", "MASQUERADE"])
    if rc != 0:
        return {"ok": False, "error": err.strip(), "ifname": ifname}
    return {"ok": True, "added": True, "ifname": ifname}


def remove_iface_masquerade(ifname: str, family: str = "v4") -> dict:
    """Удалить MASQUERADE-правило по oifname (если есть)."""
    cmd = "iptables" if family == "v4" else "ip6tables"
    _run([cmd, "-t", "nat", "-D", NAT_CHAIN,
          "-o", ifname, "-j", "MASQUERADE"])
    return {"ok": True, "ifname": ifname}


# ─────────────────────── forward accept (filter) ───────────────────

def ensure_iface_forward(ifname: str, family: str = "v4") -> dict:
    """
    Идемпотентно разрешить форвардинг в обе стороны через ifname.

    Зачем: на роутерах FORWARD-политика обычно DROP, а штатный firewall
    (Keenetic ndm, OpenWrt fw4) НЕ знает наш AWG-интерфейс — значит
    форвард LAN→AWG проваливается в DROP, и трафик с устройств за
    роутером в туннель не идёт (с самого роутера работает, т.к. это
    OUTPUT, а не FORWARD). Поэтому вставляем ACCEPT для нашего iface
    В НАЧАЛО FORWARD (до политики DROP и до ndm-цепочек).

    `-i ifname` пропускает обратный трафик из туннеля в LAN, `-o ifname`
    — исходящий в туннель.
    """
    cmd = "iptables" if family == "v4" else "ip6tables"
    for spec in (["-o", ifname], ["-i", ifname]):
        # Чистим возможные дубликаты, затем ставим в позицию 1.
        for _ in range(4):
            rc, _o, _e = _run([cmd, "-t", "filter", "-D", "FORWARD"]
                              + spec + ["-j", "ACCEPT"])
            if rc != 0:
                break
        _run([cmd, "-t", "filter", "-I", "FORWARD", "1"]
             + spec + ["-j", "ACCEPT"])
    return {"ok": True, "ifname": ifname}


def remove_iface_forward(ifname: str, family: str = "v4") -> dict:
    cmd = "iptables" if family == "v4" else "ip6tables"
    for spec in (["-o", ifname], ["-i", ifname]):
        for _ in range(4):
            rc, _o, _e = _run([cmd, "-t", "filter", "-D", "FORWARD"]
                              + spec + ["-j", "ACCEPT"])
            if rc != 0:
                break
    return {"ok": True, "ifname": ifname}


# ─────────────────────── ip rule fwmark ─────────────────────────────

def add_ip_rule_fwmark(mark: int, table: int, family: str = "v4",
                       priority: int = 10100) -> dict:
    """ip rule add fwmark <mark> lookup <table>."""
    fam = "-6" if family == "v6" else "-4"
    # Сначала удаляем дубликат — идемпотентно
    _run(["ip", fam, "rule", "del", "fwmark", str(mark),
          "lookup", str(table)])
    rc, _o, err = _run(["ip", fam, "rule", "add", "fwmark", str(mark),
                        "lookup", str(table), "priority", str(priority)])
    return {"ok": rc == 0, "error": err.strip()}


def del_ip_rule_fwmark(mark: int, table: int, family: str = "v4") -> dict:
    fam = "-6" if family == "v6" else "-4"
    _run(["ip", fam, "rule", "del", "fwmark", str(mark),
          "lookup", str(table)])
    return {"ok": True}
