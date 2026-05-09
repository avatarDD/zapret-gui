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
