# core/routing/nftset_backend.py
"""
Бэкенд nftables sets для domain-based routing.

Используется на OpenWrt 22.03+ и современном Linux, где iptables
заменён на nftables. dnsmasq >= 2.87 поддерживает директиву
nftset=, которая на лету заполняет именованный set.

Связка:
  1. dnsmasq пишет IP в nftset awg_routing/<set_name>
  2. nft rule в нашей таблице awg_routing маркирует пакеты:
        ip daddr @<set> meta mark set <mark>
  3. ip rule add fwmark <mark> lookup <table>

Имя нашей nft-таблицы — "awg_routing" (никогда не трогаем чужие).
"""

import subprocess

from core.log_buffer import log


TABLE_NAME = "awg_routing"


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


def available():
    rc, _o, _e = _run(["nft", "--version"], timeout=3)
    return rc == 0


def set_name_for(rule_id: str) -> str:
    """Имя set'а для правила (nftables допускает длинные имена, но всё
    равно ужимаем для стабильности)."""
    return ("awgr_" + rule_id.replace("-", "_"))[:63]


# ────────────────────── table / chains ──────────────────────────────

def _ensure_table_and_chains():
    """
    Гарантировать, что наша таблица и цепочки существуют.

    Цепочки prerouting/output типа filter с hook=mangle:
    в nft mark меняется именно через type filter hook prerouting/output
    с приоритетом mangle.

    Дополнительно создаём postrouting type=nat — туда повесим
    masquerade на исходящий AWG-интерфейс. Без MASQUERADE для
    fwmark-маршрутизации src IP пакета остаётся от первой маршрутной
    выборки (через WAN), и AWG-сервер дропает пакеты по AllowedIPs.
    Подробности — в комментарии к ensure_iface_masquerade().
    """
    rc, out, _e = _run(["nft", "list", "table", "inet", TABLE_NAME])
    if rc == 0:
        chains_ok = ("chain prerouting" in out and
                     "chain output" in out and
                     "chain postrouting" in out)
        if chains_ok:
            return True

    cmds = [
        ["nft", "add", "table", "inet", TABLE_NAME],
        ["nft", "add", "chain", "inet", TABLE_NAME, "prerouting",
         "{ type filter hook prerouting priority mangle; policy accept; }"],
        ["nft", "add", "chain", "inet", TABLE_NAME, "output",
         "{ type filter hook output priority mangle; policy accept; }"],
        ["nft", "add", "chain", "inet", TABLE_NAME, "postrouting",
         "{ type nat hook postrouting priority srcnat; policy accept; }"],
    ]
    for c in cmds:
        rc, _o, err = _run(c)
        if rc != 0 and "exists" not in (err or "").lower():
            log.warning("nft init: %s: %s" % (" ".join(c), err.strip()),
                        source="routing")
    return True


# ────────────────────── set ops ─────────────────────────────────────

def create_set(name: str, family: str = "v4") -> dict:
    _ensure_table_and_chains()
    typ = "ipv6_addr" if family == "v6" else "ipv4_addr"

    rc, out, _e = _run(["nft", "list", "set", "inet", TABLE_NAME, name])
    if rc == 0:
        return {"ok": True, "created": False, "name": name}

    rc, _o, err = _run(["nft", "add", "set", "inet", TABLE_NAME, name,
                        "{ type %s; flags interval; auto-merge; }" % typ])
    if rc != 0 and "exists" not in (err or "").lower():
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "created": True, "name": name}


def destroy_set(name: str) -> dict:
    rc, _o, err = _run(["nft", "delete", "set", "inet", TABLE_NAME, name])
    if rc != 0 and "no such" not in (err or "").lower():
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "name": name}


def flush_set(name: str) -> dict:
    rc, _o, err = _run(["nft", "flush", "set", "inet", TABLE_NAME, name])
    return {"ok": rc == 0, "error": err.strip() if rc else "", "name": name}


# ────────────────────── mark rules ──────────────────────────────────

def _rule_exists(chain: str, set_name: str, mark: int, family: str) -> bool:
    rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                        TABLE_NAME, chain])
    if rc != 0:
        return False
    daddr = "ip6 daddr" if family == "v6" else "ip daddr"
    needle = "%s @%s meta mark set 0x%x" % (daddr, set_name, mark)
    return needle in out


def setup_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    _ensure_table_and_chains()
    daddr = "ip6 daddr" if family == "v6" else "ip daddr"
    errors = []
    for chain in ("prerouting", "output"):
        if _rule_exists(chain, set_name, mark, family):
            continue
        rule = "%s @%s meta mark set %d" % (daddr, set_name, mark)
        rc, _o, err = _run(["nft", "add", "rule", "inet", TABLE_NAME,
                            chain] + rule.split())
        if rc != 0:
            errors.append("nft add rule %s: %s" % (chain, err.strip()))
    return {"ok": not errors, "mark": mark, "errors": errors}


def ensure_iface_masquerade(ifname: str) -> dict:
    """
    Идемпотентно повесить masquerade на исходящий ifname в нашей
    postrouting-nat цепочке.

    Зачем: для fwmark-routing (domain-rules) src IP пакета выбирается
    при ПЕРВОМ route lookup'е (mark=0 → main-таблица → src=WAN_IP).
    После того как OUTPUT mangle поставит метку и ядро переректит пакет
    через AWG-таблицу, src в IP-заголовке УЖЕ зафиксирован — ядро его
    не пересчитывает. В итоге пакет уходит через AWG с src=WAN_IP,
    и AWG-сервер дропает его по AllowedIPs (там 10.x клиента, не
    WAN_IP). Поэтому маскарадим всё, что физически выходит через AWG —
    src перепишется на интерфейсный IP. На CIDR-routing это no-op:
    там src уже корректный.

    Поскольку цепочка `inet`, одно правило `oifname X masquerade`
    покрывает и v4, и v6.
    """
    _ensure_table_and_chains()
    rc, out, _e = _run(["nft", "list", "chain", "inet",
                        TABLE_NAME, "postrouting"])
    if rc == 0:
        needle = "oifname \"%s\" masquerade" % ifname
        # У некоторых версий nft вывод без кавычек — учитываем обе формы
        if needle in out or ("oifname %s masquerade" % ifname) in out:
            return {"ok": True, "added": False, "ifname": ifname}

    rc, _o, err = _run(["nft", "add", "rule", "inet", TABLE_NAME,
                        "postrouting", "oifname", ifname, "masquerade"])
    if rc != 0:
        return {"ok": False, "error": err.strip(), "ifname": ifname}
    return {"ok": True, "added": True, "ifname": ifname}


def remove_iface_masquerade(ifname: str) -> dict:
    """Удалить ВСЕ masquerade-правила по oifname в postrouting (по handle)."""
    rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                        TABLE_NAME, "postrouting"])
    if rc != 0:
        return {"ok": True, "removed": 0}
    removed = 0
    needles = (
        "oifname \"%s\" masquerade" % ifname,
        "oifname %s masquerade" % ifname,
    )
    for line in out.splitlines():
        if any(n in line for n in needles) and "handle" in line:
            parts = line.rsplit("handle", 1)
            if len(parts) == 2:
                h = parts[1].strip().split()[0]
                if h.isdigit():
                    rc2, _o, _e2 = _run(["nft", "delete", "rule", "inet",
                                          TABLE_NAME, "postrouting",
                                          "handle", h])
                    if rc2 == 0:
                        removed += 1
    return {"ok": True, "removed": removed, "ifname": ifname}


def teardown_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    """Удаляем по handle: получаем list -a, ищем строку с нашим set."""
    daddr = "ip6 daddr" if family == "v6" else "ip daddr"
    needle = "%s @%s meta mark set 0x%x" % (daddr, set_name, mark)

    for chain in ("prerouting", "output"):
        rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                            TABLE_NAME, chain])
        if rc != 0:
            continue
        for line in out.splitlines():
            if needle in line and "handle" in line:
                # ... # handle 42
                parts = line.rsplit("handle", 1)
                if len(parts) == 2:
                    h = parts[1].strip().split()[0]
                    if h.isdigit():
                        _run(["nft", "delete", "rule", "inet", TABLE_NAME,
                              chain, "handle", h])
    return {"ok": True}


# ────────────────────── ip rule fwmark ──────────────────────────────

def add_ip_rule_fwmark(mark: int, table: int, family: str = "v4",
                       priority: int = 10100) -> dict:
    fam = "-6" if family == "v6" else "-4"
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
