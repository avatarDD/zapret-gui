# core/routing/sweeper.py
"""
Сброс «левых» артефактов маршрутизации (orphan sweep).

Правила маршрутизации живут в двух местах: в нашем storage
(`core/routing/storage.py`) и в ядре (`ip rule`, ipset/nftset,
таблицы маршрутизации). Обычно они синхронны, но расходятся, когда:

  * маршрут удалили или выключили, пока туннель лежал — снимать было
    нечего, а после `up` ядро получило записи из прошлой сессии;
  * apply упал на полпути: часть `ip rule` легла, а правило откатилось
    из storage (см. RoutingManager.update_rule);
  * туннель пересоздали под другим именем — таблица старого осталась;
  * GUI обновили/переустановили, а ядро сохранило записи прошлой версии.

Такие записи невидимы в GUI, но продолжают заворачивать трафик — отсюда
классическое «правил нет / правила правильные, а маршрутизация не
работает (или работает не туда)».

Sweep консервативен: трогаем ТОЛЬКО заведомо своё —

  * `ip rule` с приоритетом из нашего диапазона (10000..10299), который
    указывает в одну из НАШИХ таблиц (`routing.table_map`);
  * ipset/nftset с префиксом `awgr_`, за которым не стоит ни одного
    domain-правила;
  * наши таблицы маршрутизации, чей интерфейс исчез из ядра.

Всё остальное — правила пользователя, main/local/default, чужие
таблицы и наборы — не трогаем.
"""

import re
import subprocess

from core.log_buffer import log


# Диапазон приоритетов `ip rule`, которые расставляет проект:
#   10000 — CidrRoutingRule (rules.DEFAULT_PRIORITY)
#   10100 — DomainRoutingRule (fwmark + iproute-фолбэк «to <ip>/32»)
#   10150 — DscpRoutingRule (fwmark)
#   10200 — DeviceRoutingRule («from <ip>»)
MANAGED_PRIO_MIN = 10000
MANAGED_PRIO_MAX = 10299

# fwmark domain-правил: _mark_for() выдаёт 0x10000..0x1FFFF.
DOMAIN_MARK_MIN = 0x10000
DOMAIN_MARK_MAX = 0x1FFFF

SET_PREFIX = "awgr_"

_RULE_LINE = re.compile(r"^\s*(\d+):\s*(.*)$")


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


def _iface_exists(ifname: str) -> bool:
    rc, _o, _e = _run(["ip", "link", "show", "dev", ifname], timeout=5)
    return rc == 0


# ─────────────────────── что ДОЛЖНО существовать ─────────────────────

def _table_map() -> dict:
    """{ifname: table_id} — наши таблицы, как их раздал table_id_for()."""
    try:
        from core.config_manager import get_config_manager
        tm = get_config_manager().get("routing", "table_map", default={}) or {}
        if not isinstance(tm, dict):
            return {}
    except Exception:
        return {}
    out = {}
    for ifname, tid in tm.items():
        try:
            out[str(ifname)] = int(tid)
        except (TypeError, ValueError):
            continue
    return out


def _set_names_for_rule_id(rule_id: str) -> set:
    """Все имена set'ов, которые может занять одно domain-правило."""
    from core.routing import ipset_backend, nftset_backend
    names = set()
    for base in (ipset_backend.set_name_for(rule_id),
                 nftset_backend.set_name_for(rule_id)):
        names.add(base)
        names.add(base + "6")
    return names


def collect_expected() -> dict:
    """
    Артефакты, за которыми стоит живое правило из storage.

    Возвращает {"marks", "devices", "cidrs", "sets", "tables"}, где
    devices/cidrs — множества пар (адрес, table_id).
    """
    from core.routing import domain_rule, storage
    from core.routing.manager import table_id_for
    from core.routing.rules import (CidrRoutingRule, DeviceRoutingRule,
                                    DomainRoutingRule, DscpRoutingRule)

    marks, devices, cidrs, sets_, tables = set(), set(), set(), set(), set()

    rules = storage.load_rules()
    known_ids = set()
    for rule in rules:
        known_ids.add(rule.id)
        # set'ы бережём у ВСЕХ domain-правил, даже выключенных: их снимет
        # remove_rule, а sweep не должен обгонять пользователя, который
        # временно выключил маршрут и ждёт, что включение будет мгновенным.
        if isinstance(rule, DomainRoutingRule):
            sets_ |= _set_names_for_rule_id(rule.id)
        if not rule.enabled:
            continue
        try:
            table = table_id_for(rule.target_iface)
        except Exception:
            continue
        tables.add(table)
        if isinstance(rule, DomainRoutingRule):
            marks.add(domain_rule._mark_for(rule.id))
        elif isinstance(rule, DscpRoutingRule):
            # fwmark DSCP-правила = id таблицы интерфейса (см. dscp_rule).
            marks.add(table)
        elif isinstance(rule, DeviceRoutingRule):
            if rule.source_ip:
                devices.add((rule.source_ip.strip(), table))
        elif isinstance(rule, CidrRoutingRule):
            for cidr, _fam in rule.cidr_families():
                cidrs.add((cidr, table))

    # iproute-фолбэк domain-правил кладёт по «to <ip>/32 lookup <table>»
    # на каждый разрезолвленный IP. Эти записи динамические — источник
    # истины по ним не rules, а domain_iproute-state.
    try:
        iproute_state = domain_rule._iproute_state_load()
    except Exception:
        iproute_state = {}
    for rule_id, entries in (iproute_state or {}).items():
        if rule_id not in known_ids:
            continue
        rule = storage.get_rule(rule_id)
        if rule is None or not rule.enabled:
            continue
        try:
            table = table_id_for(rule.target_iface)
        except Exception:
            continue
        for entry in entries or []:
            if isinstance(entry, (list, tuple)) and entry:
                cidrs.add((str(entry[0]), table))

    return {"marks": marks, "devices": devices, "cidrs": cidrs,
            "sets": sets_, "tables": tables}


# ─────────────────────── разбор `ip rule show` ───────────────────────

def _parse_ip_rules(family: str) -> list:
    """
    `ip -4|-6 rule show` → список словарей. Строки, где встречаются
    неизвестные нам селекторы (iif/oif/suppress_prefixlength/…),
    помечаются `foreign=True` — их sweep не трогает никогда.
    """
    rc, out, _e = _run(["ip", family, "rule", "show"], timeout=5)
    if rc != 0:
        return []
    known = {"from", "to", "fwmark", "lookup", "table"}
    parsed = []
    for line in out.splitlines():
        m = _RULE_LINE.match(line)
        if not m:
            continue
        entry = {"priority": int(m.group(1)), "family": family,
                 "src": "", "dst": "", "fwmark": None, "table": "",
                 "foreign": False}
        tokens = m.group(2).split()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            val = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok not in known:
                entry["foreign"] = True
                break
            if tok == "from":
                entry["src"] = val
            elif tok == "to":
                entry["dst"] = val
            elif tok == "fwmark":
                try:
                    entry["fwmark"] = int(val, 0)
                except ValueError:
                    entry["foreign"] = True
                    break
            else:                      # lookup | table
                entry["table"] = val
            i += 2
        parsed.append(entry)
    return parsed


def _del_argv(entry: dict) -> list:
    """Команда точечного удаления разобранного `ip rule`."""
    argv = ["ip", entry["family"], "rule", "del",
            "priority", str(entry["priority"])]
    if entry["src"] and entry["src"] != "all":
        argv += ["from", entry["src"]]
    if entry["dst"] and entry["dst"] != "all":
        argv += ["to", entry["dst"]]
    if entry["fwmark"] is not None:
        argv += ["fwmark", str(entry["fwmark"])]
    argv += ["lookup", str(entry["table"])]
    return argv


def _describe(entry: dict) -> str:
    bits = []
    if entry["src"] and entry["src"] != "all":
        bits.append("from %s" % entry["src"])
    if entry["dst"] and entry["dst"] != "all":
        bits.append("to %s" % entry["dst"])
    if entry["fwmark"] is not None:
        bits.append("fwmark 0x%x" % entry["fwmark"])
    return "%s %d: %s lookup %s" % (entry["family"], entry["priority"],
                                    " ".join(bits) or "all", entry["table"])


def _is_orphan_rule(entry: dict, expected: dict, our_tables: set) -> bool:
    """Наша ли это запись и стоит ли за ней живое правило."""
    if entry["foreign"]:
        return False
    if not (MANAGED_PRIO_MIN <= entry["priority"] <= MANAGED_PRIO_MAX):
        return False
    try:
        table = int(entry["table"])
    except (TypeError, ValueError):
        return False              # main/local/default и прочие именованные
    if table not in our_tables:
        return False              # чужая таблица — не наше дело

    if entry["fwmark"] is not None:
        mark = entry["fwmark"]
        ours = (DOMAIN_MARK_MIN <= mark <= DOMAIN_MARK_MAX
                or mark in our_tables)
        if not ours:
            return False
        return mark not in expected["marks"]

    if entry["src"] and entry["src"] != "all":
        return (entry["src"], table) not in expected["devices"]

    if entry["dst"] and entry["dst"] != "all":
        return (entry["dst"], table) not in expected["cidrs"]

    # `from all lookup <наша таблица>` без селекторов — такого мы не
    # ставим никогда, а работает оно как безусловный перехват.
    return True


# ─────────────────────── ipset / nftset ──────────────────────────────

def _list_ipsets() -> list:
    rc, out, _e = _run(["ipset", "list", "-n"], timeout=10)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines()
            if ln.strip().startswith(SET_PREFIX)]


def _list_nftsets() -> list:
    from core.routing.nftset_backend import TABLE_NAME
    rc, out, _e = _run(["nft", "list", "table", "inet", TABLE_NAME],
                       timeout=10)
    if rc != 0:
        return []
    names = []
    for line in out.splitlines():
        m = re.match(r"\s*set\s+(\S+)\s*\{", line)
        if m and m.group(1).startswith(SET_PREFIX):
            names.append(m.group(1))
    return names


def _drop_ipset_refs(name: str) -> None:
    """Снять iptables-правила, ссылающиеся на set (иначе destroy не даст)."""
    from core.routing.ipset_backend import OUTPUT_CHAIN, PREROUTING_CHAIN
    for cmd in ("iptables", "ip6tables"):
        for chain in (PREROUTING_CHAIN, OUTPUT_CHAIN):
            rc, out, _e = _run([cmd, "-t", "mangle", "-S", chain], timeout=10)
            if rc != 0:
                continue
            for line in out.splitlines():
                if "--match-set %s " % name not in line + " ":
                    continue
                args = line.split()
                if not args or args[0] != "-A":
                    continue
                _run([cmd, "-t", "mangle", "-D"] + args[1:], timeout=10)


def _drop_nftset_refs(name: str) -> None:
    """Снять nft-правила, ссылающиеся на set (по handle)."""
    from core.routing.nftset_backend import TABLE_NAME
    needle = "@%s " % name
    for chain in ("prerouting", "output", "forward", "postrouting"):
        rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                            TABLE_NAME, chain], timeout=10)
        if rc != 0:
            continue
        for line in out.splitlines():
            if needle not in line + " " or "handle" not in line:
                continue
            parts = line.rsplit("handle", 1)
            if len(parts) != 2:
                continue
            handle = parts[1].strip().split()[0]
            if handle.isdigit():
                _run(["nft", "delete", "rule", "inet", TABLE_NAME,
                      chain, "handle", handle], timeout=10)


# ─────────────────────────── sweep ───────────────────────────────────

def sweep(dry_run: bool = False) -> dict:
    """
    Найти (и, если не dry_run, снять) артефакты без живого правила.

    Возвращает {"ok", "ip_rules", "sets", "tables", "errors"}, где
    каждый список — человекочитаемые описания того, что нашли/сняли.
    """
    expected = collect_expected()
    table_map = _table_map()
    our_tables = set(table_map.values())

    found_rules, found_sets, found_tables, errors = [], [], [], []

    # 1) ip rule
    for family in ("-4", "-6"):
        for entry in _parse_ip_rules(family):
            if not _is_orphan_rule(entry, expected, our_tables):
                continue
            desc = _describe(entry)
            found_rules.append(desc)
            if dry_run:
                continue
            rc, _o, err = _run(_del_argv(entry), timeout=5)
            if rc != 0:
                errors.append("ip rule del (%s): %s" % (desc, err.strip()))

    # 2) ipset / nftset
    for kind, names in (("ipset", _list_ipsets()),
                        ("nftset", _list_nftsets())):
        for name in names:
            if name in expected["sets"]:
                continue
            found_sets.append("%s %s" % (kind, name))
            if dry_run:
                continue
            if kind == "ipset":
                from core.routing import ipset_backend
                _drop_ipset_refs(name)
                res = ipset_backend.destroy_set(name)
            else:
                from core.routing import nftset_backend
                _drop_nftset_refs(name)
                res = nftset_backend.destroy_set(name)
            if not res.get("ok"):
                errors.append("%s destroy %s: %s"
                              % (kind, name, res.get("error")))

    # 3) наши таблицы маршрутизации, чей интерфейс исчез
    for ifname, table in sorted(table_map.items()):
        if _iface_exists(ifname):
            continue
        empty = True
        for family in ("-4", "-6"):
            rc, out, _e = _run(["ip", family, "route", "show", "table",
                                str(table)], timeout=5)
            if rc == 0 and (out or "").strip():
                empty = False
        if empty:
            continue
        found_tables.append("table %d (%s)" % (table, ifname))
        if dry_run:
            continue
        for family in ("-4", "-6"):
            _run(["ip", family, "route", "flush", "table", str(table)],
                 timeout=5)

    total = len(found_rules) + len(found_sets) + len(found_tables)
    if total:
        log.info("routing sweep%s: ip rule %d, set %d, таблиц %d"
                 % (" (dry-run)" if dry_run else "", len(found_rules),
                    len(found_sets), len(found_tables)),
                 source="routing")

    return {
        "ok":       not errors,
        "dry_run":  dry_run,
        "ip_rules": found_rules,
        "sets":     found_sets,
        "tables":   found_tables,
        "total":    total,
        "errors":   errors,
    }
