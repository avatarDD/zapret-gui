# core/routing/doctor.py
"""
Пошаговая диагностика маршрутизации ПРЯМО на устройстве: где именно
рвётся «правило создано, а трафик мимо туннеля».

Для каждого включённого правила проверяется вся цепочка:
  интерфейс поднят → default-route в его таблице → (set-путь) ipset
  существует и наполнен → mark-правила в mangle стоят и их счётчики
  растут → `ip rule fwmark` на месте → masquerade повешен → контрольный
  резолв первого домена → его IP в set'е → `ip route get <ip> mark <m>`
  ведёт в туннель. Для iproute/CIDR/device-правил — их собственные звенья
  (`ip rule to/from`, покрытие резолвленного IP).

Смысл: отчёты вида «без выбора устройства не работает» нельзя чинить
вслепую — doctor показывает первый ✗ в цепочке.

CLI (работает даже без bottle):
    python3 -m core.routing.doctor          # человекочитаемо
    python3 -m core.routing.doctor --json   # машиночитаемо
API: GET /api/routing/doctor (api/routing.py).
"""

import json
import sys

from core.log_buffer import log


def _run(args, timeout=5):
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", str(e)


def _check(name, ok, details=""):
    return {"name": name, "ok": bool(ok), "details": details}


# ─────────────────────── примитивы проверок ──────────────────────────

def _ipset_count(set_name: str):
    """Число записей в ipset или None, если set не существует."""
    rc, out, _e = _run(["ipset", "list", set_name])
    if rc != 0:
        return None
    for line in out.splitlines():
        if line.lower().startswith("number of entries"):
            try:
                return int(line.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                break
    # Фолбэк: считаем строки после "Members:"
    members = False
    n = 0
    for line in out.splitlines():
        if members and line.strip():
            n += 1
        if line.strip().lower() == "members:":
            members = True
    return n


def _mangle_mark_counters(set_name: str, family: str = "v4"):
    """
    (found, packets): стоят ли mark-правила `--match-set <set> dst` в
    наших mangle-цепочках и сколько пакетов они уже пометили.
    packets > 0 — маркировка реально срабатывает на живом трафике.
    """
    from core.routing import ipset_backend
    cmd = "iptables" if family == "v4" else "ip6tables"
    found = False
    packets = 0
    for chain in (ipset_backend.PREROUTING_CHAIN,
                  ipset_backend.OUTPUT_CHAIN):
        rc, out, _e = _run([cmd, "-t", "mangle", "-L", chain,
                            "-v", "-n", "-x"])
        if rc != 0:
            continue
        for line in out.splitlines():
            if set_name in line and "match-set" in line:
                found = True
                try:
                    packets += int(line.split()[0])
                except (ValueError, IndexError):
                    pass
    return found, packets


def _ip_rule_lines(family: str = "-4"):
    rc, out, _e = _run(["ip", family, "rule"])
    return out.splitlines() if rc == 0 else []


def _has_fwmark_rule(mark: int, table: int, family: str = "-4") -> bool:
    hexmark = "0x%x" % mark
    for line in _ip_rule_lines(family):
        if "fwmark" in line and "lookup %d" % table in line \
                and (hexmark in line or " %d " % mark in line):
            return True
    return False


def _table_default_iface(table: int, family: str = "-4"):
    """Интерфейс default-route в таблице или ''."""
    rc, out, _e = _run(["ip", family, "route", "show", "table",
                        str(table), "default"])
    if rc != 0:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            i = parts.index("dev")
            if i + 1 < len(parts):
                return parts[i + 1]
    return ""


def _masquerade_present(ifname: str, family: str = "v4") -> bool:
    from core.routing import ipset_backend, nftset_backend
    # masquerade.ensure_for_iface ставит nft-правило, если nft есть, —
    # иначе iptables. Проверяем оба места.
    rc, out, _e = _run(["nft", "list", "chain", "inet",
                        nftset_backend.TABLE_NAME, "postrouting"])
    if rc == 0 and ('oifname "%s" masquerade' % ifname in out
                    or "oifname %s masquerade" % ifname in out):
        return True
    cmd = "iptables" if family == "v4" else "ip6tables"
    rc, out, _e = _run([cmd, "-t", "nat", "-S", ipset_backend.NAT_CHAIN])
    return rc == 0 and ("-o %s -j MASQUERADE" % ifname) in out


def _route_get_dev(ip: str, mark: int = None):
    """Через какой iface ядро отправит пакет к ip (с меткой mark)."""
    args = ["ip", "route", "get", ip]
    if mark is not None:
        args += ["mark", str(mark)]
    rc, out, _e = _run(args)
    if rc != 0:
        return ""
    parts = (out.splitlines() or [""])[0].split()
    if "dev" in parts:
        i = parts.index("dev")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _ipset_test(set_name: str, ip: str) -> bool:
    rc, _o, _e = _run(["ipset", "test", set_name, ip])
    return rc == 0


def _nft_set_count(set_name: str):
    """Число элементов nft-набора нашей таблицы или None, если его нет."""
    from core.routing import nftset_backend
    rc, out, _e = _run(["nft", "list", "set", "inet",
                        nftset_backend.TABLE_NAME, set_name])
    if rc != 0:
        return None
    i = out.find("elements = {")
    if i < 0:
        return 0
    body = out[i + len("elements = {"):]
    body = body[:body.find("}")] if "}" in body else body
    return len([x for x in body.replace("\n", " ").split(",") if x.strip()])


def _nft_mark_present(set_name: str) -> bool:
    """Стоят ли mark-правила `daddr @<set>` в нашей nft-таблице."""
    from core.routing import nftset_backend
    rc, out, _e = _run(["nft", "list", "table", "inet",
                        nftset_backend.TABLE_NAME])
    return rc == 0 and ("@%s " % set_name) in out


def _nft_set_test(set_name: str, ip: str) -> bool:
    from core.routing import nftset_backend
    rc, _o, _e = _run(["nft", "get", "element", "inet",
                       nftset_backend.TABLE_NAME, set_name, "{ %s }" % ip])
    return rc == 0


def _probe_xt_set():
    """
    (ok, details): работает ли `iptables -m set` С ЯДРОМ (модуль xt_set).

    Коварный случай Keenetic: userspace-ipset и ip_set в ядре есть
    (наборы создаются), а матчер xt_set для iptables в прошивку не
    собран — тогда mark-правила set-пути не встают и весь путь мёртв.
    Проба в отдельной нигде не вызываемой цепочке — трафик не трогаем.
    """
    set_name = "awgr_doctor_probe"
    chain = "AWGR_DOCTOR"
    rc, _o, err = _run(["ipset", "create", set_name, "hash:ip", "-exist"])
    if rc != 0:
        return False, "ipset create: %s" % err.strip()
    try:
        _run(["iptables", "-t", "mangle", "-N", chain])
        rc, _o, err = _run(["iptables", "-t", "mangle", "-A", chain,
                            "-m", "set", "--match-set", set_name, "dst",
                            "-j", "RETURN"])
        if rc == 0:
            return True, "работает — set-путь доступен"
        return False, (err.strip() or "iptables -m set не работает") + \
            " (нет xt_set в ядре? домены пойдут iproute-фолбэком)"
    finally:
        _run(["iptables", "-t", "mangle", "-F", chain])
        _run(["iptables", "-t", "mangle", "-X", chain])
        _run(["ipset", "destroy", set_name])


# ─────────────────────── диагностика правил ─────────────────────────

def _diagnose_domain_rule(rule, sets_state, iproute_state) -> list:
    from core.routing import domain_rule
    checks = []
    ifname = rule.target_iface
    table = domain_rule._table_id_for(ifname)
    mark = domain_rule._mark_for(rule.id)

    if rule.id in sets_state:
        kind = sets_state[rule.id]
        checks.append(_check("бэкенд", True, "%s без dnsmasq" % kind))
        set_v4 = domain_rule._set_name_for(rule.id, kind)
        if kind == "nftset":
            # nft: свои примитивы. Счётчиков в наших правилах нет —
            # звено «маркировка видит трафик» здесь не проверить.
            cnt = _nft_set_count(set_v4)
            checks.append(_check(
                "nft set %s" % set_v4, cnt is not None and cnt > 0,
                "нет такого set'а" if cnt is None else "%d записей" % cnt))
            found = _nft_mark_present(set_v4)
            pkts = 0
            checks.append(_check(
                "mark-правила в nft", found,
                "есть" if found else "нет — маркировка не срабатывает"))
        else:
            cnt = _ipset_count(set_v4)
            checks.append(_check(
                "ipset %s" % set_v4, cnt is not None and cnt > 0,
                "нет такого set'а" if cnt is None else "%d IP" % cnt))
            found, pkts = _mangle_mark_counters(set_v4)
            checks.append(_check(
                "mark-правила в mangle", found,
                ("есть, помечено пакетов: %d" % pkts) if found
                else "нет — маркировка не срабатывает"))
        if found and kind != "nftset":
            checks.append(_check(
                "маркировка видит трафик", pkts > 0,
                "%d пакетов" % pkts if pkts > 0 else
                "0 пакетов — трафик к IP из set'а не идёт "
                "(клиент ходит на другие IP: DNS/CDN?)"))
        checks.append(_check(
            "ip rule fwmark → table %d" % table,
            _has_fwmark_rule(mark, table),
            "mark=0x%x" % mark))
    elif rule.id in iproute_state:
        entries = iproute_state.get(rule.id) or []
        checks.append(_check("бэкенд", True,
                             "iproute (%d IP в state)" % len(entries)))
        live = sum(1 for line in _ip_rule_lines("-4")
                   if "lookup %d" % table in line)
        checks.append(_check(
            "ip rule → table %d" % table, live > 0,
            "%d правил в policy-db" % live))
    else:
        checks.append(_check("бэкенд", True,
                             "набор наполняет dnsmasq (nftset/ipset)"
                             " или NDMS"))
        # Набор и fwmark-правило ставит apply_domain_rule и в dnsmasq-пути —
        # без этих строк отчёт молчал, на каком звене правило не легло.
        try:
            _backend, kind = domain_rule._detect_backend()
        except Exception:                                # noqa: BLE001
            kind = ""
        if kind == "nftset":
            set_v4 = domain_rule._set_name_for(rule.id, kind)
            cnt = _nft_set_count(set_v4)
            checks.append(_check(
                "nft set %s" % set_v4, cnt is not None and cnt > 0,
                "нет такого set'а" if cnt is None else "%d записей" % cnt))
        elif kind == "ipset":
            set_v4 = domain_rule._set_name_for(rule.id, kind)
            cnt = _ipset_count(set_v4)
            checks.append(_check(
                "ipset %s" % set_v4, cnt is not None and cnt > 0,
                "нет такого set'а" if cnt is None else "%d IP" % cnt))
        if kind:
            checks.append(_check(
                "ip rule fwmark → table %d" % table,
                _has_fwmark_rule(mark, table),
                "mark=0x%x" % mark))

    dev = _table_default_iface(table)
    checks.append(_check(
        "default-route в table %d" % table, dev == ifname,
        ("dev %s" % dev) if dev else "нет default — трафик некуда слать"))
    mq = _masquerade_present(ifname)
    checks.append(_check("masquerade на %s" % ifname, mq,
                         "" if mq else
                         "нет — пакеты уйдут с чужим src и сервер их дропнет"
                         " (нажмите «Переприменить и сбросить лишнее»)"))
    fw = _forward_check(ifname)
    if fw:
        checks.append(fw)

    # Алиас, который не скачался, молча выпадает из набора: geoip:telegram
    # с 404 оставлял приложение Telegram мимо туннеля (issue #404/#386).
    from core.routing import alias_resolver
    try:
        failed = alias_resolver.expand_domains(
            rule.domains or []).get("aliases_failed") or []
    except Exception:                                    # noqa: BLE001
        failed = []
    for a in failed:
        checks.append(_check(
            "%s:%s" % (a.get("kind"), a.get("name")), False,
            "список не скачался — его адреса в набор не попали"))

    # Набор, в котором ищем адреса: свой (без dnsmasq) или dnsmasq-путь.
    set_kind = sets_state.get(rule.id) or ""
    if not set_kind and rule.id not in iproute_state:
        try:
            set_kind = domain_rule._detect_backend()[1]
        except Exception:                                # noqa: BLE001
            set_kind = ""
    set_test = _nft_set_test if set_kind == "nftset" else _ipset_test
    set_name = (domain_rule._set_name_for(rule.id, set_kind)
                if set_kind else "")

    # Контрольный прогон: домен, который точно должен резолвиться.
    domains, cidrs = domain_rule._expand_rule(rule)
    probe, ips, tried = _pick_probe(rule, domains)
    if tried:
        if not ips:
            checks.append(_check("резолв %s" % ", ".join(tried), False,
                                 "ни один домен не резолвится с роутера"))
        else:
            ip = ips[0]
            if set_name:
                in_set = set_test(set_name, ip)
                checks.append(_check(
                    "%s (%s) в set'е" % (probe, ip), in_set,
                    "" if in_set else "IP не в set — рефрешер/prepopulate"
                                      " не отработал"))
                via = _route_get_dev(ip, mark=mark)
            else:
                via = _route_get_dev(ip)
            checks.append(_check(
                "route get %s → %s" % (ip, ifname), via == ifname,
                "уходит через %s" % (via or "?")))
    # geoip-сети лежат в том же наборе: проверяем первую v4-сеть.
    v4 = [c for c in cidrs if ":" not in c]
    if v4 and set_name:
        ip = v4[0].split("/", 1)[0]
        in_set = set_test(set_name, ip)
        checks.append(_check(
            "%s (geoip) в set'е" % v4[0], in_set,
            "" if in_set else "сети geoip не в set — переприменить правило"))
    return checks


_PROBE_TRIES = 4


def _pick_probe(rule, domains):
    """
    (домен, его IP, что пробовали) для контрольного прогона правила.

    Раньше брался первый домен развёрнутого списка, а у geosite:telegram
    это cdn-telegram.org, который не резолвится вовсе, — отчёт рисовал ✗
    там, где правило в порядке (issue #386). Порядок: явные домены
    правила, известный домен категории (GEOSITE_PROBES), остальные из
    развёрнутого списка; первый резолвящийся из нескольких.
    """
    from core.routing import alias_resolver, domain_rule
    explicit, cats = [], []
    for token in rule.domains or []:
        kind, name = alias_resolver.parse_alias(str(token))
        if kind == "geosite":
            cats.append(name)
        elif not kind and "/" not in str(token):
            explicit.append(str(token).strip().lower())
    cand = []
    for d in explicit + [alias_resolver.probe_domain_for(cats)] + \
            list(domains or []):
        if d and d not in cand and "*" not in d:
            cand.append(d)
    tried = []
    for d in cand[:_PROBE_TRIES]:
        tried.append(d)
        ips = domain_rule._resolve_ips(d, "v4")
        if ips:
            return d, ips, tried
    return "", [], tried


def _diagnose_cidr_rule(rule) -> list:
    from core.routing.manager import table_id_for
    checks = []
    table = table_id_for(rule.target_iface)
    lines = _ip_rule_lines("-4") + _ip_rule_lines("-6")
    want = [c for c, _f in rule.cidr_families()]
    # Считаем только `to <сеть>` этого правила: в ту же таблицу ведут и
    # fwmark-правила доменного маршрута, и отчёт писал «12 правил
    # (ожидалось до 10)» там, где всё в порядке.
    import ipaddress

    def _net(text):
        try:
            return ipaddress.ip_network(text.strip(), strict=False)
        except (ValueError, TypeError):
            return None

    want_set = {_net(c) for c in want} - {None}
    live = 0
    for line in lines:
        parts = line.split()
        if "lookup" not in parts or "to" not in parts:
            continue
        i, j = parts.index("to"), parts.index("lookup")
        if (i + 1 < len(parts) and j + 1 < len(parts)
                and parts[j + 1] == str(table)
                and _net(parts[i + 1]) in want_set):
            live += 1
    checks.append(_check(
        "ip rule to → table %d" % table, live > 0,
        "%d из %d сетей" % (live, len(want))))
    dev = _table_default_iface(table)
    checks.append(_check(
        "default-route в table %d" % table, dev == rule.target_iface,
        ("dev %s" % dev) if dev else "нет default"))
    if live:
        fw = _forward_check(rule.target_iface)
        if fw:
            checks.append(fw)
    if want:
        probe_ip = want[0].split("/")[0]
        via = _route_get_dev(probe_ip)
        checks.append(_check(
            "route get %s → %s" % (probe_ip, rule.target_iface),
            via == rule.target_iface, "уходит через %s" % (via or "?")))
    return checks


def _forward_accept_present(ifname: str, family: str = "v4") -> bool:
    """Есть ли ACCEPT форварда через ifname (FORWARD-политика обычно DROP)."""
    cmd = "iptables" if family == "v4" else "ip6tables"
    rc, out, _e = _run([cmd, "-t", "filter", "-S", "FORWARD"])
    if rc != 0:
        return False
    return ("-o %s -j ACCEPT" % ifname) in out


def _forward_check(ifname: str, family: str = "v4"):
    """
    Звено «firewall пропускает форвард LAN → туннель» или None, если
    проверить нечем.

    На OpenWrt fw4 интерфейс без зоны получает reject в forward_lan, и
    наш accept в своей таблице этого не отменяет: туннель поднят,
    маршрут стоит, `route get` показывает туннель — а трафик устройств
    не проходит (issue #386). На iptables смотрим ACCEPT в FORWARD.
    """
    from core.routing import nftset_backend
    try:
        from core.routing.manager import _is_ndms_native_iface
        if _is_ndms_native_iface(ifname):
            return None                # форвард нативных ведёт сам NDMS
    except Exception:                                    # noqa: BLE001
        pass
    if nftset_backend.fw4_present():
        ok = nftset_backend.fw4_forward_allowed(ifname)
        return _check(
            "fw4 пропускает LAN → %s" % ifname, ok,
            "" if ok else
            "нет — у интерфейса нет зоны fw4, и форвард из LAN"
            " отклоняется (с самого роутера при этом работает). Нажмите"
            " «Переприменить и сбросить лишнее» или добавьте %s в зону"
            " wan в LuCI" % ifname)
    rc, _o, _e = _run(["iptables" if family == "v4" else "ip6tables",
                       "-t", "filter", "-S", "FORWARD"])
    if rc != 0:
        return None
    fw = _forward_accept_present(ifname, family)
    return _check(
        "форвард LAN→%s разрешён" % ifname, fw,
        "" if fw else "нет ACCEPT в FORWARD — трафик С УСТРОЙСТВ режется"
                      " (с самого роутера при этом работает)")


def _shadowing_rule(src: str, table: int, priority: int, family: str = "-4"):
    """
    Правило ВЫШЕ нашего (меньший приоритет), которое перехватит трафик
    устройства раньше и уведёт его мимо туннеля.

    Классика на роутерах: прошивка (ndm/multi-wan) ставит свои `ip rule`
    с приоритетами 0..9999 — наши 10200 до них не доживают, и «правило на
    месте, а трафик идёт через провайдера».
    """
    for line in _ip_rule_lines(family):
        parts = line.split(":", 1)
        if len(parts) != 2 or not parts[0].strip().isdigit():
            continue
        prio = int(parts[0].strip())
        body = parts[1].strip()
        if prio >= priority:
            continue
        if body.startswith("from all lookup local"):
            continue                       # local — обязателен и безобиден
        # Нас интересует то, что может поймать пакет этого устройства:
        # `from all …` или `from <наша подсеть/ip> …`, ведущее НЕ в нашу
        # таблицу.
        if "lookup %d" % table in body:
            continue                       # ведёт туда же, куда и мы
        if " dport " in body or " sport " in body:
            continue                       # по портам — забирает не всё
        if body.startswith("from all") or ("from %s" % src) in body:
            return "%d: %s" % (prio, body)
    return ""


def _route_get_from(dst: str, src: str):
    """Через какой iface уйдёт пакет ОТ src К dst (как у форварда)."""
    rc, out, _e = _run(["ip", "route", "get", dst, "from", src])
    if rc != 0:
        # Без iif ядро может отказать для чужого src — пробуем как есть.
        return _route_get_dev(dst)
    parts = (out.splitlines() or [""])[0].split()
    if "dev" in parts:
        i = parts.index("dev")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _diagnose_device_rule(rule) -> list:
    """
    Полная цепочка device-правила, а не только факт наличия `ip rule`.

    Раньше здесь проверялось единственное звено — что правило есть в
    policy-db. Но «весь трафик с устройства в туннель» рвётся ещё в трёх
    местах, и все они молчаливые: пустая таблица маршрутизации, снятый
    masquerade (сервер дропает пакеты с LAN-src) и правило прошивки
    ВЫШЕ нашего по приоритету. Отчёт должен показывать первый ✗, иначе
    чинить приходится вслепую.
    """
    from core.routing.device_rule import DEVICE_PRIORITY, _table_id_for
    checks = []
    ifname = rule.target_iface
    table = _table_id_for(ifname)
    src = (rule.source_ip or "").strip()
    v6 = ":" in src
    family = "-6" if v6 else "-4"
    fam = "v6" if v6 else "v4"

    # 1. Само правило в policy-db.
    src_short = src.split("/")[0]
    found = any(("from %s" % src_short) in line and "lookup %d" % table in line
                for line in _ip_rule_lines(family))
    checks.append(_check("ip rule from %s" % src, found,
                         "table %d" % table if found else
                         "нет в policy-db — правило не применено"
                         " (интерфейс лежал в момент apply?)"))

    # 2. Таблице есть куда слать.
    dev = _table_default_iface(table, family)
    checks.append(_check(
        "default-route в table %d" % table, dev == ifname,
        ("dev %s" % dev) if dev else
        "нет default — пакет попадёт в пустую таблицу и уйдёт по main"
        " (то есть через провайдера)"))

    # 3. MASQUERADE: без него сервер дропнет пакеты с LAN-src.
    mq = _masquerade_present(ifname, fam)
    checks.append(_check(
        "masquerade на %s" % ifname, mq,
        "" if mq else "нет — пакеты уйдут с адресом устройства (192.168.x.y),"
                      " и сервер туннеля их отбросит"))

    # 4. FORWARD-ACCEPT: политика FORWARD на роутерах — DROP, на
    #    OpenWrt fw4 — reject для интерфейса без зоны.
    fw = _forward_check(ifname, fam)
    if fw:
        checks.append(fw)

    # 5. Куда уходит трафик, пока туннель перезапускается.
    #
    # Это и есть «работает нестабильно, на 2ip то туннель, то провайдер»:
    # watchdog кладёт интерфейс, ядро выкидывает его маршруты, таблица
    # пустеет — и policy-db идёт дальше, до main.
    try:
        from core.routing import killswitch
        ks = killswitch.status(table, family)
        checks.append(_check(
            "kill-switch (не выпускать мимо туннеля)",
            True,
            "включён — пока туннель лежит, трафик устройства дропается"
            if ks["present"] else
            "выключен: пока туннель перезапускается, трафик устройства"
            " уходит через провайдера (включается на странице"
            " «Маршрутизация»)"))
    except Exception:
        pass

    # 6. Не перебивает ли нас правило прошивки.
    shadow = _shadowing_rule(src_short, table, DEVICE_PRIORITY, family)
    checks.append(_check(
        "нет правила выше нашего", not shadow,
        "" if not shadow else
        "«%s» стоит выше (приоритет < %d) и уводит трафик раньше"
        % (shadow, DEVICE_PRIORITY)))

    # 6a. Правило на ПОДСЕТЬ без исключений = роутер уехал в туннель.
    from core.routing.device_rule import (LOCAL_EXEMPT_PRIORITY, _is_subnet,
                                          _exempt_targets)
    if _is_subnet(src):
        nets, own = _exempt_targets(src, family)
        lines = _ip_rule_lines(family)
        missing = [n for n in nets
                   if not any(("from %s" % src) in ln and ("to %s" % n) in ln
                              and "lookup main" in ln for ln in lines)]
        checks.append(_check(
            "локальная сеть не уходит в туннель", not missing,
            "" if not missing else
            "нет исключений (приоритет %d) для %s — трафик внутри LAN и"
            " ответы роутера уедут в туннель, роутер пропадёт из сети"
            % (LOCAL_EXEMPT_PRIORITY, ", ".join(missing))))
        if own:
            miss_self = [a for a in own
                         if not any(("from %s" % a.split("/")[0]) in ln
                                    and "lookup main" in ln for ln in lines)]
            checks.append(_check(
                "адреса роутера вне правила", not miss_self,
                "" if not miss_self else
                "нет исключения для %s — собственный трафик роутера уходит"
                " в туннель" % ", ".join(miss_self)))

    # 7. Контрольный вопрос ядру: куда реально уйдёт пакет устройства.
    if found and not v6:
        via = _route_get_from("1.1.1.1", src_short)
        checks.append(_check(
            "пакет от %s уходит в %s" % (src_short, ifname), via == ifname,
            "ядро отправит через %s" % (via or "?")))
    return checks


def _singbox_tuns(iface: str, configs: list) -> list:
    """[(config, tun-inbound | None)] конфигов sing-box, у которых есть
    TUN-inbound с interface_name == iface. None — файл не прочитать."""
    out = []
    for c in configs:
        try:
            with open(c["path"], "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            # Битый файл не прячем: list_configs у такого tun_iface не
            # знает, поэтому смотрим только на те, где он был известен.
            if c.get("tun_iface") == iface:
                out.append((c, None))
            continue
        for ib in (cfg.get("inbounds") or []):
            if isinstance(ib, dict) and ib.get("type") == "tun" and \
                    (ib.get("interface_name") or "singbox-tun") == iface:
                out.append((c, ib))
                break
    return out


def _singbox_tun_checks(iface: str, configs: list) -> list:
    """
    Звено «внутри sing-box»: ip rule/ipset довели трафик до TUN, но что с
    ним делает движок. Ищем конфиг, чей TUN-inbound создаёт `iface`
    (запущенный — в первую очередь: по умолчанию у всех конфигов
    `singbox-tun`), и проверяем, что он запущен и что стек пропустит TCP:
    system (и mixed — TCP у него тоже через системный стек) без auto_route
    TCP не перехватывает — UDP/DNS идут, а сайты и Telegram «не
    открываются, хотя ошибок нет» (issue #386). Нужен gvisor.
    """
    found = _singbox_tuns(iface, configs)
    if not found:
        return [_check("конфиг sing-box с TUN %s" % iface, False,
                       "ни в одном конфиге нет TUN-inbound с таким"
                       " interface_name")]
    found.sort(key=lambda x: not x[0].get("running"))
    c, tun = found[0]
    running = bool(c.get("running"))
    checks = [_check("конфиг sing-box «%s» запущен" % c["name"], running,
                     "" if running else
                     "остановлен — интерфейс есть, а трафик некому принять")]
    if tun is None:
        checks.append(_check("конфиг «%s»" % c["name"], False,
                             "не читается как JSON"))
        return checks
    stack = tun.get("stack") or "mixed"
    auto_route = bool(tun.get("auto_route"))
    bad = stack != "gvisor" and not auto_route
    checks.append(_check(
        "TUN-стек %s" % stack, not bad,
        ("без auto_route стек %s не пропускает TCP — открывается только"
         " то, что ходит по UDP. Пересоздайте TUN-инбаунд со стеком"
         " gvisor (sing-box → TUN-интерфейс)" % stack) if bad else
        ("auto_route" if auto_route else "")))
    return checks


# ─────────────────────── публичный API ──────────────────────────────

def diagnose() -> dict:
    """Полный отчёт по всем включённым правилам маршрутизации."""
    from core.routing import domain_rule, storage
    from core.routing.rules import (CidrRoutingRule, DeviceRoutingRule,
                                    DomainRoutingRule)

    sets_state = domain_rule._sets_state_load()
    iproute_state = domain_rule._iproute_state_load()

    env = []
    rc_nft, _o, _e = _run(["nft", "--version"], timeout=3)
    rc_ipset, _o, _e = _run(["ipset", "-v"], timeout=3)
    rc_ipt, _o, _e = _run(["iptables", "-V"], timeout=3)
    if rc_nft == 0:
        env.append(_check("nftables", True))
    if rc_ipset == 0 and rc_ipt == 0:
        env.append(_check("ipset", True))
        env.append(_check("iptables", True))
        xt_ok, xt_details = _probe_xt_set()
        env.append(_check("iptables -m set (xt_set)", xt_ok, xt_details))
    elif rc_nft == 0:
        # OpenWrt 22.03+ (fw4) и современный Linux: iptables/ipset нет и
        # не нужно — set'ы и метки ставятся в nftables. Раньше отчёт
        # рисовал тут два ✗ и уводил искать поломку не туда (issue #386).
        env.append(_check("ipset/iptables", True,
                          "нет — не нужны, работаем через nftables"))
    else:
        env.append(_check("ipset", rc_ipset == 0))
        env.append(_check("iptables", rc_ipt == 0,
                          "" if rc_ipt == 0 else
                          "нет ни iptables, ни nftables — доменам и"
                          " устройствам нечем ставить метки"))
    try:
        from core.routing import dnsmasq_integration
        st = dnsmasq_integration.DnsmasqIntegration().status()
        env.append(_check("dnsmasq", True,
                          "работает" if st.get("running")
                          else "нет (Keenetic: норм — set-путь/iproute)"))
        if st.get("running"):
            dn = dnsmasq_integration.DnsmasqIntegration()
            if not (dn.supports_nftset() or dn.supports_ipset()):
                # Штатный dnsmasq OpenWrt: домены маршрутизируются, но
                # их IP резолвит сам GUI (set-путь + рефрешер), живые
                # DNS-запросы клиентов в set не попадают.
                env.append(_check(
                    "dnsmasq nftset/ipset", True,
                    "не собран — IP доменов резолвит GUI сам; чтобы в"
                    " набор попадали и живые DNS-запросы клиентов,"
                    " поставьте dnsmasq-full"))
        # OpenWrt: dnsmasq в ujail видит только явно прокинутые пути.
        # Include на непрокинутый файл = dnsmasq не стартует вообще,
        # вместе с DHCP и DNS роутера (issue #332).
        if st.get("jailed") and st.get("include_present") \
                and not st.get("jail_mount_ok"):
            env.append(_check(
                "dnsmasq ujail", False,
                "%s подключён в dnsmasq.conf, но не прокинут внутрь ujail"
                " (addnmount в /etc/config/dhcp) — dnsmasq не сможет"
                " стартовать" % st.get("managed_file", "")))
    except Exception as e:
        env.append(_check("dnsmasq", True, "статус не снят: %s" % e))

    rules_report = []
    for rule in storage.load_rules():
        entry = {"id": rule.id, "type": rule.type_name,
                 "iface": rule.target_iface,
                 "enabled": bool(rule.enabled), "checks": []}
        if not rule.enabled:
            entry["checks"].append(_check("правило", True, "выключено"))
            rules_report.append(entry)
            continue
        try:
            from core.routing.domain_rule import _iface_exists
            up = _iface_exists(rule.target_iface)
            entry["checks"].append(_check(
                "интерфейс %s" % rule.target_iface, up,
                "" if up else "не поднят — правило в deferred"))
            if up:
                if isinstance(rule, DomainRoutingRule):
                    entry["checks"] += _diagnose_domain_rule(
                        rule, sets_state, iproute_state)
                elif isinstance(rule, CidrRoutingRule):
                    entry["checks"] += _diagnose_cidr_rule(rule)
                elif isinstance(rule, DeviceRoutingRule):
                    entry["checks"] += _diagnose_device_rule(rule)
        except Exception as e:
            entry["checks"].append(_check("диагностика", False,
                                          "упала: %s" % e))
        rules_report.append(entry)

    # Unified-маршруты: пользователь видит их, а работают — производные
    # низкоуровневые правила. Если derived-правило отсутствует (apply
    # вернул ошибку и manager откатил его из storage), маршрут «есть на
    # странице», но маршрутизировать нечего — ровно случай «правил
    # маршрутизации нет» при созданном маршруте.
    unified_report = []
    try:
        from core.unified import storage as ustorage
        from core.unified.applier import (_cidr_rule_id, _dev_rule_id,
                                          _dom_rule_id, _singbox_sees_all,
                                          active_method)
        from core.unified.model import parse_method
        known = {r.id for r in storage.load_rules()}
        sb_configs = None   # список конфигов sing-box — один раз на отчёт
        for route in ustorage.load_routes():
            entry = {"id": route.id, "name": route.name, "checks": []}
            checks = entry["checks"]
            if not route.enabled:
                checks.append(_check("маршрут", True, "выключен"))
                unified_report.append(entry)
                continue
            method = active_method(route)
            entry["method"] = method
            try:
                kind, _target = parse_method(method)
            except ValueError:
                kind = ""
            has_src = bool(route.devices) or route.dscp is not None
            # `warp` (usque/MASQUE) раскладывается applier'ом тем же путём,
            # что awg/singbox/mihomo (см. applier.apply_route), но здесь его
            # не было — и маршруты через WARP отчёт молча объявлял
            # «не требующими правил».
            if kind not in ("awg", "singbox", "mihomo", "warp"):
                if has_src:
                    # Устройства/DSCP работают ТОЛЬКО с туннельным методом.
                    # Маршрут выглядит настроенным, а трафик устройств идёт
                    # мимо — тот самый «на 2ip адрес провайдера».
                    checks.append(_check(
                        "метод", False,
                        "%s — но у маршрута выбраны устройства/DSCP, а они"
                        " работают только с туннелем (awg:/singbox:/mihomo:/"
                        "warp:). Сейчас трафик этих устройств никуда не"
                        " заворачивается" % (method or "?")))
                else:
                    checks.append(_check(
                        "метод", True,
                        "%s — производных правил не требует" % (method or "?")))
                unified_report.append(entry)
                continue
            if method != route.method:
                # Failover увёл маршрут на запасной метод: в списке маршрутов
                # виден основной, а работает другой.
                checks.append(_check(
                    "активный метод", True,
                    "%s (основной — %s, переключил failover)"
                    % (method, route.method)))
            resolved = route.destination.resolve()
            # geosite/geoip без нативной обработки в sing-box applier
            # разворачивает в то же производное domain-правило (см.
            # applier.apply_route). Без этой проверки маршрут «только
            # Telegram» из мастера не сверялся вовсе (issue #386).
            geo_in_rule = bool(resolved.get("geosite")
                               or resolved.get("geoip")) and not (
                kind == "singbox" and _singbox_sees_all(_target))
            if resolved.get("domains") or geo_in_rule:
                present = _dom_rule_id(route.id) in known
                checks.append(_check(
                    "производное domain-правило", present,
                    "" if present else
                    "НЕ создано — apply вернул ошибку и откатился "
                    "(см. лог routing); маршрутизировать нечего"))
            if resolved.get("cidrs"):
                present = _cidr_rule_id(route.id) in known
                checks.append(_check(
                    "производное cidr-правило", present,
                    "" if present else
                    "НЕ создано — apply вернул ошибку и откатился "
                    "(см. лог routing)"))
            for dev in (route.devices or []):
                present = _dev_rule_id(route.id, dev.get("ip", "")) in known
                checks.append(_check(
                    "device-правило %s" % dev.get("ip", "?"), present,
                    "" if present else "НЕ создано"))
            if not checks and not (resolved.get("geosite")
                                   or resolved.get("geoip")):
                checks.append(_check(
                    "назначение", False,
                    "пустое (нет доменов/CIDR/устройств)"))
            if kind == "singbox":
                try:
                    if sb_configs is None:
                        from core.singbox_manager import get_singbox_manager
                        sb_configs = get_singbox_manager().list_configs()
                    checks += _singbox_tun_checks(_target, sb_configs)
                except Exception as e:
                    checks.append(_check("sing-box TUN", True,
                                         "не проверен: %s" % e))
            unified_report.append(entry)
    except Exception as e:
        unified_report.append({
            "id": "unified", "name": "unified",
            "checks": [_check("сверка unified", False, "упала: %s" % e)]})

    ok = all(c["ok"] for r in rules_report for c in r["checks"]) \
        and all(c["ok"] for r in unified_report for c in r["checks"]) \
        and all(c["ok"] for c in env)
    return {"ok": ok, "env": env, "rules": rules_report,
            "unified": unified_report}


def render_text(report: dict) -> str:
    lines = ["── Окружение ──"]
    for c in report.get("env", []):
        lines.append(" %s %s%s" % ("✓" if c["ok"] else "✗", c["name"],
                                   (" — " + c["details"])
                                   if c.get("details") else ""))
    for r in report.get("unified", []):
        lines.append("── маршрут %s (%s%s) ──"
                     % (r.get("name") or r["id"], r["id"],
                        (" · " + r["method"]) if r.get("method") else ""))
        for c in r["checks"]:
            lines.append(" %s %s%s" % ("✓" if c["ok"] else "✗", c["name"],
                                       (" — " + c["details"])
                                       if c.get("details") else ""))
    for r in report.get("rules", []):
        lines.append("── %s (%s → %s) ──"
                     % (r["id"], r["type"], r["iface"]))
        for c in r["checks"]:
            lines.append(" %s %s%s" % ("✓" if c["ok"] else "✗", c["name"],
                                       (" — " + c["details"])
                                       if c.get("details") else ""))
    if not report.get("rules"):
        lines.append("низкоуровневых правил маршрутизации нет"
                     + (" — а unified-маршруты есть: производные правила"
                        " не создались (см. ✗ выше)"
                        if any(not c["ok"] for r in report.get("unified", [])
                               for c in r["checks"]) else ""))
    return "\n".join(lines)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    report = diagnose()
    if "--json" in argv:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_text(report))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
