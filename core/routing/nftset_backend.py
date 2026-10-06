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

def _output_chain_type_wrong(table_listing: str) -> bool:
    """
    True, если в выводе `nft list table inet awg_routing` цепочка output
    имеет старый тип `filter` вместо нужного `route`.

    type=filter в output НЕ триггерит реререйтинг пакета после изменения
    mark — ядро тихо отправляет пакет по уже выбранному (WAN) маршруту.
    Нужен type=route. До v0.19.21 цепочка создавалась как filter, поэтому
    у уже установленных пользователей таблицу надо мигрировать.
    """
    if "type filter hook output" in table_listing:
        return True
    return False


def _ensure_table_and_chains():
    """
    Гарантировать, что наша таблица и цепочки существуют.

    Цепочки:
      * prerouting — type filter hook prerouting priority mangle.
        Для forwarded-трафика mark выставляется ДО routing decision,
        так что type filter ok.
      * output — **type route** hook output priority mangle.
        Для локально-генерируемых пакетов routing decision уже
        принят к моменту OUTPUT mangle. Нужно `type route`, чтобы
        ядро пере-рутило пакет после изменения mark. Без этого
        пакет уходит через первый выбранный (WAN) маршрут с уже
        стоящим mark — fwmark-rule не успевает.
      * postrouting — type nat hook postrouting priority srcnat.
        Туда вешаем masquerade на исходящий AWG-iface, чтобы src
        не остался от WAN после переректа (см. ensure_iface_masquerade).

    Если таблица уже есть, но output создан со старым type=filter,
    мы её сносим целиком и пересоздаём с правильными типами. Часть
    rules при этом теряется — caller (apply_domain_rule) повторно
    разложит их через reapply-логику.
    """
    rc, out, _e = _run(["nft", "list", "table", "inet", TABLE_NAME])
    if rc == 0:
        if _output_chain_type_wrong(out):
            log.info("nft migration: пересоздаю awg_routing с"
                     " type=route hook output (was type=filter)",
                     source="routing")
            _run(["nft", "delete", "table", "inet", TABLE_NAME])
        else:
            chains_ok = ("chain prerouting" in out and
                         "chain output" in out and
                         "chain postrouting" in out and
                         "chain forward" in out)
            if chains_ok:
                return True

    cmds = [
        ["nft", "add", "table", "inet", TABLE_NAME],
        ["nft", "add", "chain", "inet", TABLE_NAME, "prerouting",
         "{ type filter hook prerouting priority mangle; policy accept; }"],
        ["nft", "add", "chain", "inet", TABLE_NAME, "output",
         "{ type route hook output priority mangle; policy accept; }"],
        ["nft", "add", "chain", "inet", TABLE_NAME, "postrouting",
         "{ type nat hook postrouting priority srcnat; policy accept; }"],
        # forward — чтобы разрешить форвардинг LAN↔AWG, если основной
        # firewall дропает форвард для незнакомого ему iface. priority
        # filter-1, чтобы наш accept отрабатывал раньше дефолтных правил.
        ["nft", "add", "chain", "inet", TABLE_NAME, "forward",
         "{ type filter hook forward priority -1; policy accept; }"],
    ]
    for c in cmds:
        rc, _o, err = _run(c)
        if rc != 0 and "exists" not in (err or "").lower():
            log.warning("nft init: %s: %s" % (" ".join(c), err.strip()),
                        source="routing")
    return True


def needs_migration() -> bool:
    """Публичная проверка: нужна ли миграция nft-таблицы (старый type=filter
    в output). Caller (domain_rule.apply_domain_rule) использует, чтобы
    после миграции переразложить ВСЕ enabled-правила, иначе пострадают
    соседние rules в той же таблице."""
    rc, out, _e = _run(["nft", "list", "table", "inet", TABLE_NAME])
    if rc != 0:
        return False
    return _output_chain_type_wrong(out)


# ────────────────────── set ops ─────────────────────────────────────

def create_set(name: str, family: str = "v4") -> dict:
    _ensure_table_and_chains()
    typ = "ipv6_addr" if family == "v6" else "ipv4_addr"

    rc, out, _e = _run(["nft", "list", "set", "inet", TABLE_NAME, name])
    if rc == 0:
        return {"ok": True, "created": False, "name": name}

    # flags timeout — записи с TTL из DNS истекают сами (см.
    # add_entry_argv); элементы без срока (CIDR geoip) живут вечно.
    rc, _o, err = _run(["nft", "add", "set", "inet", TABLE_NAME, name,
                        "{ type %s; flags interval, timeout; auto-merge; "
                        "size 1048576; }" % typ])
    if rc != 0 and "exists" not in (err or "").lower():
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "created": True, "name": name}


def set_has_timeout(name: str) -> bool:
    """Создан ли set с `flags timeout` (наборы прошлых версий — без)."""
    rc, out, _e = _run(["nft", "list", "set", "inet", TABLE_NAME, name])
    if rc != 0:
        return True             # нет set'а — create_set создаст правильный
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("flags "):
            return "timeout" in line
    return False


def recreate_with_timeout(name: str, family: str = "v4") -> dict:
    """Пересоздать set прошлой версии (без `flags timeout`).

    Флаги set'а в nft не меняются — только delete + add, а delete не
    пройдёт, пока на set ссылаются правила: их снимаем первыми (caller
    после этого ставит mark-правила заново)."""
    teardown_mark_rule(name)
    destroy_set(name)
    return create_set(name, family)


def add_entry_argv(name: str, ip: str, timeout: int = 0) -> list:
    """argv добавления IP; timeout>0 — запись истечёт сама."""
    elem = ip if not timeout or timeout <= 0 else \
        "%s timeout %ds" % (ip, int(timeout))
    return ["nft", "add", "element", "inet", TABLE_NAME, name,
            "{ %s }" % elem]


def add_entry(name: str, ip: str, timeout: int = 0) -> bool:
    rc, _o, err = _run(add_entry_argv(name, ip, timeout), timeout=5)
    if rc != 0 and timeout and "timeout" in (err or "").lower():
        # set без flags timeout (прошлая версия) — кладём бессрочно.
        rc, _o, err = _run(add_entry_argv(name, ip, 0), timeout=5)
    return rc == 0 or "exist" in (err or "").lower()


def destroy_set(name: str) -> dict:
    rc, _o, err = _run(["nft", "delete", "set", "inet", TABLE_NAME, name])
    if rc != 0 and "no such" not in (err or "").lower():
        return {"ok": False, "error": err.strip(), "name": name}
    return {"ok": True, "name": name}


def flush_set(name: str) -> dict:
    rc, _o, err = _run(["nft", "flush", "set", "inet", TABLE_NAME, name])
    return {"ok": rc == 0, "error": err.strip() if rc else "", "name": name}


# ────────────────────── mark rules ──────────────────────────────────
#
# Как в ipset_backend (см. там): своё поле бит метки, три правила на
# запись — connmark → mark (соединение не меняет маршрут, когда IP выпал
# из набора по таймауту), dst в наборе → mark, dst в наборе → connmark.
# Только ORIGINAL-направление. Цепочки общие с DSCP-правилами, поэтому
# правила записи помечены комментарием `awgr:<set>` и меняются одной
# транзакцией `nft -f` (удалить старые по handle + добавить новые).


def _comment(set_name: str) -> str:
    return "awgr:%s" % set_name


def entry_rules(set_name: str, mark: int, family: str = "v4") -> list:
    """Тексты правил одной записи (без `add rule inet T chain`). Чистая."""
    from core.routing import marks as _marks
    daddr = "ip6 daddr" if family == "v6" else "ip daddr"
    proto = "ipv6" if family == "v6" else "ipv4"
    tag = 'comment "%s"' % _comment(set_name)
    return [
        "meta nfproto %s ct direction original ct mark and 0x%08x == "
        "0x%08x %s %s" % (proto, _marks.MASK, mark,
                          _marks.nft_set_expr(mark), tag),
        "ct direction original %s @%s %s %s"
        % (daddr, set_name, _marks.nft_set_expr(mark), tag),
        "ct direction original %s @%s %s %s"
        % (daddr, set_name, _marks.nft_ct_set_expr(mark), tag),
    ]


def _entry_handles(chain: str, set_name: str) -> list:
    """Хэндлы правил записи: наши (по комментарию) и старого формата."""
    rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                        TABLE_NAME, chain])
    if rc != 0:
        return []
    tag = '"%s"' % _comment(set_name)
    ref = "@%s " % set_name
    handles = []
    for line in out.splitlines():
        if "handle" not in line:
            continue
        if tag not in line and (ref not in line + " "
                                or "meta mark set" not in line):
            continue
        h = line.rsplit("handle", 1)[1].strip().split()[0]
        if h.isdigit():
            handles.append(h)
    return handles


def _nft_batch(lines: list) -> tuple:
    if not lines:
        return True, ""
    try:
        r = subprocess.run(["nft", "-f", "-"], input="\n".join(lines) + "\n",
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0, (r.stderr or "").strip()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def setup_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    _ensure_table_and_chains()
    batch = []
    for chain in ("prerouting", "output"):
        for h in _entry_handles(chain, set_name):
            batch.append("delete rule inet %s %s handle %s"
                         % (TABLE_NAME, chain, h))
        for rule in entry_rules(set_name, mark, family):
            batch.append("add rule inet %s %s %s" % (TABLE_NAME, chain, rule))
    ok, err = _nft_batch(batch)
    return {"ok": ok, "mark": mark,
            "errors": [] if ok else ["nft -f: %s" % err]}


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


def ensure_iface_forward(ifname: str) -> dict:
    """
    Разрешить форвардинг LAN↔ifname в нашей forward-цепочке (best-effort).

    Примечание: accept в нашей отдельной таблице не отменяет drop в чужой
    nft-таблице на том же hook (на OpenWrt форвардинг рулится зонами fw4).
    Для iptables-роутеров используется ipset_backend.ensure_iface_forward,
    где ACCEPT в FORWARD терминирующий.
    """
    _ensure_table_and_chains()
    rc, out, _e = _run(["nft", "list", "chain", "inet",
                        TABLE_NAME, "forward"])
    have = {}
    if rc == 0:
        for direction in ("oifname", "iifname"):
            needle = '%s "%s" accept' % (direction, ifname)
            have[direction] = (needle in out or
                               ("%s %s accept" % (direction, ifname)) in out)
    for direction in ("oifname", "iifname"):
        if have.get(direction):
            continue
        _run(["nft", "add", "rule", "inet", TABLE_NAME, "forward",
              direction, ifname, "accept"])
    return {"ok": True, "ifname": ifname}


def remove_iface_forward(ifname: str) -> dict:
    """Удалить наши forward-accept правила по ifname (по handle)."""
    rc, out, _e = _run(["nft", "-a", "list", "chain", "inet",
                        TABLE_NAME, "forward"])
    if rc != 0:
        return {"ok": True, "removed": 0}
    removed = 0
    needles = (
        'oifname "%s" accept' % ifname, "oifname %s accept" % ifname,
        'iifname "%s" accept' % ifname, "iifname %s accept" % ifname,
    )
    for line in out.splitlines():
        if any(n in line for n in needles) and "handle" in line:
            parts = line.rsplit("handle", 1)
            if len(parts) == 2:
                h = parts[1].strip().split()[0]
                if h.isdigit():
                    rc2, _o, _e2 = _run(["nft", "delete", "rule", "inet",
                                          TABLE_NAME, "forward",
                                          "handle", h])
                    if rc2 == 0:
                        removed += 1
    return {"ok": True, "removed": removed, "ifname": ifname}


def teardown_mark_rule(set_name: str, mark: int = 0,
                       family: str = "v4") -> dict:
    """Снять все правила записи набора (новые и старого формата)."""
    batch = []
    for chain in ("prerouting", "output"):
        for h in _entry_handles(chain, set_name):
            batch.append("delete rule inet %s %s handle %s"
                         % (TABLE_NAME, chain, h))
    ok, err = _nft_batch(batch)
    return {"ok": ok, "errors": [] if ok else [err]}


# ────────────────────── ip rule fwmark ──────────────────────────────

def add_ip_rule_fwmark(mark: int, table: int, family: str = "v4",
                       priority: int = 10100) -> dict:
    from core.routing import marks as _marks
    return _marks.ip_rule_add(mark, table, family=family, priority=priority)


def del_ip_rule_fwmark(mark: int, table: int, family: str = "v4") -> dict:
    from core.routing import marks as _marks
    return _marks.ip_rule_del(mark, table, family=family)
