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
import threading

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
                        "family", fam, "hashsize", "1024", "maxelem", "1048576", "timeout", "0"])
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


def add_entry_argv(name: str, ip: str, timeout: int = 0) -> list:
    """argv добавления IP. timeout>0 — запись истечёт сама (TTL из DNS +
    запас); `-exist` обновляет срок уже лежащей записи. 0 — навсегда."""
    argv = ["ipset", "add", name, ip]
    if timeout and timeout > 0:
        argv += ["timeout", str(int(timeout))]
    return argv + ["-exist"]


def add_entry(name: str, ip: str, timeout: int = 0) -> bool:
    rc, _o, _e = _run(add_entry_argv(name, ip, timeout), timeout=5)
    return rc == 0


# ─────────────────────── iptables wiring ────────────────────────────

def _ensure_chain(table: str, chain: str, cmd: str = "iptables"):
    """Создать цепочку, если её нет."""
    rc, _o, err = _run([cmd, "-t", table, "-N", chain])
    chain_existed = (rc != 0 and "already exists" in (err or "").lower())

    return chain_existed or rc == 0


def _ensure_jump(table: str, parent: str, chain: str,
                 cmd: str = "iptables"):
    """В parent-цепочке добавляем -j chain один раз."""
    rc, out, _e = _run([cmd, "-t", table, "-S", parent])
    if rc == 0:
        for line in out.splitlines():
            if line.strip() == "-A %s -j %s" % (parent, chain):
                return True
    rc, _o, err = _run([cmd, "-t", table, "-A", parent, "-j", chain])
    if rc != 0:
        log.warning("iptables jump %s→%s: %s" % (parent, chain, err.strip()),
                    source="routing")
        return False
    return True


# ─────────── mark-правила: цепочка целиком, одним iptables-restore ───────────
#
# Содержимое AWG_ROUTING_PRE/OUT — функция списка «набор → метка». Раньше
# правила добавлялись и снимались по одной команде: между ними цепочка
# бывала в промежуточном состоянии, а повторы копили дубли. Теперь
# список читается из самой цепочки, правится и записывается обратно ЦЕЛИКОМ
# одним `iptables-restore --noflush` (объявление `:ЦЕПОЧКА` в таком режиме
# очищает её, и всё содержимое встаёт атомарно) — приём MagiTrickle.
#
# На каждую запись три правила (метка — своё поле бит, см. core/routing/marks):
#   1. connmark → mark: соединение, уже уведённое в туннель, остаётся
#      в нём, даже когда IP выпал из набора по таймауту (TTL записей);
#   2. dst в наборе → mark (только своё поле, чужие биты целы);
#   3. dst в наборе → connmark (для п.1 и для Keenetic, где без
#      сохранения метки в conntrack маршрутизация не работала —
#      MagiTrickle: «DO NOT REMOVE»).
# Первым — `--ctdir REPLY -j RETURN`: ответный трафик не метим.

_HEADER = ["-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"]


def entry_rules(set_name: str, mark: int, mask: int) -> list:
    """argv-хвосты правил одной записи (без `-A ЦЕПОЧКА`). Чистая."""
    from core.routing import marks as _marks
    xmark = "0x%x/0x%x" % (mark, mask)
    if mask != _marks.MASK:
        # Запись старого формата (метка целиком): переносим как есть,
        # пока правило не переприменят.
        return [["-m", "set", "--match-set", set_name, "dst",
                 "-j", "MARK", "--set-xmark", xmark]]
    return [
        ["-m", "connmark", "--mark", xmark,
         "-j", "MARK", "--set-xmark", xmark],
        ["-m", "set", "--match-set", set_name, "dst",
         "-j", "MARK", "--set-xmark", xmark],
        ["-m", "set", "--match-set", set_name, "dst",
         "-j", "CONNMARK", "--set-xmark", xmark],
    ]


def parse_chain_entries(dump: str) -> list:
    """`iptables -S <цепочка>` → [(set, mark, mask)] в порядке цепочки.

    Записью считается правило `--match-set S dst -j MARK --set-xmark`.
    `--set-mark N` (старые iptables так и печатают) — это `N/0xffffffff`.
    """
    out, seen = [], set()
    for line in (dump or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] != "-A" or "--match-set" not in parts:
            continue
        if "MARK" not in parts or "CONNMARK" in parts:
            continue
        try:
            set_name = parts[parts.index("--match-set") + 1]
            if "--set-xmark" in parts:
                token = parts[parts.index("--set-xmark") + 1]
            else:
                token = parts[parts.index("--set-mark") + 1]
        except (ValueError, IndexError):
            continue
        value, _, mask = token.partition("/")
        try:
            mark = int(value, 0)
            mask = int(mask, 0) if mask else 0xFFFFFFFF
        except ValueError:
            continue
        if set_name in seen:
            continue
        seen.add(set_name)
        out.append((set_name, mark, mask))
    return out


def render_restore(entries: list, chains=None) -> str:
    """Текст для `iptables-restore --noflush`: наши цепочки целиком."""
    chains = chains or (PREROUTING_CHAIN, OUTPUT_CHAIN)
    lines = ["*mangle"]
    lines += [":%s - [0:0]" % ch for ch in chains]
    for ch in chains:
        if entries:
            lines.append(" ".join(["-A", ch] + _HEADER))
        for set_name, mark, mask in entries:
            for tail in entry_rules(set_name, mark, mask):
                lines.append(" ".join(["-A", ch] + tail))
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def _current_entries(cmd: str) -> list:
    rc, out, _e = _run([cmd, "-t", "mangle", "-S", PREROUTING_CHAIN])
    return parse_chain_entries(out) if rc == 0 else []


def _restore(cmd: str, text: str) -> tuple:
    """Записать цепочки; без *-restore — по одной команде (не атомарно)."""
    try:
        r = subprocess.run([cmd + "-restore", "--noflush"], input=text,
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return True, ""
        err = (r.stderr or "").strip()
        if r.returncode != 127:
            return False, err
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        err = str(e)
    # Фолбэк: та же последовательность обычными командами.
    errors = []
    for line in text.splitlines():
        if line.startswith(":"):
            ch = line[1:].split()[0]
            _run([cmd, "-t", "mangle", "-N", ch])
            _run([cmd, "-t", "mangle", "-F", ch])
        elif line.startswith("-A "):
            rc, _o, e = _run([cmd, "-t", "mangle"] + line.split())
            if rc != 0:
                errors.append(e.strip())
    return not errors, "; ".join(errors[:3])


_chain_lock = threading.Lock()


def _sync_locked(entries: list, family: str) -> dict:
    cmd = "iptables" if family == "v4" else "ip6tables"
    _ensure_chain("mangle", PREROUTING_CHAIN, cmd)
    _ensure_chain("mangle", OUTPUT_CHAIN, cmd)
    _ensure_jump("mangle", "PREROUTING", PREROUTING_CHAIN, cmd)
    _ensure_jump("mangle", "OUTPUT", OUTPUT_CHAIN, cmd)
    ok, err = _restore(cmd, render_restore(entries))
    return {"ok": ok, "errors": [err] if err else []}


def sync_mark_entries(entries: list, family: str = "v4") -> dict:
    """Переписать наши mangle-цепочки семейства под список записей."""
    with _chain_lock:
        return _sync_locked(entries, family)


def setup_mark_rule(set_name: str, mark: int, family: str = "v4") -> dict:
    """
    Добавить (идемпотентно) маркировку пакетов, чьи dst входят в set_name.

    Цепочки переписываются целиком: прочие записи сохраняются, запись
    этого набора (в том числе старого формата) заменяется новой. Чтение
    и запись — под одним замком: иначе параллельная правка (сторож
    после перезаписи netfilter, соседнее правило) потеряла бы запись.
    Возвращает {ok, errors, mark}.
    """
    from core.routing import marks as _marks
    cmd = "iptables" if family == "v4" else "ip6tables"
    with _chain_lock:
        entries = [e for e in _current_entries(cmd) if e[0] != set_name]
        entries.append((set_name, mark, _marks.MASK))
        res = _sync_locked(entries, family)
    return {"ok": res["ok"], "mark": mark, "errors": res["errors"]}


def teardown_mark_rule(set_name: str, mark: int = 0,
                       family: str = "v4") -> dict:
    """Убрать запись набора из наших цепочек (метка не важна)."""
    cmd = "iptables" if family == "v4" else "ip6tables"
    with _chain_lock:
        current = _current_entries(cmd)
        entries = [e for e in current if e[0] != set_name]
        if len(entries) == len(current):
            return {"ok": True}
        res = _sync_locked(entries, family)
    return {"ok": res["ok"], "errors": res["errors"]}


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
    """ip rule add fwmark <mark>/<поле меток> lookup <table>."""
    from core.routing import marks as _marks
    return _marks.ip_rule_add(mark, table, family=family, priority=priority)


def del_ip_rule_fwmark(mark: int, table: int, family: str = "v4") -> dict:
    from core.routing import marks as _marks
    return _marks.ip_rule_del(mark, table, family=family)
