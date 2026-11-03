# core/geneva_auto_fw.py
"""
Режим «Авто» geneva: правила firewall групп (своя таблица и цепочки).

Каждая группа «Авто» — свой ``geneva run --firewall none`` на очереди
340+i. Отбирают её трафик правила zapret-gui: только адреса и порты
сервисов группы и только первые пакеты соединения. Без адресов в очередь
не уходит ничего — «все порты» у самого процесса безопасны лишь потому,
что правила узкие.

nftables (таблица ``inet zapret_geneva_auto``):

* наборы ``geneva_auto_<Q>_<n>_v4/v6`` (``flags timeout``,
  ``timeout 7d``): адреса целей группы с одинаковыми портами. Наборы на
  «очередь + порты», а не на очередь: у сайта 443/tcp, у резолвера
  53/tcp+udp, и общий набор пустил бы через стратегию чужой порт;
* ``post`` (postrouting, после NAT — как у nfqws2) — исходящие:
  ``daddr`` в наборе, протокол и порты сервера,
  ``ct original packets 1-12``; ``pre`` (prerouting) — ответы: ``saddr``
  в наборе, ``ct reply packets 1-6``; ``queue num Q bypass`` — упавший
  процесс не рвёт трафик;
* DHT (цель по локальному порту) — по исходному кортежу conntrack
  (``ct original ip saddr <клиент> ct original proto-src <порт>``) и
  направлению: после NAT адрес клиента в пакете уже другой;
* в начале обеих цепочек — пропуск метки geneva ``0x20000000`` (свои
  пакеты движков и проба без обхода) и блока портов оценщика
  30000–30511 (подбор идёт своей очередью 311). Порты проб «Авто»
  (30512–30575) не пропускаются: проверка с обходом обязана пройти
  через группу.

iptables (таблица ``mangle``, цепочки ``ZGGA_POST``/``ZGGA_PRE``,
``ip6tables`` — то же): ``ipset`` ``hash:ip timeout`` с теми же
именами, ``-m set --match-set``, ``-m connbytes``, ``-m conntrack
--ctorigsrc/--ctorigsrcport --ctdir`` для DHT, ``-j NFQUEUE --queue-num
Q --queue-bypass``. Нет ``ipset`` или ``xt_connbytes`` — понятная ошибка,
а не тихое «весь трафик через geneva»: без ограничителя первых пакетов
очередь получила бы каждый пакет потока.

Всё строят чистые функции (:func:`build_auto_rules`,
:func:`ipt_commands`, :func:`teardown_commands`) — golden-тесты в
``tests/test_geneva_auto_fw.py``. Применение идемпотентно: nft — заменой
таблицы целиком одним ``nft -f``, iptables — сменой содержимого наборов
через ``ipset swap`` и пересборкой своих цепочек. Снятие убирает всё
(очереди 340–347), даже не зная, какие группы были: так правила уходят и
при восстановлении после сбоя.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess

from core import geneva_auto as ga
from core.log_buffer import log

TABLE = "zapret_geneva_auto"
CHAIN_POST = "ZGGA_POST"
CHAIN_PRE = "ZGGA_PRE"
MARK = "0x20000000"
EVAL_PORTS = (30000, 30511)       # блок оценщика geneva (8 воркеров × 64)
SET_TIMEOUT_SEC = 7 * 86400
PRIO_POST = 151                   # после NAT (srcnat 100), рядом с nfqws2
PRIO_PRE = -149
QUEUES = range(ga.QUEUE_BASE, ga.QUEUE_BASE + ga.MAX_GROUPS_LIMIT)


class FirewallError(RuntimeError):
    """Правила не встали: ``hint`` — что поставить."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


# ───────────────────────────── разбор целей ─────────────────────────

def _split(addresses):
    v4, v6 = [], []
    for a in addresses or []:
        try:
            ip = ipaddress.ip_address(str(a))
        except ValueError:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    key4 = sorted(set(v4), key=lambda x: ipaddress.ip_address(x))
    key6 = sorted(set(v6), key=lambda x: ipaddress.ip_address(x))
    return key4, key6


def _ranges(spec: str) -> list:
    """``443-444,8443`` → ``[(443, 444), (8443, 8443)]``."""
    out = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if 1 <= lo <= hi <= 65535:
            out.append((lo, hi))
    return out


def layout(queues: dict) -> list:
    """Группы → плоский список правил-заготовок, общий для обоих бэкендов.

    ``queues`` — ``{очередь: ga.Group}``. Элемент: ``{"queue", "kind":
    "addr"|"port", …}``; у ``addr`` — имя набора и адреса v4/v6, порты
    tcp/udp; у ``port`` — клиент, протокол, локальный порт.
    """
    out = []
    for q in sorted(queues):
        g = queues[q]
        sets = {}                          # (tcp, udp) → номер набора
        for t in g.targets:
            if t.by_local_port:
                ip = str(t.client or "")
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                for proto, ports in (("tcp", t.tcp_ports),
                                     ("udp", t.udp_ports)):
                    for lo, _hi in _ranges(ports)[:1]:
                        out.append({"queue": q, "kind": "port",
                                    "client": ip, "proto": proto,
                                    "port": lo})
                continue
            v4, v6 = _split(t.addresses)
            if not (v4 or v6) or not (t.tcp_ports or t.udp_ports):
                continue
            sig = (t.tcp_ports, t.udp_ports)
            if sig not in sets:
                sets[sig] = {"queue": q, "kind": "addr",
                             "set": "geneva_auto_%d_%d" % (q, len(sets)),
                             "v4": [], "v6": [],
                             "tcp": _ranges(t.tcp_ports),
                             "udp": _ranges(t.udp_ports)}
                out.append(sets[sig])
            entry = sets[sig]
            entry["v4"] = sorted(set(entry["v4"]) | set(v4),
                                 key=ipaddress.ip_address)
            entry["v6"] = sorted(set(entry["v6"]) | set(v6),
                                 key=ipaddress.ip_address)
    return out


# ───────────────────────────── nftables ─────────────────────────────

def _nft_ports(ranges) -> str:
    items = ["%d" % lo if lo == hi else "%d-%d" % (lo, hi)
             for lo, hi in ranges]
    return "{ %s }" % ", ".join(items)


def build_auto_rules(queues: dict, backend: str = "nft") -> str:
    """Правила групп текстом: nft-скрипт для ``nft -f -`` или команды
    iptables/ipset построчно (для golden-тестов и журнала)."""
    if backend == "nft":
        return _nft_script(layout(queues))
    return "\n".join(" ".join(c) for c, _must in ipt_commands(queues)) + "\n"


def _nft_script(items) -> str:
    lines = ["table inet %s" % TABLE,
             "delete table inet %s" % TABLE,
             "table inet %s {" % TABLE]
    for it in items:
        if it["kind"] != "addr":
            continue
        for fam, typ in (("v4", "ipv4_addr"), ("v6", "ipv6_addr")):
            if not it[fam]:
                continue
            lines += ["\tset %s_%s {" % (it["set"], fam),
                      "\t\ttype %s" % typ,
                      "\t\tflags timeout",
                      "\t\ttimeout 7d",
                      "\t\telements = { %s }" % ", ".join(it[fam]),
                      "\t}"]
    lo, hi = EVAL_PORTS
    for chain, hook, prio, direction in (
            ("post", "postrouting", PRIO_POST, "original"),
            ("pre", "prerouting", PRIO_PRE, "reply")):
        out = direction == "original"
        port_side = "sport" if out else "dport"
        lines += ["\tchain %s {" % chain,
                  "\t\ttype filter hook %s priority %d; policy accept;"
                  % (hook, prio),
                  "\t\tmeta mark & %s == %s return" % (MARK, MARK),
                  "\t\ttcp %s %d-%d return" % (port_side, lo, hi),
                  "\t\tudp %s %d-%d return" % (port_side, lo, hi)]
        limit = "ct original packets 1-%d" % ga.OUT_PACKETS if out \
            else "ct reply packets 1-%d" % ga.IN_PACKETS
        for it in items:
            q = it["queue"]
            if it["kind"] == "port":
                lines.append(
                    "\t\tmeta l4proto %s ct original ip%s saddr %s "
                    "ct original proto-src %d ct direction %s %s "
                    "queue num %d bypass"
                    % (it["proto"], "6" if ":" in it["client"] else "",
                       it["client"], it["port"], direction, limit, q))
                continue
            addr = "daddr" if out else "saddr"
            svc = "dport" if out else "sport"
            for fam, ipkw in (("v4", "ip"), ("v6", "ip6")):
                if not it[fam]:
                    continue
                for proto in ("tcp", "udp"):
                    if not it[proto]:
                        continue
                    lines.append(
                        "\t\t%s %s @%s_%s %s %s %s %s queue num %d bypass"
                        % (ipkw, addr, it["set"], fam, proto, svc,
                           _nft_ports(it[proto]), limit, q))
        lines.append("\t}")
    lines.append("}")
    return "\n".join(lines) + "\n"


# ───────────────────────────── iptables ─────────────────────────────

def _ipt_ports(lo, hi) -> str:
    return "%d" % lo if lo == hi else "%d:%d" % (lo, hi)


def ipt_commands(queues: dict) -> list:
    """Команды iptables/ip6tables/ipset: ``[(argv, обязательна)]``.

    Необязательные — удаление того, чего может не быть (идемпотентность).
    Списки портов бьются на правила по одному диапазону: ``multiport``
    на Entware бывает не установлен.
    """
    items = layout(queues)
    cmds = []
    to = str(SET_TIMEOUT_SEC)
    for it in items:
        if it["kind"] != "addr":
            continue
        for fam, family in (("v4", "inet"), ("v6", "inet6")):
            name = "%s_%s" % (it["set"], fam)
            tmp = name + "_t"
            cmds += [
                (["ipset", "create", name, "hash:ip", "family", family,
                  "timeout", to, "-exist"], True),
                (["ipset", "create", tmp, "hash:ip", "family", family,
                  "timeout", to, "-exist"], True),
                (["ipset", "flush", tmp], True)]
            cmds += [(["ipset", "add", tmp, ip, "-exist"], True)
                     for ip in it[fam]]
            cmds += [(["ipset", "swap", tmp, name], True),
                     (["ipset", "destroy", tmp], False)]
    lo, hi = EVAL_PORTS
    for ipt, fam in (("iptables", "v4"), ("ip6tables", "v6")):
        for chain, hook, direction in ((CHAIN_POST, "POSTROUTING", "original"),
                                       (CHAIN_PRE, "PREROUTING", "reply")):
            out = direction == "original"
            base = [ipt, "-t", "mangle"]
            cmds += [(base + ["-N", chain], False),
                     (base + ["-F", chain], True),
                     (base + ["-D", hook, "-j", chain], False),
                     (base + ["-I", hook, "1", "-j", chain], True),
                     (base + ["-A", chain, "-m", "mark", "--mark",
                              "%s/%s" % (MARK, MARK), "-j", "RETURN"], True)]
            side = "--sport" if out else "--dport"
            for proto in ("tcp", "udp"):
                cmds.append((base + ["-A", chain, "-p", proto, side,
                                     "%d:%d" % (lo, hi), "-j", "RETURN"],
                             True))
            limit = ["-m", "connbytes", "--connbytes-dir", direction,
                     "--connbytes-mode", "packets", "--connbytes",
                     "1:%d" % (ga.OUT_PACKETS if out else ga.IN_PACKETS)]
            for it in items:
                q = str(it["queue"])
                target = ["-j", "NFQUEUE", "--queue-num", q,
                          "--queue-bypass"]
                if it["kind"] == "port":
                    if (":" in it["client"]) != (fam == "v6"):
                        continue
                    cmds.append((base + [
                        "-A", chain, "-p", it["proto"], "-m", "conntrack",
                        "--ctorigsrc", it["client"],
                        "--ctorigsrcport", str(it["port"]),
                        "--ctdir", direction.upper()] + limit + target,
                        True))
                    continue
                if not it[fam]:
                    continue
                name = "%s_%s" % (it["set"], fam)
                for proto in ("tcp", "udp"):
                    for plo, phi in it[proto]:
                        cmds.append((base + [
                            "-A", chain, "-p", proto, "-m", "set",
                            "--match-set", name, "dst" if out else "src",
                            "--dport" if out else "--sport",
                            _ipt_ports(plo, phi)] + limit + target, True))
    return cmds


def teardown_commands(backend: str, sets=()) -> list:
    """Снять всё режима (все очереди 340–347): ``[(argv, обязательна)]``.

    ``sets`` — имена из ``ipset list -n``: уничтожаются только наборы
    режима (префикс ``geneva_auto_``), а не перебор всех возможных имён.
    """
    if backend == "nft":
        return [(["nft", "delete", "table", "inet", TABLE], False)]
    cmds = []
    for ipt in ("iptables", "ip6tables"):
        base = [ipt, "-t", "mangle"]
        for chain, hook in ((CHAIN_POST, "POSTROUTING"),
                            (CHAIN_PRE, "PREROUTING")):
            cmds += [(base + ["-D", hook, "-j", chain], False),
                     (base + ["-F", chain], False),
                     (base + ["-X", chain], False)]
    for name in sorted(sets or ()):
        if str(name).startswith("geneva_auto_"):
            cmds.append((["ipset", "destroy", str(name)], False))
    return cmds


# ───────────────────────────── I/O ──────────────────────────────────

def _backend() -> str:
    from core.firewall import get_firewall_manager
    fw = get_firewall_manager().detect_fw_type()
    if fw == "nftables":
        return "nft"
    if fw == "iptables":
        return "iptables"
    raise FirewallError("ни nft, ни iptables не найдены",
                        "Entware: opkg install iptables; OpenWrt: nftables")


def _run(argv, stdin=None):
    try:
        r = subprocess.run(argv, input=stdin, capture_output=True,
                           text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    if r.returncode == 0:
        return True, (r.stdout or "").strip()
    return False, (r.stderr or r.stdout or "").strip()


def check_requirements(backend: str, has_addr: bool = True) -> None:
    """Нет нужного модуля — ``FirewallError`` с подсказкой."""
    if backend == "nft":
        if not shutil.which("nft"):
            raise FirewallError("нет nft", "opkg install nftables")
        return
    from core.firewall import get_firewall_manager
    fw = get_firewall_manager()
    if has_addr and not shutil.which("ipset"):
        raise FirewallError(
            "для режима «Авто» с iptables нужен ipset",
            "opkg install ipset (Entware/OpenWrt) / apt install ipset")
    if not fw._connbytes_supported("iptables"):
        raise FirewallError(
            "нет матча connbytes (xt_connbytes): без него в geneva ушёл бы "
            "каждый пакет потока",
            "opkg install iptables-mod-conntrack-extra")


def apply(queues: dict, backend: str = "") -> dict:
    """Поставить правила групп (замена целиком). ``{"ok", "backend",
    "error", "hint"}``."""
    try:
        backend = backend or _backend()
        if not queues:
            remove(backend)
            return {"ok": True, "backend": backend}
        check_requirements(backend, any(i["kind"] == "addr"
                                        for i in layout(queues)))
    except FirewallError as e:
        return {"ok": False, "backend": backend, "error": str(e),
                "hint": e.hint}
    if backend == "nft":
        ok, err = _run(["nft", "-f", "-"], stdin=build_auto_rules(queues))
        if not ok:
            log.error("geneva-auto: nft: %s" % err, source="geneva")
            return {"ok": False, "backend": backend,
                    "error": "nft не принял правила: %s" % err[:300]}
        return {"ok": True, "backend": backend}
    has_v6 = shutil.which("ip6tables") is not None
    for argv, must in ipt_commands(queues):
        if argv[0] == "ip6tables" and not has_v6:
            continue
        ok, err = _run(argv)
        if not ok and must:
            log.error("geneva-auto: %s: %s" % (" ".join(argv), err),
                      source="geneva")
            remove(backend)
            return {"ok": False, "backend": backend,
                    "error": "%s: %s" % (argv[0], err[:300])}
    return {"ok": True, "backend": backend}


def remove(backend: str = "") -> None:
    """Снять правила режима (всегда: выключение, стоп, выход, сбой)."""
    try:
        backend = backend or _backend()
    except FirewallError:
        return
    sets = []
    if backend != "nft" and shutil.which("ipset"):
        ok, out = _run(["ipset", "list", "-n"])
        sets = out.split() if ok else []
    for argv, _must in teardown_commands(backend, sets):
        if argv[0] in ("ip6tables", "ipset") and not shutil.which(argv[0]):
            continue
        _run(argv)
