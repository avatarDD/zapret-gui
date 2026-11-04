# core/geneva_auto_observer.py
"""
Режим «Авто» geneva: наблюдение за трафиком через роутер (conntrack).

Отличие: в AutoTuner наблюдение — захват всего трафика ПК срезами по
15 с и разбор потоков (``AutoObserver``). На роутере pcap всего трафика не
нужен: ядро и так ведёт каждое соединение в conntrack, со счётчиками
пакетов и байт в обе стороны. Отсюда и берётся срез:

* **источник** — ``/proc/net/nf_conntrack`` (или старый
  ``/proc/net/ip_conntrack``), иначе ``conntrack -L -o extended``.
  На время режима включаются ``net.netfilter.nf_conntrack_acct=1``
  (счётчики ``packets=``/``bytes=``) и ``nf_conntrack_timestamp=1``
  (возраст ``delta-time=``); прежние значения возвращаются при
  выключении (:meth:`Observer.restore`). Где этих sysctl нет (Keenetic
  NDMS 14.x), учёт ядром не управляется; есть ли счётчики, решает срез
  (``last_stats["counted"]``), а не наличие файлов;
* **что берём** — только трафик в интернет от клиентов LAN и самого
  роутера. Пропускаются: адреса не из интернета (RFC1918, CGNAT,
  loopback, multicast), входящие соединения (клиент не локальный),
  перенаправленные на сам роутер (REDIRECT/TPROXY sing-box и mihomo:
  ответ идёт не от сервера), пробы GUI и geneva (connmark-исключение
  ``0x20000000`` и метка проб ``0x10000000`` в ``mark=``, блок
  локальных портов оценщика geneva 30000–30511 и проб «Авто»
  30512–30575), трафик в туннели
  zapret-gui (ответ приходит на адрес туннельного интерфейса: awg, wg,
  nwg, tun, …) и адреса из настройки ``geneva.auto.exclude``.
  **Внешние** соединения туннелей и прокси (роутер → сервер AmneziaWG,
  WireGuard, sing-box, mihomo, usque) наблюдаются, как любой трафик: если
  до сервера VPN или прокси не достучаться из-за DPI, «Авто» подберёт
  стратегию и для него (``geneva.auto.help_tunnels``, по умолчанию да;
  ``false`` — прежнее поведение, серверы из ``awg/wg show all endpoints``
  исключаются). Такие сервисы подписаны «Туннель: …»;
* **оценка соединения** — :func:`judge`, перенос ``AutoObserver.Judge``
  на счётчики conntrack (пороги одним блоком ниже);
* **имя сайта** — карта «IP → имя» из DNS-ответов, которую ведёт
  :mod:`core.block_detector` (второго сниффера DNS нет), плюс имена,
  узнанные из захвата (SNI);
* **протокол по первому пакету** (WireGuard, OpenVPN, DHT, STUN, QUIC) и
  ``replay`` conntrack не даёт. Для подозрительного сервиса снимается
  короткий захват его первых пакетов (:meth:`Observer.identify`,
  ``core/traffic_capture.capture_first``: фиксированный argv tcpdump,
  фильтр по адресу и порту, файл удаляется) и разбирается
  :func:`analyze_capture`. Без tcpdump сервис остаётся ``endpoint`` по
  порту и судится пассивно.

Чистые функции (разбор строки, фильтр, оценка, ключи, распознавание
протокола, разбор захвата) отделены от I/O класса :class:`Observer` и
покрыты тестами фикстурами строк OpenWrt, Keenetic и обычного Linux.

Отличия от эталона (``AutoObserver``), помимо источника:

* DHT без захвата узнаётся по «веер узлов с одного порта»: UDP с одного
  исходного порта клиента к ≥ ``P2P_FANOUT`` разным адресам — это
  ``local_port`` с приложением ``p2p``. Иначе каждый узел DHT стал бы
  своим ``ep:``-сервисом и книга (300 сервисов) переполнилась бы;
* UDP-поток живёт в conntrack долго (WireGuard, QUIC), поэтому после
  первого вердикта он судится по приросту счётчиков за срез: клиент
  слал, а ответа за срез нет — провал; ответ был — успех;
* соединения, перехваченные TPROXY (sing-box, mihomo), в conntrack
  выглядят прямыми (кортеж не меняется, ct mark не ставится): их
  серверы исключаются настройкой ``geneva.auto.exclude``;
* MTProto по первому пакету не распознаётся: нужен AES-CTR, а его в
  stdlib нет. Такой поток — ``tcp``, судится по своему трафику.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field

from core import geneva_auto as ga
from core.log_buffer import log

# ───────────────────────────── пороги ───────────────────────────────

SLICE = 15.0                      # срез: раз в столько секунд
CONNTRACK_FILES = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")
CONNTRACK_CANDIDATES = ("conntrack", "/opt/sbin/conntrack",
                        "/usr/sbin/conntrack", "/sbin/conntrack")
MAX_LINES = 30000                 # строк таблицы за срез (роутер)
MAX_TRACKED = 20000               # соединений в памяти наблюдателя

SYSCTL_DIR = "/proc/sys/net/netfilter"
SYSCTLS = ("nf_conntrack_acct", "nf_conntrack_timestamp")

# Оценка соединения (AutoObserver.Judge на счётчиках conntrack).
TCP_NO_CONN_AGE = 3.0             # SYN без ответа: нет соединения
STALL_AGE = 5.0                   # соединение есть, данных нет
UDP_AGE = 5.0                     # UDP без ответа: провал
STALL_REPLY_PACKETS = 3           # ответных пакетов «почти нет»
STALL_REPLY_PAYLOAD = 100         # байт данных ответа «почти нет»
STALL_OUT_PACKETS = 4             # клиент повторял (SYN, ACK, данные, повтор)
RESET_REPLY_PAYLOAD = 200         # CLOSE (RST) с ответом меньше этого
OK_REPLY_PAYLOAD = 2048           # «ответ в несколько КБ»: успех
CUT_MIN = 8 * 1024                # обрыв «на 16 КБ» (SessionClassifier)
CUT_MAX = 32 * 1024
STALL_GAP = 4.0                   # данных ответа нет столько, клиент шлёт
WEB_PORTS = (80, 443)

# Заголовки на пакет, чтобы оценить байты данных по bytes=/packets=.
# У TCP — с запасом на опции (SYN — 20 байт опций, остальные — 12 на
# timestamps): SYN и голые ACK не должны выглядеть «данными». Данные
# занижаются на ≤ 20 байт на пакет; ClientHello всё равно сотни байт.
_HDR = {("tcp", 4): 60, ("tcp", 6): 80, ("udp", 4): 28, ("udp", 6): 48}

# Свои соединения GUI и geneva.
SKIP_CT_MARK = 0x20000000 | 0x10000000   # исключение (пробы) | метка проб
PROBE_PORT_BASE = 30000                  # блок портов оценщика geneva_c
PROBE_PORT_COUNT = 64 * 8                # 64 на воркера, до 8 воркеров
# Сразу за ним — исходные порты проб самого «Авто» (core/geneva_auto_probes):
# проба без обхода и проверка с обходом не должны попасть в срез как
# трафик пользователя (ct mark в режиме geneva никто не ставит).
AUTO_PROBE_PORTS = (PROBE_PORT_BASE + PROBE_PORT_COUNT,
                    PROBE_PORT_BASE + PROBE_PORT_COUNT + 63)
# Две половины блока: проба без обхода и проба с обходом. Правила групп
# пропускают первую половину по порту: SO_MARK есть только у исходящих
# пакетов пробы, а её ответы без порта ушли бы в очередь живой группы,
# и входящая часть стратегии сделала бы «доступно без обхода».
AUTO_BASELINE_PORTS = (AUTO_PROBE_PORTS[0], AUTO_PROBE_PORTS[0] + 31)
AUTO_BYPASS_PORTS = (AUTO_PROBE_PORTS[0] + 32, AUTO_PROBE_PORTS[1])

# Туннельные интерфейсы: ответ на их адрес — трафик ушёл в туннель.
TUNNEL_PREFIXES = ("awg", "wg", "nwg", "tun", "tap", "utun", "usque",
                   "sing", "sbox", "mihomo", "meta", "clash", "warp",
                   "opkgtun", "ovpn", "ipsec", "xfrm", "l2tp", "gre")

P2P_FANOUT = 8                    # узлов с одного UDP-порта: это P2P

# Захват первых пакетов для распознавания протокола.
CAPTURE_PACKETS = 16
CAPTURE_SECONDS = 20
MAX_REPLAY = 4                    # пакетов в replay
MAX_REPLAY_BYTES = 4096

_TCP_FIN_STATES = ("FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT")

# ───────────────────────────── запись conntrack ─────────────────────


@dataclass
class Conn:
    """Одна строка conntrack: исходное направление и ответ."""
    proto: str                    # tcp | udp
    src: str
    dst: str
    sport: int
    dport: int
    rsrc: str = ""
    rdst: str = ""
    rsport: int = 0
    rdport: int = 0
    state: str = ""               # TCP: ESTABLISHED, SYN_SENT, …
    opackets: int = None          # None — учёт выключен
    obytes: int = None
    rpackets: int = None
    rbytes: int = None
    unreplied: bool = False
    assured: bool = False
    offload: bool = False
    mark: int = 0
    zone: int = 0
    delta: float = None           # секунд с начала (nf_conntrack_timestamp)
    timeout: int = 0

    @property
    def family(self) -> int:
        return 6 if ":" in self.src else 4

    @property
    def cid(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport,
                self.zone)

    @property
    def counted(self) -> bool:
        return self.opackets is not None and self.rpackets is not None

    def payload_out(self) -> int:
        return _payload(self.obytes, self.opackets, self.proto, self.family)

    def payload_in(self) -> int:
        return _payload(self.rbytes, self.rpackets, self.proto, self.family)


def _payload(nbytes, packets, proto, family) -> int:
    if nbytes is None or packets is None:
        return 0
    return max(0, int(nbytes) - int(packets) * _HDR[(proto, family)])


_L4 = frozenset(("tcp", "udp", "udplite", "sctp", "dccp", "icmp", "icmpv6",
                 "gre", "unknown"))


def parse_line(line: str):
    """Строка ``/proc/net/nf_conntrack`` или ``conntrack -L`` → ``Conn``.

    Форматы: ``ipv4 2 tcp 6 <timeout> <STATE> src= dst= sport= dport=
    [packets= bytes=] [UNREPLIED] src= … [OFFLOAD] [ASSURED] mark=
    [zone=] [delta-time=] use=`` (ядро), то же без ``ipv4 2`` (старый
    ip_conntrack и ``conntrack -L``). Незнакомые поля (secctx=, у
    Keenetic свои) пропускаются. Не TCP/UDP и мусор — ``None``.
    """
    tokens = (line or "").split()
    i = next((k for k, t in enumerate(tokens[:4]) if t in _L4), -1)
    if i < 0 or tokens[i] not in ("tcp", "udp"):
        return None
    proto = tokens[i]
    rest = tokens[i + 2:]
    if not rest:
        return None
    timeout = 0
    if rest[0].isdigit():
        timeout = int(rest[0])
        rest = rest[1:]
    state = ""
    if proto == "tcp" and rest and "=" not in rest[0] and \
            not rest[0].startswith("["):
        state = rest[0]
        rest = rest[1:]
    orig, reply = {}, {}
    cur = orig
    flags = set()
    extra = {}
    for t in rest:
        if t.startswith("[") and t.endswith("]"):
            flags.add(t[1:-1])
            continue
        key, eq, value = t.partition("=")
        if not eq:
            continue
        if key == "src" and "src" in orig:
            cur = reply
        if key in ("src", "dst", "sport", "dport", "packets", "bytes"):
            if key not in cur:
                cur[key] = value
        else:
            extra.setdefault(key, value)
    try:
        conn = Conn(
            proto=proto,
            src=_norm_ip(orig["src"]), dst=_norm_ip(orig["dst"]),
            sport=int(orig["sport"]), dport=int(orig["dport"]),
            rsrc=_norm_ip(reply.get("src", "")),
            rdst=_norm_ip(reply.get("dst", "")),
            rsport=int(reply.get("sport") or 0),
            rdport=int(reply.get("dport") or 0),
            state=state.upper(),
            opackets=_int_or_none(orig.get("packets")),
            obytes=_int_or_none(orig.get("bytes")),
            rpackets=_int_or_none(reply.get("packets")),
            rbytes=_int_or_none(reply.get("bytes")),
            unreplied="UNREPLIED" in flags,
            assured="ASSURED" in flags,
            offload=bool(flags & {"OFFLOAD", "HW_OFFLOAD"}),
            mark=_int_any(extra.get("mark")),
            zone=_int_any(extra.get("zone")),
            delta=_float_or_none(extra.get("delta-time")),
            timeout=timeout,
        )
    except (KeyError, ValueError):
        return None
    if not conn.src or not conn.dst:
        return None
    return conn


def parse_table(lines) -> list:
    out = []
    for n, line in enumerate(lines or []):
        if n >= MAX_LINES:
            break
        c = parse_line(line)
        if c is not None:
            out.append(c)
    return out


def _norm_ip(value: str) -> str:
    if not value:
        return ""
    try:
        a = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def _int_or_none(v):
    try:
        return None if v is None else int(v)
    except ValueError:
        return None


def _float_or_none(v):
    try:
        return None if v is None else float(v)
    except ValueError:
        return None


def _int_any(v) -> int:
    if not v:
        return 0
    try:
        return int(v, 0)
    except ValueError:
        return 0


# ───────────────────────────── что наше ─────────────────────────────

def is_internet(ip: str) -> bool:
    """Адрес в интернете: не RFC1918/CGNAT/loopback/link-local/multicast."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def is_local_client(ip: str, local) -> bool:
    """Клиент LAN или сам роутер.

    ``local`` — :class:`Local`: собственные адреса роутера и его сети
    LAN (у IPv6 клиенты с глобальными адресами из делегированного
    префикса). Частный адрес — всегда локальный.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not a.is_global:
        return not a.is_multicast and not a.is_unspecified
    if local is None:
        return False
    if ip in local.own:
        return True
    return any(a in net for net in local.nets if net.version == a.version)


@dataclass
class Local:
    """Что считается «своим»: адреса роутера, сети LAN, туннели."""
    own: set = field(default_factory=set)          # адреса роутера
    nets: list = field(default_factory=list)       # сети LAN (IPv6 GUA)
    tunnel: set = field(default_factory=set)       # адреса туннелей
    exclude: set = field(default_factory=set)      # не наблюдать
    servers: set = field(default_factory=set)      # серверы туннелей


def is_probe_port(port: int) -> bool:
    """Порт из блока проб оценщика geneva или проб «Авто»: не трафик
    пользователя."""
    return PROBE_PORT_BASE <= int(port) <= AUTO_PROBE_PORTS[1]


def skip_reason(c: Conn, local) -> str:
    """Почему соединение не наблюдается; ``""`` — наблюдается."""
    if not is_internet(c.dst):
        return "not_internet"
    if not is_local_client(c.src, local):
        return "inbound"
    if c.mark & SKIP_CT_MARK:
        return "own_mark"
    if is_probe_port(c.sport):
        return "probe_port"
    if c.rsrc and c.rsrc != c.dst:
        # Ответ идёт не от сервера: REDIRECT/TPROXY в локальный прокси
        # (sing-box, mihomo) или DNAT — соединение не прямое.
        return "redirected"
    if local is not None:
        if c.rdst and c.rdst in local.tunnel:
            return "tunnel"
        if c.dst in local.exclude:
            return "excluded"
    return ""


# ───────────────────────────── оценка ───────────────────────────────

def judge(c: Conn, age: float, kind: str = "", hung: bool = False):
    """Как прошло соединение: ``(health, why)`` или ``None`` (рано судить).

    ``AutoObserver.Judge`` на счётчиках conntrack. ``hung`` — данные
    ответа не росли ``STALL_GAP`` секунд, а клиент ещё слал (считает
    :class:`Observer` по прошлому срезу).
    """
    if c.proto == "udp":
        return _judge_udp(c, age, kind)
    replied = (c.rpackets or 0) > 0 if c.counted else not c.unreplied
    if c.state in ("SYN_SENT", "SYN_SENT2", "NONE") or (
            c.unreplied and not replied):
        # SYN отправлен повторно, в ответ ничего: соединения нет
        if replied or age < TCP_NO_CONN_AGE:
            return None
        if c.counted and c.opackets < 2:
            return None
        return ga.NO_CONNECTION, "соединение не устанавливается"
    if not c.counted:
        # Без учёта пакетов судить зависание нельзя: только «нет
        # соединения» выше.
        return None
    out = c.payload_out()
    inn = c.payload_in()
    if c.offload:
        # Поток ушёл в offload: ядро больше не считает его пакеты, и
        # «данных мало» ничего не значит. Много данных — успех.
        return (ga.OK, "") if inn >= OK_REPLY_PAYLOAD else None
    if c.state == "CLOSE":
        # CLOSE — это RST. Клиент спросил, а данных в ответ почти нет.
        if out > 0 and inn < RESET_REPLY_PAYLOAD:
            return ga.FAILED, "сброс соединения (RST)"
        return (ga.OK, "") if inn >= RESET_REPLY_PAYLOAD else None
    if c.state.startswith(_TCP_FIN_STATES):
        return (ga.OK, "") if inn > STALL_REPLY_PAYLOAD else None
    if c.state != "ESTABLISHED":
        return None
    if CUT_MIN <= inn <= CUT_MAX:
        # данные встали на 8–32 КБ, клиент ещё шлёт: обрыв «на 16 КБ»
        return (ga.FAILED, "обрыв на 16 КБ") if hung else None
    if inn >= OK_REPLY_PAYLOAD:
        return ga.OK, ""
    if out > 0 and inn <= STALL_REPLY_PAYLOAD and \
            c.rpackets <= STALL_REPLY_PACKETS and age >= STALL_AGE and (
                c.opackets >= STALL_OUT_PACKETS or c.dport in WEB_PORTS
                or kind in (ga.WEB, ga.DNS)):
        return ga.FAILED, "соединение есть, данных нет"
    if inn > STALL_REPLY_PAYLOAD and age >= STALL_AGE:
        return ga.OK, ""
    return None


def _judge_udp(c: Conn, age: float, kind: str):
    replied = (c.rpackets or 0) > 0 if c.counted else not c.unreplied
    if replied:
        return ga.OK, ""
    if age < UDP_AGE:
        return None
    sent = c.opackets if c.counted else 1
    if kind == ga.LOCAL_PORT:
        return (ga.FAILED, "нет ответа") if sent > 0 else None
    asked = 1 if kind == ga.DNS or c.dport == 53 else 2
    if sent < asked:
        return None
    return ga.FAILED, "запросы без ответа"


# ───────────────────────────── ключ сервиса ─────────────────────────

def classify(c: Conn, name: str = "", app: str = "", p2p: bool = False):
    """``(kind, key, shown, app)`` соединения, как ``AutoObserver.Sample``.

    ``app`` — протокол, если он известен из захвата; иначе транспорт.
    ``p2p`` — веер узлов с одного UDP-порта (DHT без захвата).
    """
    transport = c.proto
    name = (name or "").strip().strip(".").lower()
    app = app or ""
    if app == "dht" or (p2p and transport == "udp" and not app):
        app = app or "p2p"
        key = ga.service_key(ga.LOCAL_PORT, transport, client=c.src,
                             local_port=c.sport)
        shown = "%s (%s %d)" % (ga.app_title(app), transport.upper(),
                                c.sport)
        return ga.LOCAL_PORT, key, shown, app
    if c.dport == 53 or app == "dns":
        return (ga.DNS, ga.service_key(ga.DNS, transport, ip=c.dst),
                "DNS " + c.dst, app or "dns")
    if transport == "tcp" and name and (app in ("tls", "http")
                                        or c.dport in WEB_PORTS):
        site = ga.registrable(name)
        return ga.WEB, ga.service_key(ga.WEB, transport, site=site), site, \
            app or ("http" if c.dport == 80 else "tls")
    if transport == "udp" and name and (app == "quic" or (
            not app and c.dport == 443)):
        # QUIC Initial conntrack не видит; UDP 443 к сайту с именем из
        # DNS на деле и есть QUIC.
        site = ga.registrable(name)
        return ga.QUIC, ga.service_key(ga.QUIC, transport, site=site), \
            site + " (QUIC)", "quic"
    app = app or transport
    ep = ga.ep_text(c.dst, c.dport)
    key = ga.service_key(ga.ENDPOINT, transport, ip=c.dst, port=c.dport,
                         app=app)
    shown = "%s %s" % (ga.app_title(app),
                       ep if not name else "%s (%s)" % (name, ep))
    return ga.ENDPOINT, key, shown, app


def fanout_ports(conns) -> set:
    """``{(client, sport)}`` UDP-портов, с которых клиент ходит к
    ≥ ``P2P_FANOUT`` разным адресам (DHT, торренты, P2P-клиенты)."""
    peers = {}
    for c in conns:
        if c.proto != "udp" or c.dport == 53:
            continue
        peers.setdefault((c.src, c.sport), set()).add(c.dst)
    return {k for k, v in peers.items() if len(v) >= P2P_FANOUT}


# ───────────────────────────── протокол по первому пакету ───────────

def is_openvpn(p: bytes, tcp: bool) -> bool:
    """P_CONTROL_HARD_RESET_CLIENT_V2 (7) / _V3 (10), key id 0; по TCP —
    после двухбайтовой длины."""
    if tcp:
        if len(p) < 16 or struct.unpack(">H", p[:2])[0] != len(p) - 2:
            return False
        p = p[2:]
    return len(p) >= 14 and (p[0] >> 3) in (7, 10) and (p[0] & 7) == 0


def is_dht(p: bytes) -> bool:
    """Сообщение Mainline DHT (BEP 5): bencode-словарь q/r/e."""
    if len(p) < 12 or p[:1] != b"d" or p[-1:] != b"e":
        return False
    return b"1:y1:q" in p or b"1:y1:r" in p or b"1:y1:e" in p


def is_stun(p: bytes) -> bool:
    return (len(p) >= 20 and (p[0] & 0xC0) == 0 and (p[3] & 3) == 0
            and p[4:8] == b"\x21\x12\xa4\x42"
            and struct.unpack(">H", p[2:4])[0] <= len(p) - 20)


def is_ice_check(p: bytes) -> bool:
    """STUN с USERNAME/MESSAGE-INTEGRITY: повтор узел проигнорирует."""
    if not is_stun(p):
        return False
    end = min(len(p), 20 + struct.unpack(">H", p[2:4])[0])
    pos = 20
    while pos + 4 <= end:
        typ, ln = struct.unpack(">HH", p[pos:pos + 4])
        if typ in (0x0006, 0x0008, 0x001C, 0x8029, 0x802A):
            return True
        pos += 4 + ((ln + 3) & ~3)
    return False


def is_discord_ip_discovery(p: bytes) -> bool:
    return (len(p) == 74 and p[:4] == b"\x00\x01\x00\x46"
            and not any(p[8:72]))


def is_wireguard(p: bytes) -> bool:
    if len(p) < 4:
        return False
    head = struct.unpack(">I", p[:4])[0]
    return {0x01000000: 148, 0x02000000: 92, 0x03000000: 64,
            0x04000000: 32}.get(head) == len(p)


def is_dtls(p: bytes) -> bool:
    return (len(p) > 13 and 0x14 <= p[0] <= 0x17
            and ((p[1] == 0xFE and p[2] in (0xFF, 0xFD, 0xFC))
                 or (p[1] == 0x01 and p[2] == 0x00))
            and struct.unpack(">H", p[11:13])[0] + 13 <= len(p))


def is_dns_query(p: bytes) -> bool:
    return (len(p) >= 12 and (p[2] & 0xFE) == 0
            and p[4:10] == b"\x00\x01\x00\x00\x00\x00"
            and struct.unpack(">H", p[10:12])[0] <= 3)


def is_dns_response(p: bytes) -> bool:
    return (len(p) >= 12 and (p[2] & 0xF8) == 0x80
            and struct.unpack(">H", p[4:6])[0] == 1
            and all(struct.unpack(">H", p[k:k + 2])[0] <= 100
                    for k in (6, 8, 10)))


_QUIC_VERSIONS = (0x00000001, 0x6B3343CF, 0xFF00001D, 0xFF00001E,
                  0xFF00001F, 0xFF000020, 0xFF000021, 0xFF000022)


def is_quic_initial(p: bytes) -> bool:
    """Длинный заголовок QUIC Initial (v1, v2, черновики 29–34)."""
    if len(p) < 1200 or (p[0] & 0xC0) != 0xC0:
        return False
    version = struct.unpack(">I", p[1:5])[0]
    if version not in _QUIC_VERSIONS:
        return False
    ptype = (p[0] >> 4) & 3
    # у v2 (RFC 9369) Initial — тип 1, у остальных — 0
    return ptype == (1 if version == 0x6B3343CF else 0)


def is_tls_client_hello(p: bytes) -> bool:
    return (len(p) >= 11 and p[0] == 0x16 and p[1] == 0x03 and p[2] <= 3
            and p[5] == 0x01 and p[9] == 0x03 and p[10] <= 3)


_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"OPTIONS ", b"PUT ",
                 b"DELETE ", b"CONNECT ", b"TRACE ", b"PATCH ")


def is_http_request(p: bytes) -> bool:
    if not p.startswith(_HTTP_METHODS):
        return False
    line = p.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    parts = line.split()
    return len(parts) >= 3 and parts[2].startswith(b"HTTP/1.")


def detect_app(p: bytes, transport: str) -> str:
    """Протокол по первому пакету клиента (``AutoObserver.AppName`` и
    детектор nfqws2): ``""`` — не узнан."""
    p = bytes(p or b"")
    if not p:
        return ""
    tcp = transport == "tcp"
    if not tcp and is_dht(p):
        return "dht"
    if is_openvpn(p, tcp):
        return "openvpn"
    if tcp:
        if is_tls_client_hello(p):
            return "tls"
        if is_http_request(p):
            return "http"
        return ""
    if is_quic_initial(p):
        return "quic"
    if is_discord_ip_discovery(p):
        return "discord"
    if is_stun(p):
        return "stun"
    if is_dns_query(p) or is_dns_response(p):
        return "dns"
    if is_dtls(p) and p[0] == 0x16 and p[13] in (1, 2):
        return "dtls"
    if is_wireguard(p):
        return "wireguard"
    return ""


def can_replay(app: str, payloads) -> bool:
    """Повтор первых пакетов покажет рабочую стратегию: только
    рукопожатия ``REPLAYABLE_APPS`` и не ICE-проверки STUN."""
    if not payloads or app not in ga.REPLAYABLE_APPS:
        return False
    if app == "stun" and is_ice_check(payloads[0]):
        return False
    return True


def analyze_capture(packets, server: str, port: int, transport: str,
                    local_port: int = 0) -> dict:
    """Захват первых пакетов → ``{app, host, replay, outgoing}``.

    ``packets`` — записи :func:`core.pcap_reader.read_bytes` с
    ``payload``. Исходящие — к ``server:port`` (или с ``local_port``
    для P2P). Захват идёт на всех интерфейсах сразу: копии пакета с
    LAN-стороны и с WAN (до и после NAT) склеиваются по payload'у.
    ``replay`` — начало потока, где увидено рукопожатие: у TCP — данные
    после SYN, у UDP — подряд идущие датаграммы того же протокола.
    """
    flows = {}
    order = []
    for pk in packets or []:
        if pk.get("error") or pk.get("proto") != transport:
            continue
        if local_port:
            out = pk.get("sport") == local_port
        else:
            out = pk.get("dst") == server and pk.get("dport") == port
        if not out:
            continue
        fid = pk.get("sport")
        if fid not in flows:
            flows[fid] = {"syn": False, "payloads": [], "seqs": set(),
                          "src": pk.get("src") or ""}
            order.append(fid)
        f = flows[fid]
        flags = pk.get("flags") or []
        if "SYN" in flags and "ACK" not in flags:
            f["syn"] = True
        data = pk.get("payload") or b""
        if not data:
            continue
        if transport == "tcp":
            seq = pk.get("seq")
            if seq in f["seqs"]:
                continue                  # повтор или копия до/после NAT
            f["seqs"].add(seq)
        elif f["payloads"] and f["payloads"][-1] == data:
            continue                      # та же датаграмма на втором iface
        f["payloads"].append(bytes(data))

    best = {"app": "", "host": "", "replay": [], "outgoing": 0,
            "src": "", "sport": 0}
    for fid in order:
        f = flows[fid]
        pls = f["payloads"]
        best["outgoing"] += len(pls)
        if not pls:
            continue
        if transport == "tcp":
            app = detect_app(pls[0], "tcp")
            start = 0 if f["syn"] else None
        else:
            start = None
            app = ""
            for k, p in enumerate(pls):
                app = detect_app(p, "udp")
                if app:
                    start = k
                    break
        if not app:
            continue
        host = ""
        if app == "tls":
            from core.pcap_reader import tls_sni
            host = tls_sni(b"".join(pls[:MAX_REPLAY]))
        elif app == "http":
            from core.pcap_reader import http_host
            host = http_host(pls[0])[0]
        replay = []
        if start is not None and transport == "tcp":
            replay = _first_message(pls, app)
        elif start is not None:
            size = 0
            for p in pls[start:start + MAX_REPLAY]:
                if transport == "udp" and replay and \
                        detect_app(p, "udp") != app:
                    break
                if size + len(p) > MAX_REPLAY_BYTES:
                    break
                replay.append(p)
                size += len(p)
        if not can_replay(app, replay):
            replay = []
        cand = {"app": app, "host": (host or "").lower().strip("."),
                "replay": replay, "src": f["src"], "sport": fid or 0}
        # лучше поток с повтором, затем — с узнанным протоколом
        if not best["app"] or (replay and not best["replay"]):
            best.update(cand)
        if best["replay"]:
            break
    return best


def _first_message(segments, app: str) -> list:
    """Первое сообщение клиента по TCP из сегментов после SYN.

    Повторяется только оно (ClientHello, hard reset OpenVPN): дальше
    у TLS идут Finished и данные сессии, их повтор бессмыслен. Длина —
    из заголовка записи TLS или двухбайтовой длины OpenVPN.
    """
    data = b""
    for p in segments[:MAX_REPLAY]:
        data += p
        if len(data) >= 5:
            break_at = 0
            if app == "tls":
                break_at = 5 + struct.unpack(">H", data[3:5])[0]
            elif app == "openvpn":
                break_at = 2 + struct.unpack(">H", data[0:2])[0]
            if break_at and len(data) >= break_at:
                data = data[:break_at]
                break
    if not data or len(data) > MAX_REPLAY_BYTES:
        return []
    return [data]


# ───────────────────────────── срез ─────────────────────────────────

@dataclass
class _Track:
    first: float                  # когда впервые увидели (или начало)
    verdict: str = ""             # уже отданный вердикт: ok | failed | …
    rbytes: int = 0
    opackets: int = 0
    rchange: float = 0.0          # когда последний раз рос ответ
    seen: float = 0.0


def build_samples(conns, now: float, tracks: dict, *, local=None,
                  names=None, learned=None, learned_ports=None,
                  sticky=None, stats=None) -> list:
    """Чистая часть среза: записи conntrack → ``[Sample]``.

    ``tracks`` — память наблюдателя между срезами (``cid → _Track``),
    правится на месте: одно TCP-соединение даёт один вердикт (успех
    после провала — ещё один), UDP после первого вердикта судится по
    приросту счётчиков за срез. ``names`` — ``{ip: имя}`` из DNS,
    ``learned`` — ``{(transport, ip, port): (app, host)}`` из захватов,
    ``learned_ports`` — ``{(клиент или "", исходный порт): app}``: UDP-порт
    клиента, на котором захват увидел DHT,
    ``sticky`` — ``{(transport, ip, port): ключ}``: ключ ``ep:`` не
    меняется, когда протокол узнан позже.
    """
    names = names or {}
    learned = learned or {}
    learned_ports = learned_ports or {}
    sticky = sticky if sticky is not None else {}
    st = stats if stats is not None else {}
    st.setdefault("connections", 0)
    st.setdefault("observed", 0)
    st.setdefault("skipped", {})
    st.setdefault("offload", 0)
    st.setdefault("samples", 0)
    st.setdefault("counted", 0)
    kept = []
    for c in conns:
        st["connections"] += 1
        if c.counted:
            st["counted"] += 1
        why = skip_reason(c, local)
        if why:
            st["skipped"][why] = st["skipped"].get(why, 0) + 1
            continue
        kept.append(c)
    fan = fanout_ports(kept)
    out = []
    alive = set()
    for c in kept:
        st["observed"] += 1
        if c.offload:
            st["offload"] += 1
        cid = c.cid
        alive.add(cid)
        tr = tracks.get(cid)
        if tr is None:
            if len(tracks) >= MAX_TRACKED:
                continue
            first = now - c.delta if c.delta is not None else now
            tr = _Track(first=first, rbytes=c.rbytes or 0,
                        opackets=c.opackets or 0, rchange=now)
            tracks[cid] = tr
        elif c.delta is not None:
            tr.first = min(tr.first, now - c.delta)
        age = now - tr.first
        # данные ответа выросли — отметка; клиент шлёт, а ответа нет
        rb, op = c.rbytes or 0, c.opackets or 0
        hung = False
        if rb != tr.rbytes:
            tr.rchange = now
        elif op > tr.opackets and now - tr.rchange >= STALL_GAP:
            hung = True
        prev_rb, prev_op = tr.rbytes, tr.opackets
        tr.rbytes, tr.opackets, tr.seen = rb, op, now

        app, host = learned.get((c.proto, c.dst, c.dport), ("", ""))
        if c.proto == "udp" and (learned_ports.get((c.src, c.sport)) or
                                 learned_ports.get(("", c.sport))):
            app = learned_ports.get((c.src, c.sport)) or \
                learned_ports[("", c.sport)]
        name = host or names.get(c.dst, "")
        kind, key, shown, app = classify(
            c, name=name, app=app, p2p=(c.src, c.sport) in fan)
        if kind == ga.ENDPOINT:
            skey = (c.proto, c.dst, c.dport)
            key = sticky.setdefault(skey, key)
        if local is not None and c.dst in local.servers:
            # внешнее соединение туннеля zapret-gui: видно, чьё оно
            shown = "Туннель: " + shown

        verdict = None
        t = tr.first
        if c.proto == "udp" and tr.verdict and c.counted:
            # долгий UDP-поток: прирост за срез
            d_out, d_in = op - prev_op, rb - prev_rb
            if d_in > 0 and d_out > 0:
                verdict = (ga.OK, "")
            elif d_out >= (1 if kind in (ga.DNS, ga.LOCAL_PORT) else 2) \
                    and d_in == 0:
                verdict = (ga.FAILED, "запросы без ответа")
            t = now
        elif tr.verdict != ga.OK:
            verdict = judge(c, age, kind, hung)
            # Одно соединение — один провал: «нет соединения», потом
            # «данных нет» не два провала. После провала отдаётся только
            # успех (сайт всё-таки ответил).
            if verdict is not None and tr.verdict and verdict[0] != ga.OK:
                verdict = None
        if verdict is None:
            continue
        tr.verdict = verdict[0]
        out.append(ga.Sample(
            key=key, kind=kind, transport=c.proto, name=shown, app=app,
            ip="" if kind == ga.LOCAL_PORT else c.dst,
            port=0 if kind == ga.LOCAL_PORT else c.dport,
            local_port=c.sport, client=c.src, time=t,
            health=verdict[0], why=verdict[1],
            host=name if kind in (ga.WEB, ga.QUIC) else (host or "")))
    for cid in [k for k in tracks if k not in alive]:
        del tracks[cid]
    st["samples"] += len(out)
    return out


# ───────────────────────────── адреса роутера ───────────────────────

def parse_ip_addr(text: str, wan=()) -> Local:
    """Вывод ``ip -o addr show`` → :class:`Local`.

    Адреса всех интерфейсов — собственные. Сети IPv6 с глобальными
    адресами на не-WAN интерфейсах — LAN (клиенты без NAT). Адреса
    туннельных интерфейсов (по имени, кроме WAN) — туннели.
    """
    loc = Local()
    wan = set(wan or ())
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue
        ifname = parts[1].split("@", 1)[0].rstrip(":")
        try:
            iface = ipaddress.ip_interface(parts[3])
        except ValueError:
            continue
        ip = str(iface.ip)
        loc.own.add(ip)
        tunnel = ifname not in wan and ifname.lower().startswith(
            TUNNEL_PREFIXES)
        if tunnel:
            loc.tunnel.add(ip)
            continue
        if iface.version == 6 and iface.ip.is_global and ifname not in wan \
                and iface.network.prefixlen < 128:
            loc.nets.append(iface.network)
    return loc


def parse_wg_endpoints(text: str) -> set:
    """``awg/wg show all endpoints`` → адреса серверов туннелей."""
    out = set()
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] in ("(none)", ""):
            continue
        ep = parts[2]
        host = ep[1:ep.index("]")] if ep.startswith("[") and "]" in ep \
            else ep.rsplit(":", 1)[0]
        host = _norm_ip(host)
        if host:
            out.add(host)
    return out


OPENWRT_FIREWALL = "/etc/config/firewall"
OFFLOAD_TEXT = (
    "включено ускорение NAT (flow offloading): установленные соединения "
    "клиентов идут мимо netfilter, и geneva не видит их ClientHello — "
    "найденные стратегии сработают только для самого роутера. Выключите "
    "его: OpenWrt — «Сеть → Межсетевой экран → Программная/аппаратная "
    "разгрузка потоков» (flow_offloading, flow_offloading_hw); Keenetic — "
    "аппаратное ускорение (hwnat/PPE)")
OFFLOAD_TEXT_EN = (
    "NAT acceleration (flow offloading) is on: established client "
    "connections bypass netfilter and geneva never sees their ClientHello, "
    "so strategies work only for the router itself. Turn it off "
    "(OpenWrt: Network → Firewall → software/hardware flow offloading; "
    "Keenetic: hardware NAT/PPE)")


def openwrt_offload(text: str) -> bool:
    """``/etc/config/firewall`` OpenWrt: в ``defaults`` включён
    ``flow_offloading`` или ``flow_offloading_hw``."""
    section = ""
    for raw in (text or "").splitlines():
        parts = raw.split()
        if not parts:
            continue
        if parts[0] == "config":
            section = parts[1].strip("'\"") if len(parts) > 1 else ""
        elif parts[0] == "option" and section == "defaults" and \
                len(parts) >= 3 and parts[1] in ("flow_offloading",
                                                 "flow_offloading_hw"):
            if parts[2].strip("'\"") in ("1", "on", "true", "yes"):
                return True
    return False


def offload_enabled(stats: dict = None, path: str = OPENWRT_FIREWALL) -> bool:
    """Ускорение NAT мешает «Авто»: потоки ``[OFFLOAD]`` в срезе или
    включённый offload в конфигурации OpenWrt. Отличие: на ПК AutoTuner
    такой проблемы нет."""
    if stats and int(stats.get("offload", 0) or 0) > 0:
        return True
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return openwrt_offload(f.read())
    except OSError:
        return False


def install_hint() -> str:
    return ("поставьте пакет conntrack: «opkg install conntrack» (Entware, "
            "OpenWrt до 24.10), «apk add conntrack» (OpenWrt 25+), "
            "«apt install conntrack» (Linux) / install the conntrack "
            "package")


# ───────────────────────────── I/O: наблюдатель ─────────────────────

class ObserverError(RuntimeError):
    """Наблюдать нечем: ``code`` и подсказка, что поставить."""

    def __init__(self, code: str, message: str, hint: str = ""):
        super().__init__(message)
        self.code = code
        self.hint = hint


def _run(argv, timeout=10):
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return r.returncode, r.stdout.decode("utf-8", "replace")


class Observer:
    """Срезы conntrack для менеджера режима. Им владеет поток режима;
    фоновый захват (:meth:`identify_async`) пишет узнанное под замком.

    Все внешние зависимости подменяемы (тесты): ``reader()`` — строки
    таблицы, ``names()`` — карта «IP → имя», ``local()`` — :class:`Local`,
    ``capture(host, port, proto)`` — результат ``capture_first``.
    """

    def __init__(self, *, reader=None, names=None, local=None,
                 capture=None, clock=time.time, sysctl_dir=SYSCTL_DIR,
                 exclude=(), help_tunnels: bool = True, sniffer=None):
        self._reader = reader
        # Сборщик имён (core/name_sniffer): DNS-ответы и SNI всё время
        # режима. Отличие: в AutoTuner имена даёт захват всего трафика ПК.
        self._sniffer = sniffer
        self._names = names
        self._local = local
        self._capture = capture
        self._clock = clock
        self._sysctl_dir = sysctl_dir
        self._exclude = set(exclude or ())
        # Внешние соединения туннелей наблюдаются (geneva поможет и им);
        # False — серверы туннелей исключаются, как раньше.
        self.help_tunnels = bool(help_tunnels)
        self._saved = {}                 # sysctl → прежнее значение
        self._tracks = {}
        self._sticky = {}
        self._learned = {}               # (proto, ip, port) → (app, host)
        self._learned_ports = {}         # (клиент | "", порт) → app
        self._extra_names = {}           # ip → имя из захвата (SNI)
        self._local_cache = (0.0, None)
        # Замок на всё, что меняет фоновый захват (identify_async) и
        # читает срез: словари узнанного и очередь итогов.
        self._jobs_lock = threading.RLock()
        self._job = None
        self._done = []
        self.source = ""
        self.last_stats = {}

    # ── источник ──

    def check(self) -> dict:
        """Чем наблюдать. ``ObserverError`` — нечем (с подсказкой)."""
        if self._reader is not None:
            self.source = "custom"
            return {"source": self.source}
        for path in CONNTRACK_FILES:
            if os.path.exists(path):
                self.source = path
                return {"source": "proc", "path": path}
        binary = self._conntrack_binary()
        if binary:
            self.source = binary
            return {"source": "conntrack", "path": binary}
        if os.path.exists(os.path.join(self._sysctl_dir,
                                       "nf_conntrack_max")):
            raise ObserverError(
                "conntrack_tool_missing",
                "таблица соединений не видна: /proc/net/nf_conntrack нет, "
                "утилиты conntrack нет / no conntrack table access",
                install_hint())
        raise ObserverError(
            "conntrack_unsupported",
            "ядро без conntrack: режим «Авто» не поддерживается / "
            "kernel has no conntrack, Auto mode is not supported",
            "")

    @staticmethod
    def _conntrack_binary() -> str:
        for cand in CONNTRACK_CANDIDATES:
            found = shutil.which(cand) if "/" not in cand else (
                cand if os.access(cand, os.X_OK) else "")
            if found:
                return found
        return ""

    def _lines(self) -> list:
        if self._reader is not None:
            return list(self._reader())
        if not self.source:
            self.check()
        if self.source.startswith("/proc/"):
            out = []
            with open(self.source, "r", encoding="utf-8",
                      errors="replace") as f:
                for n, line in enumerate(f):
                    if n >= MAX_LINES:
                        break
                    out.append(line)
            return out
        # Без -f conntrack -L отдаёт только IPv4.
        rc, text = _run([self.source, "-L", "-o", "extended"], timeout=15)
        if rc != 0 and not text:
            raise ObserverError("conntrack_failed",
                                "conntrack -L не отработал", install_hint())
        _rc6, text6 = _run([self.source, "-L", "-f", "ipv6", "-o",
                            "extended"], timeout=15)
        return (text.splitlines() + text6.splitlines())[:MAX_LINES]

    # ── учёт пакетов и время соединений ──

    def enable_accounting(self) -> dict:
        """``nf_conntrack_acct=1`` и ``nf_conntrack_timestamp=1`` на время
        режима; прежние значения запоминаются для :meth:`restore`.
        Возвращает ``{sysctl: True | False | None}``: ``True`` — включено,
        ``False`` — файл есть, но запись не прошла (права, RO), ``None`` —
        файла нет: ядро не даёт управлять учётом (Keenetic NDMS 14.x:
        счётчики ``packets=`` в таблице есть всегда). Есть ли учёт на
        деле, видно только по срезу: ``last_stats["counted"]``."""
        out = {}
        for name in SYSCTLS:
            path = os.path.join(self._sysctl_dir, name)
            try:
                with open(path) as f:
                    old = f.read().strip()
            except OSError:
                out[name] = None
                continue
            if old != "1":
                try:
                    with open(path, "w") as f:
                        f.write("1")
                    self._saved.setdefault(name, old)
                except OSError as e:
                    log.warning("geneva-auto: %s=1 не включён: %s"
                                % (name, e), source="geneva")
                    out[name] = False
                    continue
            out[name] = True
        if self._sniffer is not None:
            try:
                out["names"] = bool(self._sniffer.start("geneva-auto"))
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: сборщик имён: %s" % e,
                          source="geneva")
                out["names"] = False
        return out

    def restore(self) -> None:
        """Вернуть sysctl, как было до режима; остановить сборщик имён."""
        if self._sniffer is not None:
            try:
                self._sniffer.stop("geneva-auto")
            except Exception:                       # noqa: BLE001
                pass
        for name, old in list(self._saved.items()):
            try:
                with open(os.path.join(self._sysctl_dir, name), "w") as f:
                    f.write(old)
                del self._saved[name]
            except OSError as e:
                log.warning("geneva-auto: %s не восстановлен: %s"
                            % (name, e), source="geneva")

    @property
    def saved_sysctls(self) -> dict:
        return dict(self._saved)

    # ── что своё ──

    def local(self) -> Local:
        if self._local is not None:
            loc = self._local()
        else:
            at, cached = self._local_cache
            now = self._clock()
            if cached is None or now - at > 60:
                cached = self._read_local()
                self._local_cache = (now, cached)
            loc = cached
        extra = set(self._exclude)
        if not self.help_tunnels:
            extra |= set(loc.servers)
        if extra:
            loc = Local(own=set(loc.own), nets=list(loc.nets),
                        tunnel=set(loc.tunnel),
                        exclude=set(loc.exclude) | extra,
                        servers=set(loc.servers))
        return loc

    @staticmethod
    def _read_local() -> Local:
        try:
            from core.firewall import _detect_wan_from_routes
            wan = _detect_wan_from_routes()
        except Exception:                           # noqa: BLE001
            wan = []
        _rc, text = _run(["ip", "-o", "addr", "show"], timeout=5)
        loc = parse_ip_addr(text, wan)
        for tool in ("awg", "wg"):
            if shutil.which(tool):
                _rc, text = _run([tool, "show", "all", "endpoints"],
                                 timeout=5)
                loc.servers |= parse_wg_endpoints(text)
        return loc

    def set_exclude(self, ips) -> None:
        """Адреса, которые не наблюдать (``geneva.auto.exclude``)."""
        self._exclude = {_norm_ip(str(x)) for x in ips or []} - {""}

    def names(self) -> dict:
        if self._names is not None:
            got = dict(self._names())
        else:
            try:
                from core.block_detector import get_block_detector
                got = get_block_detector().refresh_names()
            except Exception as e:                  # noqa: BLE001
                log.debug("geneva-auto: имена DNS: %s" % e, source="geneva")
                got = {}
        with self._jobs_lock:
            got.update(self._extra_names)
        return got

    # ── срез ──

    def seed_keys(self, keys) -> None:
        """Ключи ``ep:`` из книги: после перезапуска тот же сервис
        продолжает свой ключ, даже если протокол узнан позже."""
        for key in keys or []:
            if not key.startswith("ep:"):
                continue
            try:
                _ep, _app, transport, rest = key.split(":", 3)
                host, _, port = rest.rpartition(":")
                ip = _norm_ip(host.strip("[]"))
                if ip:
                    self._sticky.setdefault((transport, ip, int(port)), key)
            except ValueError:
                continue

    def slice(self, now: float = None) -> list:
        """Один срез: ``[Sample]``; сводка — в :attr:`last_stats`."""
        now = self._clock() if now is None else now
        conns = parse_table(self._lines())
        stats = {}
        names = self.names()
        with self._jobs_lock:
            learned = dict(self._learned)
            learned_ports = dict(self._learned_ports)
        samples = build_samples(
            conns, now, self._tracks, local=self.local(),
            names=names, learned=learned,
            learned_ports=learned_ports, sticky=self._sticky,
            stats=stats)
        if len(self._sticky) > ga.MAX_SERVICES * 4:
            # ключи давно ушедших серверов: держим только живые
            alive = {(c.proto, c.dst, c.dport) for c in conns}
            self._sticky = {k: v for k, v in self._sticky.items()
                            if k in alive}
        stats["time"] = now
        stats["source"] = self.source
        self.last_stats = stats
        return samples

    # ── протокол по первым пакетам ──

    def identify(self, ip: str, port: int, transport: str,
                 local_port: int = 0, client: str = "") -> dict:
        """Снять первые пакеты сервиса и узнать протокол (блокирует до
        ``CAPTURE_SECONDS``). ``{app, host, replay, error}``; узнанное
        запоминается: следующие срезы называют сервис по нему.

        Сервис ``endpoint`` — фильтр по адресу и порту сервера;
        ``local_port`` — по ``client`` и его исходному порту.
        """
        host, cport = (client, local_port) if local_port else (ip, port)
        if not host:
            return {"app": "", "host": "", "replay": [],
                    "error": "нет адреса для захвата"}
        try:
            if self._capture is not None:
                got = self._capture(host, cport, transport)
            else:
                from core import traffic_capture
                got = traffic_capture.capture_first(
                    host=host, port=cport, proto=transport,
                    packets=CAPTURE_PACKETS, seconds=CAPTURE_SECONDS)
        except Exception as e:                      # noqa: BLE001
            return {"app": "", "host": "", "replay": [], "error": str(e)}
        res = analyze_capture(got.get("packets") or [], ip, port, transport,
                              local_port=local_port)
        res["error"] = got.get("error") or ""
        app = res["app"]
        if not app:
            return res
        with self._jobs_lock:
            self._remember(res, ip, port, transport, local_port, client)
        return res

    def _remember(self, res, ip, port, transport, local_port, client):
        app = res["app"]
        if not local_port:
            self._learned[(transport, ip, port)] = (app, res["host"])
            if res["host"]:
                self._extra_names[ip] = res["host"]
        if app == "dht" and transport == "udp":
            # весь порт клиента — DHT, не только этот узел
            src = client or (res["src"] if res["src"]
                             and not is_internet(res["src"]) else "")
            sport = local_port or res["sport"]
            if sport:
                self._learned_ports[(src, sport)] = app
        if len(self._learned) > ga.MAX_SERVICES * 4:
            self._learned = dict(list(self._learned.items())[
                -ga.MAX_SERVICES * 2:])
        if len(self._learned_ports) > 1024:
            self._learned_ports = dict(list(self._learned_ports.items())[
                -512:])
        if len(self._extra_names) > 4096:
            self._extra_names = dict(list(self._extra_names.items())[
                -2048:])

    def identify_async(self, key: str, ip: str, port: int, transport: str,
                       local_port: int = 0, client: str = "") -> bool:
        """То же фоном; ``False`` — захват уже идёт. Итог —
        :meth:`identified`."""
        with self._jobs_lock:
            if self._job is not None and self._job.is_alive():
                return False

            def work():
                res = self.identify(ip, port, transport, local_port,
                                    client)
                res["key"] = key
                with self._jobs_lock:
                    self._done.append(res)

            self._job = threading.Thread(target=work, daemon=True,
                                         name="geneva-auto-capture")
            self._job.start()
            return True

    def identified(self) -> list:
        """Готовые итоги :meth:`identify_async` (забираются один раз)."""
        with self._jobs_lock:
            out, self._done = self._done, []
        return out

    @property
    def busy(self) -> bool:
        with self._jobs_lock:
            return self._job is not None and self._job.is_alive()
