# core/geneva_auto.py
"""
Режим «Авто» geneva: чистое ядро (скил geneva, §10).

Пользователь включает один переключатель. Дальше zapret-gui сам следит за
трафиком через роутер, находит заблокированные сервисы любых протоколов,
подтверждает блокировку пробой без обхода, подбирает каждому стратегию
geneva и применяет её только к трафику этого сервиса.

Здесь только чистые функции и данные: время приходит от вызывающего, ни
одного файла, процесса или сокета. Поэтому все правила покрыты тестами
без ожидания. Это перенос ``Core/Geneva/Auto/*`` из Zapret2_AutoTuner
(ветка main): виды сервисов, состояния, пороги (``AutoRules``), машина
состояний (``AutoBook``), группы и цели (``AutoPlan``), шаблоны
стратегий (``AutoCandidates``). Отличия от эталона перечислены в §10
скила и помечены в коде словом «отличие».

Наблюдение (conntrack) — :mod:`core.geneva_auto_observer`, пробы —
:mod:`core.geneva_auto_probes`, цикл, процессы и правила —
:mod:`core.geneva_auto_manager`.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field

from core import geneva_auto_lists as gal
from core.geneva_ext import needs_ext

# ───────────────────────────── виды и состояния ─────────────────────

# Что ищем и к чему применяем (AutoKind).
WEB = "web"              # TLS/HTTP по TCP к сайту (регистрируемый домен)
QUIC = "quic"            # QUIC к сайту: браузер уходит на TCP
DNS = "dns"              # резолвер (порт 53, UDP или TCP)
ENDPOINT = "endpoint"    # любой сервер: WireGuard, OpenVPN, STUN, …
LOCAL_PORT = "local_port"  # программа со многими узлами с одного порта
KINDS = (WEB, QUIC, DNS, ENDPOINT, LOCAL_PORT)

# Где сервис сейчас (AutoStatus).
WATCHING = "watching"
SUSPECTED = "suspected"
BLOCKED = "blocked"
NOT_BLOCKED = "not_blocked"
IP_BLOCKED = "ip_blocked"
FALLBACK = "fallback"
SEARCHING = "searching"
APPLIED = "applied"
DEGRADED = "degraded"
NOT_FOUND = "not_found"
STATUSES = (WATCHING, SUSPECTED, BLOCKED, NOT_BLOCKED, IP_BLOCKED,
            FALLBACK, SEARCHING, APPLIED, DEGRADED, NOT_FOUND)

# Как прошёл один поток (AutoHealth).
OK = "ok"
FAILED = "failed"
NO_CONNECTION = "no_connection"

# Что сказала проба без обхода (AutoConfirm).
C_BLOCKED = "blocked"
C_NOT_BLOCKED = "not_blocked"
C_IP_BLOCKED = "ip_blocked"
C_UNKNOWN = "unknown"

# Подписи состояний для страницы (engine.as_* AutoTuner): ru, en.
STATUS_TEXT = {
    WATCHING: ("работает", "works"),
    SUSPECTED: ("подозрение", "suspected"),
    BLOCKED: ("заблокирован", "blocked"),
    NOT_BLOCKED: ("не заблокирован", "not blocked"),
    IP_BLOCKED: ("блокировка по IP", "blocked by IP"),
    FALLBACK: ("работает через TCP", "works over TCP"),
    SEARCHING: ("подбор обхода", "searching"),
    APPLIED: ("обход работает", "bypassed"),
    DEGRADED: ("обход ослаб", "bypass weakened"),
    NOT_FOUND: ("обход не найден", "no bypass yet"),
}

# ───────────────────────────── пороги (AutoRules) ───────────────────
# Одним блоком, чтобы документация и тесты называли одни и те же числа.

MINUTE = 60.0
HOUR = 3600.0
DAY = 86400.0

WINDOW = 10 * MINUTE              # окно наблюдения
FAILS_TO_SUSPECT = 3              # TCP: провалов без единого успеха
UDP_FAILS_TO_SUSPECT = 2          # UDP: повтор клиента — уже два
PEER_FAILS_TO_SUSPECT = 20        # DHT: мёртвые узлы — норма
NOT_BLOCKED_PAUSE = 1 * HOUR
IP_BLOCKED_PAUSE = 6 * HOUR
RETRY_PAUSE = 1 * HOUR            # «не найдено»: удваивается…
MAX_RETRY_PAUSE = 24 * HOUR       # …до суток
UNKNOWN_RECHECK = 1 * MINUTE      # сервис без пробы: второй срез
FORGET = 30 * DAY
ADDRESS_LIFE = 7 * DAY
MAX_SERVICES = 300
MAX_ADDRESSES = 64
MAX_PORTS = 8
MAX_TIMES = 200                   # отметок времени в одном списке
MAX_REJECTED = 20                 # отвергнутых стратегий у сервиса
REDEGRADE = 30 * MINUTE           # снова ослабла после «проба прошла»
MAX_QUICK_CANDIDATES = 64        # в одном круге перебора (eval)
MAX_CANDIDATES = 192             # всех кругов вместе
OUT_PACKETS = 12                  # пакетов соединения через geneva
IN_PACKETS = 6
POPULATION = 20
GENERATIONS = 10
MORE_GENERATIONS = 5
# Групп одновременно. На роутере 4 (память и CPU), в AutoTuner 8.
# Настройка geneva.auto.max_groups (1–8), очереди 340..340+N-1.
MAX_GROUPS = 4
MAX_GROUPS_LIMIT = 8
QUEUE_BASE = 340

# Сайты за TCP: порт по умолчанию.
WEB_PORT = 443
DNS_PORT = 53

# Протоколы, чьё первое сообщение — рукопожатие, на которое ответит любой
# сервер и в котором нет ничего пользовательского (ReplayableApps).
# Открытый HTTP (cookies) и неизвестные протоколы (логин) не хранятся и
# не повторяются: такие сервисы судятся по их собственному трафику.
REPLAYABLE_APPS = frozenset(("tls", "quic", "dtls", "dns", "stun",
                             "openvpn", "mtproto"))

# Шкала фитнеса geneva (docs/EVAL.md geneva_c).
FIT_OK = 400
FIT_RESET = -360
FIT_NO_CONNECTION = -400
FIT_NO_ANSWER = -400
FIT_CLOSED = -480

APP_TITLES = {
    "wireguard": "WireGuard", "openvpn": "OpenVPN", "dtls": "DTLS",
    "stun": "STUN", "mtproto": "MTProto", "discord": "Discord",
    "quic": "QUIC", "tls": "TLS", "http": "HTTP", "dns": "DNS",
    "dht": "DHT", "p2p": "P2P",
}


def app_title(app: str) -> str:
    return APP_TITLES.get(app or "", (app or "?").upper())


# ───────────────────────────── данные ───────────────────────────────

@dataclass
class Sample:
    """Один поток наблюдения, отнесённый к своему сервису (AutoSample)."""
    key: str
    kind: str
    transport: str            # tcp | udp
    name: str
    app: str
    ip: str = ""              # сервер ("" у local_port)
    port: int = 0
    local_port: int = 0
    client: str = ""          # IP клиента LAN (или самого роутера)
    time: float = 0.0
    health: str = OK
    why: str = ""
    host: str = ""            # полное имя (SNI или ответ DNS)
    replay: list = field(default_factory=list)   # [bytes, …]


@dataclass
class Service:
    """Сервис режима со всем, что о нём известно (AutoService)."""
    key: str
    kind: str = ENDPOINT
    transport: str = "tcp"
    name: str = ""
    host: str = ""
    app: str = ""
    addresses: list = field(default_factory=list)   # [{"ip", "seen"}]
    ports: list = field(default_factory=list)
    local_port: int = 0
    client: str = ""
    replay: str = ""          # base64 через запятую
    status: str = WATCHING
    since: float = 0.0
    why: str = ""
    strategy: str = None
    fitness: float = 0.0
    applied_at: float = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    fails: list = field(default_factory=list)
    oks: list = field(default_factory=list)
    no_connections: list = field(default_factory=list)
    next_check: float = None
    attempts: int = 0
    suspicions: int = 0
    restored_at: float = None   # проба с обходом вернула в applied
    rejected: list = field(default_factory=list)  # не работают у устройств
    # Важность (core/geneva_auto_lists): вычисленная и слово пользователя.
    priority: int = 1
    user_priority: str = ""
    pinned: bool = False        # провалы не ведут к новому подбору
    pinned_warned: bool = False  # журнал уже сказал (не сохраняется)
    baseline_at: float = None   # последнее «заблокирован» без обхода
    detected: list = field(default_factory=list)   # отметки детектора
    detected_why: str = ""
    # Критерий успеха страницы, найденный без обхода (шейпер, обрыв
    # 16 КБ): {"min_rate", "pad", "min_bytes"}; пусто — обычная загрузка.
    criteria: dict = field(default_factory=dict)

    # ── свойства ──

    @property
    def can_replay(self) -> bool:
        return bool(self.replay)

    @property
    def probeable(self) -> bool:
        """Проба без обхода может судить: загрузка страницы, повтор
        первых пакетов или свежий запрос (DNS, STUN)."""
        return (self.kind in (WEB, DNS) or self.can_replay
                or self.app == "stun")

    @property
    def port(self) -> int:
        if self.ports:
            return int(self.ports[0])
        if self.kind in (WEB, QUIC):
            return WEB_PORT
        if self.kind == DNS:
            return DNS_PORT
        return 0

    @property
    def address(self) -> str:
        """Новейший адрес: туда идут пробы."""
        best = None
        for a in self.addresses:
            if _valid_ip(a.get("ip")) and (best is None
                                          or a.get("seen", 0) >
                                          best.get("seen", 0)):
                best = a
        return best["ip"] if best else ""

    @property
    def peer(self) -> bool:
        """Пир или фон: места книги для сайтов ему не достаются."""
        return self.priority >= gal.LOW

    @property
    def is_active(self) -> bool:
        """Стратегия включена. Не во время подбора: пробы подбора идут на
        те же адреса, и две стратегии на одном пакете не судят ни одну."""
        return self.status in (APPLIED, DEGRADED) and bool(self.strategy)

    def clone(self) -> "Service":
        return Service.from_dict(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "key": self.key, "kind": self.kind, "transport": self.transport,
            "name": self.name, "host": self.host, "app": self.app,
            "addresses": [dict(a) for a in self.addresses],
            "ports": list(self.ports), "local_port": self.local_port,
            "client": self.client, "replay": self.replay,
            "status": self.status, "since": self.since, "why": self.why,
            "strategy": self.strategy, "fitness": self.fitness,
            "applied_at": self.applied_at, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "fails": list(self.fails),
            "oks": list(self.oks),
            "no_connections": list(self.no_connections),
            "next_check": self.next_check, "attempts": self.attempts,
            "suspicions": self.suspicions,
            "restored_at": self.restored_at,
            "rejected": list(self.rejected),
            "priority": self.priority,
            "user_priority": self.user_priority,
            "pinned": self.pinned,
            "baseline_at": self.baseline_at,
            "detected": list(self.detected),
            "detected_why": self.detected_why,
            "criteria": dict(self.criteria),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        d = d or {}

        def num(key, default=0.0):
            try:
                v = d.get(key)
                return default if v is None else float(v)
            except (TypeError, ValueError):
                return default

        def opt(key):
            v = d.get(key)
            try:
                return None if v is None else float(v)
            except (TypeError, ValueError):
                return None

        def times(key):
            out = []
            for t in d.get(key) or []:
                try:
                    out.append(float(t))
                except (TypeError, ValueError):
                    continue
            return out[-MAX_TIMES:]

        addrs = []
        for a in d.get("addresses") or []:
            if isinstance(a, dict) and _valid_ip(a.get("ip")):
                try:
                    addrs.append({"ip": str(a["ip"]),
                                  "seen": float(a.get("seen") or 0)})
                except (TypeError, ValueError):
                    continue
        ports = []
        for p in d.get("ports") or []:
            try:
                p = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= p <= 65535 and p not in ports:
                ports.append(p)
        kind = d.get("kind") if d.get("kind") in KINDS else ENDPOINT
        status = d.get("status") if d.get("status") in STATUSES \
            else WATCHING
        strategy = d.get("strategy")
        return cls(
            key=str(d.get("key") or ""), kind=kind,
            transport="udp" if d.get("transport") == "udp" else "tcp",
            name=str(d.get("name") or "")[:200],
            host=str(d.get("host") or "")[:253],
            app=str(d.get("app") or "")[:20],
            addresses=addrs[-MAX_ADDRESSES:], ports=ports[:MAX_PORTS],
            local_port=int(num("local_port")),
            client=str(d.get("client") or "") if _valid_ip(
                d.get("client")) else "",
            replay=str(d.get("replay") or ""),
            status=status, since=num("since"),
            why=str(d.get("why") or "")[:300],
            strategy=str(strategy) if strategy else None,
            fitness=num("fitness"), applied_at=opt("applied_at"),
            first_seen=num("first_seen"), last_seen=num("last_seen"),
            fails=times("fails"), oks=times("oks"),
            no_connections=times("no_connections"),
            next_check=opt("next_check"),
            attempts=int(num("attempts")),
            suspicions=int(num("suspicions")),
            restored_at=opt("restored_at"),
            rejected=[str(x) for x in d.get("rejected") or []
                      if isinstance(x, str) and x][-MAX_REJECTED:],
            priority=min(3, max(0, int(num("priority", 1)))),
            user_priority=d.get("user_priority")
            if d.get("user_priority") in ("important", "unimportant")
            else "",
            pinned=bool(d.get("pinned")) and bool(strategy),
            baseline_at=opt("baseline_at"),
            detected=times("detected"),
            detected_why=str(d.get("detected_why") or "")[:120],
            criteria=_criteria(d.get("criteria")),
        )


def _criteria(value) -> dict:
    """Критерий страницы из файла: только известные числа."""
    out = {}
    if not isinstance(value, dict):
        return out
    for k in ("min_rate", "pad", "min_bytes"):
        try:
            v = int(value.get(k) or 0)
        except (TypeError, ValueError):
            continue
        if v > 0:
            out[k] = v
    return out


def _valid_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value or ""))
        return True
    except ValueError:
        return False


# ───────────────────────────── ключи ────────────────────────────────

def registrable(name: str) -> str:
    """Регистрируемый домен той же функцией, что у автообнаружения."""
    from core.registrable import registrable as _reg
    name = (name or "").strip().strip(".").lower()
    return _reg(name) or name


def _family_kept(old: str, new: str) -> bool:
    """Хост с семейством не уступает хосту без семейства: семейство
    сервиса — по хосту (:func:`core.geneva_auto_lists.service_family`),
    и ``youtubei.googleapis.com`` → ``fonts.googleapis.com`` не должен
    то давать, то отнимать у ``googleapis.com`` семейство YouTube."""
    return bool(old) and bool(gal.family_of(old)) and \
        not gal.family_of(new)


def ep_text(ip: str, port: int) -> str:
    return ("[%s]:%d" % (ip, port)) if ":" in ip else ("%s:%d" % (ip, port))


def service_key(kind: str, transport: str, *, ip: str = "", port: int = 0,
                site: str = "", app: str = "", client: str = "",
                local_port: int = 0) -> str:
    """Ключ сервиса, как в AutoTuner (``AutoObserver.Sample``).

    Отличие: у ``port:`` есть IP клиента — на роутере один и тот же
    порт бывает у разных устройств.
    """
    if kind == WEB:
        return "web:" + site
    if kind == QUIC:
        return "quic:" + site
    if kind == DNS:
        return "dns:" + ip
    if kind == LOCAL_PORT:
        return "port:%s:%s:%d" % (transport, client, local_port)
    return "ep:%s:%s:%s" % (app or transport, transport, ep_text(ip, port))


# ───────────────────────────── replay ───────────────────────────────

def to_base64(payloads) -> str:
    return ",".join(base64.b64encode(bytes(p)).decode("ascii")
                    for p in payloads or [] if p)


def from_base64(text: str) -> list:
    if not text:
        return []
    try:
        return [base64.b64decode(part, validate=True)
                for part in str(text).split(",") if part]
    except (ValueError, TypeError):
        return []


# ───────────────────────────── книга (AutoBook) ─────────────────────

_ORDER = {SEARCHING: 0, DEGRADED: 1, APPLIED: 2, BLOCKED: 3, SUSPECTED: 4,
          NOT_FOUND: 5, IP_BLOCKED: 6, FALLBACK: 7, NOT_BLOCKED: 8}
# Внутри одной важности: сайт, DNS, QUIC, сервер, пир (AutoBook.Queue).
_SEARCH_ORDER = {WEB: 0, DNS: 1, QUIC: 2, ENDPOINT: 3}
DETECTOR_CLASSES = ("THROTTLE", "FREEZE_N")
DETECTOR_WHY = {
    "THROTTLE": "детектор geneva: замедление (шейпер)",
    "FREEZE_N": "детектор geneva: заморозка на 8–64 КБ",
}
DNS_POISON_EVERY = HOUR


def threshold(s: Service) -> int:
    if s.kind == LOCAL_PORT:
        return PEER_FAILS_TO_SUSPECT
    if s.transport == "udp":
        return UDP_FAILS_TO_SUSPECT
    return FAILS_TO_SUSPECT


def suspicious(s: Service):
    """``(похоже на DPI, почему)``: провалы и ни одного успеха; или
    детектор geneva видел полку скорости или заморозку — срезу эти потоки
    кажутся удачными, решает проба."""
    why = s.why
    if s.detected:
        return True, s.detected_why or "детектор geneva"
    if s.oks:
        return False, why
    fails = len(s.fails) + len(s.no_connections)
    if s.no_connections and not s.fails:
        why = "соединение не устанавливается"
    return fails >= threshold(s), why


def _move(s: Service, to: str, now: float, why: str) -> None:
    if s.status != to:
        s.status = to
        s.since = now
    if why:
        s.why = why


def handshake_seen(s: Service) -> bool:
    """Адрес сервиса отвечает: в окне есть успехи или (TCP) провалы
    после рукопожатия — «соединение есть, данных нет», сброс, обрыв.
    Отказ «нет соединения» сюда не входит, он — в ``no_connections``.

    Отличие: в эталоне «блокировка по IP» ставится по одной пробе, у
    которой не установилось соединение. На ПК проба идёт с того же
    адреса, что и браузер; на роутере проба — с самого роутера, и таймаут
    её connect (метка, маршрут, временная «чёрная дыра» ТСПУ на весь
    адрес после заблокированного ClientHello) противоречит тому, что
    устройства сети соединяются. Тогда это блокировка по содержимому, и
    geneva может помочь."""
    return bool(s.oks) or (s.transport == "tcp" and bool(s.fails))


IP_REACHABLE_WHY = ("адрес отвечает — соединения устанавливаются, "
                    "блокировка по содержимому")


def _evictable(s: Service) -> bool:
    """Для него ничего не делается: наблюдается, открыт, блок по адресу,
    QUIC через TCP. Фоновый, ждущий пробы или подбора, — тоже: пир,
    который вернётся, будет увиден снова."""
    return s.status in (WATCHING, NOT_BLOCKED, FALLBACK, IP_BLOCKED) or (
        s.priority == gal.BACKGROUND and s.status in (SUSPECTED, BLOCKED,
                                                      NOT_FOUND))


def _trim(s: Service, now: float) -> None:
    start = now - WINDOW
    for name in ("fails", "oks", "no_connections", "detected"):
        lst = [t for t in getattr(s, name) if t >= start]
        setattr(s, name, lst[-MAX_TIMES:])


class Book:
    """Сервисы режима и их переходы. Не потокобезопасна: замок у владельца.

    Правила переходов перенесены из ``AutoBook`` без изменений, кроме
    одного исправления: сервис, сохранённый в состоянии ``searching``
    (питание пропало посреди подбора), при загрузке становится
    ``blocked``. В эталоне он оставался «в подборе» навсегда:
    ``NextToSearch`` берёт только ``blocked``.
    """

    def __init__(self, saved=None, now: float = 0.0, lists=None):
        self._services = {}
        self.lists = lists if lists is not None else gal.Lists()
        self._dns_poisoned = {}
        # Сайты, которые ведёт процесс «по имени» (geneva_c 2.0): его
        # стратегия доходит до них на любом адресе.
        self.by_name = set()
        for item in saved or []:
            s = item if isinstance(item, Service) else \
                Service.from_dict(item)
            if not s.key:
                continue
            # Книга старой версии могла хранить первые пакеты протокола,
            # который больше не повторяется.
            if s.app not in REPLAYABLE_APPS:
                s.replay = ""
            if s.status == SEARCHING:
                _move(s, BLOCKED, now or s.since, "подбор прерван, продолжу")
            self._services[s.key] = s
        # Списки могли смениться, пока режим был выключен: «Не трогать»
        # и «Не подбирать» действуют и на сохранённую книгу.
        self.set_lists(self.lists)

    @property
    def services(self) -> list:
        return list(self._services.values())

    def find(self, key: str):
        return self._services.get(key)

    def snapshot(self) -> list:
        items = [s.clone() for s in self._services.values()]
        items.sort(key=lambda s: (_ORDER.get(s.status, 9), s.name))
        return items

    def to_list(self) -> list:
        return [s.to_dict() for s in self._services.values()]

    # ── списки пользователя ──

    def set_lists(self, lists) -> tuple:
        """Новые списки: важность считается заново, сервисы из «Не
        трогать» уходят из книги (их стратегии больше не применяются),
        из «Не подбирать» — тоже, если стратегия не применена и подбор
        не идёт. ``(ушли по «Не трогать», ушли по «Не подбирать»)``."""
        self.lists = lists
        gone, skipped = [], []
        for s in list(self._services.values()):
            if lists.exclude.matches(s):
                del self._services[s.key]
                gone.append(s.name)
                continue
            if not s.is_active and s.status != SEARCHING and \
                    lists.no_search.matches(s):
                del self._services[s.key]
                skipped.append(s.name)
                continue
            s.priority = gal.base_priority(s, lists)
        return gone, skipped

    def not_searched(self, s: Service) -> bool:
        """Пользователь не хочет обхода для этого сервиса."""
        return self.lists.no_search.matches(s)

    # ── наблюдение ──

    def feed(self, samples, now: float) -> None:
        """Срез в книгу. Новый сервис начинает с ``watching``."""
        for x in samples or []:
            s = self._services.get(x.key)
            if s is None:
                if self.lists.exclude.matches_sample(x):
                    continue
                # не подбирать: даже в проблемы на странице не попадает
                if self.lists.no_search.matches_sample(x):
                    continue
                s = Service(key=x.key, kind=x.kind, transport=x.transport,
                            name=x.name, app=x.app, status=WATCHING,
                            host=x.host or "",
                            since=now, first_seen=x.time,
                            ports=[x.port] if x.port else [],
                            local_port=x.local_port
                            if x.kind == LOCAL_PORT else 0,
                            client=x.client if x.kind == LOCAL_PORT else "")
                s.priority = gal.base_priority(s, self.lists)
                if not self._make_room(s.priority):
                    continue
                self._services[x.key] = s
            # Адрес, которого ещё нет у применённого сервиса (новый адрес
            # CDN): поток шёл без обхода, его провал о стратегии ничего не
            # говорит — адрес сначала войдёт в набор.
            if x.ip and x.kind != LOCAL_PORT and \
                    self.lists.exclude.matches_address(x.ip):
                # адрес в «Не трогать» (подсеть): в набор группы не идёт
                continue
            uncovered = s.is_active and x.kind != LOCAL_PORT and \
                bool(x.ip) and s.key not in self.by_name and \
                not any(a["ip"] == x.ip for a in s.addresses)
            s.last_seen = max(s.last_seen, x.time)
            if x.host and not _family_kept(s.host, x.host):
                s.host = x.host
            if x.kind != LOCAL_PORT and x.ip:
                _add_address(s, x.ip, x.time)
                if x.port and x.port not in s.ports and \
                        len(s.ports) < MAX_PORTS:
                    s.ports.append(x.port)
            if x.replay:
                s.replay = to_base64(x.replay)
            if uncovered and x.health != OK:
                _trim(s, now)
                continue
            if x.health == OK:
                s.oks.append(x.time)
            elif x.health == FAILED:
                s.fails.append(x.time)
                s.why = x.why
            elif x.health == NO_CONNECTION:
                s.no_connections.append(x.time)
                s.why = x.why
            _trim(s, now)

    def learn(self, key: str, *, app: str = "", replay=None, host: str = "",
              name: str = "") -> None:
        """Что показал короткий захват первых пакетов (протокол, replay)."""
        s = self.find(key)
        if s is None:
            return
        if app:
            s.app = app
        if name:
            s.name = name
        if host and not s.host:
            s.host = host
        if replay is not None:
            s.replay = to_base64(replay) if app in REPLAYABLE_APPS else ""

    def _make_room(self, priority: int) -> bool:
        """Место новому сервису важности ``priority``: полная книга
        вытесняет наименее важный из тех, кого можно (сначала фоновые,
        затем давно не виденные), а пиры не занимают места, оставленные
        сайтам (:data:`gal.RESERVED_PLACES`). ``False`` — места нет."""
        minor = priority >= gal.LOW
        minors = sum(1 for s in self._services.values() if s.peer)
        full = len(self._services) >= MAX_SERVICES
        minors_full = minor and minors >= MAX_SERVICES - gal.RESERVED_PLACES
        if not full and not minors_full:
            return True
        victims = [s for s in self._services.values()
                   if _evictable(s) and s.priority >= priority
                   and (not minors_full or s.peer)]
        if not victims:
            return False
        victim = sorted(victims, key=lambda s: (-s.priority,
                                                s.last_seen))[0]
        del self._services[victim.key]
        return True

    # ── оценка окна ──

    def evaluate(self, now: float) -> list:
        """Переходы по окну. Возвращает строки журнала."""
        out = []
        for s in list(self._services.values()):
            _trim(s, now)
            if s.status not in (APPLIED, DEGRADED) and \
                    now - s.last_seen > FORGET:
                del self._services[s.key]
                continue
            if len(s.addresses) > 1:
                keep = [a for a in s.addresses
                        if now - a["seen"] <= ADDRESS_LIFE]
                s.addresses = keep or s.addresses[-1:]
            s.priority = gal.base_priority(s, self.lists)
            sus, why = suspicious(s)
            due = s.next_check is None or now >= s.next_check
            st = s.status
            if st == IP_BLOCKED and handshake_seen(s):
                # устройства соединяются с адресом: это не блокировка по
                # IP (в т.ч. сервисы, сохранённые так прежней версией)
                s.next_check = None
                _move(s, BLOCKED, now, IP_REACHABLE_WHY)
                out.append("%s: адрес отвечает, это не блокировка по IP — "
                           "ищу обход" % s.name)
                continue
            if st in (WATCHING, FALLBACK) or (
                    st in (NOT_BLOCKED, IP_BLOCKED) and due):
                if not sus:
                    if st in (NOT_BLOCKED, IP_BLOCKED):
                        _move(s, WATCHING, now, "")
                    s.suspicions = 0
                    continue
                if s.kind == QUIC and self._tcp_works(s):
                    if st != FALLBACK:
                        out.append("%s: QUIC не проходит, браузер "
                                   "открывает сайт по TCP" % s.name)
                    _move(s, FALLBACK, now, "QUIC не проходит, работает TCP")
                    continue
                s.suspicions = 1
                _move(s, SUSPECTED, now, why)
                out.append("%s: похоже на блокировку (%s)" % (s.name, why))
            elif st == SUSPECTED:
                s.suspicions = s.suspicions + 1 if sus else 0
                if not sus:
                    _move(s, WATCHING, now, "")
            elif st == APPLIED and s.applied_at is not None:
                # Провалы после последнего успеха. Отличие: в эталоне —
                # «ни одного успеха с применения», и сайт, который
                # проработал 10 минут и сломался, оставался «работает»,
                # пока старые успехи не уходили из окна.
                at = max([s.applied_at] + [t for t in s.oks
                                           if t > s.applied_at])
                fails = sum(1 for t in s.fails if t > at) + \
                    sum(1 for t in s.no_connections if t > at)
                if fails >= threshold(s) and s.pinned:
                    # закреплена пользователем: нового подбора нет,
                    # провалы только видны
                    if not s.pinned_warned:
                        out.append("%s: закреплённая стратегия даёт ошибки, "
                                   "оставляю её (снимите закрепление для "
                                   "нового подбора)" % s.name)
                    s.pinned_warned = True
                    if not s.why.startswith("закреплена"):
                        s.why = "закреплена; есть ошибки: " + s.why
                    s.applied_at = now
                elif fails >= threshold(s):
                    _move(s, DEGRADED, now, "обход перестал работать: " +
                          s.why)
                    s.next_check = None
                    out.append("%s: обход перестал работать, проверяю"
                               % s.name)
            elif st == NOT_FOUND and s.next_check is not None and \
                    now >= s.next_check:
                _move(s, BLOCKED, now, "повторный подбор")
        return out

    def _tcp_works(self, quic: Service) -> bool:
        web = self.find("web:" + quic.key[len("quic:"):])
        return web is not None and bool(web.oks)

    # ── что дальше ──

    def _queue(self, cands, now: float) -> list:
        """Порядок AutoBook.Queue: важность (с учётом ожидания), затем
        сломавшийся обход, вид (сайт, DNS, QUIC, сервер, пир), свежесть
        и трафик. Число провалов не решает: пиры торрента проваливаются
        сотнями."""
        return sorted(cands, key=lambda s: (
            gal.effective(s, now), s.status != DEGRADED,
            _SEARCH_ORDER.get(s.kind, 4), -s.last_seen,
            -(len(s.oks) + len(s.fails) + len(s.no_connections)), s.key))

    def next_to_confirm(self, now: float, allowed=None):
        """Следующий на проверку; ``allowed(s)`` — фильтр (сервис, на
        котором идёт подбор или проверка своей стратегии, не трогать:
        его обход сейчас — пробная стратегия, а не своя)."""
        cands = [s for s in self._services.values()
                 if (allowed is None or allowed(s))
                 and s.status in (SUSPECTED, DEGRADED)
                 and (s.next_check is None or now >= s.next_check)
                 and (s.status == DEGRADED or not self.not_searched(s))]
        q = self._queue(cands, now)
        return q[0] if q else None

    def next_to_search(self, now: float, allowed=None):
        """Следующий заблокированный для подбора; ``allowed(s)`` —
        фильтр (подборы рядом не пересекаются)."""
        cands = [s for s in self._services.values()
                 if s.status == BLOCKED
                 and (s.next_check is None or now >= s.next_check)
                 and not self.not_searched(s)
                 and (allowed is None or allowed(s))]
        q = self._queue(cands, now)
        return q[0] if q else None

    def preempting(self, searching: str, now: float, allowed=None):
        """Заблокированный, ради которого стоит прервать подбор
        ``searching``: важнее его сейчас и сам не фоновый (пир, что долго
        ждал, поднимается, но не прерывает никого)."""
        cur = self.find(searching)
        if cur is None:
            return None
        nxt = self.next_to_search(now, allowed)
        if nxt is None or nxt.key == searching or \
                nxt.priority == gal.BACKGROUND:
            return None
        return nxt if gal.effective(nxt, now) < gal.effective(cur, now) \
            else None

    # ── действия пользователя ──

    def check_now(self, key: str, now: float) -> str:
        """«Проверить сейчас»: применённый проверяется с обходом (и
        подбирается заново, если не прошёл), любой другой — пробой без
        обхода сразу, паузы не в счёт; «не найдено» — подбор сейчас."""
        s = self.find(key)
        if s is None:
            return ""
        s.next_check = None
        if s.status == APPLIED:
            _move(s, DEGRADED, now, "проверка по просьбе пользователя")
        elif s.status == NOT_FOUND:
            _move(s, BLOCKED, now, "повторный подбор по просьбе "
                  "пользователя")
        elif s.status in (SEARCHING, BLOCKED, DEGRADED):
            return "%s: уже в работе" % s.name
        else:
            # сервис без пробы на слово пользователя считается блоком
            s.suspicions = 2
            _move(s, SUSPECTED, now, "проверка по просьбе пользователя")
        return "%s: проверяю сейчас" % s.name

    def pin(self, key: str, pinned: bool) -> bool:
        s = self.find(key)
        if s is None or (pinned and not s.strategy):
            return False
        s.pinned = bool(pinned)
        s.pinned_warned = False
        return True

    def set_user_priority(self, key: str, value: str) -> bool:
        s = self.find(key)
        if s is None or value not in gal.USER_PRIORITIES:
            return False
        s.user_priority = value
        s.priority = gal.base_priority(s, self.lists)
        return True

    def family_strategy(self, s: Service):
        """Стратегия, работающая у другого домена того же семейства
        (видео YouTube для его сайта): её пробовать первой."""
        fam = gal.service_family(s)
        if not fam:
            return None
        cands = [x for x in self._services.values()
                 if x.key != s.key and x.is_active
                 and x.transport == s.transport
                 and gal.service_family(x) == fam]
        if not cands:
            return None
        return max(cands, key=lambda x: x.applied_at or 0).strategy

    # ── детектор geneva ──

    def detect(self, level: str, key: str, cls: str, now: float) -> list:
        """Ключ, который детектор geneva держит заблокированным
        (``ext_status`` → ``impaired``): имя (``host``) или адрес
        (``ip``) с классом из :data:`DETECTOR_CLASSES`. Сервисы — сайт по
        имени или поддомену, TCP-сервис по адресу — становятся
        подозреваемыми, если ими ещё не занимаются. Возвращает имена
        новых подозреваемых."""
        hit = []
        key = str(key or "").strip().rstrip(".").lower()
        if cls not in DETECTOR_CLASSES or not key:
            return hit
        for s in self._services.values():
            if level == "host":
                site = gal.site_of(s)
                match = s.kind == WEB and (key == (s.host or "").lower() or
                                           key == site or
                                           key.endswith("." + site))
            elif level == "ip":
                match = s.transport == "tcp" and any(
                    a["ip"].lower() == key for a in s.addresses)
            else:
                match = False
            if not match:
                continue
            if s.status not in (WATCHING, FALLBACK, SUSPECTED) and not (
                    s.status == NOT_BLOCKED and (s.next_check is None or
                                                 now >= s.next_check)):
                continue
            fresh = not s.detected
            if fresh or now - s.detected[-1] >= MINUTE:
                s.detected.append(now)
            s.detected_why = DETECTOR_WHY.get(cls, cls)
            if fresh:
                hit.append(s.name)
        return hit

    def dns_poisoned(self, name: str, now: float) -> bool:
        """Детектор видел поддельный ответ DNS для имени: пакетная
        стратегия не поможет, нужен DoH. ``True`` — имя новое или о нём
        говорили больше часа назад."""
        name = str(name or "").strip().rstrip(".").lower()
        at = self._dns_poisoned.get(name)
        if not name or (at is not None and now - at < DNS_POISON_EVERY):
            return False
        # только имена своих сервисов: чужие журнал не засоряют
        if not any(name in ((x.host or "").lower(), (x.name or "").lower())
                   for x in self._services.values()):
            return False
        while len(self._dns_poisoned) >= 256:
            # самое давнее — вон, а не всё сразу (иначе повторы)
            del self._dns_poisoned[min(self._dns_poisoned,
                                       key=self._dns_poisoned.get)]
        self._dns_poisoned[name] = now
        return True

    # ── итоги проб и подбора ──

    def confirmed(self, key: str, result: str, now: float) -> str:
        s = self.find(key)
        if s is None:
            return ""
        degraded = s.status == DEGRADED
        if result == C_NOT_BLOCKED and degraded and s.strategy and \
                s.restored_at is not None and now - s.restored_at < REDEGRADE:
            # Проба роутера с обходом проходит, а устройства снова не
            # открывают: стратегия работает только для самого роутера
            # (ускорение NAT, другой путь трафика). Отличие от эталона:
            # там это вечный круг «ослабла → проба прошла → работает».
            bad = s.strategy
            if bad not in s.rejected:
                s.rejected = (s.rejected + [bad])[-MAX_REJECTED:]
            s.restored_at = None
            s.next_check = None
            _move(s, BLOCKED, now, "проба роутера проходит, у устройств — "
                  "нет: ищу другую стратегию")
            return ("%s: стратегия помогает роутеру, но не устройствам — "
                    "ищу другую" % s.name)
        if result == C_NOT_BLOCKED:
            s.detected = []
        if result in (C_BLOCKED, C_UNKNOWN) and degraded and s.pinned:
            s.applied_at = now
            s.fails = []
            s.no_connections = []
            s.detected = []
            _move(s, APPLIED, now, "закреплена; проверка с обходом не "
                  "прошла")
            return ("%s: проверка с обходом не прошла, но стратегия "
                    "закреплена — оставляю" % s.name)
        if result in (C_BLOCKED, C_UNKNOWN) and degraded and \
                self.not_searched(s) and (result == C_BLOCKED or
                                          s.suspicions >= 2):
            # обход перестал работать, а новый пользователь не хочет —
            # сервис уходит, как при смене списков
            del self._services[s.key]
            return ("%s: обход перестал работать; в списке «Не подбирать» "
                    "— новый не ищу" % s.name)
        if result == C_NOT_BLOCKED and degraded:
            s.fails = []
            s.no_connections = []
            s.applied_at = now
            s.restored_at = now
            _move(s, APPLIED, now, "проверка с обходом прошла")
            return "%s: с обходом открывается, оставляю стратегию" % s.name
        if result == C_NOT_BLOCKED:
            s.next_check = now + NOT_BLOCKED_PAUSE
            _move(s, NOT_BLOCKED, now, "без обхода открывается")
            return "%s: без обхода открывается, это не блокировка" % s.name
        if result == C_IP_BLOCKED and handshake_seen(s):
            result = C_BLOCKED
            s.next_check = None
            _move(s, BLOCKED, now, IP_REACHABLE_WHY)
            return ("%s: проба не соединилась, но устройства соединяются — "
                    "блокировка по содержимому, ищу обход" % s.name)
        if result == C_IP_BLOCKED:
            s.next_check = now + IP_BLOCKED_PAUSE
            _move(s, IP_BLOCKED, now, "блокировка по адресу: geneva не "
                                      "поможет, нужен туннель")
            return "%s: блокировка по адресу, обход пакетами не поможет" \
                % s.name
        if result == C_UNKNOWN and s.suspicions < 2 and not degraded:
            s.next_check = now + UNKNOWN_RECHECK
            return ""
        s.next_check = None
        if not degraded and result == C_BLOCKED:
            s.baseline_at = now
        s.detected = []
        _move(s, BLOCKED, now, "обход перестал работать: ищу новую "
              "стратегию" if degraded else "заблокирован")
        return ("%s: стратегия больше не работает, ищу новую" if degraded
                else "%s: блокировка подтверждена, ищу обход") % s.name

    def searching(self, key: str, now: float) -> None:
        s = self.find(key)
        if s is not None:
            _move(s, SEARCHING, now, "подбор")

    def applied(self, key: str, strategy: str, fitness: float,
                now: float) -> None:
        s = self.find(key)
        if s is None:
            return
        s.strategy = strategy
        s.fitness = float(fitness or 0)
        s.applied_at = now
        s.restored_at = None
        s.attempts = 0
        s.next_check = None
        s.fails = []
        s.no_connections = []
        s.detected = []
        _move(s, APPLIED, now, "обход работает")

    def not_found(self, key: str, now: float) -> None:
        s = self.find(key)
        if s is None:
            return
        s.attempts += 1
        pause = min(MAX_RETRY_PAUSE,
                    RETRY_PAUSE * (1 << min(s.attempts - 1, 10)))
        s.next_check = now + pause
        _move(s, NOT_FOUND, now, "обход не найден, следующая попытка "
              "через %d ч" % round(pause / HOUR))

    def wake_not_found(self, strategy: str, now: float) -> int:
        """Нашлась новая рабочая стратегия — сервисы «не найдено» того же
        транспорта подбираются сразу, а не через свою паузу: в первом
        круге их подбора она будет первой. Отличие: в эталоне они ждут
        паузу. Счётчик попыток не сбрасывается — пауза дальше растёт."""
        n = 0
        for s in self._services.values():
            if s.status == NOT_FOUND and _fits(s, strategy):
                s.next_check = now
                n += 1
        return n

    def reset(self, key: str, now: float) -> bool:
        s = self.find(key)
        if s is None:
            return False
        s.strategy = None
        s.applied_at = None
        s.restored_at = None
        s.pinned = False
        s.detected = []
        s.criteria = {}
        s.rejected = []
        s.next_check = None
        s.attempts = 0
        s.fails = []
        s.no_connections = []
        _move(s, WATCHING, now, "")
        return True

    def interrupted(self, key: str, now: float) -> None:
        s = self.find(key)
        if s is None or s.status != SEARCHING:
            return
        # остановлен, потому что пользователь убрал его из подбора: уходит
        # из проблем, как при смене списков
        if not s.is_active and self.not_searched(s):
            del self._services[key]
            return
        _move(s, BLOCKED, now, "подбор прерван, продолжу")

    def rules_restored(self, now: float) -> int:
        """Правила групп были снесены извне (прошивка) и поставлены
        заново: провалы до этого момента — без обхода, а не вина
        стратегии. ``APPLIED`` считает провалы с ``now``, ``DEGRADED``
        возвращается в ``APPLIED`` без пробы (проба «с обходом» в окне
        без правил отвергла бы рабочую стратегию). Отличие от эталона:
        на ПК чужого сноса правил нет. Возвращает число вернувшихся."""
        back = 0
        for s in self._services.values():
            if not s.strategy or s.status not in (APPLIED, DEGRADED):
                continue
            s.applied_at = now
            if s.status == DEGRADED:
                s.next_check = None
                _move(s, APPLIED, now, "правила обхода были сняты прошивкой "
                      "и поставлены заново")
                back += 1
        return back

    def counts(self) -> dict:
        out = {}
        for s in self._services.values():
            out[s.status] = out.get(s.status, 0) + 1
        return out


def overlap(a: Service, b: Service) -> bool:
    """Подборы этих двух рядом не идут: общий адрес сервера (пробная
    группа одного забрала бы адрес другого) или один и тот же сайт (TCP и
    QUIC)."""
    if a.key == b.key:
        return True
    if a.kind in (WEB, QUIC) and b.kind in (WEB, QUIC) and \
            gal.site_of(a) == gal.site_of(b):
        return True
    if a.kind == LOCAL_PORT and b.kind == LOCAL_PORT:
        return a.local_port == b.local_port and a.client == b.client
    ips = {x["ip"] for x in a.addresses}
    return any(y["ip"] in ips for y in b.addresses)


def _add_address(s: Service, ip: str, seen: float) -> None:
    for a in s.addresses:
        if a["ip"] == ip:
            a["seen"] = max(a["seen"], seen)
            break
    else:
        s.addresses.append({"ip": ip, "seen": seen})
    if len(s.addresses) > MAX_ADDRESSES:
        s.addresses = sorted(s.addresses, key=lambda a: -a["seen"])[
            :MAX_ADDRESSES]


# ───────────────────────────── план (AutoPlan) ──────────────────────

@dataclass
class Target:
    """Трафик одного сервиса, который идёт через geneva (AutoTarget)."""
    addresses: list = field(default_factory=list)
    tcp_ports: str = ""
    udp_ports: str = ""
    # Порты — исходные порты клиента ``client``, а не порты сервера.
    by_local_port: bool = False
    client: str = ""

    def to_dict(self) -> dict:
        return {"addresses": list(self.addresses),
                "tcp_ports": self.tcp_ports, "udp_ports": self.udp_ports,
                "by_local_port": self.by_local_port, "client": self.client}


@dataclass
class Group:
    """Стратегия и её сервисы: один ``geneva run`` со своей очередью."""
    strategy: str
    services: list
    targets: list

    def to_dict(self) -> dict:
        return {"strategy": self.strategy, "services": list(self.services),
                "targets": [t.to_dict() for t in self.targets]}


def format_ports(ports) -> str:
    """[443, 8443, 444] → ``443-444,8443`` (PortList.Format/Merge)."""
    nums = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    out = []
    for p in nums:
        if out and p == out[-1][1] + 1:
            out[-1][1] = p
        else:
            out.append([p, p])
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in out)


def target(s: Service):
    """Цель сервиса; ``None`` — целиться не во что (адресов нет)."""
    def ports(fallback: int) -> str:
        return format_ports(s.ports) if s.ports else str(fallback)

    if s.kind == LOCAL_PORT:
        if not 1 <= int(s.local_port or 0) <= 65535 or not s.client:
            return None
        lp = str(int(s.local_port))
        return Target(by_local_port=True, client=s.client,
                      tcp_ports=lp if s.transport == "tcp" else "",
                      udp_ports=lp if s.transport == "udp" else "")
    addrs = []
    for a in s.addresses:
        if _valid_ip(a.get("ip")) and a["ip"] not in addrs:
            addrs.append(a["ip"])
    if not addrs:
        return None
    if s.kind == DNS:
        # резолвер спрашивают по UDP и по TCP для больших ответов
        return Target(addresses=addrs, tcp_ports="53", udp_ports="53")
    if s.kind == WEB:
        return Target(addresses=addrs, tcp_ports=ports(WEB_PORT))
    if s.kind == QUIC:
        return Target(addresses=addrs, udp_ports=ports(WEB_PORT))
    if not s.port:
        return None
    if s.transport == "udp":
        return Target(addresses=addrs, udp_ports=ports(s.port))
    return Target(addresses=addrs, tcp_ports=ports(s.port))


# ── применение по имени (geneva_c 2.0: ext_profile, ext_lists) ──

# Процесс профилей слушает диапазон 340..340+N-1, и N — предел самого
# движка (``--ext-workers`` 1–64, docs/EXT.md «Многоочередной движок»).
# Очереди «по имени» и детектора стоят СРАЗУ за этим диапазоном, а не
# внутри него: иначе число потоков пришлось бы держать меньше, чем умеет
# geneva.
ENGINE_WORKERS_MAX = 64          # предел geneva_c (--ext-workers 1–64)
HOST_QUEUE = QUEUE_BASE + ENGINE_WORKERS_MAX         # 404: «по имени»
OBSERVE_QUEUE = HOST_QUEUE + 1                       # 405: детектор
ENGINE_QUEUES_MAX = HOST_QUEUE - QUEUE_BASE          # 64: 340..403
HOST_TCP_PORTS = (80, 443)
HOST_UDP_PORT = 443
MAX_HOST_PROFILES = 24
HOST_FEATURES = ("ext", "ext_profile", "ext_lists", "ext_l7")
OBSERVE_PORT = 9                 # discard: движок детектора берёт только его
OBSERVE_FEATURE = "ext_auto"


def host_profiles(services, trial_keys=(), quic: bool = False,
                  families: bool = True) -> list:
    """Профили процесса «по имени» (AutoPlan.HostProfiles AutoTuner):
    стратегия → сайты, где она применена. Новый адрес CDN работает
    сразу: geneva узнаёт сайт по имени из ClientHello (или из кэша
    адресов). К сайту добавляются домены его семейства, если у них нет
    своей жизни в книге (своя стратегия, проба или подбор). Пробная
    стратегия не идёт (решает её группа); домен — первому профилю, что
    его назвал; не больше :data:`MAX_HOST_PROFILES`.

    ``[{"strategy", "udp", "domains", "services"}]``."""
    allsv = list(services or ())
    trial_keys = set(trial_keys or ())
    busy = {(gal.site_of(s), s.kind == QUIC) for s in allsv
            if s.kind in (WEB, QUIC) and (s.is_active or s.status in (
                SEARCHING, BLOCKED, SUSPECTED, NOT_FOUND, DEGRADED))}
    groups = {}
    for s in allsv:
        if not s.is_active or not s.strategy or s.key in trial_keys:
            continue
        if not (s.kind == WEB or (quic and s.kind == QUIC)):
            continue
        groups.setdefault((s.strategy, s.kind == QUIC), []).append(s)
    order = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0][0],
                                                   kv[0][1]))
    claimed, out = set(), []
    for (strategy, udp), members in order:
        domains = []
        for s in sorted(members, key=lambda x: x.key):
            site = gal.site_of(s)
            if site and (site, udp) not in claimed:
                claimed.add((site, udp))
                domains.append(site)
        if families:
            fams = []
            for s in members:
                # семейство всего сайта, не его хоста: googleapis.com с
                # хостом youtubei.googleapis.com не забирает себе домены
                # YouTube у стратегии самого YouTube
                f = gal.site_family(s)
                if f and f not in fams:
                    fams.append(f)
            for f in fams:
                for d in gal.FAMILIES.get(f, ()):
                    if (d, udp) not in busy and (d, udp) not in claimed:
                        claimed.add((d, udp))
                        domains.append(d)
        if not domains:
            continue
        out.append({"strategy": strategy, "udp": udp, "domains": domains,
                    "services": [s.key for s in members]})
        if len(out) >= MAX_HOST_PROFILES:
            break
    return out


def by_name_covers(services, profiles) -> set:
    """Сайты, которые покрывает процесс «по имени»: названы в TCP-профиле
    и все их порты — из :data:`HOST_TCP_PORTS`."""
    named = {k for p in profiles or () if not p["udp"]
             for k in p["services"]}
    return {s.key for s in services or ()
            if s.kind == WEB and s.key in named and
            all(int(x) in HOST_TCP_PORTS for x in (s.ports or [WEB_PORT]))}


def plan_groups(services, trial=None, max_groups: int = MAX_GROUPS,
                trials=None) -> list:
    """Группы: активные сервисы по стратегии, пробуемые — первыми.

    ``trial`` — ``(Service, strategy)``: стратегия, которую сейчас
    проверяют на одном сервисе; ``trials`` — несколько таких (подборы
    рядом, AutoPlan.Groups(services, trials)). Пара «адрес + транспорт»
    (или локальный порт) достаётся только первой группе: сайты за одним
    адресом CDN с разными стратегиями не делят пакеты.
    """
    trials = [t for t in list(trials or ()) + ([trial] if trial else [])
              if t and t[1]]
    trial_keys = {t[0].key for t in trials}
    trial_pairs = {(t[0].key, t[1]) for t in trials}
    active = [(s, s.strategy) for s in services
              if s.is_active and s.key not in trial_keys]
    active = [(t[0], t[1]) for t in trials] + active
    by = {}
    order = []
    for s, strat in active:
        if strat not in by:
            by[strat] = []
            order.append(strat)
        by[strat].append(s)
    groups = []
    for strat in order:
        svcs = by[strat]
        targets = [t for t in (target(s) for s in svcs) if t is not None]
        if targets:
            groups.append(Group(strat, [s.key for s in svcs], targets))
    groups.sort(key=lambda g: (
        not any((k, g.strategy) in trial_pairs for k in g.services),
        -len(g.services), g.strategy))
    claimed = set()
    claimed_ports = set()
    result = []
    for g in groups:
        targets = []
        for t in g.targets:
            if t.by_local_port:
                tcp = t.tcp_ports if t.tcp_ports and (
                    "tcp", t.client, t.tcp_ports) not in claimed_ports \
                    else ""
                udp = t.udp_ports if t.udp_ports and (
                    "udp", t.client, t.udp_ports) not in claimed_ports \
                    else ""
                if tcp:
                    claimed_ports.add(("tcp", t.client, tcp))
                if udp:
                    claimed_ports.add(("udp", t.client, udp))
                if tcp or udp:
                    targets.append(Target(by_local_port=True,
                                          client=t.client, tcp_ports=tcp,
                                          udp_ports=udp))
                continue

            def free(proto, ports):
                if not ports:
                    return []
                out = []
                for a in t.addresses:
                    if (proto, a) not in claimed and a not in out:
                        out.append(a)
                return out
            tcp_free = free("tcp", t.tcp_ports)
            udp_free = free("udp", t.udp_ports)
            if tcp_free and tcp_free == udp_free:
                targets.append(Target(addresses=tcp_free,
                                      tcp_ports=t.tcp_ports,
                                      udp_ports=t.udp_ports))
                continue
            if tcp_free:
                targets.append(Target(addresses=tcp_free,
                                      tcp_ports=t.tcp_ports))
            if udp_free:
                targets.append(Target(addresses=udp_free,
                                      udp_ports=t.udp_ports))
        if not targets:
            continue
        for t in targets:
            if t.by_local_port:
                continue
            for a in t.addresses:
                if t.tcp_ports:
                    claimed.add(("tcp", a))
                if t.udp_ports:
                    claimed.add(("udp", a))
        result.append(Group(g.strategy, g.services, targets))
        if len(result) >= max_groups:
            break
    return result


# ── профили geneva 2.0 (X6a/X6b): много стратегий в одном процессе ──

MAX_PROFILES = 200        # профилей в файле (XPROF_MAX у geneva — 255)
PROFILE_FEATURE = "ext_profile"


@dataclass
class Profile:
    """Стратегия и её трафик в одном процессе «Авто».

    Раньше стратегия была группой: свой ``geneva run``, своя очередь
    NFQUEUE. Теперь это профиль: ``--ext-workers`` дают потоки и очереди
    диапазоном, а профиль сам отбирает пакеты своим ipset-файлом
    (``--ipset``) и порт-фильтром. Предел — :data:`MAX_PROFILES`, а не
    восемь очередей.
    """
    strategy: str
    services: list = field(default_factory=list)
    targets: list = field(default_factory=list)
    name: str = ""            # имя для лога geneva и журнала
    trial: bool = False       # пробная стратегия подбора

    @property
    def addresses(self) -> list:
        """Адреса всех целей профиля (для ipset-файла)."""
        out = []
        for t in self.targets:
            if t.by_local_port:
                continue
            for a in t.addresses:
                if a not in out:
                    out.append(a)
        return out

    @property
    def tcp_ports(self) -> str:
        """Порты сервера по TCP: у целей по локальному порту это порт
        клиента, и в фильтр профиля он попасть не должен — geneva
        сравнивает порт сервера."""
        return _ports_union(t.tcp_ports for t in self.targets
                            if not t.by_local_port)

    @property
    def udp_ports(self) -> str:
        return _ports_union(t.udp_ports for t in self.targets
                            if not t.by_local_port)

    @property
    def port_only(self) -> bool:
        """Профиль только из целей по локальному порту (пир, DHT): адресов
        сервера у него нет, пакеты к нему кладут правила по conntrack, а
        сам профиль обязан брать все порты сервера."""
        return bool(self.targets) and all(t.by_local_port
                                          for t in self.targets)

    @property
    def port_proto(self) -> str:
        """Протокол порт-целей профиля: у «все порты» можно назвать
        только один (geneva запрещает профиль без фильтра протокола)."""
        udp = any(t.udp_ports for t in self.targets)
        tcp = any(t.tcp_ports for t in self.targets)
        return "udp" if udp and not tcp else "tcp"

    def to_dict(self) -> dict:
        return {"name": self.name, "strategy": self.strategy,
                "services": list(self.services),
                "targets": [t.to_dict() for t in self.targets],
                "trial": self.trial,
                "addresses": self.addresses}


def _ports_union(specs) -> str:
    """Порт-фильтр профиля одним списком: ``["443", "80,443"]`` →
    ``"80,443"`` (geneva считает порты профиля одним набором)."""
    nums = set()
    for spec in specs or ():
        for part in str(spec or "").split(","):
            part = part.strip()
            if not part:
                continue
            lo, _, hi = part.partition("-")
            try:
                lo, hi = int(lo), int(hi or lo)
            except ValueError:
                continue
            nums.update(range(lo, hi + 1))
    return format_ports(nums) if nums else ""


def _profile_name(strategy: str, n: int, udp: bool, kind: str = "") -> str:
    """Имя профиля для лога geneva: номер, транспорт, вид цели и начало
    стратегии. Имя в ini — одно слово без пробелов и ``]``."""
    text = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                   for ch in str(strategy or ""))[:40]
    return "p%d-%s%s-%s" % (n, "udp" if udp else "tcp",
                            "-" + kind if kind else "",
                            text.strip("_") or "s")


def plan_profiles(services, trials=None, max_profiles: int = MAX_PROFILES
                  ) -> list:
    """Профили вместо групп: активные сервисы по стратегии, пробуемые —
    первыми. Возвращает ``[Profile]``.

    Пересечение адресов у профилей допустимо и нормально: профиль сам
    отбирает пакеты своим ``--ipset``-файлом и порт-фильтром, а пакет
    берёт первый подходящий профиль (geneva: профили в порядке файла).
    Порядок — по важности: пробная стратегия, затем важные сервисы, затем
    остальные. Цели по локальному порту (пиры, DHT) — отдельный профиль
    той же стратегии (:attr:`Profile.port_only`): адресов сервера у них
    нет, пакеты кладут правила по conntrack (см. ``geneva_auto_fw``), а
    профиль берёт все порты сервера. Смешать их с адресными целями
    нельзя: geneva проверяет ipset и порт вместе, и порт клиента (6881)
    пакет сервера не пропустит никогда.
    """
    trials = [t for t in list(trials or ()) if t and t[1]]
    trial_keys = {t[0].key for t in trials}
    trial_pairs = {(t[0].key, t[1]) for t in trials}
    items = [(t[0], t[1], True) for t in trials]
    items += [(s, s.strategy, False) for s in services
              if s.is_active and s.key not in trial_keys]
    # Профиль «все порты сервера» ставится последним: он ничего не
    # отбирает и забрал бы себе пакеты любого адресного профиля ниже.
    items.sort(key=lambda x: (
        not x[2], not (x[0].addresses or ()), x[0].priority,
        -len(x[0].addresses or ()), x[0].key))
    # Порт-цели (пир, DHT) отделяются от адресных целей той же стратегии:
    # geneva проверяет ipset и порт вместе, и профиль с адресами не пустил
    # бы пакет пира — у того порт сервера произвольный.
    order, by = [], {}
    for s, strat, trial in items:
        t0 = target(s)
        port_only = bool(t0 is not None and t0.by_local_port)
        key = (strat, port_only)
        if key not in by:
            by[key] = []
            order.append((key, trial))
        by[key].append(s)
    out = []
    for (strat, port_only), trial in order:
        svcs = by[(strat, port_only)]
        targets = [t for t in (target(s) for s in svcs) if t is not None]
        if not targets:
            continue
        udp = all(not t.tcp_ports for t in targets)
        p = Profile(strategy=strat, services=[s.key for s in svcs],
                    targets=targets, trial=trial)
        p.name = _profile_name(strat, len(out) + 1, udp,
                               "peer" if port_only else "")
        out.append(p)
        if len(out) >= max_profiles:
            break
    return out


def describe_target(t: Target) -> str:
    """Коротко для журнала и страницы."""
    if t.by_local_port:
        head = "локальный порт %s" % t.client
    else:
        head = ", ".join(t.addresses[:3]) + (
            " (+%d)" % (len(t.addresses) - 3) if len(t.addresses) > 3
            else "")
    parts = [head]
    if t.tcp_ports:
        parts.append("tcp " + t.tcp_ports)
    if t.udp_ports:
        parts.append("udp " + t.udp_ports)
    return " ".join(parts)


# ───────────────────────────── кандидаты (AutoCandidates) ───────────
# Предустановленные — найдены подбором «Авто» на живых сетях (провайдеры
# РФ, ТСПУ) и сработали на десятках сервисов: с них подбор начинается
# сразу после установки, и большинство сайтов, QUIC и STUN получают обход
# без генетического поиска. Не сработали — дальше шаблоны и evolve.
# Отличие: в эталоне предустановленных нет, кандидаты — только группы,
# найденные раньше и шаблоны AutoCandidates.
# fragment{tcp:34:True:17} — сегменты по 34 байта с перекрытием 17:
# SNI разрезан, а сервер собирает поток как обычно. У найденного
# оригинала была ещё входящая ветка [TCP:seq:2285867905:4]-tamper{…} —
# она срабатывает только на пакете с этим номером последовательности,
# то есть никогда, поэтому её нет.

AUTO_PRESETS_TCP = (
    r"[TCP:flags:PA]-fragment{tcp:34:True:17}-| \/",
    r"[TCP:flags:PA]-fragment{tcp:-1:False}-| \/",
)

AUTO_PRESETS_UDP = (
    r"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \/",
    r"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt}(duplicate,),)-| \/",
)

# Остальные скопированы из AutoCandidates AutoTuner: все проходят geneva
# check.

AUTO_CANDIDATES_TCP = (
    r"[TCP:flags:PA]-fragment{tcp:-1:True}-| \/",
    r"[TCP:flags:PA]-fragment{tcp:8:True}-| \/",
    r"[TCP:flags:PA]-fragment{tcp:-1:False}-| \/",
    r"[TCP:flags:PA]-duplicate(tamper{TCP:chksum:corrupt},)-| \/",
    r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4},)-| \/",
    r"[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:R}"
    r"(tamper{TCP:chksum:corrupt},),)-| \/",
    r"[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}"
    r"(tamper{TCP:chksum:corrupt},),)-| \/",
    # Windows шлёт SYN как SEC (ECN): обе формы
    r"[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-| "
    r"[TCP:flags:SEC]-duplicate(tamper{TCP:flags:replace:SA},)-| \/",
    r"[TCP:flags:PA]-fragment{ip:-1:True}-| \/",
)

AUTO_CANDIDATES_UDP = (
    r"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \/",
    r"[UDP:sport:*]-duplicate(tamper{UDP:chksum:corrupt},)-| \/",
    r"[UDP:sport:*]-duplicate(tamper{IP:ttl:replace:3},)-| \/",
    r"[UDP:sport:*]-fragment{ip:-1:True}-| \/",
    r"[UDP:sport:*]-fragment{ip:-1:False}-| \/",
    r"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt}(duplicate,),)-| \/",
)

AUTO_CANDIDATES_DNS = (
    r"[UDP:dport:53]-tamper{DNS:qd:compress}-| \/",
    r"[UDP:dport:53]-duplicate(tamper{UDP:chksum:corrupt},)-| \/",
)


# x-действия и полезные нагрузки L7 geneva_c 2.0, которые есть только у
# одного транспорта (docs/EXT.md: X5a, X5b, X8) — AutoCandidates.Fits.
_TCP_ONLY = re.compile(
    r"(?:^|[-(,])x(?:split|disorder|tcpseg|hostfake|fakedsplit|"
    r"fakeddisorder|synack|synacksplit|wsize|wssize|syndata|rst|http|oob|"
    r"tlsrec|drip|tlsclone|synhide)(?=[{(,)-]|$)"
    r"|payload[:=](?:tls_client_hello|http_req)\b|\[TCP:", re.I)
_UDP_ONLY = re.compile(
    r"(?:^|[-(,])x(?:udplen|dhtdn|wgobfs|udp2icmp)(?=[{(,)-]|$)"
    r"|payload[:=](?:quic_initial|dht|wireguard\w*|stun|"
    r"discord_ip_discovery|dtls\w*)\b|\[UDP:", re.I)


def _fits(s: Service, strategy: str) -> bool:
    """Стратегия действует на пакеты сервиса: TCP-деревья — для TCP,
    UDP (DNS, IP) — для UDP. Триггеры потока, L7 и мета geneva_c 2.0
    (``[FLOW:n:a]``) подходят обоим транспортам: решают действия под ними
    (TCP-разрезы и OOB — только TCP, QUIC Initial — только UDP)."""
    low = strategy.lower()
    udp = s.transport == "udp" or s.kind == DNS
    if "[flow:" in low or "[l7:" in low or "[meta:" in low:
        return not _TCP_ONLY.search(strategy) if udp else \
            not _UDP_ONLY.search(strategy)
    if udp:
        return "[udp:" in low or "[ip:" in low or "[dns" in low
    return "[tcp:" in low or "[ip:" in low


# ── методы zapret2 как x-действия geneva_c 2.0 (AutoCandidates AutoTuner
# 1.4: XTcp, XQuic, XTcpWide, XHttp, XQuicWide, XUdp, XDht, XTcpAny) ──

X_TCP = (
    r"[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=1,midsld}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20}(xdisorder{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;md5}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;badsum;tlsmod=rnd,rndsni,dupsid}(xsplit{pos=midsld},)-| \/",
    r"[TCP:flags:PA]-xfakedsplit{pos=midsld;ttl=4}-| \/",
    r"[TCP:flags:PA]-xhostfake{ttl=auto:-2:3-20}-| \/",
    r"[TCP:flags:PA]-xtlsrec{pos=sniext+1}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=sniext+1}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=4;repeats=2}(xdisorder{pos=midsld},)-| \/",
)

X_QUIC = (
    r"[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=6;ttl=4}-| \/",
    r"[UDP:dport:443]-xfake{blob=fake_default_quic;repeats=6;badsum}-| \/",
    r"[UDP:dport:443]-xsend{ipfrag;ipfrag_pos_udp=8}(drop,)-| \/",
)

X_TCP_WIDE = (
    r"[TCP:flags:PA]-xsplit{pos=2}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=host}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=1,host,midsld,endhost}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=2,6,10,14,18,22,26,30}-| \/",
    r"[TCP:flags:PA]-xsplit{pos=midsld;seqovl=336;seqovl_pattern=fake_default_tls}-| \/",
    r"[TCP:flags:PA]-xdisorder{pos=2,midsld;seqovl=1}-| \/",
    r"[TCP:flags:PA]-xdisorder{pos=1,midsld;legacy}-| \/",
    r"[TCP:flags:PA]-xtcpseg{pos=0,midsld;ip_id=rnd}-| \/",
    r"[TCP:flags:PA]-xfakeddisorder{pos=midsld;ttl=auto:-2:3-20}-| \/",
    r"[TCP:flags:PA]-xfakedsplit{pos=midsld;md5}-| \/",
    r"[TCP:flags:PA]-xhostfake{midhost=midsld;md5}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;seq=-10000}(xsplit{pos=1},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ts=-600000}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;tlsmod=padencap}(xdisorder{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;badsum;repeats=6}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;ipfrag}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xtlsclone{blob=c;sni_first=www.google.com}(xfake{blob=c;ttl=auto:-2:3-20}(xsplit{pos=1,midsld},),)-| \/",
    r"[TCP:flags:PA]-xrepeat{repeats=3}(xfake{blob=fake_default_tls;ttl=auto:-2:3-20},xsplit{pos=1,midsld})-| \/",
    r"[TCP:flags:PA]-xrst{badsum}-| \/",
    r"[TCP:flags:PA]-xrst{ttl=auto:-2:3-20}(xsplit{pos=1},)-| \/",
    r"[TCP:flags:PA]-xdrip{n=8;delay=20}-| \/",
    r"[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=32}(drop,)-| \/",
    r"[FLOW:n:a]-xsyndata{blob=fake_default_tls;tlsmod=rnd}-| \/",
    r"[FLOW:n:a]-xoob{urp=b}-| \/",
    r"[FLOW:n:a]-xoob{urp=midsld}-| \/",
    r"[FLOW:n:a]-xtlsrec{pos=midsld}(xsplit{pos=1},)-| \/",
    # SYN Windows — SEC (ECN): обе формы, как в эталоне
    r"[TCP:flags:S]-xsynack-| [TCP:flags:SEC]-xsynack-| \/",
    r"[FLOW:n:a]-xwssize{wsize=1;scale=6}-| \/",
    r"\/ [TCP:flags:SA]-xwsize{wsize=1;scale=6}-|",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ack=-66000}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;flags-=ACK}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;tsup;nopdel;ipid=rnd}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;tlsmod=sni=www.google.com}(xdisorder{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ip6ext=hopbyhop2;ttl=auto:-2:3-20}(xsplit{pos=1,midsld},)-| \/",
    r"[TCP:flags:PA]-xwhen{iff=L7:payload:tls_client_hello}(xfake{blob=fake_default_tls;md5}(xsplit{pos=2},),)-| \/",
    r"[TCP:flags:PA]-xcutoff{dir=out}(xfake{blob=fake_default_tls;ttl=auto:-2:3-20}(xsplit{pos=1,midsld},),)-| \/",
)

X_HTTP = (
    r"[TCP:flags:PA]-xhttp{hostcase}-| \/",
    r"[TCP:flags:PA]-xhttp{domcase}-| \/",
    r"[TCP:flags:PA]-xhttp{methodeol}-| \/",
    r"[TCP:flags:PA]-xhttp{unixeol}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_http;ttl=auto:-2:3-20}(xsplit{pos=method+2},)-| \/",
    r"[TCP:flags:PA]-xsplit{pos=method+2,host+1}-| \/",
)

X_QUIC_WIDE = (
    r"[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=11;ttl=auto:-2:3-20}-| \/",
    r"[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=6;md5;badsum}-| \/",
    r"[UDP:dport:443]-xfake{blob=fake_default_quic;repeats=6;ttl=4;ipfrag}-| \/",
    r"[UDP:dport:443]-xudplen{increment=2}-| \/",
    r"[UDP:dport:443]-xsend{ipfrag;ipfrag_pos_udp=16;ipfrag_disorder}(drop,)-| \/",
)

X_UDP = (
    r"[UDP:sport:*]-xfake{blob=0x" + "00" * 64 + r";repeats=6;ttl=4;payload=all}-| \/",
    r"[UDP:sport:*]-xfake{blob=0x" + "00" * 16 + r";repeats=2;badsum;payload=all}-| \/",
    r"[UDP:sport:*]-xsend{ipfrag;ipfrag_pos_udp=8}(drop,)-| \/",
    r"[UDP:sport:*]-xudplen{increment=4;payload=all}-| \/",
)

X_DHT = (
    r"[UDP:sport:*]-xdhtdn{dn=3}-| \/",
    r"[UDP:sport:*]-xdhtdn{dn=2}-| \/",
)

X_TCP_ANY = (
    r"[TCP:flags:PA]-xsplit{pos=2;payload=all}-| \/",
    r"[TCP:flags:PA]-xdisorder{pos=2;payload=all}-| \/",
    r"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20;payload=all}(xsplit{pos=2;payload=all},)-| \/",
    r"[TCP:flags:PA]-xfakedsplit{pos=2;md5;payload=all}-| \/",
    r"[TCP:flags:PA]-xtcpseg{pos=0,2;ip_id=rnd;payload=all}-| \/",
    r"[FLOW:n:a]-xoob{urp=b}-| \/",
    r"[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=16}(drop,)-| \/",
)

FAKES_PER_ROUND = 8


def blob_kind(name: str) -> str:
    """Вид фейка zapret2 по имени блоба (GenevaBlobs.KindOf)."""
    n = name[3:] if name.startswith("z2_") else name
    if n.startswith("tls_clienthello"):
        return "tls_hello"
    if n.startswith(("quic_initial", "quic2_")):
        return "quic_initial"
    if n.startswith("http_"):
        return "http"
    if n.startswith("dht_"):
        return "dht"
    if n.startswith("zero_"):
        return "zero"
    if n.startswith(("bgp", "bitcoin", "rdp", "rtsp", "smtp", "tls_")):
        return "tcp_other"
    return "udp_other"


def _tls_site(s: Service) -> bool:
    return s.kind == WEB or (s.transport == "tcp" and
                             s.app in ("tls", "http"))


def slice_round(items, size: int, rnd: int) -> list:
    """``rnd``-й отрезок по ``size`` с переходом через конец: круги
    вместе проходят весь список."""
    items = list(items)
    if len(items) <= size:
        return items
    start = max(0, int(rnd)) * size % len(items)
    return [items[(start + i) % len(items)] for i in range(size)]


def blob_candidates(s: Service, blobs) -> list:
    """По стратегии на каждый подходящий сервису фейк zapret2."""
    names = sorted(set(blobs or ()))

    def of(*kinds):
        return [n for n in names if blob_kind(n) in kinds]
    out = []
    ports = set(s.ports or ())
    if s.kind == QUIC:
        for b in of("quic_initial"):
            out.append(r"[UDP:dport:443]-xfake{blob=%s;repeats=6;"
                       r"ttl=auto:-2:3-20}-| \/" % b)
    elif _tls_site(s):
        # сайт, виденный только на 80, ClientHello не шлёт
        tls = not ports or 443 in ports or 80 not in ports
        hellos = of("tls_hello") if tls else []
        for b in hellos:
            out.append(r"[TCP:flags:PA]-xfake{blob=%s;ttl=auto:-2:3-20}"
                       r"(xsplit{pos=1,midsld},)-| \/" % b)
            out.append(r"[TCP:flags:PA]-xfake{blob=%s;md5}"
                       r"(xdisorder{pos=1,midsld},)-| \/" % b)
        if hellos:
            out.append(r"[TCP:flags:PA]-xsplit{pos=midsld;seqovl=336;"
                       r"seqovl_pattern=%s}-| \/" % hellos[0])
        if 80 in ports:
            for b in of("http"):
                out.append(r"[TCP:flags:PA]-xfake{blob=%s;ttl=auto:-2:3-20}"
                           r"(xsplit{pos=method+2},)-| \/" % b)
    elif s.kind == DNS:
        pass
    elif s.transport == "udp":
        kinds = ("dht", "zero") if s.app == "dht" else ("udp_other", "zero")
        for b in of(*kinds):
            out.append(r"[UDP:sport:*]-xfake{blob=%s;repeats=4;ttl=4;"
                       r"payload=all}-| \/" % b)
    else:
        for b in of("tcp_other", "zero", "http"):
            out.append(r"[TCP:flags:PA]-xfake{blob=%s;ttl=auto:-2:3-20;"
                       r"payload=all}(xsplit{pos=2;payload=all},)-| \/" % b)
    return out


def x_for(s: Service, ext: bool, wide: bool = True, blobs=(),
          rnd: int = 0) -> list:
    """Методы zapret2 для сервиса (XFor): обычные и, в широком круге,
    остальные плюс фейки zapret2 по :data:`FAKES_PER_ROUND` за круг
    (каждый круг — следующие). Пусто без ``ext`` (фича ``ext_xact``)."""
    if not ext:
        return []
    ports = set(s.ports or ())
    # чистый HTTP — только если сайт не виден на 443: TLS xhttp не трогает
    http = 80 in ports and 443 not in ports
    fakes = slice_round(blob_candidates(s, blobs) if wide else [],
                        FAKES_PER_ROUND, rnd)
    if s.kind == QUIC:
        return list(X_QUIC) + (list(X_QUIC_WIDE) if wide else []) + fakes
    if _tls_site(s):
        return (list(X_HTTP) if http or (wide and 80 in ports) else []) + \
            list(X_TCP) + (list(X_TCP_WIDE) if wide else []) + fakes
    if s.kind == DNS:
        return []
    if s.transport == "udp":
        return (list(X_DHT) if s.app == "dht" else list(X_UDP)) + fakes
    return list(X_TCP_ANY) + fakes


def candidate_rounds(s: Service, running=(), found=(), proven=(),
                     library=(), ext: bool = False, blobs=(),
                     rnd: int = 0) -> list:
    """Круги перебора до генетического подбора: ``[[проверенные],
    [остальные]]`` (пустые круги выброшены).

    1. **проверенные в этой сети** — стратегии работающих групп того же
       транспорта (сервис вступит в группу, а не откроет новую), найденные
       раньше для этой цели (``found``), затем работающие для других
       сервисов и импортированные (``proven`` — уже по рангу: больше
       сервисов и успехов — раньше);
    2. **все остальные** — стартовый набор, шаблоны и вся библиотека
       исследований Geneva (``library``) для транспорта.

    С ``ext`` (geneva_c 2.0, ``ext_xact``) во второй круг перед
    библиотекой идут методы zapret2 (:func:`x_for`, широкий набор и
    фейки zapret2 ``blobs`` по 8 за круг ``rnd``), сверх
    :data:`MAX_CANDIDATES`.

    Отличие от эталона: там один круг до 12 кандидатов и без библиотеки.
    Здесь перебираются все известные стратегии, но второй круг
    запускается, только если проверенные не подошли.
    """
    from core.geneva_manager import check_strategy_text
    if s.kind == DNS:
        classics = AUTO_CANDIDATES_DNS + AUTO_PRESETS_UDP + \
            AUTO_CANDIDATES_UDP
    elif s.transport == "udp":
        classics = AUTO_PRESETS_UDP + AUTO_CANDIDATES_UDP
    else:
        classics = AUTO_PRESETS_TCP + AUTO_CANDIDATES_TCP
    # отвергнутые для этого сервиса (помогали роутеру, но не устройствам)
    seen = set(s.rejected or ())
    total = [0]

    xs = x_for(s, ext, True, blobs, rnd)
    limit = MAX_CANDIDATES + len(xs)

    def take(items, cap) -> list:
        out = []
        for c in items:
            if not c or not _fits(s, c):
                continue
            if not ext and needs_ext(c):
                continue
            try:
                c = check_strategy_text(c)
            except ValueError:
                continue
            if c in seen:
                continue
            if len(out) >= cap or total[0] >= limit:
                break
            seen.add(c)
            out.append(c)
            total[0] += 1
        return out

    first = take(list(running) + list(found) + list(proven),
                 MAX_QUICK_CANDIDATES)
    rest = take(list(classics) + xs + list(library), limit)
    return [r for r in (first, rest) if r]


def candidates_for(s: Service, running=(), found=()) -> list:
    """Что пробовать: стратегии работающих групп того же транспорта
    (сервис вступит в группу, а не откроет новую), найденные раньше,
    предустановленные, затем классика."""
    if s.kind == DNS:
        classics = AUTO_CANDIDATES_DNS + AUTO_PRESETS_UDP + \
            AUTO_CANDIDATES_UDP
    elif s.transport == "udp":
        classics = AUTO_PRESETS_UDP + AUTO_CANDIDATES_UDP
    else:
        classics = AUTO_PRESETS_TCP + AUTO_CANDIDATES_TCP
    from core.geneva_manager import check_strategy_text
    out = []
    for c in list(x for x in running if _fits(s, x)) + \
            list(x for x in found if _fits(s, x)) + list(classics):
        try:
            c = check_strategy_text(c)
        except ValueError:
            continue
        if c not in out:
            out.append(c)
        if len(out) >= MAX_QUICK_CANDIDATES:
            break
    return out


def protos_for(s: Service) -> str:
    """Пространство поиска geneva (``--protos``)."""
    if s.kind == DNS:
        return "UDP,IP,DNS,DNSQR"
    return "UDP,IP" if s.transport == "udp" else "TCP"


def search_target(s: Service) -> str:
    """Ключ цели в базе оценок geneva: страница сайта или повтор."""
    if s.kind == WEB:
        return "https:%s" % (s.host or s.name)
    return "replay:%s:%d" % (s.address, s.port)


# ───────────────────────────── найденные стратегии ──────────────────

def _target_text(target: str) -> str:
    """``https:www.x.org`` → ``www.x.org``, ``replay:1.2.3.4:53`` →
    ``1.2.3.4:53``: цель базы оценок человеческим языком."""
    t = str(target or "")
    for prefix in ("https:", "http:", "tls:", "replay:", "dns:", "tcp:"):
        if t.startswith(prefix):
            return t[len(prefix):]
    return t


def found_strategies(services, db_items=(), working: str = "") -> list:
    """Стратегии, которые РАБОТАЮТ в этой сети, для страницы «Стратегии».

    Источники — только проверенное у пользователя: сервисы режима «Авто»
    с обходом (``applied``/``degraded``) и оценки ручного подбора с
    успехами (``geneva db top``). Библиотека исследований и шаблоны сюда
    не входят. Строка — одна стратегия: где работает, лучшая оценка,
    когда последний раз подтверждена; первыми — те, что держат больше
    сервисов.
    """
    rows = {}

    def row(strategy):
        strategy = str(strategy or "").strip()
        if not strategy:
            return None
        if strategy not in rows:
            rows[strategy] = {"strategy": strategy, "services": [],
                              "targets": [], "auto": False,
                              "degraded": 0, "fitness": None, "last": 0.0,
                              "working": strategy == (working or "").strip()}
        return rows[strategy]

    for s in services or []:
        if isinstance(s, dict):
            s = Service.from_dict(s)
        if s.status not in (APPLIED, DEGRADED) or not s.strategy:
            continue
        r = row(s.strategy)
        r["auto"] = True
        r["services"].append({"key": s.key, "name": s.name or s.key,
                              "kind": s.kind, "status": s.status})
        if s.status == DEGRADED:
            r["degraded"] += 1
        if s.fitness:
            r["fitness"] = max(r["fitness"] or s.fitness, s.fitness)
        r["last"] = max(r["last"], float(s.applied_at or 0))
    for it in db_items or []:
        try:
            ok = int(it.get("ok") or 0)
        except (TypeError, ValueError):
            ok = 0
        if ok <= 0:
            continue
        r = row(it.get("strategy"))
        if r is None:
            continue
        text = _target_text(it.get("target", ""))
        if text and text not in r["targets"]:
            r["targets"].append(text)
        best = it.get("best_fitness")
        try:
            best = float(best) if best is not None else None
        except (TypeError, ValueError):
            best = None
        if best is not None:
            r["fitness"] = best if r["fitness"] is None \
                else max(r["fitness"], best)
        try:
            r["last"] = max(r["last"], float(it.get("last_ok") or 0))
        except (TypeError, ValueError):
            pass
    out = list(rows.values())
    for r in out:
        r["services"].sort(key=lambda x: x["name"])
    out.sort(key=lambda r: (-len(r["services"]), -len(r["targets"]),
                            -(r["fitness"] or 0), r["strategy"]))
    return out
