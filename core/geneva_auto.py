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
from dataclasses import dataclass, field

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
        )


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
_SEARCH_ORDER = {WEB: 0, DNS: 1, ENDPOINT: 2, QUIC: 3}


def threshold(s: Service) -> int:
    if s.kind == LOCAL_PORT:
        return PEER_FAILS_TO_SUSPECT
    if s.transport == "udp":
        return UDP_FAILS_TO_SUSPECT
    return FAILS_TO_SUSPECT


def suspicious(s: Service):
    """``(похоже на DPI, почему)``: провалы и ни одного успеха."""
    why = s.why
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


def _trim(s: Service, now: float) -> None:
    start = now - WINDOW
    for name in ("fails", "oks", "no_connections"):
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

    def __init__(self, saved=None, now: float = 0.0):
        self._services = {}
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

    # ── наблюдение ──

    def feed(self, samples, now: float) -> None:
        """Срез в книгу. Новый сервис начинает с ``watching``."""
        for x in samples or []:
            s = self._services.get(x.key)
            if s is None:
                if len(self._services) >= MAX_SERVICES and not self._evict():
                    continue
                s = Service(key=x.key, kind=x.kind, transport=x.transport,
                            name=x.name, app=x.app, status=WATCHING,
                            since=now, first_seen=x.time,
                            local_port=x.local_port
                            if x.kind == LOCAL_PORT else 0,
                            client=x.client if x.kind == LOCAL_PORT else "")
                self._services[x.key] = s
            s.last_seen = max(s.last_seen, x.time)
            if x.host:
                s.host = x.host
            if x.kind != LOCAL_PORT and x.ip:
                _add_address(s, x.ip, x.time)
                if x.port and x.port not in s.ports and \
                        len(s.ports) < MAX_PORTS:
                    s.ports.append(x.port)
            if x.replay:
                s.replay = to_base64(x.replay)
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

    def _evict(self) -> bool:
        victims = [s for s in self._services.values()
                   if s.status in (WATCHING, NOT_BLOCKED, FALLBACK,
                                   IP_BLOCKED)]
        if not victims:
            return False
        victim = min(victims, key=lambda s: s.last_seen)
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
                if fails >= threshold(s):
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

    def next_to_confirm(self, now: float):
        cands = [s for s in self._services.values()
                 if s.status in (SUSPECTED, DEGRADED)
                 and (s.next_check is None or now >= s.next_check)]
        if not cands:
            return None
        return sorted(cands, key=lambda s: (
            s.status != DEGRADED,
            -(len(s.fails) + len(s.no_connections))))[0]

    def next_to_search(self, now: float):
        cands = [s for s in self._services.values()
                 if s.status == BLOCKED
                 and (s.next_check is None or now >= s.next_check)]
        if not cands:
            return None
        return sorted(cands, key=lambda s: (
            _SEARCH_ORDER.get(s.kind, 4),
            -(len(s.fails) + len(s.no_connections))))[0]

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
        s.rejected = []
        s.next_check = None
        s.attempts = 0
        s.fails = []
        s.no_connections = []
        _move(s, WATCHING, now, "")
        return True

    def interrupted(self, key: str, now: float) -> None:
        s = self.find(key)
        if s is not None and s.status == SEARCHING:
            _move(s, BLOCKED, now, "подбор прерван, продолжу")

    def counts(self) -> dict:
        out = {}
        for s in self._services.values():
            out[s.status] = out.get(s.status, 0) + 1
        return out


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


def plan_groups(services, trial=None, max_groups: int = MAX_GROUPS) -> list:
    """Группы: активные сервисы по стратегии, пробуемая — первой.

    ``trial`` — ``(Service, strategy)``: стратегия, которую сейчас
    проверяют на одном сервисе. Пара «адрес + транспорт» (или локальный
    порт) достаётся только первой группе: сайты за одним адресом CDN с
    разными стратегиями не делят пакеты.
    """
    trial_key = trial[0].key if trial else None
    active = [(s, s.strategy) for s in services
              if s.is_active and s.key != trial_key]
    if trial:
        active.append((trial[0], trial[1]))
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
        not (trial and g.strategy == trial[1] and trial_key in g.services),
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


def _fits(s: Service, strategy: str) -> bool:
    low = strategy.lower()
    if s.transport == "udp" or s.kind == DNS:
        return "[udp:" in low or "[ip:" in low or "[dns" in low
    return "[tcp:" in low or "[ip:" in low


def candidate_rounds(s: Service, running=(), found=(), proven=(),
                     library=()) -> list:
    """Круги перебора до генетического подбора: ``[[проверенные],
    [остальные]]`` (пустые круги выброшены).

    1. **проверенные в этой сети** — стратегии работающих групп того же
       транспорта (сервис вступит в группу, а не откроет новую), найденные
       раньше для этой цели (``found``), затем работающие для других
       сервисов и импортированные (``proven`` — уже по рангу: больше
       сервисов и успехов — раньше);
    2. **все остальные** — стартовый набор, шаблоны и вся библиотека
       исследований Geneva (``library``) для транспорта.

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

    def take(items, cap) -> list:
        out = []
        for c in items:
            if not c or not _fits(s, c):
                continue
            try:
                c = check_strategy_text(c)
            except ValueError:
                continue
            if c in seen:
                continue
            if len(out) >= cap or total[0] >= MAX_CANDIDATES:
                break
            seen.add(c)
            out.append(c)
            total[0] += 1
        return out

    first = take(list(running) + list(found) + list(proven),
                 MAX_QUICK_CANDIDATES)
    rest = take(list(classics) + list(library), MAX_CANDIDATES)
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
