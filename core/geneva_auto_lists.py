# core/geneva_auto_lists.py
"""
Режим «Авто» geneva: важность сервисов и списки пользователя.

Перенос ``Core/Geneva/Auto/AutoPriorities.cs`` Zapret2_AutoTuner (issue 28
эталона, v1.3–v1.4). Чистые функции и данные: сеть нужна только
:func:`fetch_asn` (RIPEstat), её зовёт менеджер в своём потоке.

**Важность** (:data:`IMPORTANT` … :data:`BACKGROUND`, меньше — важнее)
решает, кого подтверждать и подбирать первым, кто может прервать чужой
подбор и кто первым уходит из полной книги:

- ``important`` — метка пользователя, список «Важно» и известные
  семейства (:data:`FAMILIES`: YouTube, Discord, Telegram, WhatsApp,
  Instagram/Facebook, X), если включено ``known_important``;
- ``normal`` — сайт, QUIC и DNS;
- ``low`` — сервер (с именем или узнанным протоколом);
- ``background`` — локальный порт, «голый» пир (без имени, протокол не
  узнан, порт ≥ 10000: так выглядят пиры торрента) и список «Не важно».
  Фоновый, который ждёт подтверждения или подбора дольше
  :data:`STARVATION_STEP`, поднимается до ``low``: когда-нибудь его
  подберут, но чужой подбор он не прервёт никогда.

**Списки** (:class:`NameList`): домен (с поддоменами), адрес и подсеть.
Списки, которые читает только zapret-gui («Важно», «Не важно», «Не
подбирать»), берут ещё маски: зону (``*.ru`` или ``.ru``), шаблон с
``*`` и ``?`` (``*google*``) и сеть провайдера по номеру AS
(``AS12389``), её адреса — из RIPEstat. «Не трогать» уходит в geneva
(ручной ``run``) как есть, поэтому принимает только домены, адреса и
подсети (:func:`problem`).
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re

# ───────────────────────────── важность ─────────────────────────────

IMPORTANT = 0
NORMAL = 1
LOW = 2
BACKGROUND = 3
PRIORITY_NAMES = ("important", "normal", "low", "background")
PRIORITY_TEXT = {
    IMPORTANT: ("важный", "important"),
    NORMAL: ("обычный", "normal"),
    LOW: ("сервер", "server"),
    BACKGROUND: ("фон", "background"),
}

# Слово пользователя об одном сервисе: перекрывает вычисленную важность.
USER_NONE = ""
USER_IMPORTANT = "important"
USER_UNIMPORTANT = "unimportant"
USER_PRIORITIES = (USER_NONE, USER_IMPORTANT, USER_UNIMPORTANT)

STARVATION_STEP = 30 * 60.0      # фоновый ждёт столько — поднимается
RESERVED_PLACES = 60             # мест книги только для важных и обычных
BARE_PORT = 10000                # «голый» пир: порт не ниже этого

# Сервисы, которые для человека одно, а в сети — несколько сайтов:
# YouTube — это youtube.com, его видео с googlevideo.com и картинки с
# ytimg.com. Стратегия, найденная одному, первой пробуется остальным.
FAMILIES = {
    "YouTube": ("youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
                "ggpht.com", "youtube-nocookie.com",
                "youtubei.googleapis.com", "yt.be"),
    "Discord": ("discord.com", "discord.gg", "discordapp.com",
                "discordapp.net", "discord.media", "discordcdn.com",
                "discord.dev", "discordstatus.com"),
    "Telegram": ("telegram.org", "t.me", "telegram.me", "telesco.pe",
                 "tdesktop.com", "telegra.ph", "cdn-telegram.org"),
    "WhatsApp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "Instagram": ("instagram.com", "cdninstagram.com", "facebook.com",
                  "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com"),
    "X": ("x.com", "twitter.com", "twimg.com", "t.co"),
}
_BY_DOMAIN = {d: f for f, ds in FAMILIES.items() for d in ds}

# Пределы списков: строки уходят в settings.json и в argv geneva.
MAX_ENTRIES = 500
MAX_ASN_PREFIXES = 5000          # сетей на один AS
ASN_REFRESH = 7 * 86400.0        # сети AS обновляются раз в неделю
ASN_URL = ("https://stat.ripe.net/data/announced-prefixes/data.json"
           "?resource=AS%d")


def family_of(name: str):
    """Семейство имени (хост или регистрируемый домен) или ``None``."""
    n = str(name or "").strip().rstrip(".").lower()
    # «youtube.com (QUIC)» на странице: имя — первое слово
    n = n.split(" ", 1)[0]
    while n:
        f = _BY_DOMAIN.get(n)
        if f:
            return f
        if "." not in n:
            break
        n = n.split(".", 1)[1]
    return None


def site_of(s) -> str:
    """Регистрируемый домен сайта или QUIC-сервиса (ключ без вида)."""
    key = getattr(s, "key", "") or ""
    if key.startswith("web:"):
        return key[4:]
    if key.startswith("quic:"):
        return key[5:]
    return getattr(s, "name", "") or ""


def service_family(s):
    """Семейство сайта или QUIC-сервиса; ``None`` для остальных."""
    if getattr(s, "kind", "") not in ("web", "quic"):
        return None
    return family_of(site_of(s))


# ───────────────────────────── списки ───────────────────────────────

_DOMAIN_CHARS = re.compile(r"^[a-z0-9._-]+$")
_PATTERN_CHARS = re.compile(r"^[a-z0-9._*?-]+$")
_ZONE_CHARS = re.compile(r"^[a-z0-9-]{1,63}$")


def _norm(entry) -> str:
    return str(entry or "").strip().rstrip(".").lower()


def _net(e: str):
    """Адрес или подсеть → ``ip_network`` или ``None``."""
    if not e or e.count("/") > 1:
        return None
    try:
        net = ipaddress.ip_network(e, strict=False)
    except ValueError:
        return None
    # голый адрес без длины — /32 или /128 (ip_network так и делает)
    if net.version == 6 and net.network_address.ipv4_mapped is not None \
            and net.prefixlen == 128:
        net = ipaddress.ip_network(str(net.network_address.ipv4_mapped))
    return net


def _is_domain(e: str) -> bool:
    # ведущая «*» — только как «*.»: «*cdn.net» — шаблон (fastcdn.net)
    if e.startswith("*") and not e.startswith("*."):
        return False
    d = e.lstrip("*.")
    if not d or len(d) > 253 or "." not in d:
        return False
    if not _DOMAIN_CHARS.match(d):
        return False
    return not d.startswith(".") and not d.endswith(".") and ".." not in d


def _zone(e: str):
    """Целая зона: ``*.ru`` или ``.ru`` (одна метка — не домен)."""
    if not (e.startswith("*.") or e.startswith(".")):
        return None
    z = e.lstrip("*.")
    return z if _ZONE_CHARS.match(z) else None


def _asn(e: str):
    if len(e) < 3 or len(e) > 12 or not e.startswith("as"):
        return None
    tail = e[2:]
    if not tail.isdigit():
        return None
    n = int(tail)
    return n if n > 0 else None


def _is_pattern(e: str) -> bool:
    return (len(e) <= 253 and ("*" in e or "?" in e)
            and any(c.isalnum() for c in e)
            and bool(_PATTERN_CHARS.match(e)))


def _pattern_re(e: str):
    return re.compile("^" + re.escape(e).replace(r"\*", ".*")
                      .replace(r"\?", ".") + "$")


def problem(entry) -> str:
    """Почему строка не домен, не адрес и не подсеть (строгий вид: «Не
    трогать», его берёт geneva как есть); ``""`` — годится."""
    e = _norm(entry)
    if not e or e.startswith("#"):
        return ""
    if _net(e) is not None or _is_domain(e):
        return ""
    return "не домен и не адрес: %s" % str(entry).strip()[:80]


def mask_problem(entry) -> str:
    """Как :func:`problem`, но годятся и маски: зона, шаблон, AS."""
    e = _norm(entry)
    if not e or e.startswith("#"):
        return ""
    if _net(e) is not None or _is_domain(e) or _zone(e) is not None or \
            _asn(e) is not None or _is_pattern(e):
        return ""
    return "не домен, не маска, не адрес и не AS: %s" % \
        str(entry).strip()[:80]


def asns_of(entries) -> list:
    """Номера AS, названные в строках (``AS12389``)."""
    out = []
    for raw in entries or []:
        n = _asn(_norm(raw))
        if n is not None and n not in out:
            out.append(n)
    return out


class NameList:
    """Список пользователя: домены, маски, адреса, подсети и сети AS.

    ``asn`` — ``{"12389": ["1.2.3.0/24", …]}``; AS без сетей пока ничего
    не находит. Сети AS сливаются и ищутся бинарным поиском: у крупного
    оператора их тысячи.
    """

    def __init__(self, entries=(), asn=None):
        self.domains = set()
        self.nets = []
        self.patterns = []
        self.asns = []
        self._ranges = {4: [], 6: []}
        asn_nets = []
        for raw in entries or []:
            e = _norm(raw)
            if not e or e.startswith("#"):
                continue
            net = _net(e)
            if net is not None:
                self.nets.append(net)
            elif _is_domain(e):
                self.domains.add(e.lstrip("*."))
            elif _zone(e) is not None:
                self.domains.add(_zone(e))
            elif _asn(e) is not None:
                n = _asn(e)
                self.asns.append(n)
                for p in (asn or {}).get(str(n)) or []:
                    pn = _net(_norm(p))
                    if pn is not None:
                        asn_nets.append(pn)
            elif _is_pattern(e):
                self.patterns.append(_pattern_re(e))
        for ver in (4, 6):
            merged = ipaddress.collapse_addresses(
                [n for n in asn_nets if n.version == ver])
            self._ranges[ver] = [(int(n.network_address),
                                  int(n.broadcast_address))
                                 for n in merged]
        self._starts = {v: [a for a, _ in r]
                        for v, r in self._ranges.items()}

    @property
    def empty(self) -> bool:
        return not (self.domains or self.nets or self.patterns or
                    self._ranges[4] or self._ranges[6])

    def plain_domains(self) -> list:
        """Домены с точкой (зоны и шаблоны geneva не нужны)."""
        return sorted(d for d in self.domains if "." in d)

    def subnets(self) -> list:
        """Подсети в виде CIDR (адрес — /32 или /128), без сетей AS."""
        return [str(n) for n in self.nets]

    def matches_name(self, name) -> bool:
        if not name or not (self.domains or self.patterns):
            return False
        n = _norm(name)
        for p in self.patterns:
            if p.match(n):
                return True
        while n:
            if n in self.domains:
                return True
            if "." not in n:
                return False
            n = n.split(".", 1)[1]
        return False

    def matches_address(self, ip) -> bool:
        try:
            a = ipaddress.ip_address(str(ip or ""))
        except ValueError:
            return False
        if a.version == 6 and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        for n in self.nets:
            if a.version == n.version and a in n:
                return True
        ranges = self._ranges[a.version]
        if not ranges:
            return False
        x = int(a)
        i = bisect.bisect_right(self._starts[a.version], x) - 1
        return i >= 0 and x <= ranges[i][1]

    def matches(self, s) -> bool:
        """Сервис списка: по сайту, по имени хоста, по любому адресу."""
        if self.empty:
            return False
        kind = getattr(s, "kind", "")
        if kind in ("web", "quic") and (self.matches_name(site_of(s)) or
                                        self.matches_name(s.host)):
            return True
        if kind == "endpoint" and self.matches_name(s.host):
            return True
        return any(self.matches_address(a.get("ip"))
                   for a in getattr(s, "addresses", []) or [])

    def matches_sample(self, x) -> bool:
        """Поток среза: по имени или адресу сервера."""
        if self.empty:
            return False
        return self.matches_name(getattr(x, "host", "")) or \
            self.matches_name(getattr(x, "name", "")) or \
            self.matches_address(getattr(x, "ip", ""))


EMPTY = NameList()


# ───────────────────────────── набор списков ────────────────────────

LIST_KEYS = ("important", "unimportant", "no_search", "exclude")


def clean_entries(value, strict: bool = False):
    """Строки списка из текста или списка → ``(строки, ошибки)``.
    ``strict`` — только домены, адреса, подсети («Не трогать»)."""
    if isinstance(value, str):
        value = value.replace(",", "\n").splitlines()
    if not isinstance(value, (list, tuple)):
        return [], ["ожидается список строк"]
    out, errors = [], []
    for raw in value:
        e = str(raw or "").strip()
        if not e or e.startswith("#"):
            continue
        why = problem(e) if strict else mask_problem(e)
        if why:
            errors.append(why)
            continue
        e = _norm(e)
        net = _net(e)
        if net is not None:
            e = str(net.network_address) if net.prefixlen == \
                net.max_prefixlen else str(net)
        if e not in out:
            out.append(e)
    if len(out) > MAX_ENTRIES:
        errors.append("не больше %d строк в списке" % MAX_ENTRIES)
        out = out[:MAX_ENTRIES]
    return out, errors


class Lists:
    """Списки, которые ведут режим (``geneva.auto.lists`` + сети AS)."""

    def __init__(self, raw=None, asn=None):
        raw = raw if isinstance(raw, dict) else {}
        self.raw = {}
        for k in LIST_KEYS:
            v = raw.get(k) or []
            self.raw[k] = [str(x) for x in v if x][:MAX_ENTRIES] \
                if isinstance(v, list) else []
        self.known_important = bool(raw.get("known_important", True))
        self.asn = asn if isinstance(asn, dict) else {}
        self.important = NameList(self.raw["important"], self.asn)
        self.unimportant = NameList(self.raw["unimportant"], self.asn)
        self.no_search = NameList(self.raw["no_search"], self.asn)
        # «Не трогать» уходит в geneva как есть: без масок и AS
        self.exclude = NameList([e for e in self.raw["exclude"]
                                 if not problem(e)])

    def to_dict(self) -> dict:
        d = {k: list(v) for k, v in self.raw.items()}
        d["known_important"] = self.known_important
        return d

    def asns(self) -> list:
        return asns_of(self.raw["important"] + self.raw["unimportant"] +
                       self.raw["no_search"])


def base_priority(s, lists: Lists = None) -> int:
    """Важность без учёта ожидания."""
    lists = lists or Lists()
    up = getattr(s, "user_priority", "") or ""
    if up == USER_IMPORTANT:
        return IMPORTANT
    if up == USER_UNIMPORTANT:
        return BACKGROUND
    if lists.important.matches(s):
        return IMPORTANT
    if lists.unimportant.matches(s):
        return BACKGROUND
    if lists.known_important and service_family(s):
        return IMPORTANT
    kind = getattr(s, "kind", "")
    if kind in ("web", "quic", "dns"):
        return NORMAL
    if kind == "local_port":
        return BACKGROUND
    return BACKGROUND if is_bare(s) else LOW


def is_bare(s) -> bool:
    """Скорее пир, чем сервер: без имени, протокол не узнан, высокий
    порт. VPN на 51820 узнаётся как WireGuard и голым не считается."""
    return (getattr(s, "kind", "") == "endpoint"
            and not getattr(s, "host", "")
            and (getattr(s, "app", "") or "") in ("tcp", "udp", "")
            and int(getattr(s, "port", 0) or 0) >= BARE_PORT)


def effective(s, now: float) -> int:
    """Важность с учётом ожидания: фоновый, ждущий подтверждения или
    подбора дольше :data:`STARVATION_STEP`, поднимается до ``low``."""
    p = int(getattr(s, "priority", NORMAL))
    if p != BACKGROUND or getattr(s, "status", "") not in ("blocked",
                                                           "suspected"):
        return p
    since = getattr(s, "since", None)
    since = now if since is None else float(since)
    return LOW if now - since >= STARVATION_STEP else BACKGROUND


# ───────────────────────────── сети AS (RIPEstat) ───────────────────

def parse_ripe(payload) -> list:
    """Ответ ``announced-prefixes`` → слитые сети (не больше
    :data:`MAX_ASN_PREFIXES`)."""
    try:
        data = json.loads(payload) if isinstance(payload, (str, bytes)) \
            else payload
        items = data["data"]["prefixes"]
    except (ValueError, KeyError, TypeError):
        return []
    nets = []
    for it in items or []:
        n = _net(_norm((it or {}).get("prefix") if isinstance(it, dict)
                       else ""))
        if n is not None:
            nets.append(n)
    out = []
    for ver in (4, 6):
        out += [str(n) for n in ipaddress.collapse_addresses(
            [n for n in nets if n.version == ver])]
    return out[:MAX_ASN_PREFIXES]


def fetch_asn(number: int, timeout: float = 20.0) -> list:
    """Сети AS из RIPEstat. Уходит только номер AS; сертификат
    проверяется: ответ решает, какой трафик важен. Ошибка — исключение."""
    import ssl
    import urllib.request
    req = urllib.request.Request(ASN_URL % int(number),
                                 headers={"User-Agent": "zapret-gui"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return parse_ripe(r.read(8 * 1024 * 1024))


def stale_asns(lists: Lists, fetched: dict, now: float) -> list:
    """AS из списков, чьи сети не загружены или старше недели."""
    out = []
    for n in lists.asns():
        at = (fetched or {}).get(str(n))
        try:
            at = float(at)
        except (TypeError, ValueError):
            at = None
        if at is None or now - at >= ASN_REFRESH:
            out.append(n)
    return out
