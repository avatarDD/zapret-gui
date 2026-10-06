# core/routing/domain_match.py
"""
Сопоставление имён из DNS с доменами маршрута: суффикс, wildcard, regex.

Запись в списке доменов маршрута бывает трёх видов:

* ``example.com`` (и ``*.example.com`` — то же самое) — сам домен и
  все поддомены. Это единственный вид, который понимают все пути:
  dnsmasq (``ipset=/…/``), NDMS (``object-group fqdn``), заблаговременный
  резолв и DNS-перехват;
* wildcard — ``*`` или ``?`` не только в ведущем ``*.``:
  ``cdn*.example.com``, ``r?---sn-*.googlevideo.com``. ``*`` — любая
  последовательность символов (в том числе с точками), ``?`` — ровно один;
* regex — ``regexp:<выражение>`` (как в v2fly/sing-box), ищется
  ``re.search`` по имени в нижнем регистре.

Wildcard и regex — шаблоны, а не имена: их нельзя заранее разрезолвить и
нельзя отдать dnsmasq или NDMS. Работают они только там, где видны живые
DNS-ответы клиентов, — в DNS-перехвате (``core/routing/dns_intercept``).
Остальные пути их пропускают (:func:`plain_domains`), а страница маршрутов
предупреждает, если перехват выключен (MagiTrickle держит те же типы
правил: domain/namespace/wildcard/regex).

Имена сравниваются в нижнем регистре: резолвер может ответить с
рандомизацией регистра (0x20), и ``Example.COM`` не должен пройти мимо
правила — у MagiTrickle эту грабли не обойдены.
"""

import re

REGEX_PREFIX = "regexp:"

# Защита от катастрофического бэктрекинга в пользовательском regex:
# имя DNS не длиннее 253 символов, а шаблон ограничим разумно.
MAX_PATTERN_LEN = 256


def kind_of(entry: str) -> str:
    """'domain' | 'wildcard' | 'regex' | '' (пусто/мусор). Чистая."""
    e = (entry or "").strip()
    if not e:
        return ""
    if e.lower().startswith(REGEX_PREFIX):
        return "regex"
    body = e[2:] if e.startswith("*.") else e
    if "*" in body or "?" in body:
        return "wildcard"
    return "domain"


def normalize_domain(entry: str) -> str:
    """``*.Example.com.`` → ``example.com`` (для вида 'domain')."""
    e = (entry or "").strip().lower().rstrip(".")
    if e.startswith("*."):
        e = e[2:]
    return e.strip(".")


def is_pattern(entry: str) -> bool:
    return kind_of(entry) in ("wildcard", "regex")


def plain_domains(entries) -> list:
    """Только обычные домены (нормализованные) — для dnsmasq/NDMS/резолва."""
    out, seen = [], set()
    for e in entries or []:
        if kind_of(e) != "domain":
            continue
        d = normalize_domain(e)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def patterns(entries) -> list:
    """Только шаблоны (wildcard/regex), как записаны."""
    return [str(e).strip() for e in entries or [] if is_pattern(e)]


def wildcard_to_regex(pattern: str) -> str:
    """``cdn*.example.com`` → ``^cdn.*\\.example\\.com$``. Чистая."""
    out = []
    for ch in pattern.lower():
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


def compile_entry(entry: str):
    """Скомпилированный regex шаблона или None (обычный домен/ошибка)."""
    kind = kind_of(entry)
    e = str(entry).strip()
    if len(e) > MAX_PATTERN_LEN:
        return None
    try:
        if kind == "regex":
            return re.compile(e[len(REGEX_PREFIX):], re.IGNORECASE)
        if kind == "wildcard":
            return re.compile(wildcard_to_regex(e))
    except re.error:
        return None
    return None


def validate_entry(entry: str) -> str:
    """Текст ошибки для записи списка доменов или '' (всё в порядке)."""
    e = (entry or "").strip()
    kind = kind_of(e)
    if not kind:
        return "пустая запись"
    if len(e) > MAX_PATTERN_LEN:
        return "слишком длинная запись (>%d символов)" % MAX_PATTERN_LEN
    if kind == "regex":
        try:
            re.compile(e[len(REGEX_PREFIX):])
        except re.error as exc:
            return "regex не компилируется: %s" % exc
        return ""
    body = normalize_domain(e) if kind == "domain" else e.lower()
    if kind == "wildcard":
        body = body.replace("*", "a").replace("?", "a")
        if body.startswith("a."):
            body = body[2:]
    if not _DOMAIN_RE.match(body):
        return "не похоже на домен"
    return ""


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


class Matcher:
    """Набор доменов и шаблонов одного правила."""

    __slots__ = ("domains", "regexes")

    def __init__(self, entries):
        self.domains = set()
        self.regexes = []
        for e in entries or []:
            kind = kind_of(e)
            if kind == "domain":
                d = normalize_domain(e)
                if d:
                    self.domains.add(d)
            elif kind:
                rx = compile_entry(e)
                if rx is not None:
                    self.regexes.append(rx)

    def __bool__(self):
        return bool(self.domains or self.regexes)

    def match(self, name: str) -> bool:
        """Имя под правилом? Суффикс — проход по меткам, без перебора."""
        n = (name or "").lower().rstrip(".")
        if not n:
            return False
        if self.domains:
            probe = n
            while True:
                if probe in self.domains:
                    return True
                dot = probe.find(".")
                if dot < 0:
                    break
                probe = probe[dot + 1:]
        for rx in self.regexes:
            if rx.search(n):
                return True
        return False

    def match_any(self, names) -> bool:
        return any(self.match(n) for n in names or ())
