# core/geneva_related.py
"""
Связанные ресурсы сайта для итоговой проверки стратегии geneva.

Перенос итоговой проверки AutoTuner 1.5 (``GenevaBrowserCheck``,
``AutoPlan.TrialFamilies``). Там встроенный браузер открывает страницу и
смотрит, загрузились ли и её важные ресурсы: другие имена сайта и его
семейства (для YouTube — ``googlevideo.com``, ``ytimg.com``). На роутере
браузера нет, поэтому отличие от эталона: ресурсы берутся не со страницы,
а из семейства сайта (:data:`core.geneva_auto_lists.FAMILIES`), и каждый
проверяется своей пробой (TLS и ответ HTTP) — по имени, которое уже
видели устройства сети (книга «Авто»), иначе по известному имени из
:data:`PROBE_HOSTS`.

Вердикт одного ресурса (:func:`judge`):

* ответ HTTP пришёл (любой код) — ресурс загрузился;
* соединения нет (адрес недоступен, имя не разрешилось) — без вердикта:
  стратегия geneva это не исправит, у ресурса своя блокировка, она
  пишется в журнал;
* соединение есть, а ответа нет (сброс, тишина после ClientHello,
  чужой сертификат) — ресурс не загрузился, стратегия не годится;
* сертификат от корня, которого нет в бандле роутера (Минцифры), — без
  вердикта, как у проб.

Чистые функции здесь, сеть — у вызывающего (:mod:`core.geneva_auto_probes`).
"""

from __future__ import annotations

import ipaddress

from core import geneva_auto_lists as gal

# Имена, по которым проверяется домен семейства, если устройства сети его
# ещё не открывали. Только постоянные адреса, которые отвечают по HTTPS.
PROBE_HOSTS = {
    "ytimg.com": "i.ytimg.com",
    "ggpht.com": "yt3.ggpht.com",
    "googlevideo.com": "redirector.googlevideo.com",
    "discordapp.com": "cdn.discordapp.com",
    "discordapp.net": "media.discordapp.net",
    "twimg.com": "abs.twimg.com",
    "cdninstagram.com": "static.cdninstagram.com",
    "fbcdn.net": "static.xx.fbcdn.net",
    "whatsapp.com": "web.whatsapp.com",
    "telegram.org": "telegram.org",
}
MAX_HOSTS = 4                 # ресурсов на одну проверку (каждый — проба)
SETTLE = 2.0                  # процесс «по имени» перезапускается


def under(host: str, domain: str) -> bool:
    """``host`` — это ``domain`` или его поддомен."""
    h = str(host or "").strip().rstrip(".").lower()
    d = str(domain or "").strip().rstrip(".").lower()
    return bool(d) and (h == d or h.endswith("." + d))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text or "").strip("[]"))
    except ValueError:
        return False
    return True


def site_and_family(host: str) -> list:
    """Что стратегия сайта ``host`` должна пропускать, кроме него самого:
    его регистрируемый домен и домены семейства (семейство — по самому
    хосту). У адреса нет ни других имён, ни семейства."""
    h = str(host or "").strip().rstrip(".").lower()
    if not h or _is_ip(h):
        return []
    site = registrable(h)
    fam = gal.family_of(h)
    if not fam:
        return [site]
    domains = list(gal.FAMILIES.get(fam, ()))
    # регистрируемый домен — свой у сайта, только если семейство берёт
    # его целиком (youtubei.googleapis.com — не весь googleapis.com)
    first = site if any(under(site, d) for d in domains) else h
    out = [first]
    for d in domains:
        if d not in out:
            out.append(d)
    return out


def registrable(host: str) -> str:
    """Грубо: две последние метки (три — для ``co.uk`` и подобных)."""
    parts = [p for p in str(host or "").lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-2]) <= 3 and len(parts[-1]) == 2 and parts[-2] in (
            "co", "com", "net", "org", "gov", "edu", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def hosts_to_check(domains, seen=(), own: str = "") -> list:
    """Имена для проверки доменов ``domains``: ``[(имя, адрес или "")]``.

    ``seen`` — ``[(хост, адрес)]``, которые открывали устройства сети
    (книга «Авто»): они важнее известных имён. Домен сайта ``own`` и его
    поддомены не проверяются — сайт проверила его проба. Не больше
    :data:`MAX_HOSTS`, по одному имени на домен."""
    out, used = [], set()
    seen = [(str(h or "").strip().rstrip(".").lower(), str(a or ""))
            for h, a in seen or () if h]
    for d in domains or ():
        d = str(d or "").strip().rstrip(".").lower()
        if not d or (own and (under(own, d) or under(d, own))):
            continue
        pick = next(((h, a) for h, a in seen
                     if under(h, d) and not _is_ip(h)), None)
        if pick is None and d in PROBE_HOSTS:
            pick = (PROBE_HOSTS[d], "")
        if pick is None or pick[0] in used:
            continue
        used.add(pick[0])
        out.append(pick)
        if len(out) >= MAX_HOSTS:
            break
    return out


# Вердикты одного ресурса
OK = "ok"
FAILED = "failed"
NO_VERDICT = "skip"


def judge(r) -> str:
    """Проба ресурса (:class:`core.geneva_auto_probes.PageResult`) →
    :data:`OK`, :data:`FAILED` или :data:`NO_VERDICT`."""
    if r is None:
        return NO_VERDICT
    if getattr(r, "untrusted_root", False) and not getattr(r, "national",
                                                           False):
        return NO_VERDICT
    tls = getattr(r, "tls", True)
    if r.connect_ok and r.status is not None and (
            not tls or (r.tls_ok and r.cert_valid)):
        return OK
    if not r.connect_ok:
        return NO_VERDICT
    return FAILED


def summary(results) -> tuple:
    """``[(имя, вердикт, текст)]`` → ``(ok, текст)``: ``ok`` — ``True``
    (провалов нет), ``False`` (есть) или ``None`` (проверять было нечего
    или ни одного вердикта)."""
    results = list(results or [])
    failed = [(h, t) for h, v, t in results if v == FAILED]
    good = [h for h, v, _ in results if v == OK]
    if failed:
        return False, ", ".join("%s: %s" % (h, t) for h, t in failed)
    if good:
        return True, ", ".join(good)
    return None, ""


def trial_families(services, trials, taken=()) -> list:
    """Пробная стратегия по имени на время итоговой проверки
    (AutoPlan.TrialFamilies): другие имена сайта и домены его семейства
    идут через неё, как пойдут после применения (``host_profiles``
    добавляет семейство). Член семейства со своей жизнью в книге (своя
    стратегия, проба, подбор, блокировка) и домен, который уже назван
    применённым профилем (``taken``), остаются при своём. Сайт сам
    остаётся со своей группой по адресам: профиль не называет сервисов.

    ``trials`` — ``[(Service, стратегия)]``; ответ — ``[(ключ, профиль)]``.
    """
    from core import geneva_auto as ga
    allsv = list(services or ())
    claimed = {d for p in taken or () if not p.get("udp")
               for d in p.get("domains") or ()}
    own = [s for s in allsv if s.kind == ga.WEB and (
        s.is_active or s.status in (ga.SEARCHING, ga.BLOCKED, ga.SUSPECTED,
                                    ga.NOT_FOUND, ga.DEGRADED))]
    out = []
    for s, strategy in trials or ():
        if s.kind != ga.WEB or not strategy:
            continue
        site = gal.site_of(s)
        fam = gal.service_family(s)
        names = [site]
        if fam:
            members = list(gal.FAMILIES.get(fam, ()))
            # как в site_and_family: весь сайт — только если семейство
            # берёт его целиком (youtubei.googleapis.com — не весь
            # googleapis.com, остальной googleapis.com — мимо пробы)
            host = str(s.host or "").strip().rstrip(".").lower()
            if not any(under(site, d) for d in members) and host and \
                    not _is_ip(host) and under(host, site):
                names = [host]
            names += members
        domains = []
        for d in names:
            if not d or d in domains:
                continue
            if d != names[0] and any(o.key != s.key and gal.site_of(o) == d
                                 for o in own):
                continue
            # списки geneva берут поддомены: имя над или под уже
            # названным забрало бы его трафик
            if any(under(d, c) or under(c, d) for c in claimed):
                continue
            domains.append(d)
        claimed.update(domains)
        if domains:
            out.append((s.key, {"strategy": strategy, "udp": False,
                                "domains": domains, "services": []}))
    return out


def seen_hosts(services) -> list:
    """``[(хост, адрес)]`` сайтов книги — что открывали устройства сети,
    свежие первыми."""
    from core import geneva_auto as ga
    items = []
    for s in services or ():
        if s.kind != ga.WEB or not s.host:
            continue
        addr = s.address or ""
        items.append((float(s.last_seen or 0), s.host, addr))
    items.sort(key=lambda x: -x[0])
    return [(h, a) for _, h, a in items]
