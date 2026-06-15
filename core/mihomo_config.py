# core/mihomo_config.py
"""
Генератор clash-YAML конфигов mihomo для маршрутизации трафика через прокси.

Аналог `core/singbox_config.py` (builders FakeIP / system-route), но mihomo
маршрутизирует НАТИВНО в своём YAML: `tun` (auto-route + dns-hijack) + `dns`
(fake-ip) + `rules` (DOMAIN-SUFFIX/RULE-SET/SRC-IP-CIDR) + `external-controller`.
Поэтому OS-слой `ip rule` для mihomo НЕ нужен — всё делает сам движок. Это
чище, чем у sing-box (см. задание §3).

Функции-билдеры — чистые (без I/O), возвращают Python-структуру (dict), которую
оркестратор (`core/mihomo_routing.py`) сериализует через
`core.clash_yaml.dump_yaml`, проверяет `mihomo -t` и сохраняет.

Два режима (как у sing-box FakeIP / lite-route):
  build_domain_config() — выборочно по доменам/спискам (RULE-SET/DOMAIN-SUFFIX →
      PROXY, MATCH → DIRECT) + fake-ip; стек по умолчанию gvisor (надёжный
      доменный роутинг). Либо «весь трафик» (MATCH → PROXY).
  build_source_config() — по устройствам (SRC-IP-CIDR → PROXY, MATCH → DIRECT)
      либо «весь трафик»; стек по умолчанию system (kernel, низкий CPU).

Уроки sing-box (применены): MTU низкий (1500, не 9000 — иначе gvisor на MIPS
уходит в GC-thrash/100% CPU); QUIC НЕ глушим по умолчанию (ломает DoH клиента);
DNS блокируемых доменов резолвится чисто (через прокси — fake-ip отдаёт домен
прокси-серверу, без DPI-подмены); домен прокси-сервера — напрямую (без петли);
strict-route=false (не «лочим» роутер).
"""

from __future__ import annotations

import re


# Диапазон fake-ip mihomo (дефолт движка — 198.18.0.1/16).
FAKEIP_RANGE = "198.18.0.1/16"

# Имя TUN-устройства по умолчанию (≤15 символов — лимит Linux TUN).
DEFAULT_TUN_DEVICE = "mihomo-tun"

# Чистый резолвер для прямого трафика / резолва домена прокси-сервера.
# DoH задаём ПО ИМЕНИ ХОСТА (а не по IP-литералу): URL `https://1.1.1.1/...`
# валит проверку TLS-сертификата («no alternative certificate subject name
# matches 1.1.1.1») и резолвер мертвеет — проверено на железе. Имя хоста
# (cloudflare-dns.com / dns.google) совпадает с SAN сертификата; сам хост
# бутстрапится через default-nameserver (обычный UDP), петли нет. Блокируемые
# (проксируемые) домены сюда НЕ попадают — их резолвит сам прокси (fake-ip),
# поэтому nameserver обслуживает только прямой трафик и домен прокси-сервера.
DEFAULT_DOH = "https://cloudflare-dns.com/dns-query"
DEFAULT_DOH_SERVERS = ["https://cloudflare-dns.com/dns-query",
                       "https://dns.google/dns-query"]
DEFAULT_BOOTSTRAP = ["1.1.1.1", "8.8.8.8"]

# Имя select-группы (через неё watchdog-проба и переключение узла) и inline
# rule-provider'а проксируемых доменов.
DEFAULT_GROUP = "PROXY"
DEFAULT_RULESET = "proxied"

# Приватные/локальные подсети — всегда напрямую (LAN/роутер/loopback), иначе
# при «весь трафик»/auto-route отвалится связь с самим роутером и LAN.
PRIVATE_CIDRS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]

# fake-ip НЕ выдаём только для доменов, которым реально нужен НАСТОЯЩИЙ IP:
# LAN-discovery, connectivity-проба ОС, NTP (синхронизация времени до туннеля),
# STUN, спец-домен QQ-логина. Список держим МИНИМАЛЬНЫМ — широкие записи вроде
# `+.qq.com` тут вредны: они исключили бы из fake-ip домен, который
# пользователь, наоборот, хочет проксировать. Домены прокси-серверов
# добавляются динамически в make_fakeip_dns().
DEFAULT_FAKEIP_FILTER = [
    "*.lan", "*.localdomain", "*.local", "+.local", "+.home.arpa",
    "localhost.ptlogin2.qq.com",
    "+.pool.ntp.org", "time.*.com", "ntp.*.com",
    "+.msftconnecttest.com", "+.msftncsi.com",
    "stun.*.*",
]

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ─────────────────────── helpers ───────────────────────

def _looks_like_ip(s: str) -> bool:
    """Грубо: IP-литерал (v4/v6), а не доменное имя?"""
    s = (s or "").strip().strip("[]")
    return bool(_IPV4_RE.match(s)) or (":" in s)


def _norm_suffix_domains(domains) -> list:
    """Нормализовать домены под суффиксный матч: lower, без схемы/www/*., без
    дублей; отбросить IP/localhost (это не суффиксы). Тот же контракт, что у
    singbox_config._norm_suffix_domains."""
    out, seen = [], set()
    for d in (domains or []):
        s = str(d).strip().lower()
        for pre in ("https://", "http://", "//", "*.", "+.", "www."):
            if s.startswith(pre):
                s = s[len(pre):]
        s = s.split("/")[0].strip().rstrip(".")
        if not s or s in seen:
            continue
        if s == "localhost" or _IPV4_RE.match(s) or ":" in s:
            continue
        seen.add(s)
        out.append(s)
    return out


def _norm_src_cidr(s: str) -> str:
    """IP без маски → /32 (v4) или /128 (v6); CIDR — как есть."""
    s = (s or "").strip()
    if not s or "/" in s:
        return s
    return s + ("/128" if ":" in s else "/32")


def collect_proxy_server_domains(proxies) -> list:
    """Доменные `server` всех прокси (не IP) — их резолвим напрямую (а не через
    прокси) и исключаем из fake-ip, чтобы не было петли «резолв адреса прокси
    через сам прокси»."""
    out = set()
    for p in (proxies or []):
        if not isinstance(p, dict):
            continue
        srv = str(p.get("server") or "").strip()
        if srv and not _looks_like_ip(srv):
            out.add(srv)
    return sorted(out)


# ─────────────────────── section builders ───────────────────────

def make_tun(*, device: str = DEFAULT_TUN_DEVICE, stack: str = "gvisor",
             mtu: int = 1500, auto_route: bool = True,
             auto_redirect: bool = False, strict_route: bool = False,
             dns_hijack=None) -> dict:
    """
    Секция `tun`. mihomo сам создаёт интерфейс и (auto-route) забирает трафик.

    stack: 'gvisor' (userspace, ловит TCP+UDP сам — нужен для надёжного
           доменного роутинга), 'system' (kernel, низкий CPU — нужен auto-route
           чтобы ловить трафик), 'mixed'.
    mtu=1500 (не 9000): для туннеля поверх прокси большой MTU бессмыслен, а с
           gvisor на слабом MIPS раздувает буферы → GC-молотьба/100% CPU.
    strict_route=False: не «лочим» роутер (иначе при мёртвом прокси «умирает
           интернет до перезагрузки»).
    auto_redirect: только nftables (mihomo сам ставит nft-redirect, чтобы
           забрать и ПЕРЕсылаемый трафик LAN-клиентов).
    """
    tun = {
        "enable": True,
        "stack": stack or "gvisor",
        "device": (device or DEFAULT_TUN_DEVICE)[:15],
        "auto-route": bool(auto_route),
        "auto-detect-interface": True,
        "dns-hijack": list(dns_hijack) if dns_hijack else ["any:53"],
        "mtu": int(mtu) if mtu else 1500,
        "strict-route": bool(strict_route),
    }
    # auto-redirect валиден только вместе с auto-route и на nftables.
    if auto_redirect and auto_route:
        tun["auto-redirect"] = True
    return tun


def make_fakeip_dns(*, proxy_server_domains=None, doh=None,
                    extra_filter=None, ipv6: bool = False) -> dict:
    """
    Секция `dns` с enhanced-mode fake-ip.

    Блокируемые (проксируемые) домены получают fake-ip → их трафик роутится по
    доменным правилам в прокси, а РЕАЛЬНЫЙ резолв делает сам прокси-сервер
    (remote DNS) — без DPI-подмены провайдера. Прямой трафик резолвится через
    DoH (`nameserver`); домен самого прокси-сервера — через
    `proxy-server-nameserver` (чисто, без DPI-подмены) и исключён из fake-ip.

    `doh` — список DoH-серверов (по имени хоста, см. DEFAULT_DOH); по умолчанию
    cloudflare-dns.com + dns.google. Имена бутстрапятся через default-nameserver.
    """
    servers = list(doh) if doh else list(DEFAULT_DOH_SERVERS)
    flt = list(DEFAULT_FAKEIP_FILTER)
    for d in (extra_filter or []):
        if d and d not in flt:
            flt.append(d)
    # Домены прокси-серверов — точным именем (не +.), чтобы не исключить из
    # fake-ip лишнего; mihomo должен получить их РЕАЛЬНЫЙ IP для дозвона.
    for d in collect_proxy_server_domains(proxy_server_domains or []):
        if d not in flt:
            flt.append(d)
    return {
        "enable": True,
        "ipv6": bool(ipv6),
        "enhanced-mode": "fake-ip",
        "fake-ip-range": FAKEIP_RANGE,
        "fake-ip-filter": flt,
        # default-nameserver (обычный UDP) — резолвит ИМЕНА DoH-хостов и служит
        # бутстрапом; только IP-литералы.
        "default-nameserver": list(DEFAULT_BOOTSTRAP),
        "nameserver": servers,
        "proxy-server-nameserver": servers,
    }


def make_proxy_group(name: str, proxy_names, *, group_type: str = "select",
                     url: str = "https://cp.cloudflare.com/generate_204",
                     interval: int = 300) -> dict:
    """
    proxy-group, через который идёт весь проксируемый трафик. `select` —
    ручное переключение (через external-controller/UI); `url-test` — авто-выбор
    самого быстрого узла. Имя группы — общая цель правил и точка watchdog-пробы.
    """
    grp = {"name": name, "type": group_type or "select",
           "proxies": list(proxy_names)}
    if (group_type or "select") == "url-test":
        grp["url"] = url
        grp["interval"] = int(interval)
    return grp


def make_domain_rule_provider(domains) -> dict:
    """inline rule-provider (behavior: domain) со списком проксируемых доменов.
    `+.<домен>` = домен и все поддомены (семантика DOMAIN-SUFFIX)."""
    payload = ["+.%s" % d for d in _norm_suffix_domains(domains)]
    return {"type": "inline", "behavior": "domain", "payload": payload}


def private_direct_rules() -> list:
    """Правила «приватные/локальные подсети → DIRECT» (no-resolve — не
    провоцируем DNS на IP-правиле)."""
    return ["IP-CIDR,%s,DIRECT,no-resolve" % c for c in PRIVATE_CIDRS]


def quic_reject_rule() -> str:
    """Глушение QUIC: REJECT для UDP/443 (логическое правило). Опция —
    включать, только если QUIC через прокси не ходит (иначе ломает DoH3)."""
    return "AND,((NETWORK,udp),(DST-PORT,443)),REJECT"


def active_proxy_group(cfg: dict) -> str:
    """Имя первой select/url-test proxy-group (цель watchdog-пробы delay).
    '' если групп нет."""
    if not isinstance(cfg, dict):
        return ""
    for g in (cfg.get("proxy-groups") or []):
        if isinstance(g, dict) and g.get("name") \
                and str(g.get("type") or "").lower() in ("select", "url-test",
                                                         "fallback",
                                                         "load-balance"):
            return str(g["name"])
    return ""


def find_tun_device(cfg: dict) -> str:
    """Имя TUN-устройства из секции tun (или '' если tun выключен/нет)."""
    tun = cfg.get("tun") if isinstance(cfg, dict) else None
    if isinstance(tun, dict) and tun.get("enable"):
        return str(tun.get("device") or "")
    return ""


# ─────────────────────── full config builders ───────────────────────

def _base_config(*, proxies, group_name, group_type, controller_port,
                 controller_secret, dns) -> dict:
    """Общий каркас конфига: general-ключи, external-controller, proxies,
    proxy-group, dns. Без tun/rules — их добавляют конкретные билдеры."""
    names = [str(p["name"]) for p in proxies
             if isinstance(p, dict) and p.get("name")]
    cfg = {
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
    }
    if controller_port:
        cfg["external-controller"] = "127.0.0.1:%d" % int(controller_port)
        if controller_secret:
            cfg["secret"] = controller_secret
    cfg["dns"] = dns
    cfg["proxies"] = [dict(p) for p in proxies if isinstance(p, dict)]
    cfg["proxy-groups"] = [make_proxy_group(group_name, names,
                                            group_type=group_type)]
    return cfg


def build_domain_config(*, proxies, proxied_domains=None, proxied_cidrs=None,
                        route_all: bool = False, stack: str = "gvisor",
                        mtu: int = 1500, device: str = DEFAULT_TUN_DEVICE,
                        reject_quic: bool = False, auto_redirect: bool = False,
                        controller_port: int = 0, controller_secret: str = "",
                        group_name: str = DEFAULT_GROUP,
                        group_type: str = "select",
                        ruleset_name: str = DEFAULT_RULESET,
                        use_ruleset: bool = True) -> dict:
    """
    Конфиг ВЫБОРОЧНОЙ маршрутизации по доменам/спискам (+ fake-ip).

    route_all=True → весь трафик в прокси (MATCH,PROXY), приватное напрямую.
    Иначе → выбранные домены (RULE-SET/DOMAIN-SUFFIX) и подсети (IP-CIDR) в
    прокси, остальное напрямую (MATCH,DIRECT).

    use_ruleset=True → проксируемые домены кладём в inline rule-provider
    (RULE-SET,<name>,PROXY) — компактно и эффективно для больших списков.
    use_ruleset=False → разворачиваем как отдельные DOMAIN-SUFFIX-правила
    (максимально совместимо со старыми сборками; оркестратор откатывается на
    этот вариант, если `mihomo -t` отверг rule-provider).
    """
    if not proxies:
        raise ValueError("нужен хотя бы один прокси")

    domains = _norm_suffix_domains(proxied_domains)
    cidrs = [str(c).strip() for c in (proxied_cidrs or []) if str(c).strip()]

    dns = make_fakeip_dns(proxy_server_domains=proxies)
    cfg = _base_config(proxies=proxies, group_name=group_name,
                       group_type=group_type, controller_port=controller_port,
                       controller_secret=controller_secret, dns=dns)
    cfg["tun"] = make_tun(device=device, stack=stack, mtu=mtu,
                          auto_route=True, auto_redirect=auto_redirect)

    rules = list(private_direct_rules())
    if reject_quic:
        rules.append(quic_reject_rule())

    if route_all:
        rules.append("MATCH,%s" % group_name)
    else:
        if domains:
            if use_ruleset:
                cfg["rule-providers"] = {
                    ruleset_name: make_domain_rule_provider(domains)}
                rules.append("RULE-SET,%s,%s" % (ruleset_name, group_name))
            else:
                rules.extend("DOMAIN-SUFFIX,%s,%s" % (d, group_name)
                             for d in domains)
        for c in cidrs:
            rules.append("IP-CIDR,%s,%s,no-resolve" % (c, group_name))
        rules.append("MATCH,DIRECT")

    cfg["rules"] = rules
    return cfg


def build_source_config(*, proxies, source_ips=None, route_all: bool = False,
                        stack: str = "system", mtu: int = 1500,
                        device: str = DEFAULT_TUN_DEVICE,
                        reject_quic: bool = False, auto_redirect: bool = False,
                        controller_port: int = 0, controller_secret: str = "",
                        group_name: str = DEFAULT_GROUP,
                        group_type: str = "select") -> dict:
    """
    Конфиг маршрутизации ПО УСТРОЙСТВАМ (source-IP) или «весь трафик».

    Стек по умолчанию `system` (kernel) — низкий CPU (без gvisor). auto-route
    забирает трафик; кого в прокси решают правила:
      route_all=True → весь трафик (MATCH,PROXY);
      иначе          → только source_ip выбранных устройств (SRC-IP-CIDR →
                       PROXY), остальное напрямую (MATCH,DIRECT).

    DNS — fake-ip (как в доменном режиме): чистый резолв проксируемых доменов
    через прокси. Приватные адреса — напрямую. strict-route=false.
    """
    if not proxies:
        raise ValueError("нужен хотя бы один прокси")

    srcs = [_norm_src_cidr(s) for s in (source_ips or []) if str(s).strip()]

    dns = make_fakeip_dns(proxy_server_domains=proxies)
    cfg = _base_config(proxies=proxies, group_name=group_name,
                       group_type=group_type, controller_port=controller_port,
                       controller_secret=controller_secret, dns=dns)
    cfg["tun"] = make_tun(device=device, stack=stack, mtu=mtu,
                          auto_route=True, auto_redirect=auto_redirect)

    rules = list(private_direct_rules())
    if reject_quic:
        rules.append(quic_reject_rule())

    if route_all:
        rules.append("MATCH,%s" % group_name)
    else:
        for s in srcs:
            rules.append("SRC-IP-CIDR,%s,%s" % (s, group_name))
        rules.append("MATCH,DIRECT")

    cfg["rules"] = rules
    return cfg
