# core/site_trace.py
"""
«Куда пойдёт сайт»: трассировка решения по всем слоям для одного домена.

## Зачем

Самый частый вопрос — «почему этот сайт идёт не через то, что я
настроил». Ответ раскидан по слоям: ``/etc/hosts`` подменяет адрес до
DNS, DNS-маршрутизация выбирает резолвер, маршрут единого слоя уводит
трафик в туннель (тогда nfqws2 его вообще не видит), и только оставшееся
доходит до nfqws2, где первый подходящий профиль решает, что с потоком
делать. Здесь всё это проверяется по порядку и объясняется (приём
nfqws2-ui, расширенный на наши слои).

## Слои, по порядку

1. **hosts** — запись с этим именем: адрес задан вручную.
2. **DNS** — правило «домен → свой DNS» (``dns_routing.rules``).
3. **Единый слой** — включённые маршруты, чьи домены (явные, из
   именованных списков, маски) покрывают домен. Туннельный метод —
   трафик уходит мимо nfqws2; ``nfqws2`` — домен попадает в общий
   hostlist единого слоя.
4. **nfqws2** — для HTTPS (TCP 443, TLS), QUIC (UDP 443) и HTTP (TCP 80):
   перехватывается ли порт firewall'ом и какой профиль стратегии
   возьмёт поток — первый, у которого сошлись порт, ``--filter-l7``,
   hostlist/ipset и не сработали исключения. Для каждого пропущенного
   профиля — почему.

Плюс — в каких хостлистах и именованных списках домен уже есть.

## Чего симулятор не знает

* Автохостлист (``--hostlist-auto``) пополняется на ходу: домена в нём
  может ещё не быть — это и пишется.
* ipset сверяется с адресами из системного DNS роутера (а не того, что
  спросит клиент).
* geosite/geoip единого слоя разворачивает движок — такие маршруты
  показываются как «возможно».

Разбор профилей и совпадений — чистые функции, ввод-вывод — в
:func:`trace`.
"""

from __future__ import annotations

import ipaddress
import os
import gzip
import socket
import threading

# Потоки, которые проверяем: имя → (протокол, порт, l7).
FLOWS = (
    ("https", "tcp", 443, "tls"),
    ("quic", "udp", 443, "quic"),
    ("http", "tcp", 80, "http"),
)
FLOW_TITLES = {"https": "HTTPS (TCP 443)", "quic": "QUIC (UDP 443)",
               "http": "HTTP (TCP 80)"}


# ─────────────────────────── чистые функции ────────────────────────────

def parse_ports(spec: str) -> list:
    """«80,443,1000-2000» или «~80», «*» → [(lo, hi, invert)]."""
    out = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        inv = part.startswith("~")
        part = part.lstrip("~")
        if part == "*":
            out.append((0, 65535, inv))
            continue
        sep = "-" if "-" in part else (":" if ":" in part else "")
        try:
            if sep:
                lo, hi = part.split(sep, 1)
                out.append((int(lo), int(hi), inv))
            else:
                out.append((int(part), int(part), inv))
        except ValueError:
            continue
    return out


def port_in(ranges: list, port: int) -> bool:
    """Порт под фильтром: прямые диапазоны — «или», ``~`` — «кроме»."""
    direct = [r for r in ranges if not r[2]]
    inverted = [r for r in ranges if r[2]]
    if any(lo <= port <= hi for lo, hi, _ in inverted):
        return False
    if direct:
        return any(lo <= port <= hi for lo, hi, _ in direct)
    return bool(inverted)


def parse_profile(args) -> dict:
    """Фильтры одного профиля nfqws2 из его argv."""
    p = {"tcp": None, "udp": None, "l7": None, "l3": None,
         "hostlists": [], "hostlist_domains": [],
         "exclude_lists": [], "exclude_domains": [],
         "ipsets": [], "ipset_ips": [], "ipset_exclude": [],
         "ipset_exclude_ips": [], "auto": [], "actions": []}

    def _vals(text):
        return [v.strip() for v in text.split(",") if v.strip()]

    for arg in args or []:
        arg = str(arg)
        key, _, val = arg.partition("=")
        if key == "--filter-tcp":
            p["tcp"] = (p["tcp"] or []) + parse_ports(val)
        elif key == "--filter-udp":
            p["udp"] = (p["udp"] or []) + parse_ports(val)
        elif key == "--filter-l7":
            p["l7"] = (p["l7"] or set()) | {v.lower() for v in _vals(val)}
        elif key == "--filter-l3":
            p["l3"] = val.strip().lower()
        elif key == "--hostlist":
            p["hostlists"] += _vals(val)
        elif key == "--hostlist-domains":
            p["hostlist_domains"] += [v.lower() for v in _vals(val)]
        elif key == "--hostlist-exclude":
            p["exclude_lists"] += _vals(val)
        elif key == "--hostlist-exclude-domains":
            p["exclude_domains"] += [v.lower() for v in _vals(val)]
        elif key == "--hostlist-auto":
            p["auto"] += _vals(val)
        elif key == "--ipset":
            p["ipsets"] += _vals(val)
        elif key == "--ipset-ip":
            p["ipset_ips"] += _vals(val)
        elif key == "--ipset-exclude":
            p["ipset_exclude"] += _vals(val)
        elif key == "--ipset-exclude-ip":
            p["ipset_exclude_ips"] += _vals(val)
        elif key == "--lua-desync":
            p["actions"].append(val.split(":", 1)[0])
    return p


def domain_hit(domain: str, entries) -> str:
    """Какая запись покрывает домен ("" — никакая).

    Как nfqws2: запись покрывает сам домен и поддомены, ``^`` в начале —
    только сам домен.
    """
    entries = set(entries or ())
    if "^" + domain in entries or domain in entries:
        return "^" + domain if "^" + domain in entries else domain
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in entries:
            return parent
    return ""


def ip_hit(ips, entries) -> str:
    """Какая запись ipset покрывает один из адресов ("" — никакая)."""
    nets = []
    for e in entries or ():
        try:
            nets.append((e, ipaddress.ip_network(e.strip(), strict=False)))
        except ValueError:
            continue
    for ip in ips or ():
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for text, net in nets:
            if addr.version == net.version and addr in net:
                return "%s ∈ %s" % (ip, text)
    return ""


def _host_hit(prof: dict, domain: str, read_list) -> str:
    """Чем домен попал в хостлисты профиля ("" — ничем)."""
    hit = domain_hit(domain, prof["hostlist_domains"])
    if hit:
        return "--hostlist-domains (%s)" % hit
    for path in prof["hostlists"]:
        hit = domain_hit(domain, read_list(path))
        if hit:
            return "список %s (%s)" % (os.path.basename(path), hit)
    for path in prof["auto"]:
        hit = domain_hit(domain, read_list(path))
        if hit:
            return "автохостлист %s (%s)" % (os.path.basename(path), hit)
    return ""


def profile_verdict(prof: dict, flow: tuple, domain: str, ips,
                    read_list) -> tuple:
    """(подходит ли профиль, почему). ``read_list(path) -> set``."""
    _name, proto, port, l7 = flow
    if prof["l3"]:
        fams = {v.strip() for v in prof["l3"].split(",")}
        have = {"ipv6" if ":" in ip else "ipv4"
                for ip in ips or ["0.0.0.0"]}
        if not fams & have:
            return False, "только %s" % prof["l3"]
    tcp, udp = prof["tcp"], prof["udp"]
    if tcp is not None or udp is not None:
        ranges = tcp if proto == "tcp" else udp
        if ranges is None:
            return False, "фильтр только по %s" % (
                "UDP" if proto == "tcp" else "TCP")
        if not port_in(ranges, port):
            return False, "порт %d не в --filter-%s" % (port, proto)
    if prof["l7"] and not ({l7, "all", "known"} & prof["l7"]):
        return False, "--filter-l7=%s не включает %s" % (
            ",".join(sorted(prof["l7"])), l7)
    # Исключения сильнее включений.
    hit = domain_hit(domain, prof["exclude_domains"])
    if hit:
        return False, "исключён --hostlist-exclude-domains (%s)" % hit
    for path in prof["exclude_lists"]:
        hit = domain_hit(domain, read_list(path))
        if hit:
            return False, "исключён списком %s (%s)" % (
                os.path.basename(path), hit)
    hit = ip_hit(ips, prof["ipset_exclude_ips"])
    for path in prof["ipset_exclude"]:
        hit = hit or ip_hit(ips, read_list(path))
    if hit:
        return False, "исключён ipset'ом (%s)" % hit
    has_hosts = bool(prof["hostlists"] or prof["hostlist_domains"]
                     or prof["auto"])
    has_ips = bool(prof["ipsets"] or prof["ipset_ips"])
    if not has_hosts and not has_ips:
        return True, "профиль без списков — берёт весь такой трафик"
    why = []
    # ipset и hostlist у nfqws2 — оба условия профиля («и»): адрес
    # проверяется по ipset'у, имя — по хостлистам.
    if has_ips:
        if not ips:
            return False, "адреса сайта не узнаны — ipset не проверить"
        hit = ip_hit(ips, prof["ipset_ips"])
        for path in prof["ipsets"]:
            hit = hit or ip_hit(ips, read_list(path))
        if not hit:
            return False, "адреса нет в ipset'ах профиля"
        why.append("ipset (%s)" % hit)
    if has_hosts:
        host = _host_hit(prof, domain, read_list)
        if not host:
            if prof["auto"]:
                return False, ("нет в автохостлисте — попадёт туда сам "
                               "после нескольких неудачных попыток")
            return False, "домена нет в списках профиля"
        why.append(host)
    return True, "; ".join(why)


def pick_profile(profiles, flow: tuple, domain: str, ips,
                 read_list) -> dict:
    """Первый подходящий профиль и причины пропуска предыдущих.

    ``profiles`` — как :func:`core.strategy_lint.split_profiles`: нулевая
    секция — глобальные опции и одновременно первый профиль.
    """
    skipped = []
    for i, args in enumerate(profiles or []):
        prof = parse_profile(args)
        ok, why = profile_verdict(prof, flow, domain, ips, read_list)
        if ok:
            return {"profile": i + 1, "reason": why,
                    "actions": prof["actions"], "skipped": skipped}
        skipped.append({"profile": i + 1, "reason": why})
    return {"profile": None, "reason": "ни один профиль не подошёл — "
                                       "поток идёт без обхода",
            "actions": [], "skipped": skipped}


# ─────────────────────────── сбор ────────────────────────────

def _resolve(domain: str, timeout: float = 3.0) -> list:
    """Адреса из системного DNS роутера. getaddrinfo таймаутов не знает
    (а ``setdefaulttimeout`` — общий на процесс), поэтому ждём его в
    отдельном потоке не дольше ``timeout``."""
    box = []

    def run():
        try:
            infos = socket.getaddrinfo(domain, 443, socket.AF_INET,
                                       socket.SOCK_STREAM)
            box.append(sorted({i[4][0] for i in infos}))
        except OSError:
            box.append([])
    t = threading.Thread(target=run, name="site-trace-dns", daemon=True)
    t.start()
    t.join(timeout)
    return box[0] if box else []


def _list_reader():
    """read_list(path) с кешем; относительный путь — от base_path."""
    from core.config_manager import get_config_manager
    base = get_config_manager().get("zapret", "base_path",
                                    default="/opt/zapret2") or ""
    cache = {}

    def read(path):
        path = str(path).strip().strip("\"'")
        if not os.path.isabs(path):
            path = os.path.join(base, path)
        if path not in cache:
            items = set()
            try:
                opener = gzip.open if path.endswith(".gz") else open
                with opener(path, "rt", encoding="utf-8",
                            errors="replace") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            items.add(line)
            except OSError:
                pass
            cache[path] = items
        return cache[path]
    return read


def _hosts_layer(domain: str) -> list:
    from core.hosts_manager import get_hosts_manager
    out = []
    for e in get_hosts_manager().get_entries() or []:
        if str(e.get("domain", "")).lower() == domain:
            out.append({"ip": e.get("ip", ""),
                        "system": bool(e.get("is_system"))})
    return out


def _dns_layer(domain: str) -> list:
    from core.config_manager import get_config_manager
    out = []
    for r in get_config_manager().get("dns_routing", "rules",
                                      default=[]) or []:
        rd = str(r.get("domain", "")).strip().lower().lstrip(".")
        if rd and domain_hit(domain, [rd]):
            out.append({"rule": rd,
                        "server": r.get("dns") or r.get("dns_server", ""),
                        "enabled": r.get("enabled", True)})
    return out


def _unified_layer(domain: str) -> list:
    from core.routing import domain_match
    from core.unified import storage
    from core.unified.applier import active_method
    from core.unified.model import is_tunnel_method
    out = []
    for route in storage.load_routes() or []:
        if not route.enabled or route.destination is None:
            continue
        try:
            res = route.destination.resolve()
        except Exception:                           # noqa: BLE001
            continue
        doms = [str(d).lower() for d in res.get("domains") or []]
        hit = domain_hit(domain, domain_match.plain_domains(doms))
        if not hit:
            for pat in domain_match.patterns(doms):
                rx = domain_match.compile_entry(pat)
                if rx is not None and rx.match(domain):
                    hit = pat
                    break
        maybe = not hit and bool(route.destination.geosite)
        if hit or maybe:
            method = active_method(route)
            pending = (bool(hit) and is_tunnel_method(method)
                       and not _in_kernel(route.id, hit))
            out.append({"id": getattr(route, "id", ""), "name": route.name,
                        "method": method,
                        "failover": method != route.method,
                        "devices": [d.get("hostname") or d.get("ip") or
                                    d.get("mac") or "?"
                                    for d in route.devices or []],
                        "tunnel": is_tunnel_method(method),
                        "match": hit or "geosite: %s" % ", ".join(
                            route.destination.geosite),
                        "maybe": maybe,
                        "pending": pending})
    return out


def _in_kernel(route_id: str, entry: str) -> bool:
    """Попала ли запись в разложенное доменное правило маршрута.

    Маршрут на списке раскладывается снимком: в производное правило
    (`uni-<id>-dom`) уходят домены на момент применения. Домен, добавленный
    в список после, совпадает с маршрутом «по намерению», но в dnsmasq и
    nft его ещё нет — трафик идёт напрямую. Нет данных — не пугаем.
    """
    try:
        from core.routing import storage as rstorage
        from core.unified.applier import _dom_rule_id
        rule = rstorage.get_rule(_dom_rule_id(route_id))
    except Exception:                               # noqa: BLE001
        return True
    if rule is None:
        return False
    return entry.lstrip("^") in {str(d).lower().lstrip("^")
                                 for d in getattr(rule, "domains", [])}


def _lists_layer(domain: str, read=None) -> dict:
    """Где домен уже есть. Файлы читает тот же кеширующий ``read``, что и
    профили, — большой список не читается дважды; ``get_hostlist`` не
    годится — он ещё и создаёт встроенный список, которого нет."""
    from core.hostlist_manager import get_hostlist_manager
    from core import named_lists
    hm = get_hostlist_manager()
    read = read or _list_reader()
    hostlists = []
    for name in hm.list_names():
        path = hm._file_path(name)
        hit = domain_hit(domain, read(path)) if os.path.exists(path) else ""
        if hit:
            hostlists.append({"name": name, "match": hit})
    named = []
    for item in named_lists.list_all() or []:
        hit = domain_hit(domain, {str(d).lower() for d in
                                  item.get("domains") or []})
        if hit:
            named.append({"id": item.get("id"), "name": item.get("name"),
                          "match": hit})
    return {"hostlists": hostlists, "named": named}


def _firewall_ports() -> dict:
    """Порты перехвата так, как их ставит ``firewall.apply_rules``: те же
    умолчания и без портов управления."""
    from core.config_manager import get_config_manager
    from core.firewall import strip_management_ports
    cfg = get_config_manager()
    tcp = cfg.get("nfqws", "ports_tcp", default="80,443") or "80,443"
    udp = cfg.get("nfqws", "ports_udp", default="443") or "443"
    tcp, _dropped = strip_management_ports(tcp, cfg)
    return {"tcp": parse_ports(tcp), "udp": parse_ports(udp)}


def _safe(fn, *args):
    try:
        return fn(*args), ""
    except Exception as e:                          # noqa: BLE001 — граница
        return None, "%s: %s" % (type(e).__name__, e)


def normalize(domain: str) -> str:
    """Имя из того, что вставили: адрес, «домен/путь», «домен:порт».

    ``www.`` не срезается: nfqws2 сверяет списки с тем именем, которое
    спросил браузер.
    """
    d = str(domain or "").strip().lower()
    if "://" not in d:
        d = "http://" + d
    from urllib.parse import urlparse
    try:
        d = urlparse(d).hostname or ""
    except ValueError:
        d = ""
    return d.strip(".").lstrip("^")


def _is_block_ip(ip: str) -> bool:
    """0.0.0.0, ::, 127.x — запись hosts, которая «глушит» сайт."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return a.is_unspecified or a.is_loopback


class _NoStrategy(Exception):
    """Стратегия не выбрана — профилей нет вовсе."""


def trace(domain: str, resolve: bool = True) -> dict:
    """Пройти все слои для домена. Ошибка слоя — в ``errors``, не исключение."""
    domain = normalize(domain)
    if not domain or "." not in domain:
        return {"ok": False, "error": "нужно имя сайта, например youtube.com"}
    errors = {}
    out = {"ok": True, "domain": domain}
    read = None
    try:
        read = _list_reader()
    except Exception:                               # noqa: BLE001
        pass
    for key, fn in (("hosts", _hosts_layer), ("dns", _dns_layer),
                    ("routes", _unified_layer),
                    ("lists", lambda d: _lists_layer(d, read))):
        val, err = _safe(fn, domain)
        out[key] = val if val is not None else ([] if key != "lists"
                                                else {})
        if err:
            errors[key] = err
    ips = _resolve(domain) if resolve else []
    if out["hosts"]:
        ips = [h["ip"] for h in out["hosts"]]
        out["blocked"] = all(_is_block_ip(ip) for ip in ips)
    out["ips"] = ips

    nfq = {"running": False, "strategy": "", "flows": {}}
    try:
        from core.config_manager import get_config_manager
        from core.list_lint import _strategy_argv
        from core.unified import nfqws_hostlist
        from core.nfqws_manager import get_nfqws_manager
        from core.strategy_lint import split_profiles
        nfq["running"] = bool(get_nfqws_manager().is_running())
        nfq["strategy"] = get_config_manager().get(
            "strategy", "current_name", default="") or ""
        # Как compose_command: hostlist единого слоя ДО профилей стратегии —
        # он входит в первый профиль, а не в последний.
        argv = _strategy_argv()
        if not argv:
            nfq["no_strategy"] = True
            raise _NoStrategy()
        profiles = split_profiles(
            list(nfqws_hostlist.compose_extra_args() or []) + argv)
        read = read or _list_reader()
        fw = _firewall_ports()
        for flow in FLOWS:
            name, proto, port, _l7 = flow
            item = pick_profile(profiles, flow, domain, ips, read)
            item["title"] = FLOW_TITLES[name]
            item["intercepted"] = port_in(fw[proto], port) \
                if fw[proto] else False
            nfq["flows"][name] = item
    except _NoStrategy:
        pass
    except Exception as e:                          # noqa: BLE001 — граница
        errors["nfqws"] = "%s: %s" % (type(e).__name__, e)
    out["nfqws"] = nfq
    out["errors"] = errors
    out["summary"] = summarize(out)
    return out


def summarize(t: dict) -> list:
    """Чистая функция: итог человеческими строками, по слоям."""
    lines = []
    for h in t.get("hosts") or []:
        lines.append("hosts: адрес задан вручную — %s%s"
                     % (h["ip"], " (системная запись)" if h["system"]
                        else ""))
    for d in t.get("dns") or []:
        if d.get("enabled", True):
            lines.append("DNS: спрашивается у %s (правило %s)"
                         % (d["server"], d["rule"]))
    tunnels = [r for r in t.get("routes") or [] if r["tunnel"]
               and not r["maybe"] and not r.get("pending")]
    if t.get("blocked"):
        lines.append("Итог: hosts отправляет сайт в никуда — он не "
                     "откроется, обход тут ни при чём")
        return lines
    for r in t.get("routes") or []:
        lines.append("Единый слой: «%s» → %s (%s)%s%s%s%s" % (
            r["name"] or r["id"], r["method"], r["match"],
            " — сейчас запасной метод" if r.get("failover") else "",
            " — только для устройств: %s" % ", ".join(r["devices"])
            if r.get("devices") else "",
            " — возможно, решает движок по geosite" if r["maybe"] else "",
            " — но в ядро ещё НЕ разложен: трафик идёт мимо туннеля, "
            "переприменить — unified_route_apply" if r.get("pending")
            else ""))
    methods = sorted({r["method"] for r in tunnels})
    if len(methods) > 1:
        lines.append("Итог: трафик уходит в один из туннелей (%s) — "
                     "побеждает маршрут, применённый последним (поле "
                     "priority этого не решает) — уберите перекрытие; "
                     "nfqws2 его не видит" % ", ".join(methods))
        return lines
    if tunnels:
        scoped = all(r.get("devices") for r in tunnels)
        lines.append("Итог: трафик %sуходит в туннель %s — nfqws2 его не "
                     "видит" % ("указанных устройств " if scoped else "",
                                methods[0]))
        if not scoped:
            return lines
    nfq = t.get("nfqws") or {}
    if not nfq.get("running"):
        lines.append("nfqws2 не запущен — обхода DPI нет")
    if nfq.get("no_strategy"):
        lines.append("Стратегия не выбрана — профилей nfqws2 нет")
    for name in ("https", "quic", "http"):
        f = (nfq.get("flows") or {}).get(name)
        if not f:
            continue
        if not f.get("intercepted"):
            lines.append("%s: порт не перехватывается firewall'ом "
                         "(Настройки → nfqws) — nfqws2 поток не увидит"
                         % f["title"])
        elif f.get("profile"):
            lines.append("%s: профиль %d — %s%s" % (
                f["title"], f["profile"], f["reason"],
                ("; приёмы: %s" % ", ".join(f["actions"]))
                if f.get("actions") else ""))
        else:
            lines.append("%s: %s" % (f["title"], f["reason"]))
    return lines
