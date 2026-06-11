# core/unified/model.py
"""
Модель единого слоя маршрутизации: «что маршрутизируем → метод».

Цель (TODO.md): для каждого назначения (домены / CIDR / именованный
список / geosite / geoip) гибко выбрать, через что пустить трафик, с
приоритетной цепочкой fallback'ов и (опц.) автопереключением.

Сущности:

  Destination — что маршрутизируем. Селекторы:
      domains[]  — явные домены
      cidrs[]    — явные IP/подсети
      list_ids[] — ссылки на core/named_lists
      geosite[]  — категории geosite (понимают sing-box/mihomo)
      geoip[]    — категории geoip
    resolve() сводит domains/cidrs (включая из named-list'ов) в плоские
    множества; geosite/geoip отдаются как есть (их разворачивает движок).

  Method — через что. Строка-токен:
      'direct'            — напрямую (обход правил)
      'nfqws2'            — обход DPI на месте (домены → hostlist)
      'awg:<iface>'       — туннель AmneziaWG/WireGuard (iface)
      'singbox:<iface>'   — sing-box tun-интерфейс
      'mihomo:<iface>'    — mihomo tun-интерфейс
    parse_method() разбирает в (kind, target).

  UnifiedRoute — связка: селекторы + method(primary) + fallbacks[] +
    приоритет + флаги мониторинга/failover. Селекторы бывают:
      destination     — по НАЗНАЧЕНИЮ трафика (см. Destination);
      devices[]       — по ИСТОЧНИКУ: весь трафик с устройств
                        [{"ip","mac","hostname"}, ...] идёт через метод
                        (бывшие device-правила core/routing);
      dscp / dscp_self — по DSCP-метке (QoS) в IP-заголовке
                        (бывшие dscp-правила core/routing).
    devices/dscp имеют смысл только для туннельных методов — applier
    помечает их как skipped для direct/nfqws2.
"""

import time
import uuid


METHOD_KINDS = ("direct", "nfqws2", "awg", "singbox", "mihomo")


def parse_method(method: str) -> tuple:
    """
    Разобрать method-токен в (kind, target).
      'direct'          -> ('direct', '')
      'nfqws2'          -> ('nfqws2', '')
      'awg:awg0'        -> ('awg', 'awg0')
      'singbox:tun0'    -> ('singbox', 'tun0')
    Бросает ValueError на неизвестный/битый токен.
    """
    s = (method or "").strip()
    if not s:
        raise ValueError("Пустой метод")
    if ":" in s:
        kind, target = s.split(":", 1)
        kind, target = kind.strip().lower(), target.strip()
    else:
        kind, target = s.lower(), ""
    if kind not in METHOD_KINDS:
        raise ValueError("Неизвестный метод: %s" % method)
    if kind in ("awg", "singbox", "mihomo") and not target:
        raise ValueError("Метод %s требует интерфейс (%s:<iface>)"
                         % (kind, kind))
    return (kind, target)


def method_iface(method: str) -> str:
    """Целевой интерфейс метода ('' для direct/nfqws2)."""
    try:
        _kind, target = parse_method(method)
        return target
    except ValueError:
        return ""


def is_tunnel_method(method: str) -> bool:
    """True, если метод — туннель (маршрутизируется через iface)."""
    try:
        kind, _ = parse_method(method)
        return kind in ("awg", "singbox", "mihomo")
    except ValueError:
        return False


# ─────────────────────── Destination ─────────────────────────────────

class Destination:

    def __init__(self, *, domains=None, cidrs=None, list_ids=None,
                 geosite=None, geoip=None):
        self.domains  = _clean_list(domains, lower=True)
        self.cidrs    = _clean_list(cidrs)
        self.list_ids = _clean_list(list_ids)
        self.geosite  = _clean_list(geosite, lower=True)
        self.geoip    = _clean_list(geoip, lower=True)

    def is_empty(self) -> bool:
        return not (self.domains or self.cidrs or self.list_ids
                    or self.geosite or self.geoip)

    def resolve(self) -> dict:
        """
        Свести в плоские domains/cidrs, развернув named-list'ы.
        geosite/geoip возвращаются как есть.
        """
        domains = list(self.domains)
        cidrs = list(self.cidrs)
        for lid in self.list_ids:
            try:
                from core.named_lists import resolve as _resolve_list
                r = _resolve_list(lid)
                domains += r.get("domains", [])
                cidrs += r.get("cidrs", [])
            except Exception:
                continue
        return {
            "domains": _dedup(domains),
            "cidrs":   _dedup(cidrs),
            "geosite": list(self.geosite),
            "geoip":   list(self.geoip),
        }

    def to_dict(self) -> dict:
        return {
            "domains": list(self.domains), "cidrs": list(self.cidrs),
            "list_ids": list(self.list_ids),
            "geosite": list(self.geosite), "geoip": list(self.geoip),
        }

    @staticmethod
    def from_dict(d: dict):
        d = d or {}
        return Destination(
            domains=d.get("domains"), cidrs=d.get("cidrs"),
            list_ids=d.get("list_ids"),
            geosite=d.get("geosite"), geoip=d.get("geoip"))


# ─────────────────────── UnifiedRoute ────────────────────────────────

class UnifiedRoute:

    def __init__(self, *, name="", destination=None, method="direct",
                 fallbacks=None, priority=0, enabled=True,
                 monitor_enabled=False, failover_enabled=False,
                 probe_domain="", route_id="", created_at=0,
                 devices=None, dscp=None, dscp_self=False):
        self.id = route_id or ("route-" + uuid.uuid4().hex[:8])
        self.name = (name or "").strip() or self.id
        self.destination = (destination if isinstance(destination, Destination)
                            else Destination.from_dict(destination))
        # Валидируем методы — бросит ValueError при битом токене.
        parse_method(method)
        self.method = method.strip()
        self.fallbacks = []
        for m in (fallbacks or []):
            parse_method(m)
            self.fallbacks.append(m.strip())
        self.priority = int(priority or 0)
        self.enabled = bool(enabled)
        self.monitor_enabled = bool(monitor_enabled)
        self.failover_enabled = bool(failover_enabled)
        self.probe_domain = (probe_domain or "").strip()
        self.created_at = int(created_at or time.time())
        self.devices = _clean_devices(devices)
        self.dscp = _clean_dscp(dscp)
        self.dscp_self = bool(dscp_self)

    def has_selectors(self) -> bool:
        """Есть ли у маршрута хоть один селектор трафика."""
        return (not self.destination.is_empty()
                or bool(self.devices) or self.dscp is not None)

    def method_chain(self) -> list:
        """Приоритетная цепочка методов: primary + fallbacks (без дублей)."""
        out, seen = [], set()
        for m in [self.method] + self.fallbacks:
            if m and m not in seen:
                seen.add(m)
                out.append(m)
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name,
            "destination": self.destination.to_dict(),
            "method": self.method, "fallbacks": list(self.fallbacks),
            "priority": self.priority, "enabled": self.enabled,
            "monitor_enabled": self.monitor_enabled,
            "failover_enabled": self.failover_enabled,
            "probe_domain": self.probe_domain,
            "created_at": self.created_at,
            "devices": [dict(x) for x in self.devices],
            "dscp": self.dscp,
            "dscp_self": self.dscp_self,
        }

    @staticmethod
    def from_dict(d: dict):
        d = d or {}
        return UnifiedRoute(
            route_id=d.get("id") or "",
            name=d.get("name") or "",
            destination=Destination.from_dict(d.get("destination")),
            method=d.get("method") or "direct",
            fallbacks=d.get("fallbacks") or [],
            priority=d.get("priority") or 0,
            enabled=d.get("enabled", True),
            monitor_enabled=d.get("monitor_enabled", False),
            failover_enabled=d.get("failover_enabled", False),
            probe_domain=d.get("probe_domain") or "",
            created_at=d.get("created_at") or 0,
            devices=d.get("devices"),
            dscp=d.get("dscp"),
            dscp_self=d.get("dscp_self", False))


# ─────────────────────── helpers ─────────────────────────────────────

def _clean_devices(v) -> list:
    """
    Нормализовать список устройств-источников:
    [{"ip": str, "mac": str, "hostname": str}, ...]. Записи без ip
    отбрасываются, дубликаты по ip схлопываются (последний выигрывает
    mac/hostname, если они заполнены).
    """
    if not isinstance(v, (list, tuple)):
        return []
    by_ip = {}
    order = []
    for x in v:
        if not isinstance(x, dict):
            continue
        ip = str(x.get("ip") or "").strip()
        if not ip:
            continue
        entry = by_ip.get(ip)
        if entry is None:
            entry = {"ip": ip, "mac": "", "hostname": ""}
            by_ip[ip] = entry
            order.append(ip)
        mac = str(x.get("mac") or "").strip()
        hostname = str(x.get("hostname") or "").strip()
        if mac:
            entry["mac"] = mac
        if hostname:
            entry["hostname"] = hostname
    return [by_ip[ip] for ip in order]


def _clean_dscp(v):
    """DSCP-селектор: None (нет) или int 0..63. Иначе — ValueError."""
    if v is None or v == "":
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError("DSCP должен быть числом 0..63")
    if not (0 <= n <= 63):
        raise ValueError("DSCP вне диапазона 0..63: %d" % n)
    return n


def _clean_list(v, lower=False) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    out = []
    for x in v:
        s = str(x or "").strip()
        if lower:
            s = s.lower()
        if s:
            out.append(s)
    return _dedup(out)


def _dedup(seq) -> list:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
