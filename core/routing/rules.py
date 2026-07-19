# core/routing/rules.py
"""
Типы правил selective routing.

Каждое правило знает свой тип, целевой интерфейс и параметры.
Сериализуется в dict для хранения в settings.json.
"""

import ipaddress
import os
import re
import time


# MR-36: Приоритет по умолчанию для правил маршрутизации.
# 10000 находится в диапазоне 0-32767, но выше системных правил (0-9999),
# чтобы не конфликтовать с ними.
DEFAULT_PRIORITY = 10000


# Допустимые имена интерфейсов: то же ограничение, что и в awg_manager.
_IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")


def _valid_iface_name(name: str) -> bool:
    return bool(name) and bool(_IFACE_NAME_RE.match(name))


def _detect_family(cidr: str) -> str:
    """Вернуть 'v4' или 'v6' для CIDR-строки."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        raise ValueError("Некорректный CIDR: %s" % cidr)
    return "v6" if net.version == 6 else "v4"


def _normalize_cidr(cidr: str) -> str:
    """Нормализовать CIDR (lowercase, with_prefixlen)."""
    s = (cidr or "").strip()
    if not s:
        raise ValueError("Пустой CIDR")
    # Поддержим одиночный IP без маски — превращаем в /32 или /128
    if "/" not in s:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            raise ValueError("Некорректный IP/CIDR: %s" % cidr)
        return "%s/%d" % (str(ip), 32 if ip.version == 4 else 128)
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        raise ValueError("Некорректный CIDR: %s" % cidr)


# ───────────────────────── base ──────────────────────────────────────

class RoutingRule:
    """Базовый класс правила. Не использовать напрямую."""

    type_name = "base"

    def __init__(self, target_iface: str = "", description: str = "",
                 enabled: bool = True, rule_id: str = "",
                 priority: int = 0, created_at: int = 0):
        if not _valid_iface_name(target_iface):
            raise ValueError("Имя целевого интерфейса некорректно")
        self.id          = rule_id or self._make_id()
        self.target_iface = target_iface
        self.description  = (description or "").strip()
        self.enabled      = bool(enabled)
        self.priority     = int(priority) if priority else DEFAULT_PRIORITY
        self.created_at   = int(created_at) if created_at else int(time.time())

    def _make_id(self) -> str:
        # os.urandom, а не uuid: на Entware python3-light без модуля uuid
        return "%s-%s" % (self.type_name, os.urandom(4).hex())

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "type":         self.type_name,
            "target_iface": self.target_iface,
            "description":  self.description,
            "enabled":      self.enabled,
            "priority":     self.priority,
            "created_at":   self.created_at,
        }

    def __repr__(self):
        return "<%s id=%s iface=%s>" % (self.__class__.__name__,
                                        self.id, self.target_iface)


# ───────────────────────── CIDR ──────────────────────────────────────

class CidrRoutingRule(RoutingRule):
    """
    Маршрутизация по CIDR.

    Все запросы к адресам из `cidrs` уходят через `target_iface`.
    Если `ip_version` = "auto" — определяется по каждому CIDR.
    """

    type_name = "cidr"

    def __init__(self, target_iface: str, cidrs=None, ip_version: str = "auto",
                 **kwargs):
        super().__init__(target_iface=target_iface, **kwargs)

        raw = cidrs or []
        if isinstance(raw, str):
            raw = [raw]
        norm = []
        for c in raw:
            if not str(c).strip():
                continue
            norm.append(_normalize_cidr(str(c)))
        if not norm:
            raise ValueError("Нужен хотя бы один CIDR")

        if ip_version not in ("auto", "v4", "v6"):
            raise ValueError("ip_version должен быть auto|v4|v6")

        # Если зафиксирована версия — проверим, что все CIDR ей соответствуют
        if ip_version != "auto":
            for c in norm:
                if _detect_family(c) != ip_version:
                    raise ValueError(
                        "CIDR %s не соответствует ip_version=%s" % (c, ip_version)
                    )

        self.cidrs       = norm
        self.ip_version  = ip_version

    def cidr_families(self):
        """Список (cidr, 'v4'|'v6')."""
        return [(c, _detect_family(c)) for c in self.cidrs]

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["cidrs"]      = list(self.cidrs)
        d["ip_version"] = self.ip_version
        return d


# ───────────────────────── Domain (заглушка) ─────────────────────────

class DomainRoutingRule(RoutingRule):
    """
    Маршрутизация по доменам через dnsmasq + ipset/nftset.
    Полная реализация — в следующем промте.
    """

    type_name = "domain"

    def __init__(self, target_iface: str, domains=None, **kwargs):
        super().__init__(target_iface=target_iface, **kwargs)
        self.domains = [str(d).strip() for d in (domains or []) if str(d).strip()]

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["domains"] = list(self.domains)
        return d


# ───────────────────────── Device (заглушка) ─────────────────────────

class DeviceRoutingRule(RoutingRule):
    """
    Маршрутизация по устройству (per-device).
    Полная реализация — в следующем промте.
    """

    type_name = "device"

    def __init__(self, target_iface: str, source_ip: str = "",
                 mac: str = "", hostname: str = "", **kwargs):
        super().__init__(target_iface=target_iface, **kwargs)
        self.source_ip = (source_ip or "").strip()
        self.mac       = (mac or "").strip()
        self.hostname  = (hostname or "").strip()

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["source_ip"] = self.source_ip
        d["mac"]       = self.mac
        d["hostname"]  = self.hostname
        return d


# ───────────────────────── DSCP / QoS ────────────────────────────────

class DscpRoutingRule(RoutingRule):
    """
    Маршрутизация по DSCP-метке (QoS). Заимствовано из XKeen.

    Пакеты, несущие заданное значение DSCP в IP-заголовке, уходят
    через `target_iface`. Метку DSCP обычно ставит штатный QoS роутера
    (Keenetic IntelliQoS, OpenWrt SQM/qosify) — по приложению, порту,
    устройству. Мы лишь маршрутизируем уже промаркированный трафик в
    туннель: `-m dscp --dscp N -j MARK` + `ip rule fwmark`.

    dscp: 0..63 (DSCP-класс, напр. 46 = EF для realtime).
    """

    type_name = "dscp"

    def __init__(self, target_iface: str, dscp=None,
                 proxy_self: bool = False, **kwargs):
        super().__init__(target_iface=target_iface, **kwargs)
        try:
            self.dscp = int(dscp)
        except (TypeError, ValueError):
            raise ValueError("DSCP должен быть числом 0..63")
        if not (0 <= self.dscp <= 63):
            raise ValueError("DSCP вне диапазона 0..63: %d" % self.dscp)
        self.proxy_self = bool(proxy_self)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["dscp"] = self.dscp
        d["proxy_self"] = self.proxy_self
        return d


# ───────────────────────── factory ───────────────────────────────────

_TYPE_REGISTRY = {
    "cidr":   CidrRoutingRule,
    "domain": DomainRoutingRule,
    "device": DeviceRoutingRule,
    "dscp":   DscpRoutingRule,
}


def rule_from_dict(d: dict) -> RoutingRule:
    """Десериализовать правило из dict."""
    if not isinstance(d, dict):
        raise ValueError("Правило должно быть объектом")
    rtype = (d.get("type") or "").strip().lower()
    cls = _TYPE_REGISTRY.get(rtype)
    if cls is None:
        raise ValueError("Неизвестный тип правила: %s" % rtype)

    common = dict(
        rule_id=d.get("id") or "",
        target_iface=d.get("target_iface") or "",
        description=d.get("description") or "",
        enabled=bool(d.get("enabled", True)),
        priority=int(d.get("priority") or DEFAULT_PRIORITY),
        created_at=int(d.get("created_at") or 0),
    )

    if cls is CidrRoutingRule:
        return CidrRoutingRule(
            cidrs=d.get("cidrs") or [],
            ip_version=d.get("ip_version") or "auto",
            **common,
        )
    if cls is DomainRoutingRule:
        return DomainRoutingRule(
            domains=d.get("domains") or [],
            **common,
        )
    if cls is DeviceRoutingRule:
        return DeviceRoutingRule(
            source_ip=d.get("source_ip") or "",
            mac=d.get("mac") or "",
            hostname=d.get("hostname") or "",
            **common,
        )
    if cls is DscpRoutingRule:
        return DscpRoutingRule(
            dscp=d.get("dscp"),
            proxy_self=bool(d.get("proxy_self", False)),
            **common,
        )
    raise ValueError("Неподдерживаемый тип: %s" % rtype)
