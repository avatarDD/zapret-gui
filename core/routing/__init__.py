# core/routing/__init__.py
"""
Selective routing engine.

Универсальный движок selective routing: маршрутизация трафика
в произвольный сетевой интерфейс по разным критериям (CIDR,
домены, устройства).

Архитектурно не привязан к AmneziaWG — будет переиспользоваться
будущей Sing-box интеграцией.

Поверхностный API:
    from core.routing import (
        get_routing_manager,
        CidrRoutingRule,
        DomainRoutingRule,
        DeviceRoutingRule,
    )

    mgr = get_routing_manager()
    rule = CidrRoutingRule(target_iface="warp1", cidrs=["1.2.3.0/24"])
    mgr.add_rule(rule)
    mgr.apply_rule(rule)
"""

from core.routing.rules import (
    RoutingRule,
    CidrRoutingRule,
    DomainRoutingRule,
    DeviceRoutingRule,
    rule_from_dict,
)
from core.routing.manager import RoutingManager, get_routing_manager
from core.routing.applier import (
    apply_all_on_interface_up,
    remove_all_on_interface_down,
)

__all__ = [
    "RoutingRule",
    "CidrRoutingRule",
    "DomainRoutingRule",
    "DeviceRoutingRule",
    "rule_from_dict",
    "RoutingManager",
    "get_routing_manager",
    "apply_all_on_interface_up",
    "remove_all_on_interface_down",
]
