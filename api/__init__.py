# api/__init__.py
"""
Регистрация всех API-маршрутов Bottle-приложения.
"""

# Модули api/* импортируют bottle на уровне модуля. Если системного
# bottle нет (dev-окружение, установка без python3-bottle) — здесь, при
# первом же `import api.<...>`, подключается встроенный vendor/bottle.py.
from core.bottle_vendor import ensure_bottle
ensure_bottle()


def register_routes(app):
    """Зарегистрировать все API-маршруты в Bottle-приложении."""
    from api.status import register as reg_status
    from api.logs import register as reg_logs
    from api.config_api import register as reg_config
    from api.control import register as reg_control
    from api.strategies import register as reg_strategies
    from api.hostlists import register as reg_hostlists
    from api.ipsets import register as reg_ipsets
    from api.lua_scripts import register as reg_lua
    from api.blobs import register as reg_blobs
    from api.hosts import register as reg_hosts
    from api.diagnostics import register as reg_diagnostics
    from api.autostart import register as reg_autostart
    from api.zapret_manager import register as reg_zapret_manager
    from api.blockcheck import register as reg_blockcheck
    from api.blockcheck2 import register as reg_blockcheck2
    from api.scan import register as reg_scan
    from api.gui_update import register as reg_gui_update
    from api.catalog_update import register as reg_catalog_update
    from api.awg import register as reg_awg
    from api.routing import register as reg_routing
    from api.devices import register as reg_devices
    from api.connectivity import register as reg_connectivity
    from api.singbox import register as reg_singbox
    from api.mihomo import register as reg_mihomo
    from api.lists import register as reg_lists
    from api.unified import register as reg_unified
    from api.backup import register as reg_backup
    from api.healthcheck import register as reg_healthcheck
    from api.usque import register as reg_usque
    from api.tgproxy import register as reg_tgproxy
    from api.block_detector import register as reg_block_detector
    from api.geosite import register as reg_geosite
    from api.opera_proxy import register as reg_opera_proxy
    from api.update_checker import register as reg_update_checker
    from api.auto_remediation import register as reg_auto_remediation
    from api.warp_in_warp import register as reg_warp_in_warp
    from api.tunnel_monitor import register as reg_tunnel_monitor
    from api.tunnel_optimizer import register as reg_tunnel_optimizer
    from api.dns_routing import register as reg_dns_routing

    reg_status(app)
    reg_logs(app)
    reg_config(app)
    reg_control(app)
    reg_strategies(app)
    reg_hostlists(app)
    reg_ipsets(app)
    reg_lua(app)
    reg_blobs(app)
    reg_hosts(app)
    reg_diagnostics(app)
    reg_autostart(app)
    reg_zapret_manager(app)
    reg_blockcheck(app)
    reg_blockcheck2(app)
    reg_scan(app)
    reg_gui_update(app)
    reg_catalog_update(app)
    reg_awg(app)
    reg_routing(app)
    reg_devices(app)
    reg_connectivity(app)
    reg_singbox(app)
    reg_mihomo(app)
    reg_lists(app)
    reg_unified(app)
    reg_backup(app)
    reg_healthcheck(app)
    reg_usque(app)
    reg_tgproxy(app)
    reg_block_detector(app)
    reg_geosite(app)
    reg_opera_proxy(app)
    reg_update_checker(app)
    reg_auto_remediation(app)
    reg_warp_in_warp(app)
    reg_tunnel_monitor(app)
    reg_tunnel_optimizer(app)
    reg_dns_routing(app)

    # MR-56: добавить /api/v1/<path> aliases для всех /api/<path> маршрутов
    from api.v1_compat import register_v1_aliases
    register_v1_aliases(app)
