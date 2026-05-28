# core/ndms/__init__.py
"""
Интеграция со встроенным Keenetic Router Control Interface (RCI).

RCI — локальный HTTP API роутера на http://localhost:79/rci/,
позволяющий выполнять любые NDMS-CLI команды через JSON-payload'ы.
Доступен без аутентификации, когда запрос пришёл с самого роутера
(127.0.0.1).

Этот пакет — фундамент для Keenetic-native бэкенда selective
routing: вместо нашего dnsmasq+ipset+fwmark стека мы используем
штатные средства Keenetic (`object-group fqdn`, `dns-proxy route`,
`ip route`), которые умеют работать с системным ndnsproxy на
53-м порту — без конфликта.

Доступность RCI ВСЕГДА проверяется в рантайме (см. `is_ndms_available()`).
Никакой код этого пакета не должен импортироваться на не-Keenetic
платформах при модульном уровне — только внутри функций,
где уже сделана проверка.

Поверхностный API:

    from core.ndms import is_ndms_available, get_ndms_commands

    if is_ndms_available():
        cmd = get_ndms_commands()
        cmd.upsert_fqdn_group("zapret-gui-yt", include=["youtube.com"])
        cmd.set_dns_proxy_route("zapret-gui-yt", "Wireguard0")
"""

from core.ndms.rci_client import (
    NdmsRciClient,
    get_rci_client,
    is_ndms_available,
)
from core.ndms.commands import (
    NdmsCommands,
    get_ndms_commands,
)
from core.ndms.wg_discovery import (
    list_native_wg_interfaces,
    is_native_wg,
)
from core.ndms.ping_check import (
    get_native_wg_status,
    should_delegate_monitoring,
)

__all__ = [
    "NdmsRciClient",
    "NdmsCommands",
    "get_rci_client",
    "get_ndms_commands",
    "is_ndms_available",
    "list_native_wg_interfaces",
    "is_native_wg",
    "get_native_wg_status",
    "should_delegate_monitoring",
]
