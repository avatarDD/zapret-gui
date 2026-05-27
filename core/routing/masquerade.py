# core/routing/masquerade.py
"""
Общий помощник: MASQUERADE (SNAT) на исходящий AWG-интерфейс.

Любое selective-routing правило (cidr/device/domain), которое способно
завернуть в AWG-туннель ЧУЖОЙ (forwarded) трафик, обязано маскарадить
его на выходе. Иначе пакет уходит в туннель с исходным src (LAN-IP
клиента за роутером), AWG/WARP-сервер дропает его — туннель принимает
только пакеты с выданного клиенту адреса. Локально-сгенерированный
трафик самого роутера и так получает src=AWG_IP, для него masquerade —
безвредный no-op.

Раньше masquerade вешали только device- и domain-правила, а CIDR — нет
(ошибочно считалось, что у CIDR src «всегда корректный»). Для трафика,
форвардящегося с LAN-клиента, это неверно: правило `ip rule to <cidr>`
ловит и forwarded-пакеты, у которых src остаётся LAN-овым. Поэтому
masquerade нужен всем трём типам, а снимать его можно только когда на
интерфейс не ссылается ни одно включённое правило.

Backend выбирается так же, как для domain-rules: nft, если доступен
(одно inet-правило покрывает v4+v6), иначе iptables (по правилу на
семью).
"""

from core.log_buffer import log
from core.routing import ipset_backend, nftset_backend


def _backend():
    if nftset_backend.available():
        return nftset_backend
    if ipset_backend.available():
        return ipset_backend
    return None


def ensure_for_iface(ifname: str, families=("v4", "v6")) -> dict:
    """
    Идемпотентно повесить masquerade на исходящий ifname.

    families — какие семьи реально использует правило. Для iptables
    важно не дёргать ip6tables, если правило чисто v4 (на части роутеров
    ip6tables отсутствует, и лишний вызов даёт ложную ошибку). На nft
    одно inet-правило покрывает обе семьи, поэтому families игнорируется.
    """
    backend = _backend()
    if backend is None:
        return {"ok": False, "error": "нет backend (nft/iptables) для masquerade"}

    if backend is nftset_backend:
        return backend.ensure_iface_masquerade(ifname)

    errors = []
    added = False
    for fam in families:
        mq = backend.ensure_iface_masquerade(ifname, family=fam)
        if mq.get("ok"):
            added = added or bool(mq.get("added"))
        else:
            errors.append("%s: %s" % (fam, mq.get("error")))
    if errors:
        return {"ok": False, "error": "; ".join(errors), "ifname": ifname}
    return {"ok": True, "added": added, "ifname": ifname}


def remove_if_unused(ifname: str, excluding_id: str = "") -> dict:
    """
    Снять masquerade с ifname, если на него не ссылается ни одно ДРУГОЕ
    включённое routing-правило (cidr/device/domain).

    excluding_id — id правила, которое прямо сейчас снимается; его не
    учитываем при подсчёте «кому ещё нужен masquerade».
    """
    from core.routing import storage
    from core.routing.rules import (
        CidrRoutingRule,
        DeviceRoutingRule,
        DomainRoutingRule,
    )

    for r in storage.load_rules():
        if not r.enabled or r.id == excluding_id:
            continue
        if r.target_iface != ifname:
            continue
        if isinstance(r, (CidrRoutingRule, DeviceRoutingRule, DomainRoutingRule)):
            return {"ok": True, "removed": False, "reason": "still in use"}

    # Никто больше не использует интерфейс — снимаем masquerade с обоих
    # бэкендов (idempotent), чтобы не оставить висящего правила, если
    # доступность бэкендов между apply и remove поменялась.
    if nftset_backend.available():
        nftset_backend.remove_iface_masquerade(ifname)
    if ipset_backend.available():
        for fam in ("v4", "v6"):
            ipset_backend.remove_iface_masquerade(ifname, family=fam)
    log.info("routing: masquerade снят с %s (больше не используется)" % ifname,
             source="routing")
    return {"ok": True, "removed": True, "ifname": ifname}
