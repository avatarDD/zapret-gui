# core/warp_importer.py
"""
Импорт готовых AmneziaWG-WARP конфигов, сгенерированных сторонними
сервисами (например, https://warp-generator.github.io).

Принципы:
  * Парсинг и валидация — через core.awg_config (без дублирования логики).
  * Дополнительная эвристика is_warp_config(): peer endpoint в диапазонах
    Cloudflare WARP и AllowedIPs = 0.0.0.0/0 / ::/0.
  * Сохранение — через core.awg_manager.save_config(), с авто-выбором
    свободного имени warp-1, warp-2, ...

Использование:
    from core.warp_importer import import_from_text, is_warp_config
    res = import_from_text(text)
    # res = {"ok": True, "name": "warp-1", "config": {...}, "warnings": [...]}
"""

import ipaddress
import re

from core.awg_config import parse_conf, validate as validate_cfg


# Известные пулы Cloudflare WARP — endpoint должен попадать сюда.
# Источник: cloudflareclient v0a2483 + публичные диапазоны Cloudflare,
# которые используются engage.cloudflareclient.com.
WARP_ENDPOINT_NETWORKS_V4 = (
    "162.159.192.0/24",   # engage.cloudflareclient.com
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/22",    # резервные пулы CF WARP
)

WARP_ENDPOINT_NETWORKS_V6 = (
    "2606:4700:d0::/48",
    "2606:4700:d1::/48",
)

# AllowedIPs, типичные для WARP (full-tunnel).
WARP_ALLOWED_IPS = ("0.0.0.0/0", "::/0")

DEFAULT_NAME_PREFIX = "warp"
MAX_NAME_INDEX = 999


# ───────────────────────── helpers ──────────────────────────────────

def _to_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _split_endpoint(endpoint: str):
    """'host:port' → (host, port). Поддержка [ipv6]:port."""
    if not endpoint:
        return "", ""
    s = endpoint.strip()
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if m:
            return m.group(1), m.group(2)
        return "", ""
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, port
    return s, ""


def _is_in_warp_range(host: str) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Доменное имя — мягко считаем WARP'ом, если на него совпадает
        # известная маска (engage.cloudflareclient.com и т. п.)
        h = host.lower()
        if "cloudflareclient.com" in h or h.endswith(".cloudflare.com"):
            return True
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        for cidr in WARP_ENDPOINT_NETWORKS_V4:
            if ip in ipaddress.ip_network(cidr):
                return True
    else:
        for cidr in WARP_ENDPOINT_NETWORKS_V6:
            if ip in ipaddress.ip_network(cidr):
                return True
    return False


# ───────────────────────── detection ────────────────────────────────

def is_warp_config(parsed: dict) -> dict:
    """
    Проверить, похож ли распарсенный конфиг на WARP.
    Возвращает {"is_warp": bool, "score": int, "reasons": [...]}.

    score > 0  — есть признаки WARP'а
    score >= 2 — уверенно WARP
    """
    reasons = []
    score = 0
    parsed = parsed or {}
    peers = parsed.get("peers") or []

    if not peers:
        return {"is_warp": False, "score": 0, "reasons": ["нет [Peer]"]}

    # Берём первый peer — у WARP обычно один.
    peer = peers[0]
    endpoint = (peer.get("Endpoint") or "").strip()
    host, _port = _split_endpoint(endpoint)
    if _is_in_warp_range(host):
        score += 2
        reasons.append("endpoint в диапазоне Cloudflare WARP")
    elif host:
        reasons.append(f"endpoint {host} — не из известных WARP-диапазонов")

    allowed = set(_to_list(peer.get("AllowedIPs")))
    if any(a in allowed for a in WARP_ALLOWED_IPS):
        score += 1
        reasons.append("AllowedIPs содержит full-tunnel")

    # AmneziaWG-обфускация — не обязательна, но бонус к уверенности.
    iface = parsed.get("interface") or {}
    if any(k in iface for k in ("Jc", "Jmin", "Jmax", "S1", "S2",
                                "H1", "H2", "H3", "H4")):
        score += 1
        reasons.append("есть AmneziaWG-обфускация")

    return {
        "is_warp": score >= 2,
        "score":   score,
        "reasons": reasons,
    }


# ───────────────────────── naming ───────────────────────────────────

def pick_default_name(existing_names) -> str:
    """
    Выбрать свободное имя warp-1, warp-2, ... по списку существующих.
    """
    taken = set(existing_names or [])
    for i in range(1, MAX_NAME_INDEX + 1):
        candidate = f"{DEFAULT_NAME_PREFIX}-{i}"
        if candidate not in taken:
            return candidate
    raise RuntimeError("Не удалось подобрать свободное имя warp-N")


# ───────────────────────── import ───────────────────────────────────

def import_from_text(text: str, name: str = None) -> dict:
    """
    Распарсить .conf-текст и сохранить как AWG-конфиг.

    Параметры:
        text — содержимое .conf
        name — желаемое имя; если None — авто (warp-N)

    Возвращает:
        {
          "ok":       bool,
          "name":     str,           # имя сохранённого конфига
          "config":   {...},         # результат awg_manager.get_config()
          "is_warp":  bool,
          "warnings": [...]          # предупреждения, если конфиг не похож
                                     # на WARP — импорт всё равно проходит
        }

    При ошибках валидации/парсинга бросает ValueError с понятным сообщением.
    """
    if not text or not text.strip():
        raise ValueError("Пустой конфиг")

    try:
        parsed = parse_conf(text)
    except Exception as e:
        raise ValueError(f"Не удалось распарсить .conf: {e}")

    errors = validate_cfg(parsed)
    if errors:
        raise ValueError("Ошибки конфига: " + "; ".join(errors))

    detection = is_warp_config(parsed)
    warnings = []
    if not detection["is_warp"]:
        warnings.append(
            "Конфиг не похож на WARP. " +
            "; ".join(detection.get("reasons") or [])
        )

    # Импорт через AwgManager — он возьмёт на себя запись и валидацию имени.
    # Импорт здесь, чтобы не плодить циклические зависимости при загрузке.
    from core.awg_manager import get_awg_manager
    mgr = get_awg_manager()

    if not name:
        existing = [c["name"] for c in mgr.list_configs()]
        name = pick_default_name(existing)

    cfg = mgr.save_config(name, text=text, allow_overwrite=False)

    return {
        "ok":        True,
        "name":      name,
        "config":    cfg,
        "is_warp":   detection["is_warp"],
        "warnings":  warnings,
    }
