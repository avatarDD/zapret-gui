# core/tgproxy_redirect.py
"""
Заворачивание трафика к датацентрам Telegram на локальный порт
резервного движка (`tg-mtproxy-client`) через nat REDIRECT.

Зачем это отдельный слой. tg-mtproxy-client — НЕ MTProto-прокси: он
читает исходный адрес назначения через `SO_ORIGINAL_DST` (listener.go
апстрима) и умеет работать ТОЛЬКО с трафиком, который ядро завернуло на
его порт правилом REDIRECT. Без этих правил движок запускается, держит
порт и не получает ни одного соединения — ровно то состояние, в котором
он и жил до появления этого модуля.

Отличие от `route_telegram_dc_via_tunnel()`: тот отправляет те же CIDR в
ТУННЕЛЬ (ip rule/route через awg/warp-интерфейс), а здесь — локальный
REDIRECT на порт процесса. Механизмы независимы и не должны включаться
одновременно: иначе пакет сперва редиректится на локальный порт и до
туннельного маршрута уже не доходит.

Правила живут в СВОЕЙ цепочке (iptables) или СВОЕЙ таблице (nft), чтобы
снятие было точным и идемпотентным, а чужие правила не пострадали.

Только IPv4. Диапазоны v6 Telegram сюда не включаем по той же причине,
что и в маршрутизации: у апстрима `getOriginalDst` для IPv6 усекает
адрес до первых 20 байт, и корректность держится только на удачном
попадании в известные префиксы.
"""

import re
import shutil
import subprocess

from core.log_buffer import log

# Своё имя — чтобы снимать ровно наши правила и не трогать чужие.
CHAIN = "ZAPRET_TGDC"
NFT_TABLE = "tgproxy_redirect"

_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


def _run(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _backend() -> str:
    """'nftables' | 'iptables' | '' — тем же правилом, что и firewall.

    Важно не разойтись с core/firewall: на OpenWrt 22+ `iptables` — лишь
    шим над nftables, и наши правила иначе уехали бы в таблицу, которой
    владеет fw4, и терялись при перезагрузке firewall.
    """
    try:
        from core.firewall import FirewallManager
        return FirewallManager._auto_detect() or ""
    except Exception:
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        return ""


def _valid_cidrs(cidrs) -> list:
    return [c for c in (cidrs or []) if _CIDR_RE.match(str(c or "").strip())]


# ─────────────────────────── iptables ───────────────────────────

def _ipt_apply(port: int, cidrs: list) -> dict:
    # Пересоздаём цепочку с нуля: так «применить» идемпотентно и не
    # копит дубли при повторных запусках.
    _ipt_remove()

    rc, _o, err = _run(["iptables", "-t", "nat", "-N", CHAIN])
    if rc != 0 and "exists" not in err.lower():
        return {"ok": False, "error": "создать цепочку %s: %s"
                                      % (CHAIN, err.strip())}

    for cidr in cidrs:
        rc, _o, err = _run([
            "iptables", "-t", "nat", "-A", CHAIN,
            "-p", "tcp", "-d", cidr,
            "-j", "REDIRECT", "--to-ports", str(port),
        ])
        if rc != 0:
            _ipt_remove()
            return {"ok": False, "error": "правило для %s: %s"
                                          % (cidr, err.strip())}

    # PREROUTING — трафик LAN-клиентов (форвардинг), OUTPUT — трафик
    # самого роутера. Нужны оба: иначе либо телефоны, либо сам роутер
    # ходят мимо движка.
    for hook in ("PREROUTING", "OUTPUT"):
        rc, _o, err = _run(["iptables", "-t", "nat", "-I", hook,
                            "-j", CHAIN])
        if rc != 0:
            _ipt_remove()
            return {"ok": False, "error": "подключить %s к %s: %s"
                                          % (CHAIN, hook, err.strip())}
    return {"ok": True, "backend": "iptables", "rules": len(cidrs)}


def _ipt_remove() -> None:
    # Отцепить из хуков (может быть несколько ссылок — снимаем все).
    for hook in ("PREROUTING", "OUTPUT"):
        for _ in range(10):
            rc, _o, _e = _run(["iptables", "-t", "nat", "-D", hook,
                               "-j", CHAIN])
            if rc != 0:
                break
    _run(["iptables", "-t", "nat", "-F", CHAIN])
    _run(["iptables", "-t", "nat", "-X", CHAIN])


def _ipt_active() -> bool:
    rc, out, _e = _run(["iptables", "-t", "nat", "-S", CHAIN])
    return rc == 0 and "-A %s" % CHAIN in out


# ───────────────────────────── nft ──────────────────────────────

def _nft_apply(port: int, cidrs: list) -> dict:
    _nft_remove()

    daddr = ", ".join(cidrs)
    # priority dstnat — та же точка, где работает штатный NAT прошивки.
    ruleset = "\n".join([
        "table ip %s {" % NFT_TABLE,
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat; policy accept;",
        "    ip daddr { %s } tcp dport 1-65535 redirect to :%d"
        % (daddr, port),
        "  }",
        "  chain output {",
        "    type nat hook output priority dstnat; policy accept;",
        "    ip daddr { %s } tcp dport 1-65535 redirect to :%d"
        % (daddr, port),
        "  }",
        "}",
        "",
    ])
    # Через stdin, а не argv: правило многострочное, и `nft -f -` —
    # штатный способ применить его атомарно целиком.
    try:
        r = subprocess.run(["nft", "-f", "-"], input=ruleset,
                           capture_output=True, text=True, timeout=20)
        rc, err = r.returncode, (r.stderr or "")
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "error": "nft: %s" % e}
    if rc != 0:
        return {"ok": False, "error": "nft: %s" % err.strip()}
    return {"ok": True, "backend": "nftables", "rules": len(cidrs)}


def _nft_remove() -> None:
    _run(["nft", "delete", "table", "ip", NFT_TABLE])


def _nft_active() -> bool:
    rc, out, _e = _run(["nft", "list", "table", "ip", NFT_TABLE])
    return rc == 0 and "redirect to" in out


# ─────────────────────────── публичное ──────────────────────────

def apply(port: int, cidrs=None) -> dict:
    """Завернуть TCP к CIDR Telegram на 127.0.0.1:<port>."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Некорректный порт"}
    if not (1 <= port <= 65535):
        return {"ok": False, "error": "Порт вне диапазона 1-65535"}

    if cidrs is None:
        from core.tgproxy_manager import TELEGRAM_DC_CIDRS
        cidrs = TELEGRAM_DC_CIDRS
    cidrs = _valid_cidrs(cidrs)
    if not cidrs:
        return {"ok": False, "error": "Пустой список CIDR"}

    backend = _backend()
    if backend == "nftables":
        res = _nft_apply(port, cidrs)
    elif backend == "iptables":
        res = _ipt_apply(port, cidrs)
    else:
        return {"ok": False,
                "error": "Не найден ни nft, ни iptables — заворачивать "
                         "трафик нечем"}

    if res.get("ok"):
        log.success("tgproxy: Telegram DC (%d диапазонов) заворачиваются на "
                    "порт %d (%s)" % (len(cidrs), port, res["backend"]),
                    source="tgproxy")
    else:
        log.warning("tgproxy: REDIRECT не применён: %s"
                    % res.get("error", ""), source="tgproxy")
    return res


def remove() -> dict:
    """Снять наши правила. Идемпотентно."""
    backend = _backend()
    if backend == "nftables":
        _nft_remove()
    elif backend == "iptables":
        _ipt_remove()
    else:
        # Бэкенда нет — снимать нечего, это не ошибка.
        return {"ok": True, "noop": True}
    log.info("tgproxy: REDIRECT Telegram DC снят", source="tgproxy")
    return {"ok": True}


def status() -> dict:
    backend = _backend()
    if backend == "nftables":
        return {"ok": True, "backend": backend, "active": _nft_active()}
    if backend == "iptables":
        return {"ok": True, "backend": backend, "active": _ipt_active()}
    return {"ok": True, "backend": "", "active": False}
