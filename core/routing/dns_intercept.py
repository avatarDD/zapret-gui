# core/routing/dns_intercept.py
"""
Перехват DNS LAN-клиентов (:53 → наш прокси) для доменной маршрутизации
без dnsmasq (типичный Keenetic: 53-й порт занят ndnsproxy).

Проблема, которую решает: без dnsmasq GUI не видит живые DNS-запросы
клиентов — доменные правила ловят только IP, которые разрезолвил сам
роутер, а браузер ходит на ротацию CDN-поддоменов
(rr3---sn-*.googlevideo.com) и уезжает мимо туннеля. Отсюда «маршрут
работает только с выбором устройства».

Как работает:
  1) iptables nat PREROUTING (наша цепочка AWG_DNS_INT):
     `-p udp --dport 53 -j REDIRECT --to-ports <port>` — ловим ЛЮБОЙ
     клиентский DNS (и адресованный роутеру, и hardcoded 8.8.8.8).
     Запросы самого роутера идут через OUTPUT и НЕ перехватываются —
     петли нет.
  2) UDP-прокси (threading, без asyncio — python3-light) пересылает
     запрос штатному резолверу (upstream, по умолчанию 127.0.0.1:53 —
     ndnsproxy) и возвращает ответ клиенту как есть.
  3) Разбирая ответ (A/AAAA, с компрессией имён), прокси сверяет qname
     с доменами активных domain-правил (suffix-match — поддомены
     покрываются) и кладёт IP в ipset правила (set-путь) либо в
     policy-db (`ip rule to`, iproute-путь). Клиент получает тот же
     ответ, но его IP уже маршрутизируются в туннель.

Failsafe: REDIRECT ставится только когда прокси реально слушает порт, и
снимается при stop()/atexit/ошибке цикла. Если процесс GUI убит жёстко
(kill -9), правило может остаться до перезапуска GUI — поэтому фича
opt-in. Ограничение любого перехвата :53: клиенты с DoH (браузерный
DNS-over-HTTPS) идут мимо.

Настройки (settings.json → routing.dns_intercept):
    enabled  — по умолчанию false (кнопка на странице «Маршрутизация»);
    port     — локальный порт прокси (по умолчанию 15353);
    upstream — "ip:port" (по умолчанию "127.0.0.1:53").
"""

import atexit
import queue
import socket
import struct
import threading
import time

from core.log_buffer import log


DEFAULT_PORT = 15353
DEFAULT_UPSTREAM = ("127.0.0.1", 53)
NAT_CHAIN = "AWG_DNS_INT"
_WORKERS = 4
_RULES_TTL = 60.0        # сек: перечитать домены правил не чаще
_UPSTREAM_TIMEOUT = 4.0


def _run(args, timeout=5):
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", str(e)


# ─────────────────────── DNS-парсер ─────────────────────────────────

def _read_name(data: bytes, off: int, depth: int = 0):
    """(имя, следующий offset). Понимает компрессию (0xC0-указатели)."""
    if depth > 8:
        raise ValueError("compression loop")
    labels = []
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            tail, _ = _read_name(data, ptr, depth + 1)
            if tail:
                labels.append(tail)
            off += 2
            break
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    return ".".join(labels), off


def parse_dns_response(data: bytes):
    """
    Разобрать DNS-ответ: (qname, [(ip, 'v4'|'v6'), ...]).
    Возвращает ("", []) на любом мусоре — прокси не должен падать.
    """
    try:
        if len(data) < 12:
            return "", []
        _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(
            "!HHHHHH", data[:12])
        if not flags & 0x8000:          # не ответ
            return "", []
        off = 12
        qname = ""
        for _ in range(qdcount):
            qname, off = _read_name(data, off)
            off += 4                    # qtype + qclass
        ips = []
        for _ in range(ancount):
            _name, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(
                "!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:          # A
                ips.append((socket.inet_ntop(socket.AF_INET, rdata), "v4"))
            elif rtype == 28 and rdlen == 16:      # AAAA
                ips.append((socket.inet_ntop(socket.AF_INET6, rdata), "v6"))
        return qname.lower().rstrip("."), ips
    except (ValueError, struct.error, OSError):
        return "", []


def domain_matches(qname: str, domain: str) -> bool:
    """Суффикс-матч: qname == domain или *.domain."""
    d = (domain or "").lower().strip(".")
    if not d or not qname:
        return False
    return qname == d or qname.endswith("." + d)


# ─────────────────────── настройки ──────────────────────────────────

def _settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        sec = get_config_manager().get("routing", "dns_intercept",
                                       default={}) or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:
        return {}


def is_enabled() -> bool:
    return bool(_settings().get("enabled", False))


def _port() -> int:
    try:
        return int(_settings().get("port", DEFAULT_PORT))
    except (TypeError, ValueError):
        return DEFAULT_PORT


def _upstream():
    s = str(_settings().get("upstream", "")).strip()
    if ":" in s:
        host, _, port = s.rpartition(":")
        try:
            return (host or DEFAULT_UPSTREAM[0], int(port))
        except ValueError:
            pass
    return DEFAULT_UPSTREAM


# ─────────────────────── прокси ─────────────────────────────────────

class DnsIntercept:

    def __init__(self):
        self._lock = threading.Lock()
        self._sock = None
        self._queue = None
        self._threads = []
        self._running = False
        self._redirected = False
        self._rules_cache = []       # [{id, kind, set_v4, set_v6, table,
        #                              iface, domains}], kind: ipset|nftset|iproute
        self._rules_at = 0.0
        self._seen = set()           # (rule_id, ip) — уже добавленные
        self.stats = {"queries": 0, "matched": 0, "ips_added": 0,
                      "errors": 0}

    # ── публичное API ─────────────────────────────────────────────

    def start(self) -> dict:
        with self._lock:
            if self._running:
                return {"ok": True, "already": True}
            port = _port()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.settimeout(1.0)
            except OSError as e:
                return {"ok": False,
                        "error": "не удалось занять порт %d: %s" % (port, e)}
            self._sock = sock
            self._queue = queue.Queue(maxsize=256)
            self._running = True
            self._threads = []
            t = threading.Thread(target=self._recv_loop, daemon=True,
                                 name="dns-int-recv")
            t.start()
            self._threads.append(t)
            for i in range(_WORKERS):
                w = threading.Thread(target=self._worker, daemon=True,
                                     name="dns-int-w%d" % i)
                w.start()
                self._threads.append(w)
            # REDIRECT — только когда сокет реально слушает.
            red = self._ensure_redirect(port)
            if not red.get("ok"):
                self._teardown_locked()
                return {"ok": False,
                        "error": "REDIRECT не установлен: %s"
                                 % red.get("error")}
            self._redirected = True
            log.success("dns_intercept: перехват DNS включён "
                        "(:53 → 127.0.0.1:%d, upstream %s:%d)"
                        % (port, *_upstream()), source="routing")
            return {"ok": True, "port": port}

    def stop(self) -> dict:
        with self._lock:
            self._teardown_locked()
        log.info("dns_intercept: перехват DNS выключен", source="routing")
        return {"ok": True}

    def status(self) -> dict:
        return {
            "enabled": is_enabled(),
            "running": self._running,
            "redirected": self._redirected,
            "port": _port(),
            "upstream": "%s:%d" % _upstream(),
            "rules_watched": len(self._load_rules()),
            "stats": dict(self.stats),
        }

    def sync_rules(self):
        """Сбросить кэш правил (дёргается из domain_rule при apply/remove)."""
        self._rules_at = 0.0

    # ── внутренности ──────────────────────────────────────────────

    def _teardown_locked(self):
        self._running = False
        if self._redirected:
            self._remove_redirect()
            self._redirected = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _recv_loop(self):
        try:
            while self._running and self._sock is not None:
                try:
                    data, addr = self._sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    self._queue.put_nowait((data, addr))
                except queue.Full:
                    self.stats["errors"] += 1
        finally:
            # Цикл умер (ошибка/стоп) — REDIRECT не должен пережить
            # прокси, иначе весь DNS LAN уйдёт в мёртвый порт.
            if self._running:
                log.warning("dns_intercept: приёмный цикл умер — "
                            "снимаю REDIRECT", source="routing")
                with self._lock:
                    self._teardown_locked()

    def _worker(self):
        while self._running:
            try:
                data, addr = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._handle(data, addr)
            except Exception:
                self.stats["errors"] += 1

    def _handle(self, data: bytes, addr):
        self.stats["queries"] += 1
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            up.settimeout(_UPSTREAM_TIMEOUT)
            up.sendto(data, _upstream())
            resp, _ = up.recvfrom(4096)
        except OSError:
            self.stats["errors"] += 1
            return
        finally:
            up.close()
        sock = self._sock
        if sock is not None:
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass
        qname, ips = parse_dns_response(resp)
        if qname and ips:
            self._harvest(qname, ips)

    # ── правила и добавление IP ───────────────────────────────────

    def _load_rules(self):
        now = time.time()
        if now - self._rules_at < _RULES_TTL:
            return self._rules_cache
        out = []
        try:
            from core.routing import domain_rule, storage
            from core.routing.rules import DomainRoutingRule
            sets_state = domain_rule._sets_state_load()
            iproute_state = domain_rule._iproute_state_load()
            for rule in storage.load_rules():
                if not isinstance(rule, DomainRoutingRule) or not rule.enabled:
                    continue
                domains, _cidrs = domain_rule._expand_rule(rule)
                if not domains:
                    continue
                entry = {"id": rule.id, "iface": rule.target_iface,
                         "table": domain_rule._table_id_for(
                             rule.target_iface),
                         "domains": [d.lower().strip(".")
                                     for d in domains]}
                if rule.id in sets_state:
                    kind = sets_state[rule.id]
                    entry["kind"] = kind
                    base = domain_rule._set_name_for(rule.id, kind)
                    entry["set_v4"], entry["set_v6"] = base, base + "6"
                elif rule.id in iproute_state:
                    entry["kind"] = "iproute"
                else:
                    continue    # dnsmasq/NDMS сами видят запросы
                out.append(entry)
        except Exception as e:
            log.warning("dns_intercept: чтение правил: %s" % e,
                        source="routing")
        self._rules_cache = out
        self._rules_at = now
        return out

    def _harvest(self, qname: str, ips):
        for entry in self._load_rules():
            if not any(domain_matches(qname, d)
                       for d in entry["domains"]):
                continue
            self.stats["matched"] += 1
            for ip, fam in ips:
                key = (entry["id"], ip)
                if key in self._seen:
                    continue
                if self._add_ip(entry, ip, fam):
                    self._seen.add(key)
                    self.stats["ips_added"] += 1

    def _add_ip(self, entry, ip: str, fam: str) -> bool:
        kind = entry.get("kind")
        if kind in ("ipset", "nftset"):
            set_name = entry["set_v6"] if fam == "v6" else entry["set_v4"]
            if kind == "nftset":
                from core.routing import nftset_backend
                rc, _o, _e = _run(["nft", "add", "element", "inet",
                                   nftset_backend.TABLE_NAME, set_name,
                                   "{ %s }" % ip])
            else:
                rc, _o, e = _run(["ipset", "add", set_name, ip, "-exist"])
            return rc == 0
        if kind == "iproute":
            from core.routing import domain_rule
            family = "-6" if fam == "v6" else "-4"
            cidr = ip + ("/128" if fam == "v6" else "/32")
            rc, _o, err = _run(["ip", family, "rule", "add", "to", cidr,
                                "lookup", str(entry["table"]),
                                "priority",
                                str(domain_rule.FWMARK_PRIORITY)])
            if rc != 0 and "File exists" not in (err or ""):
                return False
            try:
                state = domain_rule._iproute_state_load()
                entries = list(state.get(entry["id"]) or [])
                if [cidr, family] not in entries:
                    entries.append([cidr, family])
                    state[entry["id"]] = entries
                    domain_rule._iproute_state_save(state)
            except Exception:
                pass
            return True
        return False

    # ── iptables REDIRECT ─────────────────────────────────────────

    def _ensure_redirect(self, port: int) -> dict:
        rc, _o, err = _run(["iptables", "-t", "nat", "-N", NAT_CHAIN])
        if rc != 0 and "already exists" not in (err or "").lower():
            return {"ok": False, "error": err.strip()}
        _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
        rc, _o, err = _run(["iptables", "-t", "nat", "-A", NAT_CHAIN,
                            "-p", "udp", "--dport", "53",
                            "-j", "REDIRECT", "--to-ports", str(port)])
        if rc != 0:
            return {"ok": False, "error": err.strip()}
        # Прыжок в начало PREROUTING (до NDM-цепочек), без дублей.
        for _ in range(8):
            rc_d, _o, _e = _run(["iptables", "-t", "nat", "-D",
                                 "PREROUTING", "-j", NAT_CHAIN])
            if rc_d != 0:
                break
        rc, _o, err = _run(["iptables", "-t", "nat", "-I", "PREROUTING",
                            "1", "-j", NAT_CHAIN])
        if rc != 0:
            return {"ok": False, "error": err.strip()}
        return {"ok": True}

    def _remove_redirect(self):
        for _ in range(8):
            rc, _o, _e = _run(["iptables", "-t", "nat", "-D",
                               "PREROUTING", "-j", NAT_CHAIN])
            if rc != 0:
                break
        _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
        _run(["iptables", "-t", "nat", "-X", NAT_CHAIN])


# ─────────────────────── singleton ──────────────────────────────────

_instance = None
_instance_lock = threading.Lock()


def get_dns_intercept() -> DnsIntercept:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = DnsIntercept()
                atexit.register(_instance.stop)
    return _instance


def set_enabled(enabled: bool) -> dict:
    """Сохранить флаг в настройках и привести состояние (start/stop)."""
    try:
        from core.config_manager import get_config_manager, save_config
        cfg = get_config_manager().load()
        if not isinstance(cfg, dict):
            cfg = {}
        cfg.setdefault("routing", {}).setdefault("dns_intercept", {})
        cfg["routing"]["dns_intercept"]["enabled"] = bool(enabled)
        try:
            save_config()
        except Exception as e:
            log.warning("dns_intercept: save_config: %s" % e,
                        source="routing")
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return apply_enabled_state()


def apply_enabled_state() -> dict:
    """Привести к настройке: enabled → start, иначе stop (boot/переключение)."""
    di = get_dns_intercept()
    if is_enabled():
        return di.start()
    if di._running:
        return di.stop()
    return {"ok": True, "noop": True}
