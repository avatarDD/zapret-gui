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
  1) nat PREROUTING: `udp dport 53 → REDIRECT :<port>` — ловим ЛЮБОЙ
     клиентский DNS (и адресованный роутеру, и hardcoded 8.8.8.8).
     Запросы самого роутера идут через OUTPUT и НЕ перехватываются —
     петли нет. Правило ставится тем бэкендом, который есть на машине:
     iptables (своя цепочка AWG_DNS_INT в nat PREROUTING, Keenetic/
     Entware) или nftables (своя таблица inet awg_dns_int, приоритет
     dstnat-5 — раньше цепочек fw4/NDM). На OpenWrt 22+/fw4 iptables нет
     вовсе, и раньше перехват там не включался совсем (issue #280).
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
import os
import queue
import shutil
import socket
import struct
import threading
import time

from core.log_buffer import log


DEFAULT_PORT = 15353
DEFAULT_UPSTREAM = ("127.0.0.1", 53)
NAT_CHAIN = "AWG_DNS_INT"
NFT_TABLE = "awg_dns_int"
_WORKERS = 4
_RULES_TTL = 60.0        # сек: перечитать домены правил не чаще
_UPSTREAM_TIMEOUT = 4.0
_TCP_IDLE = 10.0         # сек: простой TCP-соединения клиента
_TCP_MAX_CONNS = 32      # одновременных TCP-клиентов
_SEEN_MAX = 20000        # записей «уже добавлено» до чистки
_MAX_MSG = 65535
# Linux: IP_PKTINFO = 8 (в socket-модуле есть не на всех сборках).
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)


def _ensure_sbin_in_path():
    """iptables/nft живут в /sbin и /usr/sbin, которых нет в PATH у
    процесса, запущенного не из root-шелла (см. core/firewall.py)."""
    extra = ["/usr/local/sbin", "/usr/sbin", "/sbin"]
    cur = os.environ.get("PATH", "")
    parts = cur.split(os.pathsep) if cur else []
    added = [d for d in extra if d not in parts and os.path.isdir(d)]
    if added:
        os.environ["PATH"] = os.pathsep.join(parts + added)


_ensure_sbin_in_path()


def _redirect_backend() -> str:
    """Чем ставить REDIRECT: 'iptables', 'nftables' или '' (нечем).

    На OpenWrt 22+/fw4 iptables нет вовсе (issue #280: «REDIRECT не
    установлен: [Errno 2] No such file or directory: 'iptables'»), и весь
    перехват DNS был недоступен. Выбор бэкенда — тот же, что у
    core/firewall.py: учитывается настройка firewall.type, а iptables-шим
    поверх nftables проигрывает нативному nft, чтобы не писать в чужой
    backend через compat-слой.
    """
    fw = ""
    try:
        from core.firewall import FirewallManager
        fw = FirewallManager().detect_fw_type() or ""
    except Exception:
        fw = ""
    # Настройка могла зафиксировать бэкенд, которого на машине нет —
    # тогда правило ставить нечем, и надо взять то, что реально есть.
    if fw == "iptables" and not shutil.which("iptables"):
        fw = ""
    if fw == "nftables" and not shutil.which("nft"):
        fw = ""
    if fw:
        return fw
    if shutil.which("nft"):
        return "nftables"
    if shutil.which("iptables"):
        return "iptables"
    return ""


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


def parse_dns_message(data: bytes) -> dict:
    """
    Разобрать DNS-ответ целиком.

    Возвращает dict:
      qname  — имя вопроса (нижний регистр, без точки);
      qtype  — тип вопроса (1 — A, 28 — AAAA, …);
      names  — все имена цепочки: вопрос, владельцы и цели CNAME
               (правило на CDN-домен срабатывает, когда клиент спросил
               www.apple.com, а ответ пришёл CNAME'ом на akamaiedge.net —
               приём MagiTrickle, у него для этого кеш алиасов);
      ips    — [(ip, 'v4'|'v6', ttl)];
      qend   — смещение конца секции вопросов (для урезанного ответа).
    Пустой dict на любом мусоре — прокси не должен падать.
    """
    try:
        if len(data) < 12:
            return {}
        _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(
            "!HHHHHH", data[:12])
        if not flags & 0x8000:          # не ответ
            return {}
        off = 12
        qname, qtype = "", 0
        for _ in range(qdcount):
            qname, off = _read_name(data, off)
            if off + 4 > len(data):
                return {}
            qtype = struct.unpack("!H", data[off:off + 2])[0]
            off += 4                    # qtype + qclass
        qend = off
        names = []
        if qname:
            names.append(qname.lower().rstrip("."))
        ips = []
        for _ in range(ancount):
            owner, off = _read_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack(
                "!HHIH", data[off:off + 10])
            off += 10
            rstart = off
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:          # A
                ips.append((socket.inet_ntop(socket.AF_INET, rdata), "v4",
                            ttl))
            elif rtype == 28 and rdlen == 16:      # AAAA
                ips.append((socket.inet_ntop(socket.AF_INET6, rdata), "v6",
                            ttl))
            elif rtype == 5:                       # CNAME
                target, _ = _read_name(data, rstart)
                for n in (owner, target):
                    n = n.lower().rstrip(".")
                    if n and n not in names:
                        names.append(n)
        return {"qname": names[0] if names else "", "qtype": qtype,
                "names": names, "ips": ips, "qend": qend}
    except (ValueError, struct.error, OSError):
        return {}


def parse_dns_response(data: bytes):
    """
    Разобрать DNS-ответ: (qname, [(ip, 'v4'|'v6'), ...]).
    Возвращает ("", []) на любом мусоре — прокси не должен падать.
    """
    msg = parse_dns_message(data)
    if not msg:
        return "", []
    return msg["qname"], [(ip, fam) for ip, fam, _ttl in msg["ips"]]


def strip_answers(data: bytes, qend: int) -> bytes:
    """Тот же ответ без записей (NOERROR/NODATA): заголовок + вопрос.

    Нужен для вырезания AAAA: клиент, не получив IPv6-адрес домена из
    маршрута, идёт по IPv4 — в туннель, а не мимо него по IPv6 (туннели
    WARP/AWG часто без IPv6, и v6-нога маршрута пропускается)."""
    if qend <= 12 or qend > len(data):
        return data
    head = bytearray(data[:12])
    head[6:12] = b"\x00" * 6           # ancount = nscount = arcount = 0
    return bytes(head) + data[12:qend]


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


def tcp_enabled() -> bool:
    """Перехватывать ли DNS по TCP (ответы >512 байт с флагом TC,
    клиенты, которые ходят только TCP). По умолчанию — да."""
    return bool(_settings().get("tcp", True))


def drop_aaaa_mode() -> str:
    """'routed' — вырезать AAAA для доменов маршрутов (по умолчанию),
    'off' — отдавать ответ как есть."""
    mode = str(_settings().get("drop_aaaa", "routed") or "").strip().lower()
    return mode if mode in ("routed", "off") else "routed"


def _upstream():
    s = str(_settings().get("upstream", "")).strip()
    if ":" in s:
        host, _, port = s.rpartition(":")
        try:
            return (host or DEFAULT_UPSTREAM[0], int(port))
        except ValueError:
            pass
    return DEFAULT_UPSTREAM


# ─────────────────────── транспорт ──────────────────────────────────

def _pktinfo_dst(ancdata):
    """Адрес назначения запроса из IP_PKTINFO (или None)."""
    for level, ctype, cdata in ancdata or []:
        if level == socket.IPPROTO_IP and ctype == _IP_PKTINFO \
                and len(cdata) >= 12:
            # struct in_pktinfo { int ifindex; in_addr spec_dst; in_addr addr; }
            return socket.inet_ntoa(cdata[8:12])
    return None


def _recv_exact(conn, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _recv_framed(conn) -> bytes:
    """Одно DNS-сообщение по TCP (2 байта длины + тело) или b''."""
    head = _recv_exact(conn, 2)
    if not head:
        return b""
    size = struct.unpack("!H", head)[0]
    if not size:
        return b""
    return _recv_exact(conn, size)


def _upstream_udp(query: bytes) -> bytes:
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        up.settimeout(_UPSTREAM_TIMEOUT)
        up.sendto(query, _upstream())
        resp, _ = up.recvfrom(_MAX_MSG)
        return resp
    finally:
        up.close()


def _upstream_tcp(query: bytes) -> bytes:
    up = socket.create_connection(_upstream(), timeout=_UPSTREAM_TIMEOUT)
    try:
        up.sendall(struct.pack("!H", len(query)) + query)
        return _recv_framed(up)
    finally:
        up.close()


# ─────────────────────── прокси ─────────────────────────────────────

class DnsIntercept:

    def __init__(self):
        self._lock = threading.Lock()
        self._sock = None
        self._tcp_sock = None
        self._pktinfo = False
        self._tcp_slots = threading.BoundedSemaphore(_TCP_MAX_CONNS)
        self._queue = None
        self._threads = []
        self._running = False
        self._redirected = False
        self._backend = ""           # чем поставлен REDIRECT: iptables|nftables
        self._rules_cache = []       # [{id, kind, set_v4, set_v6, table,
        #                              iface, domains}], kind: ipset|nftset|iproute
        self._rules_at = 0.0
        # (rule_id, ip) → когда истекает запись в наборе (time.time()).
        # Пока до срока далеко — не дёргаем ipset/nft; ближе к концу —
        # продлеваем. Раньше это было вечное множество: росло без
        # предела и не давало продлить истекающую запись.
        self._seen = {}
        self._seen_lock = threading.Lock()
        self.stats = {"queries": 0, "matched": 0, "ips_added": 0,
                      "errors": 0, "tcp": 0, "aaaa_dropped": 0}

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
            # IP_PKTINFO: адрес, на который пришёл запрос, — ответ уходит
            # ровно с него (на роутере с несколькими адресами ответ с
            # «чужого» src клиент отбросит). Приём MagiTrickle.
            try:
                sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
                self._pktinfo = hasattr(sock, "recvmsg")
            except OSError:
                self._pktinfo = False
            self._sock = sock
            self._tcp_sock = None
            if tcp_enabled():
                try:
                    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                     1)
                    tsock.bind(("0.0.0.0", port))
                    tsock.listen(16)
                    tsock.settimeout(1.0)
                    self._tcp_sock = tsock
                except OSError as e:
                    log.warning("dns_intercept: TCP :%d не занят (%s) — "
                                "перехват только по UDP" % (port, e),
                                source="routing")
            self._queue = queue.Queue(maxsize=256)
            self._running = True
            self._threads = []
            t = threading.Thread(target=self._recv_loop, args=(sock,),
                                 daemon=True, name="dns-int-recv")
            t.start()
            self._threads.append(t)
            for i in range(_WORKERS):
                w = threading.Thread(target=self._worker, daemon=True,
                                     name="dns-int-w%d" % i)
                w.start()
                self._threads.append(w)
            if self._tcp_sock is not None:
                ta = threading.Thread(target=self._tcp_accept_loop,
                                      args=(self._tcp_sock,), daemon=True,
                                      name="dns-int-tcp")
                ta.start()
                self._threads.append(ta)
            # REDIRECT — только когда сокет реально слушает.
            red = self._ensure_redirect(port, tcp=self._tcp_sock is not None)
            if not red.get("ok"):
                self._teardown_locked()
                return {"ok": False,
                        "error": "REDIRECT не установлен: %s"
                                 % red.get("error")}
            self._redirected = True
            self._backend = red.get("backend", "")
            log.success("dns_intercept: перехват DNS включён "
                        "(:53 %s → 127.0.0.1:%d, upstream %s:%d, %s)"
                        % ("udp+tcp" if self._tcp_sock else "udp", port,
                           *_upstream(), self._backend or "?"),
                        source="routing")
            return {"ok": True, "port": port, "backend": self._backend}

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
            "backend": self._backend or _redirect_backend(),
            "port": _port(),
            "upstream": "%s:%d" % _upstream(),
            "tcp": self._tcp_sock is not None,
            "drop_aaaa": drop_aaaa_mode(),
            "rules_watched": len(self._load_rules()),
            "stats": dict(self.stats),
        }

    def sync_rules(self):
        """Сбросить кэш правил (дёргается из domain_rule при apply/remove).

        Заодно забываем «уже добавлено»: правило могли переприменить с
        пересозданием набора, и IP, которые кладёт только перехват
        (шаблоны), иначе ждали бы полсрока до повторного добавления."""
        self._rules_at = 0.0
        with self._seen_lock:
            self._seen.clear()

    # ── внутренности ──────────────────────────────────────────────

    def _teardown_locked(self):
        self._running = False
        if self._redirected:
            self._remove_redirect()
            self._redirected = False
            self._backend = ""
        for attr in ("_sock", "_tcp_sock"):
            sock = getattr(self, attr)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
                setattr(self, attr, None)

    def _recv_loop(self, sock):
        """Приём UDP. Поток привязан к СВОЕМУ сокету: после stop()+start()
        (смена tcp/порта) старый поток, проснувшись на закрытом сокете, не
        должен сносить перехват, поднятый уже заново."""
        try:
            while self._running and self._sock is sock:
                try:
                    if self._pktinfo:
                        data, anc, _fl, addr = sock.recvmsg(
                            _MAX_MSG, socket.CMSG_SPACE(12))
                        local = _pktinfo_dst(anc)
                    else:
                        data, addr = sock.recvfrom(_MAX_MSG)
                        local = None
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    self._queue.put_nowait((data, addr, local))
                except queue.Full:
                    self.stats["errors"] += 1
        finally:
            # Цикл умер (ошибка/стоп) — REDIRECT не должен пережить
            # прокси, иначе весь DNS LAN уйдёт в мёртвый порт.
            self._loop_died(sock, "_sock", "приёмный цикл")

    def _loop_died(self, sock, attr: str, what: str):
        with self._lock:
            if self._running and getattr(self, attr) is sock:
                log.warning("dns_intercept: %s умер — снимаю REDIRECT"
                            % what, source="routing")
                self._teardown_locked()

    def _worker(self):
        while self._running:
            try:
                data, addr, local = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._handle(data, addr, local)
            except Exception:
                self.stats["errors"] += 1

    def _handle(self, data: bytes, addr, local=None):
        resp = self._process(data, _upstream_udp)
        sock = self._sock
        if resp is None or sock is None:
            return
        try:
            if local and self._pktinfo:
                # in_pktinfo: ifindex=0 (по маршруту), spec_dst = адрес,
                # на который пришёл запрос.
                cmsg = struct.pack("=i4s4s", 0, socket.inet_aton(local),
                                   b"\x00" * 4)
                sock.sendmsg([resp], [(socket.IPPROTO_IP, _IP_PKTINFO,
                                       cmsg)], 0, addr)
            else:
                sock.sendto(resp, addr)
        except OSError:
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass

    def _process(self, query: bytes, transport):
        """Запрос клиента → ответ клиенту (или None). Общий для UDP/TCP:
        переслать upstream, собрать IP для правил, вырезать AAAA."""
        self.stats["queries"] += 1
        try:
            resp = transport(query)
        except OSError:
            self.stats["errors"] += 1
            return None
        if not resp:
            return None
        msg = parse_dns_message(resp)
        if not msg or not msg.get("names"):
            return resp
        try:
            matched = self._harvest(msg["names"], msg["ips"])
        except Exception as e:
            # Сбор IP — побочная задача: клиент ответ получить обязан.
            self.stats["errors"] += 1
            log.debug("dns_intercept: harvest: %s" % e, source="routing")
            return resp
        if matched and msg.get("qtype") == 28 and \
                drop_aaaa_mode() == "routed":
            self.stats["aaaa_dropped"] += 1
            return strip_answers(resp, msg["qend"])
        return resp

    # ── TCP ───────────────────────────────────────────────────────

    def _tcp_accept_loop(self, lsock):
        try:
            while self._running and self._tcp_sock is lsock:
                try:
                    conn, _addr = lsock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not self._tcp_slots.acquire(blocking=False):
                    conn.close()            # перегруз — клиент повторит
                    self.stats["errors"] += 1
                    continue
                t = threading.Thread(target=self._tcp_client,
                                     args=(conn,), daemon=True,
                                     name="dns-int-tcpc")
                t.start()
        finally:
            self._loop_died(lsock, "_tcp_sock", "TCP-приём")

    def _tcp_client(self, conn):
        """Один клиент: запросы с префиксом длины, по очереди, пока не
        закроет соединение или не замолчит на _TCP_IDLE секунд."""
        try:
            conn.settimeout(_TCP_IDLE)
            while self._running:
                query = _recv_framed(conn)
                if not query:
                    break
                self.stats["tcp"] += 1
                resp = self._process(query, _upstream_tcp)
                if resp is None:
                    break
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._tcp_slots.release()

    # ── правила и добавление IP ───────────────────────────────────

    def _load_rules(self):
        now = time.time()
        if now - self._rules_at < _RULES_TTL:
            return self._rules_cache
        out = []
        try:
            from core.routing import domain_match, domain_rule, storage
            from core.routing.rules import DomainRoutingRule
            sets_state = domain_rule._sets_state_load()
            iproute_state = domain_rule._iproute_state_load()
            dnsmasq_kind = None
            for rule in storage.load_rules():
                if not isinstance(rule, DomainRoutingRule) or not rule.enabled:
                    continue
                domains, _cidrs = domain_rule._expand_rule(rule)
                # Шаблоны (wildcard/regex) заранее не разрезолвить —
                # они работают только здесь, по живым ответам.
                matcher = domain_match.Matcher(
                    list(domains) + domain_match.patterns(rule.domains))
                if not matcher:
                    continue
                entry = {"id": rule.id, "iface": rule.target_iface,
                         "table": domain_rule._table_id_for(
                             rule.target_iface),
                         "matcher": matcher}
                if rule.id in sets_state:
                    kind = sets_state[rule.id]
                elif rule.id in iproute_state:
                    kind = "iproute"
                else:
                    # dnsmasq/NDMS сами кладут IP обычных доменов: перехват
                    # для них только вырезает AAAA, а IP кладёт лишь для
                    # шаблонов (их dnsmasq не понимает) — в набор
                    # dnsmasq-пути и бессрочно, как сам dnsmasq.
                    pats = domain_match.patterns(rule.domains)
                    entry["add_matcher"] = domain_match.Matcher(pats)
                    entry["ttl"] = False
                    kind = ""
                    if pats:
                        if dnsmasq_kind is None:
                            _b, dnsmasq_kind = domain_rule._detect_backend()
                        kind = dnsmasq_kind or ""
                entry["kind"] = kind
                if kind in ("ipset", "nftset"):
                    base = domain_rule._set_name_for(rule.id, kind)
                    entry["set_v4"], entry["set_v6"] = base, base + "6"
                out.append(entry)
        except Exception as e:
            log.warning("dns_intercept: чтение правил: %s" % e,
                        source="routing")
        self._rules_cache = out
        self._rules_at = now
        return out

    def _harvest(self, names, ips) -> bool:
        """Положить IP ответа в наборы правил, под которые попало любое
        имя цепочки. True — ответ про домен маршрута."""
        from core.routing import set_ttl
        if isinstance(names, str):
            names = [names]
        matched = False
        now = time.time()
        for entry in self._load_rules():
            if not entry["matcher"].match_any(names):
                continue
            matched = True
            self.stats["matched"] += 1
            adder = entry.get("add_matcher")
            if adder is not None and not adder.match_any(names):
                continue                    # IP кладёт dnsmasq/NDMS
            if not entry.get("kind"):
                continue
            for item in ips:
                ip, fam = item[0], item[1]
                dns_ttl = item[2] if len(item) > 2 else None
                key = (entry["id"], ip)
                if entry.get("kind") == "iproute" or \
                        entry.get("ttl") is False:
                    timeout = 0             # policy-db / набор dnsmasq
                else:
                    timeout = set_ttl.timeout_for(dns_ttl)
                with self._seen_lock:
                    expires = self._seen.get(key)
                if expires is not None and (
                        timeout == 0 or expires - now > timeout / 2):
                    continue                # свежая — продлевать рано
                if self._add_ip(entry, ip, fam, timeout):
                    self._remember(key, now + (timeout or 86400), now)
                    self.stats["ips_added"] += 1
        return matched

    def _remember(self, key, expires: float, now: float):
        with self._seen_lock:
            if len(self._seen) >= _SEEN_MAX:
                self._seen = {k: v for k, v in self._seen.items()
                              if v > now}
                if len(self._seen) >= _SEEN_MAX:
                    self._seen.clear()
            self._seen[key] = expires

    def _add_ip(self, entry, ip: str, fam: str, timeout: int = 0) -> bool:
        kind = entry.get("kind")
        if kind in ("ipset", "nftset"):
            set_name = entry["set_v6"] if fam == "v6" else entry["set_v4"]
            if kind == "nftset":
                from core.routing import nftset_backend
                return nftset_backend.add_entry(set_name, ip, timeout)
            from core.routing import ipset_backend
            return ipset_backend.add_entry(set_name, ip, timeout)
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

    # ── REDIRECT: iptables или nftables ───────────────────────────

    def _ensure_redirect(self, port: int, tcp: bool = False) -> dict:
        backend = _redirect_backend()
        if not backend:
            return {"ok": False,
                    "error": "не найден ни iptables, ни nft — "
                             "перехват :53 ставить нечем"}
        protos = ("udp", "tcp") if tcp else ("udp",)
        if backend == "nftables":
            return self._ensure_redirect_nft(port, protos)
        return self._ensure_redirect_ipt(port, protos)

    def reassert(self) -> dict:
        """Вернуть REDIRECT, если его снесли извне (NDMS перезаписал
        netfilter — хук netfilter.d зовёт reapply). Прокси жив — правило
        ставим заново; не жив — ничего не делаем."""
        with self._lock:
            if not self._running or not self._redirected:
                return {"ok": True, "noop": True}
            red = self._ensure_redirect(_port(),
                                        tcp=self._tcp_sock is not None)
            return red

    def _remove_redirect(self):
        # Снимаем ОБА варианта: бэкенд мог смениться (доустановили
        # iptables) между start() и stop(), и оставленное правило увело бы
        # весь DNS LAN в мёртвый порт.
        if shutil.which("iptables"):
            self._remove_redirect_ipt()
        if shutil.which("nft"):
            self._remove_redirect_nft()

    # ── iptables ──────────────────────────────────────────────────

    def _ensure_redirect_ipt(self, port: int, protos=("udp",)) -> dict:
        rc, _o, err = _run(["iptables", "-t", "nat", "-N", NAT_CHAIN])
        if rc != 0 and "already exists" not in (err or "").lower():
            return {"ok": False, "error": err.strip()}
        _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
        for proto in protos:
            rc, _o, err = _run(["iptables", "-t", "nat", "-A", NAT_CHAIN,
                                "-p", proto, "--dport", "53",
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
        return {"ok": True, "backend": "iptables"}

    def _remove_redirect_ipt(self):
        for _ in range(8):
            rc, _o, _e = _run(["iptables", "-t", "nat", "-D",
                               "PREROUTING", "-j", NAT_CHAIN])
            if rc != 0:
                break
        _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
        _run(["iptables", "-t", "nat", "-X", NAT_CHAIN])

    # ── nftables ──────────────────────────────────────────────────

    def _ensure_redirect_nft(self, port: int, protos=("udp",)) -> dict:
        """То же правило в nftables — своей таблицей, чужих не трогаем.

        Приоритет dstnat-5: раньше цепочки fw4/NDM, чтобы поймать DNS до
        чужих redirect'ов (аналог `-I PREROUTING 1` в iptables-пути).
        Таблица inet, но правило только для IPv4 (`meta nfproto ipv4`):
        прокси слушает IPv4-сокет, и IPv6-запрос, уведённый на него,
        остался бы без ответа — у IPv6-клиентов пропадал бы DNS.
        """
        # Пересоздаём таблицу целиком: правило одно, идемпотентность
        # дешевле проверять сносом (иначе после смены порта в настройках
        # осталось бы два redirect'а, и выигрывал бы старый).
        self._remove_redirect_nft()
        cmds = [
            ["nft", "add", "table", "inet", NFT_TABLE],
            ["nft", "add", "chain", "inet", NFT_TABLE, "prerouting",
             "{ type nat hook prerouting priority dstnat - 5 ; policy accept ; }"],
        ]
        cmds += [["nft", "add", "rule", "inet", NFT_TABLE, "prerouting",
                  "meta", "nfproto", "ipv4", proto, "dport", "53",
                  "redirect", "to", ":%d" % port] for proto in protos]
        for cmd in cmds:
            rc, _o, err = _run(cmd)
            if rc != 0:
                self._remove_redirect_nft()
                return {"ok": False,
                        "error": "nft: %s" % ((err or "").strip()
                                              or "код %d" % rc)}
        return {"ok": True, "backend": "nftables"}

    def _remove_redirect_nft(self):
        _run(["nft", "delete", "table", "inet", NFT_TABLE])


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
        cfg = get_config_manager().current()
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


def set_options(drop_aaaa=None, tcp=None) -> dict:
    """Сохранить drop_aaaa ('routed'|'off') и tcp (bool). Смена tcp у
    работающего перехвата — перезапуск (сокет и правило REDIRECT)."""
    from core.config_manager import get_config_manager, save_config
    cfg = get_config_manager().current()
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "настройки недоступны"}
    sec = cfg.setdefault("routing", {}).setdefault("dns_intercept", {})
    restart = False
    if drop_aaaa is not None:
        mode = str(drop_aaaa).strip().lower()
        if mode not in ("routed", "off"):
            return {"ok": False, "error": "drop_aaaa: routed | off"}
        sec["drop_aaaa"] = mode
    if tcp is not None and bool(tcp) != bool(sec.get("tcp", True)):
        sec["tcp"] = bool(tcp)
        restart = True
    save_config()
    di = get_dns_intercept()
    if restart and di._running:
        di.stop()
        return di.start()
    return {"ok": True}


def apply_enabled_state() -> dict:
    """Привести к настройке: enabled → start, иначе stop (boot/переключение)."""
    di = get_dns_intercept()
    if is_enabled():
        return di.start()
    if di._running:
        return di.stop()
    return {"ok": True, "noop": True}
