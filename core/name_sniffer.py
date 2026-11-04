# core/name_sniffer.py
"""
Имена серверов на роутере: DNS-ответы, SNI и Host — пассивно, всё время.

## Зачем

Режим «Авто» geneva видит соединения через conntrack, а там только
адреса. Имя сайта — ключ ``web:<домен>``, проба загрузкой страницы и
подпись в списке — берётся из карты «IP → имя» детектора блокировок
(``core.block_detector.remember_names``). На ПК AutoTuner видит весь
трафик захватом и знает имя каждого TLS-соединения. На роутере карта
заполнялась плохо:

* на OpenWrt dnsmasq пишет в syslog, а не в ``/var/log/dnsmasq.log``, и
  без ``log-queries`` не пишет ответы вовсе — источник ``af_packet``;
* сниффер ``af_packet`` детектора слушал 1 секунду раз в 10–15 с, то есть
  ловил малую долю ответов, разбирал только Ethernet + IPv4 (на
  ``pppoe-wan`` и туннелях заголовка Ethernet нет) и не видел SNI;
* браузеры с DoH/DoT не шлют DNS открыто: имя есть только в SNI, а
  захват tcpdump для SNI шёл по одному подозрительному сервису и только
  при установленном tcpdump.

Поэтому большая часть соединений становилась ``ep:tcp:<ip>:443`` —
«TCP ip:port» в списке, без пробы страницей и без группировки по сайту.

## Как

Один сокет ``AF_PACKET``/``SOCK_DGRAM`` (данные с IP-заголовка на любом
интерфейсе: Ethernet, VLAN, PPP, tun) с классическим BPF-фильтром в
ядре. В Python приходят только:

* UDP с исходным портом 53 (DNS-ответы, IPv4 и IPv6) — A/AAAA → имя
  вопроса;
* TCP к портам 443 и 80, у которых данные начинаются с ``0x16``
  (TLS handshake) или с ``G``/``P``/``H`` (GET, POST/PUT/PATCH, HEAD) —
  SNI ClientHello и ``Host`` → адрес сервера.

Остальной трафик фильтр отбрасывает в ядре, поэтому нагрузка на роутер —
десятки пакетов в секунду, а не весь поток. Ничего не пишется на диск и
никуда не отправляется: только карта «IP → имя» в памяти (на сутки, как
у детектора). QUIC Initial не разбирается (нужен AES, его нет в stdlib):
имя QUIC — из DNS. Фрагменты IPv4 и цепочки заголовков IPv6 фильтр
пропускает мимо.

Нет прав на ``AF_PACKET`` (не root, нет ``CAP_NET_RAW``) — сборщик не
стартует и пишет одну строку в журнал; режим работает, как раньше.
"""

from __future__ import annotations

import array
import ipaddress
import socket
import struct
import threading
import time

from core.log_buffer import log

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
SNAPLEN = 2048            # ClientHello с ключом ML-KEM — до ~1.8 КБ
RECV_TIMEOUT = 1.0
WEB_PORTS = (443, 80)

# ───────────────────────────── BPF ──────────────────────────────────
# Классический BPF (linux/filter.h): (code, jt, jf, k).
_LDB_ABS, _LDH_ABS = 0x30, 0x28
_LDB_IND, _LDH_IND = 0x50, 0x48
_LDX_MSH = 0xb1                       # X = 4 * ([k] & 0xf)
_RSH_K, _AND_K, _ADD_K, _ADD_X = 0x74, 0x54, 0x04, 0x0c
_TAX = 0x07
_JA, _JEQ_K, _JSET_K = 0x05, 0x15, 0x45
_RET_K = 0x06


def _assemble(prog) -> list:
    """Метки → смещения. Элемент — ``"метка:"`` или
    ``(code, jt, jf, k)``, где jt/jf/k у переходов — имена меток
    (``None`` — следующая инструкция)."""
    labels, body = {}, []
    for ins in prog:
        if isinstance(ins, str):
            labels[ins.rstrip(":")] = len(body)
        else:
            body.append(ins)
    def rel(i, target):
        if target is None:
            return 0
        off = labels[target] - (i + 1)
        if off < 0:
            raise ValueError("BPF: переход назад")
        return off

    out = []
    for i, (code, jt, jf, k) in enumerate(body):
        if code == _JA:
            out.append((code, 0, 0, rel(i, k)))
        elif code in (_JEQ_K, _JSET_K):
            out.append((code, rel(i, jt), rel(i, jf), k))
        else:
            out.append((code, 0, 0, k))
    for code, jt, jf, _k in out:
        if jt > 255 or jf > 255:
            raise ValueError("BPF: переход дальше 255")
    return out


def bpf_program() -> list:
    """Фильтр: DNS-ответы и первые байты запросов к 443/80 (см. модуль).
    Смещения — от IP-заголовка (``SOCK_DGRAM``)."""
    return _assemble([
        (_LDB_ABS, None, None, 0),
        (_RSH_K, None, None, 4),
        (_JEQ_K, "v4", None, 4),
        (_JEQ_K, "v6", "drop", 6),
        "v4:",
        (_LDH_ABS, None, None, 6),
        (_JSET_K, "drop", None, 0x1fff),          # не первый фрагмент
        (_LDB_ABS, None, None, 9),
        (_JEQ_K, "v4udp", None, 17),
        (_JEQ_K, "v4tcp", "drop", 6),
        "v4udp:",
        (_LDX_MSH, None, None, 0),
        (_LDH_IND, None, None, 0),                # UDP sport
        (_JEQ_K, "accept", "drop", 53),
        "v4tcp:",
        (_LDX_MSH, None, None, 0),
        (_LDH_IND, None, None, 2),                # TCP dport
        (_JEQ_K, "v4data", None, 443),
        (_JEQ_K, "v4data", "drop", 80),
        "v4data:",
        (_LDB_IND, None, None, 12),               # data offset
        (_RSH_K, None, None, 2),
        (_AND_K, None, None, 0x3c),
        (_ADD_X, None, None, 0),
        (_TAX, None, None, 0),
        (_LDB_IND, None, None, 0),                # первый байт данных
        (_JA, None, None, "payload"),
        "v6:",
        (_LDB_ABS, None, None, 6),                # next header
        (_JEQ_K, "v6udp", None, 17),
        (_JEQ_K, "v6tcp", "drop", 6),
        "v6udp:",
        (_LDH_ABS, None, None, 40),
        (_JEQ_K, "accept", "drop", 53),
        "v6tcp:",
        (_LDH_ABS, None, None, 42),
        (_JEQ_K, "v6data", None, 443),
        (_JEQ_K, "v6data", "drop", 80),
        "v6data:",
        (_LDB_ABS, None, None, 52),
        (_RSH_K, None, None, 2),
        (_AND_K, None, None, 0x3c),
        (_ADD_K, None, None, 40),
        (_TAX, None, None, 0),
        (_LDB_IND, None, None, 0),
        "payload:",
        (_JEQ_K, "accept", None, 0x16),
        (_JEQ_K, "accept", None, ord("G")),
        (_JEQ_K, "accept", None, ord("P")),
        (_JEQ_K, "accept", "drop", ord("H")),
        "accept:",
        (_RET_K, None, None, SNAPLEN),
        "drop:",
        (_RET_K, None, None, 0),
    ])


def attach_filter(sock, prog) -> None:
    """``SO_ATTACH_FILTER`` без ctypes: адрес массива — ``buffer_info``
    (на OpenWrt ctypes — отдельный пакет)."""
    raw = b"".join(struct.pack("=HBBI", c, jt, jf, k)
                   for c, jt, jf, k in prog)
    buf = array.array("B", raw)
    addr, _n = buf.buffer_info()
    fprog = struct.pack("@HP", len(prog), addr)
    # ядро копирует программу в setsockopt: buf нужен только до него
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


# ───────────────────────────── разбор ───────────────────────────────

def parse_packet(pkt: bytes) -> list:
    """Пакет с IP-заголовка → ``[(ip сервера, имя), …]``.

    DNS-ответ — пары из A/AAAA; TLS ClientHello — SNI и адрес
    назначения; HTTP-запрос — ``Host``. Любая неожиданность — пустой
    список: фильтр в ядре грубый, а сюда может прийти что угодно.
    """
    try:
        if len(pkt) < 20:
            return []
        ver = pkt[0] >> 4
        if ver == 4:
            ihl = (pkt[0] & 0x0F) * 4
            if ihl < 20 or len(pkt) < ihl + 8:
                return []
            if struct.unpack("!H", pkt[6:8])[0] & 0x1FFF:
                return []
            proto = pkt[9]
            dst = socket.inet_ntop(socket.AF_INET, pkt[16:20])
            l4 = pkt[ihl:]
        elif ver == 6:
            if len(pkt) < 48:
                return []
            proto = pkt[6]
            dst = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
            l4 = pkt[40:]
        else:
            return []
        if proto == 17:
            sport = struct.unpack("!H", l4[0:2])[0]
            if sport != 53:
                return []
            from core.block_detector import parse_dns_answers
            return parse_dns_answers(l4[8:])
        if proto != 6 or len(l4) < 20:
            return []
        dport = struct.unpack("!H", l4[2:4])[0]
        if dport not in WEB_PORTS:
            return []
        doff = (l4[12] >> 4) * 4
        data = l4[doff:]
        if not data:
            return []
        from core.pcap_reader import http_host, tls_sni
        if data[0] == 0x16:
            name = tls_sni(data)
        else:
            name = http_host(data)[0]
            # Host может быть с портом: example.org:8080
            if name and not name.startswith("["):
                name = name.rsplit(":", 1)[0] if name.count(":") == 1 \
                    else name
        name = (name or "").strip().strip(".").lower()
        if not name or not _is_hostname(name):
            return []
        return [(dst, name)]
    except (IndexError, struct.error, ValueError, OSError):
        return []


def _is_hostname(name: str) -> bool:
    if len(name) > 253 or "." not in name:
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass
    return all(ch.isalnum() or ch in "-._" for ch in name)


# ───────────────────────────── сборщик ──────────────────────────────

class NameSniffer:
    """Фоновый сборщик имён. ``start``/``stop`` — с подсчётом
    владельцев: «Авто» и другие потребители не гасят друг друга."""

    def __init__(self, *, remember=None, opener=None):
        self._remember = remember
        self._opener = opener
        self._lock = threading.Lock()
        self._owners = set()
        self._thread = None
        self._stop = threading.Event()
        self._warned = False
        self.stats = {"packets": 0, "names": 0, "error": "",
                      "started": 0.0}

    @property
    def running(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive()

    def start(self, owner: str = "auto") -> bool:
        with self._lock:
            self._owners.add(owner)
            if self.running:
                return True
            try:
                sock = self._open()
            except OSError as e:
                self.stats["error"] = str(e)
                if not self._warned:
                    self._warned = True
                    log.warning("имена серверов: сниффер не запущен (%s) — "
                                "имена только из журналов DNS" % e,
                                source="geneva")
                return False
            self._stop = threading.Event()
            self.stats.update(error="", started=time.time())
            self._thread = threading.Thread(
                target=self._loop, args=(sock, self._stop), daemon=True,
                name="name-sniffer")
            self._thread.start()
            return True

    def stop(self, owner: str = "auto") -> None:
        with self._lock:
            self._owners.discard(owner)
            if self._owners:
                return
            self._stop.set()
            t = self._thread
            self._thread = None
        if t is not None and t is not threading.current_thread():
            t.join(RECV_TIMEOUT + 1)

    def _open(self):
        if self._opener is not None:
            return self._opener()
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                             socket.htons(ETH_P_ALL))
        try:
            attach_filter(sock, bpf_program())
            sock.settimeout(RECV_TIMEOUT)
        except OSError:
            sock.close()
            raise
        return sock

    def _loop(self, sock, stop) -> None:
        remember = self._remember
        if remember is None:
            from core.block_detector import remember_names
            remember = remember_names
        try:
            while not stop.is_set():
                try:
                    pkt = sock.recv(SNAPLEN)
                except socket.timeout:
                    continue
                except OSError as e:
                    self.stats["error"] = str(e)
                    break
                self.stats["packets"] += 1
                pairs = parse_packet(pkt)
                if pairs:
                    try:
                        self.stats["names"] += remember(pairs) or 0
                    except Exception as e:          # noqa: BLE001
                        log.debug("имена серверов: %s" % e, source="geneva")
        finally:
            try:
                sock.close()
            except OSError:
                pass


_sniffer = None
_sniffer_lock = threading.Lock()


def get_name_sniffer() -> NameSniffer:
    global _sniffer
    with _sniffer_lock:
        if _sniffer is None:
            _sniffer = NameSniffer()
        return _sniffer
