# core/download_transport.py
"""
Транспорт скачивания — «через что» качать файлы из интернета.

Нашей аудитории GitHub часто недоступен напрямую, но на роутере уже
может работать обход: AWG-туннель, sing-box или mihomo с локальным
прокси-портом. Этот модуль позволяет пустить исходящий HTTP(S)-запрос
GUI (скачивание релизов/манифестов, в перспективе — обновление списков
и подписок, задача 7 роадмапа) через одно из этих средств.

Спека транспорта — строка:
    "" | "direct"                — напрямую (по умолчанию);
    "awg" | "awg:<iface>"        — через AWG/WG-интерфейс: сокет
                                   привязывается к устройству
                                   (SO_BINDTODEVICE, нужен root; фолбэк —
                                   bind на IPv4-адрес интерфейса);
    "singbox" | "singbox:<name>" — через mixed/http-inbound ЗАПУЩЕННОГО
                                   sing-box конфига <name>;
    "mihomo" | "mihomo:<name>"   — через mixed-port/port ЗАПУЩЕННОГО
                                   mihomo-конфига <name>.

Без аргумента берётся первый доступный кандидат данного типа.

Ограничения (осознанные):
  - для awg-транспорта DNS-резолв имени идёт через системный resolver
    (не через туннель) — утечка имени, но скачивание работает;
  - для singbox/mihomo прокси-протокол — HTTP CONNECT (mixed/http
    inbound); socks-only inbound'ы и inbound'ы с авторизацией
    пропускаются (urllib не умеет socks, а пароль нам неоткуда взять);
  - нативные Keenetic-WG интерфейсы (Wireguard0..N) в кандидатах не
    перечисляются (их обнаружение требует NDMS-запросов), но явное
    "awg:Wireguard0" сработает, если интерфейс существует в системе.

API:
    parse_transport(spec)   → (kind, arg)
    list_transports()       → {"ok", "transports": [{id,kind,label,...}]}
    resolve_transport(spec) → {"ok", "kind", ...} | {"ok": False, "error"}
    build_opener(spec)      → urllib opener | None (direct);
                              RuntimeError если транспорт недоступен
    urlopen_via(url, transport=..., timeout=..., headers=...) → response
"""

import http.client
import json
import os
import socket
import ssl
import urllib.request

from core.log_buffer import log


DEFAULT_TIMEOUT = 30


# ─────── разбор спеки ───────

def parse_transport(spec):
    """'awg:wg0' → ('awg', 'wg0'); '' / 'direct' → ('direct', '')."""
    s = str(spec or "").strip()
    if not s or s.lower() == "direct":
        return ("direct", "")
    kind, _, arg = s.partition(":")
    kind = kind.strip().lower()
    arg = arg.strip()
    if kind in ("awg", "wg", "wireguard"):
        return ("awg", arg)
    if kind in ("singbox", "sing-box"):
        return ("singbox", arg)
    if kind == "mihomo":
        return ("mihomo", arg)
    return ("unknown", s)


# ─────── чистые функции: где у движка локальный прокси ───────

def _local_host(listen) -> str:
    """Адрес, по которому САМА машина может подключиться к inbound'у
    с данным listen-адресом ('' / 0.0.0.0 / :: / 127.0.0.1 → loopback,
    конкретный адрес — как есть)."""
    s = str(listen or "").strip().strip("[]")
    if s in ("", "0.0.0.0", "::", "127.0.0.1", "localhost"):
        return "127.0.0.1"
    return s


def singbox_local_proxy(cfg: dict):
    """
    {"host","port","type"} первого пригодного inbound'а sing-box-конфига
    (mixed/http без авторизации), либо None. Чистая функция.
    """
    if not isinstance(cfg, dict):
        return None
    for ib in (cfg.get("inbounds") or []):
        if not isinstance(ib, dict):
            continue
        if (ib.get("type") or "").lower() not in ("mixed", "http"):
            continue
        if ib.get("users"):           # авторизация — пароль нам неизвестен
            continue
        try:
            port = int(ib.get("listen_port") or 0)
        except (TypeError, ValueError):
            continue
        if not (0 < port < 65536):
            continue
        return {"host": _local_host(ib.get("listen")), "port": port,
                "type": (ib.get("type") or "").lower()}
    return None


def mihomo_local_proxy(cfg: dict):
    """
    {"host","port","type"} локального прокси mihomo-конфига
    (mixed-port, затем port=http), либо None. mihomo принимает
    соединения с loopback независимо от allow-lan. Чистая функция.
    """
    if not isinstance(cfg, dict):
        return None
    if cfg.get("authentication"):     # глобальная авторизация прокси
        return None
    for key, typ in (("mixed-port", "mixed"), ("port", "http")):
        try:
            port = int(cfg.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if 0 < port < 65536:
            return {"host": "127.0.0.1", "port": port, "type": typ}
    return None


# ─────── кандидаты по движкам ───────

def _awg_candidates() -> list:
    out = []
    try:
        from core.awg_manager import get_awg_manager
        # _wg_interfaces — лёгкий способ (awg show interfaces / ip link),
        # без пер-интерфейсного status и без NDMS-запросов.
        for ifname in get_awg_manager()._wg_interfaces():
            if not ifname:
                continue
            out.append({
                "id":     "awg:%s" % ifname,
                "kind":   "awg",
                "device": ifname,
                "label":  "AWG: %s" % ifname,
                "detail": "исходящие соединения через интерфейс %s" % ifname,
            })
    except Exception as e:
        log.debug("download_transport: awg-кандидаты: %s" % e,
                  source="download_transport")
    return out


def _singbox_candidates() -> list:
    out = []
    try:
        from core.singbox_manager import get_singbox_manager
        mgr = get_singbox_manager()
        for c in mgr.list_configs():
            if not c.get("running"):
                continue
            name = c.get("name") or ""
            res = mgr.get_config(name)
            if not res.get("ok"):
                continue
            cfg = res.get("parsed")
            if not isinstance(cfg, dict):
                try:
                    cfg = json.loads(res.get("text") or "")
                except ValueError:
                    continue
            p = singbox_local_proxy(cfg)
            if not p:
                continue
            out.append({
                "id":    "singbox:%s" % name,
                "kind":  "singbox",
                "name":  name,
                "proxy": "http://%s:%d" % (p["host"], p["port"]),
                "label": "sing-box: %s" % name,
                "detail": "%s-inbound %s:%d" % (p["type"], p["host"], p["port"]),
            })
    except Exception as e:
        log.debug("download_transport: singbox-кандидаты: %s" % e,
                  source="download_transport")
    return out


def _mihomo_candidates() -> list:
    out = []
    try:
        from core.mihomo_manager import get_mihomo_manager
        from core.clash_yaml import parse_yaml
        mgr = get_mihomo_manager()
        for c in mgr.list_configs():
            if not c.get("running"):
                continue
            name = c.get("name") or ""
            res = mgr.get_config(name)
            if not res.get("ok"):
                continue
            try:
                cfg = parse_yaml(res.get("text") or "")
            except Exception:
                continue
            p = mihomo_local_proxy(cfg if isinstance(cfg, dict) else {})
            if not p:
                continue
            out.append({
                "id":    "mihomo:%s" % name,
                "kind":  "mihomo",
                "name":  name,
                "proxy": "http://%s:%d" % (p["host"], p["port"]),
                "label": "mihomo: %s" % name,
                "detail": "%s %s:%d" % (p["type"], p["host"], p["port"]),
            })
    except Exception as e:
        log.debug("download_transport: mihomo-кандидаты: %s" % e,
                  source="download_transport")
    return out


def list_transports() -> dict:
    """Все доступные сейчас транспорты (для селекта в UI)."""
    items = [{"id": "direct", "kind": "direct", "label": "Напрямую",
              "detail": "обычное соединение (учитывает зеркало install.mirror)"}]
    items += _awg_candidates()
    items += _singbox_candidates()
    items += _mihomo_candidates()
    return {"ok": True, "transports": items}


def resolve_transport(spec) -> dict:
    """
    Спека → конкретный способ соединения.
    {"ok": True, "kind": "direct"} |
    {"ok": True, "kind": "awg", "device": ...} |
    {"ok": True, "kind": "singbox"|"mihomo", "proxy": "http://..."} |
    {"ok": False, "error": "..."}
    """
    kind, arg = parse_transport(spec)
    if kind == "direct":
        return {"ok": True, "kind": "direct", "id": "direct"}

    if kind == "awg":
        cands = _awg_candidates()
        if arg:
            for c in cands:
                if c["device"] == arg:
                    return dict(c, ok=True)
            # Интерфейс может существовать, но не находиться нашим
            # лёгким детектом (например, нативный Keenetic WG).
            if os.path.isdir("/sys/class/net/%s" % arg):
                return {"ok": True, "kind": "awg", "id": "awg:%s" % arg,
                        "device": arg, "label": "AWG: %s" % arg}
            return {"ok": False,
                    "error": "транспорт awg: интерфейс '%s' не найден" % arg}
        if cands:
            return dict(cands[0], ok=True)
        return {"ok": False,
                "error": "транспорт awg: нет активных AWG/WG-интерфейсов"}

    if kind in ("singbox", "mihomo"):
        cands = (_singbox_candidates() if kind == "singbox"
                 else _mihomo_candidates())
        if arg:
            for c in cands:
                if c["name"] == arg:
                    return dict(c, ok=True)
            return {"ok": False,
                    "error": "транспорт %s: конфиг '%s' не запущен или без "
                             "mixed/http-порта" % (kind, arg)}
        if cands:
            return dict(cands[0], ok=True)
        return {"ok": False,
                "error": "транспорт %s: нет запущенного конфига с локальным "
                         "mixed/http-портом" % kind}

    return {"ok": False, "error": "неизвестный транспорт '%s'" % spec}


# ─────── привязка сокета к интерфейсу (awg) ───────

def _iface_ipv4(device: str) -> str:
    """IPv4-адрес интерфейса через SIOCGIFADDR ('' если нет)."""
    try:
        import fcntl
        import struct
    except ImportError:
        return ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", device.encode()[:15])
        addr = fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24]  # SIOCGIFADDR
        return socket.inet_ntoa(addr)
    except OSError:
        return ""
    finally:
        s.close()


def _bind_to_device(sock, device: str, af):
    """
    Привязать сокет к интерфейсу. Сначала SO_BINDTODEVICE (надёжно:
    маршрутизация принудительно через устройство; требует root — GUI на
    роутере работает под ним), при неудаче — bind на IPv4-адрес
    интерфейса (работает с policy routing «from <ip>»).
    """
    if hasattr(socket, "SO_BINDTODEVICE"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            (device + "\0").encode())
            return
        except OSError:
            pass
    if af == socket.AF_INET:
        ip = _iface_ipv4(device)
        if ip:
            sock.bind((ip, 0))
            return
    raise OSError("не удалось привязать сокет к интерфейсу %s" % device)


def _connect_bound(host, port, timeout, device):
    """socket.create_connection с привязкой к устройству ДО connect."""
    last_err = None
    for af, socktype, proto, _cn, sa in socket.getaddrinfo(
            host, port, 0, socket.SOCK_STREAM):
        s = socket.socket(af, socktype, proto)
        try:
            if timeout is not None:
                s.settimeout(timeout)
            _bind_to_device(s, device, af)
            s.connect(sa)
            return s
        except OSError as e:
            last_err = e
            try:
                s.close()
            except OSError:
                pass
    if last_err is not None:
        raise last_err
    raise OSError("getaddrinfo не вернул адресов для %s" % host)


class _BoundHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=None, device="", **kw):
        super().__init__(host, port, **kw)
        self._zg_device = device

    def connect(self):
        self.sock = _connect_bound(self.host, self.port, self.timeout,
                                   self._zg_device)
        if self._tunnel_host:
            self._tunnel()


class _BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, device="", context=None, **kw):
        super().__init__(host, port, context=context, **kw)
        self._zg_device = device

    def connect(self):
        sock = _connect_bound(self.host, self.port, self.timeout,
                              self._zg_device)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(
            sock, server_hostname=server_hostname)


class _BoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, device):
        super().__init__()
        self._device = device

    def http_open(self, req):
        def factory(host, **kw):
            return _BoundHTTPConnection(host, device=self._device, **kw)
        return self.do_open(factory, req)


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, device):
        super().__init__()
        self._device = device

    def https_open(self, req):
        def factory(host, **kw):
            kw.pop("context", None)
            kw.pop("check_hostname", None)
            return _BoundHTTPSConnection(host, device=self._device, **kw)
        return self.do_open(factory, req)


# ─────── openers ───────

def build_opener(spec):
    """
    Спека → urllib opener (None для direct). RuntimeError с
    человекочитаемым сообщением, если транспорт недоступен.
    """
    res = resolve_transport(spec)
    if not res.get("ok"):
        raise RuntimeError(res.get("error") or "транспорт недоступен")
    kind = res["kind"]
    if kind == "direct":
        return None
    if kind == "awg":
        dev = res["device"]
        return urllib.request.build_opener(
            _BoundHTTPHandler(dev), _BoundHTTPSHandler(dev))
    # singbox / mihomo: локальный HTTP-прокси (CONNECT для https)
    proxy = res["proxy"]
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))


def urlopen_via(url, transport="", timeout=DEFAULT_TIMEOUT, headers=None):
    """
    urlopen с учётом транспорта. transport=''/direct → обычный urlopen.
    Вызывающая сторона сама применяет зеркало (resolve_url) к url.
    """
    req = urllib.request.Request(url, headers=dict(headers or {}))
    opener = build_opener(transport)
    if opener is None:
        return urllib.request.urlopen(req, timeout=timeout)
    return opener.open(req, timeout=timeout)
