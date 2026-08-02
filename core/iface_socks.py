# core/iface_socks.py
"""
Временный локальный SOCKS5, у которого ИСХОДЯЩИЕ соединения привязаны к
конкретному сетевому интерфейсу (SO_BINDTODEVICE).

Зачем. Часть наших средств обхода — это прокси с локальным портом
(opera-proxy, sing-box, mihomo): чтобы отправить через них чужой процесс,
достаточно передать ему HTTPS_PROXY. А AmneziaWG и WARP/MASQUE — это
интерфейсы, порта у них нет, и «сходить через awg0» стороннему бинарнику
нечем.

Этот модуль закрывает разрыв: поднимает на 127.0.0.1 эфемерный SOCKS5,
который каждое исходящее соединение вешает на нужный интерфейс. Дальше
любому процессу, понимающему HTTPS_PROXY (в том числе `usque register` —
он ходит через http.DefaultClient с ProxyFromEnvironment), можно сказать
socks5://127.0.0.1:<port> и получить выход через туннель БЕЗ правки
таблиц маршрутизации и firewall.

Живёт ровно столько, сколько нужно операции: это не сервис, а
context manager. Слушатель — только на loopback, и только на хосты из
белого списка: открытый SOCKS даже на секунду и даже на 127.0.0.1 —
лишний риск, которого легко избежать.

Тот же приём (SO_BINDTODEVICE) уже используется пробой watchdog'а в
core/usque_watchdog.py.
"""

import socket
import struct
import threading

from core.log_buffer import log

# Linux: SO_BINDTODEVICE. В socket-модуле есть не везде, поэтому число.
_SO_BINDTODEVICE = 25

_SOCKS_VERSION = 5
_CMD_CONNECT = 1
_ATYP_IPV4 = 1
_ATYP_DOMAIN = 3
_ATYP_IPV6 = 4

_REP_OK = 0
_REP_GENERAL_FAILURE = 1
_REP_NOT_ALLOWED = 2
_REP_HOST_UNREACHABLE = 4
_REP_CMD_NOT_SUPPORTED = 7

_IO_TIMEOUT = 30
_CONNECT_TIMEOUT = 20
_BUF = 65536


def iface_supported() -> bool:
    """Умеет ли ядро привязывать сокет к интерфейсу."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, b"lo\0")
        return True
    except (OSError, AttributeError):
        return False
    finally:
        s.close()


def _bind_to_iface(sock, iface: str) -> bool:
    """Привязать сокет к интерфейсу и УБЕДИТЬСЯ, что привязка встала.

    Проверка чтением обязательна: без неё молчаливый отказ setsockopt
    (нет CAP_NET_RAW) означал бы, что трафик пошёл мимо туннеля — то есть
    ровно туда, откуда мы уходим.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE,
                        (iface + "\0").encode())
    except (OSError, AttributeError):
        return False
    try:
        got = sock.getsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, 256)
        return got.split(b"\0", 1)[0].decode(errors="ignore") == iface
    except (OSError, AttributeError):
        # Прочитать не удалось — считаем, что привязки нет: fail-closed.
        return False


def _resolve(host: str):
    """IP-адреса хоста: системный резолвер, при неудаче — DoH проекта."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if ips:
            return ips
    except OSError:
        pass
    # Провайдер может не только резать TLS, но и травить DNS.
    try:
        from core.routing import doh_resolver
        res = doh_resolver.resolve(host, "v4")
        if res.get("ok"):
            return list(res.get("ips") or ())
    except Exception:
        pass
    return []


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(_BUF)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class IfaceSocksProxy:
    """SOCKS5 на 127.0.0.1, чей выход прибит к интерфейсу.

    Использование:

        with IfaceSocksProxy("awg0", allow_hosts=["api.example.com"]) as p:
            if p.ok:
                env["HTTPS_PROXY"] = p.url
    """

    def __init__(self, iface: str, allow_hosts=None):
        self.iface = iface
        # Пустой список = «никуда нельзя»; None = «куда угодно».
        self.allow_hosts = (set(h.lower() for h in allow_hosts)
                            if allow_hosts is not None else None)
        self.port = 0
        self.error = ""
        self._srv = None
        self._thread = None
        self._stop = threading.Event()
        self._conns = 0
        self._lock = threading.Lock()

    # ─────── свойства ───────

    @property
    def ok(self) -> bool:
        return bool(self.port) and not self.error

    @property
    def url(self) -> str:
        return "socks5://127.0.0.1:%d" % self.port if self.port else ""

    @property
    def connections(self) -> int:
        """Сколько соединений прошло — для диагностики «а он вообще звал?»."""
        with self._lock:
            return self._conns

    # ─────── жизненный цикл ───────

    def start(self) -> dict:
        if not self.iface:
            self.error = "не указан интерфейс"
            return {"ok": False, "error": self.error}
        if not iface_supported():
            self.error = ("ядро/права не позволяют привязать сокет к"
                          " интерфейсу (нужен root)")
            return {"ok": False, "error": self.error}

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bound = _bind_to_iface(probe, self.iface)
        probe.close()
        if not bound:
            self.error = ("не удалось привязаться к интерфейсу %s — он не"
                          " существует или нет прав" % self.iface)
            return {"ok": False, "error": self.error}

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(16)
            srv.settimeout(0.5)
        except OSError as e:
            self.error = "не удалось открыть локальный порт: %s" % e
            return {"ok": False, "error": self.error}

        self._srv = srv
        self.port = srv.getsockname()[1]
        self._thread = threading.Thread(
            target=self._serve, name="iface-socks-%s" % self.iface,
            daemon=True)
        self._thread.start()
        log.info("iface-socks: 127.0.0.1:%d → %s" % (self.port, self.iface),
                 source="usque")
        return {"ok": True, "url": self.url, "port": self.port}

    def stop(self):
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_exc):
        self.stop()
        return False

    # ─────── обслуживание ───────

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _recv_exact(self, sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("соединение закрыто")
            buf += chunk
        return buf

    def _handle(self, conn):
        upstream = None
        try:
            conn.settimeout(_IO_TIMEOUT)

            # greeting: VER NMETHODS METHODS...
            ver, nmethods = self._recv_exact(conn, 2)
            if ver != _SOCKS_VERSION:
                return
            self._recv_exact(conn, nmethods)
            conn.sendall(bytes([_SOCKS_VERSION, 0]))   # no auth

            # request: VER CMD RSV ATYP DST.ADDR DST.PORT
            ver, cmd, _rsv, atyp = self._recv_exact(conn, 4)
            if ver != _SOCKS_VERSION:
                return
            if cmd != _CMD_CONNECT:
                self._reply(conn, _REP_CMD_NOT_SUPPORTED)
                return

            if atyp == _ATYP_IPV4:
                host = socket.inet_ntoa(self._recv_exact(conn, 4))
            elif atyp == _ATYP_IPV6:
                host = socket.inet_ntop(socket.AF_INET6,
                                        self._recv_exact(conn, 16))
            elif atyp == _ATYP_DOMAIN:
                # Go отдаёт SOCKS5-прокси имя, а не адрес, — резолвим мы
                # (системный резолвер, при неудаче DoH; см. _resolve).
                length = self._recv_exact(conn, 1)[0]
                host = self._recv_exact(conn, length).decode(
                    "utf-8", "replace")
            else:
                self._reply(conn, _REP_GENERAL_FAILURE)
                return
            port = struct.unpack("!H", self._recv_exact(conn, 2))[0]

            if not self._allowed(host):
                log.warning("iface-socks: запрос к %s отклонён (не в белом"
                            " списке)" % host, source="usque")
                self._reply(conn, _REP_NOT_ALLOWED)
                return

            upstream = self._connect_via_iface(host, port)
            if upstream is None:
                self._reply(conn, _REP_HOST_UNREACHABLE)
                return

            with self._lock:
                self._conns += 1
            self._reply(conn, _REP_OK)

            t = threading.Thread(target=_pipe, args=(conn, upstream),
                                 daemon=True)
            t.start()
            _pipe(upstream, conn)
            t.join(timeout=1)
        except OSError:
            pass
        finally:
            for s in (conn, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _allowed(self, host: str) -> bool:
        if self.allow_hosts is None:
            return True
        return host.lower() in self.allow_hosts

    def _reply(self, conn, code: int):
        try:
            conn.sendall(bytes([_SOCKS_VERSION, code, 0, _ATYP_IPV4])
                         + b"\x00" * 6)
        except OSError:
            pass

    def _connect_via_iface(self, host: str, port: int):
        try:
            socket.inet_aton(host)
            candidates = [host]
        except OSError:
            candidates = _resolve(host)
        if not candidates:
            log.warning("iface-socks: не удалось зарезолвить %s" % host,
                        source="usque")
            return None

        for ip in candidates:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(_CONNECT_TIMEOUT)
            if not _bind_to_iface(s, self.iface):
                s.close()
                return None
            try:
                s.connect((ip, port))
                s.settimeout(_IO_TIMEOUT)
                return s
            except OSError:
                s.close()
                continue
        return None
