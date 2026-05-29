# core/testers/proxy.py
"""
Минимальный SOCKS5 / HTTP-CONNECT клиент (без внешних зависимостей).

Позволяет прогонять TLS-пробы BlockCheck через прокси, чтобы сравнить
доступность «напрямую» и «через туннель/прокси». Идея заимствована из
YT-DPI (там curl -x socks5/http).

Поддерживает только TCP (CONNECT). UDP-тесты (STUN/QUIC) через эти прокси
не идут — вызывающий код должен их пропускать при включённом прокси.

Использование:
    from core.testers.proxy import open_proxied_socket, parse_proxy
    proxy = parse_proxy({"type": "socks5", "host": "127.0.0.1", "port": 1080})
    sock = open_proxied_socket(proxy, "youtube.com", 443, timeout=10)
"""

from __future__ import annotations

import base64
import socket
import struct
from typing import Any, Optional


class ProxyError(Exception):
    """Ошибка установления соединения через прокси."""


def parse_proxy(raw: Any) -> Optional[dict]:
    """Нормализовать описание прокси из JSON в dict или None.

    Принимает:
        {"type": "socks5"|"http", "host": "...", "port": 1080,
         "user": "...", "pass": "..."}

    Возвращает нормализованный dict либо None, если прокси не задан/невалиден.
    """
    if not raw or not isinstance(raw, dict):
        return None
    host = str(raw.get("host", "")).strip()
    if not host:
        return None
    try:
        port = int(raw.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not (0 < port < 65536):
        return None

    ptype = str(raw.get("type", "socks5")).strip().lower()
    if ptype in ("socks", "socks5", "socks5h"):
        ptype = "socks5"
    elif ptype in ("http", "https", "connect"):
        ptype = "http"
    else:
        return None

    user = raw.get("user") or raw.get("username") or ""
    pwd = raw.get("pass") or raw.get("password") or ""
    return {
        "type": ptype,
        "host": host,
        "port": port,
        "user": str(user),
        "pass": str(pwd),
    }


def proxy_label(proxy: Optional[dict]) -> str:
    """Человекочитаемая метка прокси для логов/UI."""
    if not proxy:
        return ""
    auth = "@" if proxy.get("user") else ""
    return f"{proxy['type']}://{auth}{proxy['host']}:{proxy['port']}"


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Прочитать ровно n байт или бросить ProxyError при EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyError("Прокси закрыл соединение преждевременно")
        buf += chunk
    return buf


def _socks5_connect(
    sock: socket.socket, proxy: dict, dest_host: str, dest_port: int,
) -> None:
    """Выполнить SOCKS5 handshake + CONNECT (RFC 1928 / 1929)."""
    user = proxy.get("user") or ""
    pwd = proxy.get("pass") or ""

    # Greeting: предлагаем no-auth (0x00) и при наличии логина user/pass (0x02).
    methods = b"\x00"
    if user:
        methods = b"\x00\x02"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)

    resp = _recvn(sock, 2)
    if resp[0] != 0x05:
        raise ProxyError("Не SOCKS5-ответ от прокси")
    method = resp[1]

    if method == 0xFF:
        raise ProxyError("Прокси отверг методы аутентификации")
    if method == 0x02:
        if not user:
            raise ProxyError("Прокси требует логин/пароль")
        u = user.encode("utf-8")[:255]
        p = pwd.encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        ar = _recvn(sock, 2)
        if ar[1] != 0x00:
            raise ProxyError("SOCKS5: неверный логин/пароль")
    elif method != 0x00:
        raise ProxyError(f"SOCKS5: неподдерживаемый метод {method}")

    # CONNECT по доменному имени (ATYP=3) — резолв на стороне прокси.
    dh = dest_host.encode("idna") if dest_host else b""
    if len(dh) > 255:
        dh = dest_host.encode("utf-8")[:255]
    req = (
        b"\x05\x01\x00\x03"
        + bytes([len(dh)]) + dh
        + struct.pack(">H", dest_port)
    )
    sock.sendall(req)

    rep = _recvn(sock, 4)
    if rep[1] != 0x00:
        codes = {
            1: "общий сбой", 2: "запрещено правилами", 3: "сеть недоступна",
            4: "хост недоступен", 5: "соединение отклонено",
            6: "TTL истёк", 7: "команда не поддерживается",
            8: "тип адреса не поддерживается",
        }
        raise ProxyError(f"SOCKS5 CONNECT: {codes.get(rep[1], rep[1])}")

    # Дочитываем BND.ADDR + BND.PORT.
    atyp = rep[3]
    if atyp == 0x01:
        _recvn(sock, 4)
    elif atyp == 0x03:
        ln = _recvn(sock, 1)[0]
        _recvn(sock, ln)
    elif atyp == 0x04:
        _recvn(sock, 16)
    _recvn(sock, 2)


def _http_connect(
    sock: socket.socket, proxy: dict, dest_host: str, dest_port: int,
) -> None:
    """Выполнить HTTP CONNECT-туннель."""
    hostport = f"{dest_host}:{dest_port}"
    lines = [f"CONNECT {hostport} HTTP/1.1", f"Host: {hostport}"]
    user = proxy.get("user") or ""
    if user:
        token = base64.b64encode(
            f"{user}:{proxy.get('pass') or ''}".encode("utf-8")
        ).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    sock.sendall(request)

    # Читаем заголовки ответа до пустой строки.
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            raise ProxyError("HTTP-прокси закрыл соединение")
        buf += chunk
        if len(buf) > 8192:
            raise ProxyError("HTTP-прокси: слишком длинный ответ")

    status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or parts[1] != "200":
        raise ProxyError(f"HTTP CONNECT не удался: {status_line[:80]}")


def open_proxied_socket(
    proxy: dict, dest_host: str, dest_port: int, timeout: float,
) -> socket.socket:
    """Открыть TCP-соединение до dest через прокси и вернуть сокет.

    Сокет уже подключён к месту назначения — поверх него можно делать
    TLS handshake (wrap_socket + do_handshake).

    Raises:
        ProxyError: при любой ошибке установления туннеля.
    """
    try:
        sock = socket.create_connection(
            (proxy["host"], proxy["port"]), timeout=timeout,
        )
    except OSError as e:
        raise ProxyError(f"Не удалось подключиться к прокси: {str(e)[:80]}")

    sock.settimeout(timeout)
    try:
        if proxy["type"] == "socks5":
            _socks5_connect(sock, proxy, dest_host, dest_port)
        else:
            _http_connect(sock, proxy, dest_host, dest_port)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise
    return sock
