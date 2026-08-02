# core/tgproxy_manager.py
"""
Обход блокировки Telegram — два движка на выбор:

  tgwsproxy — tg-ws-proxy-go (spatiumstas/tg-ws-proxy-go, форк
              Flowseal/tg-ws-proxy под встраиваемые устройства).
              Локальный MTProto-прокси: приложение Telegram подключается
              к роутеру явной ссылкой tg://proxy, исходящее соединение
              заворачивается в WSS и (опционально) уходит через
              Cloudflare CDN — что помогает именно при блокировке по
              IP-диапазону датацентров Telegram, а не только при
              активном зондировании. ОСНОВНОЙ движок.

  mtproto   — tg-mtproxy-client (Go), релей-based. РЕЗЕРВНЫЙ движок —
              на случай, если когда-либо ляжет вся инфраструктура
              Cloudflare разом (общая точка отказа у tgwsproxy) —
              тогда нужна независимая от Cloudflare инфраструктура.

teleproxy сознательно НЕ используется. Его Direct-to-DC режим по
конструкции подключается напрямую к настоящему IP датацентра Telegram
— то есть ровно к тому диапазону, который у части пользователей режется
по IP целиком, независимо от того, насколько хорошо замаскирован
fake-TLS на входящей стороне. Обёртка через nfqws2, которая теоретически
могла бы это компенсировать, ничего не даёт именно в этом случае: nfqws2
десинхронизирует СОДЕРЖИМОЕ TCP-потока, но не меняет IP назначения —
если блокировка режет по диапазону адресов, а не по сигнатуре протокола,
пакет всё равно летит на заблокированный IP.

Оба оставленных движка работают ЛОКАЛЬНО, без VPS: сервер (сам движок) и
клиент (приложение Telegram) находятся в одной домашней сети, соединение
между ними никогда не покидает LAN — белый IP тут не требуется, он нужен
только чтобы прокси видели люди за пределами вашей сети.

──────────────────────────────────────────────────────────────────────
О сочетании с nfqws2 (важно понимать, что именно это даёт):

nfqws2 имеет смысл добавлять поверх tgwsproxy КАК ВТОРУЮ, независимую
линию защиты — на случай, если провайдер научится фингерпринтить сам
WSS-хендшейк к Cloudflare (TLS ClientHello/JA3 паттерн), а не как замену
Cloudflare-фоллбэку. Практически это означает: домен, который tgwsproxy
использует для CF-прокси/CF-Worker (если вы настроили СВОЙ домен, а не
дефолтный community-пул), должен попасть в hostlist, который
обрабатывает nfqws2 — тогда стратегия десинхронизации будет применяться
и к WSS-соединению до Cloudflare тоже.

Для дефолтного community-пула доменов (CFPROXY_DOMAINS_URL) это НЕ
делается автоматически здесь: сам бинарник tg-ws-proxy-go выбирает
домен из пула во время работы, и без более глубокого доступа к его
внутренней логике выбора нет надёжного способа заранее знать, какой
именно домен окажется активным — pretending otherwise here would be
дезинформацией. Если задан именно СВОЙ CF-домен явно (cf_domain /
cf_worker_domain) — вот тогда это известно заранее, и делается
best-effort регистрация в core.unified.manager с method="nfqws2" (см.
_register_cf_domain_for_nfqws ниже).
──────────────────────────────────────────────────────────────────────
"""

import os
import ipaddress
import re
import secrets
import shlex
import socket
import subprocess
import threading
import time
import tempfile
from urllib.parse import urlparse
from typing import Any

from core.log_buffer import log


# ─────────────────────────── tg-ws-proxy-go ───────────────────────────

TGWSPROXY_CONFIG_DIR = "/opt/etc/tg-ws-proxy"
TGWSPROXY_CONFIG_DIR_CANDIDATES = [
    "/opt/etc/tg-ws-proxy",  # Entware
    "/etc/tg-ws-proxy",     # OpenWrt package
]
TGWSPROXY_CONFIG_FILE = os.path.join(TGWSPROXY_CONFIG_DIR, "config.conf")
TGWSPROXY_SECRET_FILE = os.path.join(TGWSPROXY_CONFIG_DIR, "secret.conf")
TGWSPROXY_INITD_CANDIDATES = [
    "/opt/etc/init.d/S99tg-ws-proxy",
    "/etc/init.d/S99tg-ws-proxy",
    "/etc/init.d/tg-ws-proxy",
]

_DEFAULT_CFPROXY_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/"
    ".github/cfproxy-domains.txt"
)

# Поля config.conf, как их читает init.d-скрипт пакета (простой
# KEY=VALUE, шелл-совместимый — значения должны быть в кавычках).
#
# X_CF_DOMAIN / X_CF_WORKER_DOMAIN — НЕ читаются самим init.d-скриптом
# пакета (unknown-переменные шелл просто игнорирует), это наши
# собственные учётные поля. Без них get_config() не мог бы честно
# вернуть обратно то, что было сохранено: реальное поведение бинарника
# управляется через EXTRA_ARGS (--cfproxy-domain=... /
# --cfproxy-worker-domain=...), а распарсить их обратно из EXTRA_ARGS
# ненадёжно (могут быть смешаны с другими ручными флагами
# пользователя). Отдельные X_-поля — источник истины для GUI,
# EXTRA_ARGS — то, что реально передаётся бинарнику.
#
# X_EXTRA_ARGS — по той же причине: в EXTRA_ARGS лежит СМЕСЬ
# пользовательских флагов и тех, что мы сами собрали из mode/профиля
# ресурсов (--no-cfproxy, --pool-size=…). Отдавать эту смесь как
# `extra_args` было нельзя: GET config → PUT config тем же телом падал
# с «Недопустимый extra_args флаг: --no-cfproxy» (whitelist знает
# только пользовательские флаги). Пользовательская часть хранится
# отдельно и именно она возвращается в get_config()["extra_args"].
#
# Набор ключей сверен с upstream (files/common/etc/tg-ws-proxy/config.conf
# и files/*/etc/init.d/S99tg-ws-proxy в spatiumstas/tg-ws-proxy-go):
# init.d читает HOST, PORT, SECRET, DC_IP_DEFAULT, DC_IP_DEFAULT_POOL,
# CFPROXY_DOMAINS, CFPROXY_DOMAINS_URL, CFPROXY_WORKER_DOMAINS,
# FAKE_TLS_DOMAIN и EXTRA_ARGS (последний дописывается в конец
# командной строки, поэтому наши флаги перекрывают всё, что собрано
# выше). LOG_LEVEL там НЕ читается — это наше поле, verbose включается
# флагом `-v` в EXTRA_ARGS (см. save_config).
_TGWSPROXY_CONFIG_KEYS = [
    "HOST",
    "PORT",
    "LOG_LEVEL",
    "DC_IP_DEFAULT",
    "DC_IP_DEFAULT_POOL",
    "FAKE_TLS_DOMAIN",
    "CFPROXY_DOMAINS",
    "CFPROXY_DOMAINS_URL",
    "CFPROXY_WORKER_DOMAINS",
    "EXTRA_ARGS",
    "X_CF_DOMAIN",
    "X_CF_WORKER_DOMAIN",
    "X_MODE",
    "X_POOL_SIZE",
    "X_MAX_CONNS",
    "X_BUF_KB",
    "X_NO_CFPROXY_DOMAIN_REFRESH",
    "X_EXTRA_ARGS",
]

_TGWSPROXY_MODES = ("direct", "cfcommunity", "cfdomain", "hybrid", "tunnel")

# Фиксированный id авто-маршрута «CF-домен tg-ws-proxy → nfqws2» в едином
# слое: маршрут ровно один и он пересоздаётся (а не плодится) при каждом
# сохранении конфига.
_CF_DOMAIN_ROUTE_ID = "tgproxy-cf-domain-nfqws2"

_ALLOWED_USER_EXTRA_FLAGS = {
    "--v",
    "--log-file",
    "--log-max-mb",
    "--log-backups",
    "--pprof-listen",
    "--no-cfproxy-domain-refresh",
}
_HOST_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$")


def _pkg_version(pkg_name: str) -> str:
    """Версия установленного пакета tg-ws-proxy / tg-mtproxy-client.

    Поддерживаем и opkg, и apk, потому что в разных прошивках пакеты
    ставятся по-разному.
    """
    if not pkg_name:
        return ""
    for cmd, args in (
        ("opkg", ["status", pkg_name]),
        ("apk", ["info", "-v", pkg_name]),
    ):
        try:
            proc = subprocess.run(
                [cmd, *args], capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0 or not proc.stdout:
            continue
        if cmd == "opkg":
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        else:
            # apk info -v pkg -> первая строка обычно начинается с
            # "<pkg>-<version> ..."; берём хвост после имени пакета.
            first = proc.stdout.splitlines()[0].strip()
            prefix = pkg_name + "-"
            if first.startswith(prefix):
                return first[len(prefix):].split()[0].strip()
            if first:
                return first.split()[0]
    return ""


def _find_tgwsproxy_initd() -> str:
    for path in TGWSPROXY_INITD_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def _config_dir_for(initd: str = "") -> str:
    """Return the config directory matching the installed package layout."""
    if initd.startswith("/etc/"):
        return "/etc/tg-ws-proxy"
    if initd.startswith("/opt/"):
        return "/opt/etc/tg-ws-proxy"
    for path in TGWSPROXY_CONFIG_DIR_CANDIDATES:
        if os.path.isfile(os.path.join(path, "config.conf")):
            return path
    if not initd:
        # Development/test host without an installed package: keep writes out
        # of read-only /opt. Installed Entware/OpenWrt services always take
        # the explicit branches above.
        return os.path.join(tempfile.gettempdir(), "zapret-gui", "tg-ws-proxy")
    return TGWSPROXY_CONFIG_DIR


def _config_paths(initd: str = "") -> tuple[str, str, str]:
    directory = _config_dir_for(initd)
    return (directory, os.path.join(directory, "config.conf"),
            os.path.join(directory, "secret.conf"))


def _shell_quote_value(v: str) -> str:
    # config.conf is sourced by the init script. Single-quote every value
    # and reject control characters before this point.
    return shlex.quote(str(v or ""))


def _write_kv_conf(path: str, values: dict[str, str], keys_order: list[str]) -> None:
    lines = []
    for k in keys_order:
        v = values.get(k, "")
        lines.append("%s=%s" % (k, _shell_quote_value(v)))
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _valid_host(value: str) -> bool:
    value = str(value or "").strip()
    if value in ("0.0.0.0", "::"):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOST_RE.match(value))


def _valid_http_url(value: str) -> bool:
    value = str(value or "").strip()
    if not value:
        return True
    try:
        u = urlparse(value)
        return u.scheme in ("http", "https") and bool(u.hostname)
    except ValueError:
        return False


def _valid_ip_pool(value: str) -> bool:
    values = [v.strip() for v in str(value or "").split(",") if v.strip()]
    try:
        return all(ipaddress.ip_address(v) for v in values)
    except ValueError:
        return False


def _validate_user_extra(parts: list[str]) -> str:
    for part in parts:
        name = part.split("=", 1)[0]
        if name not in _ALLOWED_USER_EXTRA_FLAGS:
            return "Недопустимый extra_args флаг: %s" % name
    return ""


def _read_kv_conf(path: str) -> dict[str, str]:
    out = {}
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                out[k] = v
    except OSError as e:
        log.warning(
            "tg-ws-proxy: не удалось прочитать %s: %s" % (path, e), source="tgproxy"
        )
    return out


def _lan_ip() -> str:
    """LAN-адрес роутера (для генерации tg://proxy ссылки, когда
    HOST=0.0.0.0). Best-effort: если не удалось определить — вызывающий
    код должен позволить пользователю ввести адрес вручную, а не
    полагаться слепо на пустую строку."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return ""


def _build_proxy_link(
    host: str, port: int, secret_hex: str, fake_tls_domain: str = ""
) -> str:
    """tg://proxy ссылка. dd-режим (обычный secure) без fake_tls_domain,
    ee-режим (fake-TLS, SNI-fronting) — с ним. Формат секрета —
    стандартная конвенция MTProxy (dd/ee + 32 hex + hex(domain) для ee),
    задокументирована публично, не специфична для этого проекта."""
    secret_hex = secret_hex.strip().lower()
    if fake_tls_domain:
        domain_hex = fake_tls_domain.strip().encode("ascii", "ignore").hex()
        secret = "ee" + secret_hex + domain_hex
    else:
        secret = "dd" + secret_hex
    return "tg://proxy?server=%s&port=%s&secret=%s" % (host, port, secret)


class TgWsProxyManager:
    """Управление tg-ws-proxy-go. В отличие от остальных менеджеров этого
    проекта (usque/awg/...), это НЕ голый бинарник, которым мы управляем
    напрямую через subprocess.Popen — это установленный opkg-пакет со
    своим init.d-скриптом, который сам занимается демонизацией,
    PID-файлом и логами. Поэтому здесь мы управляем им ЧЕРЕЗ init.d
    (`start`/`stop`/`status`), а не пытаемся продублировать то, что уже
    делает сам пакет — попытка второй раз демонизировать то же самое
    приведёт к рассинхронизации PID-файлов и путанице при рестартах."""

    def __init__(self):
        self._lock = threading.Lock()

    # ─────── detect / config ───────

    def detect(self) -> dict[str, Any]:
        initd = _find_tgwsproxy_initd()
        installed = bool(initd)
        _directory, config_file, _secret_file = _config_paths(initd)
        return {
            "installed": installed,
            "path": initd,
            "config_exists": os.path.isfile(config_file),
            "config_dir": _directory,
            "package": "tg-ws-proxy",
            "version": _pkg_version("tg-ws-proxy") if installed else "",
            "upstream_tls_verified": False,
            "upstream_tls_warning": (
                "Текущий upstream tg-ws-proxy-go использует InsecureSkipVerify; "
                "исправление требует нового upstream-бинарника"),
        }

    def get_config(self) -> dict[str, Any]:
        initd = _find_tgwsproxy_initd()
        _directory, config_file, secret_file = _config_paths(initd)
        cfg = _read_kv_conf(config_file)
        secret_cfg = _read_kv_conf(secret_file)
        def _cfg_int(key: str, default: int) -> int:
            try:
                return int(cfg.get(key) or default)
            except (TypeError, ValueError):
                return default

        cf_domain = cfg.get("X_CF_DOMAIN", "")
        cf_worker_domain = cfg.get("X_CF_WORKER_DOMAIN", "")
        # X_MODE появился позже самого config.conf: у конфига, записанного
        # прежней версией GUI (или вручную), его нет. Отдавать в этом
        # случае "direct" — врать: если задан CF-домен, выход идёт через
        # Cloudflare, и GUI показывал бы не тот выбранный режим.
        mode = cfg.get("X_MODE", "")
        if mode not in _TGWSPROXY_MODES:
            mode = "cfdomain" if (cf_domain or cf_worker_domain) else "direct"

        return {
            "host": cfg.get("HOST", "0.0.0.0"),
            "port": _cfg_int("PORT", 1443),
            "log_level": cfg.get("LOG_LEVEL", "0"),
            "dc_ip_default": cfg.get("DC_IP_DEFAULT", "149.154.167.220"),
            "dc_ip_default_pool": cfg.get("DC_IP_DEFAULT_POOL", ""),
            "fake_tls_domain": cfg.get("FAKE_TLS_DOMAIN", ""),
            "cf_domain": cf_domain,
            "cf_worker_domain": cf_worker_domain,
            "cfproxy_domains": cfg.get("CFPROXY_DOMAINS", ""),
            "cfproxy_domains_url": cfg.get(
                "CFPROXY_DOMAINS_URL", _DEFAULT_CFPROXY_DOMAINS_URL
            ),
            # Только пользовательская часть — её и принимает save_config()
            # обратно (см. комментарий у _TGWSPROXY_CONFIG_KEYS).
            "extra_args": cfg.get("X_EXTRA_ARGS", ""),
            # Полная строка, которая реально уходит бинарнику — для
            # диагностики в GUI/логах; на вход save_config() не годится.
            "extra_args_effective": cfg.get("EXTRA_ARGS", ""),
            "mode": mode,
            "pool_size": _cfg_int("X_POOL_SIZE", 2),
            "max_conns": _cfg_int("X_MAX_CONNS", 64),
            "buf_kb": _cfg_int("X_BUF_KB", 64),
            "no_cfproxy_domain_refresh": (
                cfg.get("X_NO_CFPROXY_DOMAIN_REFRESH", "0") == "1"),
            "secret": secret_cfg.get("SECRET", ""),
            "upstream_tls_verified": False,
        }

    def save_config(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 1443,
        dc_ip_default: str = "149.154.167.220",
        dc_ip_default_pool: str = "",
        fake_tls_domain: str = "",
        cf_domain: str = "",
        cf_worker_domain: str = "",
        cfproxy_domains: str = "",
        cfproxy_domains_url: str = "",
        extra_args: str = "",
        secret: str = "",
        log_level: str = "0",
        mode: str = "direct",
        pool_size: int = 2,
        max_conns: int = 64,
        buf_kb: int = 64,
        no_cfproxy_domain_refresh: bool = False,
    ) -> dict[str, Any]:
        """Сохранить config.conf/secret.conf.

        cf_domain / cf_worker_domain — свой домен под CF-прокси (обычный
        Cloudflare CDN, "оранжевое облако") / CF-Worker соответственно.
        CLI-флаги подтверждены по upstream parseFlags: пользовательский
        extra_args ограничен whitelist, а сетевые режимы/pool/max-conns
        формируются только из валидированных полей.
        """
        if mode not in _TGWSPROXY_MODES:
            return {"ok": False, "error": "Неизвестный режим tg-ws-proxy: %s" % mode}

        initd = _find_tgwsproxy_initd()
        config_dir, config_file, secret_file = _config_paths(initd)
        if not secret:
            # Saving unrelated settings must not rotate a live Telegram link.
            existing = _read_kv_conf(secret_file).get("SECRET", "")
            secret = existing or secrets.token_hex(16)
        if not re.match(r"^[0-9a-fA-F]{32}$", secret):
            return {"ok": False, "error": "secret должен содержать 32 hex-символа"}

        try:
            pool_size = int(pool_size)
            max_conns = int(max_conns)
            buf_kb = int(buf_kb)
        except (TypeError, ValueError):
            return {"ok": False, "error": "pool_size/max_conns/buf_kb должны быть числами"}
        if not (0 <= pool_size <= 16):
            return {"ok": False, "error": "pool_size вне диапазона 0-16"}
        if not (1 <= max_conns <= 512):
            return {"ok": False, "error": "max_conns вне диапазона 1-512"}
        if not (4 <= buf_kb <= 1024):
            return {"ok": False, "error": "buf_kb вне диапазона 4-1024"}

        for label, value in (("host", host), ("dc_ip_default", dc_ip_default),
                             ("dc_ip_default_pool", dc_ip_default_pool),
                             ("fake_tls_domain", fake_tls_domain),
                             ("cf_domain", cf_domain),
                             ("cf_worker_domain", cf_worker_domain),
                             ("cfproxy_domains", cfproxy_domains),
                             ("cfproxy_domains_url", cfproxy_domains_url),
                             ("extra_args", extra_args)):
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in str(value or "")):
                return {"ok": False, "error": "Недопустимые управляющие символы: %s" % label}

        try:
            host = str(host or "0.0.0.0").strip()
            port = int(port)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Некорректные host/port"}
        if not (1 <= port <= 65535):
            return {"ok": False, "error": "port вне диапазона 1-65535"}
        if not _valid_host(host):
            return {"ok": False, "error": "Некорректный host"}
        try:
            if dc_ip_default and not ipaddress.ip_address(str(dc_ip_default).strip()):
                return {"ok": False, "error": "Некорректный dc_ip_default"}
        except ValueError:
            return {"ok": False, "error": "Некорректный dc_ip_default"}
        if dc_ip_default_pool and not _valid_ip_pool(dc_ip_default_pool):
            return {"ok": False, "error": "Некорректный dc_ip_default_pool"}
        if not _valid_http_url(cfproxy_domains_url):
            return {"ok": False, "error": "Некорректный cfproxy_domains_url"}
        if mode == "cfdomain" and not (cf_domain or cf_worker_domain):
            return {"ok": False, "error": "Для custom Cloudflare укажите домен или Worker"}
        if cf_domain and cf_worker_domain:
            return {"ok": False, "error": "Укажите только один CF-домен или Worker"}

        extra = (extra_args or "").strip()
        if any(ch in extra for ch in "$`;&|<>\n\r"):
            return {"ok": False, "error": "extra_args содержит запрещённые shell-символы"}
        try:
            extra_parts = shlex.split(extra) if extra else []
        except ValueError as e:
            return {"ok": False, "error": "Некорректный extra_args: %s" % e}
        if any(not p.startswith("--") for p in extra_parts):
            return {"ok": False, "error": "extra_args должен содержать только CLI-флаги"}
        extra_error = _validate_user_extra(extra_parts)
        if extra_error:
            return {"ok": False, "error": extra_error}
        user_extra = " ".join(shlex.quote(p) for p in extra_parts)
        # Verbose. LOG_LEVEL из config.conf init.d-скрипт не читает
        # вообще (сверено с upstream) — само по себе это поле не давало
        # ничего. Реальный тумблер — `-v` в EXTRA_ARGS, причём именно с
        # ОДНИМ дефисом: init.d включает запись в лог-файл по
        # `case " $EXTRA_ARGS " in *" -v "*)`, и `--v` под этот шаблон не
        # попадает (бинарник-то его понимает, а лог-файл не появляется).
        if str(log_level or "0").strip().lower() not in ("", "0", "off", "false"):
            extra_parts.append("-v")
        if mode in ("direct", "tunnel"):
            extra_parts.append("--no-cfproxy")
        elif mode == "hybrid":
            extra_parts.append("--cfproxy-priority=false")
        if cf_domain:
            extra_parts += ["--cfproxy-domain=%s" % cf_domain]
        if cf_worker_domain:
            extra_parts += ["--cfproxy-worker-domain=%s" % cf_worker_domain]
        extra_parts += [
            "--pool-size=%d" % pool_size,
            "--max-conns=%d" % max_conns,
            "--buf-kb=%d" % buf_kb,
        ]
        if no_cfproxy_domain_refresh:
            extra_parts.append("--no-cfproxy-domain-refresh")
        extra = " ".join(shlex.quote(p) for p in extra_parts)

        os.makedirs(config_dir, exist_ok=True)

        _write_kv_conf(
            config_file,
            {
                "HOST": host,
                "PORT": str(int(port)),
                "LOG_LEVEL": log_level,
                "DC_IP_DEFAULT": dc_ip_default,
                "DC_IP_DEFAULT_POOL": dc_ip_default_pool,
                "FAKE_TLS_DOMAIN": fake_tls_domain,
                "CFPROXY_DOMAINS": cfproxy_domains,
                "CFPROXY_DOMAINS_URL": (
                    cfproxy_domains_url or _DEFAULT_CFPROXY_DOMAINS_URL
                ),
                # Родное поле upstream-конфига под тот же
                # --cfproxy-worker-domain, что мы дублируем в EXTRA_ARGS:
                # значение одно и то же (конфликта нет, EXTRA_ARGS идёт
                # последним), но правка config.conf руками теперь не
                # разъезжается с тем, что показывает GUI.
                "CFPROXY_WORKER_DOMAINS": cf_worker_domain,
                "EXTRA_ARGS": extra,
                "X_CF_DOMAIN": cf_domain,
                "X_CF_WORKER_DOMAIN": cf_worker_domain,
                "X_MODE": mode,
                "X_POOL_SIZE": str(pool_size),
                "X_MAX_CONNS": str(max_conns),
                "X_BUF_KB": str(buf_kb),
                "X_NO_CFPROXY_DOMAIN_REFRESH": "1" if no_cfproxy_domain_refresh else "0",
                "X_EXTRA_ARGS": user_extra,
            },
            _TGWSPROXY_CONFIG_KEYS,
        )

        _write_kv_conf(secret_file, {"SECRET": secret}, ["SECRET"])
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass

        active_cf_domain = cf_domain or cf_worker_domain
        if active_cf_domain:
            self._register_cf_domain_for_nfqws(active_cf_domain)
        else:
            # Ушли с cfdomain-режима (или сменили домен на пустой) —
            # снимаем авто-маршрут, иначе nfqws2 продолжал бы обрабатывать
            # домен, которого в конфиге уже нет.
            self._unregister_cf_domain_for_nfqws()

        return {"ok": True, "secret_configured": True}

    def rotate_secret(self, confirm: bool = False) -> dict[str, Any]:
        """Explicitly rotate the MTProto secret; ordinary saves never do it."""
        if not confirm:
            return {"ok": False,
                    "error": "Подтвердите ротацию: существующие Telegram-ссылки перестанут работать"}
        cfg = self.get_config()
        was_running = self.get_status().get("running", False)
        if was_running:
            self.stop()
        result = self.save_config(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 1443),
            dc_ip_default=cfg.get("dc_ip_default", "149.154.167.220"),
            dc_ip_default_pool=cfg.get("dc_ip_default_pool", ""),
            fake_tls_domain=cfg.get("fake_tls_domain", ""),
            cf_domain=cfg.get("cf_domain", ""),
            cf_worker_domain=cfg.get("cf_worker_domain", ""),
            cfproxy_domains=cfg.get("cfproxy_domains", ""),
            cfproxy_domains_url=cfg.get("cfproxy_domains_url", ""),
            # Пользовательская часть флагов (X_EXTRA_ARGS) — ротация
            # секрета не должна их терять.
            extra_args=cfg.get("extra_args", ""),
            secret=secrets.token_hex(16),
            log_level=cfg.get("log_level", "0"),
            mode=cfg.get("mode", "direct"),
            pool_size=cfg.get("pool_size", 2),
            max_conns=cfg.get("max_conns", 64),
            buf_kb=cfg.get("buf_kb", 64),
            no_cfproxy_domain_refresh=cfg.get("no_cfproxy_domain_refresh", False),
        )
        if result.get("ok") and was_running:
            restart = self.start()
            if not restart.get("ok"):
                result["warning"] = "secret сменён, но сервис не перезапустился: %s" % restart.get("error")
        return result

    # ─────── nfqws2 hook (best-effort, см. docstring файла) ───────

    def _register_cf_domain_for_nfqws(self, domain: str) -> None:
        """Зарегистрировать явно заданный CF-домен как цель nfqws2 через
        core.unified.manager (реальный, проверенный API этого проекта —
        не выдуманный). Только для явно указанного пользователем
        домена — для дефолтного community-пула это не делается (см.
        docstring файла, почему).

        id маршрута фиксирован: без него UnifiedRoute генерировал новый
        `route-<rand>` на КАЖДОЕ сохранение конфига, и в единый слой
        сыпались дубликаты «tg-ws-proxy CF-домен (авто)» — по одному на
        каждое нажатие «Сохранить», включая маршруты на давно убранные
        домены."""
        try:
            from core.unified import manager as unified_manager

            result = unified_manager.save_route(
                {
                    "id": _CF_DOMAIN_ROUTE_ID,
                    "name": "tg-ws-proxy CF-домен (авто)",
                    "destination": {"domains": [domain]},
                    "method": "nfqws2",
                },
                apply=True,
            )
            if result.get("ok"):
                log.info(
                    "tg-ws-proxy: домен %s добавлен под nfqws2" % domain,
                    source="tgproxy",
                )
            else:
                log.warning(
                    "tg-ws-proxy: не удалось добавить %s под "
                    "nfqws2: %s" % (domain, result.get("error")),
                    source="tgproxy",
                )
        except Exception as e:
            log.warning(
                "tg-ws-proxy: интеграция с nfqws2 недоступна "
                "(%s) — добавьте домен %s в hostlist вручную "
                "через Unified Routing" % (e, domain),
                source="tgproxy",
            )

    def _unregister_cf_domain_for_nfqws(self) -> None:
        """Снять авто-маршрут CF-домена (его больше нет в конфиге)."""
        try:
            from core.unified import manager as unified_manager

            if unified_manager.get_route(_CF_DOMAIN_ROUTE_ID) is None:
                return
            result = unified_manager.delete_route(_CF_DOMAIN_ROUTE_ID)
            if result.get("ok"):
                log.info("tg-ws-proxy: авто-маршрут CF-домена под nfqws2 снят",
                         source="tgproxy")
        except Exception as e:
            log.warning("tg-ws-proxy: снятие авто-маршрута CF-домена: %s" % e,
                        source="tgproxy")

    # ─────── start / stop / status через init.d ───────

    def start(self) -> dict[str, Any]:
        with self._lock:
            det = self.detect()
            if not det["installed"]:
                return {
                    "ok": False,
                    "error": "tg-ws-proxy-go не установлен (%s не найден)"
                    % ", ".join(TGWSPROXY_INITD_CANDIDATES),
                }
            if not det["config_exists"]:
                return {"ok": False,
                        "error": "Нет config.conf — сначала сохраните "
                                 "настройки tg-ws-proxy"}

            initd = det.get("path") or _find_tgwsproxy_initd()
            r = subprocess.run(
                [initd, "start"], capture_output=True, text=True, timeout=15
            )
            if r.returncode != 0:
                return {
                    "ok": False,
                    "error": (r.stderr or r.stdout or "неизвестная ошибка").strip(),
                }

            # init.d "start" обычно возвращается сразу после форка демона
            # — даём секунду и проверяем реальное состояние, а не верим
            # только коду возврата команды start (см. audit ISSUE-003 —
            # никогда не доверять единственному сигналу состояния).
            time.sleep(1)
            st = self._status_locked()
            if not st.get("running"):
                return {
                    "ok": False,
                    "error": "init.d вернул успех, но процесс не поднялся — "
                    "проверьте логи tg-ws-proxy",
                }
            return {"ok": True}

    def stop(self) -> dict:
        with self._lock:
            det = self.detect()
            if not det["installed"]:
                return {"ok": True, "message": "не установлен"}
            initd = det.get("path") or _find_tgwsproxy_initd()
            r = subprocess.run(
                [initd, "stop"], capture_output=True, text=True, timeout=15
            )
            return {
                "ok": r.returncode == 0,
                "error": (r.stderr or "").strip() if r.returncode else "",
            }

    def restart(self) -> dict[str, Any]:
        self.stop()
        time.sleep(1)
        return self.start()

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict[str, Any]:
        det = self.detect()
        if not det["installed"]:
            return {"running": False, "installed": False}

        via_initd = False
        try:
            initd = det.get("path") or _find_tgwsproxy_initd()
            r = subprocess.run(
                [initd, "status"], capture_output=True, text=True, timeout=8
            )
            out = (r.stdout or "").lower()
            via_initd = r.returncode == 0 and (
                "running" in out or "active" in out or "alive" in out
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Дублируем независимой проверкой порта — тот же принцип, что и
        # в init.d-статусе других сервисов: не доверять единственному
        # источнику истины.
        cfg = self.get_config()
        port_open = self._port_listening(cfg.get("port", 1443), cfg.get("host", ""))

        return {
            "installed": True,
            "running": via_initd or port_open,
            "port": cfg.get("port"),
            "host": cfg.get("host"),
            "upstream_tls_verified": False,
        }

    def _port_listening(self, port: int, host: str = "") -> bool:
        # Probe the configured bind address; for a wildcard bind probe
        # loopback. A service bound to a LAN address is not required to
        # listen on lo, so loopback is not a fallback for that case.
        targets = [host] if host and host not in ("0.0.0.0", "::") else ["127.0.0.1"]
        for target in targets:
            try:
                try:
                    family = (socket.AF_INET6 if
                              ipaddress.ip_address(target).version == 6
                              else socket.AF_INET)
                except ValueError:
                    family = socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(1.0)
                address = ((target, int(port), 0, 0) if
                           family == socket.AF_INET6 else (target, int(port)))
                r = s.connect_ex(address)
                s.close()
                if r == 0:
                    return True
            except OSError:
                continue
        return False

    def get_connect_info(self) -> dict[str, Any]:
        """tg://proxy ссылка для GUI (показать/сгенерировать QR)."""
        cfg = self.get_config()
        host = cfg.get("host") or "0.0.0.0"
        if host in ("0.0.0.0", ""):
            host = _lan_ip() or host
        link = _build_proxy_link(
            host,
            cfg.get("port", 1443),
            cfg.get("secret", ""),
            cfg.get("fake_tls_domain", ""),
        )
        return {
            "link": link,
            "host": host,
            "port": cfg.get("port"),
            "fake_tls": bool(cfg.get("fake_tls_domain")),
        }


_tgwsproxy_instance = None
_tgwsproxy_lock = threading.Lock()


def get_tgwsproxy_manager() -> TgWsProxyManager:
    global _tgwsproxy_instance
    if _tgwsproxy_instance is None:
        with _tgwsproxy_lock:
            if _tgwsproxy_instance is None:
                _tgwsproxy_instance = TgWsProxyManager()
    return _tgwsproxy_instance


# ──────────────────────────── tg-mtproxy-client ────────────────────────
"""
Резервный движок: релей-based MTProxy-клиент (Go). В отличие от
tgwsproxy это голый бинарник, которым управляем напрямую через
subprocess — здесь применены конкретные исправления из аудита этого же
файла в предыдущей версии:

  ISSUE-006 (had stdout=PIPE без чтения → пайп переполняется, процесс
  зависает на write()) — здесь stdout/stderr=DEVNULL, как это уже
  корректно сделано в core/usque_manager.py.

  ISSUE-007 (после kill() не вызывался wait() → zombie-процессы) —
  здесь wait() вызывается и после SIGTERM, и после SIGKILL.
"""

MTPROXY_BIN_CANDIDATES = [
    "/opt/usr/bin/tg-mtproxy-client",
    "/opt/sbin/tg-mtproxy-client",
]

# Значения по умолчанию — ровно те, что апстрим зашивает в свои сборки
# (`tg-mtproxy-client -h` печатает их как default). Мы собираем бинарник
# сами и секрет в него НЕ зашиваем: держать его здесь лучше, потому что
# сменить значение — это правка настройки в GUI, а не пересборка и
# релиз. Пользователь может указать свой релей и свой секрет —
# tgproxy.tunnel_url / tgproxy.tunnel_secret перекрывают эти дефолты.
#
# ВАЖНО: это ключ HMAC для аутентификации НА РЕЛЕЕ (см. computeAuthHMAC
# и /register в апстриме), а НЕ секрет MTProto-ссылки. Он общий для всех
# пользователей публичного релея — приватности в нём нет.
#
# ОТКУДА ВЗЯТ И КАК ОБНОВИТЬ, КОГДА ПЕРЕСТАНЕТ РАБОТАТЬ.
# Апстрим зашивает секрет в свои сборки при компиляции
# (-X main.defaultTunnelSecret) и в исходники не коммитит. Реверс не
# нужен — Go печатает дефолты флагов сам:
#
#   git clone --depth 1 https://github.com/necronicle/z2k
#   chmod +x z2k/mtproxy-client/builds/tg-mtproxy-client-linux-amd64
#   z2k/mtproxy-client/builds/tg-mtproxy-client-linux-amd64 -h
#     -tunnel-secret string ... (default "63d91c...")
#     -tunnel-url    string ... (default "wss://213.176.74.63.nip.io/ws")
#
# Симптом протухшего ключа: движок стартует, но туннель не поднимается.
# Подробности — .claude/skills/telegram-tunnel/SKILL.md §10.3.
MTPROXY_DEFAULT_RELAY = "wss://213.176.74.63.nip.io/ws"
MTPROXY_DEFAULT_TUNNEL_SECRET = (
    "63d91c9c6fbc14b59043696af837774c1f90ecabe112b97113e5d0b289900070"
)
MTPROXY_LOCAL_PORT = 1443

# Секрет релея — hex-строка произвольной длины (у публичного релея это
# 64 символа). Прежняя проверка требовала РОВНО 32 hex, то есть формат
# MTProto-ссылки, и отвергала настоящий секрет: ввести рабочее значение
# в GUI было физически нельзя.
_TUNNEL_SECRET_RE = re.compile(r"^[0-9a-fA-F]{16,128}$")


def _find_mtproxy_binary() -> str:
    for p in MTPROXY_BIN_CANDIDATES:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return ""


class MtProxyClientManager:
    """tg-mtproxy-client — релей-режим, резервный движок."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._secret = ""
        self._port = MTPROXY_LOCAL_PORT
        self._relay = MTPROXY_DEFAULT_RELAY
        self._host = ""

    def detect(self) -> dict[str, Any]:
        bin_path = _find_mtproxy_binary()
        # Версию НЕ спрашиваем у бинарника: у tg-mtproxy-client нет
        # `--version`, и попытка его запросить просто запускает прокси
        # (ext_binary_installer._get_version перебирает флаги вслепую).
        # detect() дёргается на каждый рендер страницы и на каждую
        # проверку обновлений — берём тег, записанный установщиком.
        version = ""
        if bin_path:
            try:
                from core.config_manager import get_config_manager
                version = get_config_manager().get(
                    "tgproxy", "mtproto_installed_tag", default="") or ""
            except Exception:
                version = ""
        return {"installed": bool(bin_path), "path": bin_path,
                "version": version}

    def start(
        self,
        *,
        port: int = MTPROXY_LOCAL_PORT,
        relay: str = MTPROXY_DEFAULT_RELAY,
        secret: str = "",
        host: str = "",
        apply_redirect: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                return {"ok": False, "error": "уже запущен"}

            bin_path = _find_mtproxy_binary()
            if not bin_path:
                return {
                    "ok": False,
                    "error": "tg-mtproxy-client не найден (%s)"
                    % ", ".join(MTPROXY_BIN_CANDIDATES),
                }

            relay = (relay or "").strip()
            if not relay:
                return {"ok": False, "error": "relay обязателен для mtproto-режима"}
            relay_scheme = urlparse(relay).scheme
            if relay_scheme not in ("ws", "wss", "http", "https"):
                return {"ok": False,
                        "error": "relay должен быть URL ws://, wss://, "
                                 "http:// или https://"}

            try:
                port = int(port)
            except (TypeError, ValueError):
                return {"ok": False, "error": "Некорректный port"}
            if not (1 <= port <= 65535):
                return {"ok": False, "error": "port вне диапазона 1-65535"}

            # Пустой секрет — берём общий дефолт публичного релея.
            #
            # Раньше здесь генерировался СЛУЧАЙНЫЙ secrets.token_hex(16),
            # и это не могло работать в принципе: --tunnel-secret — ключ
            # HMAC, которым клиент аутентифицируется на релее (и которым
            # подписывает /register). Релей должен знать это значение
            # заранее, поэтому случайное всегда отвергалось — процесс
            # запускался, а туннель молча не поднимался.
            secret = (secret or "").strip() or MTPROXY_DEFAULT_TUNNEL_SECRET
            if not _TUNNEL_SECRET_RE.match(secret):
                return {"ok": False,
                        "error": "secret релея — hex-строка (16–128 символов)"}

            # Слушать по умолчанию на LAN-адресе роутера, а не на
            # 127.0.0.1: телефон подключается по ссылке tg://proxy из той
            # же сети, а get_connect_info() и раньше выдавал LAN-адрес —
            # то есть ссылка вела на адрес, который процесс не слушал, и
            # резервный движок был нерабочим по построению.
            host = (host or "").strip() or _lan_ip() or "127.0.0.1"
            if not _valid_host(host):
                return {"ok": False, "error": "Некорректный host"}

            args = [
                bin_path,
                "--listen",
                "%s:%d" % (host, port),
                "--tunnel-url",
                relay,
                "--tunnel-secret",
                secret,
            ]
            try:
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
            except OSError as e:
                return {"ok": False, "error": "не удалось запустить: %s" % e}

            time.sleep(0.5)
            if proc.poll() is not None:
                return {
                    "ok": False,
                    "error": "процесс завершился сразу после запуска (rc=%s)"
                    % proc.returncode,
                }

            self._proc = proc
            self._secret = secret
            self._port = port
            self._relay = relay
            self._host = host
            log.success(
                "tg-mtproxy-client: запущен (relay=%s, %s:%d)"
                % (relay, host, port),
                source="tgproxy",
            )
            # Без REDIRECT движок не получит ни одного соединения: он
            # работает по SO_ORIGINAL_DST, то есть только с трафиком,
            # завёрнутым ядром на его порт. Ставим правила ПОСЛЕ
            # успешного старта — вешать их на неподнятый порт значило бы
            # оборвать Telegram совсем.
            redirect = {"ok": False, "error": "не применялся"}
            if apply_redirect:
                # Та же пара механизмов, что и в
                # route_telegram_dc_via_tunnel, только с другой стороны:
                # если DC уже уведены в туннель, наш REDIRECT перехватит
                # их раньше и туннель окажется не при делах. Не молчим.
                try:
                    from core.unified import manager as _um
                    if _um.get_route(_DC_ROUTE_ID) is not None:
                        log.warning(
                            "tgproxy: Telegram DC уже маршрутизируются через "
                            "туннель — REDIRECT на резервный движок "
                            "перехватит их раньше", source="tgproxy")
                except Exception:
                    pass
                try:
                    from core import tgproxy_redirect
                    redirect = tgproxy_redirect.apply(port)
                except Exception as e:
                    redirect = {"ok": False, "error": str(e)}

            return {"ok": True, "port": port, "host": host,
                    "redirect": redirect,
                    "using_default_secret":
                        secret == MTPROXY_DEFAULT_TUNNEL_SECRET}

    def _drop_redirect(self) -> None:
        """Снять REDIRECT. Обязательно при любой остановке.

        Правила переживают смерть процесса, и оставленные они уводят весь
        Telegram-трафик на порт, который больше никто не слушает, — то
        есть Telegram отваливается совсем, а не «возвращается напрямую».
        """
        try:
            from core import tgproxy_redirect
            tgproxy_redirect.remove()
        except Exception as e:
            log.warning("tgproxy: не удалось снять REDIRECT: %s" % e,
                        source="tgproxy")

    def stop(self) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            self._proc = None
            # Снимаем ДО проверки «уже остановлен»: если процесс умер сам
            # (упал/убит извне), правила всё равно надо убрать.
            self._drop_redirect()
            if not proc or proc.poll() is not None:
                return {"ok": True, "message": "уже остановлен"}
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)  # ISSUE-007: обязателен и после kill()
                except Exception as e:
                    log.warning(
                        "tg-mtproxy-client: kill/wait: %s" % e, source="tgproxy"
                    )
            except Exception as e:
                log.warning("tg-mtproxy-client stop: %s" % e, source="tgproxy")
            log.info("tg-mtproxy-client: остановлен", source="tgproxy")
            return {"ok": True}

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            running = bool(self._proc and self._proc.poll() is None)
        # Состояние REDIRECT спрашиваем вне лока: это вызов nft/iptables,
        # держать на нём мьютекс менеджера незачем.
        redirect = {"active": False}
        try:
            from core import tgproxy_redirect
            redirect = tgproxy_redirect.status()
        except Exception:
            pass
        return {
            "running": running,
            "port": self._port if running else None,
            "host": self._host if running else None,
            "relay": self._relay if running else None,
            # Процесс без REDIRECT бесполезен (см. get_connect_info), и
            # это единственный способ увидеть такое состояние в GUI.
            "redirect_active": bool(redirect.get("active")),
            "redirect_backend": redirect.get("backend", ""),
        }

    def get_connect_info(self) -> dict[str, Any]:
        """Как подключаться к резервному движку.

        Ссылки tg://proxy здесь НЕТ и быть не может: в отличие от
        tg-ws-proxy, этот движок — не MTProto-прокси, а прозрачный
        форвардер. Он читает исходный адрес назначения через
        SO_ORIGINAL_DST (listener.go апстрима), то есть работает только с
        трафиком, завёрнутым на его порт правилом iptables/nft REDIRECT,
        и MTProto-рукопожатия не делает вовсе.

        Раньше мы отдавали сюда tg://proxy со случайным секретом — такая
        ссылка не работала бы ни при каких условиях: на этом порту никто
        не говорит по MTProto.

        Правила REDIRECT ставит и снимает сам менеджер (см. start/stop и
        core/tgproxy_redirect), поэтому настраивать вручную ничего не
        нужно — но если их почему-то нет, движок бесполезен, и это видно
        в поле `redirect_active`.
        """
        with self._lock:
            if not (self._proc and self._proc.poll() is None):
                return {"link": "", "error": "не запущен"}
            host = self._host or _lan_ip() or "127.0.0.1"
            port = self._port

        redirect = {"active": False}
        try:
            from core import tgproxy_redirect
            redirect = tgproxy_redirect.status()
        except Exception:
            pass

        if redirect.get("active"):
            note = ("Ничего настраивать не нужно: трафик к датацентрам "
                    "Telegram заворачивается на %s:%d автоматически "
                    "(%s)." % (host, port, redirect.get("backend", "")))
        else:
            note = ("Правила REDIRECT не активны — движок не получит ни "
                    "одного соединения. Перезапустите его; если не "
                    "помогло, смотрите лог: возможно, на этой прошивке "
                    "нет ни nft, ни iptables.")
        return {
            "link": "",
            "host": host,
            "port": port,
            "mode": "transparent",
            "redirect_active": bool(redirect.get("active")),
            "note": note,
        }


_mtproxy_instance = None
_mtproxy_lock = threading.Lock()


def get_mtproxy_client_manager() -> MtProxyClientManager:
    global _mtproxy_instance
    if _mtproxy_instance is None:
        with _mtproxy_lock:
            if _mtproxy_instance is None:
                _mtproxy_instance = MtProxyClientManager()
    return _mtproxy_instance


# ──────────────────────── общий фасад для API/GUI ──────────────────────


def get_active_engine_status() -> dict[str, Any]:
    """Статус обоих движков сразу — удобно для одной карточки в GUI,
    чтобы явно показывать, какой из двух реально активен (не должно
    быть активно два сразу — это две отдельные ссылки tg://proxy,
    приложение Telegram использует только одну)."""
    tgws = get_tgwsproxy_manager().get_status()
    mtp = get_mtproxy_client_manager().get_status()
    return {
        "tgwsproxy": tgws,
        "mtproto": mtp,
        "any_running": bool(tgws.get("running") or mtp.get("running")),
    }


# ──────────── маршрутизация Telegram DC через уже поднятый WARP ────────────
"""
Альтернатива CF-домену/CF-Worker: вместо отдельного выхода в интернет
через Cloudflare CDN, направить трафик к датацентрам Telegram через уже
работающий AWG+WARP или MASQUE(usque)+WARP туннель. Использует штатный
core.unified слой (проверено по исходникам applier.py: method="warp:<iface>"
и method="awg:<iface>" оба обрабатываются через _apply_tunnel() →
CidrRoutingRule — тот же зрелый механизм маршрутизации, что и во всём
остальном проекте, не новодел).

Не заменяет CF-домен, а дополняет — держите оба способа переключаемыми
на случай, если WARP-инфраструктура и CF-CDN-инфраструктура откажут не
одновременно (это два разных failure domain у Cloudflare).
"""

# Источник — https://core.telegram.org/resources/cidr.txt (та же
# выгрузка, что лежит в import/lists/ipset-telegram.txt). Раньше здесь
# не хватало 91.105.192.0/23 и 185.76.151.0/24: часть сессий уходила
# мимо туннеля, и обход выглядел «через раз».
#
# IPv6-диапазоны Telegram (2001:b28::/…, 2a0a:f280::/32) сознательно НЕ
# добавлены: CidrRoutingRule развернул бы их в `ip -6 rule`, а на
# IPv4-только туннеле (типичный WARP/AWG-профиль без IPv6 в AllowedIPs)
# default-route в таблице для v6 не создаётся — маршрут целиком
# отчитался бы ошибкой. Telegram работает по IPv4, если IPv6 у клиента
# не маршрутизируется.
TELEGRAM_DC_CIDRS = [
    "149.154.160.0/20",
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "185.76.151.0/24",
]

_DC_ROUTE_ID = "tgproxy-telegram-dc-via-tunnel"


def list_available_warp_tunnels() -> list[dict[str, Any]]:
    """Уже поднятые/сконфигурированные туннели, которые можно
    использовать как выход для Telegram DC-трафика. Каждый элемент:
    {"kind": "warp"|"awg", "iface": <имя интерфейса>, "label": <для GUI>,
     "running": bool}."""
    out = []

    try:
        from core.usque_manager import get_usque_manager

        umgr = get_usque_manager()
        for cfg in umgr.list_configs():
            iface = cfg.get("iface") or cfg.get("name", "")
            if not iface:
                continue
            st = umgr.status(iface)
            out.append(
                {
                    "kind": "warp",
                    "iface": iface,
                    "label": "MASQUE/usque: %s" % cfg.get("name", iface),
                    "running": bool(st.get("running")),
                }
            )
    except Exception as e:
        log.warning("list_available_warp_tunnels(usque): %s" % e, source="tgproxy")

    try:
        from core.awg_manager import get_awg_manager

        amgr = get_awg_manager()
        for cfg in amgr.list_configs():
            name = cfg.get("name", "")
            if not name:
                continue
            # Имя конфига ≠ имя интерфейса: `awg0-opkgtun0.conf` живёт на
            # интерфейсе `opkgtun0`. Маршрут строится по ИНТЕРФЕЙСУ —
            # раньше сюда уходило имя файла, и `ip rule` вешался на
            # несуществующий iface (правило навсегда оставалось
            # deferred), а «запущен/не запущен» определялось по нему же.
            iface = cfg.get("iface") or name
            out.append(
                {
                    "kind": "awg",
                    "iface": iface,
                    "label": ("AWG: %s" % name if iface == name
                              else "AWG: %s (%s)" % (name, iface)),
                    "running": bool(cfg.get("active") or amgr.is_running(iface)),
                }
            )
    except Exception as e:
        log.warning("list_available_warp_tunnels(awg): %s" % e, source="tgproxy")

    return out


def route_telegram_dc_via_tunnel(kind: str, iface: str) -> dict[str, Any]:
    """Направить CIDR-диапазоны датацентров Telegram через уже
    поднятый WARP-туннель (kind='warp' для MASQUE/usque, kind='awg'
    для AmneziaWG)."""
    if kind not in ("warp", "awg"):
        return {"ok": False, "error": "kind должен быть 'warp' или 'awg'"}

    # Взаимоисключающие механизмы на одних и тех же CIDR: REDIRECT
    # срабатывает в nat раньше, чем принимается решение о маршруте, —
    # пакет уйдёт на локальный порт и до туннеля не доедет. Молча
    # включить оба означало бы «настроил туннель, а он не используется».
    try:
        from core import tgproxy_redirect
        if tgproxy_redirect.status().get("active"):
            return {"ok": False,
                    "error": "Сейчас трафик Telegram заворачивается на "
                             "резервный движок (tg-mtproxy-client). "
                             "Остановите его — иначе до туннеля пакеты "
                             "не дойдут."}
    except Exception:
        pass
    iface = (iface or "").strip()
    if not iface:
        return {"ok": False, "error": "Не указан интерфейс туннеля"}
    # Имя интерфейса приходит с клиента и уходит в argv `ip rule` —
    # держим его в рамках того, что вообще может быть именем iface.
    if not re.match(r"^[A-Za-z0-9_.@-]{1,15}$", iface):
        return {"ok": False, "error": "Некорректное имя интерфейса: %s" % iface}

    try:
        from core.unified import manager as unified_manager

        result = unified_manager.save_route(
            {
                "id": _DC_ROUTE_ID,
                "name": "Telegram DC через %s-туннель (авто, tgproxy)" % kind,
                "destination": {"cidrs": TELEGRAM_DC_CIDRS},
                "method": "%s:%s" % (kind, iface),
            },
            apply=True,
        )
        if result.get("ok"):
            log.success(
                "tgproxy: Telegram DC направлены через %s:%s" % (kind, iface),
                source="tgproxy",
            )
        return result
    except Exception as e:
        return {"ok": False, "error": "core.unified недоступен: %s" % e}


def unroute_telegram_dc_via_tunnel() -> dict[str, Any]:
    """Снять маршрутизацию Telegram DC через туннель (вернуть на CF-домен
    / прямое подключение — в зависимости от того, что настроено в
    config.conf tg-ws-proxy-go)."""
    try:
        from core.unified import manager as unified_manager

        # Идемпотентно: «маршрута нет» — это уже нужное состояние, а не
        # ошибка. GUI дёргает снятие при каждом сохранении не-tunnel
        # режима, и ok:False там означал бы ложную ошибку.
        if unified_manager.get_route(_DC_ROUTE_ID) is None:
            return {"ok": True, "noop": True}
        return unified_manager.delete_route(_DC_ROUTE_ID)
    except Exception as e:
        return {"ok": False, "error": str(e)}
