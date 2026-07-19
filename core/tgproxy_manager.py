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
import secrets
import shlex
import socket
import subprocess
import threading
import time
from typing import Any

from core.log_buffer import log


# ─────────────────────────── tg-ws-proxy-go ───────────────────────────

TGWSPROXY_CONFIG_DIR = "/opt/etc/tg-ws-proxy"
TGWSPROXY_CONFIG_FILE = os.path.join(TGWSPROXY_CONFIG_DIR, "config.conf")
TGWSPROXY_SECRET_FILE = os.path.join(TGWSPROXY_CONFIG_DIR, "secret.conf")
TGWSPROXY_INITD_CANDIDATES = [
    "/opt/etc/init.d/S99tg-ws-proxy",
    "/etc/init.d/S99tg-ws-proxy",
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
# управляется через EXTRA_ARGS (--cf-domain=.../--cf-worker-domain=...),
# а распарсить их обратно из EXTRA_ARGS ненадёжно (могут быть смешаны с
# другими ручными флагами пользователя). Отдельные X_-поля — источник
# истины для GUI, EXTRA_ARGS — то, что реально передаётся бинарнику.
_TGWSPROXY_CONFIG_KEYS = [
    "HOST",
    "PORT",
    "LOG_LEVEL",
    "DC_IP_DEFAULT",
    "DC_IP_DEFAULT_POOL",
    "FAKE_TLS_DOMAIN",
    "CFPROXY_DOMAINS",
    "CFPROXY_DOMAINS_URL",
    "EXTRA_ARGS",
    "X_CF_DOMAIN",
    "X_CF_WORKER_DOMAIN",
]


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


def _shell_quote_value(v: str) -> str:
    v = str(v or "")
    return '"%s"' % v.replace("\\", "\\\\").replace('"', '\\"')


def _write_kv_conf(path: str, values: dict[str, str], keys_order: list[str]) -> None:
    lines = []
    for k in keys_order:
        v = values.get(k, "")
        lines.append("%s=%s" % (k, _shell_quote_value(v)))
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
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
        return {
            "installed": installed,
            "path": initd,
            "config_exists": os.path.isfile(TGWSPROXY_CONFIG_FILE),
            "package": "tg-ws-proxy",
            "version": _pkg_version("tg-ws-proxy") if installed else "",
        }

    def get_config(self) -> dict[str, Any]:
        cfg = _read_kv_conf(TGWSPROXY_CONFIG_FILE)
        secret_cfg = _read_kv_conf(TGWSPROXY_SECRET_FILE)
        return {
            "host": cfg.get("HOST", "0.0.0.0"),
            "port": int(cfg.get("PORT") or 1443),
            "log_level": cfg.get("LOG_LEVEL", "0"),
            "dc_ip_default": cfg.get("DC_IP_DEFAULT", ""),
            "dc_ip_default_pool": cfg.get("DC_IP_DEFAULT_POOL", ""),
            "fake_tls_domain": cfg.get("FAKE_TLS_DOMAIN", ""),
            "cf_domain": cfg.get("X_CF_DOMAIN", ""),
            "cf_worker_domain": cfg.get("X_CF_WORKER_DOMAIN", ""),
            "cfproxy_domains": cfg.get("CFPROXY_DOMAINS", ""),
            "cfproxy_domains_url": cfg.get(
                "CFPROXY_DOMAINS_URL", _DEFAULT_CFPROXY_DOMAINS_URL
            ),
            "extra_args": cfg.get("EXTRA_ARGS", ""),
            "secret": secret_cfg.get("SECRET", ""),
        }

    def save_config(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 1443,
        dc_ip_default: str = "",
        dc_ip_default_pool: str = "",
        fake_tls_domain: str = "",
        cf_domain: str = "",
        cf_worker_domain: str = "",
        cfproxy_domains: str = "",
        cfproxy_domains_url: str = "",
        extra_args: str = "",
        secret: str = "",
        log_level: str = "0",
    ) -> dict[str, Any]:
        """Сохранить config.conf/secret.conf.

        cf_domain / cf_worker_domain — свой домен под CF-прокси (обычный
        Cloudflare CDN, "оранжевое облако") / CF-Worker соответственно.
        Точные имена CLI-флагов для них у конкретной версии бинарника
        стоит свериться через `tg-ws-proxy-go --help` — здесь они
        передаются через EXTRA_ARGS, а не как отдельные первоклассные
        поля config.conf, потому что я не могу подтвердить их точное
        название без доступа к самому бинарнику; ниже — наиболее
        вероятные по документации проекта имена, ПРОВЕРЬТЕ перед
        продакшн-использованием.
        """
        if not secret:
            secret = secrets.token_hex(16)  # 32 hex chars

        extra = (extra_args or "").strip()
        extra_parts = shlex.split(extra) if extra else []
        if cf_domain:
            extra_parts += ["--cfproxy-domain=%s" % cf_domain]
        if cf_worker_domain:
            extra_parts += ["--cfproxy-worker-domain=%s" % cf_worker_domain]
        extra = " ".join(shlex.quote(p) for p in extra_parts)

        os.makedirs(TGWSPROXY_CONFIG_DIR, exist_ok=True)

        _write_kv_conf(
            TGWSPROXY_CONFIG_FILE,
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
                "EXTRA_ARGS": extra,
                "X_CF_DOMAIN": cf_domain,
                "X_CF_WORKER_DOMAIN": cf_worker_domain,
            },
            _TGWSPROXY_CONFIG_KEYS,
        )

        _write_kv_conf(TGWSPROXY_SECRET_FILE, {"SECRET": secret}, ["SECRET"])
        try:
            os.chmod(TGWSPROXY_SECRET_FILE, 0o600)
        except OSError:
            pass

        active_cf_domain = cf_domain or cf_worker_domain
        if active_cf_domain:
            self._register_cf_domain_for_nfqws(active_cf_domain)

        return {"ok": True, "secret": secret}

    # ─────── nfqws2 hook (best-effort, см. docstring файла) ───────

    def _register_cf_domain_for_nfqws(self, domain: str) -> None:
        """Зарегистрировать явно заданный CF-домен как цель nfqws2 через
        core.unified.manager (реальный, проверенный API этого проекта —
        не выдуманный). Только для явно указанного пользователем
        домена — для дефолтного community-пула это не делается (см.
        docstring файла, почему)."""
        try:
            from core.unified import manager as unified_manager

            result = unified_manager.save_route(
                {
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
                return {"ok": False, "error": "Нет config.conf — сначала save_config()"}

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
            via_initd = r.returncode == 0 and ("running" in out or "active" in out)
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Дублируем независимой проверкой порта — тот же принцип, что и
        # в init.d-статусе других сервисов: не доверять единственному
        # источнику истины.
        cfg = self.get_config()
        port_open = self._port_listening(cfg.get("port", 1443))

        return {
            "installed": True,
            "running": via_initd or port_open,
            "port": cfg.get("port"),
            "host": cfg.get("host"),
        }

    def _port_listening(self, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            r = s.connect_ex(("127.0.0.1", int(port)))
            s.close()
            return r == 0
        except OSError:
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
MTPROXY_DEFAULT_RELAY = "wss://213.176.74.63.nip.io/ws"
MTPROXY_LOCAL_PORT = 1443


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

    def detect(self) -> dict[str, Any]:
        bin_path = _find_mtproxy_binary()
        return {"installed": bool(bin_path), "path": bin_path}

    def start(
        self,
        *,
        port: int = MTPROXY_LOCAL_PORT,
        relay: str = MTPROXY_DEFAULT_RELAY,
        secret: str = "",
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

            secret = secret or secrets.token_hex(16)

            args = [
                bin_path,
                "--listen",
                "127.0.0.1:%d" % port,
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
            log.success(
                "tg-mtproxy-client: запущен (relay=%s, port=%d)" % (relay, port),
                source="tgproxy",
            )
            return {"ok": True, "secret": secret, "port": port}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            self._proc = None
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
            return {
                "running": running,
                "port": self._port if running else None,
                "relay": self._relay if running else None,
            }

    def get_connect_info(self) -> dict[str, Any]:
        with self._lock:
            if not (self._proc and self._proc.poll() is None):
                return {"link": "", "error": "не запущен"}
            host = _lan_ip() or "127.0.0.1"
            link = _build_proxy_link(host, self._port, self._secret)
            return {"link": link, "host": host, "port": self._port}


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

TELEGRAM_DC_CIDRS = [
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
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
            out.append(
                {
                    "kind": "awg",
                    "iface": name,
                    "label": "AWG: %s" % name,
                    "running": bool(amgr.is_running(name)),
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
    if not iface:
        return {"ok": False, "error": "Не указан интерфейс туннеля"}

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

        return unified_manager.delete_route(_DC_ROUTE_ID)
    except Exception as e:
        return {"ok": False, "error": str(e)}
