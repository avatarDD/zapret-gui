# core/tgproxy_manager.py
"""
Менеджер Telegram MTProto Proxy.

Два движка, оба работают "из коробки" на роутере:

  teleproxy (C) — Direct-to-DC на роутере, nfqws2 обходит DPI.
                  Без VPS. Только ARM64.

  tg-mtproxy-client (Go) — Go-клиент + relay.
                           relay: VPS, Cloudflare Worker, или локальный (LAN).
                           Все архитектуры включая MIPS.

Telegram DC CIDRs (общие для обоих):
  149.154.160.0/20
  91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22
  91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22
"""

import os
import re
import signal
import subprocess
import threading
import time

from core.log_buffer import log


# Telegram DC CIDRs для iptables REDIRECT
TELEGRAM_DC_CIDRS = [
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
]

CHAIN_NAME = "TG_TRANSPARENT"


class TgProxyManager:
    """Singleton-менеджер Telegram MTProto Proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._process = None
        self._engine = None  # "teleproxy" | "mtproto"

    # ─────── detect ───────

    def detect(self) -> dict:
        """Определить доступные движки и текущий статус."""
        arch = self._get_arch()
        teleproxy = self._detect_teleproxy()
        mtproto = self._detect_mtproto()

        # Автовыбор: ARM64 → teleproxy, иначе → mtproto
        if arch == "aarch64" and teleproxy.get("installed"):
            selected = "teleproxy"
        elif mtproto.get("installed"):
            selected = "mtproto"
        elif teleproxy.get("installed"):
            selected = "teleproxy"
        else:
            selected = ""

        return {
            "arch": arch,
            "engines": {
                "teleproxy": teleproxy,
                "mtproto": mtproto,
            },
            "selected": selected,
            "running": self._is_running(),
        }

    def _get_arch(self) -> str:
        try:
            r = subprocess.run(["uname", "-m"], capture_output=True, text=True, timeout=5)
            m = (r.stdout or "").strip().lower()
            if "aarch64" in m or "arm64" in m:
                return "aarch64"
            if "x86_64" in m or "x86-64" in m:
                return "x86_64"
            if "mipsel" in m:
                return "mipsel"
            if "mips" in m:
                return "mips"
            if "armv7" in m or "arm" in m:
                return "armv7"
        except Exception:
            pass
        return ""

    def _detect_teleproxy(self) -> dict:
        """Обнаружить teleproxy binary."""
        candidates = [
            "/opt/usr/bin/teleproxy",
            "/opt/bin/teleproxy",
            "/usr/local/bin/teleproxy",
            "/usr/bin/teleproxy",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                version = self._get_version(p)
                return {"installed": True, "binary": p, "version": version}
        return {"installed": False, "binary": "", "version": ""}

    def _detect_mtproto(self) -> dict:
        """Обнаружить tg-mtproxy-client binary."""
        candidates = [
            "/opt/sbin/tg-mtproxy-client",
            "/opt/usr/sbin/tg-mtproxy-client",
            "/opt/bin/tg-mtproxy-client",
            "/usr/local/bin/tg-mtproxy-client",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                version = self._get_version(p)
                return {"installed": True, "binary": p, "version": version}
        return {"installed": False, "binary": "", "version": ""}

    def _get_version(self, binary: str) -> str:
        try:
            r = subprocess.run([binary, "--version"],
                               capture_output=True, text=True, timeout=5)
            out = (r.stdout or r.stderr or "").strip()
            return out[:50] if out else ""
        except Exception:
            return ""

    # ─────── engine selection ───────

    def select_engine(self, engine: str) -> dict:
        """Выбрать движок (teleproxy | mtproto | auto)."""
        if engine not in ("auto", "teleproxy", "mtproto"):
            return {"ok": False, "error": "Неизвестный движок: %s" % engine}
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("tgproxy", "engine", engine)
        cm.save()
        return {"ok": True, "engine": engine}

    def _resolve_engine(self, preferred: str = "") -> str:
        """Определить какой движок использовать."""
        if preferred and preferred != "auto":
            return preferred
        detect = self.detect()
        return detect.get("selected", "")

    # ─────── iptables management ───────

    def _setup_iptables(self, port: int) -> dict:
        """Создать iptables REDIRECT правила для Telegram DC."""
        try:
            # Загружаем модуль если нужно
            subprocess.run(["modprobe", "xt_REDIRECT"], capture_output=True, timeout=5)

            # Удаляем старую цепочку если есть
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING",
                            "-j", CHAIN_NAME],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-F", CHAIN_NAME],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-X", CHAIN_NAME],
                           capture_output=True, timeout=5)

            # Создаём новую цепочку
            r = subprocess.run(["iptables", "-t", "nat", "-N", CHAIN_NAME],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0 and "already exists" not in (r.stderr or ""):
                return {"ok": False, "error": "iptables -N: %s" % r.stderr}

            # Добавляем REDIRECT правила для каждого CIDR
            for cidr in TELEGRAM_DC_CIDRS:
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", CHAIN_NAME,
                     "-d", cidr, "-p", "tcp", "-j", "REDIRECT",
                     "--to-ports", str(port)],
                    capture_output=True, timeout=5)

            # Вставляем цепочку в PREROUTING
            r = subprocess.run(
                ["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                 "-j", CHAIN_NAME],
                capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return {"ok": False, "error": "iptables -I: %s" % r.stderr}

            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _teardown_iptables(self) -> dict:
        """Удалить iptables REDIRECT правила."""
        try:
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING",
                            "-j", CHAIN_NAME],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-F", CHAIN_NAME],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-X", CHAIN_NAME],
                           capture_output=True, timeout=5)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ─────── lifecycle ───────

    def start(self, engine: str = "", port: int = 9443,
              secret: str = "", domain: str = "",
              tunnel_url: str = "", tunnel_secret: str = "",
              direct_dc: bool = True) -> dict:
        """Запустить Telegram proxy.

        Два режима "из коробки" (без VPS):
          teleproxy  — Direct-to-DC на роутере, nfqws2 обходит DPI
          mtproto    — Go-клиент + локальный relay на роутере (LAN only)
        """
        if self._is_running():
            return {"ok": False, "error": "Telegram proxy уже запущен"}

        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        engine = self._resolve_engine(engine or cfg.get("tgproxy", "engine", default="auto"))
        if not engine:
            return {"ok": False, "error": "Нет доступных движков. Установите teleproxy или tg-mtproxy-client."}

        port = port or cfg.get("tgproxy", "port", default=9443)
        secret = secret or cfg.get("tgproxy", "teleproxy_secret", default="")
        domain = domain or cfg.get("tgproxy", "teleproxy_domain", default="")
        tunnel_url = tunnel_url or cfg.get("tgproxy", "tunnel_url", default="")
        tunnel_secret = tunnel_secret or cfg.get("tgproxy", "tunnel_secret", default="")
        direct_dc = cfg.get("tgproxy", "teleproxy_direct_dc", default=True) if direct_dc is None else direct_dc

        # Настраиваем iptables
        fw_result = self._setup_iptables(port)
        if not fw_result.get("ok"):
            return {"ok": False, "error": "iptables: %s" % fw_result.get("error")}

        # Запускаем движок
        if engine == "teleproxy":
            result = self._start_teleproxy(port, secret, domain, direct_dc)
        else:
            result = self._start_mtproto(port, tunnel_url, tunnel_secret)

        if not result.get("ok"):
            self._teardown_iptables()
            return result

        self._engine = engine
        log.info("telegram-proxy: запущен (%s, port=%d)" % (engine, port),
                 source="tgproxy")
        return {"ok": True, "engine": engine, "port": port}

    def _start_teleproxy(self, port: int, secret: str, domain: str,
                         direct_dc: bool) -> dict:
        """Запустить teleproxy."""
        detect = self._detect_teleproxy()
        binary = detect.get("binary")
        if not binary:
            return {"ok": False, "error": "teleproxy не найден"}

        if not secret:
            # Генерируем секрет если не задан
            import secrets
            secret = secrets.token_hex(16)

        cmd = [binary, "-S", secret, "-H", str(port)]
        if direct_dc:
            cmd.append("--direct")
        if domain:
            cmd.extend(["-D", domain])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True)

            with self._lock:
                self._process = proc

            # Ждём запуска (до 3s)
            time.sleep(0.5)
            if proc.poll() is not None:
                out = ""
                try:
                    out = proc.stdout.read(4096).decode("utf-8", errors="replace")
                except Exception:
                    pass
                return {"ok": False, "error": "teleproxy завершился: %s" % out[:200]}

            return {"ok": True, "pid": proc.pid}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _start_mtproto(self, port: int, tunnel_url: str,
                       tunnel_secret: str) -> dict:
        """Запустить tg-mtproxy-client.

        Relay по умолчанию: wss://213.176.74.63.nip.io/ws (z2k community relay).
        Можно заменить на свой VPS или Cloudflare Worker.
        """
        detect = self._detect_mtproto()
        binary = detect.get("binary")
        if not binary:
            return {"ok": False, "error": "tg-mtproxy-client не найден"}

        # Relay по умолчанию — z2k community relay (бесплатный, без VPS)
        if not tunnel_url:
            tunnel_url = "wss://213.176.74.63.nip.io/ws"

        if not tunnel_url:
            return {"ok": False, "error": "tunnel_url обязателен для mtproto"}

        cmd = [binary, "-port", str(port), "-host", "0.0.0.0"]
        if tunnel_url:
            cmd.extend(["-tunnel", tunnel_url])
        if tunnel_secret:
            cmd.extend(["-secret", tunnel_secret])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True)

            with self._lock:
                self._process = proc

            time.sleep(0.5)
            if proc.poll() is not None:
                out = ""
                try:
                    out = proc.stdout.read(4096).decode("utf-8", errors="replace")
                except Exception:
                    pass
                return {"ok": False, "error": "mtproto завершился: %s" % out[:200]}

            return {"ok": True, "pid": proc.pid}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def stop(self) -> dict:
        """Остановить Telegram proxy."""
        # Убираем iptables
        self._teardown_iptables()

        # Убиваем процесс
        proc = None
        with self._lock:
            proc = self._process
            self._process = None

        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        self._engine = None
        log.info("telegram-proxy: остановлен", source="tgproxy")
        return {"ok": True}

    def status(self) -> dict:
        """Статус Telegram proxy."""
        running = self._is_running()
        engine = self._engine or ""
        pid = None
        with self._lock:
            if self._process:
                pid = self._process.pid
        return {
            "running": running,
            "engine": engine,
            "pid": pid,
        }

    def _is_running(self) -> bool:
        with self._lock:
            proc = self._process
        if proc and proc.poll() is None:
            return True
        return False


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_tgproxy_manager() -> TgProxyManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TgProxyManager()
    return _instance
