# core/opera_proxy_manager.py
"""
Менеджер Opera Proxy (opera-proxy).

Standalone Opera VPN клиент: создаёт HTTP/SOCKS5 прокси-сервер,
направляющий трафик через SurfEasy VPN инфраструктуру Opera.

Zero-config: запустил → прокси работает.

Бинарник: Go, из Alexey71/opera-proxy.
Режимы: HTTP proxy (:18080) или SOCKS5 proxy.
Страны: EU, AS, AM.
"""

import os
import signal
import subprocess
import threading
import time

from core.log_buffer import log


class OperaProxyManager:
    """Singleton-менеджер Opera Proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._process = None

    # ─────── detect ───────

    def detect(self) -> dict:
        """Обнаружить opera-proxy binary."""
        binary = self._find_binary()
        if not binary:
            return {"installed": False, "binary": "", "version": ""}
        version = self._get_version(binary)
        countries = self._list_countries(binary)
        return {
            "installed": True,
            "binary": binary,
            "version": version,
            "countries": countries,
        }

    def _find_binary(self) -> str:
        candidates = [
            "/opt/usr/bin/opera-proxy",
            "/opt/bin/opera-proxy",
            "/usr/local/bin/opera-proxy",
            "/usr/bin/opera-proxy",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return ""

    def _get_version(self, binary: str) -> str:
        try:
            r = subprocess.run([binary, "-version"],
                               capture_output=True, text=True, timeout=5)
            return (r.stdout or r.stderr or "").strip()[:50]
        except Exception:
            return ""

    def _list_countries(self, binary: str) -> list:
        try:
            r = subprocess.run([binary, "-list-countries"],
                               capture_output=True, text=True, timeout=5)
            countries = []
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if "," in line and not line.startswith("country"):
                    code, name = line.split(",", 1)
                    countries.append({"code": code.strip(), "name": name.strip()})
            return countries
        except Exception:
            return []

    # ─────── lifecycle ───────

    def start(self, country: str = "EU", bind: str = "127.0.0.1:18080",
              socks_mode: bool = False, proxy_bypass: str = "",
              fake_sni: str = "", verbosity: int = 20) -> dict:
        """Запустить opera-proxy."""
        if self._is_running():
            return {"ok": False, "error": "Opera proxy уже запущен"}

        binary = self._find_binary()
        if not binary:
            return {"ok": False, "error": "opera-proxy не найден"}

        cmd = [binary, "-country", country, "-bind-address", bind]
        if socks_mode:
            cmd.append("-socks-mode")
        if proxy_bypass:
            cmd.extend(["-proxy-bypass", proxy_bypass])
        if fake_sni:
            cmd.extend(["-fake-SNI", fake_sni])
        cmd.extend(["-verbosity", str(verbosity)])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True)

            # Ждём запуска (до 5s)
            time.sleep(1)
            if proc.poll() is not None:
                out = ""
                try:
                    out = proc.stdout.read(4096).decode("utf-8", errors="replace")
                except Exception:
                    pass
                return {"ok": False, "error": "opera-proxy завершился: %s" % out[:200]}

            with self._lock:
                self._process = proc

            # Дренаж stdout в фоне: opera-proxy при verbosity<=20 логирует
            # каждое соединение. Без вычитывания OS-буфер пайпа (~64 КБ)
            # переполняется, child блокируется на write() и перестаёт
            # форвардить трафик («прокси завис»). Пишем в никуда.
            def _drain(pipe):
                try:
                    for _ in iter(lambda: pipe.read(4096), b""):
                        pass
                except Exception:
                    pass
            t = threading.Thread(target=_drain, args=(proc.stdout,),
                                 daemon=True, name="opera-proxy-drain")
            t.start()

            try:
                from core.opera_proxy_watchdog import get_opera_proxy_watchdog
                get_opera_proxy_watchdog().reset()
            except Exception:
                pass

            log.info("opera-proxy: запущен (country=%s, bind=%s)"
                     % (country, bind), source="opera_proxy")
            return {"ok": True, "pid": proc.pid, "bind": bind,
                    "country": country}

        except Exception as e:
            return {"ok": False, "error": str(e)}

    def stop(self) -> dict:
        """Остановить opera-proxy."""
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
                    try:
                        proc.wait(timeout=1)
                    except Exception:
                        pass
                except Exception:
                    pass

        log.info("opera-proxy: остановлен", source="opera_proxy")
        return {"ok": True}

    def status(self) -> dict:
        """Статус opera-proxy."""
        running = self._is_running()
        pid = None
        with self._lock:
            if self._process:
                pid = self._process.pid
        return {
            "running": running,
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


def get_opera_proxy_manager() -> OperaProxyManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = OperaProxyManager()
    return _instance
