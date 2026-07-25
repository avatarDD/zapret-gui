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


def start_kwargs_from_config(cfg=None) -> dict:
    """
    Полный набор параметров запуска из настроек.

    Заведён, чтобы все три пути старта (API, автозапуск при загрузке,
    рестарт watchdog'ом) использовали ОДИН источник. Раньше они
    расходились: boot-автозапуск передавал только country/bind/socks_mode,
    и после перезагрузки прокси поднимался без fake_sni, proxy_bypass и
    verbosity — то есть без анти-DPI маскировки, ровно там, где она и
    нужна. Watchdog терял verbosity.
    """
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    return {
        "country": cfg.get("opera_proxy", "country", default="EU"),
        "bind": cfg.get("opera_proxy", "bind", default="127.0.0.1:18080"),
        "socks_mode": cfg.get("opera_proxy", "socks_mode", default=False),
        "proxy_bypass": cfg.get("opera_proxy", "proxy_bypass", default=""),
        "fake_sni": cfg.get("opera_proxy", "fake_sni", default=""),
        "verbosity": cfg.get("opera_proxy", "verbosity", default=20),
    }


class OperaProxyManager:
    """Singleton-менеджер Opera Proxy."""

    def __init__(self):
        self._lock = threading.Lock()
        self._process = None

    # ─────── pid-файл ───────
    #
    # Без него запущенный прокси «терялся» при перезапуске GUI: _is_running()
    # смотрел только на объект процесса в памяти, поэтому status() показывал
    # «остановлен», stop() ничего не убивал, а watchdog бесконечно пытался
    # поднять второй экземпляр на занятый порт.

    def _pid_path(self) -> str:
        from core.platform_dirs import config_dir
        return os.path.join(config_dir(), "opera-proxy.pid")

    def _write_pid(self, pid: int) -> None:
        try:
            path = self._pid_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(str(pid))
        except OSError:
            pass

    def _read_pid(self):
        try:
            with open(self._pid_path()) as f:
                v = f.read().strip()
            return int(v) if v.isdigit() else None
        except (OSError, ValueError):
            return None

    def _clear_pid(self) -> None:
        try:
            os.remove(self._pid_path())
        except OSError:
            pass

    def _pid_is_opera(self, pid: int) -> bool:
        """Наш ли это процесс. /proc недоступен → доверяем."""
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            return True
        return "opera-proxy" in cmd.lower() if cmd.strip() else True

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
            self._write_pid(proc.pid)

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
        else:
            # Объекта процесса нет (GUI перезапускали) — гасим по pid-файлу,
            # иначе прокси остался бы работать, а кнопка «Остановить»
            # молча ничего не делала.
            pid = self._read_pid()
            if pid and self._pid_is_opera(pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                    for _ in range(30):
                        time.sleep(0.1)
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            break
                    else:
                        os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass

        self._clear_pid()
        log.info("opera-proxy: остановлен", source="opera_proxy")
        return {"ok": True}

    def status(self) -> dict:
        """Статус opera-proxy."""
        running = self._is_running()
        pid = None
        with self._lock:
            if self._process:
                pid = self._process.pid
        if pid is None:
            pid = self._read_pid()      # пережил перезапуск GUI
        return {
            "running": running,
            "pid": pid if running else None,
        }

    def _is_running(self) -> bool:
        with self._lock:
            proc = self._process
        if proc and proc.poll() is None:
            return True
        # Процесс мог быть запущен до перезапуска GUI — тогда объекта в
        # памяти нет, но сам прокси работает. Сверяем pid-файл, проверяя
        # принадлежность PID (файл лежит в /opt и переживает перезагрузку,
        # так что чужой PID вполне возможен).
        pid = self._read_pid()
        if pid:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                self._clear_pid()
                return False
            except PermissionError:
                return True
            except OSError:
                return False
            if self._pid_is_opera(pid):
                return True
            self._clear_pid()
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
