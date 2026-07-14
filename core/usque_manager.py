# core/usque_manager.py
"""
Менеджер WARP/MASQUE (usque-keenetic).

Управление Cloudflare WARP через usque (MASQUE-протокол).
Usque тянется как бинарник из side-effect-tm/usque-keenetic —
по аналогии с sing-box из SagerNet/sing-box.

Лайфцикл:
  1. Регистрация сессии: usque register --accept-tos --config <path>
  2. Запуск туннеля: usque nativetun --config <session> --interface-name <iface> --no-iproute2
  3. TUN-интерфейс создаётся через ndmc (Keenetic CLI) или ip (Linux)
"""

import os
import re
import signal
import subprocess
import threading
import time

from core.log_buffer import log


_VALID_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")


class UsqueManager:
    """Singleton-менеджер WARP/MASQUE туннелей."""

    def __init__(self):
        self._lock = threading.Lock()
        self._processes = {}  # iface -> subprocess.Popen
        self._pid_dir = "/opt/var/run"

    # ─────── detect ───────

    def detect(self) -> dict:
        """Определить установлен ли usque, версию, архитектуру."""
        binary = self._find_binary()
        if not binary:
            return {"installed": False, "binary": "", "version": "",
                    "arch": ""}

        version = self._get_version(binary)
        arch = self._get_arch(binary)
        return {
            "installed": True,
            "binary": binary,
            "version": version,
            "arch": arch,
        }

    def _find_binary(self) -> str:
        """Поиск бинарника usque в стандартных путях."""
        candidates = [
            "/opt/usr/bin/usque",
            "/opt/bin/usque",
            "/usr/local/bin/usque",
            "/usr/bin/usque",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return ""

    def _get_version(self, binary: str) -> str:
        try:
            r = subprocess.run([binary, "--version"],
                               capture_output=True, text=True, timeout=5)
            # usque выводит версию в stderr или stdout
            out = (r.stdout or "") + (r.stderr or "")
            # Ищем паттерн типа "1.2.3" или "v1.2.3"
            m = re.search(r"v?(\d+\.\d+\.\d+)", out)
            return m.group(1) if m else out.strip()[:50]
        except Exception:
            return ""

    def _get_arch(self, binary: str) -> str:
        try:
            r = subprocess.run(["file", binary],
                               capture_output=True, text=True, timeout=5)
            out = (r.stdout or "").lower()
            if "aarch64" in out or "arm64" in out:
                return "aarch64"
            if "mipsel" in out or "mips" in out:
                return "mipsel" if "little" in out or "mipsel" in out else "mips"
            if "x86-64" in out or "x86_64" in out:
                return "x86_64"
            if "arm" in out:
                return "armv7"
        except Exception:
            pass
        return ""

    # ─────── session management ───────

    def register(self, config_path: str) -> dict:
        """Зарегистрировать новую WARP-сессию."""
        binary = self._find_binary()
        if not binary:
            return {"ok": False, "error": "usque не установлен"}

        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        try:
            r = subprocess.run(
                [binary, "register", "--accept-tos", "--config", config_path],
                capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return {"ok": False, "error": r.stderr or r.stdout or "ошибка регистрации"}
            return {"ok": True, "config_path": config_path}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "таймаут регистрации (30s)"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def list_configs(self) -> list:
        """Список доступных конфигов/сессий."""
        config_dir = self._config_dir()
        if not os.path.isdir(config_dir):
            return []
        out = []
        for fn in sorted(os.listdir(config_dir)):
            if fn.endswith(".conf") or fn.endswith(".toml"):
                path = os.path.join(config_dir, fn)
                name = fn.rsplit(".", 1)[0]
                iface = self._detect_iface_for_config(path)
                active = iface and self._is_running(iface)
                out.append({
                    "name": name,
                    "path": path,
                    "iface": iface,
                    "active": active,
                })
        return out

    def _config_dir(self) -> str:
        from core.platform_dirs import config_dir as platform_config_dir
        return os.path.join(platform_config_dir(), "usque")

    def _detect_iface_for_config(self, config_path: str) -> str:
        """Определить имя интерфейса для конфига (best-effort)."""
        # Проверяем running config если есть
        run_path = config_path + ".run"
        if os.path.isfile(run_path):
            try:
                with open(run_path) as f:
                    for line in f:
                        if line.startswith("IFACE="):
                            return line.split("=", 1)[1].strip().strip('"')
            except Exception:
                pass
        # Fallback: opkgtun0
        return "opkgtun0"

    # ─────── lifecycle ───────

    def start(self, iface: str, config_path: str, *, sni: str = "",
              http2: bool = False) -> dict:
        """Запустить WARP туннель."""
        binary = self._find_binary()
        if not binary:
            return {"ok": False, "error": "usque не установлен"}

        if not os.path.isfile(config_path):
            return {"ok": False, "error": "Конфиг не найден: %s" % config_path}

        if self._is_running(iface):
            return {"ok": False, "error": "Туннель %s уже запущен" % iface}

        # Строим команду
        cmd = [binary, "nativetun",
               "--config", config_path,
               "--interface-name", iface,
               "--no-iproute2"]
        if sni:
            cmd.extend(["-s", sni])
        if http2:
            cmd.append("--http2")

        pid_path = self._pid_path(iface)
        os.makedirs(os.path.dirname(pid_path), exist_ok=True)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True)

            # Ждём создания TUN-интерфейса (до 5s)
            for _ in range(50):
                time.sleep(0.1)
                if self._check_iface_up(iface):
                    break

            # Сохраняем PID
            try:
                with open(pid_path, "w") as f:
                    f.write(str(proc.pid))
            except Exception:
                pass

            with self._lock:
                self._processes[iface] = proc

            log.info("usque: туннель %s запущен (pid=%d)" % (iface, proc.pid),
                     source="usque")
            return {"ok": True, "pid": proc.pid, "iface": iface}

        except Exception as e:
            return {"ok": False, "error": str(e)}

    def stop(self, iface: str) -> dict:
        """Остановить WARP туннель."""
        pid_path = self._pid_path(iface)
        pid = self._read_pid(pid_path)

        # Пробуем остановить через stored process
        proc = None
        with self._lock:
            proc = self._processes.pop(iface, None)

        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        elif pid:
            # Fallback: kill по PID
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                pass

        # Удаляем PID-файл
        try:
            if os.path.isfile(pid_path):
                os.remove(pid_path)
        except Exception:
            pass

        log.info("usque: туннель %s остановлен" % iface, source="usque")
        return {"ok": True}

    def status(self, iface: str) -> dict:
        """Статус туннеля."""
        running = self._is_running(iface)
        pid = self._read_pid(self._pid_path(iface))
        return {
            "running": running,
            "iface": iface,
            "pid": pid,
        }

    def _is_running(self, iface: str) -> bool:
        """Проверить, работает ли процесс."""
        with self._lock:
            proc = self._processes.get(iface)
            if proc and proc.poll() is None:
                return True

        pid = self._read_pid(self._pid_path(iface))
        if pid:
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                pass
            except PermissionError:
                return True  # есть процесс, нет прав на kill
        return False

    def _check_iface_up(self, iface: str) -> bool:
        """Проверить, поднят ли интерфейс."""
        try:
            r = subprocess.run(["ip", "link", "show", iface],
                               capture_output=True, timeout=2)
            return r.returncode == 0 and "UP" in (r.stdout or "")
        except Exception:
            return False

    def _pid_path(self, iface: str) -> str:
        return os.path.join(self._pid_dir, "usque-%s.pid" % iface)

    def _read_pid(self, path: str) -> int:
        try:
            with open(path) as f:
                v = f.read().strip()
            return int(v) if v.isdigit() else None
        except Exception:
            return None


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_usque_manager() -> UsqueManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = UsqueManager()
    return _instance
