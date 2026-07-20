# core/usque_manager.py
"""
Менеджер WARP/MASQUE (usque-keenetic).

Управление Cloudflare WARP через usque (MASQUE-протокол).
Usque тянется как бинарник из side-effect-tm/usque-keenetic —
по аналогии с sing-box из SagerNet/sing-box.

Лайфцикл:
  1. Регистрация сессии: usque register --accept-tos --config <path>
    2. Запуск туннеля: usque nativetun --config <session> --interface-name <iface> --no-iproute2
       (по желанию --http2 для H2/TCP и --keepalive-period 10s)
  3. TUN-интерфейс создаётся через ndmc (Keenetic CLI) или ip (Linux)
"""

import os
import io
import re
import signal
import subprocess
import threading
import time
from collections import deque

from core.log_buffer import log


_VALID_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")
_IFACE_PREFIX_RE = re.compile(r"^[a-zA-Z0-9_-]{1,12}$")
_MAX_DIAGNOSTIC_LINES = 40


class UsqueManager:
    """Singleton-менеджер WARP/MASQUE туннелей."""

    def __init__(self):
        # start() calls _is_running() while holding the lifecycle lock.
        # A re-entrant lock avoids the deterministic self-deadlock that
        # occurred with threading.Lock().
        self._lock = threading.RLock()
        self._processes = {}  # iface -> subprocess.Popen
        self._config_by_iface = {}
        self._stderr = {}  # iface -> deque[str]
        self._stderr_threads = {}
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
        # No fixed fallback: an unknown interface must not be shown as active.
        return ""

    def allocate_iface(self, prefix: str = "opkgtun", reserved=None) -> str:
        """Allocate a free interface name without relying on fixed W-I-W names."""
        prefix = str(prefix or "opkgtun")[:12]
        if not _IFACE_PREFIX_RE.match(prefix):
            prefix = "opkgtun"
        reserved = set(reserved or ())
        with self._lock:
            used = set(self._processes) | reserved
            try:
                used.update(os.listdir("/sys/class/net"))
            except OSError:
                pass
            for n in range(0, 1000):
                name = "%s%d" % (prefix, n)
                if len(name) > 15:
                    continue
                pid_path = self._pid_path(name)
                if name not in used and not os.path.exists(pid_path):
                    return name
        return ""

    def _capture_stderr(self, iface: str, stream) -> None:
        if not isinstance(stream, (io.TextIOBase, io.BufferedIOBase)):
            return
        buf = self._stderr.setdefault(iface, deque(maxlen=_MAX_DIAGNOSTIC_LINES))
        try:
            for line in iter(stream.readline, ""):
                line = (line or "").rstrip()
                if line:
                    buf.append(line[-400:])
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _diagnostic(self, iface: str) -> str:
        lines = list(self._stderr.get(iface) or ())
        return "\n".join(lines[-8:])

    # ─────── lifecycle ───────

    def start(self, iface: str, config_path: str, *, sni: str = "",
              http2: bool = False, transport_profile: str = "performance",
              low_latency: bool = True, apply_optimizer: bool = True) -> dict:
        """Запустить WARP туннель.

        Args:
            transport_profile: performance (H3/QUIC), restricted (H2/TCP)
                или auto (H3 с fallback на H2 при подтверждённом сбое).
            low_latency: включить безопасный keepalive usque. TCP_NODELAY
                         не является параметром usque CLI, а глобальные
                         buffer sysctl здесь намеренно не меняются.
        """
        if not _VALID_IFACE_RE.match(iface):
            return {"ok": False, "error": "Неверное имя интерфейса: %s" % iface}

        binary = self._find_binary()
        if not binary:
            return {"ok": False, "error": "usque не установлен"}

        if not os.path.isfile(config_path):
            return {"ok": False, "error": "Конфиг не найден: %s" % config_path}
        if transport_profile not in ("performance", "restricted", "auto"):
            return {"ok": False, "error": "Неизвестный transport_profile: %s" % transport_profile}
        if http2:
            transport_profile = "restricted"

        # MR-13: Берем lock вокруг всего start() чтобы избежать race condition
        # когда два конкурентных запроса проходят проверку is_running и спавнят процессы
        with self._lock:
            if self._is_running(iface):
                return {"ok": False, "error": "Туннель %s уже запущен" % iface}

            # Строим команду. H3/QUIC — default usque; --http2 только для
            # restricted-профиля, чтобы случайно не запускать H2 внутри H2.
            cmd = [binary, "nativetun",
                   "--config", config_path,
                   "--interface-name", iface,
                   "--no-iproute2"]
            if sni:
                cmd.extend(["-s", sni])
            if transport_profile == "restricted":
                cmd.append("--http2")
            if low_latency:
                # usque 4.x exposes --keepalive-period; there is no
                # --tcp-nodelay or --keepalive CLI flag.
                cmd.extend(["--keepalive-period", "10s"])

            pid_path = self._pid_path(iface)
            os.makedirs(os.path.dirname(pid_path), exist_ok=True)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    start_new_session=True)

                self._stderr[iface] = deque(maxlen=_MAX_DIAGNOSTIC_LINES)
                reader = threading.Thread(
                    target=self._capture_stderr,
                    args=(iface, proc.stderr),
                    name="usque-stderr-%s" % iface,
                    daemon=True,
                )
                self._stderr_threads[iface] = reader
                reader.start()

                # Ждём создания TUN-интерфейса (до 5s)
                iface_up = False
                for _ in range(50):
                    time.sleep(0.1)
                    if self._check_iface_up(iface):
                        iface_up = True
                        break
                    if proc.poll() is not None:
                        break

                # A TUN may appear just before the process exits (for
                # example when the binary rejects a newly unsupported flag),
                # so do one final poll before reporting success.
                if proc.poll() is not None or not iface_up:
                    rc = proc.poll()
                    try:
                        proc.terminate()
                        proc.wait(timeout=1)
                    except Exception:
                        pass
                    try:
                        reader.join(timeout=0.25)
                    except Exception:
                        pass
                    diagnostic = self._diagnostic(iface)
                    if transport_profile == "auto":
                        # Auto is deliberately fail-closed: only a confirmed
                        # H3 process/interface failure triggers one H2 retry.
                        fallback = self.start(
                            iface,
                            config_path,
                            sni=sni,
                            transport_profile="restricted",
                            low_latency=low_latency,
                            apply_optimizer=apply_optimizer,
                        )
                        fallback["fallback_from"] = "performance"
                        if diagnostic and not fallback.get("diagnostic"):
                            fallback["diagnostic"] = diagnostic
                        return fallback
                    return {
                        "ok": False,
                        "error": "usque не создал интерфейс %s (rc=%s)"
                        % (iface, rc),
                        "diagnostic": diagnostic,
                    }

                # Сохраняем PID
                try:
                    with open(pid_path, "w") as f:
                        f.write(str(proc.pid))
                except Exception:
                    pass

                self._processes[iface] = proc
                self._config_by_iface[iface] = config_path
                try:
                    with open(config_path + ".run", "w") as f:
                        f.write('IFACE="%s"\nPID="%s"\n' % (iface, proc.pid))
                    os.chmod(config_path + ".run", 0o600)
                except OSError:
                    pass

                # Применяем оптимизации если low_latency
                if low_latency and apply_optimizer:
                    try:
                        from core.tunnel_optimizer import optimize_iface
                        optimize_iface(iface, "balanced", transport_kind="warp")
                    except Exception:
                        pass

                log.info("usque: туннель %s запущен (pid=%d)" % (iface, proc.pid),
                         source="usque")
                return {"ok": True, "pid": proc.pid, "iface": iface,
                        "transport_profile": transport_profile}

            except Exception as e:
                return {"ok": False, "error": str(e),
                        "diagnostic": self._diagnostic(iface)}

    def stop(self, iface: str) -> dict:
        """Остановить WARP туннель."""
        if not _VALID_IFACE_RE.match(iface):
            return {"ok": False, "error": "Неверное имя интерфейса: %s" % iface}

        pid_path = self._pid_path(iface)
        pid = self._read_pid(pid_path)

        # Пробуем остановить через stored process
        proc = None
        with self._lock:
            proc = self._processes.pop(iface, None)
            config_path = self._config_by_iface.pop(iface, None)

        if proc and proc.poll() is None:
            try:
                # MR-14: Убиваем всю группу процессов (т.к. start_new_session=True)
                if hasattr(os, "killpg"):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        proc.send_signal(signal.SIGTERM)
                else:
                    proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=3)
            except Exception:
                try:
                    if hasattr(os, "killpg"):
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
                            proc.kill()
                    else:
                        proc.kill()
                    try:
                        proc.wait(timeout=1)
                    except Exception:
                        pass
                except Exception:
                    pass
        elif pid:
            # Fallback: kill по PID
            try:
                if hasattr(os, "killpg"):
                    try:
                        os.killpg(pid, signal.SIGTERM)
                    except Exception:
                        os.kill(pid, signal.SIGTERM)
                else:
                    os.kill(pid, signal.SIGTERM)

                # MR-25: Ждем завершения с помощью poll-loop до 3с
                for _ in range(30):
                    time.sleep(0.1)
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                else:
                    if hasattr(os, "killpg"):
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except Exception:
                            os.kill(pid, signal.SIGKILL)
                    else:
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
        if config_path:
            try:
                run_path = config_path + ".run"
                if os.path.isfile(run_path):
                    os.remove(run_path)
            except OSError:
                pass

        self._stderr_threads.pop(iface, None)

        # MR-05: Восстанавливаем системные defaults, если нет других активных туннелей
        try:
            from core.tunnel_optimizer import restore_system_defaults
            restore_system_defaults(only_if_idle=True)
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
            "iface_exists": self._iface_exists(iface),
            "iface": iface,
            "pid": pid,
            "diagnostic": self._diagnostic(iface),
        }

    def _iface_exists(self, iface: str) -> bool:
        return os.path.exists("/sys/class/net/%s" % iface)

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
        """Проверить, поднят ли интерфейс.

        MR-126: читаем /sys/class/net вместо subprocess ip link show,
        чтобы исключить лишние fork/exec при каждой проверке (до 50 раз
        в течение 5 с. после старта туннеля).
        """
        operstate = "/sys/class/net/%s/operstate" % iface
        try:
            with open(operstate) as f:
                state = f.read().strip()
            return state in ("up", "unknown")
        except OSError:
            # /sys недоступен (тест/не-Linux) — ничего не знаем, считаем поднят
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
