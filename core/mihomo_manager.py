# core/mihomo_manager.py
"""
Менеджер mihomo (Clash.Meta).

Прямой аналог `core/singbox_manager.py`, но конфиги — YAML (clash-
формат), запуск — `mihomo -d <workdir> -f <config>`, проверка —
`mihomo -t -f <config>`.

Лайфцикл: один процесс = один YAML-конфиг. Имя инстанса = имя файла
без `.yaml`. PID/лог — в platform.run_dir / platform.log_dir.

fd-лимиты: как и у sing-box, поднимаем RLIMIT_NOFILE для дочернего
процесса (прокси под нагрузкой иначе упирается в дефолтные 1024).
"""

import os
import re
import signal
import subprocess
import threading
import time

from core.log_buffer import log
from core.mihomo_platform import detect_mihomo_platform
from core.mihomo_detector import get_mihomo_detector

try:
    import resource
except ImportError:
    resource = None


MIHOMO_NOFILE = 65536

_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")


def _valid_name(name: str) -> bool:
    return bool(name) and bool(_VALID_NAME_RE.match(name))


def _raise_nofile():
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE,
                           (MIHOMO_NOFILE, MIHOMO_NOFILE))
    except (ValueError, OSError):
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except (ValueError, OSError):
            pass


def _run(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _read_pid(path: str):
    try:
        with open(path, "r") as f:
            v = f.read().strip()
        return int(v) if v.isdigit() else None
    except (IOError, OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return os.path.exists("/proc/%d" % pid)
    except OSError:
        return False


# ─────── lightweight config validation ───────

def validate_yaml(text: str) -> list:
    """
    Лёгкая структурная проверка clash/mihomo-YAML. Глубокую делает
    сам бинарь (`mihomo -t`). Возвращает список ошибок-строк.
    """
    if not text or not text.strip():
        return ["Пустой конфиг"]
    try:
        from core.clash_yaml import parse_yaml
        data = parse_yaml(text)
    except Exception as e:
        return ["Некорректный YAML: %s" % e]
    if not isinstance(data, dict):
        return ["Корень YAML должен быть объектом (map)"]
    errors = []
    # proxies — для реального проксирования обязателен хотя бы один
    # источник (proxies / proxy-providers).
    if not data.get("proxies") and not data.get("proxy-providers"):
        errors.append("Нет секции 'proxies' (или 'proxy-providers') — "
                      "неизвестно, через что проксировать")
    return errors


# ─────── manager ───────

class MihomoManager:

    def __init__(self):
        self._lock = threading.Lock()

    def _platform(self):
        return detect_mihomo_platform()

    def _binary(self) -> str:
        return get_mihomo_detector().detect_binary().get("path", "")

    def _ensure_dir(self, path):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass

    # ─────── CRUD ───────

    def list_configs(self) -> list:
        platform = self._platform()
        if not os.path.isdir(platform.config_dir):
            return []
        out = []
        for fn in sorted(os.listdir(platform.config_dir)):
            if not (fn.endswith(".yaml") or fn.endswith(".yml")):
                continue
            name = fn.rsplit(".", 1)[0]
            if not _valid_name(name):
                continue
            full = os.path.join(platform.config_dir, fn)
            try:
                size = os.path.getsize(full)
                mtime = int(os.path.getmtime(full))
            except OSError:
                size, mtime = 0, 0
            out.append({
                "name":    name,
                "path":    full,
                "size":    size,
                "mtime":   mtime,
                "running": self.is_running(name),
            })
        return out

    def get_config(self, name: str) -> dict:
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        path = self._platform().config_path(name)
        if not os.path.isfile(path):
            return {"ok": False, "error": "Конфиг не найден"}
        try:
            with open(path, "r") as f:
                text = f.read()
        except OSError as e:
            return {"ok": False, "error": "read: %s" % e}
        return {"ok": True, "name": name, "text": text,
                "errors": validate_yaml(text), "path": path}

    def save_config(self, name: str, text: str = "") -> dict:
        if not _valid_name(name):
            return {"ok": False, "error":
                    "Имя: только A-Za-z0-9._-, до 32 символов"}
        if not text or not text.strip():
            return {"ok": False, "error": "Конфиг пуст"}
        errs = validate_yaml(text)
        # Блокируем только «пустой/битый YAML»; отсутствие proxies —
        # warning (пользователь может дополнять конфиг постепенно).
        hard = [e for e in errs if "YAML" in e or "объектом" in e]
        if hard:
            return {"ok": False, "error": "; ".join(hard),
                    "warnings": [e for e in errs if e not in hard]}
        self._ensure_dir(self._platform().config_dir)
        path = self._platform().config_path(name)
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(text)
            os.replace(tmp, path)
        except OSError as e:
            return {"ok": False, "error": "write: %s" % e}
        log.info("mihomo: сохранён конфиг %s" % name, source="mihomo")
        return {"ok": True, "name": name, "path": path,
                "warnings": [e for e in errs if e not in hard]}

    def delete_config(self, name: str) -> dict:
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        if self.is_running(name):
            return {"ok": False,
                    "error": "Конфиг %s запущен, сначала остановите" % name}
        path = self._platform().config_path(name)
        try:
            os.remove(path)
        except FileNotFoundError:
            return {"ok": True, "name": name, "noop": True}
        except OSError as e:
            return {"ok": False, "error": "rm: %s" % e}
        return {"ok": True, "name": name}

    # ─────── validate via binary ───────

    def validate_via_binary(self, name: str) -> dict:
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        binary = self._binary()
        if not binary:
            return {"ok": False, "error": "mihomo не установлен"}
        path = self._platform().config_path(name)
        if not os.path.isfile(path):
            return {"ok": False, "error": "Конфиг не найден"}
        rc, out, err = _run([binary, "-t", "-f", path], timeout=15)
        return {"ok": rc == 0, "stdout": out, "stderr": err,
                "returncode": rc}

    # ─────── lifecycle ───────

    def is_running(self, name: str) -> bool:
        pid = _read_pid(self._platform().pid_path(name))
        return _pid_alive(pid) if pid else False

    def status(self, name: str) -> dict:
        platform = self._platform()
        pid = _read_pid(platform.pid_path(name))
        active = bool(pid) and _pid_alive(pid)
        return {"name": name, "active": active,
                "pid": pid if active else None,
                "log_path": platform.log_path(name)}

    def up(self, name: str) -> dict:
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        with self._lock:
            return self._do_up(name)

    def down(self, name: str) -> dict:
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        with self._lock:
            return self._do_down(name)

    def restart(self, name: str) -> dict:
        self.down(name)
        time.sleep(0.5)
        return self.up(name)

    def _do_up(self, name: str) -> dict:
        binary = self._binary()
        if not binary:
            return {"ok": False, "error": "mihomo не установлен"}
        platform = self._platform()
        config = platform.config_path(name)
        if not os.path.isfile(config):
            return {"ok": False, "error": "Конфиг %s не найден" % name}
        if self.is_running(name):
            return {"ok": True, "already_running": True}

        # Pre-flight: mihomo -t.
        chk_rc, _o, chk_err = _run([binary, "-t", "-f", config], timeout=15)
        if chk_rc != 0:
            return {"ok": False, "error":
                    "mihomo -t %s: %s" % (name, (chk_err or "").strip())}

        self._ensure_dir(platform.run_dir)
        pid_file = platform.pid_path(name)
        log_file = platform.log_path(name)
        try:
            log_fh = open(log_file, "a")
        except OSError as e:
            return {"ok": False, "error": "log open: %s" % e}

        try:
            popen = subprocess.Popen(
                [binary, "-d", platform.config_dir, "-f", config],
                stdin=subprocess.DEVNULL,
                stdout=log_fh, stderr=log_fh,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_raise_nofile,
            )
        except OSError as e:
            log_fh.close()
            return {"ok": False, "error": "spawn: %s" % e}

        try:
            with open(pid_file, "w") as f:
                f.write(str(popen.pid))
        except OSError:
            pass

        time.sleep(1.0)
        if popen.poll() is not None:
            tail = _tail_file(log_file, 80)
            return {"ok": False,
                    "error": "mihomo упал при старте (exit=%s)"
                             % popen.returncode,
                    "log_tail": tail}
        log.info("mihomo: запущен '%s' (pid=%d)" % (name, popen.pid),
                 source="mihomo")
        return {"ok": True, "pid": popen.pid, "config": config,
                "log_path": log_file}

    def _do_down(self, name: str) -> dict:
        platform = self._platform()
        pid_file = platform.pid_path(name)
        pid = _read_pid(pid_file)
        if not pid:
            pid = self._find_pid_by_config(name)
        if not pid:
            return {"ok": True, "noop": True, "message": "Процесс не найден"}
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        for _ in range(50):
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            os.remove(pid_file)
        except OSError:
            pass
        log.info("mihomo: остановлен '%s' (pid=%d)" % (name, pid),
                 source="mihomo")
        return {"ok": True, "pid": pid}

    def _find_pid_by_config(self, name: str):
        config = self._platform().config_path(name)
        rc, out, _e = _run(["pgrep", "-f",
                            "mihomo .*%s" % re.escape(config)], timeout=3)
        if rc != 0 or not out.strip():
            return None
        try:
            return int(out.strip().splitlines()[0])
        except (ValueError, IndexError):
            return None


def _tail_file(path: str, lines: int = 80) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = min(size, lines * 200)
            f.seek(size - block)
            data = f.read(block)
        return "\n".join(data.decode("utf-8", errors="replace")
                         .splitlines()[-lines:])
    except (IOError, OSError):
        return ""


_manager = None
_manager_lock = threading.Lock()


def get_mihomo_manager() -> MihomoManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = MihomoManager()
    return _manager
