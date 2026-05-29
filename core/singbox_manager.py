# core/singbox_manager.py
"""
Менеджер sing-box.

Делает:
  - CRUD JSON-конфигов в `platform.config_dir`;
  - up/down процесса `sing-box run -c <config>`;
  - валидацию через `sing-box check -c <file>`;
  - чтение списка inbound'ов (для отображения «какой порт занят»).

Лайфцикл одной инсталляции:
  - Один процесс = один конфиг. Это упрощение по сравнению с AWG, где
    каждый туннель — отдельный интерфейс. Sing-box по своей модели и
    так может держать любое количество outbound'ов внутри одного
    инстанса.
  - Имя «инстанса» = имя файла конфига без `.json`.
  - PID-файл живёт в platform.run_dir.

На Keenetic'е с RCI sing-box не интегрируется через NDMS (Keenetic
не знает про этот процесс). Но routing-правила на sing-box-tun
точно так же поднимаются через наш RoutingManager: target_iface
будет `tun0` / `singbox-tun`.
"""

import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time

try:
    import resource
except ImportError:          # не-POSIX (на роутерах всегда есть)
    resource = None


# Желаемый лимит открытых файловых дескрипторов для процесса движка.
# Прокси с большим числом соединений (как Xray/sing-box под нагрузкой)
# упирается в дефолтные 1024 и начинает ронять коннекты с "too many
# open files". XKeen поднимает лимит явно — делаем так же.
SINGBOX_NOFILE = 65536


def _raise_nofile():
    """preexec_fn: поднять RLIMIT_NOFILE для дочернего процесса движка."""
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = SINGBOX_NOFILE
        # Нельзя превысить hard-лимит без root-привилегий на raise hard;
        # под root поднимаем и hard. Берём максимум доступного.
        new_hard = hard if hard != resource.RLIM_INFINITY else target
        new_soft = min(target, new_hard) if new_hard != resource.RLIM_INFINITY \
            else target
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, target))
        except (ValueError, OSError):
            # hard поднять не дали — ставим хотя бы soft до hard.
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, new_hard))
    except (ValueError, OSError):
        pass

from core.log_buffer import log
from core.singbox_platform import detect_singbox_platform
from core.singbox_config import parse_conf, render_conf, validate
from core.singbox_detector import get_singbox_detector


# ─────── helpers ───────

_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")


def _valid_name(name: str) -> bool:
    return bool(name) and bool(_VALID_NAME_RE.match(name))


def _run(args, timeout=15, input_text=None):
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            input=input_text)
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


# ─────── manager ───────

class SingboxManager:

    def __init__(self):
        self._lock = threading.Lock()

    def _platform(self):
        return detect_singbox_platform()

    def _binary(self) -> str:
        info = get_singbox_detector().detect_binary()
        return info.get("path", "")

    def _ensure_run_dir(self):
        platform = self._platform()
        try:
            os.makedirs(platform.run_dir, exist_ok=True)
        except OSError:
            pass

    def _ensure_config_dir(self):
        platform = self._platform()
        try:
            os.makedirs(platform.config_dir, exist_ok=True)
        except OSError:
            pass

    # ─────── CRUD ───────

    def list_configs(self) -> list:
        """
        Все JSON-конфиги в `platform.config_dir`.
        """
        platform = self._platform()
        if not os.path.isdir(platform.config_dir):
            return []
        out = []
        for fn in sorted(os.listdir(platform.config_dir)):
            if not fn.endswith(".json"):
                continue
            name = fn[:-5]
            if not _valid_name(name):
                continue
            full = os.path.join(platform.config_dir, fn)
            try:
                size = os.path.getsize(full)
                mtime = int(os.path.getmtime(full))
            except OSError:
                size, mtime = 0, 0
            running = self.is_running(name)
            out.append({
                "name":     name,
                "path":     full,
                "size":     size,
                "mtime":    mtime,
                "running":  running,
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
        errors = []
        parsed = None
        try:
            parsed = parse_conf(text)
            errors = validate(parsed)
        except ValueError as e:
            errors = [str(e)]
        return {"ok": True, "name": name, "text": text, "parsed": parsed,
                "errors": errors, "path": path}

    def save_config(self, name: str, *, text: str = "",
                    parsed: dict = None) -> dict:
        """
        Сохранить конфиг под именем `name`. Можно передать либо raw-text
        (raw JSON), либо `parsed` dict (он будет красиво отрендерен).
        """
        if not _valid_name(name):
            return {"ok": False, "error":
                    "Имя: только A-Za-z0-9._-, до 32 символов"}

        if parsed is not None and not text:
            text = render_conf(parsed)
        if not text or not text.strip():
            return {"ok": False, "error": "Конфиг пуст"}

        # Структурная валидация — обязательная для save (raw-JSON
        # пользователя тоже проверяем, чтобы не положить файл,
        # который sing-box не возьмёт).
        try:
            cfg = parse_conf(text)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        errs = validate(cfg)
        # validate() возвращает и warnings, и errors одной кучей —
        # для save мы блокируем только error-уровень. Эвристика:
        # «обязательная секция отсутствует» / «должен быть» —
        # это error; «неизвестный тип» — warning.
        hard_errors = [e for e in errs
                       if "неизвестный тип" not in e]
        if hard_errors:
            return {"ok": False, "error": "; ".join(hard_errors),
                    "warnings": [e for e in errs if e not in hard_errors]}

        self._ensure_config_dir()
        path = self._platform().config_path(name)
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(text)
            os.replace(tmp, path)
        except OSError as e:
            return {"ok": False, "error": "write: %s" % e}

        log.info("singbox: сохранён конфиг %s" % name, source="singbox")
        return {"ok": True, "name": name, "path": path,
                "warnings": [e for e in errs if e not in hard_errors]}

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
        """
        Запустить `sing-box check -c <file>` — это полноценная
        валидация на уровне самого бинаря, проверяет всё.
        """
        if not _valid_name(name):
            return {"ok": False, "error": "Некорректное имя"}
        binary = self._binary()
        if not binary:
            return {"ok": False, "error": "sing-box не установлен"}
        path = self._platform().config_path(name)
        if not os.path.isfile(path):
            return {"ok": False, "error": "Конфиг не найден"}
        rc, out, err = _run([binary, "check", "-c", path], timeout=10)
        return {"ok": rc == 0, "stdout": out, "stderr": err,
                "returncode": rc}

    # ─────── lifecycle ───────

    def is_running(self, name: str) -> bool:
        platform = self._platform()
        pid = _read_pid(platform.pid_path(name))
        if not pid:
            return False
        return _pid_alive(pid)

    def status(self, name: str) -> dict:
        platform = self._platform()
        pid = _read_pid(platform.pid_path(name))
        active = bool(pid) and _pid_alive(pid)
        return {
            "name":     name,
            "active":   active,
            "pid":      pid if active else None,
            "log_path": platform.log_path(name),
        }

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
        d = self.down(name)
        # down может быть «не запущено» — это всё равно ok.
        time.sleep(0.5)
        return self.up(name)

    def _do_up(self, name: str) -> dict:
        binary = self._binary()
        if not binary:
            return {"ok": False, "error": "sing-box не установлен"}

        platform = self._platform()
        config = platform.config_path(name)
        if not os.path.isfile(config):
            return {"ok": False, "error": "Конфиг %s не найден" % name}

        if self.is_running(name):
            return {"ok": True, "already_running": True}

        # Pre-flight: спросим у самого sing-box, валиден ли конфиг.
        # Если нет — не пытаемся стартовать, сразу отдаём ошибку
        # пользователю.
        chk_rc, _o, chk_err = _run([binary, "check", "-c", config],
                                    timeout=10)
        if chk_rc != 0:
            return {"ok": False, "error":
                    "sing-box check %s: %s" % (name,
                                                (chk_err or "").strip())}

        self._ensure_run_dir()
        pid_file = platform.pid_path(name)
        log_file = platform.log_path(name)

        # Запускаем sing-box в фоне и логируем stderr в файл.
        # Используем setsid → процесс отделяется от нашей сессии,
        # переживёт SIGHUP при перезапуске GUI.
        try:
            log_fh = open(log_file, "a")
        except OSError as e:
            return {"ok": False, "error": "log open: %s" % e}

        try:
            popen = subprocess.Popen(
                [binary, "run", "-c", config],
                stdin=subprocess.DEVNULL,
                stdout=log_fh, stderr=log_fh,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_raise_nofile,
            )
        except OSError as e:
            log_fh.close()
            return {"ok": False, "error": "spawn: %s" % e}

        # Запишем pid сразу — даже если процесс упадёт через секунду,
        # мы хотя бы узнаем об этом через is_running().
        try:
            with open(pid_file, "w") as f:
                f.write(str(popen.pid))
        except OSError:
            pass

        # Дадим процессу 1 секунду — если упал за это время, отдаём
        # ошибку с хвостом лога.
        time.sleep(1.0)
        if popen.poll() is not None:
            # Уже умер — собираем лог.
            tail = _tail_file(log_file, 80)
            return {"ok": False,
                    "error": "sing-box упал при старте (exit=%s)"
                             % popen.returncode,
                    "log_tail": tail}

        log.info("singbox: запущен '%s' (pid=%d)" % (name, popen.pid),
                 source="singbox")
        return {"ok": True, "pid": popen.pid, "config": config,
                "log_path": log_file}

    def _do_down(self, name: str) -> dict:
        platform = self._platform()
        pid_file = platform.pid_path(name)
        pid = _read_pid(pid_file)
        if not pid:
            # Возможно процесс есть, но pid-файл не записался — попробуем
            # найти по `pgrep -f sing-box.*<config>`.
            pid = self._find_pid_by_config(name)
        if not pid:
            return {"ok": True, "noop": True,
                    "message": "Процесс не найден"}

        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass

        # Ждём корректного завершения до 5 секунд.
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

        log.info("singbox: остановлен '%s' (pid=%d)" % (name, pid),
                 source="singbox")
        return {"ok": True, "pid": pid}

    def _find_pid_by_config(self, name: str):
        """Найти PID процесса sing-box, запущенного с нашим config."""
        platform = self._platform()
        config = platform.config_path(name)
        rc, out, _err = _run(["pgrep", "-f",
                              "sing-box .*%s" % re.escape(config)],
                              timeout=3)
        if rc != 0 or not out.strip():
            return None
        try:
            return int(out.strip().splitlines()[0])
        except (ValueError, IndexError):
            return None


# ─────── helpers ───────

def _tail_file(path: str, lines: int = 80) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            # Прикинем: 200 байт на строку с запасом.
            block = min(size, lines * 200)
            f.seek(size - block)
            data = f.read(block)
        text = data.decode("utf-8", errors="replace")
        return "\n".join(text.splitlines()[-lines:])
    except (IOError, OSError):
        return ""


# ─────── singleton ───────

_manager = None
_manager_lock = threading.Lock()


def get_singbox_manager() -> SingboxManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = SingboxManager()
    return _manager
