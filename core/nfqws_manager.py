# core/nfqws_manager.py
"""
Менеджер процесса nfqws2.

Запуск, остановка, перезапуск nfqws2.
PID-файл: /var/run/zapret-gui-nfqws.pid
Stderr перенаправляется в лог-буфер.

Использование:
    from core.nfqws_manager import get_nfqws_manager
    mgr = get_nfqws_manager()
    mgr.start(["--filter-tcp=443", "--filter-l7=tls", ...])
    mgr.stop()
    mgr.get_status()
"""

import os
import signal
import subprocess
import threading
import time

from core.log_buffer import log

# PID-файл, управляемый GUI
PID_FILE = "/var/run/zapret-gui-nfqws.pid"


class NFQWSManager:
    """
    Управление процессом nfqws2.

    Запускает nfqws2 через subprocess.Popen, читает stderr
    в фоновом потоке и пишет в лог-буфер.
    """

    def __init__(self):
        self._process = None          # subprocess.Popen
        self._pid = None              # int | None
        self._start_time = None       # time.time() момент запуска
        self._last_args = []          # аргументы последнего запуска
        self._lock = threading.Lock()
        self._stderr_thread = None    # поток чтения stderr
        self._exit_code = None        # код выхода последнего процесса

        # Пробуем восстановить PID из файла при инициализации
        self._recover_pid()

    # ─────────────────────────── public API ───────────────────────────

    def start(self, args: list = None) -> bool:
        """
        Запустить nfqws2.

        Args:
            args: Аргументы командной строки (без бинарника).
                  Если None — используем базовые параметры из конфига.

        Returns:
            True если процесс успешно запущен.
        """
        with self._lock:
            # Уже запущен?
            if self._is_running_locked():
                log.warning("nfqws2 уже запущен (PID %d)" % self._pid,
                            source="nfqws")
                return True

            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            binary = cfg.get("zapret", "nfqws_binary")

            # Проверяем бинарник
            if not os.path.isfile(binary):
                log.error("Бинарник не найден: %s" % binary, source="nfqws")
                return False
            if not os.access(binary, os.X_OK):
                log.error("Бинарник не исполняемый: %s" % binary,
                          source="nfqws")
                return False

            # Собираем базовые аргументы
            base_args = self._build_base_args(cfg)

            # Стратегические аргументы
            strategy_args = args if args else []

            full_args = [binary] + base_args + strategy_args
            self._last_args = strategy_args

            log.info("Запуск nfqws2...", source="nfqws")
            log.debug("Команда: %s" % " ".join(full_args), source="nfqws")

            try:
                self._process = subprocess.Popen(
                    full_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,  # Новая группа процессов
                )

                self._pid = self._process.pid
                self._start_time = time.time()
                self._exit_code = None

                # Сохраняем PID-файл
                self._write_pid_file(self._pid)

                # Запускаем чтение stderr в фоне
                self._start_stderr_reader()

                # Даём процессу чуть-чуть времени, проверяем что не упал
                time.sleep(0.3)
                if self._process.poll() is not None:
                    rc = self._process.returncode
                    self._exit_code = rc
                    log.error(
                        "nfqws2 завершился сразу после запуска "
                        "(exit code: %d)" % rc,
                        source="nfqws"
                    )
                    self._cleanup()
                    return False

                log.success(
                    "nfqws2 запущен (PID %d)" % self._pid, source="nfqws"
                )
                return True

            except FileNotFoundError:
                log.error("Не удалось запустить: файл не найден (%s)" % binary,
                          source="nfqws")
                return False
            except PermissionError:
                log.error("Не удалось запустить: нет прав (%s)" % binary,
                          source="nfqws")
                return False
            except OSError as e:
                log.error("Ошибка запуска nfqws2: %s" % e, source="nfqws")
                return False

    def stop(self) -> bool:
        """
        Остановить nfqws2.

        Отправляет SIGTERM, ждёт 3 секунды, если не остановился — SIGKILL.

        Returns:
            True если процесс остановлен (или не был запущен).
        """
        with self._lock:
            if not self._is_running_locked():
                log.info("nfqws2 не запущен", source="nfqws")
                self._cleanup()
                return True

            pid = self._pid
            log.info("Останавливаем nfqws2 (PID %d)..." % pid,
                     source="nfqws")

            # Пробуем SIGTERM
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                log.info("Процесс уже завершён", source="nfqws")
                self._cleanup()
                return True
            except PermissionError:
                log.error("Нет прав для остановки PID %d" % pid,
                          source="nfqws")
                return False

            # Ждём завершения (до 3 секунд)
            for _ in range(30):
                time.sleep(0.1)
                if not self._check_pid_alive(pid):
                    log.success("nfqws2 остановлен (SIGTERM)", source="nfqws")
                    self._cleanup()
                    return True

            # Не остановился — SIGKILL
            log.warning(
                "nfqws2 не ответил на SIGTERM, отправляем SIGKILL",
                source="nfqws"
            )
            try:
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.5)
            except ProcessLookupError:
                pass

            if not self._check_pid_alive(pid):
                log.success("nfqws2 остановлен (SIGKILL)", source="nfqws")
                self._cleanup()
                return True

            log.error("Не удалось остановить nfqws2 (PID %d)" % pid,
                      source="nfqws")
            return False

    def restart(self, args: list = None) -> bool:
        """
        Перезапустить nfqws2.

        Args:
            args: Новые аргументы. Если None — используем предыдущие.
        """
        log.info("Перезапуск nfqws2...", source="nfqws")

        # Запоминаем аргументы до stop() (который делает cleanup)
        restart_args = args if args is not None else list(self._last_args)

        if not self.stop():
            log.error("Не удалось остановить nfqws2 для перезапуска",
                      source="nfqws")
            return False

        time.sleep(0.3)
        return self.start(restart_args)

    def is_running(self) -> bool:
        """Проверить, запущен ли nfqws2."""
        with self._lock:
            return self._is_running_locked()

    def get_pid(self):
        """Получить PID текущего процесса или None."""
        with self._lock:
            if self._is_running_locked():
                return self._pid
            return None

    def get_uptime(self) -> int:
        """Получить uptime в секундах (0 если не запущен)."""
        with self._lock:
            if self._start_time and self._is_running_locked():
                return int(time.time() - self._start_time)
            return 0

    def get_last_args(self) -> list:
        """Аргументы последнего запуска."""
        return list(self._last_args)

    def get_exit_code(self):
        """Код выхода последнего завершённого процесса."""
        return self._exit_code

    def get_status(self) -> dict:
        """
        Полный статус для API.

        Returns:
            dict с полями: running, pid, uptime, uptime_human, binary,
                           last_args, exit_code
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        running = self.is_running()
        uptime = self.get_uptime()

        return {
            "running": running,
            "pid": self.get_pid(),
            "uptime": uptime if running else None,
            "uptime_human": _format_uptime(uptime) if running else None,
            "binary": cfg.get("zapret", "nfqws_binary"),
            "last_args": self._last_args,
            "exit_code": self._exit_code,
        }

    # ─────────────────────── internal helpers ───────────────────────

    def _build_base_args(self, cfg) -> list:
        """Собрать базовые аргументы из конфигурации."""
        args = []

        # --user
        user = cfg.get("nfqws", "user") or "nobody"
        args.append("--user=%s" % user)

        # --fwmark
        mark = cfg.get("nfqws", "desync_mark") or "0x40000000"
        args.append("--fwmark=%s" % mark)

        # --qnum
        queue_num = cfg.get("nfqws", "queue_num", default=300)
        args.append("--qnum=%d" % int(queue_num))

        # Lua-скрипты
        lua_path = cfg.get("zapret", "lua_path") or "/opt/zapret2/lua"
        lua_files = [
            "zapret-lib.lua",
            "zapret-antidpi.lua",
            "zapret-auto.lua",
        ]
        for lf in lua_files:
            full = os.path.join(lua_path, lf)
            if os.path.isfile(full):
                args.append("--lua-init=@%s" % full)

        return args

    def _is_running_locked(self) -> bool:
        """Проверить запущен ли процесс (вызывается под lock)."""
        # Если есть Popen-объект — проверяем через poll
        if self._process is not None:
            rc = self._process.poll()
            if rc is not None:
                # Процесс завершился
                self._exit_code = rc
                self._process = None
                self._remove_pid_file()
                return False
            return True

        # Нет Popen, но есть PID (восстановлен из файла)
        if self._pid is not None:
            if self._check_pid_alive(self._pid):
                return True
            else:
                self._pid = None
                self._start_time = None
                self._remove_pid_file()
                return False

        return False

    @staticmethod
    def _check_pid_alive(pid: int) -> bool:
        """Проверить что процесс с данным PID жив и это nfqws."""
        try:
            cmdline_path = "/proc/%d/cmdline" % pid
            with open(cmdline_path, "r") as f:
                cmdline = f.read()
            return "nfqws" in cmdline
        except (IOError, OSError):
            return False

    def _recover_pid(self):
        """Восстановить PID из PID-файла при инициализации."""
        pid = self._read_pid_file()
        if pid and self._check_pid_alive(pid):
            self._pid = pid
            # Пробуем определить время запуска из /proc
            try:
                stat = os.stat("/proc/%d" % pid)
                self._start_time = stat.st_mtime
            except OSError:
                self._start_time = time.time()
            log.info(
                "Обнаружен работающий nfqws2 (PID %d)" % pid,
                source="nfqws"
            )

    def _start_stderr_reader(self):
        """Запустить фоновый поток для чтения stderr."""
        if self._process and self._process.stderr:
            t = threading.Thread(
                target=self._read_stderr,
                args=(self._process,),
                daemon=True,
                name="nfqws-stderr"
            )
            t.start()
            self._stderr_thread = t

    def _read_stderr(self, proc):
        """Читать stderr процесса и писать в лог-буфер."""
        try:
            for raw_line in proc.stderr:
                try:
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                except Exception:
                    line = str(raw_line).rstrip()

                if not line:
                    continue

                # Определяем уровень по содержимому
                low = line.lower()
                if "error" in low or "fail" in low:
                    log.error(line, source="nfqws")
                elif "warn" in low:
                    log.warning(line, source="nfqws")
                else:
                    log.debug(line, source="nfqws")
        except Exception:
            pass
        finally:
            try:
                proc.stderr.close()
            except Exception:
                pass

    def _cleanup(self):
        """Очистить состояние после остановки."""
        self._process = None
        self._pid = None
        self._start_time = None
        self._remove_pid_file()

    # ─────────────── PID file ───────────────

    @staticmethod
    def _write_pid_file(pid: int):
        """Записать PID-файл."""
        try:
            os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
            with open(PID_FILE, "w") as f:
                f.write(str(pid))
        except OSError as e:
            log.warning("Не удалось записать PID-файл: %s" % e,
                        source="nfqws")

    @staticmethod
    def _read_pid_file():
        """Прочитать PID из файла."""
        try:
            with open(PID_FILE, "r") as f:
                return int(f.read().strip())
        except (IOError, ValueError):
            return None

    @staticmethod
    def _remove_pid_file():
        """Удалить PID-файл."""
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except OSError:
            pass


def _format_uptime(seconds: int) -> str:
    """Форматировать uptime."""
    if seconds <= 0:
        return "0с"
    if seconds < 60:
        return "%dс" % seconds
    if seconds < 3600:
        return "%dм %dс" % (seconds // 60, seconds % 60)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return "%dч %dм" % (hours, minutes)


# === Глобальный экземпляр (singleton) ===

_nfqws_manager = None
_manager_lock = threading.Lock()


def get_nfqws_manager() -> NFQWSManager:
    """Получить глобальный экземпляр NFQWSManager."""
    global _nfqws_manager
    if _nfqws_manager is None:
        with _manager_lock:
            if _nfqws_manager is None:
                _nfqws_manager = NFQWSManager()
    return _nfqws_manager

