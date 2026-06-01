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
import re
import signal
import subprocess
import threading
import time

from core.log_buffer import log

# PID-файл, управляемый GUI
PID_FILE = "/var/run/zapret-gui-nfqws.pid"

# ─────────────────────── Lua scripts injection ──────────────────────
# Конвенции взяты из youtubediscord/zapret (winws_runtime/runners/zapret2_runner.py).
#
# Core-скрипты загружаются всегда, когда в стратегии есть --lua-desync;
# zapret-lib.lua обязан идти первым (определяет базовые примитивы).
_CORE_LUA_FILES = (
    "zapret-lib.lua",
    "zapret-antidpi.lua",
    "zapret-auto.lua",
    "custom_funcs.lua",
    "custom_diag.lua",
)

# Extension-скрипты подключаются только если соответствующая desync-функция
# реально используется (имя слева от ':' в --lua-desync=...).
#
# ВАЖНО: набор функций должен зеркалить то, что РЕАЛЬНО экспортирует
# соответствующий .lua (см. import/lua/*.lua). Если функция определена в
# extension-скрипте, но отсутствует здесь, стратегия с её вызовом не
# подгрузит скрипт → вызов несуществующей lua-функции → тихий 0%.
# Сверка: grep '^function ' import/lua/zapret-multishake.lua и т.д.
_EXTENSION_LUA_FILES = {
    "zapret-multishake.lua": {
        "hostfakesplit_stealth",
        "hostfakesplit_chaos",
        "hostfakesplit_multi",
        "hostfakesplit_gradual",
        "hostfakesplit_decoy",
        "hostfakesplit_blend",
        "hostfakesplit_soft",
        "snifakesplit",
    },
    "fakemultisplit.lua": {"fakemultisplit"},
    "fakemultidisorder.lua": {"fakemultidisorder"},
}

_LUA_DESYNC_FUNC_RE = re.compile(r"--lua-desync=([a-zA-Z0-9_]+)")
_LUA_INIT_PATH_RE = re.compile(r"^--lua-init=@(.+)$")


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
        self._debug = False           # --debug активен → stderr на уровне INFO

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

            # Режим отладки: при --debug stderr nfqws2 показываем на INFO.
            self._debug = bool(cfg.get("nfqws", "debug", default=False))

            # Зачищаем любые «осиротевшие»/дублирующие nfqws2 перед
            # стартом, чтобы на NFQUEUE остался ровно один наш процесс
            # (issue #123). Сюда попадаем только если _is_running_locked()
            # вернул False, т.е. отслеживаемого живого процесса у нас нет.
            self._sweep_stray_processes()

            # Стратегические аргументы
            strategy_args = list(args) if args else []

            # Полная команда (binary + base + lua-init + strategy), дедуп lua.
            full_args = self.compose_command(strategy_args, binary=binary,
                                              cfg=cfg)
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
            result = True

            if not self._is_running_locked():
                log.info("nfqws2 не запущен", source="nfqws")
                self._cleanup()
            else:
                pid = self._pid
                log.info("Останавливаем nfqws2 (PID %d)..." % pid,
                         source="nfqws")
                result = self._stop_tracked_locked(pid)

            # В любом случае добиваем возможные дубли/сироты, чтобы «стоп»
            # действительно останавливал весь обход (issue #123): nfqws2
            # из автозапуска S99zapret или оставшийся от прошлой сессии.
            self._sweep_stray_processes()
            return result

    def _stop_tracked_locked(self, pid: int) -> bool:
        """Завершить отслеживаемый процесс pid (SIGTERM→SIGKILL). Под lock."""
        # Пробуем SIGTERM
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            log.info("Процесс уже завершён", source="nfqws")
            self._cleanup()
            return True
        except PermissionError:
            log.error("Нет прав для остановки PID %d" % pid, source="nfqws")
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

    # ─────────────────────── command builder ───────────────────────

    def compose_command(self, strategy_args: list, binary: str = None,
                         cfg=None) -> list:
        """Собрать полную команду запуска nfqws2.

        Единый источник истины для argv: используется и при живом запуске
        (start), и при генерации init-скрипта автозапуска — чтобы команды
        были идентичны (одни и те же base-args, lua-init, blob-декларации).

        Порядок: [binary] + base(--user/--fwmark/--qnum[/--bind-fix*]) +
                 lua-init(core+ext) + strategy_args, с дедупом --lua-init.

        Args:
            strategy_args: Аргументы стратегии (то, что вернул
                           StrategyManager.build_nfqws_args — уже с
                           blob-декларациями и резолвленными путями).
            binary: Путь к бинарнику nfqws2 (берётся из конфига, если None).
            cfg: ConfigManager (получаем сами, если None).

        Returns:
            list[str] — полный argv (включая путь к бинарнику).
        """
        if cfg is None:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
        if binary is None:
            binary = cfg.get("zapret", "nfqws_binary")

        strategy_args = list(strategy_args or [])
        base_args = self._build_base_args(cfg)

        lua_path = cfg.get("zapret", "lua_path") or "/opt/zapret2/lua"
        lua_args = self._build_lua_init_args(strategy_args, lua_path)

        # Единый слой (opt-in): --hostlist агрегата nfqws2-маршрутов перед
        # профилями стратегии — стратегия применяется к этим доменам.
        unified_args = []
        try:
            from core.unified import nfqws_hostlist
            unified_args = nfqws_hostlist.compose_extra_args()
        except Exception:
            unified_args = []

        return self._dedup_lua_init(
            [binary] + base_args + lua_args + unified_args + strategy_args
        )

    # ─────────────────────── internal helpers ───────────────────────

    def _build_base_args(self, cfg) -> list:
        """Собрать базовые аргументы из конфигурации (--user/--fwmark/--qnum).

        Lua-скрипты добавляются отдельно через _build_lua_init_args(), так как
        выбор зависит от используемых в стратегии --lua-desync функций.
        """
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

        # --debug — пер-пакетный лог nfqws2 для диагностики. Глобальная опция,
        # добавляется один раз в base. Сам вывод (stderr) пишется в лог-буфер
        # (_read_stderr); при debug он поднимается до уровня INFO, чтобы быть
        # видимым в UI/логах.
        if bool(cfg.get("nfqws", "debug", default=False)):
            args.append("--debug")

        # --bind-fix4/6 при нескольких WAN-интерфейсах. Без этого nfqws2
        # биндит raw-сокет только к первому интерфейсу, и на multi-WAN
        # (например, основной + резервный канал) обход на втором не работает.
        # Логика как в nfqws2-keenetic (_startup_args).
        try:
            wan4 = self._detect_wan_interfaces(cfg, "wan")
            if len(wan4) > 1:
                args.append("--bind-fix4")
                disable_ipv6 = cfg.get("nfqws", "disable_ipv6", default=True)
                if not disable_ipv6:
                    args.append("--bind-fix6")
        except Exception:
            # Детект интерфейсов не должен мешать запуску.
            pass

        return args

    @staticmethod
    def _detect_wan_interfaces(cfg, role: str) -> list:
        """WAN-интерфейсы из конфига или авто-детект по таблице маршрутов."""
        val = cfg.get("interfaces", role, default="")
        if isinstance(val, str):
            val = val.strip()
        if val:
            return val.split()
        from core.firewall import _detect_wan_from_routes, _detect_wan6_from_routes
        return _detect_wan6_from_routes() if role == "wan6" \
            else _detect_wan_from_routes()

    @staticmethod
    def _build_lua_init_args(strategy_args: list, lua_path: str) -> list:
        """Сформировать список --lua-init для core+extension скриптов.

        Логика по аналогии с youtubediscord/zapret:
          - если в стратегии нет --lua-desync — lua-скрипты не нужны;
          - core-список (zapret-lib первым) подключается всегда при наличии
            хотя бы одной desync-функции;
          - extension-скрипты добавляются только если в стратегии используются
            функции, объявленные ими.
        """
        used_funcs = set(_LUA_DESYNC_FUNC_RE.findall(" ".join(strategy_args)))
        if not used_funcs:
            return []

        out = []
        for lf in _CORE_LUA_FILES:
            full = os.path.join(lua_path, lf)
            if os.path.isfile(full):
                out.append("--lua-init=@%s" % full)

        for lf, funcs in _EXTENSION_LUA_FILES.items():
            if used_funcs & funcs:
                full = os.path.join(lua_path, lf)
                if os.path.isfile(full):
                    out.append("--lua-init=@%s" % full)

        return out

    @staticmethod
    def _dedup_lua_init(args: list) -> list:
        """Убрать повторы --lua-init=@<path> с сохранением порядка."""
        seen = set()
        out = []
        for a in args:
            m = _LUA_INIT_PATH_RE.match(a)
            if m:
                path = m.group(1)
                if path in seen:
                    continue
                seen.add(path)
            out.append(a)
        return out

    def _is_running_locked(self) -> bool:
        """Проверить запущен ли процесс (вызывается под lock)."""
        # Если есть Popen-объект — проверяем через poll
        if self._process is not None:
            rc = self._process.poll()
            if rc is not None:
                # Процесс завершился — но мог быть подменён другим
                # воркером/демоном, поэтому не выходим сразу, а проверяем
                # PID-файл ниже.
                self._exit_code = rc
                self._process = None
                self._remove_pid_file()
            else:
                return True

        # Нет живого Popen. Пробуем PID из памяти ИЛИ из PID-файла — файл
        # мог записать другой воркер bottle или восстановиться после
        # перезапуска GUI. Без этого менеджер «не видит» живой nfqws2 и
        # на следующем apply запускает дубль (issue #123).
        if self._pid is None:
            self._pid = self._read_pid_file()

        if self._pid is not None:
            if self._check_pid_alive(self._pid):
                if self._start_time is None:
                    try:
                        self._start_time = os.stat(
                            "/proc/%d" % self._pid).st_mtime
                    except OSError:
                        self._start_time = time.time()
                return True
            else:
                self._pid = None
                self._start_time = None
                self._remove_pid_file()
                return False

        return False

    @staticmethod
    def _find_nfqws_pids() -> list:
        """Все PID процессов nfqws/nfqws2 в системе (по basename argv[0]).

        Используется для зачистки «осиротевших» процессов (issue #123):
        nfqws2 мог быть поднят автозапуском S99zapret (--daemon, чужой
        PID-файл), остаться от упавшего GUI или от другого воркера. Все
        они висят на одной NFQUEUE и мешают друг другу.
        """
        pids = []
        try:
            for d in os.listdir("/proc"):
                if not d.isdigit():
                    continue
                pid = int(d)
                try:
                    with open("/proc/%d/cmdline" % pid, "rb") as f:
                        raw = f.read()
                except (IOError, OSError):
                    continue
                if not raw:
                    continue
                argv0 = raw.split(b"\x00", 1)[0].decode(
                    "utf-8", errors="replace")
                if argv0 and os.path.basename(argv0) in ("nfqws", "nfqws2"):
                    pids.append(pid)
        except OSError:
            pass
        return pids

    def _sweep_stray_processes(self, exclude_pid=None):
        """Завершить все процессы nfqws/nfqws2, кроме exclude_pid.

        Гарантирует, что в системе не накапливаются параллельные nfqws2
        (issue #123 «стакаются процессы запрета»). SIGTERM → ожидание →
        SIGKILL. Чужие PID-файлы, указывающие на убитые процессы,
        вычищаются, чтобы статус автозапуска не врал.
        """
        strays = [p for p in self._find_nfqws_pids() if p != exclude_pid]
        if not strays:
            return

        log.warning(
            "Обнаружены лишние процессы nfqws2 (PID %s) — завершаем во "
            "избежание дублей на NFQUEUE" % ", ".join(
                str(p) for p in strays),
            source="nfqws"
        )

        for p in strays:
            try:
                os.kill(p, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        deadline = time.time() + 2.0
        while time.time() < deadline:
            strays = [p for p in strays if self._check_pid_alive(p)]
            if not strays:
                break
            time.sleep(0.1)

        for p in strays:
            try:
                os.kill(p, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

        # Подчищаем чужие PID-файлы, указывающие на мёртвый теперь процесс.
        for pf in ("/var/run/zapret-nfqws.pid", PID_FILE):
            try:
                with open(pf, "r") as f:
                    fp = int(f.read().strip())
                if not self._check_pid_alive(fp) and fp != exclude_pid:
                    os.remove(pf)
            except (IOError, OSError, ValueError):
                pass

    @staticmethod
    def _check_pid_alive(pid: int) -> bool:
        """
        Проверить что процесс с данным PID жив и это действительно nfqws.

        Substring-проверка ('nfqws' in cmdline) даёт ложноположительные
        срабатывания на чужих процессах (например, ``tail -f
        /var/log/zapret-nfqws.log`` или ``grep nfqws``), особенно при
        recycle PID. Сравниваем по basename исполняемого файла argv[0].
        """
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                raw = f.read()
        except (IOError, OSError):
            return False

        if not raw:
            # пустой cmdline — kthread или зомби
            return False

        # argv[0] до первого NUL, затем basename
        argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        if not argv0:
            return False
        name = os.path.basename(argv0)
        return name in ("nfqws", "nfqws2")

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
                elif self._debug:
                    # В debug-режиме поднимаем обычные строки до INFO, чтобы
                    # пер-пакетный вывод nfqws2 был виден при диагностике.
                    log.info(line, source="nfqws")
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
