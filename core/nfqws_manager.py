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
import pty
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
# Core-lua = ровно то, что грузит эталонный blockcheck2 pktws_start() и что
# задокументировано в SKILL.md §1/§1.3: zapret-lib.lua (ПЕРВЫМ — базовые
# примитивы) + zapret-antidpi.lua (desync-функции fake/multisplit/...).
# Всё остальное подключается условно (extension по функциям, init_vars по
# именованным паттернам, orchestrator-bundle по circular) — см. ниже.
_CORE_LUA_FILES = (
    "zapret-lib.lua",
    "zapret-antidpi.lua",
)

# init_vars.lua объявляет именованные SNI/pattern-переменные (tls_google и
# т.п.), используемые как blob=/pattern=/seqovl_pattern=, и грузится ТОЛЬКО
# если стратегия реально на них ссылается. Грузится сразу ПОСЛЕ core (на этапе
# load зовёт tls_mod/fake_default_tls из antidpi). Его единственная функция
# invert_bytes как desync-действие не вызывается, поэтому init_vars НЕ в
# функц-карте, а триггерится по значению (см. _INIT_VARS_NAMES / _build_lua_init_args).
_INIT_VARS_LUA_FILE = "init_vars.lua"
_INIT_VARS_NAMES = {
    "bin_max", "fake_inverted_tls", "fake_max", "tls_cloudflare", "tls_discord",
    "tls_google", "tls_mail", "tls_padencap", "tls_padencap_google", "tls_rnd",
    "tls_rnd_dupsid", "tls_rnd_dupsid_google", "tls_rnd_google", "tls_rndsni",
    "tls_sber", "tls_vk", "tls_yandex", "tls_youtube",
}
# blob=/pattern=/seqovl_pattern=<NAME> — ссылка на именованный паттерн.
_NAMED_PATTERN_RE = re.compile(
    r"(?:blob|pattern|seqovl_pattern)=([A-Za-z_][A-Za-z0-9_]*)")

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
    # WireGuard/UDP-обфускация и туннелирование. wgobfs определён и в
    # zapret-wgobfs.lua, но zapret-obfs.lua — надмножество (wgobfs + ippxor +
    # udp2icmp + synhide), поэтому маршрутизируем все эти функции в него, а
    # zapret-wgobfs.lua не подключаем (дубль), чтобы не грузить wgobfs дважды.
    "zapret-obfs.lua": {"wgobfs", "ippxor", "udp2icmp", "synhide"},
    # 16KB-обход (фейк-флуд белым SNI, ttl-лесенка и пр.). Зависит от
    # lib+antidpi (оба в core).
    "zapret-16kb.lua": {
        "flood_white", "ttl_ladder", "white_sandwich", "seqovl_white",
    },
    # Флуд RST с подобранным TTL до DPI. Зависит от lib+antidpi (core).
    "zapret-rst-flood.lua": {"rst_flood"},
    # Запись pcap из lua (требует --writable). Триггер — pcap; вспомогательные
    # pcap_write* включены, чтобы набор зеркалил экспорт скрипта (см. тест).
    "zapret-pcap.lua": {
        "pcap", "pcap_write", "pcap_write_packet", "pcap_write_header",
    },
    # Auto-оркестратор: circular/condition/repeater/stopif/per_instance_condition
    # + детекторы/хосткеи, которые circular зовёт по имени. Companion-скрипты
    # (combined-detector и пр.) зависят от standard_*_detector отсюда, поэтому
    # zapret-auto до-грузится и в orchestrator-блоке (см. _build_lua_init_args).
    "zapret-auto.lua": {
        "automate_conn_record", "automate_failure_check",
        "automate_failure_counter", "automate_failure_counter_reset",
        "automate_host_record", "circular", "cond_false", "cond_lua",
        "cond_payload_str", "cond_random", "cond_tcp_has_ts", "cond_true",
        "condition", "is_dpi_redirect", "per_instance_condition", "repeater",
        "require_iff", "standard_detector_defaults", "standard_failure_detector",
        "standard_hostkey", "standard_success_detector", "stopif",
    },
    # z2k-modern-core: расширения уровня core от necronicle/z2k.
    #   z2k_nohost_key  — hostkey-генератор для бесхостовых потоков
    #                     (Discord/STUN UDP без SNI). Плагается в circular
    #                     через `hostkey=z2k_nohost_key`. Без этого
    #                     standard_hostkey бакетит состояние по dest-IP →
    #                     Discord voice фрагментируется по CDN-IP.
    #   z2k_ipfrag3 / z2k_ipfrag3_tiny — 3-фрагментные IP-фрагментаторы с
    #                     опциональным overlap (для обхода DPI-reassembly).
    #   z2k_timing_morph    — размытие сигнатур первых пакетов хендшейка
    #                         через bad-checksum фейки.
    #   z2k_quic_morph_v2   — QUIC Initial: фрагментация + модификация
    #                         version/CID/token + шумовые пакеты.
    #   z2k_game_udp        — UDP fake-инъекция для игровых протоколов.
    # Зависит только от lib+antidpi (core). См. import/lua/z2k-modern-core.lua.
    "z2k-modern-core.lua": {
        "z2k_nohost_key", "z2k_ipfrag3", "z2k_ipfrag3_tiny",
        "z2k_timing_morph", "z2k_quic_morph_v2", "z2k_game_udp",
    },
    # Расширенный каталог приёмов проекта (http_*/tls_*/discord_*/multisplit_*).
    # Зависит только от lib+antidpi (core).
    "custom_funcs.lua": {
        "decoy_hello", "desync_combo", "discord_ecn_exploit",
        "discord_router_alert", "discord_timestamp_travel",
        "discord_ultimate_combo", "discord_urgent_sni", "discord_window_collapse",
        "http_absolute_uri_v2", "http_absolute_url", "http_aggressive",
        "http_combo_bypass", "http_fake_continuation", "http_fake_xhost",
        "http_garbage_prefix", "http_header_shuffle", "http_host_bytesplit",
        "http_hostmod", "http_inject_safe_header", "http_ipfrag", "http_lf_prefix",
        "http_method_obfuscate", "http_methodeol_hostcase", "http_methodeol_safe",
        "http_methodeol_v2", "http_mgts_combo", "http_mixed_prefix",
        "http_multi_crlf", "http_multidisorder", "http_oob_prefix",
        "http_pipeline_fake", "http_pipeline_fake_v2", "http_seqovl_host",
        "http_simple_bypass", "http_space_prefix", "http_syndata",
        "http_tab_prefix", "http_triple_seqovl", "http_version_downgrade",
        "http_xpadding", "multisplit_tls", "multisplitdisorder", "rst_desync",
        "tls_aggressive", "tls_disorder_gentle", "tls_fake_disorder_gentle",
        "tls_fake_flood", "tls_fake_simple", "tls_fake_split",
        "tls_multisplit_sni", "tls_split_gentle", "tlsrec",
    },
    # Диагностические no-op desync-хелперы. Ни от чего не зависят, дозагрузка
    # только при явном --lua-desync=diag_once/diag_always.
    "custom_diag.lua": {"diag_always", "diag_once"},
}

# Auto-оркестратор (circular) — companion-скрипты, которые подключаются
# ВМЕСТЕ при использовании стратегии с `--lua-desync=circular[...]`.
#
# В отличие от extension-скриптов (триггер = собственные desync-функции),
# здесь триггер — ФИЧА (circular): сами companion'ы экспортируют не
# desync-действия, а детекторы/хосткеи/состояние, которые circular
# вызывает по имени через свои аргументы (detector=, success=, hostkey=,
# preload=...). Без их загрузки такие аргументы ссылались бы на
# несуществующие функции.
#
# Загружаются ПОСЛЕ core (нужны standard_failure_detector/host_or_ip из
# zapret-lib/zapret-auto). Порядок между собой не важен — на этапе load
# только определения функций и идемпотентная инициализация глобальных
# таблиц (SLM_* = SLM_* or {}), без вызовов и require(). Несуществующие
# файлы пропускаются (guard по os.path.isfile), поэтому на сборках без
# этих скриптов поведение не меняется.
#
# ВАЖНО (не ломать остальное): на обычные circular-стратегии из каталога,
# которые НЕ ссылаются на companion-функции, загрузка лишних определений
# не влияет — circular их просто не вызывает.
_ORCHESTRATOR_TRIGGERS = {"circular", "circular_with_preload"}
_ORCHESTRATOR_LUA_FILES = (
    "strategy-lock-manager.lua",   # SLM_*-состояние + slm_*-хелперы
    "domain-grouping.lua",         # get_grouped_hostname (группировка SNI)
    "combined-detector.lua",       # combined_failure/success_detector, и пр.
    "silent-drop-detector.lua",    # детектор тихого TCP-дропа
    "strategy-stats.lua",          # preload + circular_with_preload
    # ─────────── z2k-bundle (companion для circular) ───────────
    # Порядок важен: detectors зависят от standard_*_detector из
    # zapret-auto и от is_dpi_redirect/http_dissect_reply из antidpi;
    # state-persist обёртывает функцию circular() и ДОЛЖЕН грузиться
    # ПОСЛЕ zapret-auto (иначе оборачивать нечего).
    "z2k-modern-core.lua",         # z2k_nohost_key (hostkey=), ipfrag3, QUIC morph
    "z2k-detectors.lua",           # TLS-stall, mid-stream-stall, HTTP-classifier,
                                   # server-active-reject, silent-drop
    "z2k-fooling-ext.lua",         # fool=z2k_dynamic_ttl (real_ttl-1)
    "z2k-state-persist.lua",       # persist выученной стратегии (state.tsv);
                                   # путь — env Z2K_STATE_DIR_OVERRIDE
)

# z2k-range-rand: оборачивает fake/multisplit/multidisorder/fakedsplit/
# fakeddisorder/hostfakesplit/syndata так, что аргументы вида
# `repeats=2-6`, `seqovl=10-50`, `tcp_seq=-1000-1000`, `tcp_ts=-5-5`
# разрешаются в случайное целое (sticky per-flow). Триггер — наличие
# range-синтаксиса в любом из этих ключей в strategy_args.
_RANGE_RAND_TRIGGER_RE = re.compile(
    r"(?:repeats|seqovl|tcp_seq|tcp_ts)=-?\d+-(?:-)?\d+")
_RANGE_RAND_LUA_FILE = "z2k-range-rand.lua"

# z2k-fooling-ext: fool=z2k_dynamic_ttl ссылается на кастомную fool-функцию,
# которая НЕ является --lua-desync (значит, не триггерится extension-картой по
# имени). Для circular она грузится в orchestrator-bundle, но для обычного
# приёма (например, fake:fool=z2k_dynamic_ttl) нужен отдельный value-триггер.
# Грузится по значению fool=z2k_*.
_FOOL_EXT_TRIGGER_RE = re.compile(r"\bfool=(z2k_[A-Za-z0-9_]+)")
_FOOL_EXT_LUA_FILE = "z2k-fooling-ext.lua"

# Путь к state-каталогу (Z2K_STATE_DIR_OVERRIDE для z2k-state-persist.lua).
# Пишем в наш GUI-каталог, а не в /opt/zapret2/extra_strats — чтобы state
# выживал переустановку zapret2 и был частью бекапа GUI.
Z2K_STATE_DIR = "/opt/etc/zapret-gui/state/autocircular"

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
        self._stderr_thread = None    # поток чтения вывода
        self._out_fd = None           # master-fd PTY (вывод nfqws2) | None=pipe
        self._exit_code = None        # код выхода последнего процесса
        self._debug = False           # --debug активен → вывод на уровне INFO

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

            # nfqws2 с --debug (DLOG) пишет пер-пакетный лог в STDOUT, а
            # ошибки — в STDERR. Раньше stdout уходил в DEVNULL, поэтому при
            # включённой отладке «в логах было пусто». Теперь объединяем
            # stdout+stderr и читаем оба. Канал — PTY: nfqws2 видит tty и
            # строчно буферизует вывод (через pipe stdout буферизуется блоками
            # и debug появляется рывками/в конце). Фолбэк — pipe.
            out_fd = None
            try:
                out_fd, slave_fd = pty.openpty()
            except OSError:
                out_fd = slave_fd = None

            # env для z2k-state-persist.lua: state.tsv пишется в наш каталог
            # (а не /opt/zapret2/extra_strats — переживает переустановку
            # zapret2 и бекапится вместе с GUI). Каталог создаём заранее,
            # nfqws2 запускается под --user (обычно nobody) и при отсутствии
            # каталога Lua делает fallback в /tmp (тоже работает, но теряется
            # при ребуте).
            try:
                os.makedirs(Z2K_STATE_DIR, mode=0o755, exist_ok=True)
                # nfqws2 запускается под `--user nobody` — даём ему права на запись
                try:
                    import shutil
                    if shutil.which("chown"):
                        subprocess.run(
                            ["chown", "-R", cfg.get("nfqws", "user") or "nobody",
                             Z2K_STATE_DIR],
                            check=False, timeout=5,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                except Exception:
                    pass
            except OSError:
                # Без каталога z2k-state-persist уйдёт в /tmp fallback — это ОК.
                pass
            child_env = dict(os.environ)
            child_env["Z2K_STATE_DIR_OVERRIDE"] = Z2K_STATE_DIR

            try:
                if slave_fd is not None:
                    self._process = subprocess.Popen(
                        full_args,
                        stdin=subprocess.DEVNULL,
                        stdout=slave_fd,
                        stderr=slave_fd,
                        preexec_fn=os.setsid,  # Новая группа процессов
                        close_fds=True,
                        env=child_env,
                    )
                    os.close(slave_fd)
                    slave_fd = None
                else:
                    self._process = subprocess.Popen(
                        full_args,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        preexec_fn=os.setsid,  # Новая группа процессов
                        env=child_env,
                    )
                self._out_fd = out_fd

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
                    self._log_start_failure_hint()
                    self._cleanup()
                    return False

                log.success(
                    "nfqws2 запущен (PID %d)" % self._pid, source="nfqws"
                )
                return True

            except FileNotFoundError:
                self._close_out_fds(out_fd, slave_fd)
                log.error("Не удалось запустить: файл не найден (%s)" % binary,
                          source="nfqws")
                return False
            except PermissionError:
                self._close_out_fds(out_fd, slave_fd)
                log.error("Не удалось запустить: нет прав (%s)" % binary,
                          source="nfqws")
                return False
            except OSError as e:
                self._close_out_fds(out_fd, slave_fd)
                log.error("Ошибка запуска nfqws2: %s" % e, source="nfqws")
                return False

    @staticmethod
    def _log_start_failure_hint():
        """Назвать вероятную причину мгновенного падения nfqws2.

        Самая частая причина «завершился сразу (exit 1)» на OpenWrt —
        недоступен модуль ядра NFQUEUE (nfnetlink_queue): без него nfqws2 не
        может открыть очередь. Проверяем это и, если модуля нет, даём
        конкретную команду установки / подсказку (на OpenWrt — можно одной
        кнопкой из GUI, без консоли). Best-effort: любая ошибка тут не должна
        мешать штатному завершению запуска.
        """
        try:
            from core.diagnostics import _check_nfqueue_available
            if _check_nfqueue_available():
                return
            from core.kmod_manager import nfqueue_fix_hint
            hint = nfqueue_fix_hint()
            log.error(
                "Вероятная причина: ядру недоступен модуль NFQUEUE "
                "(nfnetlink_queue). " + (hint.get("log_line") or ""),
                source="nfqws")
        except Exception:
            pass

    @staticmethod
    def _close_out_fds(*fds):
        for fd in fds:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

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

    def dry_run(self, strategy_args: list, timeout: float = 8.0) -> dict:
        """Проверить стратегию через `nfqws2 --intercept=0` без поднятия NFQUEUE.

        Собирает argv тем же `compose_command` (единый источник истины), что
        и реальный запуск, затем заменяет перехват на валидацию через
        **`--intercept=0`** (эталон docs/manual.md zapret2: «0 = только
        запустить lua-init и выйти»). nfqws2 разбирает опции CLI, проверяет
        доступность файлов (`--blob`/`--lua-init`/`--hostlist`/…) И **исполняет
        lua-init** — то есть загружает/парсит lua-скрипты, ловя их синтаксис и
        ошибки времени загрузки (например, неверный порядок `--lua-init`, когда
        `init_vars` вызывает `tls_mod` до загрузки `zapret-antidpi`). Затем
        выходит с кодом 0 при успехе. NFQUEUE НЕ открывается, трафик не
        затрагивается.

        Почему `--intercept=0`, а не `--dry-run`: `--dry-run` по эталону Lua
        НЕ загружает («Lua не проверяется») — ловит только парсинг опций и
        наличие файлов. `--intercept=0` дополнительно прогоняет lua-init.

        Чего НЕ ловит даже так: вызов несуществующей `--lua-desync` функции —
        это происходит по-пакетно в рантайме, а не на этапе lua-init. От такого
        «тихого 0%» защищает статический инвариант `tests/test_nfqws_lua_map.py`
        (карта `_EXTENSION_LUA_FILES`), а не эта валидация.

        Из argv убираем `--user=` — иначе nfqws2 при старте пытается setuid и
        без root падает не по делу (к валидации опций/lua это не относится).
        `--daemon` мы и так не добавляем.

        Returns:
            dict: { ok, available, returncode, output, command }.
                  available=False — бинарник недоступен (валидацию не
                  провести, например, на dev-машине без zapret2).
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        binary = cfg.get("zapret", "nfqws_binary")

        if (not binary or not os.path.isfile(binary)
                or not os.access(binary, os.X_OK)):
            return {
                "ok": False, "available": False,
                "error": "Бинарник nfqws2 недоступен: %s" % binary,
                "returncode": None, "output": "", "command": "",
            }

        argv = self.compose_command(list(strategy_args or []),
                                    binary=binary, cfg=cfg)
        # Без setuid (нет root в рантайме валидации) и без любых уже
        # присутствующих intercept/dry-run флагов — задаём свой --intercept=0.
        argv = [a for a in argv
                if not a.startswith("--user=")
                and not a.startswith("--intercept")
                and a != "--dry-run"]
        argv.append("--intercept=0")

        try:
            proc = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
            out = (proc.stdout.decode("utf-8", errors="replace")
                   if proc.stdout else "")
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            return {
                "ok": False, "available": True, "returncode": None,
                "output": "Таймаут валидации (%.0fс)" % timeout,
                "command": " ".join(argv),
            }
        except OSError as e:
            return {
                "ok": False, "available": True, "returncode": None,
                "output": "Ошибка запуска валидации: %s" % e,
                "command": " ".join(argv),
            }

        return {
            "ok": rc == 0,
            "available": True,
            "returncode": rc,
            "output": out.strip(),
            "command": " ".join(argv),
        }

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
        # добавляется один раз в base. nfqws2 пишет debug в STDOUT (DLOG),
        # ошибки — в STDERR; оба объединяются и читаются в _read_output_stream
        # (через PTY, в реальном времени). При debug строки поднимаются до INFO,
        # чтобы быть видимыми в UI/логах.
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
        """Сформировать список --lua-init для core+extension+orchestrator.

        Логика по SKILL.md §1.3 (минимально достаточный набор):
          - если в стратегии нет --lua-desync — lua-скрипты не нужны;
          - core (zapret-lib первым, затем zapret-antidpi) — всегда при наличии
            хотя бы одной desync-функции (как эталонный blockcheck2 pktws_start);
          - init_vars.lua — сразу после core, только если стратегия ссылается на
            именованный паттерн (blob=/pattern=/seqovl_pattern=<NAME из init_vars>);
          - extension-скрипты — только если используются их функции;
          - companion'ы auto-оркестратора + zapret-auto — если стратегия
            использует circular[...]/circular_with_preload (см. _ORCHESTRATOR_*).
        """
        joined = " ".join(strategy_args)
        used_funcs = set(_LUA_DESYNC_FUNC_RE.findall(joined))
        if not used_funcs:
            return []

        def _add(out, lf):
            full = os.path.join(lua_path, lf)
            if os.path.isfile(full):
                out.append("--lua-init=@%s" % full)

        out = []
        for lf in _CORE_LUA_FILES:
            _add(out, lf)

        # init_vars — сразу после core (load-time зависит от antidpi), только
        # при ссылке на его именованные паттерны.
        if _INIT_VARS_NAMES & set(_NAMED_PATTERN_RE.findall(joined)):
            _add(out, _INIT_VARS_LUA_FILE)

        for lf, funcs in _EXTENSION_LUA_FILES.items():
            if used_funcs & funcs:
                _add(out, lf)

        # Auto-оркестратор: bundle companion'ов при circular. Они зависят от
        # standard_*_detector/circular из zapret-auto — для circular_with_preload
        # (не входит в экспорт zapret-auto) до-грузим zapret-auto явно; дедуп
        # уберёт повтор, если circular уже подтянул его как extension.
        if used_funcs & _ORCHESTRATOR_TRIGGERS:
            _add(out, "zapret-auto.lua")
            for lf in _ORCHESTRATOR_LUA_FILES:
                _add(out, lf)

        # z2k-range-rand: триггер по range-синтаксису (repeats=A-B и т.п.).
        # Должен грузиться ПОСЛЕ antidpi (он оборачивает её глобалы
        # fake/multisplit/...). Так как core грузится первым, естественный
        # порядок соблюдается. В orchestrator-bundle уже могла быть
        # подгрузка — дедуп уберёт повтор.
        if _RANGE_RAND_TRIGGER_RE.search(joined):
            _add(out, _RANGE_RAND_LUA_FILE)

        # z2k-fooling-ext по value-триггеру fool=z2k_* (для не-circular приёмов;
        # для circular уже подтянут bundle'ом — дедуп уберёт повтор).
        if _FOOL_EXT_TRIGGER_RE.search(joined):
            _add(out, _FOOL_EXT_LUA_FILE)

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
        """Запустить фоновый поток для чтения вывода nfqws2 (stdout+stderr)."""
        if self._process is None:
            return
        # Читаем PTY-мастер, если есть; иначе — объединённый proc.stdout.
        if self._out_fd is None and not self._process.stdout:
            return
        t = threading.Thread(
            target=self._read_output_stream,
            args=(self._process, self._out_fd),
            daemon=True,
            name="nfqws-output"
        )
        t.start()
        self._stderr_thread = t

    def _read_output_stream(self, proc, out_fd):
        """Читать вывод nfqws2 (stdout+stderr) и писать в лог-буфер.

        out_fd != None — PTY-мастер (построчно, в реальном времени); иначе —
        объединённый proc.stdout (фолбэк на pipe).
        """
        if out_fd is not None:
            buf = b""
            try:
                while True:
                    try:
                        data = os.read(out_fd, 4096)
                    except OSError:
                        break  # EIO после закрытия slave (процесс завершился)
                    if not data:
                        break
                    buf += data
                    while True:
                        nl = buf.find(b"\n")
                        if nl < 0:
                            break
                        line = buf[:nl].decode("utf-8", "replace").rstrip("\r")
                        buf = buf[nl + 1:]
                        self._log_nfqws_line(line)
            finally:
                if buf:
                    self._log_nfqws_line(
                        buf.decode("utf-8", "replace").rstrip("\r"))
                try:
                    os.close(out_fd)
                except OSError:
                    pass
                self._out_fd = None
            return

        try:
            for raw_line in proc.stdout:
                try:
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                except Exception:
                    line = str(raw_line).rstrip()
                self._log_nfqws_line(line)
        except Exception:
            pass
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass

    def _log_nfqws_line(self, line):
        """Записать строку вывода nfqws2 в лог-буфер с подбором уровня."""
        if not line:
            return
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
