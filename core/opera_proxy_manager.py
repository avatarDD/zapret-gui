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
from collections import deque

from core.log_buffer import log


# Хвост вывода opera-proxy. Держим в ОЗУ (не файл): на роутере лишняя
# запись на флешку ни к чему, а для разбора «почему прокси не отвечает»
# хватает последних строк. В обычном режиме буфер короткий, в режиме
# отладки — длинный.
_MAX_LOG_LINES = 60
_MAX_DEBUG_LOG_LINES = 600

# `-list-countries` — НЕ локальная операция: opera-proxy для неё делает
# анонимную регистрацию и регистрацию устройства в API SurfEasy. Дёргать
# её на каждый detect() нельзя (страница GUI опрашивает статус раз в 3 с —
# это была бы регистрация устройства каждые 3 секунды), поэтому список
# стран берётся из кэша и обновляется только по явному запросу.
#
# _COUNTRIES_MIN_REFRESH_SEC — минимальный интервал между реальными
# обращениями к API: защита от «нажал кнопку три раза» и от параллельных
# запросов из нескольких вкладок GUI.
_COUNTRIES_MIN_REFRESH_SEC = 60
# Собственный таймаут бинарника на сетевую операцию — 10 с, а регистраций
# две, поэтому 5 с (как было) не хватало почти никогда.
_COUNTRIES_TIMEOUT = 30

_VERBOSITY_MIN = 0
_VERBOSITY_MAX = 60


def parse_bind(bind) -> tuple:
    """
    Разобрать bind-адрес в (host, port).

    Поддерживает IPv4 (`127.0.0.1:18080`), имя хоста и IPv6 в скобках
    (`[::1]:18080`). Кидает ValueError с человекочитаемой причиной —
    единая точка разбора для API-валидации, watchdog-пробы и
    tunnel-monitor, которые раньше расходились (watchdog делал
    `rsplit(":", 1)` и на IPv6 вечно считал прокси мёртвым).
    """
    s = str(bind or "").strip()
    if not s:
        return _bind_error("адрес не задан")
    if s.startswith("["):
        host, sep, rest = s[1:].partition("]")
        if not sep or not rest.startswith(":"):
            return _bind_error("ожидается [адрес]:порт")
        port = rest[1:]
    else:
        if s.count(":") != 1:
            return _bind_error("ожидается host:порт (IPv6 — в скобках)")
        host, _, port = s.partition(":")
    host = host.strip()
    if not host:
        return _bind_error("не указан хост")
    if not port.isdigit():
        return _bind_error("порт должен быть числом")
    port_n = int(port)
    if not (1 <= port_n <= 65535):
        return _bind_error("порт должен быть от 1 до 65535")
    return host, port_n


def _bind_error(reason: str):
    raise ValueError("Некорректный bind: %s" % reason)


def debug_enabled() -> bool:
    """Включён ли режим отладки Opera Proxy (opera_proxy.debug_log)."""
    try:
        from core.config_manager import get_config_manager
        return bool(get_config_manager().get("opera_proxy", "debug_log",
                                             default=False))
    except Exception:
        return False


def _as_bool(value, field: str) -> bool:
    """Мягкое приведение к bool: GUI шлёт JSON-bool, curl — строки."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off", ""):
            return False
    raise ValueError("%s: ожидается true/false" % field)


def validate_settings(data: dict) -> dict:
    """
    Проверить и нормализовать настройки opera-proxy.

    Возвращает словарь только из переданных ключей (для частичного
    PUT). Кидает ValueError с текстом для пользователя.

    Нужна, потому что без неё в settings.json попадал любой мусор
    (`bind: "не-адрес"`, `verbosity: "abc"`), а узнавал об этом
    пользователь лишь по невнятному «opera-proxy завершился: usage: …»
    при следующем запуске — и по вечному рестарт-циклу watchdog'а.
    """
    clean = {}

    if "country" in data:
        country = str(data["country"] or "").strip().upper()
        if not country:
            raise ValueError("Страна не задана")
        if not country.isalnum() or len(country) > 8:
            raise ValueError("Некорректный код страны: %s" % country)
        clean["country"] = country

    if "bind" in data:
        host, port = parse_bind(data["bind"])
        clean["bind"] = ("[%s]:%d" % (host, port)) if ":" in host \
            else "%s:%d" % (host, port)

    for field in ("socks_mode", "autostart", "enabled", "debug_log"):
        if field in data:
            clean[field] = _as_bool(data[field], field)

    if "proxy_bypass" in data:
        bypass = str(data["proxy_bypass"] or "").strip()
        if len(bypass) > 2048:
            raise ValueError("Слишком длинный proxy bypass")
        # Список через запятую: пробелы вокруг элементов терпим и
        # вычищаем — «a.com, b.com» пользователь наберёт скорее, чем
        # «a.com,b.com», а opera-proxy пробел внутри значения не поймёт.
        bypass = ",".join(part.strip() for part in bypass.split(",")
                          if part.strip())
        if any(ch.isspace() for ch in bypass):
            raise ValueError("Proxy bypass: пробелы внутри записи недопустимы")
        clean["proxy_bypass"] = bypass

    if "fake_sni" in data:
        sni = str(data["fake_sni"] or "").strip()
        if sni:
            if len(sni) > 253 or not all(
                    ch.isalnum() or ch in ".-_" for ch in sni):
                raise ValueError("Некорректный Fake SNI: %s" % sni)
        clean["fake_sni"] = sni

    if "verbosity" in data:
        value = data["verbosity"]
        if isinstance(value, bool) or isinstance(value, float):
            raise ValueError("Verbosity: ожидается целое число")
        try:
            verbosity = int(str(value).strip())
        except (TypeError, ValueError):
            raise ValueError("Verbosity: ожидается целое число")
        if not (_VERBOSITY_MIN <= verbosity <= _VERBOSITY_MAX):
            raise ValueError("Verbosity: допустимо %d..%d"
                             % (_VERBOSITY_MIN, _VERBOSITY_MAX))
        clean["verbosity"] = verbosity

    return clean


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
        self._log = deque(maxlen=_MAX_LOG_LINES)
        self._running_bind = ""           # bind реально запущенного процесса
        # Кэш detect(): и версия, и список стран стоят fork'а (а страны —
        # ещё и двух регистраций в API SurfEasy), а detect() зовут статус-
        # поллинг GUI, selfcheck и update-checker.
        self._version_cache = {}          # stat-ключ бинарника → версия
        self._countries = []
        self._countries_ts = 0.0
        self._countries_error = ""
        self._countries_lock = threading.Lock()

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

    def detect(self, refresh_countries: bool = False) -> dict:
        """
        Обнаружить opera-proxy binary.

        Дешёвая операция: версия берётся из кэша по mtime/размеру файла,
        список стран — из кэша (сетевой запрос делается только при
        refresh_countries=True либо через list_countries()).
        """
        binary = self._find_binary()
        if not binary:
            return {"installed": False, "binary": "", "version": "",
                    "countries": []}
        version = self._get_version(binary)
        countries_info = self.list_countries(refresh=refresh_countries)
        return {
            "installed": True,
            "binary": binary,
            "version": version,
            "countries": countries_info["countries"],
            "countries_cached": countries_info["cached"],
            "countries_error": countries_info["error"],
        }

    def list_countries(self, refresh: bool = False) -> dict:
        """
        Список стран Opera VPN.

        Без refresh отдаёт кэш (возможно пустой) и НИЧЕГО не запускает:
        `-list-countries` каждый раз регистрирует новое устройство в API
        SurfEasy, а detect() зовётся из статус-поллинга GUI.
        """
        now = time.time()
        with self._lock:
            cached = list(self._countries)
            age = now - self._countries_ts if self._countries_ts else None
            error = self._countries_error
        fresh = bool(self._countries_ts) and \
            (now - self._countries_ts) < _COUNTRIES_MIN_REFRESH_SEC
        if not refresh or fresh:
            return {"ok": True, "countries": cached, "cached": True,
                    "age_sec": int(age) if age is not None else None,
                    "error": "" if cached else error}

        binary = self._find_binary()
        if not binary:
            return {"ok": False, "countries": cached, "cached": True,
                    "age_sec": int(age) if age is not None else None,
                    "error": "opera-proxy не найден"}

        # Двойной клик по «Обновить страны» не должен порождать две
        # параллельные регистрации устройства.
        if not self._countries_lock.acquire(blocking=False):
            return {"ok": True, "countries": cached, "cached": True,
                    "age_sec": int(age) if age is not None else None,
                    "error": "", "busy": True}
        try:
            countries, error = self._fetch_countries(binary)
            with self._lock:
                if countries:
                    self._countries = countries
                    self._countries_ts = time.time()
                self._countries_error = error
            return {"ok": not error, "countries": countries or cached,
                    "cached": False, "age_sec": 0 if countries else None,
                    "error": error}
        finally:
            self._countries_lock.release()

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
        """Версия бинарника. Кэш по mtime/размеру — переустановку видим."""
        try:
            st = os.stat(binary)
            key = (binary, int(st.st_mtime), st.st_size)
        except OSError:
            key = (binary, 0, 0)
        cached = self._version_cache.get(key)
        if cached is not None:
            return cached
        try:
            r = subprocess.run([binary, "-version"],
                               capture_output=True, text=True, timeout=5)
            version = (r.stdout or r.stderr or "").strip()[:50]
        except Exception:
            return ""
        # Кэшируем только удачный ответ, иначе временный сбой залипнет.
        if version:
            self._version_cache = {key: version}
        return version

    def _fetch_countries(self, binary: str) -> tuple:
        """Сходить в API SurfEasy за списком стран. Возвращает (list, error)."""
        try:
            r = subprocess.run([binary, "-list-countries"],
                               capture_output=True, text=True,
                               timeout=_COUNTRIES_TIMEOUT)
        except subprocess.TimeoutExpired:
            return [], ("opera-proxy не ответил за %ds — нет доступа к API "
                        "SurfEasy?" % _COUNTRIES_TIMEOUT)
        except Exception as e:
            return [], str(e)

        countries = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if "," in line and not line.startswith("country"):
                code, name = line.split(",", 1)
                code = code.strip()
                if code:
                    countries.append({"code": code, "name": name.strip()})
        if countries:
            return countries, ""
        err = (r.stderr or r.stdout or "").strip().splitlines()
        return [], (err[-1][:200] if err
                    else "opera-proxy вернул пустой список стран")

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

        # Настройки могли приехать из старого settings.json (валидации
        # раньше не было) — проверяем перед запуском, иначе пользователь
        # получит невнятный usage-дамп от Go-бинарника.
        try:
            clean = validate_settings({
                "country": country, "bind": bind, "socks_mode": socks_mode,
                "proxy_bypass": proxy_bypass, "fake_sni": fake_sni,
                "verbosity": verbosity,
            })
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        country = clean["country"]
        bind = clean["bind"]
        socks_mode = clean["socks_mode"]
        proxy_bypass = clean["proxy_bypass"]
        fake_sni = clean["fake_sni"]
        verbosity = clean["verbosity"]

        cmd = [binary, "-country", country, "-bind-address", bind]
        if socks_mode:
            cmd.append("-socks-mode")
        if proxy_bypass:
            cmd.extend(["-proxy-bypass", proxy_bypass])
        if fake_sni:
            cmd.extend(["-fake-SNI", fake_sni])
        cmd.extend(["-verbosity", str(verbosity)])

        # Буфер заводим ДО запуска: иначе вывод упавшего на старте процесса
        # («порт занят») нигде не оседал, и кнопка «Лог» показывала хвост
        # прошлого, удачного запуска — ровно в тот момент, когда лог нужен.
        with self._lock:
            self._log = deque(maxlen=(_MAX_DEBUG_LOG_LINES
                                      if debug_enabled()
                                      else _MAX_LOG_LINES))
            buf = self._log
        buf.append("$ %s" % " ".join(cmd))

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True)

            # Ждём запуска (1s): типичные мгновенные падения — занятый порт
            # и негодные аргументы.
            time.sleep(1)
            if proc.poll() is not None:
                out = ""
                try:
                    out = proc.stdout.read(65536).decode("utf-8", errors="replace")
                except Exception:
                    pass
                finally:
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass
                for line in out.splitlines():
                    if line.strip():
                        buf.append(line.rstrip()[-400:])
                buf.append("opera-proxy завершился, код %s" % proc.returncode)
                reason = " ".join(out.split())[:200] or ("код %s" % proc.returncode)
                log.warning("opera-proxy: не запустился (%s)" % reason,
                            source="opera_proxy")
                return {"ok": False,
                        "error": "opera-proxy завершился: %s" % reason}

            with self._lock:
                self._process = proc
                self._running_bind = bind
            self._write_pid(proc.pid)

            # Дренаж stdout в фоне: opera-proxy при verbosity<=20 логирует
            # каждое соединение. Без вычитывания OS-буфер пайпа (~64 КБ)
            # переполняется, child блокируется на write() и перестаёт
            # форвардить трафик («прокси завис»).
            #
            # Раньше вывод уходил в никуда, поэтому выбранный в GUI уровень
            # Debug (10) не давал НИЧЕГО: логи некуда было посмотреть.
            # Теперь копим хвост в кольцевом буфере — читать его при этом
            # обязательно так же непрерывно, иначе вернётся зависание.
            def _drain(pipe):
                try:
                    tail = b""
                    for chunk in iter(lambda: pipe.read(4096), b""):
                        tail += chunk
                        *ready, tail = tail.split(b"\n")
                        for raw in ready:
                            line = raw.decode("utf-8", "replace").rstrip()
                            if line:
                                buf.append(line[-400:])
                        if len(tail) > 8192:      # строка без перевода
                            buf.append(tail.decode("utf-8", "replace")[-400:])
                            tail = b""
                except Exception:
                    pass
                finally:
                    # Процесс мог умереть — закрываем свой конец пайпа, иначе
                    # каждый цикл старт/стоп подтекает файловым дескриптором.
                    try:
                        pipe.close()
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
            self._running_bind = ""

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

    def status(self, probe: bool = True) -> dict:
        """
        Статус opera-proxy.

        `listening` — реально ли принимается соединение на bind-адресе:
        живой процесс ещё не значит рабочий прокси (opera-proxy может
        крутиться, не сумев зарегистрироваться в API SurfEasy), а
        пользователь видел «Работает» и не понимал, почему трафик не идёт.
        """
        running = self._is_running()
        pid = None
        with self._lock:
            if self._process:
                pid = self._process.pid
            bind = self._running_bind
        if pid is None:
            pid = self._read_pid()      # пережил перезапуск GUI

        if not bind:
            # Процесс пережил перезапуск GUI — фактический bind неизвестен,
            # берём настроенный.
            try:
                from core.config_manager import get_config_manager
                bind = get_config_manager().get("opera_proxy", "bind",
                                                default="127.0.0.1:18080")
            except Exception:
                bind = ""

        result = {
            "running": running,
            "pid": pid if running else None,
            "bind": bind,
        }
        if running and probe and bind:
            from core.opera_proxy_watchdog import probe_proxy
            result["listening"] = probe_proxy(bind, timeout=0.7)
        return result

    def read_log(self, lines: int = 200) -> dict:
        """Хвост вывода opera-proxy для кнопки «Лог» в GUI."""
        with self._lock:
            buf = list(self._log)
        try:
            lines = max(1, min(int(lines), _MAX_DEBUG_LOG_LINES))
        except (TypeError, ValueError):
            lines = 200
        return {
            "ok": True,
            "debug": debug_enabled(),
            "captured": len(buf),
            "log": "\n".join(buf[-lines:]),
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
