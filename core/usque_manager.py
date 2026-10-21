# core/usque_manager.py
"""
Менеджер WARP/MASQUE (usque).

Управление Cloudflare WARP через usque (MASQUE-протокол). Бинарник
собираем сами (.github/workflows/build-usque-binaries.yml, релизы
usque-bin-v*), запасной источник — .ipk side-effect-tm/usque-keenetic.

Лайфцикл:
  1. Регистрация сессии: usque register --accept-tos --config <path>
  2. Запуск туннеля: usque nativetun --config <session> --interface-name <iface> --no-iproute2
     (по желанию --http2 для H2/TCP, --keepalive-period 10s, -m <mtu>)
  3. TUN создаёт сам usque; адреса, MTU и link up — мы (_configure_iface)
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

# Префикс имён TUN-интерфейсов usque: `usque0`, `usque1`, …
#
# Раньше здесь был `opkgtun`, и это давало сразу две проблемы. Во-первых,
# под тем же именем поднимаются AWG-туннели: конфиг `awg0-opkgtun0.conf`
# живёт на интерфейсе `opkgtun0`. На графиках и в списке методов
# маршрутизации было не понять, какой из туннелей чей. Во-вторых,
# allocate_iface считает имя свободным, если его нет в /sys/class/net, —
# то есть у ОСТАНОВЛЕННОГО AWG-туннеля имя можно было отобрать, и старые
# правила `awg:opkgtun0` начинали заворачивать трафик в WARP.
#
# Существующие туннели не переименовываются: имя работающего туннеля
# закрепляется за профилем (см. iface_for_config / _seed_assignment), так
# что уже настроенные правила `warp:opkgtun0` остаются рабочими. Новый
# префикс получают только профили, которым имя выдаётся впервые.
DEFAULT_IFACE_PREFIX = "usque"

# Каталоги, где ищется бинарник usque. Список вынесен наружу намеренно:
# «установлен» для usque — это ровно «в одном из этих путей лежит
# исполняемый файл», и когда GUI зажигает лампочку у того, кто ничего не
# ставил (discussion #102), пользователю нужно видеть, ГДЕ мы смотрели.
# Самодиагностика печатает этот список, когда бинарник не найден.
USQUE_BINARY_PATHS = (
    "/opt/usr/bin/usque",
    "/opt/bin/usque",
    "/usr/local/bin/usque",
    "/usr/bin/usque",
)

_MAX_DIAGNOSTIC_LINES = 40
# В режиме отладки держим заметно более длинный хвост: 40 строк хватает
# на «почему не поднялся», но не на «почему отваливается через час».
# Буфер в ОЗУ, а не файл: на роутере лишняя запись на флешку ни к чему.
_MAX_DEBUG_LINES = 500
# Дефолт usque (`-m/--mtu`, cmd/nativetun.go). Держим то же значение: с
# --no-iproute2 MTU выставляем мы, и расхождение с тем, из чего usque
# нарезает пакеты внутри туннеля, дало бы фрагментацию.
_DEFAULT_MTU = 1280
# Расширения файлов сессий usque. Имя профиля = имя файла без расширения,
# поэтому `warp.conf` и `warp.json` одновременно — это два профиля с одним
# именем, из которых по имени достижим только первый.
_CONFIG_EXTS = (".conf", ".toml", ".json")


def _run(args, timeout=10):
    """Запустить команду, вернуть (rc, stdout, stderr)."""
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


def _exec_error_text(binary: str, err: OSError) -> str:
    """Человеческий текст вместо голого «[Errno 8] Exec format error».

    Ядро отказывается запускать файл, когда он не ELF (например, скачанный
    с GitHub `.gz` положили на место бинарника), собран под другой порядок
    байт (mips вместо mipsel — `uname -m` на обоих даёт «mips») или
    повреждён. Пользователю из этой строки должно быть понятно, что чинить,
    поэтому пишем и путь, и способ починки.
    """
    import errno as _errno
    if err.errno == _errno.ENOEXEC:
        return ("Бинарник %s не запускается: ядро не признаёт его"
                " исполняемым файлом. Обычно это не та архитектура,"
                " недокачанный файл или загруженный вручную архив (.gz)"
                " вместо распакованного бинарника. Переустановите usque:"
                " «WARP/MASQUE → Установка» → «Переустановить»." % binary)
    if err.errno in (_errno.EACCES, _errno.EPERM):
        return ("Бинарник %s не запускается: нет прав на исполнение"
                " (или раздел смонтирован с noexec). Переустановите usque"
                " на странице «WARP/MASQUE → Установка»." % binary)
    if err.errno == _errno.ENOENT:
        return ("Бинарник %s исчез — переустановите usque на странице"
                " «WARP/MASQUE → Установка»." % binary)
    return str(err)


_VERSION_TTL = 6 * 3600
_VERSION_FAIL_TTL = 600
_VERSION_NUM_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)*)")


def _file_stamp(path: str) -> tuple:
    try:
        st = os.stat(path)
        return (int(st.st_mtime), st.st_size)
    except (OSError, TypeError):
        return (0, 0)


def _parse_usque_version(text: str, strict: bool) -> str:
    """Версия из вывода `usque version`.

    Строка «usque version: 4.2.0» → «4.2.0»; «dev» (сборка без ldflags)
    отдаём как есть. strict=True — для stderr: там же жалоба на config.json
    с путём, и брать можно только строку с «version» без слова «config».
    Без strict годится и голая строка-номер («4.2.1» / «v4.2.1»).
    """
    for line in (text or "").splitlines():
        low = line.lower()
        if "version" in low and ":" in line:
            if strict and "config" in low:
                continue
            value = line.split(":", 1)[1].strip()
            m = _VERSION_NUM_RE.search(value)
            if m:
                return m.group(1)
            if value and not strict:
                return value[:50]
    if not strict:
        for line in (text or "").splitlines():
            m = re.fullmatch(r"\s*(?:usque\s+)?v?(\d+\.\d+(?:\.\d+)*)\s*",
                             line)
            if m:
                return m.group(1)
    return ""


def _argv_value(argv: list, names: tuple) -> str:
    """Значение опции из argv: `-n x`, `--interface-name x` или `--opt=x`."""
    for i, arg in enumerate(argv):
        if arg in names and i + 1 < len(argv):
            return argv[i + 1]
        for name in names:
            if name.startswith("--") and arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return ""


def debug_enabled() -> bool:
    """Включён ли режим отладки usque (usque.debug_log)."""
    try:
        from core.config_manager import get_config_manager
        return bool(get_config_manager().get("usque", "debug_log",
                                             default=False))
    except Exception:
        return False


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
        # iface -> сколько раз его останавливали. По этому счётчику watchdog
        # отличает «я сам остановил и не смог поднять» от «туннель остановил
        # пользователь» (API, CLI, MCP, teardown — все идут через stop()).
        self._stop_seq = {}
        # {binary: ((mtime, size), ts, version)} — см. _get_version.
        self._version_cache = {}

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
            "external": self.find_external(),
        }

    def find_external(self) -> list:
        """`usque nativetun`, запущенные НЕ нами (init.d Entware и т.п.).

        GUI честно рапортовал «usque остановлен» про свои профили, а на
        роутере в это время работал туннель, поднятый штатным S51usque на
        `opkgtun0`: занимал интерфейс и ~15 МБ ОЗУ, но в статусе не
        значился нигде. Ищем по /proc: бинарник usque + подкоманда
        nativetun, и при этом ни наш дочерний процесс, ни интерфейс, за
        которым стоит наш профиль (<config>.run / pid-файл).

        Возвращает [{pid, iface, config, cmdline}], без /proc — [].
        """
        try:
            pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return []
        with self._lock:
            own_pids = {p.pid for p in self._processes.values()
                        if p and p.poll() is None}
            own_ifaces = set(self._processes)
        out = []
        for pid in pids:
            if pid in own_pids:
                continue
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as f:
                    raw = f.read()
            except (IOError, OSError):
                continue
            argv = [a.decode("utf-8", "replace")
                    for a in raw.split(b"\0") if a]
            if (not argv or os.path.basename(argv[0]) != "usque"
                    or "nativetun" not in argv):
                continue
            iface = _argv_value(argv, ("--interface-name", "-n"))
            config = _argv_value(argv, ("--config", "-c"))
            if iface and (iface in own_ifaces
                          or self._read_pid(self._pid_path(iface)) == pid):
                continue
            out.append({"pid": pid, "iface": iface, "config": config,
                        "cmdline": " ".join(argv)[:300]})
        return out

    def _find_binary(self) -> str:
        """Поиск бинарника usque в стандартных путях.

        Пустой файл установкой не считаем: оборванная закачка оставляет
        нулевой файл с выставленным правом на исполнение, и GUI начинал
        рапортовать «установлен» о том, что запустить нельзя.
        """
        for p in USQUE_BINARY_PATHS:
            try:
                if (os.path.isfile(p) and os.access(p, os.X_OK)
                        and os.path.getsize(p) > 0):
                    return p
            except OSError:
                continue
        return ""

    def _get_version(self, binary: str) -> str:
        """Версия бинарника через подкоманду `usque version`.

        Флага `--version` у usque НЕТ: cobra-команда не объявляет поле
        Version, и вызов падает с rc=1 и текстом
        «Error: unknown flag: --version» плюс полный usage. Раньше мы звали
        именно его, а результат отдавали как версию — GUI показывал
        «Установлен: Error: unknown flag: --version», а /api/usque/version
        всегда рапортовал о доступном обновлении.

        `usque version` печатает в stdout три строки:
            usque version: 4.2.0
            Commit: ...
            Build Date: ...
        Значение «dev» — штатное для сборки без -ldflags, его отдаём как
        есть. В stderr при этом уходит жалоба на отсутствующий config.json
        (usque читает конфиг даже для version), поэтому stderr игнорируем:
        иначе путь к конфигу попадёт в поле версии.

        Сторонние сборки (пакет Entware usque-keenetic и т.п.) бывают
        разговорчивее или пишут версию в stderr, а на нагруженном роутере
        `usque version` может не успеть за таймаут — тогда GUI показывал
        «установлен, версия: (пусто)». Поэтому: stdout, затем строки
        stderr с «version» (кроме жалоб на конфиг), затем версия пакета
        в opkg/apk. Ответ кешируется по mtime+размеру файла: detect()
        дёргают на каждый опрос статуса.
        """
        stamp = _file_stamp(binary)
        hit = self._version_cache.get(binary)
        if hit and hit[0] == stamp and time.time() - hit[1] < (
                _VERSION_TTL if hit[2] else _VERSION_FAIL_TTL):
            return hit[2]
        version = self._probe_version(binary)
        self._version_cache[binary] = (stamp, time.time(), version)
        return version

    @staticmethod
    def _probe_version(binary: str) -> str:
        try:
            r = subprocess.run([binary, "version"],
                               capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=8)
            stdout, stderr = r.stdout or "", r.stderr or ""
        except Exception:
            stdout = stderr = ""
        value = _parse_usque_version(stdout, strict=False)
        if value:
            return value
        value = _parse_usque_version(stderr, strict=True)
        if value:
            return value
        try:
            from core.ext_binary_installer import _pkg_version
            for pkg in ("usque-keenetic", "usque"):
                v = _pkg_version(pkg)
                if v:
                    return v.lstrip("vV")
        except Exception:
            pass
        return ""

    def _get_arch(self, binary: str) -> str:
        """Архитектура бинарника, а при невозможности — архитектура хоста.

        `file` на Entware/busybox обычно НЕ установлен, поэтому раньше
        поле почти всегда оставалось пустым и GUI показывал
        «Архитектура: ?». Архитектура хоста здесь — корректный ответ:
        бинарник заведомо ставился под неё.
        """
        try:
            r = subprocess.run(["file", binary],
                               capture_output=True, text=True, timeout=5)
            out = (r.stdout or "").lower()
            if "aarch64" in out or "arm64" in out:
                return "aarch64"
            if "mips" in out:
                # `file` пишет порядок байт как «LSB»/«MSB», а не словами
                # «little/big endian». Раньше искали «little» — и любой
                # mipsel-бинарник определялся как mips.
                little = ("mipsel" in out or "lsb" in out
                          or "little" in out)
                return "mipsel" if little else "mips"
            if "x86-64" in out or "x86_64" in out:
                return "x86_64"
            if "arm" in out:
                return "armv7"
        except Exception:
            pass
        try:
            from core.awg_detector import get_awg_detector
            info = get_awg_detector().detect_architecture() or {}
            return (info.get("artifact_arch") or info.get("opkg_arch")
                    or info.get("uname_m") or "")
        except Exception:
            return ""

    # ─────── session management ───────

    # Единственный хост, куда ходит `usque register` (internal/consts.go:
    # ApiUrl = "https://api.cloudflareclient.com"). Знание точное, поэтому
    # временный SOCKS сужаем до него, а не открываем «куда угодно».
    _REGISTER_HOST = "api.cloudflareclient.com"

    def register(self, config_path: str, device_name: str = "",
                 team_token: str = "", transport: str = "") -> dict:
        """Зарегистрировать новую WARP-сессию.

        device_name → `-n`: под этим именем устройство видно в аккаунте
        Cloudflare; без него все туннели выглядят одинаково.
        team_token  → `--jwt`: регистрация в ZeroTrust вместо обычного WARP.

        transport   → через что идти к API Cloudflare (спека
        core/download_transport: "", "awg:<iface>", "singbox:<name>",
        "mihomo:<name>"). Нужно там, где провайдер режет сам
        api.cloudflareclient.com: без этого регистрация падает с
        «TLS handshake timeout», хотя рабочий обход на роутере уже есть.

        Как это работает: `usque register` ходит через http.DefaultClient,
        а у него Proxy=http.ProxyFromEnvironment — то есть бинарник
        уважает HTTPS_PROXY. Для singbox/mihomo локальный HTTP-прокси уже
        есть, и мы просто передаём его адрес. У AWG прокси-порта нет,
        поэтому на время регистрации поднимаем эфемерный SOCKS5 на
        loopback, чьи исходящие соединения привязаны к интерфейсу
        (core/iface_socks).

        Замечание про AmneziaWG: сессию usque НЕЛЬЗЯ собрать из .conf
        AWG/WireGuard. Это разные протоколы (MASQUE поверх HTTP/3 против
        WireGuard) и разные ключи: у WireGuard X25519, у usque — ECDSA на
        кривой P-256. Апстрим (Diniboy1123/usque) прямо пишет «no support
        for WireGuard». Единственный путь получить сессию — регистрация
        здесь либо импорт готового usque-конфига (import_config).
        Транспорт выше — про то, КАК дойти до Cloudflare, а не про то, из
        чего сделать сессию.
        """
        binary = self._find_binary()
        if not binary:
            return {"ok": False, "error": "usque не установлен"}

        # Существующий конфиг usque не перезаписывает молча: `register`
        # спрашивает «overwrite? (y/n)» в stdin, и `--accept-tos` этот
        # вопрос НЕ снимает (cmd/register.go апстрима). Из-под init.d это
        # давало «Failed to read response: EOF», из терминала — зависание
        # на весь таймаут. Перезаписывать рабочую сессию нам и не нужно.
        name = os.path.splitext(os.path.basename(config_path))[0]
        taken = self._profile_file(name, os.path.dirname(config_path))
        if taken:
            return {"ok": False,
                    "error": "Профиль '%s' уже существует (%s). Выберите"
                             " другое имя или удалите старый профиль."
                             % (name, os.path.basename(taken))}

        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        cmd = [binary, "register", "--accept-tos", "--config", config_path]
        if device_name:
            cmd.extend(["-n", device_name])
        if team_token:
            cmd.extend(["--jwt", team_token])

        forwarder = None
        try:
            env, forwarder, err = self._register_env(transport)
            if err:
                return {"ok": False, "error": err}
            # stdin=DEVNULL: любой интерактивный вопрос usque должен
            # завершаться сразу, а не ждать ввода от процесса GUI.
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60, env=env,
                stdin=subprocess.DEVNULL)
            if r.returncode != 0:
                return {"ok": False,
                        "error": self._register_error(r, transport,
                                                      forwarder)}
            # usque создаёт конфиг через os.Create — то есть 0666 & umask,
            # обычно 0644. А в файле приватный ключ устройства и
            # access_token: читать его может только владелец.
            try:
                os.chmod(config_path, 0o600)
            except OSError as e:
                log.warning("usque: chmod 600 %s: %s" % (config_path, e),
                            source="usque")
            return {"ok": True, "config_path": config_path,
                    "transport": transport or "direct"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "таймаут регистрации (60s)"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
        finally:
            if forwarder is not None:
                forwarder.stop()

    def _register_env(self, transport: str):
        """(env, forwarder, error) для запуска `usque register`.

        env — окружение с прокси-переменными; forwarder — временный
        SOCKS, который вызывающий обязан остановить.
        """
        env = dict(os.environ)
        # Чужие прокси-переменные в окружении GUI (редко, но бывает при
        # запуске из-под чего-то) не должны молча решать за пользователя,
        # который выбрал «Напрямую».
        for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY",
                    "https_proxy", "ALL_PROXY", "all_proxy"):
            env.pop(key, None)

        if not transport or transport == "direct":
            return env, None, ""

        try:
            from core.download_transport import resolve_transport
        except ImportError as e:
            return env, None, "транспорт недоступен: %s" % e

        resolved = resolve_transport(transport)
        if not resolved.get("ok"):
            return env, None, resolved.get("error", "транспорт недоступен")

        proxy_url = resolved.get("proxy") or ""
        forwarder = None
        if not proxy_url:
            # awg и прочие «интерфейсные» транспорты: порта нет, строим мост.
            device = resolved.get("device") or ""
            if not device:
                return env, None, ("транспорт %s не даёт ни локального прокси,"
                                   " ни интерфейса" % transport)
            from core.iface_socks import IfaceSocksProxy
            forwarder = IfaceSocksProxy(device,
                                        allow_hosts=[self._REGISTER_HOST])
            res = forwarder.start()
            if not res.get("ok"):
                return env, None, ("не удалось пустить регистрацию через %s: %s"
                                   % (device, res.get("error", "")))
            proxy_url = forwarder.url

        for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            env[key] = proxy_url
        # NO_PROXY из окружения может исключить наш хост и обесценить всё
        # вышесказанное.
        for key in ("NO_PROXY", "no_proxy"):
            env.pop(key, None)
        return env, forwarder, ""

    def _register_error(self, proc, transport: str, forwarder) -> str:
        """Сообщение об ошибке регистрации с подсказкой по причине."""
        raw = (proc.stderr or proc.stdout or "ошибка регистрации").strip()
        # usque печатает две строки про отсутствующий config.json ВСЕГДА,
        # в том числе при успехе, — в сообщении об ошибке это только шум.
        lines = [ln for ln in raw.splitlines()
                 if "Config file not found" not in ln
                 and "You may only use the register command" not in ln]
        msg = "\n".join(lines).strip() or raw

        low = msg.lower()
        blocked = ("timeout" in low or "handshake" in low
                   or "connection refused" in low or "no route" in low
                   or "i/o timeout" in low)
        if blocked and (not transport or transport == "direct"):
            msg += ("\n\nПохоже, провайдер режет доступ к %s. Выберите"
                    " «Регистрировать через» — уже поднятый туннель"
                    " (AWG) или прокси (sing-box/mihomo)."
                    % self._REGISTER_HOST)
        elif forwarder is not None and forwarder.connections == 0:
            msg += ("\n\nЧерез выбранный интерфейс не прошло ни одного"
                    " соединения — проверьте, что туннель поднят и"
                    " работает.")
        return msg

    # Поля, которые usque кладёт в свой config.json (см. README апстрима).
    # private_key — ECDSA P-256 в DER/base64, access_token+id — учётка
    # устройства. Ими и отличаем настоящий usque-конфиг от чужого файла.
    _USQUE_REQUIRED = ("private_key", "access_token", "id")
    # endpoint_h2_* — эндпоинты для режима --http2 (H2/TCP). Они есть в
    # КАЖДОМ конфиге, который выдаёт `usque register` v4.x, поэтому без них
    # в списке GUI ругался «неизвестные поля» на полностью нормальный файл.
    # license в бесплатной регистрации отсутствует (появляется только после
    # привязки ключа WARP+), так что он известный, но необязательный.
    _USQUE_KNOWN = _USQUE_REQUIRED + (
        "endpoint_v4", "endpoint_v6", "endpoint_h2_v4", "endpoint_h2_v6",
        "endpoint_pub_key", "license", "ipv4", "ipv6",
    )

    def import_config(self, name: str, text: str) -> dict:
        """
        Сохранить ГОТОВЫЙ usque-конфиг (JSON), полученный извне.

        Это единственный способ «принести» сессию со стороны: собрать её
        из AWG/WireGuard-конфига нельзя — разные протоколы и разные ключи
        (X25519 против ECDSA P-256), апстрим WireGuard не поддерживает.
        """
        import json as _json

        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", name or ""):
            return {"ok": False,
                    "error": "Недопустимое имя (только a-z A-Z 0-9 _ -)"}
        if not (text or "").strip():
            return {"ok": False, "error": "Пустой файл"}
        try:
            data = _json.loads(text)
        except ValueError as e:
            return {"ok": False,
                    "error": "Это не JSON-конфиг usque: %s. Конфиг AmneziaWG"
                             " (.conf) сюда не подойдёт — usque говорит по"
                             " MASQUE, а не по WireGuard." % e}
        if not isinstance(data, dict):
            return {"ok": False, "error": "Ожидается JSON-объект"}
        missing = [k for k in self._USQUE_REQUIRED if not data.get(k)]
        if missing:
            return {"ok": False,
                    "error": "В конфиге нет обязательных полей usque: %s"
                             % ", ".join(missing)}

        config_dir = self._config_dir()
        os.makedirs(config_dir, exist_ok=True)
        path = os.path.join(config_dir, "%s.json" % name)
        real_dir = os.path.realpath(config_dir)
        if not os.path.realpath(path).startswith(real_dir + os.sep):
            return {"ok": False, "error": "path traversal denied"}
        if self._profile_file(name, config_dir):
            # Проверяем все расширения: `warp.conf` от регистрации и
            # `warp.json` от импорта — один и тот же профиль «warp».
            return {"ok": False, "error": "Конфиг '%s' уже существует" % name}

        try:
            from core.safe_io import atomic_write_text
            atomic_write_text(path, _json.dumps(data, indent=2) + "\n")
            os.chmod(path, 0o600)
        except OSError as e:
            return {"ok": False, "error": "Запись %s: %s" % (path, e)}

        unknown = [k for k in data if k not in self._USQUE_KNOWN]
        log.info("usque: импортирован конфиг %s" % name, source="usque")
        return {"ok": True, "name": name, "path": path,
                "unknown_fields": unknown}

    def list_configs(self) -> list:
        """Список доступных конфигов/сессий."""
        config_dir = self._config_dir()
        if not os.path.isdir(config_dir):
            return []
        out = []
        for fn in sorted(os.listdir(config_dir)):
            # .json — родной формат usque (по умолчанию config.json).
            # Раньше он не показывался, поэтому готовый usque-конфиг,
            # принесённый со стороны, GUI просто не видел.
            if fn.endswith(_CONFIG_EXTS):
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

    def _profile_file(self, name: str, config_dir: str = None) -> str:
        """Путь существующего файла профиля `name` с любым расширением ('' нет)."""
        config_dir = config_dir or self._config_dir()
        for ext in _CONFIG_EXTS:
            path = os.path.join(config_dir, name + ext)
            if os.path.exists(path):
                return path
        return ""

    def _detect_iface_for_config(self, config_path: str) -> str:
        """Определить имя интерфейса для конфига (best-effort).

        `.run` — интерфейс ПОДНЯТОГО туннеля, его пишет start() и удаляет
        stop(). `.iface` — имя, ЗАКРЕПЛЁННОЕ за профилем: оно переживает
        остановку, поэтому правило маршрутизации `warp:<iface>` остаётся
        валидным и после «Стоп»/«Старт». Само по себе наличие имени
        «поднятым» туннель не делает — это решает _is_running().
        """
        # Проверяем running config если есть
        run_path = config_path + ".run"
        if os.path.isfile(run_path):
            try:
                with open(run_path) as f:
                    for line in f:
                        if line.startswith("IFACE="):
                            iface = line.split("=", 1)[1].strip().strip('"')
                            if iface:
                                self._seed_assignment(config_path, iface)
                                return iface
            except Exception:
                pass
        return self._read_assigned_iface(config_path)

    def _seed_assignment(self, config_path: str, iface: str) -> None:
        """Закрепить имя уже работающего туннеля, если оно ещё не закреплено.

        Нужно ровно для одного случая — обновления GUI на версию, где имена
        стали выдаваться с префиксом `usque`. Туннель в этот момент обычно
        поднят под старым именем (`opkgtun0`), и на него уже настроены
        правила маршрутизации. Закрепив имя здесь, мы оставляем этот
        профиль на нём навсегда: «Стоп»/«Старт» ничего не сломает.
        """
        if not self._read_assigned_iface(config_path):
            self._assign_iface(config_path, iface)

    @staticmethod
    def _iface_assignment_path(config_path: str) -> str:
        return config_path + ".iface"

    def _read_assigned_iface(self, config_path: str) -> str:
        """Закреплённое за профилем имя интерфейса ('' если не закреплено)."""
        try:
            with open(self._iface_assignment_path(config_path)) as f:
                name = f.read().strip()
        except OSError:
            return ""
        return name if _VALID_IFACE_RE.match(name or "") else ""

    def iface_for_config(self, config_path: str, reserved=None) -> str:
        """Имя интерфейса профиля: закреплённое или новое (и закрепить).

        Раньше имя выделялось на КАЖДЫЙ старт, и профиль после перезапуска
        мог получить чужой номер: правило `warp:usque0` продолжало
        показывать на интерфейс, за которым теперь другой профиль. Здесь
        имя выдаётся один раз и сохраняется рядом с конфигом.
        """
        assigned = self._read_assigned_iface(config_path)
        if assigned and assigned not in set(reserved or ()):
            return assigned
        iface = self.allocate_iface(reserved=reserved)
        if iface:
            self._assign_iface(config_path, iface)
        return iface

    def _assign_iface(self, config_path: str, iface: str) -> None:
        path = self._iface_assignment_path(config_path)
        try:
            with open(path, "w") as f:
                f.write(iface + "\n")
            os.chmod(path, 0o600)
        except OSError as e:
            # Не критично: туннель поднимется, просто на следующем старте
            # имя выделится заново.
            log.warning("usque: имя %s за %s не закреплено: %s"
                        % (iface, os.path.basename(config_path), e),
                        source="usque")

    def forget_iface(self, config_path: str) -> None:
        """Снять закрепление имени (при удалении профиля)."""
        try:
            os.remove(self._iface_assignment_path(config_path))
        except OSError:
            pass

    def allocate_iface(self, prefix: str = None, reserved=None) -> str:
        """Allocate a free interface name without relying on fixed W-I-W names."""
        prefix = str(prefix or DEFAULT_IFACE_PREFIX)[:12]
        if not _IFACE_PREFIX_RE.match(prefix):
            prefix = DEFAULT_IFACE_PREFIX
        reserved = set(reserved or ())
        # Опрос чужих менеджеров дёргает подпроцессы — делаем это ДО того,
        # как возьмём lock жизненного цикла, чтобы не подвешивать на это
        # время параллельные start()/stop().
        claimed = self._names_claimed_elsewhere()
        with self._lock:
            used = set(self._processes) | reserved | claimed
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

    def _names_claimed_elsewhere(self) -> set:
        """Имена, занятые чужими туннелями, даже если те сейчас лежат.

        /sys/class/net показывает только ПОДНЯТЫЕ интерфейсы. Остановленный
        AWG-туннель там не виден, но имя за ним закреплено (конфиг
        `awg0-usque0.conf` поднимется именно как `usque0`), и правила
        маршрутизации уже смотрят на это имя. Заняв его, usque увёл бы
        чужой трафик к себе, а AWG потом не смог бы подняться.

        Сюда же — интерфейсы других профилей usque (работающие из
        <config>.run, закреплённые из <config>.iface): профиль может быть
        остановлен, но правило маршрутизации на его имя протухать не должно.
        """
        names = set()
        try:
            from core.awg_manager import AwgManager
            for cfg in AwgManager().list_configs():
                for key in ("iface", "name"):
                    val = (cfg.get(key) or "").strip()
                    if val:
                        names.add(val)
        except Exception as e:
            # AWG может быть не установлен — это не повод не дать имя.
            log.warning("usque: список AWG-интерфейсов не получен: %s" % e,
                        source="usque")
        try:
            for cfg in self.list_configs():
                iface = (cfg.get("iface") or "").strip()
                if iface:
                    names.add(iface)
        except Exception:
            pass
        return names

    def _buf_size(self) -> int:
        return _MAX_DEBUG_LINES if debug_enabled() else _MAX_DIAGNOSTIC_LINES

    def _capture_stderr(self, iface: str, stream) -> None:
        if not isinstance(stream, (io.TextIOBase, io.BufferedIOBase)):
            return
        buf = self._stderr.setdefault(iface, deque(maxlen=self._buf_size()))
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

    def read_log(self, iface: str, lines: int = 200) -> dict:
        """Хвост вывода usque по интерфейсу (для кнопки «Лог» в GUI).

        Раньше наружу отдавались только последние 8 строк в поле
        `diagnostic` — этого хватает на «не поднялся», но не на разбор
        обрывов. Полный буфер держится в памяти; его глубина зависит от
        режима отладки.
        """
        if not _VALID_IFACE_RE.match(iface or ""):
            return {"ok": False, "error": "Неверное имя интерфейса"}
        buf = list(self._stderr.get(iface) or ())
        try:
            lines = max(1, min(int(lines), _MAX_DEBUG_LINES))
        except (TypeError, ValueError):
            lines = 200
        return {
            "ok": True,
            "iface": iface,
            "debug": debug_enabled(),
            "captured": len(buf),
            "capacity": self._buf_size(),
            "log": "\n".join(buf[-lines:]),
        }

    # ─────── lifecycle ───────

    def start(self, iface: str, config_path: str, *, sni: str = "",
              http2: bool = False, transport_profile: str = "performance",
              low_latency: bool = True, apply_optimizer: bool = True,
              mtu: int = _DEFAULT_MTU) -> dict:
        """Запустить WARP туннель.

        Возврат ok=true означает «процесс жив, интерфейс создан и настроен»,
        а НЕ «WARP подключён»: usque устанавливает MASQUE-соединение лениво,
        при первом исходящем пакете. Поэтому поле `connected` — всегда None,
        подтвердить соединение может только проба трафиком (watchdog).

        Args:
            transport_profile: performance (H3/QUIC), restricted (H2/TCP)
                или auto.

                Важно про auto: здесь он ловит только сбой САМОГО ЗАПУСКА
                (процесс умер / интерфейс не появился). Отказ H3-транспорта
                на старте не виден в принципе — из-за ленивого подключения
                usque стартует успешно даже при наглухо закрытом UDP/443.
                Переключение на H2 в этом случае делает watchdog, когда
                проба через туннель не проходит (core/usque_watchdog.py).
            low_latency: включить безопасный keepalive usque. TCP_NODELAY
                         не является параметром usque CLI, а глобальные
                         buffer sysctl здесь намеренно не меняются.
            mtu: MTU туннеля. Уходит и в usque (`-m`), и на интерфейс —
                 только вместе: usque нарезает буферы под свой `-m`, и
                 TUN с бОльшим MTU отдавал бы ему пакеты, которые тот не
                 примет. Апстрим поддерживает только 1280 (на другое
                 значение печатает предупреждение), поэтому менять его
                 стоит лишь для внешнего туннеля WARP-in-WARP.
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
        try:
            mtu = int(mtu or _DEFAULT_MTU)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Неверный MTU: %r" % (mtu,)}
        if not 1280 <= mtu <= 1500:
            # Ниже 1280 ломается IPv6 внутри CONNECT-IP, выше 1500 — путь.
            return {"ok": False, "error": "MTU %d вне 1280..1500" % mtu}

        # MR-13: Берем lock вокруг всего start() чтобы избежать race condition
        # когда два конкурентных запроса проходят проверку is_running и спавнят процессы
        with self._lock:
            if self._is_running(iface):
                return {"ok": False, "error": "Туннель %s уже запущен" % iface}
            # Имя занято чужим устройством (AWG-туннель под тем же
            # `opkgtun0`, штатный S51usque, оставшийся --persist TUN).
            # Ждать «появления» интерфейса тогда бессмысленно: он есть с
            # самого начала, проверка проходила за 0,1 с — раньше, чем
            # usque успевал упасть с EBUSY, — и _configure_iface вешал наш
            # адрес и MTU 1280 на чужой интерфейс, а наружу уходило ok.
            if self._iface_busy(iface):
                return {"ok": False,
                        "error": "Интерфейс %s уже существует, но usque на"
                                 " нём не запущен: имя занято другим туннелем"
                                 " (AWG, штатный S51usque) или осталось от"
                                 " прежнего запуска. Освободите имя или"
                                 " удалите интерфейс: ip link del %s"
                                 % (iface, iface)}

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
            if mtu != _DEFAULT_MTU:
                cmd.extend(["-m", str(mtu)])

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

                self._stderr[iface] = deque(maxlen=self._buf_size())
                reader = threading.Thread(
                    target=self._capture_stderr,
                    args=(iface, proc.stderr),
                    name="usque-stderr-%s" % iface,
                    daemon=True,
                )
                self._stderr_threads[iface] = reader
                reader.start()

                # Ждём ПОЯВЛЕНИЯ TUN-интерфейса (до 5s).
                #
                # Раньше здесь ждали operstate ∈ {up, unknown}. С флагом
                # --no-iproute2, который мы передаём всегда, usque link не
                # поднимает — operstate остаётся "down", условие не
                # выполнялось никогда, и через 5 с рабочий туннель убивался
                # с «usque не создал интерфейс». Признак готовности здесь —
                # существование интерфейса; поднимаем его мы сами ниже.
                iface_up = False
                for _ in range(50):
                    time.sleep(0.1)
                    if self._iface_exists(iface):
                        iface_up = True
                        break
                    if proc.poll() is not None:
                        break

                # A TUN may appear just before the process exits (for
                # example when the binary rejects a newly unsupported flag),
                # so do one final poll before reporting success.
                if proc.poll() is not None or not iface_up:
                    rc = proc.poll()
                    self._terminate(proc)
                    try:
                        reader.join(timeout=0.25)
                    except Exception:
                        pass
                    diagnostic = self._diagnostic(iface)
                    if transport_profile == "auto":
                        # Ровно один повтор на H2 и только по подтверждённому
                        # отказу запуска. Сетевой отказ H3 сюда не попадает
                        # (ленивое подключение) — им занимается watchdog.
                        fallback = self.start(
                            iface,
                            config_path,
                            sni=sni,
                            transport_profile="restricted",
                            low_latency=low_latency,
                            apply_optimizer=apply_optimizer,
                            mtu=mtu,
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

                # Интерфейс есть, но он «пустой»: адреса и link — на нас
                # (см. _configure_iface). Делать это надо ДО того, как
                # туннель объявлен запущенным, иначе наружу уйдёт ok=true
                # на заведомо неработающий интерфейс.
                configured = self._configure_iface(iface, config_path, mtu=mtu)
                if not configured.get("ok"):
                    self._terminate(proc)
                    try:
                        reader.join(timeout=0.25)
                    except Exception:
                        pass
                    return {"ok": False, "error": configured.get("error", ""),
                            "diagnostic": self._diagnostic(iface)}

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

                log.info("usque: туннель %s запущен (pid=%d, %s)"
                         % (iface, proc.pid, configured.get("ipv4") or "без v4"),
                         source="usque")
                # ВАЖНО: ok=true означает «процесс жив и интерфейс настроен»,
                # а НЕ «WARP подключён». usque подключается лениво — только
                # при первом исходящем пакете (в логе это «Detected outbound
                # activity … Establishing MASQUE connection»). Факт реального
                # соединения проверяет проба watchdog'а, а не старт.
                return {"ok": True, "pid": proc.pid, "iface": iface,
                        "transport_profile": transport_profile,
                        "mtu": mtu,
                        "ipv4": configured.get("ipv4", ""),
                        "ipv6": configured.get("ipv6", ""),
                        "connected": None}

            except OSError as e:
                return {"ok": False, "error": _exec_error_text(binary, e),
                        "diagnostic": self._diagnostic(iface)}
            except Exception as e:
                return {"ok": False, "error": str(e),
                        "diagnostic": self._diagnostic(iface)}

    def stop(self, iface: str, restore_defaults: bool = True) -> dict:
        """Остановить WARP туннель.

        restore_defaults=False — не трогать системные defaults в конце.
        Нужен WARP-in-WARP: он гасит свои слои под собственным замком, а
        restore_system_defaults(only_if_idle=True) обходит туннели через
        tunnel_monitor, который спрашивает статус у того же WARP-in-WARP.
        Defaults тот восстанавливает сам, отпустив замок (issue #416)."""
        if not _VALID_IFACE_RE.match(iface):
            return {"ok": False, "error": "Неверное имя интерфейса: %s" % iface}

        pid_path = self._pid_path(iface)
        pid = self._read_pid(pid_path)

        # Пробуем остановить через stored process
        proc = None
        with self._lock:
            proc = self._processes.pop(iface, None)
            config_path = self._config_by_iface.pop(iface, None)
            self._stop_seq[iface] = self._stop_seq.get(iface, 0) + 1

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
        elif pid and self._pid_is_usque(pid, iface):
            # Fallback: kill по PID. Только если PID действительно наш —
            # иначе после перезагрузки (pid-файл в /opt переживает ребут)
            # killpg снёс бы группу постороннего процесса от root.
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
        # Убираем .run-файл. config_path известен, только если туннель
        # поднимали в этом же процессе GUI; после рестарта GUI его нет —
        # тогда ищем .run по имени интерфейса, иначе list_configs()
        # продолжал бы показывать конфиг привязанным к мёртвому iface.
        for run_path in self._run_files_for_iface(iface, config_path):
            try:
                os.remove(run_path)
            except OSError:
                pass

        self._stderr_threads.pop(iface, None)

        # MR-05: Восстанавливаем системные defaults, если нет других активных туннелей
        if restore_defaults:
            try:
                from core.tunnel_optimizer import restore_system_defaults
                restore_system_defaults(only_if_idle=True)
            except Exception:
                pass

        log.info("usque: туннель %s остановлен" % iface, source="usque")
        return {"ok": True}

    def status(self, iface: str) -> dict:
        """Статус туннеля.

        `link_up` отделён от `iface_exists` намеренно: «интерфейс есть, но
        link down» — это ровно тот случай, когда usque отработал, а наша
        настройка адресов не доехала, и трафика не будет. Ни то, ни другое
        поле не означает «WARP подключён»: соединение у usque ленивое.
        """
        running = self._is_running(iface)
        pid = self._read_pid(self._pid_path(iface))
        return {
            "running": running,
            "iface_exists": self._iface_exists(iface),
            "link_up": self._check_iface_up(iface),
            "iface": iface,
            "pid": pid,
            "diagnostic": self._diagnostic(iface),
        }

    def stop_seq(self, iface: str) -> int:
        """Сколько раз туннель останавливали (для watchdog'а)."""
        with self._lock:
            return self._stop_seq.get(iface, 0)

    def _iface_exists(self, iface: str) -> bool:
        return os.path.exists("/sys/class/net/%s" % iface)

    def _iface_busy(self, iface: str) -> bool:
        """Интерфейс с этим именем существует ДО нашего запуска."""
        return os.path.exists("/sys/class/net/%s" % iface)

    @staticmethod
    def _terminate(proc) -> None:
        """Погасить usque, который не дожил до «запущен»: TERM, потом KILL.

        Голого terminate()+wait(1) мало: не уложившийся в секунду процесс
        оставался жить вместе со своим TUN, и следующий старт (например,
        повтор auto на H2) упирался в занятое имя.
        """
        try:
            proc.terminate()
            proc.wait(timeout=1)
            return
        except Exception:
            pass
        try:
            proc.kill()
            proc.wait(timeout=1)
        except Exception:
            pass

    # ─────── настройка TUN-интерфейса ───────

    def _tunnel_addresses(self, config_path: str) -> tuple:
        """(ipv4, ipv6) ВНУТРИ туннеля из session-конфига usque."""
        import json as _json
        try:
            with open(config_path) as f:
                data = _json.load(f)
        except (OSError, ValueError):
            return "", ""
        if not isinstance(data, dict):
            return "", ""
        return (str(data.get("ipv4") or "").strip(),
                str(data.get("ipv6") or "").strip())

    def _configure_iface(self, iface: str, config_path: str,
                         mtu: int = _DEFAULT_MTU) -> dict:
        """Назначить адреса и поднять link на TUN, созданном usque.

        Мы запускаем usque с `--no-iproute2`, а этот флаг, вопреки имени,
        означает «не назначать адреса И НЕ ПОДНИМАТЬ link» — usque прямо
        пишет «You should set the link up manually». Без этого шага
        интерфейс существует, но остаётся operstate=down и без единого
        адреса: трафик через него не пойдёт никогда.

        Почему вообще `--no-iproute2`, а не штатная настройка самим usque:
        в штатном режиме usque падает ЦЕЛИКОМ на хосте без IPv6
        («failed to add IPv6 address: operation not supported»), потому что
        любая ошибка netlink там фатальна. Здесь IPv4 обязателен, а IPv6 —
        best-effort.

        Порядок и префиксы повторяют cmd/nativetun_linux.go апстрима:
        MTU → адрес /32 → адрес /128 → link up.
        """
        v4, v6 = self._tunnel_addresses(config_path)
        if not v4 and not v6:
            # Без адреса интерфейс «поднят», но трафик через него не пойдёт
            # никогда — это не запущенный туннель, а ошибка конфига.
            return {"ok": False,
                    "error": "в конфиге %s нет ни ipv4, ни ipv6 — адрес"
                             " туннеля неизвестен; перерегистрируйте"
                             " профиль" % os.path.basename(config_path)}

        if mtu:
            _run(["ip", "link", "set", "dev", iface, "mtu", str(mtu)])

        if v4:
            rc, _out, err = _run(
                ["ip", "-4", "address", "add", "%s/32" % v4, "dev", iface])
            if rc != 0 and "exists" not in (err or "").lower():
                return {"ok": False,
                        "error": "не удалось назначить IPv4 %s на %s: %s"
                                 % (v4, iface, (err or "").strip())}
        if v6:
            # IPv6 намеренно best-effort: на роутере без v6 отсутствие
            # адреса не повод ронять рабочий v4-туннель.
            rc, _out, err = _run(
                ["ip", "-6", "address", "add", "%s/128" % v6, "dev", iface])
            if rc != 0 and "exists" not in (err or "").lower():
                log.info("usque: IPv6 %s на %s не назначен: %s"
                         % (v6, iface, (err or "").strip()), source="usque")

        rc, _out, err = _run(["ip", "link", "set", "dev", iface, "up"])
        if rc != 0:
            return {"ok": False,
                    "error": "не удалось поднять %s: %s"
                             % (iface, (err or "").strip())}

        return {"ok": True, "ipv4": v4, "ipv6": v6, "mtu": mtu}

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
                # PID жив — но наш ли это процесс? _pid_dir = /opt/var/run
                # лежит на постоянном носителе, pid-файлы переживают
                # перезагрузку, и тот же PID почти наверняка занят чужим
                # процессом: туннель считался бы поднятым (старт
                # отклонялся бы как «уже запущен»), а stop() убивал бы
                # целую группу постороннего процесса.
                return self._pid_is_usque(pid, iface)
            except ProcessLookupError:
                pass
            except PermissionError:
                return True  # есть процесс, нет прав на kill
        return False

    def _run_files_for_iface(self, iface: str, config_path: str = None) -> list:
        """Пути .run-файлов, относящихся к интерфейсу."""
        out = []
        if config_path:
            out.append(config_path + ".run")
        config_dir = self._config_dir()
        try:
            names = os.listdir(config_dir)
        except OSError:
            return [p for p in out if os.path.isfile(p)]
        for fn in names:
            if not fn.endswith(".run"):
                continue
            path = os.path.join(config_dir, fn)
            if path in out:
                continue
            try:
                with open(path) as f:
                    body = f.read()
            except OSError:
                continue
            if ('IFACE="%s"' % iface) in body:
                out.append(path)
        return [p for p in out if os.path.isfile(p)]

    def _pid_is_usque(self, pid: int, iface: str = None) -> bool:
        """Наш ли это `usque nativetun` (для iface — именно на этом интерфейсе).

        Подстроки «usque» в cmdline мало: её содержат `amneziawg-go usque0`
        (AWG-конфиг `awg0-usque0.conf`) и `zapret-gui usque status`. После
        перезагрузки pid-файл указывает на случайный процесс, а порядок
        загрузки роутера повторяет PID'ы, — и stop() слал бы killpg чужой
        группе. Поэтому сверяем сам бинарник, подкоманду и интерфейс.

        /proc недоступен (не Linux, тест) → доверяем, как и раньше.
        Пустой cmdline — зомби или поток ядра, это не наш живой процесс.
        """
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                raw = f.read()
        except (IOError, OSError, ValueError):
            return True
        argv = [a.decode("utf-8", "replace")
                for a in raw.split(b"\0") if a]
        if not argv:
            return False
        if os.path.basename(argv[0]) != "usque" or "nativetun" not in argv:
            return False
        if not iface:
            return True
        for i, arg in enumerate(argv[:-1]):
            if arg in ("--interface-name", "-n") and argv[i + 1] == iface:
                return True
        return ("--interface-name=%s" % iface) in argv

    def _check_iface_up(self, iface: str) -> bool:
        """Поднят ли link на интерфейсе (диагностика в status()).

        Как признак «туннель стартовал» НЕ годится: мы запускаем usque с
        --no-iproute2, и до нашего `ip link set up` operstate у TUN — "down".
        Готовность старта определяет _iface_exists().

        У TUN-устройств «поднятое» состояние читается и как "up", и как
        "unknown" (второе — обычное для интерфейсов без carrier), поэтому
        оба значения считаем поднятыми.

        MR-126: читаем /sys/class/net вместо subprocess ip link show,
        чтобы исключить лишние fork/exec при частых опросах.
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
