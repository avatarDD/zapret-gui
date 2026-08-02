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

_MAX_DIAGNOSTIC_LINES = 40
# В режиме отладки держим заметно более длинный хвост: 40 строк хватает
# на «почему не поднялся», но не на «почему отваливается через час».
# Буфер в ОЗУ, а не файл: на роутере лишняя запись на флешку ни к чему.
_MAX_DEBUG_LINES = 500
# Дефолт usque (`-m/--mtu`, cmd/nativetun.go). Держим то же значение: с
# --no-iproute2 MTU выставляем мы, и расхождение с тем, из чего usque
# нарезает пакеты внутри туннеля, дало бы фрагментацию.
_DEFAULT_MTU = 1280


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
        """
        try:
            r = subprocess.run([binary, "version"],
                               capture_output=True, text=True, timeout=5)
        except Exception:
            return ""
        for line in (r.stdout or "").splitlines():
            if "version:" not in line.lower():
                continue
            value = line.split(":", 1)[1].strip()
            m = re.search(r"v?(\d+\.\d+(?:\.\d+)*)", value)
            return m.group(1) if m else value[:50]
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
            if "mipsel" in out or "mips" in out:
                return "mipsel" if "little" in out or "mipsel" in out else "mips"
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
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60, env=env)
            if r.returncode != 0:
                return {"ok": False,
                        "error": self._register_error(r, transport,
                                                      forwarder)}
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
        if os.path.exists(path):
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
            if fn.endswith((".conf", ".toml", ".json")):
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
              low_latency: bool = True, apply_optimizer: bool = True) -> dict:
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
                configured = self._configure_iface(iface, config_path)
                if not configured.get("ok"):
                    try:
                        proc.terminate()
                        proc.wait(timeout=1)
                    except Exception:
                        pass
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
                        "ipv4": configured.get("ipv4", ""),
                        "ipv6": configured.get("ipv6", ""),
                        "connected": None}

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
        elif pid and self._pid_is_usque(pid):
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

    def _iface_exists(self, iface: str) -> bool:
        return os.path.exists("/sys/class/net/%s" % iface)

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
                return self._pid_is_usque(pid)
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

    def _pid_is_usque(self, pid: int) -> bool:
        """Принадлежит ли PID процессу usque. /proc недоступен → доверяем."""
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except (IOError, OSError, ValueError):
            return True
        return "usque" in cmd.lower() if cmd.strip() else True

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
