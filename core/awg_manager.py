# core/awg_manager.py
"""
Менеджер AmneziaWG-интерфейсов: CRUD конфигов и up/down туннелей.

amneziawg-go — userspace-демон, создающий TUN-интерфейс. Поднятие туннеля:
  1) запустить amneziawg-go <iface> (форкается, держит TUN)
  2) `awg setconf <iface> <filtered.conf>` — применить параметры WG/AWG
  3) ip address add ... + ip link set up + MTU
  4) добавить маршруты из AllowedIPs (если не Table=off)
  5) выполнить PostUp-команды (если есть)

Down:
  1) ip link delete dev <iface> (snimaet TUN, демон умирает)
  2) если демон жив — kill PID
  3) ip rule/route наши добавки убираем
  4) PostDown-команды

Конфиги храним в platform.config_dir (например /opt/etc/amneziawg/<name>.conf).
Для каждого активного интерфейса используем:
  - <platform.run_dir>/awg-<iface>.pid     — PID amneziawg-go
  - <platform.run_dir>/awg-<iface>.routes  — список добавленных нами маршрутов
"""

import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time

from core.awg_config import (
    parse_conf,
    render_conf,
    render_setconf,
    validate as validate_cfg,
)
from core.awg_detector import get_awg_detector
from core.awg_installer import get_awg_installer
from core.log_buffer import log


# ───────────────────────── helpers ───────────────────────────────────

def _run(args, timeout=15, input_text=None, env=None):
    """Запустить команду, вернуть (returncode, stdout, stderr).

    env=None — наследовать окружение текущего процесса (по умолчанию).
    Передаётся для запуска amneziawg-go с лимитом памяти Go (GOGC/GOMEMLIMIT).
    """
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            input=input_text, env=env,
        )
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
        return pid > 0 and isinstance(pid, int) and \
               os.path.exists("/proc/%d" % pid)
    except OSError:
        return False


_AWG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")


def _valid_iface_name(name: str) -> bool:
    return bool(name) and bool(_AWG_NAME_RE.match(name))


# ───────────────────────── manager ───────────────────────────────────

class AwgManager:
    """CRUD конфигов и управление интерфейсами AmneziaWG."""

    def __init__(self):
        self._lock = threading.Lock()

    # ─────────── platform / paths ───────────

    def _platform(self):
        return get_awg_detector().detect_platform()

    def _binary_dir(self):
        info = get_awg_installer().get_installed_version()
        return info.get("binary_dir") or self._platform().binary_dir

    def _amneziawg_go(self):
        info = get_awg_installer().get_installed_version()
        if info.get("amneziawg_go") and os.path.isfile(info["amneziawg_go"]):
            return info["amneziawg_go"]
        return os.path.join(self._binary_dir(), "amneziawg-go")

    def _amneziawg_go_env(self):
        """
        Окружение для запуска amneziawg-go. Если в настройках включён лимит
        памяти Go (awg.go_mem_enabled) — добавляем GOGC/GOMEMLIMIT, чтобы
        userspace-демон не разрастался и не доводил слабый роутер до OOM.
        Возвращает None (наследовать окружение) либо dict.
        """
        try:
            from core.config_manager import get_config_manager
            cm = get_config_manager()
            if not cm.get("awg", "go_mem_enabled", default=False):
                return None
            gogc = int(cm.get("awg", "go_gogc", default=50) or 0)
            memmb = int(cm.get("awg", "go_memlimit_mb", default=0) or 0)
        except Exception:
            return None
        env = dict(os.environ)
        if gogc > 0:
            env["GOGC"] = str(gogc)
        if memmb > 0:
            env["GOMEMLIMIT"] = "%dMiB" % memmb
        return env

    def _awg_bin(self):
        info = get_awg_installer().get_installed_version()
        if info.get("awg") and os.path.isfile(info["awg"]):
            return info["awg"]
        # Может звать `awg` через PATH, если в installed_dir не нашли
        return os.path.join(self._binary_dir(), "awg")

    # ─────────── binary health ───────────

    # Маркеры в stderr/исключении, означающие, что бинарник в принципе
    # не запускается (несовместимая архитектура/битый файл). На Entware
    # с busybox несовместимый ELF часто приводит к тому, что шелл пытается
    # интерпретировать его как скрипт → `syntax error: unexpected "("`.
    _BROKEN_BIN_MARKERS = (
        "exec format error",
        "syntax error",
        "cannot execute binary",
        "not executable",
    )

    def _probe_binary(self, path: str) -> dict:
        """
        Проверить, что бинарник вообще исполняется (лёгкий `--version`).

        Возвращает {"ok": bool, "exists": bool, "broken": bool,
        "detail": str}. broken=True означает «файл есть, но запустить
        нельзя» — типично после внешнего обновления awg бинарником под
        чужую архитектуру.
        """
        res = {"ok": False, "exists": False, "broken": False, "detail": ""}
        if not path or not os.path.isfile(path):
            res["detail"] = "файл не найден: %s" % (path or "—")
            return res
        res["exists"] = True
        rc, out, err = _run([path, "--version"], timeout=5)
        blob = ((err or "") + " " + (out or "")).strip()
        res["detail"] = blob
        low = blob.lower()
        if any(m in low for m in self._BROKEN_BIN_MARKERS):
            res["broken"] = True
            return res
        # rc может быть != 0 у некоторых сборок при --version, но если
        # маркеров «битости» нет — считаем, что бинарник запускается.
        res["ok"] = True
        return res

    def _binary_help_suffix(self) -> str:
        """Actionable-подсказка, куда идти чинить битые/внешние бинарники."""
        try:
            info = get_awg_installer().get_installed_version()
        except Exception:
            info = {}
        if info.get("external"):
            return (" Бинарники AmneziaWG установлены не через zapret-gui"
                    " (external) и, похоже, несовместимы с этим устройством"
                    " после внешнего обновления. Переустановите их во вкладке"
                    " «AmneziaWG → Setup».")
        return " Переустановите бинарники во вкладке «AmneziaWG → Setup»."

    def _config_dir(self):
        d = self._platform().config_dir
        os.makedirs(d, exist_ok=True)
        return d

    def _run_dir(self):
        d = self._platform().run_dir
        os.makedirs(d, exist_ok=True)
        return d

    def _scan_dirs(self) -> list:
        """
        Все каталоги, в которых ищем конфиги: основной platform.config_dir
        плюс дополнительные кандидаты (на Keenetic пользователи иногда
        держат конфиги в /opt/etc/amnezia/amneziawg/ и т.п.).
        """
        from core.awg_detector import AwgDetector
        primary = self._platform().config_dir
        seen = set()
        dirs = []
        for d in [primary] + list(AwgDetector.CONFIG_DIR_CANDIDATES):
            if d and d not in seen and os.path.isdir(d):
                seen.add(d)
                dirs.append(d)
        return dirs

    def _config_path(self, name: str) -> str:
        """
        Найти .conf для имени конфига во всех известных каталогах.
        Если нигде нет — возвращаем путь в platform.config_dir
        (туда будем сохранять новый файл при save).
        """
        fname = "%s.conf" % name
        for d in self._scan_dirs():
            p = os.path.join(d, fname)
            if os.path.isfile(p):
                return p
        return os.path.join(self._config_dir(), fname)

    def _pid_path(self, iface: str) -> str:
        return os.path.join(self._run_dir(), "awg-%s.pid" % iface)

    def _routes_path(self, iface: str) -> str:
        return os.path.join(self._run_dir(), "awg-%s.routes.json" % iface)

    def _last_up_path(self, iface: str) -> str:
        """Снимок состояния, сохранённый при последнем `up`."""
        return os.path.join(self._run_dir(), "awg-%s.last_up.json" % iface)

    # ─────────── CRUD ───────────

    def _all_config_names(self) -> set:
        """Имена всех .conf во всех каталогах (без расширения)."""
        names = set()
        for d in self._scan_dirs():
            try:
                for f in os.listdir(d):
                    if f.endswith(".conf"):
                        names.add(f[:-5])
            except OSError:
                continue
        return names

    def list_configs(self) -> list:
        """
        Список конфигов из всех известных каталогов.

        Каждая запись возвращает не только имя файла, но и `iface` —
        фактическое имя сетевого интерфейса. Это нужно для случаев,
        когда конфиг назван по схеме `<label>-<iface>.conf` (например
        `awg0-opkgtun0.conf` для интерфейса `opkgtun0`) — типично
        для скриптов, оборачивающих awg-quick.
        """
        seen = set()  # по имени файла (без .conf)
        active_ifaces = self._wg_interfaces()
        known_names = self._all_config_names()
        result = []
        for d in self._scan_dirs():
            try:
                files = sorted(os.listdir(d))
            except OSError:
                continue
            for f in files:
                if not f.endswith(".conf"):
                    continue
                name = f[:-5]
                if name in seen:
                    continue
                seen.add(name)
                path = os.path.join(d, f)
                if not os.path.isfile(path):
                    continue
                try:
                    stat = os.stat(path)
                    size = stat.st_size
                    mtime = int(stat.st_mtime)
                except OSError:
                    size = 0
                    mtime = 0
                iface = self._resolve_iface_name(name, path, active_ifaces,
                                                 known_names=known_names)
                active = self.is_running(iface) or self.is_running(name)
                result.append({
                    "name":   name,
                    "iface":  iface,
                    "path":   path,
                    "size":   size,
                    "mtime":  mtime,
                    "active": active,
                })
        return result

    def _resolve_iface_name(self, config_name: str, config_path: str,
                            active_ifaces: list, known_names=None) -> str:
        """
        Определяет имя сетевого интерфейса, которому принадлежит конфиг.

        Эвристика:
          1. Если имя конфига совпадает с активным интерфейсом — оно и есть.
          2. Если конфиг назван `<label>-<iface>.conf` и `<iface>` есть в
             списке активных — возвращаем `<iface>`.
          3. Сверка по PublicKey пира: если в конфиге есть [Peer]/PublicKey,
             совпадающий с PublicKey пира одного из активных интерфейсов,
             возвращаем имя этого интерфейса.
          4. Иначе — возвращаем сам name (классический wg-quick case).

        `known_names` — множество имён всех известных конфигов. Нужно,
        чтобы шаг 3 не «присваивал» чужой интерфейс: несколько WARP-конфигов
        имеют ОДИН и тот же PublicKey пира (общий публичный ключ сервера
        Cloudflare), поэтому без этой проверки поднятый `WARP_a` помечал бы
        активным и неподнятый `WARP_b`. Интерфейс, чьё имя совпадает с
        именем другого конфига, считаем принадлежащим тому конфигу.
        """
        active = set(active_ifaces or [])
        if config_name in active:
            return config_name

        if "-" in config_name:
            suffix = config_name.rsplit("-", 1)[-1]
            if suffix and suffix in active:
                return suffix

        # Сверка по PublicKey пира — медленнее, но надёжно.
        try:
            with open(config_path, "r") as f:
                cfg = parse_conf(f.read())
        except (IOError, OSError, ValueError):
            return config_name

        peer_keys = set()
        for peer in cfg.get("peers", []) or []:
            pk = (peer.get("PublicKey") or "").strip()
            if pk:
                peer_keys.add(pk)

        known = set(known_names or ())
        if peer_keys:
            for iface in active:
                # Интерфейс с именем другого конфига — его и оставляем
                # тому конфигу, не воруем по совпадению pubkey (WARP).
                if iface != config_name and iface in known:
                    continue
                rc, out, _ = _run([self._awg_bin(), "show", iface, "dump"], timeout=5)
                if rc != 0 or not out.strip():
                    continue
                lines = [l for l in out.splitlines() if l.strip()]
                # Первая строка — [Interface], дальше — пиры (поле[0] = pubkey).
                for line in lines[1:]:
                    parts = line.split("\t")
                    if not parts:
                        continue
                    iface_pk = parts[0].strip()
                    if iface_pk and iface_pk in peer_keys:
                        return iface

        return config_name

    def get_config(self, name: str) -> dict:
        """
        Получить конфиг {name, path, text, parsed, errors}.
        """
        if not _valid_iface_name(name):
            raise ValueError("Недопустимое имя конфига")
        path = self._config_path(name)
        if not os.path.isfile(path):
            raise FileNotFoundError(name)
        with open(path, "r") as f:
            text = f.read()
        parsed = parse_conf(text)
        return {
            "name":   name,
            "path":   path,
            "text":   text,
            "parsed": parsed,
            "errors": validate_cfg(parsed),
            "active": self.is_running(name),
        }

    def save_config(self, name: str, text: str = None,
                    parsed: dict = None, allow_overwrite: bool = True) -> dict:
        """
        Сохранить конфиг. На вход — либо `text` (raw .conf), либо `parsed`
        (структура для render_conf). Возвращает результат get_config.
        """
        if not _valid_iface_name(name):
            raise ValueError("Имя должно содержать только латиницу, "
                             "цифры, '_-.', не длиннее 15 символов")

        if text is None and parsed is None:
            raise ValueError("Нужно передать text или parsed")

        if text is None:
            text = render_conf(parsed)
        else:
            parsed = parse_conf(text)

        errors = validate_cfg(parsed)
        if errors:
            raise ValueError("Ошибки конфига: " + "; ".join(errors))

        path = self._config_path(name)
        if os.path.exists(path) and not allow_overwrite:
            raise FileExistsError(name)

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

        log.info("Сохранён AWG-конфиг %s" % name, source="awg_manager")
        return self.get_config(name)

    def delete_config(self, name: str) -> dict:
        """Удалить конфиг (и опустить интерфейс, если поднят)."""
        if not _valid_iface_name(name):
            raise ValueError("Недопустимое имя")
        if self.is_running(name):
            self.down(name)
        path = self._config_path(name)
        if os.path.isfile(path):
            os.remove(path)
            log.info("Удалён AWG-конфиг %s" % name, source="awg_manager")
        return {"ok": True, "name": name}

    # ─────────── interface state ───────────

    def is_running(self, iface: str) -> bool:
        pid = _read_pid(self._pid_path(iface))
        if pid and _pid_alive(pid):
            return True
        # Fallback — есть в `wg show interfaces`
        return iface in self._wg_interfaces()

    def _iface_for_name(self, name: str) -> str:
        """
        Найти имя реально работающего интерфейса для конфига `name`.
        Используется при down/restart: если конфиг назван
        `awg0-opkgtun0`, а активный интерфейс — `opkgtun0`, операции
        должны идти по `opkgtun0`.
        """
        active = self._wg_interfaces()
        if name in active:
            return name
        path = self._config_path(name)
        if os.path.isfile(path):
            # known_names — чтобы down/restart неподнятого WARP-конфига не
            # резолвился по общему pubkey в чужой активный интерфейс и не
            # ронял его (см. _resolve_iface_name).
            return self._resolve_iface_name(name, path, active,
                                            known_names=self._all_config_names())
        if "-" in name:
            suffix = name.rsplit("-", 1)[-1]
            if suffix in active:
                return suffix
        return name

    def _wg_interfaces(self) -> list:
        rc, out, _ = _run([self._awg_bin(), "show", "interfaces"], timeout=5)
        if rc == 0 and out.strip():
            return out.split()
        # сначала через ip link
        rc, out, _ = _run(["ip", "link", "show", "type", "wireguard"])
        if rc == 0:
            ifs = []
            for line in out.splitlines():
                m = re.match(r"\d+:\s+(\S+?)[@:]", line)
                if m:
                    ifs.append(m.group(1))
            return ifs
        return []

    def list_interfaces(self) -> list:
        """Все активные AWG/WG интерфейсы со статусом.

        На Keenetic'е дополнительно подцепляем нативные WG-туннели,
        поднимаемые самим роутером (Wireguard0..N). Они видны только
        через NDMS RCI — `wg show` их не возвращает, потому что они
        существуют в ядре Keenetic'а, а не в userspace.
        """
        seen = set()
        result = []
        for name in self._wg_interfaces():
            if name in seen:
                continue
            seen.add(name)
            result.append(self.status(name))

        # Нативные Keenetic-WG-интерфейсы — только если мы реально на
        # Keenetic'е с доступным RCI. На любой другой платформе
        # list_native_wg_interfaces() вернёт [] без сетевого probe.
        try:
            from core.ndms import list_native_wg_interfaces, get_native_wg_status
            for native in list_native_wg_interfaces():
                nm = native.get("name", "")
                if not nm or nm in seen:
                    continue
                seen.add(nm)
                # Состояние тащим через NDMS, не через awg show (его
                # для нативных интерфейсов нет вообще).
                st = get_native_wg_status(nm)
                result.append({
                    "name":       nm,
                    "active":     bool(st.get("active")),
                    "pid":        None,
                    "peers":      [],
                    "interface":  {},
                    "source":     "ndms",   # маркер, чтобы UI знал
                    "native":     True,
                    "description": native.get("description", ""),
                    "address":    native.get("address", ""),
                    "state":      st.get("state", ""),
                    "rx_bytes":   st.get("rx_bytes", 0),
                    "tx_bytes":   st.get("tx_bytes", 0),
                    "endpoint":   st.get("endpoint", ""),
                    "last_handshake": st.get("last_handshake", 0),
                })
        except Exception as e:
            log.warning("list_interfaces: ndms-часть не подцепилась: %s" % e,
                        source="awg")
        return result

    def status(self, iface: str) -> dict:
        """Статус интерфейса: peers, last handshake, RX/TX и пр.

        Принимает либо имя реального интерфейса (`opkgtun0`), либо имя
        конфига (`awg0-opkgtun0`) — во втором случае резолвим в реальный.
        """
        resolved = self._iface_for_name(iface)
        if resolved and resolved != iface and resolved in self._wg_interfaces():
            iface = resolved
        info = {
            "name":     iface,
            "active":   False,
            "pid":      _read_pid(self._pid_path(iface)),
            "peers":    [],
            "interface": {},
        }

        # Нативный Keenetic-WG (Wireguard0/1...): `awg show` его не
        # видит вообще — он в ядре роутера, а не в userspace. Идём
        # за состоянием в NDMS RCI.
        try:
            from core.ndms.ping_check import (
                should_delegate_monitoring, get_native_wg_status)
            if should_delegate_monitoring(iface):
                st = get_native_wg_status(iface)
                if st.get("available"):
                    info["active"] = bool(st.get("active"))
                    info["source"] = "ndms"
                    info["native"] = True
                    info["state"]  = st.get("state", "")
                    info["rx_bytes"] = st.get("rx_bytes", 0)
                    info["tx_bytes"] = st.get("tx_bytes", 0)
                    info["endpoint"] = st.get("endpoint", "")
                    info["last_handshake"] = st.get("last_handshake", 0)
                return info
        except Exception as e:
            log.warning("status(%s) ndms delegation: %s" % (iface, e),
                        source="awg")

        rc, out, _ = _run([self._awg_bin(), "show", iface, "dump"], timeout=5)
        if rc != 0 or not out.strip():
            return info
        info["active"] = True
        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            return info
        # Первая строка — секция [Interface]: priv pub listen-port fwmark
        parts = lines[0].split("\t")
        if len(parts) >= 3:
            info["interface"] = {
                "private_key": "***" if parts[0] != "(none)" else "",
                "public_key":  parts[1] if parts[1] != "(none)" else "",
                "listen_port": _safe_int(parts[2]),
                "fwmark":      parts[3] if len(parts) > 3 else "",
            }
        for line in lines[1:]:
            p = line.split("\t")
            if len(p) < 8:
                continue
            info["peers"].append({
                "public_key":      p[0],
                "preshared_key":   "***" if p[1] not in ("(none)", "") else "",
                "endpoint":        p[2] if p[2] != "(none)" else "",
                "allowed_ips":     p[3],
                "latest_handshake": _safe_int(p[4]),
                "rx_bytes":        _safe_int(p[5]),
                "tx_bytes":        _safe_int(p[6]),
                "persistent_keepalive": p[7] if p[7] != "off" else "",
            })
        return info

    # ─────────── diagnostics ───────────

    def diagnostics(self, name: str) -> dict:
        """
        Полный снимок состояния туннеля + системного routing.

        Используется GUI'ем как «диагностическая кнопка», когда после
        `awg up` пропадает инет — даёт всё, что нужно, чтобы понять,
        куда уходят пакеты и видит ли амнеziaWG последний handshake.
        Не дёргает `_lock`, чтобы можно было звать параллельно с
        up/down (читаем только текущее состояние ядра).
        """
        ifname = self._iface_for_name(name) or name
        table  = self._table_id_for(ifname)
        # GUI-версия — критично, чтобы понимать, какой код выполнялся
        # при создании снимка (мы регулярно правим setconf-рендер).
        try:
            from core.version import GUI_VERSION as _gv
        except Exception:
            _gv = "?"
        info   = {
            "name":         name,
            "iface":        ifname,
            "table_id":     table,
            "gui_version":  _gv,
            "active":       False,
            "platform":     {},
            "binaries":     {},
            "setconf_text": "",
            "awg_show":     "",
            "interface_state": {},
            "rules":  {"v4": "", "v6": ""},
            "routes": {
                "table_v4":  "",
                "table_v6":  "",
                "main_v4":   "",
                "main_v6":   "",
            },
            "endpoint_routes": [],
            "last_up":   None,
            "log_tail":  [],
            "routing_state": {},
            "errors": [],
        }

        # Здоровье бинарников: после внешнего обновления awg частая
        # причина «demon не стартует / setconf падает с syntax error» —
        # несовместимая архитектура бинарника. Показываем это явно.
        try:
            go_path  = self._amneziawg_go()
            awg_path = self._awg_bin()
            # amneziawg-go НЕ пробуем `--version` (см. _do_up) — только
            # сообщаем путь и существование. `awg` пробиваем полноценно.
            info["binaries"] = {
                "amneziawg_go": {
                    "path": go_path,
                    "exists": bool(go_path and os.path.isfile(go_path)),
                    "broken": False,
                    "ok": bool(go_path and os.path.isfile(go_path)),
                    "detail": "",
                },
                "awg": {"path": awg_path, **self._probe_binary(awg_path)},
            }
        except Exception as e:
            info["errors"].append("binary probe: %s" % e)

        # Конфиг (для отображения) и предварительно — что мы скармливаем
        # `awg setconf`. Это позволяет увидеть, попадает ли I1/S3/S4 в
        # реально применяемый setconf, даже если iface сейчас опущен.
        cfg_parsed = None
        try:
            cfg_wrap = self.get_config(name)
            cfg_parsed = cfg_wrap.get("parsed") or {}
            from core.awg_config import render_setconf as _render_setconf
            # Mask PrivateKey in setconf-dump — конфиг попадёт в баг-репорт
            # как есть, дёргать оттуда приватник никому не нужно.
            rendered = _render_setconf(cfg_parsed) or ""
            info["setconf_text"] = _mask_privkey(rendered)
        except Exception as e:
            info["errors"].append("render_setconf: %s" % e)

        # Last-up снапшот (если есть) — данные, снятые во время последнего
        # успешного `up`. Помогает, если пользователь после `up` теряет инет
        # и сам делает `down`, чтобы вернуть себе GUI.
        try:
            last_path = self._last_up_path(ifname)
            if os.path.isfile(last_path):
                with open(last_path, "r", encoding="utf-8") as f:
                    info["last_up"] = json.load(f)
        except Exception as e:
            info["errors"].append("last_up read: %s" % e)

        # platform info — куда мы вообще установлены
        try:
            plat = self._platform()
            info["platform"] = {
                "name":       getattr(plat, "name", ""),
                "binary_dir": getattr(plat, "binary_dir", ""),
                "config_dir": getattr(plat, "config_dir", ""),
                "run_dir":    getattr(plat, "run_dir", ""),
            }
        except Exception as e:
            info["errors"].append("platform: %s" % e)

        # Версии бинарей — критичны для AmneziaWG-v2: если демон старый
        # и не понимает I1/S3/S4, обфускация не применяется и сервер
        # дропает data-пакеты (handshake при этом проходит).
        info["binaries"] = {
            "amneziawg_go": self._amneziawg_go(),
            "awg":          self._awg_bin(),
            "awg_version":  "",
            "amneziawg_go_version": "",
        }
        rc, out, _ = _run([self._awg_bin(), "--version"], timeout=3)
        if rc == 0:
            info["binaries"]["awg_version"] = (out or "").strip()
        # amneziawg-go обычно `--version` в stderr и фолбэк через
        # подсчёт даты модификации бинаря, если флага нет.
        rc, out, err = _run([self._amneziawg_go(), "--version"], timeout=3)
        ver_out = (out or err or "").strip()
        if ver_out and "unknown" not in ver_out.lower():
            info["binaries"]["amneziawg_go_version"] = ver_out
        else:
            try:
                import os as _os, datetime as _dt
                st = _os.stat(self._amneziawg_go())
                info["binaries"]["amneziawg_go_version"] = (
                    "mtime=%s" % _dt.datetime.utcfromtimestamp(st.st_mtime)
                    .strftime("%Y-%m-%d")
                )
            except OSError:
                pass

        # Сырой текст файла-конфига с диска (с маскированным PrivateKey).
        # Часто оказывается, что на диске не то, что показано в редакторе
        # — например, после save мы пересохранили в render_conf-нормализованной
        # форме и потеряли часть полей. Видеть «что реально читается»
        # на старте `up` — критично для диагностики.
        try:
            cfg_path = self._config_path(name)
            if os.path.isfile(cfg_path):
                with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
                    info["config_file_text"] = _mask_privkey(f.read())
        except Exception as e:
            info["errors"].append("config_file_text: %s" % e)

        # Link-info интерфейса (MTU/state) — для отладки fragmented UDP.
        rc, out, _ = _run(["ip", "-d", "link", "show", "dev", ifname],
                          timeout=3)
        info["link"] = out if rc == 0 else ""
        rc, out, _ = _run(["ip", "address", "show", "dev", ifname],
                          timeout=3)
        info["addr"] = out if rc == 0 else ""

        # awg show <iface> — handshake, RX/TX, fwmark
        rc, out, err = _run([self._awg_bin(), "show", ifname], timeout=5)
        if rc == 0:
            info["awg_show"] = out
            info["active"]   = True
        else:
            info["awg_show"] = "(awg show failed) " + (err or "").strip()

        # I1: сравниваем то, что мы отправили в setconf, с тем, что
        # реально хранится в демоне (echo через `awg show`). Расхождения
        # подсказывают, где байты теряются — в нашем рендере, тулзе или
        # в демоне. Считать ОБЯЗАТЕЛЬНО после того, как `awg show` уже
        # снят (раньше — у меня тут была race и in_awg_show всегда был
        # False, даже когда демон echo'ил i1 ровно теми же байтами).
        try:
            info["i1_lengths"] = _compute_i1_lengths(
                cfg_parsed, info["awg_show"]
            )
        except Exception as e:
            info["errors"].append("i1_lengths: %s" % e)

        # структурированный статус (с уже распарсенным fwmark)
        try:
            info["interface_state"] = self.status(ifname)
        except Exception as e:
            info["errors"].append("status: %s" % e)

        # ip rule list — оба семейства
        for fam_key, fam_flag in (("v4", "-4"), ("v6", "-6")):
            rc, out, err = _run(["ip", fam_flag, "rule", "list"], timeout=5)
            info["rules"][fam_key] = out if rc == 0 else (
                "(rule list failed) " + (err or "").strip()
            )

        # таблица туннеля + main (с suppress_prefixlength 0)
        for fam_key, fam_flag in (("v4", "-4"), ("v6", "-6")):
            rc, out, _ = _run(["ip", fam_flag, "route", "show", "table",
                               str(table)], timeout=5)
            info["routes"]["table_" + fam_key] = out if rc == 0 else ""
            rc, out, _ = _run(["ip", fam_flag, "route", "show", "table",
                               "main"], timeout=5)
            info["routes"]["main_" + fam_key] = out if rc == 0 else ""

        # ip route get <peer endpoint> — самое важное для диагностики
        # петли: видно, через что РЕАЛЬНО уходит encapsulated-UDP.
        for peer in (cfg_parsed or {}).get("peers", []) or []:
            endpoint = peer.get("Endpoint", "")
            host, port = _parse_endpoint_host(endpoint)
            if not host:
                continue
            for ip in _resolve_host(host):
                fam_flag = "-6" if ":" in ip else "-4"
                rc, out, _ = _run(["ip", fam_flag, "route", "get", ip],
                                  timeout=3)
                info["endpoint_routes"].append({
                    "endpoint": endpoint,
                    "ip":       ip,
                    "family":   fam_flag,
                    "route":    out.strip() if rc == 0 else "(get failed)",
                })

        # Полный routing-state: nft/iptables/ipset/dnsmasq managed file,
        # /etc/resolv.conf. Без этого по диагностике невозможно понять,
        # почему domain/device-rules не маршрутизируют — `ip rule` и
        # `ip route` могут быть в полном порядке, а пакет всё равно не
        # уходить через AWG (например, потому что цепочка output создана
        # с неправильным типом и не триггерит реререйт после mark).
        try:
            info["routing_state"] = self._collect_routing_state()
        except Exception as e:
            info["errors"].append("routing_state: %s" % e)

        # последние записи log_buffer'а из awg-источников
        try:
            from core.log_buffer import get_log_buffer
            buf = get_log_buffer()
            entries = buf.get_filtered(search=None, n=200) or []
            keep_sources = {"awg_manager", "awg_installer", "awg_detector",
                            "warp_importer", "warp_generator", "routing"}
            info["log_tail"] = [
                e for e in entries
                if (e.get("source") if isinstance(e, dict) else None)
                   in keep_sources
            ][-80:]
        except Exception as e:
            info["errors"].append("log_buffer: %s" % e)

        return info

    # ─────────── up / down ───────────

    def up(self, name: str) -> dict:
        """Поднять интерфейс по имени конфига."""
        with self._lock:
            return self._do_up(name)

    def down(self, name: str) -> dict:
        with self._lock:
            return self._do_down(name)

    def _config_for_name(self, name: str) -> str:
        """Вернуть имя КОНФИГА для `name`.

        `name` может быть именем конфига (есть `<name>.conf` → вернём как
        есть) либо именем реального интерфейса (`opkgtun0`) — тогда найдём
        конфиг, чей интерфейс резолвится в него. Нужно watchdog'у:
        `list_interfaces()` отдаёт ИМЯ ИНТЕРФЕЙСА, а `_do_up` ждёт ИМЯ
        КОНФИГА (`<label>-<iface>.conf`); без резолва туннель опускался и
        не поднимался обратно.
        """
        if os.path.isfile(self._config_path(name)):
            return name
        for cfg in self._all_config_names():
            try:
                if self._iface_for_name(cfg) == name:
                    return cfg
            except Exception:
                continue
        return name  # не нашли — прежнее поведение

    def restart(self, name: str) -> dict:
        with self._lock:
            # Принимаем и имя конфига, и имя интерфейса (как status()).
            cfg_name = self._config_for_name(name)
            res_down = self._do_down(cfg_name)
            time.sleep(0.3)
            res_up = self._do_up(cfg_name)
            return {
                "ok":   res_up.get("ok", False),
                "down": res_down,
                "up":   res_up,
            }

    def _do_up(self, name: str) -> dict:
        if not _valid_iface_name(name):
            return {"ok": False, "message": "Недопустимое имя"}

        path = self._config_path(name)
        if not os.path.isfile(path):
            return {"ok": False, "message": "Конфиг %s не найден" % name}

        with open(path, "r") as f:
            cfg = parse_conf(f.read())
        errors = validate_cfg(cfg)
        if errors:
            return {"ok": False, "message": "Ошибки конфига: " + "; ".join(errors)}

        iface = cfg["interface"]
        ifname = name  # используем имя конфига как имя интерфейса

        if self.is_running(ifname):
            return {"ok": True, "message": "Интерфейс %s уже поднят" % ifname,
                    "already_up": True}

        # PreUp хуки
        for cmd in _as_list(iface.get("PreUp")):
            self._run_hook(cmd, ifname, "PreUp")

        # 1) запустить amneziawg-go
        bin_go = self._amneziawg_go()
        if not os.path.isfile(bin_go):
            return {"ok": False, "message":
                    "amneziawg-go не найден: %s. Установите бинарники в Setup." % bin_go}

        # Превентивно проверяем, что бинарник awg вообще исполняется. После
        # внешнего обновления awg (например через GUI роутера) бинарник
        # может оказаться под другую архитектуру — тогда `awg setconf`
        # падает с `syntax error: unexpected "("`, а demon молча не
        # поднимается. Лучше вернуть понятную ошибку, чем «ничего не
        # происходит». amneziawg-go тут НЕ пробуем `--version`: форк
        # wireguard-go может принять `--version` за имя интерфейса и
        # попытаться поднять TUN — его «битость» ловим ниже по факту запуска.
        awg_health = self._probe_binary(self._awg_bin())
        if awg_health["broken"]:
            return {"ok": False, "message":
                    "Бинарник awg не запускается (%s).%s"
                    % (awg_health["detail"] or "exec error",
                       self._binary_help_suffix())}

        rc, _out, err = _run([bin_go, ifname], timeout=15,
                             env=self._amneziawg_go_env())
        if rc != 0:
            msg = "Не удалось запустить amneziawg-go: %s" % err.strip()
            low = (err or "").lower()
            if any(m in low for m in self._BROKEN_BIN_MARKERS):
                msg += "." + self._binary_help_suffix()
            return {"ok": False, "message": msg}

        # PID amneziawg-go попробуем найти через pgrep
        pid = _pgrep_first([bin_go, ifname]) or _pgrep_first(["amneziawg-go", ifname])
        if pid:
            try:
                with open(self._pid_path(ifname), "w") as f:
                    f.write(str(pid))
            except (IOError, OSError):
                pass

        # Дать сокету подняться
        time.sleep(0.2)

        # 2) применить через `awg setconf`
        setconf_text = render_setconf(cfg)
        applied = self._apply_setconf(ifname, setconf_text)
        if not applied["ok"]:
            # откатываем
            self._cleanup_iface(ifname)
            return applied

        # 3) MTU + addresses + up
        mtu = iface.get("MTU")
        if mtu:
            _run(["ip", "link", "set", "dev", ifname, "mtu", str(mtu)])

        for addr in _as_list(iface.get("Address")):
            family = "-6" if ":" in addr else "-4"
            _run(["ip", family, "address", "add", addr, "dev", ifname])

        rc, _out, err = _run(["ip", "link", "set", "dev", ifname, "up"])
        if rc != 0:
            log.warning("ip link set up %s: %s" % (ifname, err.strip()),
                        source="awg_manager")

        # 4) маршруты из AllowedIPs (если не Table=off)
        #
        # Селективная модель zapret-gui: туннель просто *доступен* через
        # свою таблицу <table_id>. Куда направлять трафик — решают только
        # правила из «Routing» (cidr/domain/device). Main НЕ трогаем,
        # фолбэк-маршруты из AllowedIPs кладём ТОЛЬКО в нашу таблицу.
        # Без этого пользователь, который просто поднял туннель без
        # selective-правил, терял весь инет: AllowedIPs=0/0 → wg-quick-
        # схема (`ip rule not fwmark X table X` + `suppress_prefixlength
        # 0`) принудительно загоняла весь трафик в туннель, даже когда
        # пользователь ожидал, что без правил он будет идти напрямую.
        added_routes = []
        table_off = str(iface.get("Table", "")).lower() == "off"
        table_id  = self._table_id_for(ifname)

        if not table_off:
            for peer in cfg.get("peers", []):
                for ip in _as_list(peer.get("AllowedIPs")):
                    if not ip:
                        continue
                    family = "-6" if ":" in ip else "-4"
                    if ip in ("0.0.0.0/0", "::/0"):
                        rc, _o, err = _run([
                            "ip", family, "route", "add", "default",
                            "dev", ifname, "table", str(table_id),
                        ])
                        if rc == 0 or "File exists" in (err or ""):
                            added_routes.append({
                                "family": family,
                                "default": True,
                                "table": table_id,
                            })
                    else:
                        rc, _o, err = _run([
                            "ip", family, "route", "add", ip,
                            "dev", ifname, "table", str(table_id),
                        ])
                        if rc == 0 or "File exists" in (err or ""):
                            added_routes.append({
                                "family": family,
                                "cidr": ip,
                                "table": table_id,
                            })

        try:
            with open(self._routes_path(ifname), "w") as f:
                json.dump(added_routes, f)
        except (IOError, OSError):
            pass

        # PostUp
        for cmd in _as_list(iface.get("PostUp")):
            self._run_hook(cmd, ifname, "PostUp")

        # Применить routing-правила, привязанные к этому интерфейсу
        try:
            from core.routing.applier import apply_all_on_interface_up
            apply_all_on_interface_up(ifname)
        except Exception as e:
            log.warning("routing apply on up %s: %s" % (ifname, e),
                        source="awg_manager")

        # Сохраняем post-up снимок состояния для диагностики «после
        # обвала». Если у пользователя при `up` отваливается инет —
        # ему придётся самому делать down, чтобы вернуть себе GUI;
        # без снапшота к этому моменту мы теряем `awg show`, rules,
        # routes и т.п. С этим файлом — он лежит и читается из
        # diagnostics() даже когда iface уже опущен.
        try:
            self._save_last_up_snapshot(name, ifname, cfg, setconf_text)
        except Exception as e:
            log.warning("last_up snapshot не сохранён: %s" % e,
                        source="awg_manager")

        log.success("Интерфейс %s поднят" % ifname, source="awg_manager")
        return {
            "ok":      True,
            "name":    ifname,
            "message": "Интерфейс %s поднят" % ifname,
            "routes":  added_routes,
        }

    def _save_last_up_snapshot(self, cfg_name: str, ifname: str,
                                cfg: dict, setconf_text: str) -> None:
        """
        Сохранить снимок состояния интерфейса сразу после `up`,
        чтобы diagnostics() мог показать его пользователю даже после
        вынужденного down (когда инет пропал и нужно вернуть GUI).
        """
        snap = {
            "saved_at":     int(time.time()),
            "cfg_name":     cfg_name,
            "iface":        ifname,
            "table_id":     self._table_id_for(ifname),
            "setconf_text": _mask_privkey(setconf_text or ""),
            "awg_show":     "",
            "rules":  {"v4": "", "v6": ""},
            "routes": {"table_v4": "", "table_v6": "",
                       "main_v4":  "", "main_v6":  ""},
        }
        rc, out, _ = _run([self._awg_bin(), "show", ifname], timeout=5)
        snap["awg_show"] = out if rc == 0 else ""
        for fam_key, fam_flag in (("v4", "-4"), ("v6", "-6")):
            rc, out, _ = _run(["ip", fam_flag, "rule", "list"], timeout=5)
            snap["rules"][fam_key] = out if rc == 0 else ""
            rc, out, _ = _run(["ip", fam_flag, "route", "show", "table",
                               str(snap["table_id"])], timeout=5)
            snap["routes"]["table_" + fam_key] = out if rc == 0 else ""
            rc, out, _ = _run(["ip", fam_flag, "route", "show", "table",
                               "main"], timeout=5)
            snap["routes"]["main_" + fam_key] = out if rc == 0 else ""

        path = self._last_up_path(ifname)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)


    def _table_id_for(self, ifname: str) -> int:
        """Стабильный id таблицы из имени интерфейса (100..999)."""
        h = 0
        for ch in ifname:
            h = (h * 31 + ord(ch)) & 0xFFFFFFFF
        return 100 + (h % 900)

    def _collect_routing_state(self) -> dict:
        """
        Снимок состояния firewall'а / dnsmasq, относящегося к нашему
        selective-routing. Используется только для диагностики — мы тут
        ничего не меняем.

        Содержит сырые dump'ы:
          * nft awg_routing (chain types, rules, sets с содержимым)
          * iptables/ip6tables -t mangle/nat -S наших цепочек
          * ipset list awgr_* с содержимым (если ipset-бэкенд)
          * /etc/resolv.conf и /etc/systemd/resolved.conf
          * managed dnsmasq-файл и состояние демона
          * /etc/dnsmasq.conf (только наши include-строки)
        """
        out = {
            "nft_table_listing": "",
            "nft_sets":          [],
            "iptables_mangle":   "",
            "iptables_nat":      "",
            "ip6tables_mangle":  "",
            "ip6tables_nat":     "",
            "nat_postrouting_full": "",
            "filter_forward_full":  "",
            "ipset_sets":        [],
            "resolv_conf":       "",
            "resolved_conf":     "",
            "dnsmasq_status":    {},
            "dnsmasq_managed":   "",
            "dnsmasq_main":      "",
            "dnsmasq_init":      "",
            "ndm_raw":           "",
        }

        # nft awg_routing — вся таблица сразу (показывает chain types
        # и правила). Если type=filter для output — это причина почему
        # domain-routing не работает.
        rc, t, _e = _run(["nft", "list", "table", "inet", "awg_routing"],
                         timeout=5)
        if rc == 0:
            out["nft_table_listing"] = t
            # Списки наполнения: дёргаем list set отдельно, поскольку
            # nft list table даёт только описание, без элементов.
            try:
                import re as _re
                for m in _re.finditer(r"set\s+(awgr_\S+)\s*\{", t):
                    sname = m.group(1)
                    rc2, body, _e2 = _run([
                        "nft", "list", "set", "inet", "awg_routing", sname
                    ], timeout=3)
                    out["nft_sets"].append({
                        "name": sname,
                        "body": body if rc2 == 0 else "(list failed)",
                    })
            except Exception as e:
                out["nft_sets"].append({"error": str(e)})

        # iptables: только наши цепочки, чтобы вывод не разрывал диагностику
        for cmd_name, key_pref in (("iptables", ""), ("ip6tables", "ip6")):
            for table_name in ("mangle", "nat"):
                rc, dump, _e = _run([
                    cmd_name, "-t", table_name, "-S"
                ], timeout=5)
                if rc != 0:
                    continue
                # Отфильтровываем строки, упоминающие наши цепочки/наборы,
                # чтобы не тащить всю iptables-конфигурацию системы.
                wanted = []
                for line in (dump or "").splitlines():
                    if ("AWG_ROUTING" in line or
                            "awgr_" in line):
                        wanted.append(line)
                joined = "\n".join(wanted)
                key = (("ip6tables" if key_pref else "iptables")
                       + "_" + table_name)
                out[key] = joined

        # Полный POSTROUTING (nat) — чтобы видеть ПОРЯДОК наших правил
        # относительно ndm-овых SNAT/MASQUERADE. Если прыжок в
        # AWG_ROUTING_NAT стоит позже WAN-маскарада ndm, forwarded-трафик
        # уходит в туннель с WAN-src и сервер его дропает.
        rc, dump, _e = _run(["iptables", "-t", "nat", "-S", "POSTROUTING"],
                            timeout=5)
        if rc == 0:
            out["nat_postrouting_full"] = "\n".join(
                (dump or "").splitlines()[:120])

        # FORWARD (filter) — чтобы видеть, не дропает ли роутер форвард в
        # сторону AWG-интерфейса (обрезаем, чтобы не раздувать вывод).
        rc, dump, _e = _run(["iptables", "-t", "filter", "-S", "FORWARD"],
                            timeout=5)
        if rc == 0:
            lines = (dump or "").splitlines()
            out["filter_forward_full"] = "\n".join(lines[:120])
            if len(lines) > 120:
                out["filter_forward_full"] += "\n… (+%d строк)" % (len(lines) - 120)

        # Сырой вывод ndmc/ndmq — для отладки пустой колонки «Имя» в
        # списке устройств (парсер зависит от формата конкретной KeenOS).
        for cmd in (["ndmq", "-p", "show ip hotspot"],
                    ["ndmc", "-c", "show ip hotspot"]):
            rc, dump, _e = _run(cmd, timeout=5)
            if rc == 0 and (dump or "").strip():
                head = "\n".join((dump or "").splitlines()[:40])
                out["ndm_raw"] = "$ %s\n%s" % (" ".join(cmd), head)
                break

        # dnsmasq init-скрипт (на Keenetic/Entware): нашёлся ли он.
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            out["dnsmasq_init"] = DnsmasqIntegration()._find_init_script() or "(не найден)"
        except Exception as e:
            out["dnsmasq_init"] = "(error: %s)" % e

        # ipset: наполнение awgr_* (если ipset-бэкенд)
        rc, names, _e = _run(["ipset", "list", "-name"], timeout=3)
        if rc == 0:
            for name in (names or "").split():
                if not name.startswith("awgr_"):
                    continue
                rc2, body, _e2 = _run(["ipset", "list", name], timeout=3)
                out["ipset_sets"].append({
                    "name": name,
                    "body": body if rc2 == 0 else "(list failed)",
                })

        # resolv.conf + resolved.conf
        for k, p in (("resolv_conf",   "/etc/resolv.conf"),
                     ("resolved_conf", "/etc/systemd/resolved.conf")):
            try:
                if os.path.islink(p):
                    out[k] = "(symlink → %s)\n" % os.readlink(p)
                    try:
                        with open(p, "r") as f:
                            out[k] += f.read()
                    except (IOError, OSError):
                        pass
                elif os.path.isfile(p):
                    with open(p, "r") as f:
                        out[k] = f.read()
            except (IOError, OSError) as e:
                out[k] = "(read failed: %s)" % e

        # dnsmasq status + managed файл
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            dn = DnsmasqIntegration()
            out["dnsmasq_status"] = dn.status()
            mf = out["dnsmasq_status"].get("managed_file") or ""
            if mf and os.path.isfile(mf):
                try:
                    with open(mf, "r") as f:
                        out["dnsmasq_managed"] = f.read()
                except (IOError, OSError) as e:
                    out["dnsmasq_managed"] = "(read failed: %s)" % e
            main = out["dnsmasq_status"].get("main_config") or ""
            if main and os.path.isfile(main):
                try:
                    with open(main, "r") as f:
                        out["dnsmasq_main"] = f.read()
                except (IOError, OSError) as e:
                    out["dnsmasq_main"] = "(read failed: %s)" % e
        except Exception as e:
            out["dnsmasq_status"] = {"error": str(e)}

        return out

    def _apply_setconf(self, ifname: str, setconf_text: str) -> dict:
        # пишем во временный файл (awg setconf хочет путь)
        import tempfile
        with tempfile.NamedTemporaryFile(
            "w", delete=False, prefix="awg-setconf-", suffix=".conf"
        ) as tf:
            tf.write(setconf_text)
            tmp_path = tf.name
        try:
            os.chmod(tmp_path, 0o600)
            rc, _out, err = _run([self._awg_bin(), "setconf", ifname, tmp_path],
                                 timeout=15)
            if rc != 0:
                return {"ok": False, "message":
                        "awg setconf %s: %s" % (ifname, err.strip())}
            return {"ok": True}
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _do_down(self, name: str) -> dict:
        if not _valid_iface_name(name):
            return {"ok": False, "message": "Недопустимое имя"}
        # Если конфиг назван `awg0-opkgtun0`, а реальный интерфейс —
        # `opkgtun0` (поднят внешним скриптом), down должен идти по
        # реальному имени, иначе `ip link delete` ничего не найдёт.
        ifname = self._iface_for_name(name)

        # PreDown / PostDown
        path = self._config_path(name)
        cfg = None
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    cfg = parse_conf(f.read())
            except (IOError, OSError):
                cfg = None

        if cfg:
            for cmd in _as_list(cfg["interface"].get("PreDown")):
                self._run_hook(cmd, ifname, "PreDown")

        # Снять routing-правила, привязанные к этому интерфейсу
        try:
            from core.routing.applier import remove_all_on_interface_down
            remove_all_on_interface_down(ifname)
        except Exception as e:
            log.warning("routing remove on down %s: %s" % (ifname, e),
                        source="awg_manager")

        # Удалить добавленные нами маршруты/правила
        self._remove_added_routes(ifname)

        # Снять адреса/линк
        _run(["ip", "link", "set", "dev", ifname, "down"])
        rc, _o, _e = _run(["ip", "link", "delete", "dev", ifname])
        # Если интерфейса не было — это нормально

        # Убить процесс, если жив
        self._cleanup_iface(ifname)

        if cfg:
            for cmd in _as_list(cfg["interface"].get("PostDown")):
                self._run_hook(cmd, ifname, "PostDown")

        # Откатываем auto-setup dnsmasq ТОЛЬКО когда уходит последний
        # awg-интерфейс — пользователь просил, чтобы «все махинации
        # возвращались назад». Если есть ещё активные туннели,
        # systemd-resolved/dnsmasq оставляем как есть.
        try:
            if not self._wg_interfaces():
                from core.routing.dnsmasq_integration import DnsmasqIntegration
                rev = DnsmasqIntegration().revert_if_applied()
                if rev.get("ok") and not rev.get("skipped"):
                    log.info(
                        "Auto-setup dnsmasq откачен после остановки"
                        " последнего AWG-интерфейса",
                        source="awg_manager",
                    )
        except Exception as e:
            log.warning("revert_if_applied: %s" % e, source="awg_manager")

        log.info("Интерфейс %s опущен" % ifname, source="awg_manager")
        return {"ok": True, "name": ifname,
                "message": "Интерфейс %s опущен" % ifname}

    def _cleanup_iface(self, ifname: str):
        pid_path = self._pid_path(ifname)
        pid = _read_pid(pid_path)
        if pid and _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            for _ in range(10):
                if not _pid_alive(pid):
                    break
                time.sleep(0.1)
            if _pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        if os.path.exists(pid_path):
            try:
                os.remove(pid_path)
            except OSError:
                pass
        # uapi sock тоже подчистим
        sock = "/var/run/wireguard/%s.sock" % ifname
        if os.path.exists(sock):
            try:
                os.remove(sock)
            except OSError:
                pass

    def _remove_added_routes(self, ifname: str):
        """
        Teardown маршрутов, добавленных в _do_up.

        Всё что мы клали — лежит в таблице <table_id_for(ifname)>;
        просто флашим её для обеих семей. Старые записи с
        `endpoint`/`cidr` без table (от версий ≤ 0.19.14) — снимаем
        точечно для обратной совместимости со старым routes.json.
        """
        path = self._routes_path(ifname)
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                routes = json.load(f) or []
        except (IOError, OSError, ValueError):
            routes = []

        table_id = self._table_id_for(ifname)
        # Современная схема: всё в нашей таблице — флашим оба семейства
        # один раз, независимо от того, что лежит в routes.json.
        for fam in ("-4", "-6"):
            _run(["ip", fam, "route", "flush", "table", str(table_id)])

        # Старые записи из routes.json (≤ 0.19.14) могли быть в main —
        # подчищаем точечно, чтобы апгрейд с уже поднятого интерфейса
        # не оставил мусора.
        for r in routes:
            family = r.get("family", "-4")
            if r.get("default") and not r.get("table"):
                # Это было wg-quick-схема с правилами в main.
                table = self._table_id_for(ifname)
                _run(["ip", family, "rule", "del", "not", "fwmark",
                      str(table), "table", str(table)])
                _run(["ip", family, "rule", "del", "table", "main",
                      "suppress_prefixlength", "0"])
            elif r.get("cidr") and not r.get("table"):
                # cidr-маршрут лежал в main
                _run(["ip", family, "route", "del", r["cidr"], "dev", ifname])
            elif r.get("endpoint"):
                # Pinned peer endpoint в main-таблице (старая схема).
                # Если мы добавили (preexisting=False) — снимаем.
                if not r.get("preexisting"):
                    _run(["ip", family, "route", "del", r["endpoint"]])

        try:
            os.remove(path)
        except OSError:
            pass

    # ─────────── hooks ───────────

    def _run_hook(self, cmd: str, ifname: str, label: str):
        if not cmd:
            return
        # Подставляем %i как имя интерфейса (как в wg-quick)
        cmd = cmd.replace("%i", ifname)
        # Хуки исполняются через shell под root. Конфиги часто импортируются
        # из публичных подписок, где `PostUp = ...` = произвольная команда →
        # RCE. Поэтому исполнение под явным opt-in (awg.allow_hooks).
        try:
            from core.config_manager import get_config_manager
            allowed = bool(get_config_manager().get(
                "awg", "allow_hooks", default=False))
        except Exception:
            allowed = False
        if not allowed:
            log.warning(
                "[%s %s] хук пропущен (awg.allow_hooks=false): %s"
                % (label, ifname, cmd), source="awg_manager")
            return
        log.info("[%s %s] $ %s" % (label, ifname, cmd), source="awg_manager")
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=30)
            if r.returncode != 0:
                log.warning("[%s %s] rc=%d: %s" % (label, ifname,
                                                   r.returncode,
                                                   (r.stderr or "").strip()),
                            source="awg_manager")
        except (OSError, subprocess.TimeoutExpired) as e:
            log.warning("[%s %s] %s" % (label, ifname, e), source="awg_manager")


# ───────────────────────── helpers ───────────────────────────────────

def _parse_endpoint_host(endpoint: str):
    """
    `host:port` / `[ipv6]:port` → (host, port).

    Дубль `_split_endpoint` из awg_warp_in_warp, но локальный —
    чтобы избежать циклического импорта.
    """
    if not endpoint:
        return "", ""
    s = str(endpoint).strip()
    if s.startswith("["):
        rb = s.find("]")
        if rb > 0 and len(s) > rb + 1 and s[rb + 1] == ":":
            return s[1:rb], s[rb + 2:]
        return "", ""
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, port
    return s, ""


_I1_SHOW_RE = re.compile(
    r"^\s*i1:\s*(?:<b\s+)?0x([0-9a-fA-F]+)>?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def _compute_i1_lengths(cfg_parsed: dict, awg_show: str) -> dict:
    """
    Сравнить I1 на трёх уровнях:
      * config: то, что вытащил парсер из .conf
      * show:   то, что демон echo'ит назад через `awg show`
      * match:  совпадают ли байты (длины + первые 32 байта)

    Хранится в виде hex-string; «байты» считаем как len(hex)//2.
    Если демон вернул другие байты — обфускация ломается ещё до
    нашего кода до того, как пакеты пойдут.
    """
    iface_d = (cfg_parsed or {}).get("interface") or {}
    i1_cfg = (iface_d.get("I1") or "").strip()
    i1_cfg_hex = i1_cfg[2:] if i1_cfg.lower().startswith("0x") else i1_cfg
    i1_cfg_hex = i1_cfg_hex.lower()

    show_hex = ""
    m = _I1_SHOW_RE.search(awg_show or "")
    if m:
        show_hex = m.group(1).lower()

    out = {
        "config_bytes": len(i1_cfg_hex) // 2,
        "show_bytes":   len(show_hex)   // 2,
        "config_prefix": i1_cfg_hex[:64],
        "show_prefix":   show_hex[:64],
        "bytes_match":   bool(i1_cfg_hex) and i1_cfg_hex == show_hex,
        "in_awg_show":   bool(show_hex),
    }
    return out


def _mask_privkey(text: str) -> str:
    """Заменить PrivateKey-значения на «***» — в диагностическом дампе
    приватник нам не нужен и пользователь часто кидает его в баг-репорт."""
    if not text:
        return text
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith("privatekey") and "=" in s:
            key, _, _val = line.partition("=")
            lines.append("%s= ***" % key)
        else:
            lines.append(line)
    return "\n".join(lines)


def _resolve_host(host: str) -> list:
    """Резолвить host в список уникальных IP (v4+v6). IP оставляем как есть."""
    import socket as _s
    if not host:
        return []
    # Если это уже IP — отдаём без резолва
    try:
        _s.inet_pton(_s.AF_INET, host)
        return [host]
    except (OSError, ValueError):
        pass
    try:
        _s.inet_pton(_s.AF_INET6, host)
        return [host]
    except (OSError, ValueError):
        pass
    try:
        infos = _s.getaddrinfo(host, None, type=_s.SOCK_DGRAM)
    except (OSError, _s.gaierror):
        return []
    seen, out = set(), []
    for info in infos:
        ip = info[4][0]
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _as_list(v):
    if v is None or v == "":
        return []
    return v if isinstance(v, list) else [v]


def _safe_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _pgrep_first(cmd_parts: list):
    """
    Найти PID процесса по фрагменту командной строки. Возвращает первый
    подходящий.
    """
    needle = " ".join(cmd_parts).strip()
    if not needle:
        return None
    rc, out, _ = _run(["pgrep", "-f", shlex.quote(needle)])
    if rc != 0 or not out.strip():
        # fallback: ручной обход /proc
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open("/proc/%s/cmdline" % entry, "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore")
                except (IOError, OSError):
                    continue
                if needle in cmdline:
                    return int(entry)
        except OSError:
            pass
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return None


# ───────────────────────── singleton ─────────────────────────────────

_manager = None
_manager_lock = threading.Lock()


def get_awg_manager() -> AwgManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = AwgManager()
    return _manager
