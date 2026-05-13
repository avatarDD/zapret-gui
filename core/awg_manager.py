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

def _run(args, timeout=15, input_text=None):
    """Запустить команду, вернуть (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            input=input_text,
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

    def _awg_bin(self):
        info = get_awg_installer().get_installed_version()
        if info.get("awg") and os.path.isfile(info["awg"]):
            return info["awg"]
        # Может звать `awg` через PATH, если в installed_dir не нашли
        return os.path.join(self._binary_dir(), "awg")

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

    # ─────────── CRUD ───────────

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
                iface = self._resolve_iface_name(name, path, active_ifaces)
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
                            active_ifaces: list) -> str:
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

        if peer_keys:
            for iface in active:
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
            return self._resolve_iface_name(name, path, active)
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
        """Все активные AWG/WG интерфейсы со статусом."""
        seen = set()
        result = []
        for name in self._wg_interfaces():
            if name in seen:
                continue
            seen.add(name)
            result.append(self.status(name))
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

    # ─────────── up / down ───────────

    def up(self, name: str) -> dict:
        """Поднять интерфейс по имени конфига."""
        with self._lock:
            return self._do_up(name)

    def down(self, name: str) -> dict:
        with self._lock:
            return self._do_down(name)

    def restart(self, name: str) -> dict:
        with self._lock:
            res_down = self._do_down(name)
            time.sleep(0.3)
            res_up = self._do_up(name)
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

        rc, _out, err = _run([bin_go, ifname], timeout=15)
        if rc != 0:
            return {"ok": False, "message":
                    "Не удалось запустить amneziawg-go: %s" % err.strip()}

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
        added_routes = []
        table_off = str(iface.get("Table", "")).lower() == "off"
        if not table_off:
            for peer in cfg.get("peers", []):
                for ip in _as_list(peer.get("AllowedIPs")):
                    if not ip:
                        continue
                    family = "-6" if ":" in ip else "-4"
                    if ip in ("0.0.0.0/0", "::/0"):
                        # default route — wg-quick делает через fwmark+rule;
                        # упростим: пишем в main + suppress_prefixlength.
                        if self._add_default_via(ifname, family):
                            added_routes.append({"family": family, "default": True})
                    else:
                        rc, _o, _e = _run(["ip", family, "route", "add", ip,
                                           "dev", ifname])
                        if rc == 0:
                            added_routes.append({"family": family, "cidr": ip})

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

        log.success("Интерфейс %s поднят" % ifname, source="awg_manager")
        return {
            "ok":      True,
            "name":    ifname,
            "message": "Интерфейс %s поднят" % ifname,
            "routes":  added_routes,
        }

    def _add_default_via(self, ifname: str, family: str) -> bool:
        """
        Простая реализация default route через интерфейс. Используем
        отдельную таблицу <table_id> + ip rule, чтобы не ломать main.
        """
        table = self._table_id_for(ifname)
        rc, _o, _e = _run(["ip", family, "route", "add", "default",
                           "dev", ifname, "table", str(table)])
        if rc != 0:
            return False
        _run(["ip", family, "rule", "add", "not", "fwmark",
              str(table), "table", str(table)])
        return True

    def _table_id_for(self, ifname: str) -> int:
        """Стабильный id таблицы из имени интерфейса (100..999)."""
        h = 0
        for ch in ifname:
            h = (h * 31 + ord(ch)) & 0xFFFFFFFF
        return 100 + (h % 900)

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
        path = self._routes_path(ifname)
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                routes = json.load(f) or []
        except (IOError, OSError, ValueError):
            routes = []

        for r in routes:
            family = r.get("family", "-4")
            if r.get("default"):
                table = self._table_id_for(ifname)
                _run(["ip", family, "rule", "del", "not", "fwmark",
                      str(table), "table", str(table)])
                _run(["ip", family, "route", "flush", "table", str(table)])
            elif r.get("cidr"):
                _run(["ip", family, "route", "del", r["cidr"], "dev", ifname])

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
