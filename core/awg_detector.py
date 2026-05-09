# core/awg_detector.py
"""
Детект окружения для интеграции amneziawg-go.

Определяет: платформу, архитектуру, наличие TUN, существующие
установки AWG (бинарники, конфиги, активные интерфейсы).

Использование:
    from core.awg_detector import get_awg_detector
    det = get_awg_detector()
    report = det.get_environment_report()
"""

import os
import re
import subprocess
import threading

from core.awg_platform import (
    AwgPlatform,
    KeeneticPlatform,
    OpenWrtPlatform,
    GenericLinuxPlatform,
)
from core.log_buffer import log

# ─────────────────────── helpers ─────────────────────────────────────

def _cmd_out(args, timeout=5):
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


def _cmd_ok(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except (IOError, OSError):
        return ""


def _find_binary(names, extra_dirs=()):
    """Поиск бинарника по именам в стандартных PATH + extra_dirs."""
    dirs = list(extra_dirs) + [
        "/opt/usr/sbin", "/opt/usr/bin", "/opt/bin", "/opt/sbin",
        "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
        "/sbin", "/bin",
    ]
    for d in dirs:
        for name in names:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return ""


# ─────────────────────── AwgDetector ─────────────────────────────────

class AwgDetector:

    def __init__(self):
        self._lock = threading.Lock()
        self._cache = None

    # ── публичный API ─────────────────────────────────────────────

    def get_environment_report(self, force=False):
        """
        Возвращает полный dict-отчёт об окружении.
        Кэшируется до следующего вызова с force=True или перезапуска.
        """
        with self._lock:
            if self._cache is not None and not force:
                return self._cache
            try:
                self._cache = self._build_report()
            except Exception as e:
                log.error(f"Ошибка при сборе отчёта: {e}", source="awg_detector")
                self._cache = {"ok": False, "error": str(e)}
            return self._cache

    def detect_platform(self) -> AwgPlatform:
        """Вернуть экземпляр AwgPlatform для текущей системы."""
        if self._is_keenetic():
            ver = self.detect_keenos_version()
            return KeeneticPlatform(keenos_version=ver)
        if self._is_openwrt():
            return OpenWrtPlatform()
        return GenericLinuxPlatform()

    def detect_keenos_version(self):
        """
        Пытается определить версию KeenOS.
        Возвращает строку вида '5.4.1' или '' если не Keenetic.
        """
        # Ndm-команда (доступна на новых прошивках)
        ndm = _cmd_out(["ndmq", "-p", "show version"], timeout=3)
        if ndm:
            m = re.search(r'"version"\s*:\s*"([\d.]+)"', ndm)
            if m:
                return m.group(1)

        # /proc/version — содержит строку вида "Keenetic X.Y.Z"
        proc_ver = _read_file("/proc/version")
        m = re.search(r"Keenetic[^\d]*([\d]+\.[\d]+\.[\d]+)", proc_ver, re.I)
        if m:
            return m.group(1)

        # /etc/openwrt_release на Keenetic с OpenWrt основой
        rel = _read_file("/etc/openwrt_release")
        m = re.search(r'DISTRIB_DESCRIPTION="[^"]*Keenetic[^"]*?([\d]+\.[\d]+\.[\d]+)', rel, re.I)
        if m:
            return m.group(1)

        return ""

    def detect_architecture(self):
        """
        Возвращает dict с архитектурными данными, совместимыми
        с именами артефактов нашего workflow.
        """
        uname_m = _cmd_out(["uname", "-m"]) or _read_file("/proc/sys/kernel/arch").strip()

        # Опkg print-architecture — более точно на Entware
        opkg_arch = ""
        opkg_out = _cmd_out(["opkg", "print-architecture"])
        if opkg_out:
            # Первая непустая строка вида "arch mipsel-3.4 10"
            for line in opkg_out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "arch":
                    opkg_arch = parts[1]
                    break

        artifact_arch = self._map_to_artifact_arch(uname_m, opkg_arch)
        return {
            "uname_m":       uname_m,
            "opkg_arch":     opkg_arch,
            "artifact_arch": artifact_arch,   # mipsel-softfloat | aarch64 | ...
        }

    def detect_tun(self):
        """Наличие TUN, загруженность модуля."""
        dev_tun = os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")
        lsmod   = _cmd_out(["lsmod"])
        tun_mod = "tun" in lsmod.lower() if lsmod else False
        return {"device": dev_tun, "kernel_module": tun_mod, "available": dev_tun}

    def detect_existing_awg(self):
        """
        Ищет уже установленный amneziawg-go: бинарники, конфиги,
        запущенные интерфейсы. Ничего не трогает.
        """
        bin_awg_go  = _find_binary(["amneziawg-go"])
        bin_awg     = _find_binary(["awg", "wg"])
        config_dirs = self._find_config_dirs()
        interfaces  = self._find_awg_interfaces()

        return {
            "binary_awg_go":    bin_awg_go,
            "binary_awg":       bin_awg,
            "config_dirs":      config_dirs,
            "configs":          self._find_configs(config_dirs),
            "active_interfaces": interfaces,
            "has_existing":     bool(bin_awg_go or interfaces or any(d["configs"] for d in config_dirs)),
        }

    # ── внутренние методы ─────────────────────────────────────────

    def _build_report(self):
        platform = self.detect_platform()
        arch     = self.detect_architecture()
        tun      = self.detect_tun()
        existing = self.detect_existing_awg()

        # Проверяем что нужно для работы AWG на данной платформе
        prerequisites = self._check_prerequisites(platform, tun)

        return {
            "ok":            True,
            "platform":      platform.as_dict(),
            "architecture":  arch,
            "tun":           tun,
            "existing":      existing,
            "prerequisites": prerequisites,
            "ready":         prerequisites["all_met"],
        }

    def _check_prerequisites(self, platform: AwgPlatform, tun: dict):
        items = []

        # TUN
        items.append({
            "id":      "tun",
            "label":   "TUN-интерфейс (/dev/net/tun)",
            "met":     tun["available"],
            "blocker": not tun["available"],
            "hint":    platform.opkg_tun_instructions()
                       if isinstance(platform, KeeneticPlatform)
                          and not tun["available"]
                       else "",
        })

        # OpkgTun на Keenetic 5.x
        if isinstance(platform, KeeneticPlatform):
            keenos_maj = 0
            try:
                keenos_maj = int(platform._keenos_version.split(".")[0])
            except (ValueError, IndexError):
                pass
            if keenos_maj >= 5:
                opkg_tun = platform.has_opkg_tun()
                items.append({
                    "id":      "opkg_tun",
                    "label":   "Компонент OpkgTun",
                    "met":     opkg_tun,
                    "blocker": not opkg_tun,
                    "hint":    platform.opkg_tun_instructions() if not opkg_tun else "",
                })

        # ip-утилита из iproute2
        has_ip = bool(_cmd_out(["ip", "link"]))
        items.append({
            "id":      "iproute2",
            "label":   "ip (iproute2)",
            "met":     has_ip,
            "blocker": not has_ip,
            "hint":    "Установите пакет iproute2 или ip" if not has_ip else "",
        })

        blockers = [i for i in items if i["blocker"] and not i["met"]]
        return {
            "items":    items,
            "all_met":  len(blockers) == 0,
            "blockers": [i["id"] for i in blockers],
        }

    def _is_keenetic(self):
        pv = _read_file("/proc/version").lower()
        if "keenetic" in pv:
            return True
        if os.path.exists("/opt/etc/init.d") and _cmd_ok(["ndmq", "--help"]):
            return True
        rel = _read_file("/etc/openwrt_release").lower()
        return "keenetic" in rel

    def _is_openwrt(self):
        return os.path.exists("/etc/openwrt_release") or \
               os.path.exists("/etc/openwrt_version")

    def _map_to_artifact_arch(self, uname_m: str, opkg_arch: str) -> str:
        """
        Маппинг в имена артефактов из нашего workflow:
        mipsel-softfloat | mips-softfloat | aarch64 | armv7 | x86_64
        """
        ua = uname_m.lower()
        oa = opkg_arch.lower()

        if "mips" in ua or "mips" in oa:
            # softfloat → почти все Entware-роутеры
            if "el" in ua or "mips32el" in oa or "mipsel" in oa:
                return "mipsel-softfloat"
            return "mips-softfloat"

        if ua in ("aarch64", "arm64") or "aarch64" in oa:
            return "aarch64"

        if ua.startswith("armv7") or "armv7" in oa:
            return "armv7"

        if ua in ("x86_64", "amd64"):
            return "x86_64"

        # Неизвестная арх — возвращаем uname как есть
        return uname_m

    def _find_config_dirs(self):
        candidates = [
            "/opt/etc/amneziawg",
            "/opt/etc/amnezia/awg",
            "/opt/etc/wireguard",
            "/etc/amneziawg",
            "/etc/amnezia/awg",
            "/etc/wireguard",
        ]
        found = []
        for d in candidates:
            if os.path.isdir(d):
                confs = [
                    f for f in os.listdir(d)
                    if f.endswith(".conf") and os.path.isfile(os.path.join(d, f))
                ]
                found.append({"path": d, "configs": confs})
        return found

    def _find_configs(self, config_dirs):
        result = []
        for entry in config_dirs:
            for name in entry["configs"]:
                result.append({
                    "name": name[:-5],   # без .conf
                    "path": os.path.join(entry["path"], name),
                })
        return result

    def _find_awg_interfaces(self):
        """
        Активные AWG/WireGuard интерфейсы: через wg show и ip link.
        """
        interfaces = []
        seen = set()

        # Способ 1: wg show (или awg show)
        for binary in ("awg", "wg"):
            out = _cmd_out([binary, "show", "interfaces"])
            if out:
                for iface in out.split():
                    if iface and iface not in seen:
                        seen.add(iface)
                        interfaces.append({"name": iface, "source": "wg_show"})
                break

        # Способ 2: ip link show type wireguard
        out = _cmd_out(["ip", "link", "show", "type", "wireguard"])
        if out:
            for line in out.splitlines():
                m = re.match(r"\d+:\s+(\S+?)[@:]", line)
                if m:
                    iface = m.group(1)
                    if iface not in seen:
                        seen.add(iface)
                        interfaces.append({"name": iface, "source": "ip_link"})

        # Способ 3: поиск UAPI-сокетов amneziawg-go в userspace-режиме
        uapi_dir = "/var/run/wireguard"
        if os.path.isdir(uapi_dir):
            for entry in os.listdir(uapi_dir):
                if entry.endswith(".sock"):
                    iface = entry[:-5]
                    if iface not in seen:
                        seen.add(iface)
                        interfaces.append({"name": iface, "source": "uapi_sock"})

        return interfaces


# ─────────────────────── Singleton ───────────────────────────────────

_detector = None
_detector_lock = threading.Lock()


def get_awg_detector() -> AwgDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = AwgDetector()
    return _detector
