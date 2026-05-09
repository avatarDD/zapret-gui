# core/awg_platform.py
"""
Абстракция платформы для интеграции amneziawg-go.

Каждая реализация знает:
  - где хранятся бинарники и конфиги
  - как называются init-скрипты и где они лежат
  - какой firewall-бэкенд доступен
  - специфику запуска AWG на данной платформе
"""

import os
import subprocess


def _cmd_ok(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _cmd_out(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


# ───────────────────────── Base ──────────────────────────────────────

class AwgPlatform:
    name = "unknown"

    # Пути
    binary_dir = "/usr/local/bin"
    config_dir = "/etc/amneziawg"
    run_dir    = "/var/run/awg"
    log_dir    = "/var/log"

    # init.d
    init_dir      = "/etc/init.d"
    init_name     = "awg-gui"
    init_priority = "S51"          # Entware-style: S<prio><name>

    def binary_path(self, name="amneziawg-go"):
        return os.path.join(self.binary_dir, name)

    def awg_path(self):
        """Путь к awg (wg-clone с поддержкой AmneziaWG параметров)."""
        return self.binary_path("awg")

    def config_path(self, name):
        return os.path.join(self.config_dir, f"{name}.conf")

    def pid_path(self, iface):
        return os.path.join(self.run_dir, f"awg-{iface}.pid")

    def uapi_path(self, iface):
        """UAPI-сокет, создаваемый amneziawg-go в userspace-режиме."""
        return f"/var/run/wireguard/{iface}.sock"

    def init_script_path(self):
        return os.path.join(self.init_dir, f"{self.init_priority}{self.init_name}")

    # ── возможности платформы ──

    def has_opkg_tun(self):
        """OpkgTun — отдельный TUN-модуль для Entware на Keenetic KeenOS 5.x."""
        return False

    def supports_iptables_marks(self):
        """Доступны ли iptables MARK + ip rule fwmark для per-device routing."""
        return _cmd_ok(["iptables", "-t", "mangle", "-L", "-n"])

    def supports_nftables(self):
        return _cmd_ok(["nft", "list", "tables"])

    def get_firewall_backend(self):
        """Предпочитаемый firewall-бэкенд: 'nftables' | 'iptables' | 'none'."""
        if self.supports_nftables():
            return "nftables"
        if _cmd_ok(["iptables", "-L", "-n"]):
            return "iptables"
        return "none"

    def install_init_script(self, content: str):
        """Записать init-скрипт и сделать исполняемым."""
        path = self.init_script_path()
        os.makedirs(self.init_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)
        return path

    def remove_init_script(self):
        path = self.init_script_path()
        if os.path.exists(path):
            os.remove(path)

    def tun_available(self):
        return os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")

    def as_dict(self):
        return {
            "name":                   self.name,
            "binary_dir":             self.binary_dir,
            "config_dir":             self.config_dir,
            "run_dir":                self.run_dir,
            "init_dir":               self.init_dir,
            "init_name":              self.init_name,
            "init_priority":          self.init_priority,
            "has_opkg_tun":           self.has_opkg_tun(),
            "supports_iptables_marks": self.supports_iptables_marks(),
            "firewall_backend":       self.get_firewall_backend(),
            "tun_available":          self.tun_available(),
        }


# ───────────────────────── Keenetic / Entware ────────────────────────

class KeeneticPlatform(AwgPlatform):
    name = "keenetic"

    binary_dir = "/opt/usr/sbin"
    config_dir = "/opt/etc/amneziawg"
    run_dir    = "/opt/var/run/awg"
    log_dir    = "/opt/var/log"
    init_dir   = "/opt/etc/init.d"
    init_name  = "amneziawg-gui"
    init_priority = "S51"

    def __init__(self, keenos_version: str = ""):
        self._keenos_version = keenos_version

    def _version_major(self):
        try:
            return int(self._keenos_version.split(".")[0])
        except (ValueError, IndexError):
            return 0

    def has_opkg_tun(self):
        """OpkgTun нужен начиная с KeenOS 5.0."""
        if self._version_major() >= 5:
            return _cmd_ok(["opkg", "status", "opkg-tun"])
        # На KeenOS < 5 TUN обычно доступен иначе
        return self.tun_available()

    def supports_iptables_marks(self):
        # На Keenetic с OpkgTun iptables работает в Entware-цепочках
        if not self.has_opkg_tun() and self._version_major() >= 5:
            return False
        return super().supports_iptables_marks()

    def opkg_tun_instructions(self):
        """Пошаговая инструкция по установке OpkgTun."""
        return (
            "Для работы AmneziaWG на KeenOS 5.x необходим компонент OpkgTun:\n"
            "1. Откройте веб-интерфейс Keenetic (http://192.168.1.1)\n"
            "2. Перейдите в Управление → Компоненты\n"
            "3. В разделе OPKG найдите 'Поддержка TUN/TAP' (opkg-tun)\n"
            "4. Установите компонент и перезагрузите роутер\n"
            "5. После перезагрузки вернитесь сюда и повторите установку"
        )

    def as_dict(self):
        d = super().as_dict()
        d["keenos_version"] = self._keenos_version
        d["opkg_tun_installed"] = self.has_opkg_tun()
        if self._version_major() >= 5 and not self.has_opkg_tun():
            d["opkg_tun_instructions"] = self.opkg_tun_instructions()
        return d


# ───────────────────────── OpenWrt ───────────────────────────────────

class OpenWrtPlatform(AwgPlatform):
    name = "openwrt"

    binary_dir = "/usr/sbin"
    config_dir = "/etc/amneziawg"
    run_dir    = "/var/run/awg"
    log_dir    = "/var/log"
    init_dir   = "/etc/init.d"
    init_name  = "awg-gui"
    init_priority = ""   # procd init: нет S<N>-префикса

    def init_script_path(self):
        return os.path.join(self.init_dir, self.init_name)

    def supports_nftables(self):
        # OpenWrt 22.03+ использует nftables по умолчанию
        return _cmd_ok(["nft", "list", "tables"])


# ───────────────────────── Generic Linux ─────────────────────────────

class GenericLinuxPlatform(AwgPlatform):
    name = "linux"

    binary_dir = "/usr/local/bin"
    config_dir = "/etc/amneziawg"
    run_dir    = "/var/run/awg"
    log_dir    = "/var/log"
    init_dir   = "/etc/systemd/system"
    init_name  = "awg-gui"
    init_priority = ""

    def init_script_path(self):
        return os.path.join(self.init_dir, f"{self.init_name}.service")

    def install_init_script(self, content: str):
        path = super().install_init_script(content)
        _cmd_ok(["systemctl", "daemon-reload"])
        return path

    def remove_init_script(self):
        _cmd_ok(["systemctl", "disable", self.init_name])
        super().remove_init_script()
        _cmd_ok(["systemctl", "daemon-reload"])
