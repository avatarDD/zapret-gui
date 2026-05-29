# core/mihomo_platform.py
"""
Платформенная абстракция для mihomo (Clash.Meta).

Прямой аналог `core/singbox_platform.py`: те же три платформы
(Keenetic/Entware, OpenWrt, generic Linux), тот же детектор окружения
(AWG), но другие дефолты путей и имя бинаря.

mihomo — это форк Clash, движок-альтернатива sing-box (как в XKeen,
где можно быстро переключаться Xray ↔ Mihomo). Конфиг — YAML
(clash-формат), который мы уже умеем парсить (core/clash_yaml.py).
"""

import os
import subprocess

from core.awg_platform import (
    PlatformKind,
    is_keenetic, is_openwrt, is_linux_generic,
)


def _cmd_ok(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


# Кандидаты имён бинаря mihomo (исторически clash.meta / clash).
BINARY_NAMES = ("mihomo", "clash.meta", "clash-meta", "clash")


class MihomoPlatform:
    """Платформенный профиль mihomo: где жить, какой init."""

    name = "unknown"
    kind = PlatformKind.UNKNOWN

    binary_dir = "/usr/local/bin"
    config_dir = "/etc/mihomo"          # YAML-конфиги + workdir (geo-базы)
    run_dir    = "/var/run/mihomo"
    log_dir    = "/var/log"

    init_dir      = "/etc/init.d"
    init_name     = "mihomo-gui"
    init_priority = "S53"   # после sing-box (S52)

    def binary_path(self):
        return os.path.join(self.binary_dir, "mihomo")

    def config_path(self, name: str):
        return os.path.join(self.config_dir, f"{name}.yaml")

    def pid_path(self, name: str):
        return os.path.join(self.run_dir, f"mihomo-{name}.pid")

    def log_path(self, name: str):
        return os.path.join(self.log_dir, f"mihomo-{name}.log")

    def init_script_path(self):
        return os.path.join(self.init_dir,
                            f"{self.init_priority}{self.init_name}")

    def tun_available(self) -> bool:
        return os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")

    def get_firewall_backend(self) -> str:
        if _cmd_ok(["nft", "list", "tables"]):
            return "nftables"
        if _cmd_ok(["iptables", "-L", "-n"]):
            return "iptables"
        return "none"

    def install_init_script(self, content: str):
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

    def as_dict(self) -> dict:
        return {
            "name":             self.name,
            "kind":             self.kind.value if isinstance(
                self.kind, PlatformKind) else str(self.kind),
            "binary_dir":       self.binary_dir,
            "config_dir":       self.config_dir,
            "run_dir":          self.run_dir,
            "init_dir":         self.init_dir,
            "init_name":        self.init_name,
            "init_priority":    self.init_priority,
            "tun_available":    self.tun_available(),
            "firewall_backend": self.get_firewall_backend(),
        }


class KeeneticMihomo(MihomoPlatform):
    name = "keenetic"
    kind = PlatformKind.KEENETIC

    binary_dir = "/opt/usr/sbin"
    config_dir = "/opt/etc/mihomo"
    run_dir    = "/opt/var/run/mihomo"
    log_dir    = "/opt/var/log"
    init_dir   = "/opt/etc/init.d"
    init_name  = "mihomo-gui"
    init_priority = "S53"


class OpenWrtMihomo(MihomoPlatform):
    name = "openwrt"
    kind = PlatformKind.OPENWRT

    binary_dir = "/usr/sbin"
    config_dir = "/etc/mihomo"
    run_dir    = "/var/run/mihomo"
    log_dir    = "/var/log"
    init_dir   = "/etc/init.d"
    init_name  = "mihomo-gui"
    init_priority = ""

    def init_script_path(self):
        return os.path.join(self.init_dir, self.init_name)


class GenericLinuxMihomo(MihomoPlatform):
    name = "linux"
    kind = PlatformKind.LINUX

    binary_dir = "/usr/local/bin"
    config_dir = "/etc/mihomo"
    run_dir    = "/var/run/mihomo"
    log_dir    = "/var/log"
    init_dir   = "/etc/systemd/system"
    init_name  = "mihomo-gui"
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


def detect_mihomo_platform() -> MihomoPlatform:
    """Определить платформу для mihomo (тот же детектор, что у AWG)."""
    try:
        from core.awg_detector import get_awg_detector
        awg_platform = get_awg_detector().detect_platform()
    except Exception:
        return GenericLinuxMihomo()

    if is_keenetic(awg_platform):
        return KeeneticMihomo()
    if is_openwrt(awg_platform):
        return OpenWrtMihomo()
    if is_linux_generic(awg_platform):
        return GenericLinuxMihomo()
    return GenericLinuxMihomo()
