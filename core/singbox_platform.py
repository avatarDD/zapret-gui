# core/singbox_platform.py
"""
Платформенная абстракция для sing-box.

Аналог `core/awg_platform.py`, но с другими дефолтами путей.
Поскольку sing-box и AWG живут в Entware-окружении и потребляют
TUN одинаково, основная часть кода переиспользует тот же
PlatformKind enum + helper'ы.
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


# ───────────────────────── Base ──────────────────────────────────────

class SingboxPlatform:
    """
    Платформенный профиль sing-box: где жить, какой init, какой
    firewall-движок.
    """

    name = "unknown"
    kind = PlatformKind.UNKNOWN

    # Пути
    binary_dir = "/usr/local/bin"
    config_dir = "/etc/sing-box"           # JSON-конфиги
    run_dir    = "/var/run/sing-box"
    log_dir    = "/var/log"

    # init.d
    init_dir      = "/etc/init.d"
    init_name     = "sing-box-gui"
    init_priority = "S52"   # после AWG (S51), чтобы туннели AWG
                            # успели подняться до маршрутизации
                            # sing-box-outbound через них.

    def binary_path(self):
        return os.path.join(self.binary_dir, "sing-box")

    def config_path(self, name: str):
        return os.path.join(self.config_dir, f"{name}.json")

    def pid_path(self, name: str):
        return os.path.join(self.run_dir, f"singbox-{name}.pid")

    def log_path(self, name: str):
        return os.path.join(self.log_dir, f"singbox-{name}.log")

    def init_script_path(self):
        return os.path.join(self.init_dir,
                            f"{self.init_priority}{self.init_name}")

    def tun_available(self) -> bool:
        return os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")

    def supports_iptables_marks(self) -> bool:
        return _cmd_ok(["iptables", "-t", "mangle", "-L", "-n"])

    def supports_nftables(self) -> bool:
        return _cmd_ok(["nft", "list", "tables"])

    def get_firewall_backend(self) -> str:
        if self.supports_nftables():
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


# ───────────────────────── Keenetic ──────────────────────────────────

class KeeneticSingbox(SingboxPlatform):
    name = "keenetic"
    kind = PlatformKind.KEENETIC

    binary_dir = "/opt/usr/sbin"
    config_dir = "/opt/etc/sing-box"
    run_dir    = "/opt/var/run/sing-box"
    log_dir    = "/opt/var/log"
    init_dir   = "/opt/etc/init.d"
    init_name  = "sing-box-gui"
    init_priority = "S52"


# ───────────────────────── OpenWrt ───────────────────────────────────

class OpenWrtSingbox(SingboxPlatform):
    name = "openwrt"
    kind = PlatformKind.OPENWRT

    binary_dir = "/usr/sbin"
    config_dir = "/etc/sing-box"
    run_dir    = "/var/run/sing-box"
    log_dir    = "/var/log"
    init_dir   = "/etc/init.d"
    init_name  = "sing-box-gui"
    init_priority = ""   # procd init: без S<N>-префикса

    def init_script_path(self):
        return os.path.join(self.init_dir, self.init_name)


# ───────────────────────── Generic Linux ─────────────────────────────

class GenericLinuxSingbox(SingboxPlatform):
    name = "linux"
    kind = PlatformKind.LINUX

    binary_dir = "/usr/local/bin"
    config_dir = "/etc/sing-box"
    run_dir    = "/var/run/sing-box"
    log_dir    = "/var/log"
    init_dir   = "/etc/systemd/system"
    init_name  = "sing-box-gui"
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


# ───────────────────────── factory ───────────────────────────────────

def detect_singbox_platform() -> SingboxPlatform:
    """
    Определить платформу для sing-box, опираясь на тот же детектор,
    что используется для AWG (чтобы случай «Keenetic с Entware»
    распознавался идентично).
    """
    try:
        from core.awg_detector import get_awg_detector
        awg_platform = get_awg_detector().detect_platform()
    except Exception:
        return GenericLinuxSingbox()

    if is_keenetic(awg_platform):
        return KeeneticSingbox()
    if is_openwrt(awg_platform):
        return OpenWrtSingbox()
    if is_linux_generic(awg_platform):
        return GenericLinuxSingbox()
    return GenericLinuxSingbox()
