# core/awg_platform.py
"""
Абстракция платформы для интеграции amneziawg-go.

Каждая реализация знает:
  - где хранятся бинарники и конфиги
  - как называются init-скрипты и где они лежат
  - какой firewall-бэкенд доступен
  - специфику запуска AWG на данной платформе

Платформа возвращает `kind: PlatformKind` — единый enum, по которому
можно ветвить логику без `isinstance`-цепочек по всему коду.
Helper-функции `is_keenetic()`, `is_openwrt()` инкапсулируют
проверки и принимают как `AwgPlatform`, так и `PlatformKind`.
"""

import enum
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


# ───────────────────────── Platform kind enum ───────────────────────

class PlatformKind(enum.Enum):
    """
    Единый перечень целевых платформ.

    Используется вместо isinstance-проверок:

        if platform.kind is PlatformKind.KEENETIC:
            ...

    или через helper:

        from core.awg_platform import is_keenetic
        if is_keenetic(platform):
            ...

    Добавление новой платформы (например, ASUS Merlin) — это
    одна новая запись здесь + один subclass `AwgPlatform`.
    """
    KEENETIC = "keenetic"
    OPENWRT  = "openwrt"
    LINUX    = "linux"
    UNKNOWN  = "unknown"


def is_keenetic(p) -> bool:
    """True, если платформа — Keenetic (по kind или isinstance)."""
    return _kind_of(p) is PlatformKind.KEENETIC


def is_openwrt(p) -> bool:
    return _kind_of(p) is PlatformKind.OPENWRT


def is_linux_generic(p) -> bool:
    return _kind_of(p) is PlatformKind.LINUX


def _kind_of(p):
    """Достать PlatformKind из AwgPlatform / PlatformKind / строки."""
    if isinstance(p, PlatformKind):
        return p
    kind = getattr(p, "kind", None)
    if isinstance(kind, PlatformKind):
        return kind
    name = getattr(p, "name", None) or (p if isinstance(p, str) else "")
    try:
        return PlatformKind(str(name).lower())
    except ValueError:
        return PlatformKind.UNKNOWN


# ───────────────────────── Base ──────────────────────────────────────

class AwgPlatform:
    name = "unknown"
    kind = PlatformKind.UNKNOWN

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
            "kind":                   self.kind.value if isinstance(
                self.kind, PlatformKind) else str(self.kind),
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
    kind = PlatformKind.KEENETIC

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
        """
        OpkgTun-компонент нужен только на KeenOS 5.x.

        OpkgTun — это СИСТЕМНЫЙ компонент Keenetic (включается в
        веб-админке: «Управление → Компоненты → Поддержка TUN/TAP
        для OPKG»). Реальный индикатор того, что он включён, —
        появление `/dev/net/tun`.

        На KeenOS 4.x этот компонент отсутствует: там TUN обычно
        приходит через opkg-пакет `kmod-tun` либо через
        системный компонент с другим именем («VPN-сервер»).
        Мы тоже смотрим на /dev/net/tun — это универсальный
        индикатор, не зависящий от способа подъёма.

        На неизвестной (нулевой) версии — тоже смотрим на /dev/net/tun.
        """
        return self.tun_available()

    def supports_iptables_marks(self):
        """
        iptables-MARK через mangle на разных KeenOS-поколениях:

        - KeenOS 5.x БЕЗ OpkgTun: пользовательские mangle-цепочки
          вообще не работают (нет user-space netfilter).
        - KeenOS 5.x С OpkgTun: работает через Entware-цепочки.
        - KeenOS 4.x: iptables работает, но есть нюанс — основной
          firewall Keenetic'а может перетирать пользовательские
          цепочки при reload-running-config. Для надёжной работы
          лучше использовать NDMS-backend (ip policy).
        """
        major = self._version_major()
        if major >= 5 and not self.has_opkg_tun():
            return False
        # На 4.x и 5.x-with-OpkgTun возвращаем результат стандартной
        # проверки iptables -t mangle (можно поднять пакет).
        return super().supports_iptables_marks()

    def tun_instructions(self) -> str:
        """
        Пошаговая инструкция по подъёму TUN — зависит от поколения
        KeenOS.

        KeenOS 5.x → системный компонент «Поддержка TUN/TAP для OPKG».
        KeenOS 4.x → opkg-пакет `kmod-tun` (или системный компонент
                     «Прокси-сервер OpenVPN», который тянет TUN).
        Неизвестная (старый Keenetic, который не отвечает на ndmc) —
        выводим обе.
        """
        major = self._version_major()
        if major >= 5:
            return (
                "KeenOS 5.x: для работы AmneziaWG нужен системный\n"
                "компонент OpkgTun:\n"
                "  1. Откройте веб-интерфейс Keenetic (http://192.168.1.1)\n"
                "  2. Управление → Общие настройки → Изменить набор компонентов\n"
                "  3. Включите фильтр «opkg», найдите «Поддержка TUN/TAP для OPKG»\n"
                "  4. Установите и перезагрузите роутер\n"
                "  5. После перезагрузки вернитесь и повторите установку"
            )
        if major == 4:
            return (
                "KeenOS 4.x: для работы AmneziaWG нужен TUN-модуль.\n"
                "  Способ 1 (рекомендуется): opkg install kmod-tun\n"
                "  Способ 2: установите системный компонент «Прокси-сервер\n"
                "    OpenVPN» через веб-интерфейс — он автоматически\n"
                "    подтянет TUN.\n"
                "  После — перезагрузите роутер и повторите установку.\n"
                "  ВНИМАНИЕ: на KeenOS 4.x пользовательские iptables-цепочки\n"
                "  могут перетираться при reload-running-config — если\n"
                "  включён RCI (NDMS), рекомендуется использовать\n"
                "  NDMS-backend для selective routing."
            )
        # Неизвестная или unparsable версия — даём подсказку без
        # привязки к поколению.
        return (
            "Не удалось определить версию KeenOS.\n"
            "Для TUN попробуйте одно из:\n"
            "  - opkg install kmod-tun (старые прошивки 4.x)\n"
            "  - системный компонент «Поддержка TUN/TAP для OPKG» (5.x)\n"
            "  - системный компонент «Прокси-сервер OpenVPN» (тянет TUN)\n"
            "После — перезагрузите роутер."
        )

    # Алиас сохранён для обратной совместимости с местами, где
    # «opkg_tun_instructions» используется напрямую (api/awg.py UI).
    def opkg_tun_instructions(self) -> str:
        return self.tun_instructions()

    def as_dict(self):
        d = super().as_dict()
        d["keenos_version"]   = self._keenos_version
        d["keenos_major"]     = self._version_major()
        d["opkg_tun_installed"] = self.has_opkg_tun()
        # Инструкции отдаём всегда, если TUN не виден — UI сам решит,
        # показывать или нет. В as_dict нет смысла фильтровать по
        # версии — keenos_major уже доступен, фронт сам разветвится.
        if not self.tun_available():
            d["tun_instructions"] = self.tun_instructions()
            # Старое поле, оставляем для совместимости с фронтом.
            d["opkg_tun_instructions"] = d["tun_instructions"]
        return d


# ───────────────────────── OpenWrt ───────────────────────────────────

class OpenWrtPlatform(AwgPlatform):
    name = "openwrt"
    kind = PlatformKind.OPENWRT

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
    kind = PlatformKind.LINUX

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
