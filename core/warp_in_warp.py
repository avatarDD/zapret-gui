# core/warp_in_warp.py
"""
WARP-in-WARP для MASQUE: двойной туннель через usque-keenetic.

Два варианта:
  MASQUE + MASQUE — оба туннеля через usque (TCP:443, разные IP/регионы)
  MASQUE + AWG    — внешний MASQUE, внутренний AmneziaWG

Схема:
  Клиент → inner (usque/amneziawg) → outer (usque) → интернет

Идея: внешний туннель маскирует внутренний. DPI сложнее детектить
два разных протокола подряд, чем один.
"""

import os
import signal
import subprocess
import threading
import time

from core.log_buffer import log


class WarpInWarpManager:
    """Управление WARP-in-WARP (MASQUE-based)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._outer_proc = None
        self._inner_proc = None
        self._outer_iface = ""
        self._inner_iface = ""
        self._mode = ""  # "masque_masque" | "masque_awg"

    def detect(self) -> dict:
        """Проверить доступность компонентов."""
        from core.usque_manager import get_usque_manager
        from core.opera_proxy_manager import get_opera_proxy_manager

        usque_mgr = get_usque_manager()
        usque_env = usque_mgr.detect()

        # Проверяем awg (amneziawg-go)
        awg_available = False
        for p in ["/opt/usr/sbin/amneziawg-go", "/usr/local/bin/amneziawg-go"]:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                awg_available = True
                break

        return {
            "usque_installed": usque_env.get("installed", False),
            "awg_available": awg_available,
            "arch": usque_env.get("arch", ""),
        }

    def get_status(self) -> dict:
        """Статус WARP-in-WARP."""
        outer_running = self._is_proc_running(self._outer_proc)
        inner_running = self._is_proc_running(self._inner_proc)
        return {
            "active": outer_running and inner_running,
            "mode": self._mode,
            "outer_iface": self._outer_iface if outer_running else "",
            "inner_iface": self._inner_iface if inner_running else "",
            "outer_running": outer_running,
            "inner_running": inner_running,
        }

    def start(self, mode: str = "masque_masque",
              outer_sni: str = "", inner_sni: str = "",
              outer_config: str = "", inner_config: str = "",
              awg_conf: str = "") -> dict:
        """
        Запустить WARP-in-WARP (MASQUE-based).

        Три режима (плюс AWG+AWG в awg_warp.js = 4 всего):
          masque_masque — оба туннеля через usque (TCP:443)
          masque_awg    — внешний usque, внутренний AmneziaWG
          awg_masque    — внешний AmneziaWG, внутренний usque
        """
        if self.get_status().get("active"):
            return {"ok": False, "error": "WARP-in-WARP уже запущен"}

        if mode == "masque_masque":
            return self._start_masque_masque(
                outer_sni, inner_sni, outer_config, inner_config)
        elif mode == "masque_awg":
            return self._start_masque_awg(
                outer_sni, outer_config, awg_conf)
        elif mode == "awg_masque":
            return self._start_awg_masque(
                outer_config, inner_sni, inner_config)
        else:
            return {"ok": False, "error": "Неизвестный режим: %s" % mode}

    def _start_masque_masque(self, outer_sni, inner_sni,
                              outer_config, inner_config) -> dict:
        """MASQUE + MASQUE: оба туннеля через usque."""
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        # Определяем интерфейсы
        outer_iface = "opkgtun100"
        inner_iface = "opkgtun101"

        # Запускаем внешний туннель
        if outer_config:
            result = mgr.start(outer_iface, outer_config, sni=outer_sni)
        else:
            # Генерируем конфиг если не задан
            return {"ok": False, "error": "Нужен outer usque конфиг"}

        if not result.get("ok"):
            return {"ok": False, "error": "Outer: %s" % result.get("error")}

        self._outer_proc = mgr._process
        self._outer_iface = outer_iface

        # Запускаем внутренний туннель
        if inner_config:
            result = mgr.start(inner_iface, inner_config, sni=inner_sni)
        else:
            return {"ok": False, "error": "Нужен inner usque конфиг"}

        if not result.get("ok"):
            mgr.stop(outer_iface)
            return {"ok": False, "error": "Inner: %s" % result.get("error")}

        self._inner_proc = mgr._process
        self._inner_iface = inner_iface
        self._mode = "masque_masque"

        # Настраиваем маршрутизацию: inner → outer
        self._setup_routes()

        log.info("warp-in-warp: MASQUE+MASQUE запущен (%s → %s)"
                 % (inner_iface, outer_iface), source="warp_in_warp")
        return {"ok": True, "mode": "masque_masque",
                "outer": outer_iface, "inner": inner_iface}

    def _start_masque_awg(self, outer_sni, outer_config,
                           awg_conf) -> dict:
        """MASQUE + AWG: внешний MASQUE, внутренний AmneziaWG."""
        from core.usque_manager import get_usque_manager
        from core.awg_manager import get_awg_manager

        usque_mgr = get_usque_manager()
        awg_mgr = get_awg_manager()

        outer_iface = "opkgtun100"

        # Запускаем внешний MASQUE
        if outer_config:
            result = usque_mgr.start(outer_iface, outer_config, sni=outer_sni)
        else:
            return {"ok": False, "error": "Нужен outer usque конфиг"}

        if not result.get("ok"):
            return {"ok": False, "error": "Outer MASQUE: %s" % result.get("error")}

        self._outer_proc = usque_mgr._process
        self._outer_iface = outer_iface

        # Запускаем внутренний AWG
        if awg_conf:
            # Извлекаем имя интерфейса из конфига
            iface = self._extract_awg_iface(awg_conf)
            result = awg_mgr.up(iface, awg_conf)
        else:
            usque_mgr.stop(outer_iface)
            return {"ok": False, "error": "Нужен AWG конфиг для inner"}

        if not result.get("ok"):
            usque_mgr.stop(outer_iface)
            return {"ok": False, "error": "Inner AWG: %s" % result.get("error")}

        self._inner_iface = iface
        self._mode = "masque_awg"

        self._setup_routes()

        log.info("warp-in-warp: MASQUE+AWG запущен (%s → %s)"
                 % (iface, outer_iface), source="warp_in_warp")
        return {"ok": True, "mode": "masque_awg",
                "outer": outer_iface, "inner": iface}

    def _start_awg_masque(self, awg_conf, inner_sni,
                           inner_config) -> dict:
        """AWG + MASQUE: внешний AmneziaWG, внутренний MASQUE."""
        from core.usque_manager import get_usque_manager
        from core.awg_manager import get_awg_manager

        usque_mgr = get_usque_manager()
        awg_mgr = get_awg_manager()

        inner_iface = "opkgtun101"

        # Запускаем внешний AWG
        if awg_conf:
            outer_iface = self._extract_awg_iface(awg_conf)
            result = awg_mgr.up(outer_iface, awg_conf)
        else:
            return {"ok": False, "error": "Нужен AWG конфиг для outer"}

        if not result.get("ok"):
            return {"ok": False, "error": "Outer AWG: %s" % result.get("error")}

        self._outer_iface = outer_iface

        # Запускаем внутренний MASQUE
        if inner_config:
            result = usque_mgr.start(inner_iface, inner_config, sni=inner_sni)
        else:
            awg_mgr.down(outer_iface)
            return {"ok": False, "error": "Нужен inner usque конфиг"}

        if not result.get("ok"):
            awg_mgr.down(outer_iface)
            return {"ok": False, "error": "Inner MASQUE: %s" % result.get("error")}

        self._inner_proc = usque_mgr._process
        self._inner_iface = inner_iface
        self._mode = "awg_masque"

        self._setup_routes()

        log.info("warp-in-warp: AWG+MASQUE запущен (%s → %s)"
                 % (inner_iface, outer_iface), source="warp_in_warp")
        return {"ok": True, "mode": "awg_masque",
                "outer": outer_iface, "inner": inner_iface}

    def stop(self) -> dict:
        """Остановить WARP-in-WARP."""
        # Останавливаем inner
        if self._mode in ("masque_awg",):
            try:
                from core.awg_manager import get_awg_manager
                get_awg_manager().down(self._inner_iface)
            except Exception:
                pass
        elif self._mode in ("masque_masque", "awg_masque"):
            try:
                from core.usque_manager import get_usque_manager
                get_usque_manager().stop(self._inner_iface)
            except Exception:
                pass

        # Останавливаем outer
        if self._mode in ("awg_masque",):
            try:
                from core.awg_manager import get_awg_manager
                get_awg_manager().down(self._outer_iface)
            except Exception:
                pass
        else:
            try:
                from core.usque_manager import get_usque_manager
                get_usque_manager().stop(self._outer_iface)
            except Exception:
                pass

        # Снимаем маршруты
        self._teardown_routes()

        self._outer_proc = None
        self._inner_proc = None
        self._outer_iface = ""
        self._inner_iface = ""
        self._mode = ""

        log.info("warp-in-warp: остановлен", source="warp_in_warp")
        return {"ok": True}

    def _setup_routes(self):
        """Настроить маршрутизацию и оптимизации latency."""
        try:
            # Маршруты: inner трафик идёт через outer
            subprocess.run(
                ["ip", "rule", "add", "oif", self._inner_iface,
                 "lookup", "main"],
                capture_output=True, timeout=5)

            # Применяем оптимизации через tunnel_optimizer
            from core.tunnel_optimizer import optimize_iface
            optimize_iface(self._inner_iface, "balanced")
            optimize_iface(self._outer_iface, "balanced")

            log.info("warp-in-warp: маршруты + оптимизации настроены",
                     source="warp_in_warp")
        except Exception as e:
            log.warning("warp-in-warp routes: %s" % e, source="warp_in_warp")

    def _apply_tcp_tuning(self, iface: str):
        """Оптимизировать TCP-параметры для туннельного интерфейса."""
        if not iface:
            return
        try:
            # Уменьшить буферы для снижения latency
            for param, value in [
                ("rmem_max", 131072),    # 128KB
                ("wmem_max", 131072),
                ("rmem_default", 65536),  # 64KB
                ("wmem_default", 65536),
                ("fastopen", 2),           # TCP Fast Open
            ]:
                path = "/proc/sys/net/ipv4/conf/%s/tcp_%s" % (iface, param)
                if os.path.isfile(path):
                    try:
                        with open(path, "w") as f:
                            f.write(str(value))
                    except Exception:
                        pass
        except Exception:
            pass

    def _teardown_routes(self):
        """Снять маршруты."""
        try:
            subprocess.run(
                ["ip", "rule", "del", "oif", self._inner_iface,
                 "lookup", "main"],
                capture_output=True, timeout=5)
        except Exception:
            pass

    def _extract_awg_iface(self, conf_path: str) -> str:
        """Извлечь имя интерфейса из .conf файла."""
        try:
            with open(conf_path) as f:
                for line in f:
                    if line.strip().startswith("Address"):
                        # Обычно первый интерфейс = awg0
                        return "awg0"
        except Exception:
            pass
        return "awg0"

    def _is_proc_running(self, proc) -> bool:
        if proc is None:
            return False
        try:
            return proc.poll() is None
        except Exception:
            return False


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_warp_in_warp_manager() -> WarpInWarpManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = WarpInWarpManager()
    return _instance
