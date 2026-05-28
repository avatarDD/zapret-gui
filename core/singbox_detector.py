# core/singbox_detector.py
"""
Детект окружения для sing-box.

По аналогии с `core/awg_detector.py`, но проще: sing-box запускается
одним бинарём, без отдельных tools-зависимостей.
"""

import os
import re
import subprocess
import threading

from core.log_buffer import log
from core.singbox_platform import (
    SingboxPlatform, detect_singbox_platform,
)


def _cmd_out(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


def _find_binary(names, extra_dirs=()):
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


# ───────────────────────── detector ──────────────────────────────────

class SingboxDetector:

    def __init__(self):
        self._lock  = threading.Lock()
        self._cache = None

    def get_environment_report(self, force: bool = False) -> dict:
        with self._lock:
            if self._cache is not None and not force:
                return self._cache
            try:
                self._cache = self._build_report()
            except Exception as e:
                log.error("singbox_detector: %s" % e,
                          source="singbox_detector")
                self._cache = {"ok": False, "error": str(e)}
            return self._cache

    def detect_platform(self) -> SingboxPlatform:
        return detect_singbox_platform()

    def detect_binary(self) -> dict:
        platform = self.detect_platform()
        # Сначала ищем в platform.binary_dir, потом по PATH-аналогу.
        path = ""
        candidate = platform.binary_path()
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            path = candidate
        if not path:
            path = _find_binary(["sing-box"])
        if not path:
            return {"installed": False, "path": "", "version": ""}
        version = self._probe_version(path)
        return {"installed": True, "path": path, "version": version}

    def _probe_version(self, binary: str) -> str:
        """`sing-box version` отдаёт многострочный вывод; нас интересует
        первая строка с номером."""
        out = _cmd_out([binary, "version"], timeout=3)
        if not out:
            return ""
        # sing-box version 1.x.y -- ... либо первая строка содержит
        # «sing-box version 1.x.y»
        m = re.search(r"sing-box\s+(?:version\s+)?(\S+)", out, re.IGNORECASE)
        if m:
            return m.group(1)
        # Fallback — взять первый токен
        first = out.splitlines()[0].strip()
        return first

    def detect_tun(self) -> dict:
        dev_tun = os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")
        return {"device": dev_tun, "available": dev_tun}

    def _build_report(self) -> dict:
        platform = self.detect_platform()
        bin_info = self.detect_binary()
        tun      = self.detect_tun()

        prerequisites = self._check_prerequisites(platform, tun)
        return {
            "ok":            True,
            "platform":      platform.as_dict(),
            "binary":        bin_info,
            "tun":           tun,
            "prerequisites": prerequisites,
            "ready":         prerequisites["all_met"] and bin_info["installed"],
        }

    def _check_prerequisites(self, platform, tun) -> dict:
        items = []
        items.append({
            "id":      "tun",
            "label":   "TUN-интерфейс (/dev/net/tun)",
            "met":     tun["available"],
            "blocker": not tun["available"],
            "hint":    "" if tun["available"] else (
                "TUN недоступен. На Keenetic 5.x нужен компонент "
                "OpkgTun (см. AWG-инструкции — тот же компонент)."),
        })
        items.append({
            "id":    "config_dir",
            "label": "Каталог конфигов (%s)" % platform.config_dir,
            "met":   os.path.isdir(platform.config_dir),
            "blocker": False,   # будет создан при первом сохранении
            "hint":   "",
        })
        blockers = [i for i in items if i["blocker"] and not i["met"]]
        return {
            "items":    items,
            "all_met":  len(blockers) == 0,
            "blockers": [i["id"] for i in blockers],
        }


# ───────────────────────── Singleton ─────────────────────────────────

_detector = None
_detector_lock = threading.Lock()


def get_singbox_detector() -> SingboxDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = SingboxDetector()
    return _detector
