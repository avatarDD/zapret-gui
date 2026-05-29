# core/mihomo_detector.py
"""
Детект окружения для mihomo (Clash.Meta). Аналог singbox_detector.

Ищет бинарь mihomo (или исторические clash.meta / clash) и определяет
версию через `mihomo -v`.
"""

import os
import re
import subprocess
import threading

from core.log_buffer import log
from core.mihomo_platform import (
    MihomoPlatform, detect_mihomo_platform, BINARY_NAMES,
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


class MihomoDetector:

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
                log.error("mihomo_detector: %s" % e,
                          source="mihomo_detector")
                self._cache = {"ok": False, "error": str(e)}
            return self._cache

    def detect_platform(self) -> MihomoPlatform:
        return detect_mihomo_platform()

    def detect_binary(self) -> dict:
        platform = self.detect_platform()
        path = ""
        candidate = platform.binary_path()
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            path = candidate
        if not path:
            path = _find_binary(list(BINARY_NAMES))
        if not path:
            return {"installed": False, "path": "", "version": ""}
        version = self._probe_version(path)
        return {"installed": True, "path": path, "version": version}

    def _probe_version(self, binary: str) -> str:
        """`mihomo -v` → 'Mihomo Meta vX.Y.Z ...'."""
        out = _cmd_out([binary, "-v"], timeout=3)
        if not out:
            return ""
        m = re.search(r"v?(\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
        return out.splitlines()[0].strip()

    def detect_tun(self) -> dict:
        dev_tun = os.path.exists("/dev/net/tun") or os.path.exists("/dev/tun")
        return {"device": dev_tun, "available": dev_tun}

    def _build_report(self) -> dict:
        platform = self.detect_platform()
        bin_info = self.detect_binary()
        tun      = self.detect_tun()
        return {
            "ok":       True,
            "platform": platform.as_dict(),
            "binary":   bin_info,
            "tun":      tun,
            "ready":    bin_info["installed"],
        }


_detector = None
_detector_lock = threading.Lock()


def get_mihomo_detector() -> MihomoDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = MihomoDetector()
    return _detector
