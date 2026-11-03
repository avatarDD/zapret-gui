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


# `mihomo -v` на слабом роутере: бинарник ~30 МБ читается с USB-флешки,
# и первый (холодный) запуск Go-программы занимает секунды. Прежних 3 с не
# хватало — версия на странице «Обновления» оставалась пустой, хотя mihomo
# стоял и работал (Keenetic, ноябрь 2026). У sing-box бинарник меньше,
# и он в 3 с укладывался.
VERSION_PROBE_TIMEOUT = 15


def _cmd_out(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


def parse_version(out: str) -> str:
    """Версия из вывода `mihomo -v`.

    'Mihomo Meta v1.19.15 linux mipsle with go1.25.1 …' → '1.19.15';
    'Mihomo Meta alpha-a1b2c3d linux …' → 'alpha-a1b2c3d'. Раньше брался
    первый попавшийся x.y.z, и у alpha-сборки им оказывалась версия Go.
    """
    out = (out or "").strip()
    if not out:
        return ""
    m = re.search(r"(?:mihomo|clash)(?:\s+meta)?\s+v?(\d+\.\d+\.\d+\S*)",
                  out, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"(?:mihomo|clash)(?:\s+meta)?\s+(alpha\S*|beta\S*)",
                  out, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"v?(\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return out.splitlines()[0].strip()


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
            return {"installed": False, "path": "", "version": "",
                    "has_gvisor": False}
        version = self._probe_version(path)
        return {"installed": True, "path": path, "version": version,
                # has_gvisor: gvisor-стек нужен для надёжного доменного роутинга
                # (system без auto-route не ловит TCP). `mihomo -v` печатает
                # строку «Use tags: with_gvisor …» — её и парсим (см.
                # _detect_gvisor). Официальные сборки MetaCubeX/mihomo-linux-*
                # идут с with_gvisor; реальная страховка от кастомной сборки без
                # него — фолбэк стека через `mihomo -t` в core/mihomo_routing.
                "has_gvisor": self._detect_gvisor(path)}

    def _detect_gvisor(self, binary: str) -> bool:
        """
        `mihomo -v` печатает build-теги строкой «Use tags: with_gvisor …»
        (проверено на v1.19.x). Ищем gvisor в выводе → True. Если строка тегов
        есть, но gvisor в ней нет (кастомная сборка) → False; если тегов вовсе
        не видно (нестандартный вывод) — считаем, что есть (официальная сборка).
        Точную проверку (приём `stack: gvisor`) делает оркестратор маршрутизации
        через `mihomo -t` (фолбэк на system), так что ложный True не опасен.
        """
        out = self._version_output(binary).lower()
        if "gvisor" in out:
            return True
        # Строка тегов есть, но gvisor в ней нет — кастомная сборка без gvisor.
        if "tags:" in out or "features:" in out:
            return False
        return True

    def _version_output(self, binary: str) -> str:
        """Вывод `mihomo -v` — один запуск на файл.

        Его читают и версия, и проверка gvisor; раньше это были два
        запуска подряд, каждый со своим таймаутом. Кеш привязан к
        (путь, mtime, размер): после замены бинарника вывод берётся заново.
        Пустой вывод не кешируется — следующая проверка попробует снова.
        """
        try:
            st = os.stat(binary)
            key = (binary, int(st.st_mtime), st.st_size)
        except OSError:
            key = None
        cache = getattr(self, "_v_out_cache", None)
        if key is not None and cache and cache[0] == key:
            return cache[1]
        out = _cmd_out([binary, "-v"], timeout=VERSION_PROBE_TIMEOUT)
        if not out:
            log.warning("mihomo_detector: `%s -v` не ответил за %d с или"
                        " завершился с ошибкой — версия неизвестна"
                        % (binary, VERSION_PROBE_TIMEOUT),
                        source="mihomo_detector")
        elif key is not None:
            self._v_out_cache = (key, out)
        return out

    def _probe_version(self, binary: str) -> str:
        """`mihomo -v` → 'Mihomo Meta vX.Y.Z ...'."""
        return parse_version(self._version_output(binary))

    def detect_tun(self) -> dict:
        # Вместе с инструкцией «как включить» под эту платформу.
        from core.awg_platform import tun_status
        return tun_status()

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
