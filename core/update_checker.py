# core/update_checker.py
"""
Unified Update Checker: проверка обновлений ВСЕХ бинарников за один запрос.

Проверяет:
  - zapret2 (nfqws2)
  - sing-box
  - mihomo
  - AmneziaWG
  - GUI (zapret-gui)
  - usque (WARP/MASQUE)
  - teleproxy (Telegram, ARM64)
  - tg-mtproxy-client (Telegram, MIPS)
  - opera-proxy

Фоновый процесс проверяет по расписанию (default 24h).
Последние результаты кешируются в RAM.
"""

import threading
import time

from core.log_buffer import log


# Интервал проверки по умолчанию (часы)
DEFAULT_CHECK_INTERVAL_HOURS = 24

# Кешированные результаты
_results = {}
_results_lock = threading.Lock()
_last_check = 0


def check_all() -> dict:
    """
    Проверить обновления для всех бинарников.
    Возвращает {ok, results: [{name, installed, current, latest, has_update, ...}], ...}
    """
    global _results, _last_check

    results = []

    # zapret2
    results.append(_check_zapret())

    # sing-box
    results.append(_check_singbox())

    # mihomo
    results.append(_check_mihomo())

    # AmneziaWG
    results.append(_check_awg())

    # GUI
    results.append(_check_gui())

    # usque (WARP)
    results.append(_check_usque())

    # teleproxy
    results.append(_check_teleproxy())

    # tg-mtproxy-client
    results.append(_check_tgproto())

    # opera-proxy
    results.append(_check_opera())

    updates_count = sum(1 for r in results if r.get("has_update"))

    with _results_lock:
        _results = {
            "ok": True,
            "results": results,
            "updates_count": updates_count,
            "checked_at": int(time.time()),
        }
        _last_check = time.time()

    return _results


def get_cached_results() -> dict:
    """Получить кешированные результаты последней проверки."""
    with _results_lock:
        if _results:
            return _results
    return {"ok": True, "results": [], "updates_count": 0, "checked_at": 0}


def _check_zapret() -> dict:
    """Проверить zapret2."""
    try:
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        installed = inst.get_installed_version()
        latest = inst.get_latest_version()
        return {
            "name": "zapret2",
            "display_name": "zapret2 (nfqws2)",
            "installed": installed.get("installed", False),
            "current": installed.get("version", ""),
            "latest": latest.get("version", ""),
            "has_update": bool(latest.get("version") and
                               installed.get("version") and
                               latest["version"] != installed["version"]),
        }
    except Exception as e:
        return {"name": "zapret2", "display_name": "zapret2",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_singbox() -> dict:
    """Проверить sing-box."""
    try:
        from core.singbox_installer import get_singbox_installer
        inst = get_singbox_installer()
        result = inst.check_for_updates()
        return {
            "name": "singbox",
            "display_name": "sing-box",
            "installed": result.get("installed", {}).get("installed", False),
            "current": result.get("installed", {}).get("version", ""),
            "latest": result.get("latest", {}).get("version", ""),
            "has_update": result.get("has_update", False),
        }
    except Exception as e:
        return {"name": "singbox", "display_name": "sing-box",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_mihomo() -> dict:
    """Проверить mihomo."""
    try:
        from core.mihomo_installer import get_mihomo_installer
        inst = get_mihomo_installer()
        result = inst.check_for_updates()
        return {
            "name": "mihomo",
            "display_name": "mihomo",
            "installed": result.get("installed", {}).get("installed", False),
            "current": result.get("installed", {}).get("version", ""),
            "latest": result.get("latest", {}).get("version", ""),
            "has_update": result.get("has_update", False),
        }
    except Exception as e:
        return {"name": "mihomo", "display_name": "mihomo",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_awg() -> dict:
    """Проверить AmneziaWG."""
    try:
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        result = inst.check_for_updates()
        return {
            "name": "awg",
            "display_name": "AmneziaWG",
            "installed": result.get("installed", {}).get("installed", False),
            "current": result.get("installed", {}).get("version", ""),
            "latest": result.get("latest", {}).get("version", ""),
            "has_update": result.get("has_update", False),
        }
    except Exception as e:
        return {"name": "awg", "display_name": "AmneziaWG",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_gui() -> dict:
    """Проверить GUI (zapret-gui)."""
    try:
        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()
        installed = updater.get_installed_version()
        latest = updater.get_latest_version()
        return {
            "name": "gui",
            "display_name": "Zapret Web-GUI",
            "installed": True,
            "current": installed.get("version", ""),
            "latest": latest.get("version", ""),
            "has_update": bool(latest.get("version") and
                               installed.get("version") and
                               latest["version"] != installed["version"]),
        }
    except Exception as e:
        return {"name": "gui", "display_name": "Zapret Web-GUI",
                "installed": True, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_usque() -> dict:
    """Проверить usque (WARP/MASQUE)."""
    try:
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        env = mgr.detect()
        # Проверяем GitHub releases
        latest = _github_latest("side-effect-tm/usque-keenetic")
        return {
            "name": "usque",
            "display_name": "usque (WARP/MASQUE)",
            "installed": env.get("installed", False),
            "current": env.get("version", ""),
            "latest": latest,
            "has_update": bool(latest and env.get("version") and
                               latest != env["version"]),
        }
    except Exception as e:
        return {"name": "usque", "display_name": "usque (WARP/MASQUE)",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_teleproxy() -> dict:
    """Проверить teleproxy."""
    try:
        import os
        binary = ""
        for p in ["/opt/usr/bin/teleproxy", "/opt/bin/teleproxy",
                  "/usr/local/bin/teleproxy"]:
            if os.path.isfile(p):
                binary = p
                break
        current = ""
        if binary:
            import subprocess
            r = subprocess.run([binary, "--version"],
                               capture_output=True, text=True, timeout=5)
            out = (r.stdout or r.stderr or "").strip()
            current = out[:30] if out else ""

        latest = _github_latest("teleproxy/teleproxy")
        return {
            "name": "teleproxy",
            "display_name": "teleproxy (Telegram, ARM64)",
            "installed": bool(binary),
            "current": current,
            "latest": latest,
            "has_update": bool(latest and current and latest != current),
        }
    except Exception as e:
        return {"name": "teleproxy", "display_name": "teleproxy",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_tgproto() -> dict:
    """Проверить tg-mtproxy-client."""
    try:
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()
        detect = mgr._detect_mtproto()
        latest = _github_latest("necronicle/z2k")
        return {
            "name": "tgproto",
            "display_name": "tg-mtproxy-client",
            "installed": detect.get("installed", False),
            "current": detect.get("version", ""),
            "latest": latest,
            "has_update": False,  # z2k не имеет семантических версий
        }
    except Exception as e:
        return {"name": "tgproto", "display_name": "tg-mtproxy-client",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_opera() -> dict:
    """Проверить opera-proxy."""
    try:
        from core.opera_proxy_manager import get_opera_proxy_manager
        mgr = get_opera_proxy_manager()
        env = mgr.detect()
        latest = _github_latest("Alexey71/opera-proxy")
        return {
            "name": "opera",
            "display_name": "opera-proxy",
            "installed": env.get("installed", False),
            "current": env.get("version", ""),
            "latest": latest,
            "has_update": bool(latest and env.get("version") and
                               latest != env["version"]),
        }
    except Exception as e:
        return {"name": "opera", "display_name": "opera-proxy",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _github_latest(repo: str) -> str:
    """Получить/latest tag из GitHub releases."""
    try:
        import subprocess
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "https://api.github.com/repos/%s/releases/latest" % repo],
            capture_output=True, text=True, timeout=15)
        import json
        data = json.loads(r.stdout or "{}")
        tag = data.get("tag_name", "")
        return tag.lstrip("v") if tag else ""
    except Exception:
        return ""


# ─────── background checker ───────

class UpdateCheckerDaemon:
    """Фоновый процесс: проверяет обновления по расписанию."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()

    def reconfigure(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if cfg.get("update_checker", "enabled", default=False):
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="update-checker", daemon=True)
            t.start()
            self._thread = t
            log.info("update-checker: запущен", source="update_checker")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("update-checker: остановлен", source="update_checker")

    def _run_loop(self):
        while not self._stop_evt.is_set():
            try:
                from core.config_manager import get_config_manager
                cfg = get_config_manager()
                interval_h = cfg.get("update_checker", "interval_hours",
                                     default=DEFAULT_CHECK_INTERVAL_HOURS)
                result = check_all()
                updates = result.get("updates_count", 0)
                if updates:
                    log.info("update-checker: найдено %d обновлений" % updates,
                             source="update_checker")
            except Exception as e:
                log.warning("update-checker: %s" % e, source="update_checker")
            self._stop_evt.wait(interval_h * 3600)

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {"running": running}


_checker = None
_checker_lock = threading.Lock()


def get_update_checker() -> UpdateCheckerDaemon:
    global _checker
    if _checker is None:
        with _checker_lock:
            if _checker is None:
                _checker = UpdateCheckerDaemon()
    return _checker
