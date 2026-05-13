# core/awg_autostart_manager.py
"""
Менеджер автозапуска AmneziaWG-интерфейсов и привязанных routing-правил.

Что обеспечивает:
  * per-config флаг autostart хранится в settings.json
      config["awg"]["autostart"]["interfaces"][<name>] = bool
  * глобальная установка init-скрипта (Entware / OpenWrt procd / systemd)
    через AwgPlatform.install_init_script(). Скрипт вызывает CLI-режим
    app.py — `python3 app.py --apply-awg-autostart` (и --stop-awg-autostart).
  * сам CLI-режим: поднимает enabled-интерфейсы, применяет routing-правила
    (apply_all_for_iface вызывается AwgManager._do_up автоматически),
    восстанавливает WARP-in-WARP, если был активен.

Порядок при старте системы:
    1. init-скрипт стартует после сети
    2. → python3 app.py --apply-awg-autostart
    3. → для каждого enabled-конфига AwgManager.up(name)
       (внутри up: routing.apply_all_for_iface — это и есть «сначала intf,
       потом routing»)
    4. → если был активен WARP-in-WARP — wiw.setup(outer, inner)
"""

import os
import sys
import threading

from core.log_buffer import log


APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(APP_DIR, "app.py")


# ───────────────────────── singleton ─────────────────────────────────

_instance = None
_instance_lock = threading.Lock()


def get_awg_autostart_manager():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AwgAutostartManager()
    return _instance


# ───────────────────────── manager ───────────────────────────────────

class AwgAutostartManager:

    def __init__(self):
        self._lock = threading.Lock()

    # ─────────── settings.json helpers ───────────

    def _section(self) -> dict:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        sec = cm.get("awg", "autostart") or {}
        if not isinstance(sec, dict):
            sec = {}
        sec.setdefault("interfaces", {})
        sec.setdefault("enabled", False)
        return sec

    def _save_section(self, sec: dict):
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("awg", "autostart", sec)
        cm.save()

    # ─────────── per-config flag ───────────

    def is_enabled(self, name: str) -> bool:
        return bool(self._section().get("interfaces", {}).get(name))

    def set_enabled(self, name: str, value: bool) -> dict:
        with self._lock:
            sec = self._section()
            ifaces = dict(sec.get("interfaces", {}))
            if value:
                ifaces[name] = True
            else:
                ifaces.pop(name, None)
            sec["interfaces"] = ifaces
            self._save_section(sec)

            # Если включили хоть один интерфейс — и глобальный init.d
            # ещё не установлен — пробуем поставить.
            if value and not self._is_script_installed():
                try:
                    self._install_script_locked()
                except Exception as e:
                    log.warning("Не удалось установить awg autostart-скрипт: %s"
                                % e, source="awg_autostart")

            # Если выключили все — снимаем init.d (опционально).
            if not value and not any(ifaces.values()):
                if self._is_script_installed():
                    try:
                        self._remove_script_locked()
                    except Exception as e:
                        log.warning("Не удалось снять awg autostart-скрипт: %s"
                                    % e, source="awg_autostart")

        log.info("AWG autostart для %s → %s" % (name, "ON" if value else "OFF"),
                 source="awg_autostart")
        return {"ok": True, "name": name, "enabled": bool(value)}

    def get_enabled_interfaces(self) -> list:
        ifaces = self._section().get("interfaces", {})
        return sorted([n for n, v in ifaces.items() if v])

    # ─────────── init-script ───────────

    def _platform(self):
        from core.awg_detector import get_awg_detector
        return get_awg_detector().detect_platform()

    def _is_script_installed(self) -> bool:
        try:
            p = self._platform().init_script_path()
            return os.path.isfile(p)
        except Exception:
            return False

    def install_script(self) -> dict:
        with self._lock:
            try:
                path = self._install_script_locked()
                return {"ok": True, "path": path,
                        "message": "Скрипт автозапуска установлен"}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def remove_script(self) -> dict:
        with self._lock:
            try:
                self._remove_script_locked()
                return {"ok": True, "message": "Скрипт автозапуска удалён"}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def _install_script_locked(self) -> str:
        from core.awg_init_script import install_init_script
        platform = self._platform()
        path = install_init_script(platform, python_bin=_python_bin(),
                                   app_py=APP_PY)
        log.info("AWG autostart-скрипт записан: %s" % path,
                 source="awg_autostart")
        return path

    def _remove_script_locked(self):
        platform = self._platform()
        platform.remove_init_script()
        log.info("AWG autostart-скрипт удалён", source="awg_autostart")

    def regenerate(self) -> dict:
        """Пересоздать скрипт (если установлен)."""
        with self._lock:
            if not self._is_script_installed():
                return {"ok": True, "message": "Скрипт не установлен — пропуск"}
            try:
                path = self._install_script_locked()
                return {"ok": True, "path": path,
                        "message": "Скрипт автозапуска пересоздан"}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    # ─────────── status ───────────

    def get_status(self) -> dict:
        sec = self._section()
        platform = self._platform()
        try:
            script_path = platform.init_script_path()
        except Exception:
            script_path = ""
        return {
            "platform":         platform.name,
            "script_path":      script_path,
            "script_installed": self._is_script_installed(),
            "interfaces":       sec.get("interfaces", {}),
            "enabled_count":    sum(1 for v in sec.get("interfaces", {}).values() if v),
        }

    # ─────────── CLI: apply / stop ───────────

    def apply_autostart(self) -> dict:
        """
        Поднять все enabled-интерфейсы и восстановить WARP-in-WARP.
        Вызывается init-скриптом (через `app.py --apply-awg-autostart`)
        и при старте GUI (см. _apply_awg_autostart_on_boot в app.py).

        Routing-правила применяются автоматически внутри AwgManager.up()
        через apply_all_for_iface — это гарантирует, что сначала интерфейс
        поднимается, и только потом к нему привязываются правила.
        """
        from core.awg_manager import get_awg_manager
        mgr = get_awg_manager()

        results = []
        enabled = self.get_enabled_interfaces()

        # Существующие конфиги — некоторые могли быть удалены
        existing = {c["name"] for c in mgr.list_configs()}

        for name in enabled:
            if name not in existing:
                log.warning("AWG autostart: конфиг %s отсутствует, пропуск" % name,
                            source="awg_autostart")
                results.append({"name": name, "ok": False,
                                "message": "Конфиг не найден"})
                continue
            if mgr.is_running(name):
                results.append({"name": name, "ok": True,
                                "message": "Уже поднят", "already_up": True})
                continue
            log.info("AWG autostart: поднимаем %s" % name,
                     source="awg_autostart")
            r = mgr.up(name)
            results.append({"name": name, **r})

        # WARP-in-WARP — восстанавливаем, если был активен
        wiw_result = self._restore_warp_in_warp()
        if wiw_result is not None:
            results.append({"warp_in_warp": wiw_result})

        ok = all(r.get("ok", True) for r in results) if results else True
        log.success("AWG autostart применён (%d интерфейсов)" % len(enabled),
                    source="awg_autostart")
        return {"ok": ok, "results": results, "applied": enabled}

    def stop_autostart(self) -> dict:
        """Опустить все enabled-интерфейсы (используется init-скриптом stop)."""
        from core.awg_manager import get_awg_manager
        mgr = get_awg_manager()

        results = []
        # Снимаем WARP-in-WARP в первую очередь
        try:
            from core.awg_warp_in_warp import status as wiw_status, teardown as wiw_teardown
            st = wiw_status()
            if st.get("active"):
                results.append({"warp_in_warp": wiw_teardown()})
        except Exception as e:
            log.warning("teardown WiW: %s" % e, source="awg_autostart")

        # Опускаем enabled-интерфейсы (или все поднятые — для надёжности)
        targets = set(self.get_enabled_interfaces())
        for i in mgr.list_interfaces():
            targets.add(i["name"])

        for name in sorted(targets):
            try:
                r = mgr.down(name)
                results.append({"name": name, **r})
            except Exception as e:
                results.append({"name": name, "ok": False, "error": str(e)})

        return {"ok": True, "results": results}

    def _restore_warp_in_warp(self):
        """Если в settings есть активная пара WiW — восстановить связку."""
        try:
            from core.awg_warp_in_warp import status as wiw_status, setup as wiw_setup
            st = wiw_status()
            if not st.get("active"):
                return None
            outer = st.get("outer") or ""
            inner = st.get("inner") or ""
            if not (outer and inner):
                return None
            log.info("AWG autostart: восстанавливаем WARP-in-WARP (%s → %s)"
                     % (outer, inner), source="awg_autostart")
            return wiw_setup(outer, inner)
        except Exception as e:
            log.warning("WiW restore: %s" % e, source="awg_autostart")
            return {"ok": False, "error": str(e)}


# ───────────────────────── module helpers ────────────────────────────

def _python_bin() -> str:
    """Возвращает путь к интерпретатору, под которым запущен GUI."""
    return sys.executable or "/usr/bin/python3"
