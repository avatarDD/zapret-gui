# core/autostart_manager.py
"""
Менеджер автозапуска.

Поддерживает две модели автозапуска:

  1) Entware: генерирует отдельный init.d/S99zapret, который запускает
     nfqws2 независимо от GUI. Это исторический путь.

  2) systemd (Ubuntu, Debian и пр.): отдельный init для nfqws2 не
     создаётся. Автозапуск реализован тем, что systemd автоматически
     стартует zapret-gui.service, а GUI при старте применяет
     сохранённую стратегию (см. app._apply_saved_strategy_on_boot).
     В этом случае enable/disable только обновляют флаг в конфиге.

Использование:
    from core.autostart_manager import get_autostart_manager

    am = get_autostart_manager()
    am.enable()       # Генерирует и устанавливает скрипт
    am.disable()      # Удаляет скрипт
    am.regenerate()   # Пересоздаёт скрипт с текущими настройками
    am.get_status()   # Текущее состояние
"""

import os
import re
import stat
import shutil
import subprocess
import threading

from core.log_buffer import log


# Пути
INIT_DIR = "/opt/etc/init.d"
SCRIPT_NAME = "S99zapret"
SCRIPT_PATH = os.path.join(INIT_DIR, SCRIPT_NAME)

# systemd unit-файл GUI-сервиса (создаётся install.sh)
SYSTEMD_UNIT_PATH = "/etc/systemd/system/zapret-gui.service"

# Путь к локальной копии скрипта (в директории проекта)
LOCAL_INIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "init.d")
LOCAL_SCRIPT_PATH = os.path.join(LOCAL_INIT_DIR, SCRIPT_NAME)


# Шаблон init-скрипта S99zapret. Плейсхолдеры вида @NAME@ подставляются в
# _generate_script(). Firewall-логика портирована из nfqws2-keenetic
# (etc/init.d/common): отдельные цепочки nfqws_post/nfqws_pre/nfqws_nat,
# метки MARK_PROCESSED/MARK_EXCLUDE, правила на оба направления, NAT
# MASQUERADE для UDP, обработка TCP-флагов и тюнинг conntrack через sysctl.
#
# Подкоманды firewall_iptables/firewall_ip6tables/firewall_stop позволяют
# ndm-хуку (Keenetic) и hotplug-хуку (OpenWrt) переустанавливать правила
# после flush'а системного firewall — без этого правила слетают и nfqws2
# работает «вхолостую».
_S99ZAPRET_TEMPLATE = r"""#!/bin/sh
#
# Zapret Web-GUI — автозапуск nfqws2
# Сгенерировано автоматически. Не редактируйте вручную — изменения затрутся
# при следующей генерации из GUI.
#
# Стратегия: @STRATEGY_NAME@ (@STRATEGY_ID@)
#

SCRIPT_NAME="S99zapret"
NFQWS_BIN="@NFQWS_BIN@"
NFQWS_ARGS="@NFQWS_ARGS@"
PID_FILE="/var/run/zapret-nfqws.pid"

QUEUE_NUM="@QUEUE_NUM@"
PORTS_TCP="@PORTS_TCP@"
PORTS_UDP="@PORTS_UDP@"
MAX_PKT_OUT="@TCP_PKT@"
MAX_PKT_OUT_UDP="@UDP_PKT@"
MAX_PKT_IN=15
MARK_PROCESSED="@MARK_PROCESSED@"
MARK_EXCLUDE="@MARK_EXCLUDE@"
IPV6_ENABLED="@IPV6_ENABLED@"
WAN_IFACES="@WAN_IFACES@"

is_running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null
}

@FIREWALL_FUNCS@

start() {
    if is_running; then
        echo "$SCRIPT_NAME: nfqws2 уже запущен (PID $(cat "$PID_FILE"))"
        return 0
    fi
    if [ ! -x "$NFQWS_BIN" ]; then
        echo "$SCRIPT_NAME: ОШИБКА — $NFQWS_BIN не найден или не исполняемый"
        return 1
    fi

    echo "$SCRIPT_NAME: Запуск nfqws2..."
    kernel_modules

    $NFQWS_BIN $NFQWS_ARGS --daemon --pidfile="$PID_FILE" \
        2>>/tmp/zapret-nfqws-stderr.log

    sleep 1
    if is_running; then
        apply_firewall
        system_config
        echo "$SCRIPT_NAME: nfqws2 запущен (PID $(cat "$PID_FILE"))"
    else
        echo "$SCRIPT_NAME: ОШИБКА — nfqws2 не удалось запустить"
        return 1
    fi
}

stop() {
    firewall_stop
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE")"
        if kill -0 "$PID" 2>/dev/null; then
            echo "$SCRIPT_NAME: Остановка nfqws2 (PID $PID)..."
            kill "$PID" 2>/dev/null
            for i in 1 2 3 4 5; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 1
            done
            kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
        fi
        rm -f "$PID_FILE"
    fi
    echo "$SCRIPT_NAME: Остановлен"
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    status)
        if is_running; then
            echo "$SCRIPT_NAME: запущен (PID $(cat "$PID_FILE"))"
        else
            echo "$SCRIPT_NAME: остановлен"
        fi
        ;;
    firewall_iptables) is_running && firewall_iptables ;;
    firewall_ip6tables) is_running && firewall_ip6tables ;;
    firewall_stop) firewall_stop ;;
    reapply) is_running && apply_firewall ;;
    kernel_modules) kernel_modules ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|reapply|firewall_iptables|firewall_ip6tables|firewall_stop}"
        exit 1
        ;;
esac

exit 0
"""


def _is_entware() -> bool:
    """Запущены ли мы на Entware (есть /opt/etc/init.d)."""
    return os.path.isdir(INIT_DIR)


def _is_systemd() -> bool:
    """Доступен ли systemd."""
    return shutil.which("systemctl") is not None and os.path.isdir(
        "/etc/systemd/system"
    )


def _is_openwrt_procd() -> bool:
    """Чистый OpenWrt с procd (без Entware /opt/etc/init.d).

    На таких системах nfqws2 запускает сам GUI при старте (app.py boot-apply),
    а GUI поднимается через procd-сервис /etc/init.d/zapret-gui. Персистентность
    firewall обеспечивает hotplug-хук.
    """
    return (
        os.path.exists("/sbin/procd")
        or os.path.exists("/etc/openwrt_release")
    ) and os.path.isfile("/etc/init.d/zapret-gui")

# Singleton
_instance = None
_instance_lock = threading.Lock()


class AutostartManager:
    """Менеджер автозапуска для Entware."""

    def __init__(self):
        self._lock = threading.Lock()

    # ──────────────── Public API ────────────────

    def get_status(self) -> dict:
        """
        Получить полный статус автозапуска.

        Returns:
            dict с полями: enabled, script_exists, script_path, strategy_name, strategy_id, method
        """
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        enabled = cfg.get("autostart", "enabled", default=False)
        installed = self._is_installed()

        if _is_entware():
            method = "initd"
            effective_enabled = enabled and installed
            # Рассинхронизация — флаг есть, скрипта нет
            if enabled and not installed:
                log.warning(
                    "Автозапуск включён в конфиге, но init.d-скрипт "
                    "не установлен",
                    source="autostart",
                )
        elif _is_systemd():
            # На systemd скрипт init.d не нужен — стратегию применяет
            # сам GUI при старте.
            method = "systemd"
            effective_enabled = enabled and os.path.isfile(SYSTEMD_UNIT_PATH)
        elif _is_openwrt_procd():
            # Чистый OpenWrt: стратегию применяет GUI при старте, GUI поднимает
            # procd. Персистентность firewall — через hotplug-хук.
            method = "openwrt"
            effective_enabled = enabled
        else:
            method = "unsupported"
            effective_enabled = False

        return {
            "enabled": effective_enabled,
            "config_enabled": enabled,
            "script_exists": installed,
            "script_path": SCRIPT_PATH,
            "init_dir_exists": os.path.isdir(INIT_DIR),
            "method": method,
            "systemd_unit_exists": os.path.isfile(SYSTEMD_UNIT_PATH),
            "strategy_id": cfg.get("strategy", "current_id"),
            "strategy_name": cfg.get("strategy", "current_name") or "Не выбрана",
        }

    def enable(self) -> dict:
        """
        Включить автозапуск.

        Генерирует скрипт, копирует в init.d, обновляет конфиг.
        Returns:
            dict { ok: bool, message: str }
        """
        with self._lock:
            return self._enable_locked()

    def disable(self) -> dict:
        """
        Выключить автозапуск.

        Удаляет скрипт из init.d, обновляет конфиг.
        Returns:
            dict { ok: bool, message: str }
        """
        with self._lock:
            return self._disable_locked()

    def regenerate(self) -> dict:
        """
        Пересоздать скрипт с текущими настройками.

        Returns:
            dict { ok: bool, message: str }
        """
        with self._lock:
            return self._regenerate_locked()

    def get_script_content(self) -> str:
        """
        Получить содержимое текущего установленного скрипта.

        Returns:
            Содержимое скрипта или пустая строка.
        """
        if os.path.isfile(SCRIPT_PATH):
            try:
                with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
                    return f.read()
            except (OSError, IOError) as e:
                log.error("Не удалось прочитать скрипт: %s" % e, source="autostart")
        return ""

    def get_script_preview(self) -> str:
        """
        Сгенерировать и вернуть превью скрипта (без установки).

        Returns:
            Содержимое скрипта.
        """
        return self._generate_script()

    # ──────────────── Private methods ────────────────

    def _enable_locked(self) -> dict:
        """Включить автозапуск (под lock)."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        # Проверяем что есть активная стратегия
        strategy_id = cfg.get("strategy", "current_id")
        if not strategy_id:
            msg = "Нет активной стратегии. Сначала примените стратегию."
            log.warning(msg, source="autostart")
            return {"ok": False, "message": msg}

        # На systemd-системах отдельный init для nfqws2 не создаётся:
        # стратегию применяет сам GUI при старте (см. app.py).
        # Достаточно убедиться, что unit-файл GUI существует и enabled.
        if not _is_entware() and _is_systemd():
            if not os.path.isfile(SYSTEMD_UNIT_PATH):
                msg = (
                    "Systemd unit %s не найден. Установите zapret-gui "
                    "через install.sh." % SYSTEMD_UNIT_PATH
                )
                log.error(msg, source="autostart")
                return {"ok": False, "message": msg}

            # На всякий случай enable unit (idempotent)
            try:
                subprocess.run(
                    ["systemctl", "enable", "zapret-gui"],
                    check=False, timeout=10,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

            cfg.set("autostart", "enabled", True)
            cfg.set("autostart", "method", "systemd")
            cfg.save()

            strategy_name = cfg.get("strategy", "current_name") or strategy_id
            log.success(
                "Автозапуск включён через systemd "
                "(стратегия: %s применится при загрузке)" % strategy_name,
                source="autostart",
            )
            return {
                "ok": True,
                "message": "Автозапуск включён. Сохранённая стратегия "
                           "будет применена при загрузке системы.",
            }

        # Чистый OpenWrt с procd (без Entware): nfqws2 запускает GUI при
        # старте, persistence — hotplug-хук. Включаем procd-сервис GUI и
        # ставим хуки.
        if not _is_entware() and _is_openwrt_procd():
            try:
                subprocess.run(
                    ["/etc/init.d/zapret-gui", "enable"],
                    check=False, timeout=10,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

            try:
                from core.firewall_persistence import install_hooks
                install_hooks()
            except Exception as e:
                log.warning("Не удалось установить хуки персистентности: %s" % e,
                            source="autostart")

            cfg.set("autostart", "enabled", True)
            cfg.set("autostart", "method", "openwrt")
            cfg.save()

            strategy_name = cfg.get("strategy", "current_name") or strategy_id
            log.success(
                "Автозапуск включён (OpenWrt/procd, стратегия: %s "
                "применится при загрузке)" % strategy_name,
                source="autostart",
            )
            return {
                "ok": True,
                "message": "Автозапуск включён. Сохранённая стратегия будет "
                           "применена при загрузке (OpenWrt).",
            }

        # Дальше — путь Entware с init.d-скриптом
        if not os.path.isdir(INIT_DIR):
            msg = (
                "Не удалось включить автозапуск: ни init.d (%s), "
                "ни systemd не доступны." % INIT_DIR
            )
            log.error(msg, source="autostart")
            return {"ok": False, "message": msg}

        # Генерируем скрипт
        script = self._generate_script()
        if not script:
            return {"ok": False, "message": "Ошибка генерации скрипта"}

        # Сохраняем локальную копию
        try:
            os.makedirs(LOCAL_INIT_DIR, exist_ok=True)
            with open(LOCAL_SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)
        except (OSError, IOError) as e:
            log.warning("Не удалось сохранить локальную копию: %s" % e,
                        source="autostart")

        # Устанавливаем в init.d
        ok = self._install_script(script)
        if not ok:
            return {"ok": False, "message": "Ошибка установки скрипта в %s" % INIT_DIR}

        # Устанавливаем хуки персистентности (Keenetic ndm / OpenWrt hotplug),
        # чтобы правила переустанавливались после flush'а системного firewall.
        try:
            from core.firewall_persistence import install_hooks
            install_hooks()
        except Exception as e:
            log.warning("Не удалось установить хуки персистентности: %s" % e,
                        source="autostart")

        # Обновляем конфиг
        cfg.set("autostart", "enabled", True)
        cfg.save()

        strategy_name = cfg.get("strategy", "current_name") or strategy_id
        log.success("Автозапуск включён (стратегия: %s)" % strategy_name,
                    source="autostart")

        return {
            "ok": True,
            "message": "Автозапуск включён. Скрипт установлен в %s" % SCRIPT_PATH,
        }

    def _disable_locked(self) -> dict:
        """Выключить автозапуск (под lock)."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        # Удаляем init.d-скрипт если он есть (Entware-режим)
        removed = self._remove_script()

        # Снимаем хуки персистентности firewall.
        try:
            from core.firewall_persistence import remove_hooks
            remove_hooks()
        except Exception as e:
            log.warning("Не удалось снять хуки персистентности: %s" % e,
                        source="autostart")

        # Обновляем конфиг в любом случае. На systemd этого достаточно:
        # GUI при старте проверит флаг и не будет применять стратегию.
        cfg.set("autostart", "enabled", False)
        cfg.save()

        if removed:
            log.success("Автозапуск выключен, init.d-скрипт удалён",
                        source="autostart")
        else:
            log.info("Автозапуск выключен", source="autostart")
        return {"ok": True, "message": "Автозапуск выключен"}

    def _regenerate_locked(self) -> dict:
        """Пересоздать скрипт (под lock)."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        if not cfg.get("autostart", "enabled", default=False):
            return {"ok": False, "message": "Автозапуск не включён"}

        strategy_id = cfg.get("strategy", "current_id")
        if not strategy_id:
            return {"ok": False, "message": "Нет активной стратегии"}

        # На systemd init.d-скрипт не нужен — стратегия применяется
        # самим GUI при старте, а сохранённый id уже в конфиге.
        if not _is_entware() and _is_systemd():
            return {
                "ok": True,
                "message": "Systemd-режим: отдельный скрипт не требуется, "
                           "сохранённая стратегия применится при загрузке.",
            }

        # Генерируем заново
        script = self._generate_script()
        if not script:
            return {"ok": False, "message": "Ошибка генерации скрипта"}

        # Сохраняем локальную копию
        try:
            os.makedirs(LOCAL_INIT_DIR, exist_ok=True)
            with open(LOCAL_SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)
        except (OSError, IOError):
            pass

        # Устанавливаем
        ok = self._install_script(script)
        if not ok:
            return {"ok": False, "message": "Ошибка установки скрипта"}

        log.success("Скрипт автозапуска пересоздан", source="autostart")
        return {"ok": True, "message": "Скрипт пересоздан и установлен"}

    def _is_installed(self) -> bool:
        """Проверить, установлен ли скрипт в init.d."""
        return os.path.isfile(SCRIPT_PATH)

    def _install_script(self, script: str) -> bool:
        """Записать скрипт в init.d и сделать executable."""
        try:
            with open(SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)

            # chmod +x
            os.chmod(SCRIPT_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                     stat.S_IROTH | stat.S_IXOTH)  # 0o755

            return True
        except (OSError, IOError) as e:
            log.error("Ошибка установки скрипта: %s" % e, source="autostart")
            return False

    def _remove_script(self) -> bool:
        """Удалить скрипт из init.d."""
        if not os.path.isfile(SCRIPT_PATH):
            return False

        try:
            os.remove(SCRIPT_PATH)
            return True
        except (OSError, IOError) as e:
            log.error("Ошибка удаления скрипта: %s" % e, source="autostart")
            return False

    def _generate_script(self) -> str:
        """
        Сгенерировать shell-скрипт для init.d (Entware).

        Команда запуска nfqws2 и параметры firewall берутся из тех же полей
        конфига, что и живой путь (NFQWSManager/FirewallManager) — раньше
        автозапуск использовал РАССИНХРОНИЗИРОВАННЫЕ значения (хардкод
        fwmark=0x10000, queue из firewall.queue_num=200, без --fwmark/--user
        и без --lua-init), из-за чего обход в режиме автозапуска ломался:
        nfqws2 метил пакеты одной меткой, а ACCEPT-правило проверяло другую →
        петля/дубли; lua-движок не грузился → --lua-desync не работал.

        firewall приведён к схеме nfqws2-keenetic: отдельные цепочки
        nfqws_post/nfqws_pre/nfqws_nat, метки MARK_PROCESSED/MARK_EXCLUDE,
        правила на оба направления (POSTROUTING + PREROUTING), NAT MASQUERADE
        для UDP и обработка TCP-флагов.
        """
        from core.config_manager import get_config_manager
        from core.strategy_builder import get_strategy_manager
        from core.nfqws_manager import get_nfqws_manager

        cfg = get_config_manager()
        sb = get_strategy_manager()
        nm = get_nfqws_manager()

        strategy_id = cfg.get("strategy", "current_id")
        strategy_name = cfg.get("strategy", "current_name") or "unknown"

        # Полная команда nfqws2 (binary + base + lua-init + strategy) —
        # ровно та же, что собирает живой путь NFQWSManager.start().
        full_cmd = []
        if strategy_id:
            try:
                strategy = sb.get_strategy(strategy_id)
                if strategy:
                    strategy_args = sb.build_nfqws_args(strategy)
                    full_cmd = nm.compose_command(strategy_args, cfg=cfg)
            except Exception as e:
                log.warning("Не удалось собрать команду стратегии: %s" % e,
                            source="autostart")
        if not full_cmd:
            full_cmd = [cfg.get("zapret", "nfqws_binary",
                                default="/opt/zapret2/nfq2/nfqws2")]

        nfqws_bin = full_cmd[0]
        nfqws_args = " ".join(full_cmd[1:])

        # Параметры firewall — из секции nfqws (совпадают с FirewallManager).
        queue_num = int(cfg.get("nfqws", "queue_num", default=300))
        ports_tcp = cfg.get("nfqws", "ports_tcp", default="80,443")
        ports_udp = cfg.get("nfqws", "ports_udp", default="443")
        tcp_pkt = int(cfg.get("nfqws", "tcp_pkt_out", default=20))
        udp_pkt = int(cfg.get("nfqws", "udp_pkt_out", default=5))
        mark_processed = cfg.get("nfqws", "desync_mark",
                                 default="0x40000000")
        mark_exclude = cfg.get("nfqws", "desync_mark_postnat",
                               default="0x20000000")
        disable_ipv6 = cfg.get("nfqws", "disable_ipv6", default=True)
        ipv6_enabled = "0" if disable_ipv6 else "1"

        # WAN-интерфейсы (из конфига или авто-детект). Пусто → правила без
        # привязки к интерфейсу (на всех).
        wan4 = nm._detect_wan_interfaces(cfg, "wan")
        wan_ifaces = " ".join(wan4)

        # Маски для --mark: nfqws2-keenetic использует "MARK/MARK".
        mark_proc_full = "%s/%s" % (mark_processed, mark_processed)
        mark_excl_full = "%s/%s" % (mark_exclude, mark_exclude)

        # Единый источник shell-функций firewall (общий с reapply-хуками).
        from core.firewall_persistence import FIREWALL_SH_FUNCTIONS

        repl = {
            "@STRATEGY_NAME@": strategy_name,
            "@STRATEGY_ID@": strategy_id or "none",
            "@NFQWS_BIN@": nfqws_bin,
            "@NFQWS_ARGS@": nfqws_args,
            "@QUEUE_NUM@": str(queue_num),
            "@PORTS_TCP@": ports_tcp or "",
            "@PORTS_UDP@": ports_udp or "",
            "@TCP_PKT@": str(tcp_pkt),
            "@UDP_PKT@": str(udp_pkt),
            "@MARK_PROCESSED@": mark_proc_full,
            "@MARK_EXCLUDE@": mark_excl_full,
            "@IPV6_ENABLED@": ipv6_enabled,
            "@WAN_IFACES@": wan_ifaces,
            "@FIREWALL_FUNCS@": FIREWALL_SH_FUNCTIONS,
        }

        script = _S99ZAPRET_TEMPLATE
        for key, value in repl.items():
            script = script.replace(key, value)
        return script


def regenerate_systemd_unit_if_needed() -> dict:
    """
    Если установлен systemd unit /etc/systemd/system/zapret-gui.service
    с захардкоженными --port/--host — переписать ExecStart без этих
    аргументов, чтобы app.py читал host/port из settings.json.

    Это нужно потому, что прежняя версия install.sh инлайнила значения
    GUI_PORT/GUI_HOST в ExecStart на момент установки. После смены порта
    в UI настройка попадает в settings.json, но юнит остаётся со старым
    портом — и сервис стартует на старом порту.

    Возвращает dict { ok, changed, message }.
    """
    if not os.path.isfile(SYSTEMD_UNIT_PATH):
        return {"ok": False, "changed": False,
                "message": "Unit-файл не найден"}

    try:
        with open(SYSTEMD_UNIT_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except (OSError, IOError) as e:
        return {"ok": False, "changed": False,
                "message": "Не удалось прочитать unit: %s" % e}

    if "--port" not in content and "--host" not in content:
        return {"ok": True, "changed": False, "message": "Unit актуален"}

    m = re.search(r"^ExecStart=(.+)$", content, re.MULTILINE)
    if not m:
        return {"ok": False, "changed": False,
                "message": "Не найдена строка ExecStart"}

    parts = m.group(1).split()
    # Убираем --host/--port вместе с их значениями
    cleaned = []
    skip = False
    for p in parts:
        if skip:
            skip = False
            continue
        if p in ("--host", "--port"):
            skip = True
            continue
        if p.startswith("--host=") or p.startswith("--port="):
            continue
        cleaned.append(p)

    new_exec = "ExecStart=" + " ".join(cleaned)
    new_content = re.sub(
        r"^ExecStart=.+$", new_exec, content, count=1, flags=re.MULTILINE
    )

    try:
        with open(SYSTEMD_UNIT_PATH, "w", encoding="utf-8") as f:
            f.write(new_content)
    except (OSError, IOError) as e:
        return {"ok": False, "changed": False,
                "message": "Не удалось записать unit (нужны root-права?): %s"
                           % e}

    # daemon-reload, чтобы systemd увидел изменения
    try:
        subprocess.run(
            ["systemctl", "daemon-reload"],
            check=False, timeout=10,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    log.info(
        "Systemd unit обновлён (убраны жёстко прописанные --port/--host). "
        "Для применения нового порта/хоста перезапустите zapret-gui: "
        "systemctl restart zapret-gui",
        source="autostart",
    )
    return {
        "ok": True,
        "changed": True,
        "message": "Systemd unit обновлён. Для применения нового порта "
                   "выполните: systemctl restart zapret-gui",
    }


def get_autostart_manager() -> AutostartManager:
    """Получить глобальный экземпляр AutostartManager."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AutostartManager()
    return _instance
