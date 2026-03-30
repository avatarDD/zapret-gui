import os
import stat
import shutil
import threading
from core.log_buffer import log
INIT_DIR = "/opt/etc/init.d"
SCRIPT_NAME = "S99zapret"
SCRIPT_PATH = os.path.join(INIT_DIR, SCRIPT_NAME)
LOCAL_INIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "init.d")
LOCAL_SCRIPT_PATH = os.path.join(LOCAL_INIT_DIR, SCRIPT_NAME)
_instance = None
_instance_lock = threading.Lock()
class AutostartManager:
    def __init__(self):
        self._lock = threading.Lock()
    def get_status(self) -> dict:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        installed = self._is_installed()
        enabled = cfg.get("autostart", "enabled", default=False)
        if enabled and not installed:
            log.warning("Автозапуск включён в конфиге, но скрипт не установлен",
                        source="autostart")
        return {
            "enabled": enabled and installed,
            "config_enabled": enabled,
            "script_exists": installed,
            "script_path": SCRIPT_PATH,
            "init_dir_exists": os.path.isdir(INIT_DIR),
            "strategy_id": cfg.get("strategy", "current_id"),
            "strategy_name": cfg.get("strategy", "current_name") or "Не выбрана",
        }
    def enable(self) -> dict:
        with self._lock:
            return self._enable_locked()
    def disable(self) -> dict:
        with self._lock:
            return self._disable_locked()
    def regenerate(self) -> dict:
        with self._lock:
            return self._regenerate_locked()
    def get_script_content(self) -> str:
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
        # Проверяем директорию init.d
        if not os.path.isdir(INIT_DIR):
            msg = "Директория %s не найдена. Entware установлен?" % INIT_DIR
            log.error(msg, source="autostart")
            return {"ok": False, "message": msg}
        strategy_id = cfg.get("strategy", "current_id")
        if not strategy_id:
            msg = "Нет активной стратегии. Сначала примените стратегию."
            log.warning(msg, source="autostart")
            return {"ok": False, "message": msg}
        script = self._generate_script()
        if not script:
            return {"ok": False, "message": "Ошибка генерации скрипта"}
        try:
            os.makedirs(LOCAL_INIT_DIR, exist_ok=True)
            with open(LOCAL_SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)
        except (OSError, IOError) as e:
            log.warning("Не удалось сохранить локальную копию: %s" % e,
                        source="autostart")
        ok = self._install_script(script)
        if not ok:
            return {"ok": False, "message": "Ошибка установки скрипта в %s" % INIT_DIR}
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
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        removed = self._remove_script()
        cfg.set("autostart", "enabled", False)
        cfg.save()
        if removed:
            log.success("Автозапуск выключен, скрипт удалён", source="autostart")
            return {"ok": True, "message": "Автозапуск выключен"}
        else:
            log.info("Автозапуск выключен (скрипт не был установлен)",
                     source="autostart")
            return {"ok": True, "message": "Автозапуск выключен"}
    def _regenerate_locked(self) -> dict:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("autostart", "enabled", default=False):
            return {"ok": False, "message": "Автозапуск не включён"}
        strategy_id = cfg.get("strategy", "current_id")
        if not strategy_id:
            return {"ok": False, "message": "Нет активной стратегии"}
        script = self._generate_script()
        if not script:
            return {"ok": False, "message": "Ошибка генерации скрипта"}
        try:
            os.makedirs(LOCAL_INIT_DIR, exist_ok=True)
            with open(LOCAL_SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)
        except (OSError, IOError):
            pass
        ok = self._install_script(script)
        if not ok:
            return {"ok": False, "message": "Ошибка установки скрипта"}
        log.success("Скрипт автозапуска пересоздан", source="autostart")
        return {"ok": True, "message": "Скрипт пересоздан и установлен"}
    def _is_installed(self) -> bool:
        return os.path.isfile(SCRIPT_PATH)
    def _install_script(self, script: str) -> bool:
        try:
            with open(SCRIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(script)
            os.chmod(SCRIPT_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                     stat.S_IROTH | stat.S_IXOTH)
            return True
        except (OSError, IOError) as e:
            log.error("Ошибка установки скрипта: %s" % e, source="autostart")
            return False
    def _remove_script(self) -> bool:
        if not os.path.isfile(SCRIPT_PATH):
            return False
        try:
            os.remove(SCRIPT_PATH)
            return True
        except (OSError, IOError) as e:
            log.error("Ошибка удаления скрипта: %s" % e, source="autostart")
            return False
    def _generate_script(self) -> str:
        from core.config_manager import get_config_manager
        from core.strategy_builder import get_strategy_manager
        cfg = get_config_manager()
        sb = get_strategy_manager()
        strategy_id = cfg.get("strategy", "current_id")
        strategy_name = cfg.get("strategy", "current_name") or "unknown"
        nfqws_bin = cfg.get("zapret", "nfqws_binary",
                            default="/opt/zapret2/nfq2/nfqws2")
        queue_num = cfg.get("firewall", "queue_num", default=200)
        fw_type = cfg.get("firewall", "type", default="auto")
        nfqws_args = []
        if strategy_id:
            try:
                strategy = sb.get_strategy(strategy_id)
                if strategy:
                    nfqws_args = sb.build_nfqws_args(strategy)
            except Exception as e:
                log.warning("Не удалось собрать аргументы стратегии: %s" % e,
                            source="autostart")
        args_str = " ".join(nfqws_args) if nfqws_args else ""
        # Порты из конфига/стратегии
        ports_tcp = "80,443"
        ports_udp = "443,50000:50100"
        tcp_pkt = 8
        udp_pkt = 8
        if strategy_id:
            try:
                strategy = sb.get_strategy(strategy_id)
                if strategy:
                    fw = strategy.get("firewall", {})
                    if fw.get("ports_tcp"):
                        ports_tcp = fw["ports_tcp"]
                    if fw.get("ports_udp"):
                        ports_udp = fw["ports_udp"]
                    if fw.get("tcp_packets"):
                        tcp_pkt = fw["tcp_packets"]
                    if fw.get("udp_packets"):
                        udp_pkt = fw["udp_packets"]
            except Exception:
                pass
        fwmark = "0x10000"
        fwmask = "0x10000"
        script = """#!/bin/sh
#
# Zapret Web-GUI — автозапуск nfqws2
# Сгенерировано автоматически. Не редактируйте вручную.
#
# Стратегия: {strategy_name} ({strategy_id})
# Дата генерации: $(date 2>/dev/null || echo "unknown")
#
SCRIPT_NAME="S99zapret"
NFQWS_BIN="{nfqws_bin}"
NFQWS_ARGS="{args_str}"
QUEUE_NUM="{queue_num}"
PID_FILE="/var/run/zapret-nfqws.pid"
# Параметры firewall
PORTS_TCP="{ports_tcp}"
PORTS_UDP="{ports_udp}"
TCP_PKT="{tcp_pkt}"
UDP_PKT="{udp_pkt}"
FWMARK="{fwmark}"
FWMASK="{fwmask}"
IPT_COMMENT="zapret-gui"
start() {{
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "$SCRIPT_NAME: nfqws2 уже запущен (PID $(cat "$PID_FILE"))"
        return 0
    fi
    if [ ! -x "$NFQWS_BIN" ]; then
        echo "$SCRIPT_NAME: ОШИБКА — $NFQWS_BIN не найден или не исполняемый"
        return 1
    fi
    echo "$SCRIPT_NAME: Запуск nfqws2..."
    # Применяем правила firewall
    apply_firewall
    # Запускаем nfqws2
    $NFQWS_BIN --qnum=$QUEUE_NUM $NFQWS_ARGS --daemon --pidfile="$PID_FILE" \\
        2>>/tmp/zapret-nfqws-stderr.log
    sleep 1
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "$SCRIPT_NAME: nfqws2 запущен (PID $(cat "$PID_FILE"))"
    else
        echo "$SCRIPT_NAME: ОШИБКА — nfqws2 не удалось запустить"
        remove_firewall
        return 1
    fi
}}
stop() {{
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE")"
        if kill -0 "$PID" 2>/dev/null; then
            echo "$SCRIPT_NAME: Остановка nfqws2 (PID $PID)..."
            kill "$PID" 2>/dev/null
            # Ждём завершения
            for i in 1 2 3 4 5; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 1
            done
            # SIGKILL если не завершился
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null
                sleep 1
            fi
        fi
        rm -f "$PID_FILE"
    fi
    # Снимаем правила firewall
    remove_firewall
    echo "$SCRIPT_NAME: Остановлен"
}}
apply_firewall() {{
    # Определяем доступный инструмент
    if command -v iptables >/dev/null 2>&1; then
        apply_iptables
    elif command -v nft >/dev/null 2>&1; then
        apply_nftables
    else
        echo "$SCRIPT_NAME: ПРЕДУПРЕЖДЕНИЕ — ни iptables, ни nft не найдены"
    fi
}}
remove_firewall() {{
    if command -v iptables >/dev/null 2>&1; then
        remove_iptables
    fi
    if command -v nft >/dev/null 2>&1; then
        remove_nftables
    fi
}}
apply_iptables() {{
    # ACCEPT для помеченных пакетов
    iptables -t mangle -I POSTROUTING -m mark --mark "$FWMARK/$FWMASK" \\
        -m comment --comment "$IPT_COMMENT" -j ACCEPT 2>/dev/null
    # TCP -> NFQUEUE
    if [ -n "$PORTS_TCP" ]; then
        iptables -t mangle -I POSTROUTING -p tcp \\
            -m multiport --dports "$PORTS_TCP" \\
            -m connbytes --connbytes-dir=original --connbytes-mode=packets \\
            --connbytes "1:$TCP_PKT" \\
            -m comment --comment "$IPT_COMMENT" \\
            -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass 2>/dev/null
    fi
    # UDP -> NFQUEUE
    if [ -n "$PORTS_UDP" ]; then
        iptables -t mangle -I POSTROUTING -p udp \\
            -m multiport --dports "$PORTS_UDP" \\
            -m connbytes --connbytes-dir=original --connbytes-mode=packets \\
            --connbytes "1:$UDP_PKT" \\
            -m comment --comment "$IPT_COMMENT" \\
            -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass 2>/dev/null
    fi
}}
remove_iptables() {{
    # Удаляем все правила с нашим комментарием (несколько проходов)
    for pass in 1 2 3 4 5 6 7 8 9 10; do
        FOUND=0
        iptables -t mangle -L POSTROUTING --line-numbers -n 2>/dev/null | \\
            grep "$IPT_COMMENT" | awk '{{print $1}}' | sort -rn | while read NUM; do
            iptables -t mangle -D POSTROUTING "$NUM" 2>/dev/null
            FOUND=1
        done
        [ "$FOUND" = "0" ] && break
    done
}}
apply_nftables() {{
    nft add table inet zapret-gui 2>/dev/null
    nft add chain inet zapret-gui postrouting "{{ type filter hook postrouting priority 150; policy accept; }}" 2>/dev/null
    # ACCEPT помеченных
    nft add rule inet zapret-gui postrouting mark and "$FWMASK" == "$FWMARK" accept 2>/dev/null
    # TCP -> NFQUEUE
    if [ -n "$PORTS_TCP" ]; then
        nft add rule inet zapret-gui postrouting tcp dport "{{ $PORTS_TCP }}" \\
            ct original packets le "$TCP_PKT" queue num "$QUEUE_NUM" bypass 2>/dev/null
    fi
    # UDP -> NFQUEUE
    if [ -n "$PORTS_UDP" ]; then
        nft add rule inet zapret-gui postrouting udp dport "{{ $PORTS_UDP }}" \\
            ct original packets le "$UDP_PKT" queue num "$QUEUE_NUM" bypass 2>/dev/null
    fi
}}
remove_nftables() {{
    nft delete table inet zapret-gui 2>/dev/null
}}
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 1
        start
        ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "$SCRIPT_NAME: запущен (PID $(cat "$PID_FILE"))"
        else
            echo "$SCRIPT_NAME: остановлен"
        fi
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart|status}}"
        exit 1
        ;;
esac
exit 0
""".format(
            strategy_name=strategy_name,
            strategy_id=strategy_id or "none",
            nfqws_bin=nfqws_bin,
            args_str=args_str,
            queue_num=queue_num,
            ports_tcp=ports_tcp,
            ports_udp=ports_udp,
            tcp_pkt=tcp_pkt,
            udp_pkt=udp_pkt,
            fwmark=fwmark,
            fwmask=fwmask,
        )
        return script
def get_autostart_manager() -> AutostartManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AutostartManager()
    return _instance
