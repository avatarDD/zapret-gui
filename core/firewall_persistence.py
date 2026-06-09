# core/firewall_persistence.py
"""
Персистентность firewall-правил nfqws2 на роутерах.

Проблема
────────
На Keenetic системный демон NDMS периодически делает flush iptables
(переподключение WAN, смена политики, перезапуск файрвола). На OpenWrt то же
делает fw3/fw4 при reload. После такого flush'а наши NFQUEUE-правила исчезают,
nfqws2 продолжает работать, но трафик в него уже не попадает — обход «молча»
перестаёт действовать. Это главная причина, по которой связка GUI+nfqws2
«работает хуже», чем нативный пакет nfqws2-keenetic, у которого есть хук
переустановки правил.

Решение (портировано из nfqws2-keenetic)
────────────────────────────────────────
  • Keenetic: /opt/etc/ndm/netfilter.d/100-zapret-gui.sh — NDMS вызывает все
    скрипты из netfilter.d после каждого изменения таблиц; хук переустанавливает
    наши правила.
  • OpenWrt: /etc/hotplug.d/firewall/90-zapret-gui — аналогичный механизм fw3/fw4.

Оба хука вызывают reapply-скрипт, который:
  1) если есть init-скрипт автозапуска (S99zapret) и nfqws2 запущен — зовёт
     `S99zapret reapply` (пер-shell, быстро, как в nfqws2-keenetic);
  2) иначе, если nfqws2 запущен под управлением GUI — переустанавливает правила
     из сохранённого рантайм-конфига firewall.run теми же shell-функциями.

Единый источник shell-логики firewall — FIREWALL_SH_FUNCTIONS: его же встраивает
генератор init-скрипта автозапуска (core/autostart_manager).
"""

import os
import stat
import threading

from core.log_buffer import log


# Пути
NDM_NETFILTER_DIR = "/opt/etc/ndm/netfilter.d"
NDM_HOOK_PATH = os.path.join(NDM_NETFILTER_DIR, "100-zapret-gui.sh")

HOTPLUG_FW_DIR = "/etc/hotplug.d/firewall"
HOTPLUG_HOOK_PATH = os.path.join(HOTPLUG_FW_DIR, "90-zapret-gui")

GUI_RUNTIME_DIR = "/opt/etc/zapret-gui"
FW_RUN_CONF = os.path.join(GUI_RUNTIME_DIR, "firewall.run")
REAPPLY_SCRIPT = os.path.join(GUI_RUNTIME_DIR, "reapply-firewall.sh")

# PID-файлы, по которым reapply понимает, что nfqws2 жив.
GUI_PID_FILE = "/var/run/zapret-gui-nfqws.pid"     # живой путь (NFQWSManager)
AUTOSTART_PID_FILE = "/var/run/zapret-nfqws.pid"   # автозапуск (S99zapret)
AUTOSTART_INIT = "/opt/etc/init.d/S99zapret"


# ─────────────────────────────────────────────────────────────────────────
#  Единый источник shell-функций firewall (паритет с nfqws2-keenetic).
#  Использует переменные окружения, которые задаются ВЫШЕ по скрипту
#  (бейкингом в S99zapret либо `source firewall.run` в reapply):
#    QUEUE_NUM PORTS_TCP PORTS_UDP MAX_PKT_OUT MAX_PKT_OUT_UDP MAX_PKT_IN
#    MARK_PROCESSED MARK_EXCLUDE IPV6_ENABLED WAN_IFACES
# ─────────────────────────────────────────────────────────────────────────
FIREWALL_SH_FUNCTIONS = r"""
IPT_GROUP_POST="nfqws_post"
IPT_GROUP_PRE="nfqws_pre"
IPT_GROUP_NAT="nfqws_nat"
: "${MAX_PKT_IN:=15}"

_jnfq() { echo "-j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass"; }

kernel_modules() {
    modprobe -a -q nfnetlink_queue xt_multiport xt_connbytes xt_NFQUEUE xt_CONNMARK xt_connmark nf_conntrack 2>/dev/null
}

system_config() {
    sysctl -w net.netfilter.nf_conntrack_checksum=0 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1
}

_iface_list() {
    if [ -n "$WAN_IFACES" ]; then echo "$WAN_IFACES"; else echo "__ALL__"; fi
}

# Можно ли добавить правило (есть ли матч/цель в ядре)? $1=CMD, далее — аргументы
# правила. Возврат 1 ТОЛЬКО на явное «No chain/target/match by that name», иначе 0
# (не ломаем рабочий путь). Проба — в одноразовой цепочке таблицы filter.
_fw_probe() {
    _pc="$1"; shift
    "$_pc" -w -t filter -N ZGUI_PROBE 2>/dev/null
    _po=$("$_pc" -w -t filter -A ZGUI_PROBE "$@" 2>&1); _pr=$?
    "$_pc" -w -t filter -F ZGUI_PROBE 2>/dev/null
    "$_pc" -w -t filter -X ZGUI_PROBE 2>/dev/null
    if [ "$_pr" != "0" ] && echo "$_po" | grep -q "No chain/target/match"; then
        return 1
    fi
    return 0
}

# Детект multiport/connbytes/NFQUEUE для $1=CMD (issue #151). На Entware/Keenetic
# эти модули нередко отсутствуют и неустановимы через opkg — тогда деградируем.
_fw_caps() {
    _cc="$1"
    HAVE_MULTIPORT=1; HAVE_CONNBYTES=1; HAVE_NFQUEUE=1
    _fw_probe "$_cc" -p tcp -m multiport --dports 80,443 -j RETURN || HAVE_MULTIPORT=0
    _fw_probe "$_cc" -p tcp -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:5 -j RETURN || HAVE_CONNBYTES=0
    _fw_probe "$_cc" -j NFQUEUE --queue-num 0 --queue-bypass || HAVE_NFQUEUE=0
}

# Фрагмент(ы) матча портов, по одному на строку. С multiport — одна строка;
# без него — по строке на токен (одиночный порт или диапазон X:Y, понятный
# базовому матчу tcp/udp). $1=proto $2=dports|sports $3=ports.
_fw_port_match() {
    _proto="$1"; _dir="$2"; _ports="$3"
    if [ "$HAVE_MULTIPORT" = "1" ]; then
        echo "-p $_proto -m multiport --$_dir $_ports"
        return 0
    fi
    if [ "$_dir" = "dports" ]; then _single="--dport"; else _single="--sport"; fi
    _oifs="$IFS"; IFS=,
    for _p in $_ports; do
        IFS="$_oifs"
        [ -n "$_p" ] && echo "-p $_proto $_single $_p"
        IFS=,
    done
    IFS="$_oifs"
}

# Фрагмент ограничителя «первые N пакетов»; пусто, если connbytes недоступен.
# $1=original|reply $2=limit.
_fw_cb() {
    [ "$HAVE_CONNBYTES" = "1" ] || return 0
    echo "-m connbytes --connbytes-dir=$1 --connbytes-mode=packets --connbytes 1:$2"
}

_firewall_start() {
    CMD="$1"
    _fw_caps "$CMD"
    if [ "$HAVE_NFQUEUE" != "1" ]; then
        echo "zapret-gui: NFQUEUE недоступна для $CMD (нет xt_NFQUEUE / nfnetlink_queue) — обход не работает (issue #151)" >&2
        return 0
    fi
    JNFQ="$(_jnfq)"
    CONN_CHECK="-m mark ! --mark $MARK_PROCESSED"

    $CMD -w -t mangle -N $IPT_GROUP_POST 2>/dev/null
    $CMD -w -t mangle -F $IPT_GROUP_POST
    $CMD -w -t mangle -C POSTROUTING -j $IPT_GROUP_POST 2>/dev/null || \
        $CMD -w -t mangle -A POSTROUTING -j $IPT_GROUP_POST
    $CMD -w -t mangle -N $IPT_GROUP_PRE 2>/dev/null
    $CMD -w -t mangle -F $IPT_GROUP_PRE
    $CMD -w -t mangle -C PREROUTING -j $IPT_GROUP_PRE 2>/dev/null || \
        $CMD -w -t mangle -A PREROUTING -j $IPT_GROUP_PRE
    if [ "$CMD" = "iptables" ]; then
        $CMD -w -t nat -N $IPT_GROUP_NAT 2>/dev/null
        $CMD -w -t nat -F $IPT_GROUP_NAT
        $CMD -w -t nat -C POSTROUTING -j $IPT_GROUP_NAT 2>/dev/null || \
            $CMD -w -t nat -A POSTROUTING -j $IPT_GROUP_NAT
    fi

    for IFACE in $(_iface_list); do
        if [ "$IFACE" = "__ALL__" ]; then OIF=""; IIF=""; else OIF="-o $IFACE"; IIF="-i $IFACE"; fi

        $CMD -w -t mangle -A $IPT_GROUP_POST $OIF -m connmark --mark $MARK_EXCLUDE -j RETURN
        if [ -n "$PORTS_UDP" ]; then
            CB="$(_fw_cb original $MAX_PKT_OUT_UDP)"
            _fw_port_match udp dports "$PORTS_UDP" | while read -r PM; do
                [ -n "$PM" ] && $CMD -w -t mangle -A $IPT_GROUP_POST $OIF $CONN_CHECK $PM $CB $JNFQ
            done
        fi
        if [ -n "$PORTS_TCP" ]; then
            CB="$(_fw_cb original $MAX_PKT_OUT)"
            _fw_port_match tcp dports "$PORTS_TCP" | while read -r PM; do
                [ -n "$PM" ] || continue
                $CMD -w -t mangle -A $IPT_GROUP_POST $OIF $CONN_CHECK $PM $CB $JNFQ
                $CMD -w -t mangle -A $IPT_GROUP_POST $OIF $CONN_CHECK $PM --tcp-flags fin fin $JNFQ
                $CMD -w -t mangle -A $IPT_GROUP_POST $OIF $CONN_CHECK $PM --tcp-flags rst rst $JNFQ
            done
        fi

        if [ "$CMD" = "iptables" ]; then
            $CMD -w -t nat -A $IPT_GROUP_NAT $OIF -m mark --mark $MARK_PROCESSED -p udp -j MASQUERADE
        fi

        $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF -m connmark --mark $MARK_EXCLUDE -j RETURN
        $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF -m mark --mark $MARK_PROCESSED -j RETURN
        if [ -n "$PORTS_UDP" ]; then
            CB="$(_fw_cb reply $MAX_PKT_IN)"
            _fw_port_match udp sports "$PORTS_UDP" | while read -r PM; do
                [ -n "$PM" ] && $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF $CONN_CHECK $PM $CB $JNFQ
            done
        fi
        if [ -n "$PORTS_TCP" ]; then
            CB="$(_fw_cb reply $MAX_PKT_IN)"
            _fw_port_match tcp sports "$PORTS_TCP" | while read -r PM; do
                [ -n "$PM" ] || continue
                $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF $CONN_CHECK $PM $CB $JNFQ
                $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF $CONN_CHECK $PM --tcp-flags syn,ack syn,ack $JNFQ
                $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF $CONN_CHECK $PM --tcp-flags fin fin $JNFQ
                $CMD -w -t mangle -A $IPT_GROUP_PRE $IIF $CONN_CHECK $PM --tcp-flags rst rst $JNFQ
            done
        fi
    done
}

_firewall_stop() {
    CMD="$1"
    while $CMD -w -t mangle -C POSTROUTING -j $IPT_GROUP_POST 2>/dev/null; do
        $CMD -w -t mangle -D POSTROUTING -j $IPT_GROUP_POST 2>/dev/null || break
    done
    while $CMD -w -t mangle -C PREROUTING -j $IPT_GROUP_PRE 2>/dev/null; do
        $CMD -w -t mangle -D PREROUTING -j $IPT_GROUP_PRE 2>/dev/null || break
    done
    if [ "$CMD" = "iptables" ]; then
        while $CMD -w -t nat -C POSTROUTING -j $IPT_GROUP_NAT 2>/dev/null; do
            $CMD -w -t nat -D POSTROUTING -j $IPT_GROUP_NAT 2>/dev/null || break
        done
    fi
    $CMD -w -t mangle -F $IPT_GROUP_POST 2>/dev/null; $CMD -w -t mangle -X $IPT_GROUP_POST 2>/dev/null
    $CMD -w -t mangle -F $IPT_GROUP_PRE 2>/dev/null;  $CMD -w -t mangle -X $IPT_GROUP_PRE 2>/dev/null
    if [ "$CMD" = "iptables" ]; then
        $CMD -w -t nat -F $IPT_GROUP_NAT 2>/dev/null; $CMD -w -t nat -X $IPT_GROUP_NAT 2>/dev/null
    fi
}

firewall_iptables() {
    command -v iptables >/dev/null 2>&1 && _firewall_start iptables
}

firewall_ip6tables() {
    [ "$IPV6_ENABLED" = "1" ] || return 0
    command -v ip6tables >/dev/null 2>&1 && _firewall_start ip6tables
}

firewall_stop() {
    command -v iptables >/dev/null 2>&1 && _firewall_stop iptables
    if [ "$IPV6_ENABLED" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        _firewall_stop ip6tables
    fi
}

apply_firewall() {
    firewall_iptables
    firewall_ip6tables
}
"""


_lock = threading.Lock()


# ─────────────────────────── рендеринг ───────────────────────────

def render_run_conf(params: dict) -> str:
    """Сформировать текст firewall.run (sourced shell-конфиг)."""
    def q(v):
        return '"%s"' % ("" if v is None else v)
    return (
        "# Сгенерировано zapret-gui. Не редактируйте вручную.\n"
        "QUEUE_NUM=%s\n" % q(params.get("queue_num"))
        + "PORTS_TCP=%s\n" % q(params.get("ports_tcp"))
        + "PORTS_UDP=%s\n" % q(params.get("ports_udp"))
        + "MAX_PKT_OUT=%s\n" % q(params.get("tcp_pkt_out"))
        + "MAX_PKT_OUT_UDP=%s\n" % q(params.get("udp_pkt_out"))
        + "MAX_PKT_IN=%s\n" % q(params.get("pkt_in", 15))
        + "MARK_PROCESSED=%s\n" % q(params.get("mark_processed"))
        + "MARK_EXCLUDE=%s\n" % q(params.get("mark_exclude"))
        + "IPV6_ENABLED=%s\n" % q(params.get("ipv6_enabled"))
        + "WAN_IFACES=%s\n" % q(params.get("wan_ifaces"))
    )


def build_reapply_script() -> str:
    """reapply-скрипт для GUI-управляемого nfqws2 (источает firewall.run)."""
    return (
        "#!/bin/sh\n"
        "# Переустановка firewall-правил nfqws2 (GUI-режим).\n"
        "# Вызывается из ndm/hotplug-хука. Сгенерировано zapret-gui.\n"
        'RUN_CONF="%s"\n' % FW_RUN_CONF
        + '[ -f "$RUN_CONF" ] || exit 0\n'
        + '. "$RUN_CONF"\n'
        + FIREWALL_SH_FUNCTIONS
        + "\napply_firewall\n"
    )


def _hook_body() -> str:
    """Общее тело хука: переустановить правила, если nfqws2 запущен."""
    return (
        '# Если работает автозапуск (S99zapret) и nfqws2 жив — зовём его reapply.\n'
        'if [ -f "%s" ] && [ -f "%s" ] && kill -0 "$(cat "%s" 2>/dev/null)" 2>/dev/null; then\n'
        '    "%s" reapply >/dev/null 2>&1\n'
        '    exit 0\n'
        'fi\n'
        '# Иначе — GUI-режим: nfqws2 под управлением веб-интерфейса.\n'
        'if [ -f "%s" ] && kill -0 "$(cat "%s" 2>/dev/null)" 2>/dev/null; then\n'
        '    [ -x "%s" ] && "%s" >/dev/null 2>&1\n'
        'fi\n'
        % (
            AUTOSTART_INIT, AUTOSTART_PID_FILE, AUTOSTART_PID_FILE, AUTOSTART_INIT,
            GUI_PID_FILE, GUI_PID_FILE, REAPPLY_SCRIPT, REAPPLY_SCRIPT,
        )
    )


def build_ndm_hook() -> str:
    """Хук Keenetic NDMS (/opt/etc/ndm/netfilter.d). NDMS зовёт после flush."""
    return (
        "#!/bin/sh\n"
        "# zapret-gui: переустановка NFQUEUE-правил после flush'а NDMS.\n"
        "# $table и $type выставляет NDMS.\n"
        '[ "$table" != "mangle" ] && [ "$table" != "nat" ] && exit 0\n'
        + _hook_body()
        + "exit 0\n"
    )


def build_hotplug_hook() -> str:
    """Хук OpenWrt (/etc/hotplug.d/firewall). fw3/fw4 зовёт при reload."""
    return (
        "#!/bin/sh\n"
        "# zapret-gui: переустановка NFQUEUE-правил после reload firewall (OpenWrt).\n"
        '[ "$ACTION" = "add" ] || exit 0\n'
        + _hook_body()
        + "exit 0\n"
    )


# ─────────────────────────── установка ───────────────────────────

def _write_exec(path: str, content: str) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o755 | stat.S_IRGRP | stat.S_IROTH)
        return True
    except (OSError, IOError) as e:
        log.warning("Не удалось записать %s: %s" % (path, e),
                    source="firewall")
        return False


def is_keenetic() -> bool:
    """Keenetic — есть каталог netfilter.d (его наполняет NDMS)."""
    return os.path.isdir("/opt/etc/ndm") or os.path.isdir(NDM_NETFILTER_DIR)


def is_openwrt_hotplug() -> bool:
    """OpenWrt с hotplug.d/firewall."""
    return os.path.isdir("/etc/hotplug.d") or os.path.isdir(HOTPLUG_FW_DIR)


def install_hooks() -> dict:
    """Установить ndm/hotplug-хуки на поддерживаемых платформах.

    Возвращает {ndm: bool, hotplug: bool, installed: [paths]}.
    """
    with _lock:
        result = {"ndm": False, "hotplug": False, "installed": []}

        if is_keenetic():
            if _write_exec(NDM_HOOK_PATH, build_ndm_hook()):
                result["ndm"] = True
                result["installed"].append(NDM_HOOK_PATH)

        if is_openwrt_hotplug():
            if _write_exec(HOTPLUG_HOOK_PATH, build_hotplug_hook()):
                result["hotplug"] = True
                result["installed"].append(HOTPLUG_HOOK_PATH)

        if result["installed"]:
            log.info("Установлены хуки персистентности firewall: %s"
                     % ", ".join(result["installed"]), source="firewall")
        return result


def remove_hooks() -> dict:
    """Удалить установленные ndm/hotplug-хуки."""
    with _lock:
        removed = []
        for path in (NDM_HOOK_PATH, HOTPLUG_HOOK_PATH):
            try:
                if os.path.exists(path):
                    os.remove(path)
                    removed.append(path)
            except OSError as e:
                log.warning("Не удалось удалить %s: %s" % (path, e),
                            source="firewall")
        if removed:
            log.info("Удалены хуки персистентности: %s" % ", ".join(removed),
                     source="firewall")
        return {"removed": removed}


def write_runtime_conf(params: dict) -> bool:
    """Записать firewall.run + reapply-скрипт для GUI-режима."""
    ok = True
    try:
        os.makedirs(GUI_RUNTIME_DIR, exist_ok=True)
        with open(FW_RUN_CONF, "w", encoding="utf-8") as f:
            f.write(render_run_conf(params))
    except (OSError, IOError) as e:
        log.warning("Не удалось записать %s: %s" % (FW_RUN_CONF, e),
                    source="firewall")
        ok = False
    ok = _write_exec(REAPPLY_SCRIPT, build_reapply_script()) and ok
    return ok


def get_status() -> dict:
    """Статус хуков для API/диагностики."""
    return {
        "keenetic": is_keenetic(),
        "openwrt_hotplug": is_openwrt_hotplug(),
        "ndm_hook_installed": os.path.isfile(NDM_HOOK_PATH),
        "hotplug_hook_installed": os.path.isfile(HOTPLUG_HOOK_PATH),
        "reapply_script_installed": os.path.isfile(REAPPLY_SCRIPT),
        "runtime_conf_exists": os.path.isfile(FW_RUN_CONF),
    }
