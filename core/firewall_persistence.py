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

Бэкенды
───────
Shell-функции умеют оба бэкенда — iptables/ip6tables (именованные цепочки
nfqws_post/nfqws_pre/nfqws_nat) и nftables (таблица inet zapret_gui, паритет с
core/firewall.py::_apply_nftables). Какой применять — говорит переменная
FW_BACKEND из firewall.run / S99zapret: её проставляет GUI, знающий и настройку
`firewall.type`, и результат авто-детекта. Если она пуста (firewall.run от
прошлых версий), shell определяет бэкенд сам тем же правилом.

Раньше shell-путь знал только iptables. На OpenWrt с fw4 это значило, что после
`nft flush ruleset` хук не возвращал НИЧЕГО: на чистом nft-образе `iptables`
вообще нет, а где есть — это шим, пишущий мимо таблицы, которой владеет fw4.
Обход оставался «запущенным» без единого правила до ручного перезапуска.
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
#    MARK_PROCESSED MARK_EXCLUDE IPV6_ENABLED WAN_IFACES FW_BACKEND
# ─────────────────────────────────────────────────────────────────────────
FIREWALL_SH_FUNCTIONS = r"""
IPT_GROUP_POST="nfqws_post"
IPT_GROUP_PRE="nfqws_pre"
IPT_GROUP_NAT="nfqws_nat"
NFT_TABLE="zapret_gui"
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

# Снять все переходы `hook -j chain` (их может быть несколько — дубли от
# прошлых реаплаев). Счётчик обязателен: без него `-C`, который по любой
# причине продолжает отвечать «правило есть», вешает init-скрипт намертво —
# а он крутится под root при каждой загрузке и на каждом firewall-хуке.
# $1=CMD $2=таблица $3=hook-цепочка $4=наша цепочка
_fw_unhook() {
    _uh_i=0
    while [ "$_uh_i" -lt 10 ]; do
        $1 -w -t "$2" -C "$3" -j "$4" 2>/dev/null || break
        $1 -w -t "$2" -D "$3" -j "$4" 2>/dev/null || break
        _uh_i=$((_uh_i + 1))
    done
}

_firewall_stop() {
    CMD="$1"
    _fw_unhook "$CMD" mangle POSTROUTING $IPT_GROUP_POST
    _fw_unhook "$CMD" mangle PREROUTING $IPT_GROUP_PRE
    if [ "$CMD" = "iptables" ]; then
        _fw_unhook "$CMD" nat POSTROUTING $IPT_GROUP_NAT
    fi
    $CMD -w -t mangle -F $IPT_GROUP_POST 2>/dev/null; $CMD -w -t mangle -X $IPT_GROUP_POST 2>/dev/null
    $CMD -w -t mangle -F $IPT_GROUP_PRE 2>/dev/null;  $CMD -w -t mangle -X $IPT_GROUP_PRE 2>/dev/null
    if [ "$CMD" = "iptables" ]; then
        $CMD -w -t nat -F $IPT_GROUP_NAT 2>/dev/null; $CMD -w -t nat -X $IPT_GROUP_NAT 2>/dev/null
    fi
}

# ──────────────────────────── nftables ────────────────────────────
# Паритет с Python-путём (_apply_nftables в core/firewall.py): одна inet-таблица
# zapret_gui с цепочками postrouting / prerouting / natpost. Семейство inet
# покрывает сразу IPv4 и IPv6, поэтому IPV6_ENABLED здесь не при чём (ровно как
# в Python-пути).
#
# Каждая команда уходит в nft ОДНОЙ строкой-аргументом: nft склеивает argv через
# пробел и лексит заново, так что кавычки вокруг имён интерфейсов и `;` внутри
# спецификации цепочки доезжают как есть, а shell не ломает `{ … }`.

# Список портов iptables-стиля → nft-множество: "443,3478:3481" → "443, 3478-3481".
# Без замены двоеточия nft падает с «Could not resolve service: Servname not
# supported for ai_socktype» (issue #101).
_nft_ports() {
    echo "$1" | sed 's/:/-/g; s/,/, /g'
}

# `oifname "eth0"` / `oifname { "eth0", "eth1" }` / пусто (все интерфейсы).
# Кавычки обязательны: имя, начинающееся с цифры (6in4-he_net, 6to4-wan),
# nft-лексер без них читает как число+строку → синтаксическая ошибка на каждом
# правиле (issue #226).
_nft_iface() {
    [ -n "$WAN_IFACES" ] || return 0
    _ni_n=0; _ni_list=""
    for _ni in $WAN_IFACES; do
        _ni_n=$((_ni_n + 1))
        if [ -z "$_ni_list" ]; then _ni_list="\"$_ni\""
        else _ni_list="$_ni_list, \"$_ni\""; fi
    done
    if [ "$_ni_n" = "1" ]; then echo "$1 $_ni_list"
    else echo "$1 { $_ni_list }"; fi
}

# Ошибки НЕ глушим: у iptables-пути они тоже видны, а хук и init-скрипт сами
# решают, куда девать вывод. Молчаливое падение здесь означало бы «правил нет,
# и никто об этом не узнал».
_nft_rule() {
    nft add rule inet $NFT_TABLE "$1" "$2"
}

_nft_firewall_start() {
    # Метки в firewall.run записаны в iptables-форме MARK/MASK — nft нужен
    # только сам MARK.
    _mark_proc="${MARK_PROCESSED%%/*}"
    _mark_excl="${MARK_EXCLUDE%%/*}"
    _oif="$(_nft_iface oifname)"
    _iif="$(_nft_iface iifname)"
    _tcpp=""; [ -n "$PORTS_TCP" ] && _tcpp="{ $(_nft_ports "$PORTS_TCP") }"
    _udpp=""; [ -n "$PORTS_UDP" ] && _udpp="{ $(_nft_ports "$PORTS_UDP") }"

    # Таблицу пересоздаём целиком: так реаплай после flush'а не копит дубли
    # правил, а порядок гарантированно совпадает с Python-путём.
    nft delete table inet $NFT_TABLE 2>/dev/null
    nft add table inet $NFT_TABLE || {
        echo "zapret-gui: nft add table не удался — правила не поставлены" >&2
        return 1
    }
    nft add chain inet $NFT_TABLE postrouting \
        '{ type filter hook postrouting priority 150 ; }'
    nft add chain inet $NFT_TABLE prerouting \
        '{ type filter hook prerouting priority -150 ; }'
    nft add chain inet $NFT_TABLE natpost \
        '{ type nat hook postrouting priority 100 ; }'

    # ─── postrouting (исходящий) ───
    # EXCLUDE — это CONNMARK, поэтому матчим `ct mark`, а не пакетный
    # `meta mark` (иначе исключённое соединение снова попадёт в очередь).
    _nft_rule postrouting "$_oif ct mark and $_mark_excl == $_mark_excl return"
    _nft_rule postrouting "$_oif meta mark and $_mark_proc == $_mark_proc return"
    if [ -n "$_tcpp" ]; then
        _nft_rule postrouting "$_oif tcp dport $_tcpp ct original packets 1-$MAX_PKT_OUT queue num $QUEUE_NUM bypass"
        _nft_rule postrouting "$_oif tcp dport $_tcpp tcp flags fin queue num $QUEUE_NUM bypass"
        _nft_rule postrouting "$_oif tcp dport $_tcpp tcp flags rst queue num $QUEUE_NUM bypass"
    fi
    if [ -n "$_udpp" ]; then
        _nft_rule postrouting "$_oif udp dport $_udpp ct original packets 1-$MAX_PKT_OUT_UDP queue num $QUEUE_NUM bypass"
    fi

    # ─── prerouting (входящий/ответы) ───
    _nft_rule prerouting "$_iif ct mark and $_mark_excl == $_mark_excl return"
    _nft_rule prerouting "$_iif meta mark and $_mark_proc == $_mark_proc return"
    if [ -n "$_tcpp" ]; then
        _nft_rule prerouting "$_iif tcp sport $_tcpp ct reply packets 1-$MAX_PKT_IN queue num $QUEUE_NUM bypass"
        _nft_rule prerouting "$_iif tcp sport $_tcpp tcp flags syn,ack queue num $QUEUE_NUM bypass"
    fi
    if [ -n "$_udpp" ]; then
        _nft_rule prerouting "$_iif udp sport $_udpp ct reply packets 1-$MAX_PKT_IN queue num $QUEUE_NUM bypass"
    fi

    # ─── nat postrouting: MASQUERADE для переписанных nfqws2 пакетов ───
    _nft_rule natpost "$_oif meta mark and $_mark_proc == $_mark_proc meta l4proto udp masquerade"
}

_nft_firewall_stop() {
    # Отсутствие таблицы — не ошибка: глушим только stderr.
    nft delete table inet $NFT_TABLE 2>/dev/null
    return 0
}

# Какой бэкенд использовать. FW_BACKEND проставляет GUI (он знает и настройку
# firewall.type, и результат авто-детекта); пусто — определяем сами тем же
# правилом, что и core/firewall.py::_auto_detect.
_fw_backend() {
    if [ -n "$FW_BACKEND" ]; then echo "$FW_BACKEND"; return 0; fi
    _has_ipt=0; _has_nft=0
    command -v iptables >/dev/null 2>&1 && _has_ipt=1
    command -v nft >/dev/null 2>&1 && _has_nft=1
    [ "$_has_ipt" = "0" ] && { [ "$_has_nft" = "1" ] && echo nftables; return 0; }
    [ "$_has_nft" = "0" ] && { echo iptables; return 0; }
    # Обе есть. `iptables` на OpenWrt 22+/fw4 — это шим iptables-nft поверх
    # nftables: пишем нативно через nft, иначе конфликтуем с fw4. На legacy
    # (Keenetic/Entware) остаётся iptables.
    if iptables --version 2>/dev/null | grep -q nf_tables; then
        echo nftables
    else
        echo iptables
    fi
}

firewall_nftables() {
    command -v nft >/dev/null 2>&1 && _nft_firewall_start
}

firewall_iptables() {
    command -v iptables >/dev/null 2>&1 && _firewall_start iptables
}

firewall_ip6tables() {
    [ "$IPV6_ENABLED" = "1" ] || return 0
    command -v ip6tables >/dev/null 2>&1 && _firewall_start ip6tables
}

# Снимаем ОБА бэкенда независимо от текущего: настройка firewall.type могла
# смениться с прошлого старта, и правила «прошлого» бэкенда надо убрать, иначе
# они останутся висеть навсегда.
firewall_stop() {
    command -v nft >/dev/null 2>&1 && _nft_firewall_stop
    command -v iptables >/dev/null 2>&1 && _firewall_stop iptables
    if [ "$IPV6_ENABLED" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        _firewall_stop ip6tables
    fi
    return 0
}

apply_firewall() {
    if [ "$(_fw_backend)" = "nftables" ]; then
        firewall_nftables
    else
        firewall_iptables
        firewall_ip6tables
    fi
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
        # Бэкенд определяет GUI (он знает и настройку firewall.type, и
        # результат авто-детекта). Пусто — shell определит сам тем же
        # правилом; так же ведут себя firewall.run от прошлых версий.
        + "FW_BACKEND=%s\n" % q(params.get("fw_backend"))
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
