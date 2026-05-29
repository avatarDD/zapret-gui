#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# uninstall.sh — Удаление Zapret Web-GUI
# ═══════════════════════════════════════════════════════════════
#
# Использование:
#   ./uninstall.sh          — удалить (конфигурация сохраняется)
#   ./uninstall.sh --full   — полное удаление с конфигурацией
#

set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
NC="\033[0m"

FULL_REMOVE=false
[ "$1" = "--full" ] && FULL_REMOVE=true

# Автоопределение окружения
if [ -d "/opt/etc/init.d" ] && [ -d "/opt/lib" ]; then
    APP_DIR="/opt/share/zapret-gui"
    CONFIG_DIR="/opt/etc/zapret-gui"
    INITD_SCRIPT="/opt/etc/init.d/S99zapret-gui"
    PID_FILE="/opt/var/run/zapret-gui.pid"
    ENV_TYPE="entware"
elif [ -f "/etc/openwrt_release" ]; then
    APP_DIR="/usr/share/zapret-gui"
    CONFIG_DIR="/etc/zapret-gui"
    INITD_SCRIPT="/etc/init.d/zapret-gui"
    PID_FILE="/var/run/zapret-gui.pid"
    ENV_TYPE="openwrt"
else
    APP_DIR="/opt/share/zapret-gui"
    CONFIG_DIR="/opt/etc/zapret-gui"
    INITD_SCRIPT="/opt/etc/init.d/S99zapret-gui"
    PID_FILE="/var/run/zapret-gui.pid"
    ENV_TYPE="generic"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Zapret Web-GUI — Удаление"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Окружение:  $ENV_TYPE"
echo "  Приложение: $APP_DIR"
echo "  Конфиг:     $CONFIG_DIR"

if $FULL_REMOVE; then
    printf "${RED}  Режим: ПОЛНОЕ удаление (с конфигурацией)${NC}\n"
else
    printf "${GREEN}  Режим: конфигурация будет сохранена${NC}\n"
fi

echo ""
printf "Продолжить? [y/N] "
read -r answer
[ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "Отменено"; exit 0; }
echo ""

# Определяем пакетный менеджер
if [ "$ENV_TYPE" = "entware" ] || [ "$ENV_TYPE" = "openwrt" ]; then
    PKG_CMD="opkg"
else
    PKG_CMD=""
fi

# 1. Остановить
if [ -x "$INITD_SCRIPT" ]; then
    printf "${YELLOW}[...]${NC} Остановка...\n"
    "$INITD_SCRIPT" stop 2>/dev/null || true
    [ "$ENV_TYPE" = "openwrt" ] && "$INITD_SCRIPT" disable 2>/dev/null || true
fi

# 1a. Корректно снять runtime-артефакты (nfqws2, firewall-правила,
#     ndm/hotplug-хуки персистентности) ДО удаления файлов приложения.
if [ -f "$APP_DIR/app.py" ] && command -v python3 >/dev/null 2>&1; then
    printf "${YELLOW}[...]${NC} Снятие firewall-правил и хуков...\n"
    PYTHONPATH="$APP_DIR" python3 -m core.teardown 2>/dev/null || true
fi
# Shell-fallback на случай, если python недоступен/сломан: снимаем хуки
# и наши firewall-цепочки напрямую.
cleanup_firewall_shell() {
    rm -f /opt/etc/ndm/netfilter.d/100-zapret-gui.sh 2>/dev/null || true
    rm -f /etc/hotplug.d/firewall/90-zapret-gui 2>/dev/null || true
    for CMD in iptables ip6tables; do
        command -v "$CMD" >/dev/null 2>&1 || continue
        for CHAIN in nfqws_post nfqws_pre; do
            while $CMD -w -t mangle -D POSTROUTING -j "$CHAIN" 2>/dev/null; do :; done
            while $CMD -w -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null; do :; done
            $CMD -w -t mangle -F "$CHAIN" 2>/dev/null || true
            $CMD -w -t mangle -X "$CHAIN" 2>/dev/null || true
        done
    done
    if command -v iptables >/dev/null 2>&1; then
        while iptables -w -t nat -D POSTROUTING -j nfqws_nat 2>/dev/null; do :; done
        iptables -w -t nat -F nfqws_nat 2>/dev/null || true
        iptables -w -t nat -X nfqws_nat 2>/dev/null || true
    fi
    command -v nft >/dev/null 2>&1 && nft delete table inet zapret_gui 2>/dev/null || true
}
cleanup_firewall_shell
printf "${GREEN}[OK]${NC}  Firewall-правила и хуки сняты\n"

# 2. Init-скрипт
rm -f "$INITD_SCRIPT"
printf "${GREEN}[OK]${NC}  Init-скрипт удалён\n"

# 2a. Удалить пакеты, установленные через opkg
opkg_list="$CONFIG_DIR/opkg_installed.list"
if [ -n "$PKG_CMD" ] && [ -f "$opkg_list" ]; then
    printf "${YELLOW}[...]${NC} Удаление пакетов opkg...\n"
    while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        $PKG_CMD remove "$pkg" 2>/dev/null \
            && printf "${GREEN}[OK]${NC}  opkg remove %s\n" "$pkg" \
            || printf "${YELLOW}[--]${NC}  Не удалось удалить: %s\n" "$pkg"
    done < "$opkg_list"
    rm -f "$opkg_list"
fi

# 3. Приложение
if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    printf "${GREEN}[OK]${NC}  Приложение удалено: $APP_DIR\n"
else
    printf "${YELLOW}[--]${NC}  Приложение не найдено: $APP_DIR\n"
fi

# 3a. CLI-обёртка zapret-gui (живёт вне APP_DIR — в /opt/bin или /usr/bin)
for bin in /opt/bin/zapret-gui /usr/bin/zapret-gui; do
    if [ -f "$bin" ]; then
        rm -f "$bin"
        printf "${GREEN}[OK]${NC}  CLI-команда удалена: $bin\n"
    fi
done

# 4. PID файл
rm -f "$PID_FILE" 2>/dev/null || true

# 5. Init-скрипт nfqws (сгенерированный GUI)
#    Маркер 'zapret-gui:nfqws-autostart' зашит в шаблон S99zapret.
for f in /opt/etc/init.d/S99zapret /etc/init.d/zapret; do
    if [ -f "$f" ] && grep -qiE "zapret-gui:nfqws-autostart|ZAPRET-GUI" "$f" 2>/dev/null; then
        printf "${YELLOW}[WARN]${NC} Найден init-скрипт nfqws от GUI: $f\n"
        printf "  Удалить? [y/N] "
        read -r del_answer
        if [ "$del_answer" = "y" ] || [ "$del_answer" = "Y" ]; then
            rm -f "$f"
            printf "${GREEN}[OK]${NC}  Удалён: $f\n"
        fi
    fi
done

# 6. Конфигурация (только при --full)
if $FULL_REMOVE; then
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        printf "${GREEN}[OK]${NC}  Конфигурация удалена: $CONFIG_DIR\n"
    fi
    # Логи и временные файлы
    rm -rf /tmp/zapret-gui 2>/dev/null || true
    rm -f /tmp/zapret-gui-server.log 2>/dev/null || true
    rm -f /tmp/zapret-gui-scan-resume.json 2>/dev/null || true
    printf "${GREEN}[OK]${NC}  Логи и временные файлы очищены\n"
else
    printf "${GREEN}[OK]${NC}  Конфигурация сохранена: $CONFIG_DIR\n"
fi

echo ""
printf "${GREEN}✓ Zapret Web-GUI удалён${NC}\n"
if ! $FULL_REMOVE; then
    echo "  Для полного удаления: $0 --full"
fi
echo ""
