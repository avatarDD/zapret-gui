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

# 1. Остановить
if [ -x "$INITD_SCRIPT" ]; then
    printf "${YELLOW}[...]${NC} Остановка...\n"
    "$INITD_SCRIPT" stop 2>/dev/null || true
    [ "$ENV_TYPE" = "openwrt" ] && "$INITD_SCRIPT" disable 2>/dev/null || true
fi

# 2. Init-скрипт
rm -f "$INITD_SCRIPT"
printf "${GREEN}[OK]${NC}  Init-скрипт удалён\n"

# 3. Приложение
if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    printf "${GREEN}[OK]${NC}  Приложение удалено: $APP_DIR\n"
else
    printf "${YELLOW}[--]${NC}  Приложение не найдено: $APP_DIR\n"
fi

# 4. PID файл
rm -f "$PID_FILE" 2>/dev/null || true

# 5. Init-скрипт nfqws (сгенерированный GUI)
for f in /opt/etc/init.d/S99zapret /etc/init.d/zapret; do
    if [ -f "$f" ] && grep -q "ZAPRET-GUI" "$f" 2>/dev/null; then
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
