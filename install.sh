set -e
REPO_URL="https://github.com/avatarDD/zapret-gui"
BRANCH="${ZAPRET_GUI_BRANCH:-main}"
VERSION="0.14.0"
GUI_PORT="${ZAPRET_GUI_PORT:-8080}"
GUI_HOST="${ZAPRET_GUI_HOST:-0.0.0.0}"
detect_env() {
    if [ -d "/opt/etc/init.d" ] && [ -d "/opt/lib" ]; then
        ENV_TYPE="entware"
        APP_DIR="/opt/share/zapret-gui"
        CONFIG_DIR="/opt/etc/zapret-gui"
        INITD_DIR="/opt/etc/init.d"
        INITD_SCRIPT="$INITD_DIR/S99zapret-gui"
        PID_FILE="/opt/var/run/zapret-gui.pid"
        PKG_CMD="opkg"
    elif [ -f "/etc/openwrt_release" ]; then
        ENV_TYPE="openwrt"
        APP_DIR="/usr/share/zapret-gui"
        CONFIG_DIR="/etc/zapret-gui"
        INITD_DIR="/etc/init.d"
        INITD_SCRIPT="$INITD_DIR/zapret-gui"
        PID_FILE="/var/run/zapret-gui.pid"
        PKG_CMD="opkg"
    else
        ENV_TYPE="generic"
        APP_DIR="/opt/share/zapret-gui"
        CONFIG_DIR="/opt/etc/zapret-gui"
        INITD_DIR="/opt/etc/init.d"
        INITD_SCRIPT="$INITD_DIR/S99zapret-gui"
        PID_FILE="/var/run/zapret-gui.pid"
        PKG_CMD=""
    fi
}
# ── Цвета ─────────────────────────────────────────────────────
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
NC="\033[0m"
info()    { printf "${CYAN}[INFO]${NC} %s\n" "$1"; }
ok()      { printf "${GREEN}[OK]${NC}   %s\n" "$1"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error()   { printf "${RED}[ERR]${NC}  %s\n" "$1"; }
detect_downloader() {
    if command -v curl >/dev/null 2>&1; then
        DOWNLOAD_CMD="curl"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOAD_CMD="wget"
    else
        error "Ни curl, ни wget не найдены"
        error "Установите: $PKG_CMD install curl"
        exit 1
    fi
}
download() {
    local url="$1"
    local dest="$2"
    if [ "$DOWNLOAD_CMD" = "curl" ]; then
        curl -fsSL --connect-timeout 15 --max-time 120 -o "$dest" "$url"
    else
        wget -q --timeout=15 -O "$dest" "$url"
    fi
}
check_deps() {
    info "Проверка зависимостей..."
    local missing=""
    # Python3
    if command -v python3 >/dev/null 2>&1; then
        PY_VER=$(python3 --version 2>&1)
        ok "python3: $PY_VER"
    else
        missing="$missing python3-light"
        warn "python3 не найден"
    fi
    if python3 -c "import bottle" 2>/dev/null; then
        BOTTLE_VER=$(python3 -c "import bottle; print(bottle.__version__)" 2>/dev/null)
        ok "bottle: $BOTTLE_VER"
    else
        missing="$missing python3-bottle"
        warn "python3-bottle не найден"
    fi
    if [ -n "$missing" ]; then
        info "Установка:$missing"
        if [ -n "$PKG_CMD" ]; then
            $PKG_CMD update 2>/dev/null || true
            for pkg in $missing; do
                info "  Устанавливаем $pkg..."
                $PKG_CMD install "$pkg" || {
                    error "Не удалось установить $pkg"
                    error "Установите вручную: $PKG_CMD install $pkg"
                    exit 1
                }
            done
            ok "Зависимости установлены"
        else
            error "Пакетный менеджер не найден. Установите вручную:$missing"
            exit 1
        fi
    fi
}
install_from_github() {
    info "Загрузка zapret-gui из GitHub ($BRANCH)..."
    local TMP_DIR="/tmp/zapret-gui-install-$$"
    local ARCHIVE="$TMP_DIR/zapret-gui.tar.gz"
    mkdir -p "$TMP_DIR"
    trap "rm -rf '$TMP_DIR'" EXIT
    local archive_url="$REPO_URL/archive/refs/heads/$BRANCH.tar.gz"
    download "$archive_url" "$ARCHIVE" || {
        archive_url="$REPO_URL/archive/refs/tags/v$VERSION.tar.gz"
        info "Пробуем тег v$VERSION..."
        download "$archive_url" "$ARCHIVE" || {
            error "Не удалось скачать архив"
            exit 1
        }
    }
    ok "Архив загружен"
    info "Распаковка..."
    cd "$TMP_DIR"
    tar xzf "$ARCHIVE" || {
        error "Не удалось распаковать архив"
        exit 1
    }
    local src_dir=$(find "$TMP_DIR" -maxdepth 1 -type d -name 'zapret-gui*' | head -1)
    if [ -z "$src_dir" ]; then
        error "Не найдена директория проекта в архиве"
        exit 1
    fi
    ok "Распакован: $(basename $src_dir)"
    if [ -d "$APP_DIR" ]; then
        info "Обновление — бэкап конфигурации..."
        if [ -f "$CONFIG_DIR/settings.json" ]; then
            cp "$CONFIG_DIR/settings.json" "$TMP_DIR/settings.json.bak"
            ok "Бэкап settings.json"
        fi
        if [ -d "$APP_DIR/config/strategies/user" ]; then
            cp -r "$APP_DIR/config/strategies/user" "$TMP_DIR/user_strategies_bak"
            ok "Бэкап пользовательских стратегий"
        fi
    fi
    if [ -f "$INITD_SCRIPT" ] && [ -x "$INITD_SCRIPT" ]; then
        info "Остановка текущего сервера..."
        "$INITD_SCRIPT" stop 2>/dev/null || true
    fi
    info "Установка в $APP_DIR..."
    mkdir -p "$APP_DIR"
    mkdir -p "$CONFIG_DIR"
    cp "$src_dir/app.py" "$APP_DIR/"
    for dir in api core config web; do
        if [ -d "$src_dir/$dir" ]; then
            rm -rf "$APP_DIR/$dir"
            cp -r "$src_dir/$dir" "$APP_DIR/"
        fi
    done
    mkdir -p "$APP_DIR/init.d"
    mkdir -p "$APP_DIR/lists"
    mkdir -p "$APP_DIR/config/strategies/user"
    if [ -f "$TMP_DIR/settings.json.bak" ]; then
        cp "$TMP_DIR/settings.json.bak" "$CONFIG_DIR/settings.json"
        ok "Конфигурация восстановлена"
    fi
    if [ -d "$TMP_DIR/user_strategies_bak" ]; then
        cp -r "$TMP_DIR/user_strategies_bak/"* "$APP_DIR/config/strategies/user/" 2>/dev/null || true
        ok "Пользовательские стратегии восстановлены"
    fi
    find "$APP_DIR" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
    chmod 755 "$APP_DIR/app.py"
    ok "Файлы установлены"
}
install_initd() {
    info "Установка init-скрипта..."
    mkdir -p "$INITD_DIR"
    if [ "$ENV_TYPE" = "openwrt" ]; then
        cat > "$INITD_SCRIPT" << 'INITEOF'
START=99
STOP=10
USE_PROCD=1
start_service() {
    local APP_DIR="/usr/share/zapret-gui"
    local CONFIG_DIR="/etc/zapret-gui"
    local HOST="0.0.0.0"
    local PORT="8080"
    [ -f "$CONFIG_DIR/server.conf" ] && . "$CONFIG_DIR/server.conf"
    HOST="${GUI_HOST:-$HOST}"
    PORT="${GUI_PORT:-$PORT}"
    mkdir -p "$CONFIG_DIR" /tmp/zapret-gui 2>/dev/null
    procd_open_instance
    procd_set_param command python3 "$APP_DIR/app.py" --host "$HOST" --port "$PORT" --config "$CONFIG_DIR"
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
    else
        cat > "$INITD_SCRIPT" << 'INITEOF'
APP_DIR="/opt/share/zapret-gui"
CONFIG_DIR="/opt/etc/zapret-gui"
PID_FILE="/opt/var/run/zapret-gui.pid"
LOG_FILE="/tmp/zapret-gui-server.log"
GUI_HOST="0.0.0.0"
GUI_PORT="8080"
[ -f "$CONFIG_DIR/server.conf" ] && . "$CONFIG_DIR/server.conf"
start() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "zapret-gui already running (PID $PID)"
            return 0
        fi
        rm -f "$PID_FILE"
    fi
    mkdir -p "$(dirname $PID_FILE)" /tmp/zapret-gui 2>/dev/null
    echo "Starting zapret-gui on $GUI_HOST:$GUI_PORT..."
    cd "$APP_DIR"
    python3 app.py --host "$GUI_HOST" --port "$GUI_PORT" --config "$CONFIG_DIR" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 2
    if kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
        echo "zapret-gui started (PID $(cat $PID_FILE))"
    else
        echo "FAILED to start zapret-gui"
        rm -f "$PID_FILE"
        return 1
    fi
}
stop() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        echo "Stopping zapret-gui (PID $PID)..."
        kill "$PID" 2>/dev/null
        sleep 2
        kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
        rm -f "$PID_FILE"
        echo "zapret-gui stopped"
    else
        echo "zapret-gui not running"
    fi
}
case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
            echo "zapret-gui running (PID $(cat $PID_FILE))"
        else
            echo "zapret-gui not running"
        fi
        ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
INITEOF
    fi
    chmod 755 "$INITD_SCRIPT"
    ok "Init-скрипт: $INITD_SCRIPT"
    if [ ! -f "$CONFIG_DIR/server.conf" ]; then
        cat > "$CONFIG_DIR/server.conf" << CONFEOF
CONFEOF
        ok "Конфиг: $CONFIG_DIR/server.conf"
    fi
}
do_uninstall() {
    detect_env
    printf "${YELLOW}Удалить Zapret Web-GUI?${NC}\n"
    printf "  Приложение: $APP_DIR\n"
    printf "  Конфиг:     $CONFIG_DIR\n"
    printf "  Init:       $INITD_SCRIPT\n"
    printf "\n"
    printf "Конфигурация будет ${GREEN}сохранена${NC}.\n"
    printf "Продолжить? [y/N] "
    read -r answer
    [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "Отменено"; exit 0; }
    echo ""
    # Остановить
    if [ -x "$INITD_SCRIPT" ]; then
        info "Остановка..."
        "$INITD_SCRIPT" stop 2>/dev/null || true
        if [ "$ENV_TYPE" = "openwrt" ]; then
            "$INITD_SCRIPT" disable 2>/dev/null || true
        fi
    fi
    rm -f "$INITD_SCRIPT"
    ok "Init-скрипт удалён"
    if [ -d "$APP_DIR" ]; then
        rm -rf "$APP_DIR"
        ok "Приложение удалено: $APP_DIR"
    fi
    rm -f "$PID_FILE" 2>/dev/null || true
    echo ""
    ok "Zapret Web-GUI удалён"
    info "Конфигурация сохранена: $CONFIG_DIR"
    info "Для полного удаления: rm -rf $CONFIG_DIR"
    echo ""
}
# ── Главная ───────────────────────────────────────────────────
main() {
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Zapret Web-GUI — Установщик v$VERSION"
    echo "═══════════════════════════════════════════════════"
    echo ""
    detect_env
    info "Окружение: $ENV_TYPE"
    info "Установка в: $APP_DIR"
    echo ""
    detect_downloader
    check_deps
    echo ""
    install_from_github
    echo ""
    install_initd
    echo ""
    echo "═══════════════════════════════════════════════════"
    ok "Zapret Web-GUI v$VERSION установлен!"
    echo ""
    echo "  Запуск:    $INITD_SCRIPT start"
    echo "  Остановка: $INITD_SCRIPT stop"
    echo "  Статус:    $INITD_SCRIPT status"
    echo ""
    echo "  Веб-интерфейс: http://<IP роутера>:$GUI_PORT"
    echo ""
    # Предлагаем запустить
    printf "  Запустить сейчас? [Y/n] "
    read -r answer
    if [ "$answer" != "n" ] && [ "$answer" != "N" ]; then
        "$INITD_SCRIPT" start
    fi
    echo ""
}
# ── Парсинг аргументов ────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall|uninstall)
            do_uninstall
            exit 0
            ;;
        --update|update)
            main
            exit 0
            ;;
        --port)
            shift; GUI_PORT="$1"
            ;;
        --host)
            shift; GUI_HOST="$1"
            ;;
        --branch)
            shift; BRANCH="$1"
            ;;
        --help|-h)
            echo "Использование: $0 [опции]"
            echo ""
            echo "  --port PORT     Порт веб-интерфейса (по умолчанию: 8080)"
            echo "  --host HOST     Адрес привязки (по умолчанию: 0.0.0.0)"
            echo "  --branch NAME   Ветка GitHub (по умолчанию: main)"
            echo "  --update        Обновить до последней версии"
            echo "  --uninstall     Удалить"
            echo "  --help          Эта справка"
            echo ""
            exit 0
            ;;
        *)
            error "Неизвестная опция: $1"
            error "Используйте --help для справки"
            exit 1
            ;;
    esac
    shift
done
main
