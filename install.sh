#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# install.sh — Установка Zapret Web-GUI без пакетного менеджера
# ═══════════════════════════════════════════════════════════════
#
# Поддержка: Entware (Keenetic, ASUS, etc.), OpenWrt
#
# Использование:
#   chmod +x install.sh && ./install.sh
#   ./install.sh --port 8080 --host 0.0.0.0
#   ./install.sh --uninstall
#   ./install.sh --update
#
# Переменные окружения:
#   ZAPRET_GUI_PORT=8080     — порт веб-интерфейса
#   ZAPRET_GUI_HOST=0.0.0.0  — адрес привязки
#   ZAPRET_GUI_BRANCH=main   — ветка GitHub
#
# ═══════════════════════════════════════════════════════════════

set -e

# ── Настройки по умолчанию ────────────────────────────────────

REPO_URL="https://github.com/avatarDD/zapret-gui"
BRANCH="${ZAPRET_GUI_BRANCH:-main}"
VERSION="0.14.0"

GUI_PORT="${ZAPRET_GUI_PORT:-8080}"
GUI_HOST="${ZAPRET_GUI_HOST:-0.0.0.0}"

# Автоопределение окружения
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
        # Определяем пакетный менеджер для generic Linux
        if command -v apt-get >/dev/null 2>&1; then
            PKG_CMD="apt-get"
        elif command -v apt >/dev/null 2>&1; then
            PKG_CMD="apt"
        elif command -v dnf >/dev/null 2>&1; then
            PKG_CMD="dnf"
        elif command -v yum >/dev/null 2>&1; then
            PKG_CMD="yum"
        elif command -v pacman >/dev/null 2>&1; then
            PKG_CMD="pacman"
        else
            PKG_CMD=""
        fi
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

# ── Определение sudo ─────────────────────────────────────────

# Если не root — используем sudo для системных команд
if [ "$(id -u)" = "0" ]; then
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        SUDO=""
        warn "Запуск не от root и sudo не найден — установка системных пакетов может не работать"
    fi
fi

# ── Утилиты загрузки ──────────────────────────────────────────

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

# ── Прямая установка bottle (fallback) ────────────────────────

_install_bottle_direct() {
    # Bottle — один файл. Скачиваем напрямую если pip не работает.
    info "  Прямая загрузка bottle.py..."

    local BOTTLE_URL="https://raw.githubusercontent.com/bottlepy/bottle/master/bottle.py"

    # Предпочитаем user site-packages (не требует root)
    local SITE_PACKAGES=""
    SITE_PACKAGES=$(python3 -c "import site; print(site.getusersitepackages())" 2>/dev/null)

    # Fallback на системный
    if [ -z "$SITE_PACKAGES" ]; then
        SITE_PACKAGES=$(python3 -c "import site; ps=site.getsitepackages(); print(ps[0] if ps else '')" 2>/dev/null)
    fi

    if [ -z "$SITE_PACKAGES" ]; then
        error "Не удалось определить site-packages"
        return 1
    fi

    mkdir -p "$SITE_PACKAGES" 2>/dev/null
    if [ ! -w "$SITE_PACKAGES" ]; then
        # Нет прав — пробуем через sudo
        if command -v sudo >/dev/null 2>&1; then
            sudo mkdir -p "$SITE_PACKAGES" 2>/dev/null
        else
            error "Нет прав на запись в $SITE_PACKAGES"
            return 1
        fi
    fi

    local DEST="$SITE_PACKAGES/bottle.py"
    if download "$BOTTLE_URL" "$DEST" 2>/dev/null; then
        :
    elif command -v sudo >/dev/null 2>&1; then
        # Скачиваем во /tmp, потом копируем через sudo
        local TMP_BOTTLE="/tmp/bottle_$$.py"
        if download "$BOTTLE_URL" "$TMP_BOTTLE"; then
            sudo cp "$TMP_BOTTLE" "$DEST"
            rm -f "$TMP_BOTTLE"
        else
            return 1
        fi
    else
        return 1
    fi

    # Проверяем
    if python3 -c "import bottle" 2>/dev/null; then
        ok "bottle.py установлен в $SITE_PACKAGES"
        return 0
    fi

    rm -f "$DEST" 2>/dev/null
    return 1
}

# ── Проверка зависимостей ─────────────────────────────────────

check_deps() {
    info "Проверка зависимостей..."
    local need_python=false
    local need_bottle=false

    # Python3
    if command -v python3 >/dev/null 2>&1; then
        PY_VER=$(python3 --version 2>&1)
        ok "python3: $PY_VER"
    else
        need_python=true
        warn "python3 не найден"
    fi

    # Bottle
    if python3 -c "import bottle" 2>/dev/null; then
        BOTTLE_VER=$(python3 -c "import bottle; print(bottle.__version__)" 2>/dev/null)
        ok "bottle: $BOTTLE_VER"
    else
        need_bottle=true
        warn "python3-bottle не найден"
    fi

    # Если всё есть — выходим
    if ! $need_python && ! $need_bottle; then
        return 0
    fi

    # Устанавливаем недостающее
    case "$PKG_CMD" in
        opkg)
            # Entware / OpenWrt — python3-bottle отсутствует в стандартных репозиториях
            $PKG_CMD update 2>/dev/null || true
            if $need_python; then
                info "  Устанавливаем python3-light..."
                $PKG_CMD install python3-light || { error "Не удалось установить python3-light"; exit 1; }
            fi
            if $need_bottle; then
                info "  Устанавливаем bottle через pip..."
                if python3 -m pip install bottle 2>/dev/null; then
                    ok "bottle установлен через pip"
                else
                    info "  pip не сработал, скачиваем bottle.py напрямую..."
                    _install_bottle_direct || {
                        error "Не удалось установить bottle"
                        error "Установите вручную: python3 -m pip install bottle"
                        exit 1
                    }
                fi
            fi
            ok "Зависимости установлены"
            ;;
        apt-get|apt)
            # Debian / Ubuntu
            $SUDO $PKG_CMD update -qq 2>/dev/null || true
            if $need_python; then
                info "  Устанавливаем python3..."
                $SUDO $PKG_CMD install -y python3 || { error "Не удалось установить python3"; exit 1; }
            fi
            if $need_bottle; then
                info "  Устанавливаем bottle..."
                # Способ 1: системный пакет
                if $SUDO $PKG_CMD install -y python3-bottle 2>/dev/null; then
                    ok "bottle установлен через $PKG_CMD"
                else
                    # Способ 2: pip --user (не требует root)
                    info "  Системный пакет не найден, устанавливаем через pip..."
                    if ! python3 -m pip --version >/dev/null 2>&1; then
                        info "  Устанавливаем python3-pip..."
                        $SUDO $PKG_CMD install -y python3-pip 2>/dev/null || true
                    fi
                    if python3 -m pip install --user bottle 2>/dev/null; then
                        ok "bottle установлен через pip (--user)"
                    elif python3 -m pip install bottle --break-system-packages 2>/dev/null; then
                        ok "bottle установлен через pip"
                    elif python3 -m pip install bottle 2>/dev/null; then
                        ok "bottle установлен через pip"
                    else
                        info "  pip не сработал, скачиваем bottle.py напрямую..."
                        _install_bottle_direct || {
                            error "Не удалось установить bottle"
                            error "Установите вручную: pip3 install bottle  или  sudo apt install python3-bottle"
                            exit 1
                        }
                    fi
                fi
            fi
            ok "Зависимости установлены"
            ;;
        dnf|yum)
            # Fedora / RHEL / CentOS
            if $need_python; then
                $PKG_CMD install -y python3 || { error "Не удалось установить python3"; exit 1; }
            fi
            if $need_bottle; then
                python3 -m pip install bottle 2>/dev/null || {
                    $PKG_CMD install -y python3-pip 2>/dev/null || true
                    python3 -m pip install bottle || _install_bottle_direct || {
                        error "Установите вручную: python3 -m pip install bottle"; exit 1;
                    }
                }
            fi
            ok "Зависимости установлены"
            ;;
        pacman)
            # Arch Linux
            if $need_python; then
                $PKG_CMD -S --noconfirm python || { error "Не удалось установить python"; exit 1; }
            fi
            if $need_bottle; then
                python3 -m pip install bottle 2>/dev/null || {
                    $PKG_CMD -S --noconfirm python-pip 2>/dev/null || true
                    python3 -m pip install bottle || _install_bottle_direct || {
                        error "Установите вручную: python3 -m pip install bottle"; exit 1;
                    }
                }
            fi
            ok "Зависимости установлены"
            ;;
        *)
            # Нет пакетного менеджера — пробуем pip
            if $need_python; then
                error "python3 не найден. Установите вручную."
                exit 1
            fi
            if $need_bottle; then
                info "  Устанавливаем bottle..."
                if python3 -m pip install bottle --break-system-packages 2>/dev/null; then
                    ok "bottle установлен через pip"
                elif python3 -m pip install bottle 2>/dev/null; then
                    ok "bottle установлен через pip"
                else
                    _install_bottle_direct || {
                        error "Не удалось установить bottle"
                        error "Установите вручную: python3 -m pip install bottle"
                        exit 1
                    }
                fi
            fi
            ;;
    esac
}

# ── Установка из GitHub ───────────────────────────────────────

install_from_github() {
    info "Загрузка zapret-gui из GitHub ($BRANCH)..."

    local TMP_DIR="/tmp/zapret-gui-install-$$"
    local ARCHIVE="$TMP_DIR/zapret-gui.tar.gz"

    mkdir -p "$TMP_DIR"
    trap "rm -rf '$TMP_DIR'" EXIT

    # Скачиваем архив
    local archive_url="$REPO_URL/archive/refs/heads/$BRANCH.tar.gz"
    download "$archive_url" "$ARCHIVE" || {
        # Пробуем альтернативный URL (для тега)
        archive_url="$REPO_URL/archive/refs/tags/v$VERSION.tar.gz"
        info "Пробуем тег v$VERSION..."
        download "$archive_url" "$ARCHIVE" || {
            error "Не удалось скачать архив"
            exit 1
        }
    }

    ok "Архив загружен"

    # Распаковываем
    info "Распаковка..."
    cd "$TMP_DIR"
    tar xzf "$ARCHIVE" || {
        error "Не удалось распаковать архив"
        exit 1
    }

    # Находим распакованную директорию
    local src_dir=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
    if [ -z "$src_dir" ]; then
        error "Не найдена директория проекта в архиве"
        exit 1
    fi

    ok "Распакован: $(basename $src_dir)"

    # Бэкап конфигурации
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

    # Останавливаем если запущен
    if [ -f "$INITD_SCRIPT" ] && [ -x "$INITD_SCRIPT" ]; then
        info "Остановка текущего сервера..."
        $SUDO "$INITD_SCRIPT" stop 2>/dev/null || true
    fi

    # Копируем файлы
    info "Установка в $APP_DIR..."
    $SUDO mkdir -p "$APP_DIR"
    $SUDO mkdir -p "$CONFIG_DIR"

    # Копируем основные файлы
    $SUDO cp "$src_dir/app.py" "$APP_DIR/"
    for dir in api core config web catalogs data; do
        if [ -d "$src_dir/$dir" ]; then
            $SUDO rm -rf "$APP_DIR/$dir"
            $SUDO cp -r "$src_dir/$dir" "$APP_DIR/"
        fi
    done

    # Создаём рабочие директории
    $SUDO mkdir -p "$APP_DIR/init.d"
    $SUDO mkdir -p "$APP_DIR/lists"
    $SUDO mkdir -p "$APP_DIR/config/strategies/user"

    # Восстанавливаем конфигурацию из бэкапа
    if [ -f "$TMP_DIR/settings.json.bak" ]; then
        $SUDO cp "$TMP_DIR/settings.json.bak" "$CONFIG_DIR/settings.json"
        ok "Конфигурация восстановлена"
    fi
    if [ -d "$TMP_DIR/user_strategies_bak" ]; then
        $SUDO cp -r "$TMP_DIR/user_strategies_bak/"* "$APP_DIR/config/strategies/user/" 2>/dev/null || true
        ok "Пользовательские стратегии восстановлены"
    fi

    # Чистим __pycache__
    $SUDO find "$APP_DIR" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

    # Права
    $SUDO chmod 755 "$APP_DIR/app.py"

    ok "Файлы установлены"
}

# ── Init-скрипт ───────────────────────────────────────────────

install_initd() {
    info "Установка init-скрипта..."
    $SUDO mkdir -p "$INITD_DIR"

    local TMP_INIT="/tmp/zapret-gui-init-$$"

    if [ "$ENV_TYPE" = "openwrt" ]; then
        # OpenWrt — procd
        cat > "$TMP_INIT" << 'INITEOF'
#!/bin/sh /etc/rc.common
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

    elif [ "$ENV_TYPE" = "generic" ] && command -v systemctl >/dev/null 2>&1; then
        # Generic Linux с systemd
        info "Обнаружен systemd — создаём unit-файл..."
        local UNIT_FILE="/etc/systemd/system/zapret-gui.service"
        cat > "$TMP_INIT" << UNITEOF
[Unit]
Description=Zapret Web-GUI
After=network.target

[Service]
Type=simple
ExecStart=$(command -v python3) $APP_DIR/app.py --host $GUI_HOST --port $GUI_PORT --config $CONFIG_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
        $SUDO cp "$TMP_INIT" "$UNIT_FILE"
        $SUDO chmod 644 "$UNIT_FILE"
        rm -f "$TMP_INIT"
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable zapret-gui 2>/dev/null || true
        ok "Systemd unit: $UNIT_FILE"

        # Файл конфига
        if [ ! -f "$CONFIG_DIR/server.conf" ]; then
            local TMP_CONF="/tmp/zapret-gui-conf-$$"
            cat > "$TMP_CONF" << CONFEOF
# Настройки веб-сервера Zapret Web-GUI
# Раскомментируйте и измените при необходимости:
#GUI_HOST=0.0.0.0
#GUI_PORT=8080
CONFEOF
            $SUDO cp "$TMP_CONF" "$CONFIG_DIR/server.conf"
            rm -f "$TMP_CONF"
            ok "Конфиг: $CONFIG_DIR/server.conf"
        fi
        return 0

    else
        # Entware — классический init.d
        cat > "$TMP_INIT" << 'INITEOF'
#!/bin/sh
# S99zapret-gui — Zapret Web-GUI

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

    $SUDO cp "$TMP_INIT" "$INITD_SCRIPT"
    $SUDO chmod 755 "$INITD_SCRIPT"
    rm -f "$TMP_INIT"
    ok "Init-скрипт: $INITD_SCRIPT"

    # Файл переопределения настроек
    if [ ! -f "$CONFIG_DIR/server.conf" ]; then
        local TMP_CONF="/tmp/zapret-gui-conf-$$"
        cat > "$TMP_CONF" << CONFEOF
# Настройки веб-сервера Zapret Web-GUI
# Раскомментируйте и измените при необходимости:
#GUI_HOST=0.0.0.0
#GUI_PORT=8080
CONFEOF
        $SUDO cp "$TMP_CONF" "$CONFIG_DIR/server.conf"
        rm -f "$TMP_CONF"
        ok "Конфиг: $CONFIG_DIR/server.conf"
    fi
}

# ── Удаление ──────────────────────────────────────────────────

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
        $SUDO "$INITD_SCRIPT" stop 2>/dev/null || true
        if [ "$ENV_TYPE" = "openwrt" ]; then
            "$INITD_SCRIPT" disable 2>/dev/null || true
        fi
    fi

    # Удалить init-скрипт
    rm -f "$INITD_SCRIPT"
    ok "Init-скрипт удалён"

    # Удалить приложение
    if [ -d "$APP_DIR" ]; then
        rm -rf "$APP_DIR"
        ok "Приложение удалено: $APP_DIR"
    fi

    # PID файл
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
    if [ "$ENV_TYPE" = "generic" ] && command -v systemctl >/dev/null 2>&1; then
        echo "  Запуск:    systemctl start zapret-gui"
        echo "  Остановка: systemctl stop zapret-gui"
        echo "  Статус:    systemctl status zapret-gui"
    else
        echo "  Запуск:    $INITD_SCRIPT start"
        echo "  Остановка: $INITD_SCRIPT stop"
        echo "  Статус:    $INITD_SCRIPT status"
    fi
    echo ""
    echo "  Веб-интерфейс: http://<IP роутера>:$GUI_PORT"
    echo ""

    # Предлагаем запустить
    printf "  Запустить сейчас? [Y/n] "
    read -r answer
    if [ "$answer" != "n" ] && [ "$answer" != "N" ]; then
        if [ "$ENV_TYPE" = "generic" ] && command -v systemctl >/dev/null 2>&1; then
            $SUDO systemctl start zapret-gui
        else
            $SUDO "$INITD_SCRIPT" start
        fi
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
