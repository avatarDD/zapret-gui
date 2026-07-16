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
VERSION="0.22.27"

GUI_PORT="${ZAPRET_GUI_PORT:-8080}"
GUI_HOST="${ZAPRET_GUI_HOST:-0.0.0.0}"

# Пользователь явно задал host/port? (через окружение или флаги)
GUI_PORT_EXPLICIT=0
GUI_HOST_EXPLICIT=0
[ -n "$ZAPRET_GUI_PORT" ] && GUI_PORT_EXPLICIT=1
[ -n "$ZAPRET_GUI_HOST" ] && GUI_HOST_EXPLICIT=1

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
        # OpenWrt 24.10+ перешёл с opkg на apk. Берём то, что реально есть:
        # на 23.05 и раньше — opkg, на 24.10+/snapshot — apk.
        if command -v opkg >/dev/null 2>&1; then
            PKG_CMD="opkg"
        elif command -v apk >/dev/null 2>&1; then
            PKG_CMD="apk"
        else
            PKG_CMD="opkg"
        fi
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

# Чтение ответа пользователя.
# При запуске через `wget -O - URL | sh` stdin занят пайпом и `read`
# мгновенно возвращает EOF, не дожидаясь ответа. Берём ввод напрямую
# с управляющего терминала (/dev/tty), если он доступен; иначе
# возвращаем значение по умолчанию из $2.
prompt_read() {
    __prompt_default="${2:-}"
    if [ -r /dev/tty ]; then
        # shellcheck disable=SC2229
        read -r "$1" </dev/tty
    else
        eval "$1=\"\$__prompt_default\""
    fi
}

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
        if [ "$PKG_CMD" = "apk" ]; then
            error "Установите: apk add curl"
        else
            error "Установите: ${PKG_CMD:-opkg} install curl"
        fi
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

# ── Проверка зависимостей ─────────────────────────────────────

OPKG_INSTALLED_LIST=""

# `opkg/apk update` дорого — выполняем один раз за запуск (шарим между
# ensure_python_stdlib и ensure_bottle_deps).
_STDLIB_UPDATED=0

# opkg/apk-пакет Entware/OpenWrt для stdlib-модуля Python. У большинства
# модулей имя пакета — `python3-<модуль>`, но у ряда C-расширений оно НЕ
# совпадает: `unicodedata` → python3-codecs, `ssl`/`hashlib` → python3-openssl.
# Карта проверена по фиду bin.entware.net (совпадает с OpenWrt). Имя модуля
# может быть с точкой (`urllib.parse`) — берём верхний уровень.
_py_stdlib_pkg() {
    case "${1%%.*}" in
        ssl|_ssl|hashlib|_hashlib)     echo "python3-openssl" ;;
        unicodedata|_multibytecodec)   echo "python3-codecs" ;;
        decimal|_decimal)              echo "python3-decimal" ;;
        ctypes|_ctypes)                echo "python3-ctypes" ;;
        lzma|_lzma)                    echo "python3-lzma" ;;
        sqlite3|_sqlite3)              echo "python3-sqlite3" ;;
        curses|_curses)                echo "python3-ncurses" ;;
        readline)                      echo "python3-readline" ;;
        *)                             echo "python3-${1%%.*}" ;;
    esac
}

# Записать имя установленного пакета для симметричного удаления при uninstall.
_record_installed_pkg() {
    [ -n "$CONFIG_DIR" ] || return 0
    mkdir -p "$CONFIG_DIR" 2>/dev/null
    echo "$1" >> "$CONFIG_DIR/opkg_installed.list"
}

_opkg_install_pkg() {
    local pkg="$1"
    # apk использует `apk add`, opkg — `opkg install`.
    if [ "$PKG_CMD" = "apk" ]; then
        $PKG_CMD add "$pkg" || { error "Не удалось установить $pkg"; exit 1; }
    else
        $PKG_CMD install "$pkg" || { error "Не удалось установить $pkg"; exit 1; }
    fi
    # Записываем пакет в список для последующего удаления
    if [ -n "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR" 2>/dev/null
        echo "$pkg" >> "$CONFIG_DIR/opkg_installed.list"
    fi
}

# На Entware/OpenWrt интерпретатор Python разбит на пакеты: `python3-light`
# содержит только ядро, а submodule'ы стандартной библиотеки (`urllib`,
# `ssl`, ...) поставляются отдельными пакетами `python3-*`. Если пользователь
# поставил лишь `python3-light`, GUI падает при старте с
# `ModuleNotFoundError: No module named 'urllib'` (issue #231): и импорт
# ассетов, и сам веб-сервер тянут urllib/ssl уже на этапе загрузки модулей.
# Проверяем наличие критичных модулей и доставляем недостающие пакеты.
ensure_python_stdlib() {
    # Актуально только там, где Python разбит на submodule-пакеты.
    [ "$PKG_CMD" = "opkg" ] || [ "$PKG_CMD" = "apk" ] || return 0

    # module:package — имена пакетов в фидах opkg (Entware/OpenWrt≤23.05)
    # и apk (OpenWrt 24.10+) совпадают.
    #   urllib → python3-urllib   (загрузки, подписки, обновление каталогов)
    #   ssl    → python3-openssl  (HTTPS: без него не стартует download_transport)
    _PY_STDLIB_PAIRS="urllib:python3-urllib ssl:python3-openssl"

    local missing="" pair mod pkg
    for pair in $_PY_STDLIB_PAIRS; do
        mod="${pair%%:*}"
        pkg="${pair##*:}"
        if python3 -c "import $mod" >/dev/null 2>&1; then
            ok "python3 stdlib: $mod"
        else
            info "  Python-модуль '$mod' отсутствует → устанавливаем $pkg"
            [ "$_STDLIB_UPDATED" = "0" ] && { $PKG_CMD update 2>/dev/null || true; _STDLIB_UPDATED=1; }
            if [ "$PKG_CMD" = "apk" ]; then
                $PKG_CMD add "$pkg" 2>/dev/null || warn "  Не удалось установить $pkg"
            else
                $PKG_CMD install "$pkg" 2>/dev/null || warn "  Не удалось установить $pkg"
            fi
            _record_installed_pkg "$pkg"
            python3 -c "import $mod" >/dev/null 2>&1 && ok "python3 stdlib: $mod" \
                || missing="$missing $mod:$pkg"
        fi
    done

    # Без urllib/ssl веб-интерфейс не поднимется — предупреждаем явно.
    if [ -n "$missing" ]; then
        local _verb="install"; [ "$PKG_CMD" = "apk" ] && _verb="add"
        warn "Не удалось обеспечить модули Python:$(echo "$missing" | sed 's/:[A-Za-z0-9._-]*//g')"
        warn "Веб-интерфейс не запустится без них. Установите вручную:"
        for pair in $missing; do
            warn "  $PKG_CMD $_verb ${pair##*:}"
        done
    fi
}

# Наличия файла vendor/bottle.py НЕ достаточно: на Entware/OpenWrt Python
# разбит на пакеты, и bottle тянет submodule'ы (`unicodedata`, `email`, ...),
# которых в python3-light может не быть. Тогда файл на месте, но `import
# bottle` падает с ModuleNotFoundError по ЧУЖОМУ модулю, и сервер не
# стартует — а сообщение выглядит как «Bottle не найден» (issue #231).
# Поэтому реально ИМПОРТИРУЕМ встроенный bottle и доставляем то, чего не
# хватает, по имени отсутствующего модуля.
_bottle_missing_module() {
    # Печатает имя недостающего модуля (или пусто, если bottle импортируется).
    PYTHONPATH="$1" python3 - <<'PY' 2>/dev/null
try:
    import bottle  # noqa: F401
except ModuleNotFoundError as e:
    print(e.name or "")
except ImportError as e:
    print(getattr(e, "name", "") or "")
PY
}

ensure_bottle_deps() {
    local vendor_dir="$1"
    [ -f "$vendor_dir/bottle.py" ] || return 0
    # Системный bottle имеет приоритет — если он импортируется, vendored не нужен.
    python3 -c "import bottle" >/dev/null 2>&1 && return 0

    # На обычном Linux stdlib цельная — доставлять нечего, только предупредим.
    if [ "$PKG_CMD" != "opkg" ] && [ "$PKG_CMD" != "apk" ]; then
        [ -z "$(_bottle_missing_module "$vendor_dir")" ] \
            || warn "Встроенный bottle не импортируется — проверьте установку Python"
        return 0
    fi

    local attempt=0 mod pkg prev_mod=""
    while [ "$attempt" -lt 12 ]; do
        attempt=$((attempt + 1))
        mod="$(_bottle_missing_module "$vendor_dir")"
        [ -z "$mod" ] && { ok "python3: встроенный bottle импортируется"; return 0; }
        # 'bottle' здесь не появится (файл проверен выше), но на всякий случай.
        [ "$mod" = "bottle" ] && return 0
        # Тот же модуль после установки — пакет не помог (неверный фид/имя):
        # выходим, чтобы не ставить одно и то же по кругу.
        [ "$mod" = "$prev_mod" ] && break
        prev_mod="$mod"

        pkg="$(_py_stdlib_pkg "$mod")"
        info "  Bottle требует модуль '$mod' → устанавливаем $pkg"
        [ "$_STDLIB_UPDATED" = "0" ] && { $PKG_CMD update 2>/dev/null || true; _STDLIB_UPDATED=1; }
        if [ "$PKG_CMD" = "apk" ]; then
            $PKG_CMD add "$pkg" 2>/dev/null || { warn "  Не удалось установить $pkg"; break; }
        else
            $PKG_CMD install "$pkg" 2>/dev/null || { warn "  Не удалось установить $pkg"; break; }
        fi
        _record_installed_pkg "$pkg"
    done

    # Финальная проверка — если всё ещё не импортируется, явно скажем что и как.
    mod="$(_bottle_missing_module "$vendor_dir")"
    if [ -n "$mod" ] && [ "$mod" != "bottle" ]; then
        local _verb="install"; [ "$PKG_CMD" = "apk" ] && _verb="add"
        warn "Встроенный bottle не импортируется: не хватает модуля Python '$mod'."
        warn "Веб-интерфейс не запустится. Доустановите: $PKG_CMD $_verb $(_py_stdlib_pkg "$mod")"
    fi
}

check_deps() {
    info "Проверка зависимостей..."

    # Python3 — единственная внешняя зависимость.
    if command -v python3 >/dev/null 2>&1; then
        PY_VER=$(python3 --version 2>&1)
        ok "python3: $PY_VER"
    else
        warn "python3 не найден"
        case "$PKG_CMD" in
            opkg|apk)
                # Entware / OpenWrt (opkg на 23.05 и раньше, apk на 24.10+)
                $PKG_CMD update 2>/dev/null || true
                info "  Устанавливаем python3-light..."
                _opkg_install_pkg python3-light
                ;;
            apt-get|apt)
                # Debian / Ubuntu
                $SUDO $PKG_CMD update -qq 2>/dev/null || true
                info "  Устанавливаем python3..."
                $SUDO $PKG_CMD install -y python3 || { error "Не удалось установить python3"; exit 1; }
                ;;
            dnf|yum)
                # Fedora / RHEL / CentOS
                $PKG_CMD install -y python3 || { error "Не удалось установить python3"; exit 1; }
                ;;
            pacman)
                # Arch Linux
                $PKG_CMD -S --noconfirm python || { error "Не удалось установить python"; exit 1; }
                ;;
            *)
                error "python3 не найден. Установите вручную."
                exit 1
                ;;
        esac
        ok "python3 установлен"
    fi

    # Bottle встроен в проект (vendor/bottle.py) — отдельная установка
    # из сети (opkg/pip/GitHub) больше не нужна. Если в системе уже
    # стоит python3-bottle — приложение использует его (приоритет у
    # системного), иначе — встроенный.
    if python3 -c "import bottle" 2>/dev/null; then
        BOTTLE_VER=$(python3 -c "import bottle; print(bottle.__version__)" 2>/dev/null)
        ok "bottle: системный $BOTTLE_VER"
    else
        ok "bottle: будет использован встроенный (vendor/bottle.py)"
    fi

    # Критичные submodule'ы stdlib (urllib/ssl) — на Entware/OpenWrt они
    # НЕ входят в python3-light и ставятся отдельными пакетами (issue #231).
    ensure_python_stdlib
}

# ── Установка из GitHub ───────────────────────────────────────

# Если install.sh запущен из клона репо — используем локальный
# источник вместо скачивания архива из GitHub. Это важно для
# разработки и тестирования веток, которые ещё не слиты в main.
detect_local_source() {
    local script_dir
    script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    [ -z "$script_dir" ] && return 1
    # Обязательные маркеры репо zapret-gui
    if [ -f "$script_dir/app.py" ] \
       && [ -d "$script_dir/core" ] \
       && [ -d "$script_dir/web" ]; then
        LOCAL_SRC_DIR="$script_dir"
        return 0
    fi
    return 1
}

# Выбрать базовый каталог для временной распаковки. На OpenWrt /tmp —
# это tmpfs (ОЗУ) и его часто не хватает (issue #98). Предпочитаем
# ZAPRET_GUI_TMPDIR, затем каталог рядом с местом установки (постоянный
# носитель), затем /tmp.
_tmp_base() {
    if [ -n "$ZAPRET_GUI_TMPDIR" ] && mkdir -p "$ZAPRET_GUI_TMPDIR" 2>/dev/null; then
        echo "$ZAPRET_GUI_TMPDIR"; return
    fi
    local parent
    parent=$(dirname "$APP_DIR")
    if [ -n "$parent" ] && mkdir -p "$parent/.zapret-gui-tmp" 2>/dev/null; then
        echo "$parent/.zapret-gui-tmp"; return
    fi
    echo "/tmp"
}

install_from_github() {
    local TMP_DIR="$(_tmp_base)/zapret-gui-install-$$"
    mkdir -p "$TMP_DIR"
    trap "rm -rf '$TMP_DIR'" EXIT

    local src_dir=""
    if [ -n "$FORCE_GITHUB" ]; then
        :  # пользователь явно просил скачивать из GitHub
    elif detect_local_source; then
        info "Локальный источник: $LOCAL_SRC_DIR"
        src_dir="$LOCAL_SRC_DIR"
    fi

    if [ -z "$src_dir" ]; then
        info "Загрузка zapret-gui из GitHub ($BRANCH)..."
        local ARCHIVE="$TMP_DIR/zapret-gui.tar.gz"

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
        src_dir=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
        if [ -z "$src_dir" ]; then
            error "Не найдена директория проекта в архиве"
            exit 1
        fi

        ok "Распакован: $(basename $src_dir)"
    fi

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

    # Копируем основные файлы (tests — для самодиагностики:
    # она умеет гонять юнит-тесты прямо на устройстве)
    $SUDO cp "$src_dir/app.py" "$APP_DIR/"
    for dir in api core config web catalogs data import vendor tests; do
        if [ -d "$src_dir/$dir" ]; then
            $SUDO rm -rf "$APP_DIR/$dir"
            $SUDO cp -r "$src_dir/$dir" "$APP_DIR/"
        fi
    done

    # Убеждаемся, что встроенный bottle реально импортируется на этой
    # системе (на Entware/OpenWrt доставляем недостающие python3-*-пакеты).
    # Файл vendor/bottle.py только что скопирован — проверяем именно его.
    ensure_bottle_deps "$APP_DIR/vendor"

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

    # CLI-обёртка `zapret-gui` в PATH (status/nfqws/strategy/singbox/mihomo).
    case "$APP_DIR" in
        /opt/*) BIN_DIR="/opt/bin" ;;
        *)      BIN_DIR="/usr/bin" ;;
    esac
    $SUDO mkdir -p "$BIN_DIR"
    $SUDO sh -c "cat > '$BIN_DIR/zapret-gui'" <<EOF
#!/bin/sh
# zapret-gui — консольная обёртка над app.py (создана install.sh).
APP="$APP_DIR/app.py"
CFG="$CONFIG_DIR"
if [ "\$#" -eq 0 ] || [ "\$1" = "-h" ] || [ "\$1" = "--help" ]; then
    echo "Usage: zapret-gui {status|nfqws|strategy|singbox|mihomo} [args]"
    [ "\$#" -eq 0 ] && exit 1 || exit 0
fi
exec python3 "\$APP" --config "\$CFG" "\$@"
EOF
    $SUDO chmod 755 "$BIN_DIR/zapret-gui"
    ok "CLI-команда установлена: $BIN_DIR/zapret-gui"

    # Импорт bundled-ассетов (blobs/lua/lists → /opt/zapret2/) и
    # bundled-стратегий (merge в catalogs/). Базовая установка
    # zapret2 даёт только бинарник — всё остальное доставляет GUI.
    if [ ! -d "$APP_DIR/import" ]; then
        warn "Директория import/ отсутствует в $APP_DIR — пропускаем импорт"
        warn "  (возможно, сборка из устаревшей ветки без bundled-ассетов)"
    elif [ ! -f "$APP_DIR/core/asset_importer.py" ]; then
        warn "core/asset_importer.py отсутствует — пропускаем импорт"
        warn "  (возможно, сборка из устаревшей ветки без asset_importer)"
    else
        info "Импорт blobs/lua/lists/стратегий..."
        local IMP_LOG="/tmp/zapret-gui-import-$$.log"
        if $SUDO env PYTHONPATH="$APP_DIR" python3 \
                -m core.asset_importer --only all \
                >"$IMP_LOG" 2>&1; then
            ok "Ассеты импортированы"
            # Показать краткую сводку, если asset_importer что-то написал
            if [ -s "$IMP_LOG" ]; then
                grep -E "(asset-importer|скопирован|импорт)" "$IMP_LOG" \
                    2>/dev/null | head -3 | while read -r line; do
                        info "  $line"
                    done
            fi
        else
            warn "Ошибка импорта ассетов (см. $IMP_LOG):"
            tail -5 "$IMP_LOG" 2>/dev/null | while read -r line; do
                warn "  $line"
            done
        fi
    fi

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
        # ВАЖНО: НЕ инлайним --host/--port в ExecStart. App.py читает
        # их из settings.json. Иначе изменение порта/хоста через UI
        # игнорируется — systemd-юнит подсовывает старые значения.
        cat > "$TMP_INIT" << UNITEOF
[Unit]
Description=Zapret Web-GUI
After=network.target

[Service]
Type=simple
ExecStart=$(command -v python3) $APP_DIR/app.py --config $CONFIG_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
        $SUDO cp "$TMP_INIT" "$UNIT_FILE"
        $SUDO chmod 644 "$UNIT_FILE"
        rm -f "$TMP_INIT"

        # Записываем host/port в settings.json. Если файла ещё нет —
        # создаём с переданными (или дефолтными) значениями. Если файл
        # существует и пользователь НЕ передавал --port/--host явно —
        # не трогаем сохранённые значения (могли быть изменены через UI).
        $SUDO mkdir -p "$CONFIG_DIR"
        $SUDO env GUI_HOST="$GUI_HOST" GUI_PORT="$GUI_PORT" \
                  GUI_HOST_EXPLICIT="$GUI_HOST_EXPLICIT" \
                  GUI_PORT_EXPLICIT="$GUI_PORT_EXPLICIT" \
                  python3 - "$CONFIG_DIR/settings.json" <<'PYEOF' || warn "Не удалось записать host/port в settings.json"
import json, os, sys
path = sys.argv[1]
host = os.environ.get("GUI_HOST", "0.0.0.0")
port = int(os.environ.get("GUI_PORT", "8080"))
host_explicit = os.environ.get("GUI_HOST_EXPLICIT") == "1"
port_explicit = os.environ.get("GUI_PORT_EXPLICIT") == "1"

existed = os.path.isfile(path)
data = {}
if existed:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        data = {}

gui = data.get("gui") if isinstance(data.get("gui"), dict) else {}
if not existed:
    gui.setdefault("host", host)
    gui.setdefault("port", port)
if host_explicit:
    gui["host"] = host
if port_explicit:
    gui["port"] = port
data["gui"] = gui

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
PYEOF

        $SUDO systemctl daemon-reload
        $SUDO systemctl enable zapret-gui 2>/dev/null || true
        ok "Systemd unit: $UNIT_FILE"

        # Файл конфига (для совместимости со скриптами/init.d)
        if [ ! -f "$CONFIG_DIR/server.conf" ]; then
            local TMP_CONF="/tmp/zapret-gui-conf-$$"
            cat > "$TMP_CONF" << CONFEOF
# Настройки веб-сервера Zapret Web-GUI
# Эти значения НЕ используются systemd-юнитом —
# host/port читаются из settings.json (управляется через UI).
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
        # Показываем причину падения — иначе пользователь видит только
        # «FAILED» без подсказки (напр. ModuleNotFoundError на Entware).
        if [ -s "$LOG_FILE" ]; then
            echo "--- последние строки $LOG_FILE ---"
            tail -n 15 "$LOG_FILE"
            echo "----------------------------------"
        fi
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
    prompt_read answer "n"
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

    # Удалить пакеты, установленные через пакетный менеджер (opkg/apk)
    local opkg_list="$CONFIG_DIR/opkg_installed.list"
    if { [ "$PKG_CMD" = "opkg" ] || [ "$PKG_CMD" = "apk" ]; } && [ -f "$opkg_list" ]; then
        # apk удаляет через `apk del`, opkg — `opkg remove`.
        local _rmverb="remove"
        [ "$PKG_CMD" = "apk" ] && _rmverb="del"
        info "Удаление пакетов, установленных через $PKG_CMD..."
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            info "  $PKG_CMD $_rmverb $pkg"
            $PKG_CMD $_rmverb "$pkg" 2>/dev/null && ok "  Удалён: $pkg" || warn "  Не удалось удалить: $pkg"
        done < "$opkg_list"
        rm -f "$opkg_list"
    fi

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

    # Предлагаем запустить.
    # При запуске через `wget -O - URL | sh` stdin занят пайпом — берём
    # ответ с /dev/tty, иначе автоматически запускаем (значение по умолчанию).
    printf "  Запустить сейчас? [Y/n] "
    prompt_read answer "y"
    if [ -r /dev/tty ]; then
        echo ""
    else
        echo "y (нет терминала — автозапуск)"
    fi
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
            shift; GUI_PORT="$1"; GUI_PORT_EXPLICIT=1
            ;;
        --host)
            shift; GUI_HOST="$1"; GUI_HOST_EXPLICIT=1
            ;;
        --branch)
            shift; BRANCH="$1"
            ;;
        --force-github)
            FORCE_GITHUB=1
            ;;
        --help|-h)
            echo "Использование: $0 [опции]"
            echo ""
            echo "  --port PORT       Порт веб-интерфейса (по умолчанию: 8080)"
            echo "  --host HOST       Адрес привязки (по умолчанию: 0.0.0.0)"
            echo "  --branch NAME     Ветка GitHub (по умолчанию: main)"
            echo "  --force-github    Скачать с GitHub, даже если запуск из клона"
            echo "  --update          Обновить до последней версии"
            echo "  --uninstall       Удалить"
            echo "  --help            Эта справка"
            echo ""
            echo "Если install.sh запущен из клона репо (с app.py+core+web),"
            echo "по умолчанию используется локальный источник, а не GitHub."
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
