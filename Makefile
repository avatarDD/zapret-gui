# ═══════════════════════════════════════════════════════════════
# Makefile — Сборка пакета zapret-gui для Entware/OpenWrt
# ═══════════════════════════════════════════════════════════════
#
# Использование:
#   make ipk          — собрать ipk-пакет для Entware
#   make openwrt-ipk  — собрать ipk-пакет для OpenWrt (старые, opkg)
#   make openwrt-apk  — собрать apk-пакет для нового OpenWrt (24.10+/25.x,
#                       apk-tools 3; передайте APK=apk.static при отсутствии apk)
#   make release      — создать git-тег и запустить релиз
#   make clean        — очистить артефакты сборки
#   make lint         — проверка синтаксиса Python
#   make info         — информация о пакете
#
# Требования для сборки:
#   tar, gzip, fakeroot (опционально), find, python3 (для lint)
#
# ═══════════════════════════════════════════════════════════════

PKG_NAME     := zapret-gui
PKG_VERSION  := $(shell python3 -c "exec(open('core/version.py').read()); print(GUI_VERSION)" 2>/dev/null || echo "0.0.0")
PKG_RELEASE  := 1
PKG_ARCH     := all
PKG_FULLNAME := $(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_$(PKG_ARCH)

# ── Пути установки (Entware) ─────────────────────────────────
DEST_APP     := /opt/share/$(PKG_NAME)
DEST_CONFIG  := /opt/etc/$(PKG_NAME)
DEST_INITD   := /opt/etc/init.d

# ── Директории сборки ────────────────────────────────────────
BUILD_DIR    := build
STAGING      := $(BUILD_DIR)/staging
DATA_DIR     := $(BUILD_DIR)/data
CONTROL_DIR  := $(BUILD_DIR)/control
IPK_DIR      := $(BUILD_DIR)/ipk
DIST_DIR     := dist

# ── Исходные файлы ───────────────────────────────────────────
APP_FILES    := app.py
# tests — для самодиагностики (умеет гонять юнит-тесты на устройстве)
APP_DIRS     := api core config web catalogs data import vendor tests
EXCLUDE      := --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
                --exclude='.DS_Store' --exclude='.git' --exclude='build' \
                --exclude='dist' --exclude='packaging' --exclude='Makefile' \
                --exclude='install.sh' --exclude='uninstall.sh' --exclude='.gitignore' \
                --exclude='*.md' --exclude='init.d' --exclude='lists'

# ═══════════════════════════════════════════════════════════════
# Цели
# ═══════════════════════════════════════════════════════════════

.PHONY: all ipk openwrt-ipk openwrt-apk clean _clean_build lint info help release tag \
        _prepare_apk_scripts _build_apk_openwrt

all: ipk

help:
	@echo ""
	@echo "  Zapret Web-GUI — Makefile"
	@echo "  ─────────────────────────"
	@echo "  make ipk          — собрать ipk для Entware"
	@echo "  make openwrt-ipk  — собрать ipk для OpenWrt (старые, opkg)"
	@echo "  make openwrt-apk  — собрать apk для нового OpenWrt (apk-tools 3; APK=apk.static)"
	@echo "  make release VERSION=X.Y.Z — обновить версию, создать тег и запустить релиз"
	@echo "  make clean        — очистить build/ и dist/"
	@echo "  make lint         — проверка синтаксиса Python"
	@echo "  make info         — информация о пакете"
	@echo ""

# ── Информация ────────────────────────────────────────────────
info:
	@echo "Пакет: $(PKG_NAME)"
	@echo "Версия: $(PKG_VERSION)-$(PKG_RELEASE)"
	@echo "Архитектура: $(PKG_ARCH)"
	@echo "Установка: $(DEST_APP)"
	@echo "Конфигурация: $(DEST_CONFIG)"

# ── Релиз через GitHub Actions ───────────────────────────────
# Использование: make release VERSION=0.16.0
# Обновляет core/version.py, коммитит, создаёт тег → GitHub Actions собирает релиз
release:
	@if [ -z "$(VERSION)" ]; then \
		printf "\n  Использование: make release VERSION=X.Y.Z\n  Пример:        make release VERSION=0.16.0\n\n"; \
		exit 1; \
	fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "ОШИБКА: тег v$(VERSION) уже существует!"; \
		exit 1; \
	fi
	@echo "── Обновление версии до $(VERSION) ──"
	@sed -i 's/GUI_VERSION = .*/GUI_VERSION = "$(VERSION)"/' core/version.py
	@sed -i 's/^VERSION="[^"]*"/VERSION="$(VERSION)"/' install.sh
	@git add core/version.py install.sh
	@git diff --cached --quiet \
		&& echo "Версия уже актуальна, коммит не нужен" \
		|| git commit -m "chore: bump version to v$(VERSION)"
	@git push origin HEAD
	@echo "── Создание тега v$(VERSION) ──"
	@git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@git push origin "v$(VERSION)"
	@echo ""
	@printf "✓ Готово! GitHub Actions запустит сборку и опубликует релиз.\n  https://github.com/avatarDD/zapret-gui/actions\n\n"

# ── Сборка ipk для Entware ───────────────────────────────────
_clean_build:
	@rm -rf $(BUILD_DIR)

ipk: _clean_build _prepare_data _prepare_control _build_ipk
	@echo ""
	@echo "✓ Пакет собран: $(DIST_DIR)/$(PKG_FULLNAME).ipk"
	@ls -lh $(DIST_DIR)/$(PKG_FULLNAME).ipk
	@echo ""

_prepare_data:
	@echo "── Подготовка data.tar.gz ──"
	@mkdir -p $(DATA_DIR)$(DEST_APP)
	@mkdir -p $(DATA_DIR)$(DEST_CONFIG)
	@mkdir -p $(DATA_DIR)$(DEST_INITD)
	@mkdir -p $(DATA_DIR)/opt/var/log

	# Копируем файлы приложения
	@cp $(APP_FILES) $(DATA_DIR)$(DEST_APP)/
	@for dir in $(APP_DIRS); do \
		if [ -d "$$dir" ]; then \
			cp -r $$dir $(DATA_DIR)$(DEST_APP)/ ; \
		fi \
	done

	# Удаляем __pycache__ и прочий мусор
	@find $(DATA_DIR) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find $(DATA_DIR) -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' | xargs rm -f 2>/dev/null || true

	# Init-скрипт для веб-сервера GUI
	@cp packaging/entware/S99zapret-gui $(DATA_DIR)$(DEST_INITD)/S99zapret-gui
	@chmod 755 $(DATA_DIR)$(DEST_INITD)/S99zapret-gui

	# CLI-обёртка `zapret-gui` в PATH
	@mkdir -p $(DATA_DIR)/opt/bin
	@cp packaging/entware/zapret-gui-cli $(DATA_DIR)/opt/bin/zapret-gui
	@chmod 755 $(DATA_DIR)/opt/bin/zapret-gui

	# Создаём пустые директории для runtime
	@mkdir -p $(DATA_DIR)$(DEST_APP)/init.d
	@mkdir -p $(DATA_DIR)$(DEST_APP)/lists
	@mkdir -p $(DATA_DIR)$(DEST_CONFIG)

	@echo "Подготовка data: OK"

_prepare_control:
	@echo "── Подготовка control.tar.gz ──"
	@mkdir -p $(CONTROL_DIR)
	@cp packaging/entware/control $(CONTROL_DIR)/control
	@cp packaging/entware/postinst $(CONTROL_DIR)/postinst
	@cp packaging/entware/prerm $(CONTROL_DIR)/prerm
	@cp packaging/entware/conffiles $(CONTROL_DIR)/conffiles

	# Подставляем версию
	@sed -i 's/@VERSION@/$(PKG_VERSION)-$(PKG_RELEASE)/g' $(CONTROL_DIR)/control

	# Вычисляем размер
	@SIZE=$$(du -sk $(DATA_DIR) | cut -f1); \
	 sed -i "s/@SIZE@/$$SIZE/g" $(CONTROL_DIR)/control

	@chmod 755 $(CONTROL_DIR)/postinst
	@chmod 755 $(CONTROL_DIR)/prerm
	@echo "Подготовка control: OK"

_build_ipk:
	@echo "── Сборка ipk ──"
	@mkdir -p $(IPK_DIR) $(DIST_DIR)

	# debian-binary
	@echo "2.0" > $(IPK_DIR)/debian-binary

	# control.tar.gz
	@cd $(CONTROL_DIR) && tar czf ../../$(IPK_DIR)/control.tar.gz ./*

	# data.tar.gz
	@cd $(DATA_DIR) && tar czf ../../$(IPK_DIR)/data.tar.gz ./*

	# Собираем ipk (ar-архив)
	@cd $(IPK_DIR) && tar czf ../../$(DIST_DIR)/$(PKG_FULLNAME).ipk \
		./debian-binary ./control.tar.gz ./data.tar.gz

	@echo "Сборка ipk: OK"

# ── Сборка ipk для OpenWrt ───────────────────────────────────
openwrt-ipk: _clean_build _prepare_data_openwrt _prepare_control_openwrt _build_ipk_openwrt
	@echo ""
	@echo "✓ OpenWrt пакет собран: $(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_openwrt.ipk"
	@ls -lh $(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_openwrt.ipk
	@echo ""

_prepare_data_openwrt:
	@echo "── Подготовка data для OpenWrt ──"
	@mkdir -p $(DATA_DIR)/usr/share/$(PKG_NAME)
	@mkdir -p $(DATA_DIR)/etc/$(PKG_NAME)
	@mkdir -p $(DATA_DIR)/etc/init.d

	@cp $(APP_FILES) $(DATA_DIR)/usr/share/$(PKG_NAME)/
	@for dir in $(APP_DIRS); do \
		if [ -d "$$dir" ]; then \
			cp -r $$dir $(DATA_DIR)/usr/share/$(PKG_NAME)/ ; \
		fi \
	done

	@find $(DATA_DIR) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find $(DATA_DIR) -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' | xargs rm -f 2>/dev/null || true

	@cp packaging/openwrt/zapret-gui.init $(DATA_DIR)/etc/init.d/zapret-gui
	@chmod 755 $(DATA_DIR)/etc/init.d/zapret-gui

	# CLI-обёртка `zapret-gui` в PATH
	@mkdir -p $(DATA_DIR)/usr/bin
	@cp packaging/openwrt/zapret-gui-cli $(DATA_DIR)/usr/bin/zapret-gui
	@chmod 755 $(DATA_DIR)/usr/bin/zapret-gui

	@mkdir -p $(DATA_DIR)/usr/share/$(PKG_NAME)/init.d
	@mkdir -p $(DATA_DIR)/usr/share/$(PKG_NAME)/lists
	@echo "Подготовка data (OpenWrt): OK"

_prepare_control_openwrt:
	@echo "── Подготовка control для OpenWrt ──"
	@mkdir -p $(CONTROL_DIR)
	@cp packaging/openwrt/control $(CONTROL_DIR)/control
	@cp packaging/openwrt/postinst $(CONTROL_DIR)/postinst
	@cp packaging/openwrt/prerm $(CONTROL_DIR)/prerm
	@cp packaging/openwrt/conffiles $(CONTROL_DIR)/conffiles

	@sed -i 's/@VERSION@/$(PKG_VERSION)-$(PKG_RELEASE)/g' $(CONTROL_DIR)/control

	@SIZE=$$(du -sk $(DATA_DIR) | cut -f1); \
	 sed -i "s/@SIZE@/$$SIZE/g" $(CONTROL_DIR)/control

	@chmod 755 $(CONTROL_DIR)/postinst
	@chmod 755 $(CONTROL_DIR)/prerm
	@echo "Подготовка control (OpenWrt): OK"

_build_ipk_openwrt:
	@echo "── Сборка ipk (OpenWrt) ──"
	@mkdir -p $(IPK_DIR) $(DIST_DIR)

	@echo "2.0" > $(IPK_DIR)/debian-binary
	@cd $(CONTROL_DIR) && tar czf ../../$(IPK_DIR)/control.tar.gz ./*
	@cd $(DATA_DIR) && tar czf ../../$(IPK_DIR)/data.tar.gz ./*
	@cd $(IPK_DIR) && tar czf ../../$(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_openwrt.ipk \
		./debian-binary ./control.tar.gz ./data.tar.gz

	@echo "Сборка ipk (OpenWrt): OK"

# ── Сборка apk для НОВОГО OpenWrt (24.10+/25.x, apk-tools 3) ──
#
# Новые OpenWrt перешли с opkg (.ipk) на apk (.apk, формат APKv3). Пакет
# собирается той же командой `apk mkpkg`, что и штатный build-система OpenWrt
# (include/package-pack.mk): маппинг сопровождающих скриптов postinst →
# post-install, prerm → pre-deinstall; arch=noarch для arch-независимого пакета.
#
# Требуется apk-tools 3 (`apk mkpkg`). В PATH обычно нет — задайте APK=apk.static
# (напр. из alpine:edge `apk add apk-tools-static`), как это делает CI. Файловое
# дерево берём тем же `_prepare_data_openwrt`, что и для ipk — один источник.
#
# Старый OpenWrt/Entware/Keenetic по-прежнему обслуживаются целями ipk —
# ничего не ломаем.
APK          ?= apk
FAKEROOT     ?=
APK_VERSION  := $(PKG_VERSION)-r$(PKG_RELEASE)
APK_SCRIPTS  := $(BUILD_DIR)/apk-scripts
APK_OUT      := $(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_openwrt.apk

openwrt-apk: _clean_build _prepare_data_openwrt _prepare_apk_scripts _build_apk_openwrt
	@echo ""
	@echo "✓ OpenWrt apk собран: $(APK_OUT)"
	@ls -lh $(APK_OUT)
	@echo ""

_prepare_apk_scripts:
	@echo "── Подготовка apk-скриптов ──"
	@mkdir -p $(APK_SCRIPTS)
	# apk lifecycle: postinst → post-install, prerm → pre-deinstall
	@cp packaging/openwrt/postinst $(APK_SCRIPTS)/post-install
	@cp packaging/openwrt/prerm    $(APK_SCRIPTS)/pre-deinstall
	@chmod 755 $(APK_SCRIPTS)/post-install $(APK_SCRIPTS)/pre-deinstall
	@echo "Подготовка apk-скриптов: OK"

_build_apk_openwrt:
	@echo "── Сборка apk (OpenWrt) через '$(APK) mkpkg' ──"
	@mkdir -p $(DIST_DIR)
	@command -v $(APK) >/dev/null 2>&1 || { \
		echo "ОШИБКА: '$(APK)' не найден. Нужен apk-tools 3 (apk mkpkg)."; \
		echo "  Локально/CI: возьмите apk.static из alpine:edge и передайте APK=apk.static"; \
		exit 1; }
	SOURCE_DATE_EPOCH=0 $(FAKEROOT) $(APK) mkpkg \
		--info "name:$(PKG_NAME)" \
		--info "version:$(APK_VERSION)" \
		--info "description:Web GUI for managing zapret2/nfqws2 DPI bypass tool" \
		--info "arch:noarch" \
		--info "origin:$(PKG_NAME)" \
		--info "url:https://github.com/avatarDD/zapret-gui" \
		--info "maintainer:avatarDD <https://github.com/avatarDD/zapret-gui>" \
		--info "depends:python3-light python3-urllib python3-openssl python3-codecs python3-email" \
		--script "post-install:$(APK_SCRIPTS)/post-install" \
		--script "pre-deinstall:$(APK_SCRIPTS)/pre-deinstall" \
		--files "$(DATA_DIR)" \
		--output "$(APK_OUT)"
	@echo "Сборка apk (OpenWrt): OK"

# ── Очистка ───────────────────────────────────────────────────
clean:
	@echo "── Очистка ──"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@echo "Очистка: OK"

# ── Lint ──────────────────────────────────────────────────────
lint:
	@echo "── Проверка синтаксиса Python ──"
	@errors=0; \
	for f in $$(find . -name '*.py' -not -path './build/*' -not -path './dist/*' -not -path './.git/*'); do \
		if ! python3 -c "import ast; ast.parse(open('$$f').read())" 2>/dev/null; then \
			echo "  ОШИБКА: $$f"; \
			errors=$$((errors + 1)); \
		fi \
	done; \
	if [ "$$errors" -gt 0 ]; then \
		echo "Найдено ошибок: $$errors"; \
		exit 1; \
	fi
	@echo "✓ Все Python файлы корректны"
