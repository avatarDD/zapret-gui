# Changelog

## v0.12.0 — Фаза 12: Autocomplete (синтаксис-помощник)

### Добавлено
- **Autocomplete для стратегий** — выпадающий popup с контекстными подсказками при вводе аргументов
  - Автоматический вызов при наборе `--` (начало флага)
  - Ручной вызов по `Ctrl+Space` в любой позиции
  - Контекстные подсказки: флаги, desync-методы, L7-протоколы, fooling, позиции, TLS-модификации
  - Подсказки субпараметров lua-цепочек (`blob=`, `pos=`, `repeats=`, …)
  - Подсказки файлов: блобы, hostlists, ipsets с сервера
  - Фильтрация по мере набора
  - Навигация стрелками ↑↓, вставка Enter/Tab, закрытие Escape
  - Цветовые иконки по категориям: 🔵 filter, 🔴 desync, 🟢 list, 🟡 global, 🟠 dup
  - Краткие описания параметров справа от каждого варианта
  - Позиционирование popup под курсором через mirror-div
  - Хинт `Ctrl+Space` в textarea
- **Новый модуль** — `web/js/utils/autocomplete.js` (IIFE `NfqwsAutocomplete`)
- **CSS-стили** — `.nfq-ac-*` для popup, адаптив для мобильных

### Интеграция
- Autocomplete подключается при открытии редактора стратегий
- Переподключается при добавлении/удалении профилей
- Очищается при закрытии модала и уходе со страницы

---

## v0.11.0 — Фаза 11: Интеграция и полировка

### Добавлено
- **Подсветка синтаксиса стратегий** — цветовое выделение параметров nfqws/nfqws2
  - Флаги (`--filter-tcp`, `--dpi-desync`, `--lua-desync`) — голубые
  - Desync-методы (`fake`, `multisplit`, `fakedsplit`) — красные, жирные
  - Субпараметры-ключи (`blob`, `pos`, `repeats`) — зелёные
  - Субпараметры-значения и fooling — оранжевые
  - L7-протоколы (`http`, `tls`, `quic`) — фиолетовые
  - Файлы (`.txt`, `.bin`) — голубые с подчёркиванием
  - Числа и позиции — свои цвета
  - Разделитель `--new` — оранжевый с фоном
- **Синтаксис в превью стратегий** — подсветка в модальном окне превью команды
- **Синтаксис в карточках стратегий** — превью аргументов каждого профиля
- **Синтаксис в логах** — автоопределение и подсветка nfqws-команд в логах
- **Синтаксис в dashboard и control** — подсветка nfqws-аргументов в мини-логах
- **Утилиты** — `web/js/utils/syntax.js` (подсветка), `web/js/utils/debounce.js` (оптимизация)
- **README.md** — полная документация: установка, использование, API, FAQ
- **CHANGELOG.md** — история версий
- Поддержка обоих стилей параметров: nfqws2 (lua-desync) и classic nfqws (dpi-desync)
- Справочник 60+ параметров nfqws с описаниями и допустимыми значениями
- Готовая инфраструктура для будущего autocomplete-помощника

### Улучшено
- Обновлена версия до v0.11.0
- `.gitignore` расширен

### Оптимизация (Фаза 11.2)
- Утилита `debounce` и `throttle` для частых API-вызовов
- Утилита `lazyPage` для отложенной загрузки страниц

---

## v0.10.0 — Фаза 10: Сборка и пакетирование

- Makefile для сборки ipk (Entware, OpenWrt)
- install.sh — автоустановка с GitHub
- uninstall.sh — удаление (с опцией --purge)
- Init-скрипты: S99zapret-gui (Entware), procd (OpenWrt)
- Исправления: блобы files/fake/, autostart import, hosts Cache-Control

## v0.9.0 — Фаза 9: Настройки

- Страница настроек (7 секций)
- Импорт/экспорт конфигурации JSON
- Сброс к дефолтам
- Адаптивный дизайн

## v0.8.0 — Фаза 8: Автозапуск + Zapret Manager

- Генерация init-скрипта S99zapret
- Управление автозапуском
- Zapret installer: установка/обновление/удаление с GitHub
- Прогресс операций

## v0.7.0 — Фаза 7: Логи

- SSE (Server-Sent Events) для real-time логов
- Фильтрация по уровню, поиск по тексту
- Автопрокрутка, пауза/продолжение
- Копирование и очистка

## v0.6.0 — Фаза 6: Диагностика

- Ping, HTTP/HTTPS, DNS проверки
- Проверка конфликтов (другие nfqws/tpws)
- Системная информация
- Статус firewall

## v0.5.0 — Фаза 5: Hosts

- Управление /etc/hosts
- Пресеты (блокировка рекламы, YouTube и др.)
- Бэкапы /etc/hosts
- Raw-редактор

## v0.4.0 — Фаза 4: Блобы

- Hex-редактор блобов
- Генерация fake TLS/HTTP ClientHello
- Сканирование системных блобов zapret2

## v0.3.0 — Фаза 3: Списки

- Hostlists (домены) с нормализацией
- IPsets с загрузкой по ASN
- Импорт из URL, сброс к дефолтам

## v0.2.0 — Фаза 2: Стратегии

- JSON-модель стратегий (builtin + user)
- Категории сервисов
- CRUD API + UI с карточками
- Превью итоговой команды

## v0.1.0 — Фаза 1: Ядро

- NFQWSManager (запуск/остановка nfqws2)
- FirewallManager (iptables/nftables)
- API управления (start/stop/restart)
- Dashboard UI

## v0.0.1 — Фаза 0: Скелет

- Bottle сервер
- JSON конфигурация
- Кольцевой буфер логов


-Makefile
# ═══════════════════════════════════════════════════════════════
# Makefile — Сборка пакета zapret-gui для Entware/OpenWrt
# ═══════════════════════════════════════════════════════════════
#
# Использование:
#   make ipk          — собрать ipk-пакет для Entware
#   make openwrt-ipk  — собрать ipk-пакет для OpenWrt
#   make clean        — очистить артефакты сборки
#   make lint         — проверка синтаксиса Python
#   make info         — информация о пакете
#
# Требования для сборки:
#   tar, gzip, fakeroot (опционально), find, python3 (для lint)
#
# ═══════════════════════════════════════════════════════════════

PKG_NAME     := zapret-gui
PKG_VERSION  := 0.10.0
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
APP_DIRS     := api core config web
EXCLUDE      := --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
                --exclude='.DS_Store' --exclude='.git' --exclude='build' \
                --exclude='dist' --exclude='packaging' --exclude='Makefile' \
                --exclude='install.sh' --exclude='uninstall.sh' --exclude='.gitignore' \
                --exclude='*.md' --exclude='init.d' --exclude='lists'

# ═══════════════════════════════════════════════════════════════
# Цели
# ═══════════════════════════════════════════════════════════════

.PHONY: all ipk openwrt-ipk clean lint info help

all: ipk

help:
	@echo ""
	@echo "  Zapret Web-GUI — Makefile"
	@echo "  ─────────────────────────"
	@echo "  make ipk          — собрать ipk для Entware"
	@echo "  make openwrt-ipk  — собрать ipk для OpenWrt"
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

# ── Сборка ipk для Entware ───────────────────────────────────
ipk: clean _prepare_data _prepare_control _build_ipk
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
		cp -r $$dir $(DATA_DIR)$(DEST_APP)/ ; \
	done

	# Удаляем __pycache__ и прочий мусор
	@find $(DATA_DIR) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find $(DATA_DIR) -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' | xargs rm -f 2>/dev/null || true

	# Init-скрипт для веб-сервера GUI
	@cp packaging/entware/S99zapret-gui $(DATA_DIR)$(DEST_INITD)/S99zapret-gui
	@chmod 755 $(DATA_DIR)$(DEST_INITD)/S99zapret-gui

	# Создаём пустые директории для runtime
	@mkdir -p $(DATA_DIR)$(DEST_APP)/init.d
	@mkdir -p $(DATA_DIR)$(DEST_APP)/lists
	@mkdir -p $(DATA_DIR)$(DEST_CONFIG)

	# Лог-директория (symlink в /tmp при первом запуске)
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
openwrt-ipk: clean _prepare_data_openwrt _prepare_control_openwrt _build_ipk_openwrt
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
		cp -r $$dir $(DATA_DIR)/usr/share/$(PKG_NAME)/ ; \
	done

	@find $(DATA_DIR) -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find $(DATA_DIR) -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' | xargs rm -f 2>/dev/null || true

	@cp packaging/openwrt/zapret-gui.init $(DATA_DIR)/etc/init.d/zapret-gui
	@chmod 755 $(DATA_DIR)/etc/init.d/zapret-gui

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
	@echo "── Сборка OpenWrt ipk ──"
	@mkdir -p $(IPK_DIR) $(DIST_DIR)
	@echo "2.0" > $(IPK_DIR)/debian-binary
	@cd $(CONTROL_DIR) && tar czf ../../$(IPK_DIR)/control.tar.gz ./*
	@cd $(DATA_DIR) && tar czf ../../$(IPK_DIR)/data.tar.gz ./*
	@cd $(IPK_DIR) && tar czf ../../$(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_openwrt.ipk \
		./debian-binary ./control.tar.gz ./data.tar.gz
	@echo "Сборка OpenWrt ipk: OK"

# ── Очистка ──────────────────────────────────────────────────
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Очистка build/: OK"

distclean: clean
	@rm -rf $(DIST_DIR)
	@echo "Очистка dist/: OK"

# ── Линтер ───────────────────────────────────────────────────
lint:
	@echo "── Проверка синтаксиса Python ──"
	@python3 -m py_compile app.py && echo "  app.py: OK"
	@for f in api/*.py core/*.py; do \
		python3 -m py_compile "$$f" && echo "  $$f: OK" || echo "  $$f: FAIL"; \
	done
	@echo "Lint завершён"


