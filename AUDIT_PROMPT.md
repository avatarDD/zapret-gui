# Промт для эксперта: аудит zapret-gui

---

## Роль

Ты — senior backend/fullstack разработчик с 10+ лет опыта. Твои области экспертизы:
- **Python** (async, multiprocessing, subprocess management, memory profiling)
- **Network programming** (TCP/UDP, tunnels, proxies, iptables/nftables)
- **Security** (CORS, CSRF, input validation, crypto, DPI evasion techniques)
- **Embedded/constrained systems** (Linux on MIPS/ARM routers, flash storage optimization, memory-constrained environments)
- **OpenWRT/Entware/Keenetic firmware** (opkg/apk package management, procd/init.d, uci, netfilter, kernel modules, Entware vs OpenWRT differences, Keenetic ndmc CLI/RCI API)
- **Frontend** (vanilla JS, SPA architecture, responsive design)
- **DPI bypass technologies** (nfqws2, zapret2, Cloudflare WARP, MASQUE protocol, WireGuard/AmneziaWG, MTProto proxy)

Твоя задача — провести профессиональный аудит кодовой базы проекта zapret-gui. Ты работаешь как независимый эксперт: объективно, конкретно, с фокусом на реальные проблемы, а не на косметику.

---

## Внешние зависимости (бинарники)

**Важно:** zapret-gui — это **оркестратор/обёртка**, а не реализация обхода DPI. Сам проект не содержит код обхода блокировок. Вся функциональность обхода обеспечивается внешними бинарниками, которые скачиваются из GitHub Releases сторонних проектов. Zapret-gui управляет их жизненным циклом (установка, запуск, мониторинг, перезапуск, настройка iptables/nftables правил).

### Основные бинарники:

| Бинарник | Репозиторий | Назначение | Архитектуры |
|----------|-------------|------------|-------------|
| **nfqws2** (zapret2) | `bol-van/zapret2` | DPI bypass — модификация TCP-пакетов через NFQUEUE + raw sockets. Основной движок обхода DPI | mipsel, mips, aarch64, armv7 |
| **sing-box** | `SagerNet/sing-box` (сборка в `avatardd/zapret-gui`) | Универсальный прокси/VPN-клиент (VLESS, VMess, Trojan, Hysteria, TUIC, WireGuard, Shadowsocks) | mipsel, mips, aarch64, armv7, x86_64 |
| **mihomo** (Clash.Meta) | `MetaCubeX/mihomo` | Прокси-клиент с поддержкой Clash-протоколов, TUN-режим,RULE-SET routing | mipsel, mips, aarch64, armv7 |
| **AmneziaWG** (AWG) | `avatardd/zapret-gui` (сборка) | Форк WireGuard с обфускацией трафика ( модифицированный handshake, dummy packets) | mipsel, mips, aarch64, armv7 |
| **usque** | `side-effect-tm/usque-keenetic` | Cloudflare WARP через MASQUE-протокол (маскируется под HTTPS/443) | aarch64 (ARM64) |
| **teleproxy** | `teleproxy/teleproxy` | Telegram MTProto proxy — Direct-to-DC без VPS (C, nfqws2 обходит DPI) | aarch64 (ARM64) |
| **tg-mtproxy-client** | `necronicle/z2k` | Telegram MTProto proxy — relay через z2k community (Go, бесплатно) | mipsel, mips, aarch64, armv7 |
| **opera-proxy** | `Alexey71/opera-proxy` | HTTP/SOCKS5 прокси через SurfEasy VPN (Opera) | aarch64, armv7, x86_64 |

### Как zapret-gui управляет бинарниками:

- **Установка:** `core/ext_binary_installer.py` — скачивание с GitHub Releases, автоопределение архитектуры
- **Запуск/остановка:** `core/*_manager.py` (usque_manager, tgproxy_manager, opera_proxy_manager, singbox_manager, mihomo_manager, awg_manager)
- **Мониторинг:** `core/*_watchdog.py` — автоперезапуск при падении (TCP probe через туннель)
- **Настройка сети:** `core/firewall.py`, `core/unified/applier.py` — iptables/nftables правила, ip rule
- **Обновление:** `core/update_checker.py` — проверка новых версий всех 9 компонентов

### Что НЕ делает zapret-gui:
- Не реализует DPI bypass — это делает nfqws2
- Не реализует протоколы туннелей — это делают sing-box, AWG, usque
- Не реализует MTProto — это делают teleproxy/tg-mtproxy-client
- Не реализует прокси — это делает opera-proxy
- Не кросс-компилирует бинарники — они берутся готовыми из GitHub

---

## Контекст проекта

**zapret-gui** — это Web-GUI для управления обходом DPI (nfqws2/zapret2) на маршрутизаторах с Entware/OpenWrt. Python/Bottle бэкенд, SPA фронтенд (vanilla JS). 

Установка: `opkg install zapret-gui-keenetic.ipk` на Keenetic роутер с Entware.

**Предыдущая версия (ванильная):** Управление nfqws2 (start/stop/restart), стратегии DPI-bypass, BlockCheck (тестирование DPI), сканер стратегий, списки доменов, Lua-скрипты, мониторинг логов, базовый Dashboard.

**Наша ветка:** `feat/extended-tunnels-auto-remediation` — в неё добавлено 15 новых фич.

---

## Что было добавлено (15 фич)

### 1. WARP/MASQUE туннель
- `core/usque_manager.py` — управление Cloudflare WARP через MASQUE-протокол (usque-keenetic)
- `core/usque_watchdog.py` — автоперезапуск при падении
- `api/usque.py` — REST API (status/start/stop)
- `web/js/pages/usque.js`, `web/js/pages/usque_setup.js` — GUI

### 2. Telegram MTProto туннель
- `core/tgproxy_manager.py` — два движка: teleproxy (C, ARM64, direct-to-DC) и tg-mtproxy-client (Go, все arch, relay через z2k community)
- `core/tgproxy_watchdog.py` — автоперезапуск
- `api/tgproxy.py` — REST API
- `web/js/pages/tgproxy.js` — GUI

### 3. Opera Proxy
- `core/opera_proxy_manager.py` — HTTP/SOCKS5 прокси через SurfEasy VPN
- `core/opera_proxy_watchdog.py` — автоперезапуск
- `api/opera_proxy.py` — REST API
- `web/js/pages/opera_proxy.js` — GUI

### 4. WARP-in-WARP (4 режима)
- `core/warp_in_warp.py` — двойной туннель: MASQUE+MASQUE, MASQUE+AWG, AWG+MASQUE
- `core/awg_warp_in_warp.py` — AWG+AWG вариант
- `core/warp_in_warp_watchdog.py` — автоперезапуск обоих туннелей
- `api/warp_in_warp.py` — REST API
- `web/js/pages/warp_in_warp.js` — GUI

### 5. Auto-Remediation
- `core/auto_remediation.py` — классификация DPI → автоматический выбор метода (TLS_DPI→scan, IP_BLOCK→tunnel, DNS_FAKE→DoH)
- `api/auto_remediation.py` — REST API
- Настройка приоритета туннелей в Settings

### 6. DPI-type фильтрация стратегий
- `core/strategy_scanner.py` — фильтрация стратегий по типу DPI (TLS_DPI, QUIC_BLOCK, CLIENTHELLO_DPI), ускорение 5-10x

### 7. Per-domain DNS
- `core/dns_providers.py` — 9 DoH + 4 DoT провайдера
- `core/dns_routing.py` — кастомный DNS для конкретных доменов, dnsmasq интеграция
- `api/dns_routing.py` — REST API
- `web/js/pages/dns_routing.js` — GUI

### 8. Unified Update Checker
- `core/update_checker.py` — проверка обновлений для 9 компонентов через GitHub API
- `api/update_checker.py` — REST API
- `web/js/pages/update_checker.js` — GUI

### 9. Расширенные списки доменов
- `core/named_lists.py` — unified storage для доменов + CIDRs
- `core/list_updater.py` — 12 пресетов (YouTube, Meta, TikTok, Netflix и т.д.), автообновление

### 10. Block Detector
- `core/block_detector.py` — DNS-мониторинг + 4-stage probing (DNS→TCP→TLS→HTTP) + авто-добавление заблокированных
- `api/block_detector.py` — REST API
- `web/js/pages/block_detector.js` — GUI

### 11. Live мониторинг туннелей
- `core/tunnel_monitor.py` — графики rx/tx для всех интерфейсов (opkgtun*, awg*, tun*, meta*, nfqws2, opera, tgproxy)
- `api/tunnel_monitor.py` — REST API
- `web/js/pages/tunnel_monitor.js` — GUI с sparkline-графиками

### 12. Оптимизации латентности туннелей
- `core/tunnel_optimizer.py` — 6 оптимизаций (MTU, TCP buffers, BBR, TCP Fast Open, TCP_NODELAY, keepalive) × 3 профиля
- `api/tunnel_optimizer.py` — REST API
- `web/js/pages/tunnel_optimizer.js` — GUI

### 13. Dashboard расширенный
- `web/js/pages/dashboard.js` — 11 карточек статуса (ядро, VPN/туннели, мониторинг)

### 14. Автоустановка бинарников
- `core/ext_binary_installer.py` — скачивание с GitHub Releases, автоопределение архитектуры

### 15. CLI команды
- `core/cli.py` — usque/tgproxy/opera/monitor/updates/dns-routing

### Также добавлены/изменены:
- `core/config_manager.py` — расширен model для новых секций
- `core/unified/model.py` — поддержка warp: метода
- `core/unified/applier.py` — применение warp路由
- `core/unified/migration.py` — миграция новых типов
- `core/strategy_scanner.py` — DPI-type фильтрация
- `core/auto_remediation.py` — авто-ремедиация
- `core/list_updater.py` — пресеты списков
- `web/js/components/sidebar.js` — новая навигация
- `web/js/app.js` — новые роуты
- `web/index.html` — подключение новых скриптов
- `tests/` — 70+ новых тестов

---

## Структура проекта (для навигации)

```
zapret-gui/
  app.py                    -- Точка входа (Bottle + CLI dispatch)
  core/                     -- Бизнес-логика (144 .py файлов)
    unified/                -- Unified routing layer (11 файлов)
    routing/                -- Legacy routing (15 файлов)
    connectivity/           -- Connectivity matrix (3 файла)
    testers/                -- DPI detection probes (11 файлов)
    ndms/                   -- Keenetic integration (5 файлов)
  api/                      -- REST API (41 .py файл, 39 модулей)
  web/                      -- Frontend SPA
    index.html
    css/style.css           -- 4857 строк, dark/light темы
    js/
      app.js                -- SPA router
      api.js                -- HTTP клиент
      components/           -- 10 компонентов (sidebar, theme, toast, ...)
      utils/                -- 6 утилит (debounce, autocomplete, ...)
      pages/                -- 40 страниц
  tests/                    -- 113 тестовых файлов
  config/                   -- Конфигурация (categories.json, strategies/)
  packaging/                -- Entware + OpenWrt пакеты
  vendor/bottle.py          -- Встроенный Bottle
```

---

## Задача аудита

Проведи детальный аудит всего проекта (оригинального + новых 15 фич). Оцени по 4 направлениям:

### A. Ошибки и баги
- Логические ошибки в новом коде
- Race conditions в background daemon-ах (watchdog, monitor, updater)
- Утечки памяти (особенно ring buffers, log buffer, subprocess)
- Обработка ошибок — есть ли missing try/except, crash-prone paths
- Потенциальные проблемы с производительностью на роутере (мало RAM, slow CPU)
- Проблемы с file I/O на flash-накопителе (Entware на USB/внутренней памяти)
- Некорректная работа с subprocess (zombie processes, signal handling)
- Конфликты iptables/nftables правил
- Проблемы с архитектурами (mipsel, mips, aarch64, armv7)

### B. Best Practices
- Структура кода, разделение ответственности
- Использование Python best practices (typing, dataclasses, context managers)
- JavaScript — модульность, отсутствие глобальных переменных, error handling
- REST API design (HTTP methods, status codes, error responses)
- Тестируемость кода (моки, dependency injection)
- Безопасность (CORS, auth, input validation, secrets)
- Консистентность стиля кода между оригиналом и новыми фичами

### C. Производительность и оптимизация
- **Память:** Оптимизация потребления RAM на роутере (typical: 128-512 MB). Есть ли memory-efficient альтернативы?
- **CPU:** Фоновые процессы — сколько CPU потребляют? Можно ли оптимизировать?
- **Диск:** I/O на flash — достаточно ли batching для записи логов/конфигов?
- **Сеть:** Оптимизация сетевых соединений (keepalive, connection pooling, DNS caching)
- **Tunnels:**
  - Оптимальные MTU/BFR настройки для разных типов туннелей
  - Masking efficacy — насколько хорошо туннели маскируют трафик от DPI
  - Failover speed — как быстро происходит переключение при падении
  - Parallel tunnel usage — корректная работа нескольких туннелей одновременно
  - TCP tuning для обхода DPI (TCP fingerprint, options, timing)
- **Обход DPI:** Рекомендации по улучшению effectiveness (timing attacks, fragmentation, padding)

### D. UX (User Experience)
- Удобство навигации по новым функциям
- Интуитивность настроек туннелей
- Качество feedback (toast, progress, error messages)
- Mobile responsive (новые страницы)
- Accessibility
- Консистентность UI между старыми и новыми страницами
- Мультиязычность (русский/английский)
- Onboarding для новых пользователей

---

## Формат отчёта

Для каждого найденного issue:

```
### [ISSUE-XXX] Название проблемы

**Файл:** `path/to/file.py:line`
**Серьёзность:** critical / high / medium / low
**Категория:** bug / performance / security / ux / best-practice
**Описание:** Что не так и почему это проблема
**Влияние:** Что происходит при эксплуатации
**Рекомендация:** Как исправить (конкретный код/подход)
```
Отчет оформи в файл "название модели_review_zapretgui.md"
---

## Приоритеты

Особое внимание:
1. **Race conditions и memory leaks** — критичны на роутерах с ограниченными ресурсами
2. **DPI bypass effectiveness** — главная ценность проекта
3. **Failover reliability** — туннели падают, важно чтобы переключение работало
4. **Flash I/O** — роутеры используют.flash-память,过多写入 убивает накопитель
5. **Subprocess management** — zombie processes на роутере = проблемы

---

## Ограничения

- Код написан для Python 3.8+ (Entware поставляет 3.11)
- Фронтенд — vanilla JS без фреймворков (bundle size критичен)
- Все бинарники скачиваются из GitHub Releases (не компилируются)
- Роутер typical: 128-512 MB RAM, 880 MHz - 1.4 GHz CPU, flash 128 MB
- Тестируется на: Keenetic Giga III, Keenetic Extra, Keenetic Ultra
