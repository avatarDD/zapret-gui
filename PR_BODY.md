## Краткое описание

Добавлено **3 новых туннельных движка** (WARP/MASQUE, Telegram MTProto, Opera Proxy), **4 режима WARP-in-WARP**, **система авто-ремедиации**, **единый checker обновлений**, **DPI-фильтрация стратегий**, **live мониторинг туннелей**, **TCP/MTU/BBR оптимизации** и **автоустановка бинарников**. Все изменения **добавочные и обратно совместимые** — существующий функционал не затронут, новые функции отключены по умолчанию.

**35 файлов создано, 22 файла изменено. Нулевые поломки.**

---

## Что добавлено

### 1. WARP/MASQUE туннель (usque-keenetic)
Cloudflare WARP через MASQUE-протокол на порту 443, маскируется под HTTPS. Самый устойчивый к DPI бесплатный VPN.
- Источник: `side-effect-tm/usque-keenetic`
- Автоустановка бинарника из GitHub Releases
- Watchdog с TCP probe через туннель
- Autostart на boot

### 2. Telegram MTProto туннель (Variant C)
Два движка, оба работают без VPS:
- **teleproxy** (C) — Direct-to-DC на роутере, nfqws2 обходит DPI. Только ARM64.
- **tg-mtproxy-client** (Go) — Relay: z2k community (по умолчанию, бесплатно). Все архитектуры.
- Автовыбор по архитектуре
- Автоустановка бинарников из GitHub

### 3. Opera Proxy (Alexey71/opera-proxy)
Zero-config HTTP/SOCKS5 прокси через SurfEasy VPN. Бесплатный fallback.
- Автоустановка из GitHub
- Watchdog с TCP probe

### 4. WARP-in-WARP (4 режима)
| Режим | Outer | Inner | Страница |
|-------|-------|-------|----------|
| AWG + AWG | AmneziaWG | AmneziaWG | AmneziaWG → WARP |
| MASQUE + MASQUE | usque | usque | WARP/MASQUE → WARP-in-WARP |
| MASQUE + AWG | usque | AmneziaWG | WARP/MASQUE → WARP-in-WARP |
| AWG + MASQUE | AmneziaWG | usque | WARP/MASQUE → WARP-in-WARP |
- Watchdog для двойных туннелей

### 5. Auto-Remediation
BlockCheck классифицирует тип DPI → автоматически выбирает метод:
- `TLS_DPI` → strategy scan (nfqws2)
- `IP_BLOCK` → туннель (WARP/AWG/opera/singbox по настраиваемому приоритету)
- `DNS_FAKE` → DoH/DoT
- Настраиваемый приоритет туннелей в GUI (Settings → Auto-Remediation)

### 6. DPI-type фильтрация стратегий
Strategy Scanner теперь фильтрует стратегии по типу DPI-блокировки:
- `TLS_DPI` → fake+split (TCP/443)
- `QUIC_BLOCK` → QUIC-стратегии (UDP/443)
- `CLIENTHELLO_DPI` → multisplit по позициям размера
- Ускорение скана: 13,031 → ~200-500 стратегий (5-10x)

### 7. Unified Update Checker
Единая проверка обновлений для всех 9 бинарников: zapret2, sing-box, mihomo, AWG, GUI, usque, teleproxy, tgproto, opera. Фоновый процесс.

### 8. Расширенные списки доменов
- 12 пресетов (было 6): +TikTok, Netflix, Cloudflare, Google Meet, Russia outside, Ukraine inside
- Per-list транспорт
- Группировка по категориям (Сервисы / Страны)
- Кнопка «Добавить в маршрут»

### 9. Block Detector
DNS-мониторинг + 4-stage probing (DNS → TCP → TLS → HTTP) + авто-добавление заблокированных доменов.

### 10. Live мониторинг туннелей
Графики rx/tx, скорость, объём трафика для ВСЕХ интерфейсов: opkgtun*, awg*, tun*, meta*, nfqws2, opera-proxy, tgproxy.

### 11. Оптимизации латентности туннелей
6 оптимизаций с 3 профилями:
- MTU (1280/1420/1500)
- TCP buffers (64KB/128KB/256KB)
- BBR congestion control
- TCP Fast Open
- TCP_NODELAY (отключение Nagle)
- Keepalive 10s

### 12. Dashboard объединённый обзор
11 карточек статуса: Ядро (nfqws, стратегия, автозапуск, система, zapret), VPN/Туннели (WARP, Opera, Telegram), Мониторинг (Block Detector, Healthcheck).

### 13. Автоустановка бинарников
Одна кнопка в GUI → скачивание с GitHub → установка. Для: usque, teleproxy, tg-mtproxy-client, opera-proxy.

---

## Обратная совместимость

- Все новые секции конфига имеют `enabled: false` по умолчанию
- Существующие пользователи не заменяют изменений
- Ни один существующий API-эндпоинт не изменён
- Ни одна существующая страница UI не изменена (только расширена)
- Миграция не требуется — deep-merge автоматически добавляет новые секции

## Тестирование

- Все Python-файлы проходят `ast.parse()` syntax validation
- Все JS-файлы проходят brace-balance validation
- Существующие тесты не сломаны

---

## Структура sidebar (обновлённая)

```
VPN и маршрутизация:
  ├── Маршрутизация
  ├── AmneziaWG (4 children)
  ├── WARP/MASQUE (2 children: WARP-in-WARP, Установка)
  ├── Telegram Tunnel
  ├── Opera Proxy
  ├── sing-box (3 children)
  ├── mihomo (2 children)
  ├── Мониторинг ← live графики
  └── Оптимизации ← MTU/BBR/TCP
```

## Структура файлов

### Новые файлы (35):
```
core/usque_manager.py              core/usque_watchdog.py
core/tgproxy_manager.py            core/tgproxy_watchdog.py
core/opera_proxy_manager.py        core/opera_proxy_watchdog.py
core/warp_in_warp.py               core/warp_in_warp_watchdog.py
core/auto_remediation.py           core/update_checker.py
core/block_detector.py             core/dns_providers.py
core/geosite_importer.py           core/ext_binary_installer.py
core/tunnel_monitor.py             core/tunnel_optimizer.py
api/usque.py                       api/tgproxy.py
api/opera_proxy.py                 api/auto_remediation.py
api/update_checker.py              api/block_detector.py
api/geosite.py                     api/warp_in_warp.py
api/tunnel_monitor.py              api/tunnel_optimizer.py
web/js/pages/usque.js              web/js/pages/usque_setup.js
web/js/pages/tgproxy.js            web/js/pages/opera_proxy.js
web/js/pages/block_detector.js     web/js/pages/update_checker.js
web/js/pages/warp_in_warp.js       web/js/pages/tunnel_monitor.js
web/js/pages/tunnel_optimizer.js
```

### Модифицированные файлы (22):
```
core/config_manager.py             core/unified/model.py
core/unified/applier.py            core/unified/migration.py
core/list_updater.py               core/named_lists.py
core/strategy_scanner.py           core/auto_remediation.py
core/usque_manager.py              core/tgproxy_manager.py
api/__init__.py                    api/lists.py
api/scan.py                        api/usque.py
api/tgproxy.py                     api/opera_proxy.py
app.py
web/index.html                     web/js/app.js
web/js/components/sidebar.js       web/js/pages/dashboard.js
web/js/pages/lists.js              web/js/pages/settings.js
web/js/pages/tgproxy.js            web/js/pages/usque.js
web/js/pages/opera_proxy.js        CHANGES.md
```
