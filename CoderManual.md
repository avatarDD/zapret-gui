# CoderManual — руководство разработчика zapret-gui

Документ для тех, кто будет дорабатывать проект. Цель — чтобы новый
разработчик за полчаса понял, **что где лежит, как это работает и куда
добавлять новое**. Пользовательская документация — в [README.md](README.md).

---

## Содержание

1. [Стек и принципы](#1-стек-и-принципы)
2. [Архитектура в целом](#2-архитектура-в-целом)
3. [Структура репозитория](#3-структура-репозитория)
4. [Точка входа `app.py`](#4-точка-входа-apppy)
5. [Backend: `core/` по доменам](#5-backend-core-по-доменам)
6. [Backend: `api/` и REST](#6-backend-api-и-rest)
7. [Frontend: `web/` и SPA](#7-frontend-web-и-spa)
8. [Фоновые воркеры](#8-фоновые-воркеры)
9. [Конфигурация (`settings.json`)](#9-конфигурация-settingsjson)
10. [Платформенная абстракция](#10-платформенная-абстракция)
11. [Сборка, пакеты, релиз](#11-сборка-пакеты-релиз)
12. [Тесты и линт](#12-тесты-и-линт)
13. [Соглашения и «куда добавить X»](#13-соглашения-и-куда-добавить-x)

---

## 1. Стек и принципы

| Слой | Технология |
|------|------------|
| Бэкенд | Python 3.11+, [Bottle](https://bottlepy.org/) (микро-WSGI) |
| WSGI-сервер | свой `ThreadedWSGIServer` (многопоточный, ради SSE + параллельных API) |
| Фронтенд | vanilla JS (без сборки/фреймворков), hash-роутинг SPA, CSS-переменные |
| Хранилище | один JSON `settings.json` + файлы конфигов движков на диске |
| Зависимости | только `bottle`, встроен в репо (`vendor/bottle.py` — фолбэк, когда нет системного; см. `core/bottle_vendor.py`); опц. `pyyaml` — есть собственный YAML-fallback |

**Принципы, которые стоит сохранять:**

- **Минимум зависимостей.** Код едет на роутере с `python3-light`. Никаких
  тяжёлых пакетов; HTTP — через `urllib`, не `requests`.
- **Логи в RAM.** `collections.deque(maxlen=…)` — на flash не пишем
  (экономим ресурс памяти роутера).
- **Singleton-менеджеры.** `get_xxx_manager()` — thread-safe ленивые
  синглтоны. Состояние процессов/конфигов — в одном месте.
- **Чистые функции отделены от I/O.** Парсеры, классификаторы, decide-
  логика тестируются без сети/диска (см. `evaluate_conflicts`,
  `merge_preserving_manual`, `failover.decide`, `parse_*`).
- **Идемпотентность firewall.** Все правила — в своих цепочках/таблицах,
  применяются и снимаются без дублей.
- **Кроссплатформенность через абстракцию.** Архитектурно-зависим только
  бинарник; пути/init-скрипты/firewall выбираются по детекту платформы.

---

## 2. Архитектура в целом

```
            Браузер (SPA, web/)
                  │  HTTP/JSON + SSE
                  ▼
        app.py  →  Bottle app  →  api/*.register(app)   (REST-роуты)
                                      │
                                      ▼
                                  core/*               (бизнес-логика,
                                  ├─ менеджеры          синглтоны)
                                  ├─ unified/           (единый слой)
                                  ├─ routing/           (selective routing)
                                  ├─ testers/           (сетевые пробы)
                                  ├─ ndms/              (Keenetic RCI)
                                  └─ connectivity/      (матрица/трафик)
                                      │
                  ┌───────────────────┼────────────────────┐
                  ▼                   ▼                    ▼
            процессы            firewall/ip(6)tables   settings.json
        (nfqws2, sing-box,       / nftables / ipset    + конфиги движков
         mihomo, awg-go)         / dnsmasq             на диске
```

- **`api/*`** — тонкий слой: разбор запроса → вызов `core/*` → JSON. Без
  бизнес-логики.
- **`core/*`** — вся логика. Менеджеры запускают/останавливают процессы,
  пишут конфиги, дёргают firewall.
- **Фоновые потоки** (refreshers/monitors/watchdog) живут внутри `core/*`
  синглтонов и переживают перезагрузку страницы (но не процесса —
  поднимаются заново при старте `app.py`).

---

## 3. Структура репозитория

```
zapret-gui/
├── app.py                  # точка входа: web-режим, CLI, boot-хуки
├── Makefile                # сборка пакетов, lint, release
├── install.sh / uninstall.sh
├── README.md               # руководство пользователя
├── CoderManual.md          # этот файл
├── CHANGELOG.md / TODO.md
├── AGENTS.md               # инструкции для AI-агентов + индекс скилов
├── GEMINI.md               # указатель на AGENTS.md (Gemini CLI)
│
├── .claude/skills/         # предметные справочники (скилы), см. §3.1
├── .cursor/rules/          # указатель на AGENTS.md (Cursor)
├── docs/skills.json        # машиночитаемый индекс скилов
├── tools/gen_agent_index.py # генератор всего перечисленного выше
│
├── api/                    # REST-роуты (Bottle), по одному файлу на домен
├── core/                   # бизнес-логика
│   ├── unified/            # единый слой «назначение → метод»
│   ├── routing/            # selective routing (cidr/domain/device/dscp)
│   ├── testers/            # сетевые тестеры (TLS/TCP/QUIC/STUN/DPI)
│   ├── ndms/               # Keenetic RCI (интерфейсы, политики хостов)
│   └── connectivity/       # матрица связности + traffic-серии (RAM)
│
├── web/                    # фронтенд (SPA)
│   ├── index.html
│   ├── css/
│   └── js/
│       ├── pages/          # страницы (IIFE-модули render()/destroy())
│       ├── components/     # sidebar, toast, list_ui, sparkline, help,
│       │                   #   setup_ui, proxy_table, expert, transport_select, theme
│       └── utils/          # autocomplete, debounce, syntax-подсветка, nfqws2_lint
│
├── catalogs/               # INI-каталоги стратегий (basic/advanced/direct/builtin)
├── config/                 # builtin-стратегии (JSON) + categories.json
├── data/                   # bundled-данные (domains.txt, tcp_targets.json)
├── packaging/              # сборка ipk (entware/ + openwrt/)
├── tests/                  # 95 файлов unittest (+ _wsgi_client харнесс)
└── .github/workflows/      # release.yml, build-awg-binaries.yml,
                            #   build-singbox-binaries.yml
```

### 3.1 Скилы — предметные справочники по движкам

В `.claude/skills/<имя>/SKILL.md` лежат плотные справочники по каждому
внешнему движку: nfqws2/zapret2, sing-box, mihomo, AmneziaWG, MASQUE/usque,
Opera Proxy, Telegram-туннель. Это не обзоры, а рабочие спецификации —
точные CLI-флаги, форматы конфигов, инварианты, типовые причины «не
работает», плюс привязка к нашим модулям в `core/`.

**Источник правды у скила — апстрим** (`bol-van/zapret2`,
`sagernet/sing-box`, `MetaCubeX/mihomo`, …). Если апстрим ушёл вперёд —
правим скил, а не подгоняем код под устаревший текст.

Каталог `.claude/` подхватывает сам Claude Code. Чтобы скилы видели и
остальные агенты (Codex, Cursor, Copilot, Gemini CLI, Aider, Zed …),
`tools/gen_agent_index.py` раскладывает индекс по их точкам входа:
`AGENTS.md` (кросс-инструментальный стандарт и единственный файл с
содержательным текстом), `GEMINI.md`, `.github/copilot-instructions.md`,
`.cursor/rules/zapret-gui.mdc`, `docs/skills.json`. Дублируется только
список скилов, не их содержимое.

```sh
python3 tools/gen_agent_index.py           # после добавления/правки скила
python3 tools/gen_agent_index.py --check   # проверить синхронность
```

Синхронность стережёт `tests/test_agent_skill_index.py`. Ручной текст в
`AGENTS.md` вне маркеров `BEGIN/END GENERATED SKILL INDEX` переживает
перегенерацию.

### 3.2 Апстримы: `docs/upstream.json` и сверка

Проект зависит от девяти чужих репозиториев — движки (zapret2, sing-box,
mihomo, amneziawg, usque, opera-proxy, tg-ws-proxy-go) и источник каталогов
стратегий (`youtubediscord/zapret`). Их версии не видны из кода: скил
nfqws2 три месяца описывал zapret2 0.9.5.2, пока апстрим ушёл на 1.0.4, а
bundled core-lua отставала на релиз и **перезаписывала пользователю более
свежие файлы**. Ни один тест этого не ловил — сравнивать было не с чем.

`docs/upstream.json` — единственное место, где записано, чему мы
соответствуем: репозиторий, сверенная версия (`pinned`), дата сверки, скил,
vendored-файлы с sha256, отслеживаемые пути в дереве.

```sh
make upstream            # + опрос апстримов, нужна сеть
make upstream-offline    # только локальные сверки (идёт в тестах)
```

Проверяются **две разные вещи**:

| | |
|---|---|
| **offline** (`tests/test_upstream_manifest.py`) | vendored-файлы совпадают с sha256; скилы и спеки упоминают ту же версию, что манифест; манифест согласован; каждый скил привязан к апстриму |
| **online** (`.github/workflows/check-upstream.yml`, еженедельно) | последний релиз апстрима новее `pinned`? для `kind=branch` — на месте ли пути, от которых мы зависим? |

Версии апстримов берутся через `git ls-remote --tags`, а не GitHub REST API:
не нужен токен, нет rate-limit. Сравнение **числовое** — лексикографически
`v1.9.7` больше `v1.13.0`, и сторож молчал бы вечно.

Когда апстрим ушёл вперёд, workflow заводит (и потом сам закрывает) issue
с меткой `upstream-drift`. Порядок работы по ней:

1. прочитать changelog между `pinned` и `latest` — важен не номер, а
   изменившаяся семантика;
2. синхронизировать vendored-файлы, пересчитать sha256;
3. **обновить скил** — он источник правды для всех агентов, устаревший
   скил хуже отсутствующего;
4. обновить `pinned` и `verified_at`.

`pinned: null` — базовой версии ещё нет. Это долг, а не регресс: сборку не
валит, но в отчёте видно.

### 3.3 Lua-расширения и их сверка с ядром

В `import/lua/` лежат два разных класса файлов:

- **дословные копии релиза zapret2** (`zapret-lib`, `zapret-antidpi`,
  `zapret-auto`, `zapret-obfs`, `zapret-pcap`, `zapret-tests`) — правятся
  **только** синхронизацией с апстримом, запиннены по sha256;
- **наши расширения** (`custom_funcs.lua`, `zapret-multishake.lua`,
  companion'ы оркестратора, `z2k-*`, …) — их пишем мы.

Наши расширения вызывают функции ядра и C-функции nfqws2. В Lua вызов
несуществующего глобала — не ошибка загрузки, а падение на конкретном
пакете: стратегия молча не работает, а `--intercept=0` этого не видит
(он проверяет только `lua-init`). Так каталоги полгода предлагали
`discord_timestamp_travel`, звавшую несуществующую `bitright()` вместо
`bitrshift()`.

`tests/test_lua_symbols_resolve.py` резолвит каждый вызов в наших файлах
против определений бандла, C-функций nfqws2 и стандартной библиотеки.
Список исключений там самоочищающийся: отдельный тест падает, если
исключение стало ненужным, — иначе allowlist со временем замаскировал бы
настоящие опечатки.

---

## 4. Точка входа `app.py`

`app.py` делает три вещи:

1. **Различает режим.** Если в argv есть CLI-подкоманда
   (`status`/`nfqws`/`strategy`/`singbox`/`mihomo`) — уходит в
   `core/cli.py`. Иначе — web-режим.
2. **Спец-флаги** (вызываются init-скриптами при загрузке/остановке
   системы, не пользователем):
   - `--apply-awg-autostart` / `--stop-awg-autostart`
   - `--apply-singbox-transparent` / `--remove-singbox-transparent`
   - `--config <dir>` — каталог `settings.json` (по умолчанию
     `/opt/etc/zapret-gui`).
3. **Web-режим** (`--host`, `--port`, `--debug`): создаёт Bottle-app,
   вызывает `api.register_routes(app)`, поднимает `ThreadedWSGIServer` и
   выполняет **boot-хуки**:
   - применить сохранённую стратегию nfqws2 (для платформ без отдельного
     init);
   - мигрировать legacy-правила routing → единый слой
     (`unified.migration.migrate_on_boot`, идемпотентно);
   - поднять AWG-автозапуск;
   - запустить мониторинг единого слоя (`unified.monitor`);
   - реконфигурировать фоновые обновлятели подписок
     (`subscription_manager`), пула (`server_pool`) и курируемых списков
     (`list_updater`);
   - поднять watchdog'и AWG и sing-box и healthcheck-демон (каждый — no-op,
     если выключен в настройках).

> Добавляешь новый фоновый воркер? Зарегистрируй его `reconfigure()` в
> boot-хуках `app.py`, иначе автообновление не переживёт рестарт GUI.

---

## 5. Backend: `core/` по доменам

### 5.1 Инфраструктура / ядро

| Модуль | Назначение |
|--------|-----------|
| `config_manager.py` | Менеджер `settings.json`: `get/set/save/load`, deep-merge дефолтов, миграции legacy-путей. Синглтон `get_config_manager()`. |
| `log_buffer.py` | Кольцевой буфер логов в RAM (`deque`) + SSE-стрим. `log.info/success/warning/error(msg, source=…)`. |
| `version.py` | Единый источник версии `GUI_VERSION`. |
| `system_info.py` | Инфо о роутере (uptime, RAM, arch). |
| `binary_installer.py` | Общая загрузка/проверка sha/распаковка бинарников + зеркало (`ZAPRET_GUI_MIRROR`/`install.mirror`/`file://`) + retry + выбор версии (`list_releases`) + локальный файл. База для всех установщиков. |
| `ext_binary_installer.py` | Установщик «внешних» движков, которые мы собираем сами или ставим пакетом: `BINARIES` (usque, opera-proxy, оба движка Telegram) — релиз-префиксы, sha256 из `manifest.json`, opkg/apk, запасные источники. |
| `platform_dirs.py` | Пути под платформу (Entware `/opt` vs OpenWrt/Linux) — единый источник для всех менеджеров. |
| `kmod_manager.py` | Модули ядра (`nfnetlink_queue`, `xt_*`, `tun`) — детект и загрузка. |
| `update_checker.py` | Проверка обновлений ВСЕХ движков за один проход + фоновой демон по расписанию. Обновление предлагается только для установленного. |
| `system_control.py` | Перезапуск GUI и перезагрузка роутера (отложенно, в отвязанном процессе; на Keenetic — через `ndmc`). |
| `download_transport.py` | «Через что» качать (когда GitHub заблокирован напрямую): `direct`/`awg[:iface]`/`singbox[:cfg]`/`mihomo[:cfg]` → `urlopen_via`. Используется установщиками и рефрешерами. |
| `network_env.py` | Детект окружения: `router` (форвардим LAN) vs `pc` (одна NIC, заворачиваем только себя). Override `network.profile`. |
| `safe_io.py` | Общие безопасные I/O: атомарная запись (`atomic_write_*`: temp→fsync→`os.replace`) и пр. |
| `backup.py` | Экспорт/импорт всей конфигурации в один JSON. |
| `teardown.py` | Снятие всех runtime-артефактов перед удалением. |
| `selfcheck.py` | Самодиагностика на устройстве: зависимости/движки/конфиг/сеть + прогон тестов. CLI: `python3 -m core.selfcheck`. |
| `gui_updater.py` | Самообновление GUI из GitHub (выбор версии + транспорт). |
| `cli.py` | Диспетчер CLI-подкоманд. |

### 5.2 nfqws2 (обход DPI)

| Модуль | Назначение |
|--------|-----------|
| `nfqws_manager.py` | Менеджер процесса nfqws2: compose_command, start/stop/restart, PID-мониторинг. Подхватывает и чужой процесс — поднятый автозапуском (его PID-файл `/var/run/zapret-nfqws.pid`, затем скан `/proc` по демонам); такой помечен `external` в статусе. |
| `nfqws_reload.py` | Горячая перезагрузка списков в живом nfqws2 (SIGHUP): движок читает `--hostlist`/`--ipset` один раз при старте, поэтому правка файла без сигнала ничего не меняет. |
| `zapret_installer.py` | Установка/обновление бинаря nfqws2 (bol-van/zapret2). |
| `strategy_builder.py` | Менеджер стратегий (единый источник: builtin JSON + пользовательские). |
| `strategy_generator.py` | Генерация стратегий «на лету» (параметрические сетки приёмов desync). |
| `strategy_scanner.py` | Автоперебор стратегий против целей, ранжирование от простых к сложным. |
| `strategy_state.py` | Persist выученных стратегий (state.tsv от z2k-state-persist.lua: закреплённая `nstrategy` на домен). |
| `healthcheck.py` | Healthcheck-демон (autocircular watchdog): фоном дёргает референс-домены служб и чинит упавшее. |
| `scan_targets.py` | Профили целей подбора. |
| `catalog_loader.py` / `catalog_merge.py` | Загрузка INI-каталогов стратегий и merge по `section_id` с сохранением локальных секций (используется `asset_importer` при импорте bundled-каталогов). |
| `hostlist_manager.py` | Hostlist'ы доменов nfqws2 (суффикс-матчинг поддоменов). |
| `ipset_manager.py` | IP-списки (ipset/nftset, загрузка по ASN). |
| `blob_manager.py` / `blob_registry.py` | Блобы для fake-пакетов (hex, генерация fake ClientHello). |
| `lua_manager.py` | Lua-скрипты nfqws2. |
| `hosts_manager.py` | `/etc/hosts`. |
| `firewall.py` / `firewall_persistence.py` | Правила перенаправления трафика в nfqws2 + их персистентность. |
| `asset_importer.py` | Импорт bundled-ассетов (blobs/lua/lists) в рабочие директории. |

### 5.3 Тестеры и диагностика — `core/testers/` + `core/`

| Модуль | Назначение |
|--------|-----------|
| `blockcheck.py` | Оркестратор Python-проб: запускает все тестеры, агрегирует вердикт. |
| `blockcheck2.py` | Запуск ОРИГИНАЛЬНОГО `blockcheck2.sh`/`blockcheck.sh` из zapret2 как подпроцесса с потоковой телеметрией в GUI. |
| `models.py` | Модели данных blockcheck (Status/Type enum'ы и пр.). |
| `targets.py` | **Общий** каталог целей: сервисы для карточек «Диагностики» + домены по умолчанию для теста доступности. Добавлять сервис — только здесь. |
| `block_detector.py` | Фоновой мониторинг: домены из живого DNS (dnsmasq/AdGuard/AF_PACKET), периодическая проба, автодобавление в списки. |
| `testers/probe.py` | **Общая** быстрая проба DNS→TCP→TLS→HTTP + единый словарь кодов (`PROBE_CODES`) и их привязка к `DPIClassification`. Ею пользуются `block_detector.py` и DNS-фаза `blockcheck.py`. |
| `testers/tls_tester.py` | HTTPS/TLS-проба через сырой socket (ClientHello-варианты). |
| `testers/tcp_test.py` | Детект DPI, рвущего TCP на 16–20 КБ. |
| `testers/body_tester.py` | Глубокая загрузка тела HTTP(S), детект `FAKE_LEAK`. |
| `testers/quic_tester.py` | QUIC/HTTP-3 (UDP/443) проба. |
| `testers/stun_tester.py` | STUN/UDP-связность. |
| `testers/dpi_classifier.py` | Таксономия ошибок DPI + агрегирование. |
| `testers/isp_detector.py` | Блок-страницы провайдера, HTTP-инъекции, off-domain redirect. |
| `testers/youtube_cdn.py` | Реальные CDN-шарды googlevideo + детект троттлинга. |
| `testers/proxy.py` | Минимальный SOCKS5/HTTP-CONNECT клиент (пробы через прокси). |
| `diagnostics.py` | ping/HTTP/DNS, firewall-статус, **конфликты процессов и окружения** (`check_nfqws_conflicts`, `check_known_conflicts`/`evaluate_conflicts`). |
| `devices_discovery.py` | Устройства LAN (dhcp.leases/ARP). |

### 5.4 Туннели: sing-box, mihomo, AmneziaWG

Каждый движок следует одному паттерну: `*_platform` (пути/init) →
`*_detector` (детект окружения) → `*_installer` (бинарь) → `*_manager`
(CRUD конфигов + up/down) → `*_autostart` (init-скрипт).

| Группа | Модули |
|--------|--------|
| **sing-box** | `singbox_platform`, `singbox_detector`, `singbox_installer`, `singbox_manager`, `singbox_autostart`, `singbox_config` (парсер/валидатор/билдеры outbound'ов + `make_urltest_outbound`/`make_selector_outbound`/`wrap_in_group`), `singbox_transparent` (iptables TProxy/Redirect/Hybrid + `scope='self'` для ПК с 1 NIC), `singbox_transparent_nft` (nftables), `singbox_fakeip` (TUN+FakeIP «умный доменный роутинг»), `singbox_watchdog` (авто-рестарт зависшего инстанса по Clash API). |
| **mihomo** | `mihomo_platform`, `mihomo_detector`, `mihomo_installer`, `mihomo_manager`, `mihomo_autostart`, `clash_yaml` (clash-YAML → sing-box outbound + эмиттер/URI-конвертеры), `mihomo_proxies` (прокси-таблица + Clash API), `mihomo_proxy_tester` (TCP-отсев + e2e через движок). |
| **AmneziaWG** | `awg_platform`, `awg_detector`, `awg_installer`, `awg_keenetic_setup`, `awg_manager`, `awg_config` (парсер `.conf`), `awg_init_script`, `awg_autostart_manager`, `awg_watchdog` (авто-реконнект), `warp_generator`/`warp_importer`/`awg_warp_in_warp` (Cloudflare WARP). |

### 5.5 Подписки и пул серверов

| Модуль | Назначение |
|--------|-----------|
| `subscription_importer.py` | Извлечение URI из текста/base64, классификация схем. |
| `singbox_subscription.py` | URI (`vmess/vless/trojan/ss/hysteria2/tuic`) → sing-box outbound. |
| `subscription_manager.py` | Сохранённые подписки: URL в settings, фоновое автообновление, обёртка в urltest/selector, `fetch_outbounds()`. |
| `server_pool.py` | Пул из публичных источников: реестр источников + пресеты, дедуп, **last-good кэш** (не затирать при пустом), cap, сборка одного конфига `server-pool`, фоновый `PoolRefresher`. |
| `proxy_tester.py` | Гибридный тестер: TCP-отсев + e2e-замер задержки через одноразовый sing-box + Clash API `/proxies/<tag>/delay`. |
| `proxy_traffic.py` | Учёт трафика per-outbound: фоном опрашивает Clash API `/connections` запущенного инстанса (sing-box и mihomo) → колонка «Трафик» в прокси-таблице. |

### 5.6 Списки и единый слой

| Модуль | Назначение |
|--------|-----------|
| `named_lists.py` | Именованные списки доменов/CIDR: `classify_entry`/`parse_entries`, CRUD, `update_fields`. Общее хранилище для единого слоя и nfqws2. |
| `list_updater.py` | Курируемые списки доменов (podkop-стиль): пресеты itdoginfo, `merge_preserving_manual` (сохраняет ручные правки), фоновый `ListRefresher`. |

**`core/unified/`** — единый слой «назначение → метод»:

| Модуль | Назначение |
|--------|-----------|
| `model.py` | `Destination` (domains/cidrs/list_ids/geosite/geoip + `resolve()`), `parse_method`, `UnifiedRoute` (+ селекторы `devices[]`/`dscp`). |
| `storage.py` | Хранилище маршрутов в `settings.json`. |
| `manager.py` | CRUD + применение (тонкая оркестрация для API). |
| `applier.py` | Применение метода: tunnel → routing-rule, nfqws2 → hostlist, direct → снятие; раскладка `devices[]`/`dscp` в производные `DeviceRoutingRule`/`DscpRoutingRule`. |
| `migration.py` | Миграция legacy `routing.rules` (не `uni-*`) в маршруты единого слоя (`mig-<id>`, идемпотентно); `migrate_on_boot()`. |
| `monitor.py` | TLS-проба назначения, история успешности в RAM, фоновый цикл. |
| `failover.py` | Чистая `decide()` (порог/гистерезис/cooldown) + `step()` переключения. |
| `geo_engine.py` | geosite/geoip для `singbox:` — инжекция route-правила через sidecar. |
| `nfqws_hostlist.py` | Агрегат доменов nfqws2-маршрутов → `--hostlist`. |
| `scanner_hint.py` | Связка с strategy-scanner (подбор для деградировавшего nfqws2). |

**`core/routing/`** — низкоуровневый selective routing (под капотом
единого слоя и AWG-routing):

| Модуль | Назначение |
|--------|-----------|
| `manager.py` | `RoutingManager` — оркестратор. |
| `rules.py` / `storage.py` | Типы правил + хранилище. |
| `domain_rule.py` / `device_rule.py` / `dscp_rule.py` | Применение/снятие по типу. |
| `ipset_backend.py` / `nftset_backend.py` / `ndms_backend.py` | Бэкенды (Entware ipset / OpenWrt nftables / Keenetic-native). `choose_backend()` выбирает. |
| `dnsmasq_integration.py` / `doh_resolver.py` | Domain-routing через dnsmasq + DoH-резолв для pre-population set'ов. |
| `alias_resolver.py` | `geosite:`/`geoip:` → списки доменов/подсетей. |
| `masquerade.py` | MASQUERADE/SNAT на исходящий tunnel-интерфейс. |
| `dns_intercept.py` | Перехват DNS-запросов на роутере (заворот на свой резолвер). |
| `domain_refresh.py` | Фоновый пере-резолв доменных правил: IP за доменом меняются, set'ы протухают. |
| `sweeper.py` / `doctor.py` | Уборка осиротевших правил/set'ов + диагностика «почему маршрут не работает». |

**`core/ndms/`** — Keenetic RCI: `rci_client` (HTTP к Router Control
Interface), `commands` (интерфейсы, политики хостов), `wg_discovery`,
`ping_check`.

**`core/connectivity/`** — `matrix` (связность туннелей), `traffic`
(RX/TX-серии в RAM для sparkline).

### 5.7 Прочие движки и фоновые службы

| Модуль | Назначение |
|--------|-----------|
| `usque_manager.py` / `usque_watchdog.py` | WARP/MASQUE через usque: регистрация сессии, TUN-интерфейсы, старт/стоп + авто-реконнект. |
| `warp_in_warp.py` / `warp_in_warp_watchdog.py` | Двойной туннель (`masque_masque` / `masque_awg` / `awg_masque`) и его сторож. |
| `tgproxy_manager.py` / `tgproxy_redirect.py` | Telegram Tunnel: оба движка (`tg-ws-proxy-go`, резервный `tg-mtproxy-client`), секрет и `tg://proxy`, заворот CIDR датацентров. |
| `opera_proxy_manager.py` / `opera_proxy_watchdog.py` / `opera_proxy_chain.py` | Opera VPN (SurfEasy): локальный HTTP/SOCKS5-прокси, сторож с TCP-пробой, цепочка через другой транспорт. |
| `mihomo_config.py` / `mihomo_routing.py` / `mihomo_watchdog.py` | Генерация clash-YAML, доменный роутинг mihomo, авто-рестарт зависшего инстанса. |
| `dns_routing.py` | Правила «домен → свой DNS». Каталог публичных резолверов (DoH/DoT) — в `routing/doh_resolver.py`. |
| `tunnel_monitor.py` / `tunnel_optimizer.py` | Метрики туннелей (rx/tx, latency) / MTU·PMTU, TCP-буферы, BBR по профилям. |
| `auto_remediation.py` | Авто-починка: по сигналам мониторинга поднимает упавшее и переключает метод. |
| `iface_socks.py` | SOCKS-прокси, привязанный к интерфейсу (`SO_BINDTODEVICE`) — регистрация usque/WARP через уже работающий обход. |

---

## 6. Backend: `api/` и REST

Каждый файл `api/<домен>.py` экспортирует `register(app)`, который вешает
роуты. Все они собираются в `api/__init__.py:register_routes(app)`.
Соглашения: `response.content_type = "application/json; charset=utf-8"`,
ответ — dict `{ok: bool, …}`, ошибки — `{ok: false, error: …}` + HTTP-код.
Всего **более 440 роутов** (route-декораторов). Установка из локального
файла во всех трёх установщиках использует общий помощник
`api/_install_upload.py` (multipart → temp → установщик).

| Файл | Префикс | Кратко |
|------|---------|--------|
| `status.py` | `/api/status` | общий статус (+`/network/environment`, `/install/transports`) |
| `control.py` | `/api/start`, `/api/stop`, `/api/restart` | nfqws2 |
| `strategies.py` | `/api/strategies` | стратегии и категории |
| `scan.py` | `/api/scan` | подбор стратегий |
| `blockcheck.py` | `/api/blockcheck` | тестирование/классификация DPI (Python-пробы) |
| `blockcheck2.py` | `/api/blockcheck2` | оригинальный blockcheck2.sh + стрим вывода |
| `zapret_manager.py` | `/api/zapret` | установка/обновление nfqws2 (+`/releases`) |
| `hostlists.py` / `lists.py` | `/api/hostlists`, `/api/lists` | домены nfqws2 / именованные списки (+`/curated`) |
| `ipsets.py` / `blobs.py` / `lua_scripts.py` / `hosts.py` | … | IP-списки / блобы / Lua / hosts |
| `unified.py` | `/api/unified` | единый слой (routes/status/monitor/scan) |
| `routing.py` | `/api/routing` | selective routing + `/interfaces` |
| `awg.py` | `/api/awg` | AmneziaWG (configs/up/down/warp/routing) |
| `singbox.py` | `/api/singbox` | sing-box: configs/outbounds/**proxies**/subscriptions/**pool**/**test**/transparent (scope forward·self)/autostart |
| `mihomo.py` | `/api/mihomo` | mihomo: configs/**proxies**/test/traffic/debug/install (+releases·local)/autostart |
| `usque.py` / `warp_in_warp.py` | `/api/usque`, `/api/warp-in-warp` | WARP/MASQUE: регистрация, туннели, установка / двойной туннель |
| `tgproxy.py` | `/api/tgproxy` | Telegram Tunnel: оба движка, секрет и `tg://proxy`-ссылка, установка/удаление |
| `opera_proxy.py` | `/api/opera-proxy` | Opera Proxy: настройки, страны, старт/стоп, установка |
| `dns_routing.py` | `/api/dns-routing` | правила «домен → свой DNS» |
| `tunnel_monitor.py` / `tunnel_optimizer.py` | … | трафик по туннелям / MTU·буферы·BBR |
| `update_checker.py` | `/api/updates` | проверка обновлений всех движков разом |
| `block_detector.py` / `auto_remediation.py` / `geosite.py` | … | фоновой детектор блокировок / авто-починка / импорт geosite |
| `connectivity.py` / `devices.py` | … | матрица связности / устройства LAN |
| `diagnostics.py` | `/api/diagnostics` | ping/http/dns/conflicts/**known-conflicts**/firewall/system/**selfcheck** |
| `healthcheck.py` | `/api/healthcheck` | autocircular-демон: enable/disable/run/status/config |
| `backup.py` / `config_api.py` / `autostart.py` / `gui_update.py` / `logs.py` | … | бэкап / настройки / автозапуск / обновление GUI (+`/releases`) / логи (SSE) |
| `v1_compat.py` | `/api/v1/*` | алиасы старых путей — чтобы внешние скрипты не сломались при переименованиях |

> Полный список конкретных роутов — в docstring каждого файла `api/*.py`
> (там перечислены методы и пути).

---

## 7. Frontend: `web/` и SPA

- **Без сборки.** `index.html` подключает скрипты тегами; деплой — просто
  копирование файлов.
- **Hash-роутинг.** `#dashboard`, `#routing`, `#singbox-configs`
  и т.д. Роутер в `web/js/` сопоставляет хэш странице. Переехавшие разделы
  перечислены в `HASH_ALIASES` (`app.js`): старый хеш редиректит на новый,
  чтобы закладки и ссылки с дашборда не ломались.
- **Страница-хаб с вкладками.** Хаб монтирует в свои вкладки
  самостоятельные страницы, вызывая их `render/destroy`; под-страницы при
  этом не рисуют собственный `page-header`. Вкладка живёт в query-части
  хеша (`#blockcheck?tab=monitor`) — хаб слушает `hashchange` сам, т.к.
  роутер при том же `pageId` перерисовку не запускает. Так сделаны два
  раздела: `blockcheck_hub.js` (тест доступности + мониторинг DNS) и
  `strategy_scan_hub.js` (официальный blockcheck2.sh + перебор по нашему
  каталогу).
- **Деление разделов.** Подбор стратегий — в «Обход DPI», диагностика — в
  «Диагностике»; «Диагностика» отвечает за устройство и окружение,
  «Диагностика блокировок» — за конкретные домены. Один и тот же
  функционал не должен появляться в двух разделах: если он нужен обоим,
  общей делается реализация (`core/testers/probe.py`, `core/targets.py`),
  а между разделами ставится переход (кнопка «Разобрать»).
- **Каждая страница** (`web/js/pages/*.js`) — IIFE-модуль с
  `render(container)` и `destroy()`. `destroy()` обязан гасить таймеры/
  SSE (см. `diagnostics.js`, `singbox_configs.js` — там есть poll-таймеры).
- **API-хелпер** `web/js/api.js`: `API.get/post/put/delete(path, body)` →
  Promise(JSON), бросает на ошибке.
- **Компоненты** `web/js/components/`: `sidebar` (меню + мобильный бургер),
  `toast` (`Toast.success/error/info/warning`), `list_ui` (универсальные
  списки), `sparkline` (inline-SVG графики), `help` (модалка с примерами,
  кнопка «?»), `theme` (тема ☾/☀). Переиспользуемые блоки разделов:
  `setup_ui` (общий «Окружение» + «Установка», + под-компонент
  `InstallExtras` — версия/транспорт/локальный файл), `proxy_table`
  (общая прокси-таблица sing-box/mihomo), `transport_select` (селект
  «Качать через»), `expert` (режим «эксперт» — CSS-классы `.expert-only`/
  `.expert-note`, галка в футере).
- **Утилиты** `web/js/utils/`: `autocomplete`, `debounce`, подсветка
  синтаксиса (`syntax`, `lua_syntax`).

**Добавить страницу:** создать `web/js/pages/foo.js` (IIFE с
`render/destroy` + объект `FooPage`), подключить в `index.html`,
зарегистрировать в роутере и в `sidebar`. Вызовы — через `API.*`; HTML
экранировать (в каждой странице есть локальные `esc/escAttr`).

---

## 8. Фоновые воркеры

Все — daemon-потоки в синглтонах, поднимаются из boot-хуков `app.py`,
имеют `reconfigure()` (запустить/остановить по факту наличия работы):

| Воркер | Модуль | Что делает |
|--------|--------|-----------|
| Подписки | `subscription_manager.SubscriptionRefresher` | тянет подписки по `interval_hours` (через выбранный транспорт), пересобирает конфиг |
| Пул серверов | `server_pool.PoolRefresher` | пересобирает `server-pool` по таймеру (транспорт `singbox.pool.transport`) |
| Курируемые списки | `list_updater.ListRefresher` | обновляет named-lists с `source_url` (транспорт `lists.transport`) |
| Мониторинг единого слоя | `unified.monitor._MonitorLoop` | TLS-пробы назначений + `failover.step()` |
| Watchdog AWG | `awg_watchdog` | проба через туннель + handshake-age → рестарт |
| Watchdog sing-box | `singbox_watchdog` | связь по Clash API → авто-рестарт зависшего инстанса |
| Healthcheck (autocircular) | `healthcheck` | дёргает референс-домены служб → авто-починка |
| Трекер трафика прокси | `proxy_traffic` | опрос Clash API `/connections` → суммы per-outbound (пока инстанс жив) |
| Тестер прокси | `proxy_tester._TestJob` | разовый фоновый прогон (start → poll status) |

Общий паттерн «не затирать при пустом»: если внешний источник вернул
пусто/ошибку — используется прошлый успешный результат (last-good кэш),
а текущее состояние не перезаписывается. Реализован в
`server_pool` (per-source кэш) и `list_updater` (`merge_preserving_manual`).

---

## 9. Конфигурация (`settings.json`)

Единый файл (по умолчанию `/opt/etc/zapret-gui/settings.json`), читается
через `get_config_manager()`. Ключевые секции:

```jsonc
{
  "gui":    { "port": 8080, … },
  "zapret": { "base_path": "/opt/zapret2", "lists_path": …, "ipset_path": … },
  "nfqws":  { "ports_tcp": "80,443,…", "ports_udp": "…", "unified_hostlist": false },
  "install":{ "mirror": "", "tmpdir": "" },
  "network": { "profile": "auto" },         // auto | router | pc (детект 1 NIC)
  "lists":  { "transport": "" },            // транспорт автообновления курир. списков
  "named_lists": [ { id, name, domains[], cidrs[], source_url, interval_hours,
                     _remote, last_status, … } ],
  "singbox": {
    "subscriptions": { "<id>": { name, url, format, interval_hours, group, transport, … } },
    "pool": { "sources": {…}, interval_hours, group, cap, health_filter, target,
              transport, last_status, … },
    "watchdog": { "enabled": false, … }
  },
  "healthcheck": { "enabled": false, … },   // autocircular-демон
  "awg": { "watchdog": { "enabled": false, … }, … },
  "unified": { "routes": [ … ] },   // маршруты единого слоя (+ devices/dscp)
  "routing": { … }                  // legacy selective-routing (мигрируется в unified)
}
```

Рядом с `settings.json` лежит `.server_pool_cache.json` (last-good
outbound'ы по источникам). Конфиги движков — отдельные файлы на диске
(каталоги выбираются `*_platform.config_dir`).

> Новое поле настроек — добавляй в `DEFAULT_CONFIG` (`config_manager.py`),
> deep-merge подтянет его в существующие установки. Сохранение — всегда
> `get_config_manager().save()` (НЕ `config_manager.save_config()` —
> такой функции нет, это историческая ловушка).

---

## 10. Платформенная абстракция

Поддерживаются: **Keenetic/Entware** (S99 init.d, iptables+ipset, RCI),
**OpenWrt 22+** (procd, nftables+nftset), **generic Linux** (systemd,
iptables/nftables).

- Пути и init-скрипты — в `*_platform.py` каждого движка.
- Бэкенд firewall/routing выбирается `routing.choose_backend()` (iptables
  приоритетнее на Keenetic, nft на OpenWrt 22+).
- Keenetic-специфика (политики хостов, нативные WG) — `core/ndms/`.
- Установка не в `/tmp` на OpenWrt — `binary_installer.workbase()`.

---

## 11. Сборка, пакеты, релиз

```bash
make ipk           # Entware/Keenetic .ipk → dist/
make openwrt-ipk   # OpenWrt .ipk
make lint          # проверка синтаксиса всех .py
make release VERSION=X.Y.Z   # бампит версию, ставит тег → CI публикует
```

- `packaging/entware/` и `packaging/openwrt/` — control-файлы и init-
  скрипты пакетов.
- **CI** (`.github/workflows/`):
  - `release.yml` — сборка и публикация основного пакета;
  - `build-awg-binaries.yml` — кросс-сборка `amneziawg-go`/`-tools` (тег
    `awg-bin-vX`);
  - `build-singbox-binaries.yml` — сборка sing-box под платформы.
- Версия — единый источник `core/version.py`.

---

## 12. Тесты и линт

```bash
python3 -m unittest discover tests          # весь набор (95 файлов, >1600 тестов)
python3 -m unittest tests.test_server_pool  # точечно
python3 -m pytest -q                         # то же самое, если стоит pytest (опц.)
make lint
```

> На целевых устройствах pytest обычно нет — основной прогон через
> `unittest`. То, что dev-окружение не может проверить (зависит от
> системных утилит), гоняется на устройстве: `python3 -m core.selfcheck`.

- Харнесс API-тестов — `tests/_wsgi_client.py` (`WSGIClient` +
  `build_test_app()`): гоняет реальные роуты через WSGI без сети.
- Юнит-тесты конфиг-зависимых модулей мокают `get_config_manager`
  (фейк с `get/set/save/load`); пример — `tests/test_named_lists.py`,
  `tests/test_server_pool.py`.
- **Чистую логику выноси в отдельные функции** — её и тестируем без I/O
  (`evaluate_conflicts`, `merge_preserving_manual`, `failover.decide`,
  `proxy_tester.parse_delay/build_test_config`).
- Зависимости для тестов: ставить ничего не нужно — bottle встроен
  (`vendor/bottle.py`, подключается `ensure_bottle()` в
  `tests/_wsgi_client.py`), `python3 -m unittest discover tests` проходит
  в чистом окружении. Опционально: `pip install pyyaml pytest`.

---

## 13. Соглашения и «куда добавить X»

**Соглашения:**

- Бэкенд и комментарии — по-русски (как в существующем коде); сообщения
  логов — через `log.*(msg, source="…")`.
- Сетевые запросы — `urllib` с таймаутом и лимитом размера; всегда
  обрабатывай `HTTPError/URLError/OSError`.
- Менеджеры — синглтоны через `get_*()` с double-checked локом.
- Firewall/routing — только свои цепочки/таблицы, идемпотентно
  (apply повторно = без дублей, remove чистит за собой).
- Не модель `cm.load() or {}` — пустой валидный dict ложноотрицателен;
  используй `cfg = cm.load(); if not isinstance(cfg, dict): cfg = {}`.

**Шпаргалка «куда идти»:**

| Хочу… | Иду в… |
|-------|--------|
| новый протокол подписки | `singbox_subscription.py` (+`_HANDLERS`), `singbox_config.py` (билдер outbound), `subscription_importer._KNOWN_SCHEMES` |
| новый источник серверов/списков | пресеты в `server_pool.BUILTIN_PRESETS` / `list_updater.CURATED_PRESETS` |
| новый тип routing-правила | `core/routing/rules.py` + `*_rule.py` + бэкенды + `unified/model.METHOD_KINDS` если метод |
| новый сетевой тест | `core/testers/`, подключить в `blockcheck.py` |
| новый REST-эндпоинт | `api/<домен>.py` (`register`), задокументировать в docstring |
| новую страницу UI | `web/js/pages/*.js` + `index.html` + роутер + `sidebar` |
| новый фоновый воркер | синглтон с `reconfigure()` + регистрация в boot-хуках `app.py` |
| новую настройку | `DEFAULT_CONFIG` в `config_manager.py` |
| поддержку новой платформы/бэкенда | `*_platform.py` движка + `routing.choose_backend()` |

---

Вопросы по конкретному модулю — смотри его docstring (первые строки
файла обычно объясняют назначение и формат данных) и связанный
`tests/test_<модуль>.py`.
