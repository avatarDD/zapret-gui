# Аудит мёртвого кода

Дата: 2026-08-14. Ревизия: ветка `claude/unused-code-audit-d9qjvn`.

Инвентаризация кода, который не вызывается ниоткуда. **Ничего не удалено** —
это список кандидатов на удаление с обоснованием по каждому пункту.

## Как проверялось

Кросс-референс по всему репозиторию, а не один линтер:

1. **AST-разбор** всех 199 модулей `app.py` / `api/` / `core/` / `tools/` —
   собраны все определения (функции, методы, классы, модульные константы).
2. **Сбор ссылок** из всех 355 `.py` файлов (включая `tests/`): `Name`,
   `Attribute`, `alias` в импортах **и строковые литералы** — чтобы не
   пропустить `getattr`-диспетчеризацию и таблицы имён.
3. **Текстовые ссылки** из `web/**/*.js`, `*.html`, `*.css`, `*.md`, `*.sh`,
   `Makefile`, `packaging/` — фронтенд-вызовы и упоминания в документации.
4. **Отдельно роуты**: все 451 bottle-роута сопоставлены с вызовами из
   `web/js` с учётом шаблонной интерполяции (фронт строит пути вида
   `` `/api/singbox/configs/${name}/${op}` `` — наивное сравнение строк даёт
   ~130 ложных «мёртвых» роутов, поэтому сверка идёт по префиксам групп).
5. **Транзитивный проход**: что становится мёртвым после удаления
   первичного множества.
6. Дополнительно `vulture` и `ruff` (F401/F841/ARG/ERA) как перекрёстная
   проверка.

Ложные срабатывания отсеяны вручную — см. раздел «Проверено, НЕ удалять».

**Итого твёрдых кандидатов: ~810 строк Python**, плюс 45 импортов,
11 i18n-ключей и ~17 CSS-классов.

---

## A. Подсистема geosite — мертва целиком (474 строки) — ✅ УДАЛЕНО

> Выполнено. Удалены `api/geosite.py`, `core/geosite_importer.py`,
> `core/dns_providers.py`, `tests/test_geosite_importer.py`,
> `tests/test_dns_providers.py`, класс `TestGeositeEnumFix` из
> `tests/test_dev_merge_regressions.py`, регистрация в `api/__init__.py`,
> строки в `CoderManual.md` и `TESTING_PLAN.md`. Историческая таблица
> дефектов в `TESTING_PLAN.md` (строки 130, 146) сохранена намеренно — это
> лог найденного, а не живой индекс.
>
> Проверка: 2670 → 2652 теста (минус ровно 18 удалённых, пересчитано
> поимённо), 0 падений, `make lint` чист, JS 11/11, `register_routes`
> поднимает 760 роутов, geosite-роутов не осталось, живой
> `doh_resolver` цел.
>
> Расхождение каталогов зафиксировано в `CHANGELOG.md`: в мёртвом файле
> было 13 DNS-провайдеров против 3 в живом `doh_resolver.KNOWN_PROVIDERS`.



Самая крупная находка. Три модуля образуют замкнутую цепочку, в которую
никто не входит: у `/api/geosite/*` **нет ни одного вызова** из `web/js`
(страницы `geosite.js` не существует), из `core/cli.py` и из документации.
Упоминания слова «geosite» во фронтенде относятся к другой живой фиче —
полю `geosite` в `routing_unified.js` и `mihomo.js`, которое уходит в
`/api/mihomo/*` и `/api/routing/*`, а не сюда.

| Файл | Строк | Почему мёртв |
|---|---|---|
| `api/geosite.py` | 74 | 3 роута (`/providers`, `/categories`, `/import`), зарегистрированы в `api/__init__.py:84`, но не вызываются ниоткуда |
| `core/geosite_importer.py` | 280 | `parse_geosite` / `import_category` — только из `api/geosite.py`; `list_categories` (:45) — вообще ниоткуда |
| `core/dns_providers.py` | 120 | `list_providers` — только из `api/geosite.py`; `list_doh` / `list_dot` / `get_provider` — только из тестов |

Важно: `core/dns_providers.py` — **дубликат живого механизма**. Работающие
DoH-настройки идут через `core/routing/doh_resolver.py` (`KNOWN_PROVIDERS`,
роуты `/api/routing/doh*`, которые фронт действительно зовёт). Два
независимых списка DNS-провайдеров в одном проекте — источник расхождений.

Удаление тянет за собой `tests/test_geosite_importer.py`,
`tests/test_dns_providers.py` и часть `tests/test_dev_merge_regressions.py`
(3 теста на `_parse_domain_entry`), плюс строку в `CoderManual.md:448`.

**Решение за вами:** если geosite-импорт — задел на будущее, а не
заброшенная фича, его надо не удалять, а дотянуть до UI. В таком виде он
не работает никак.

## B. Фича «категории сервисов» — мертва целиком (~55 строк)

`api/strategies.py`. Роуты `/api/categories` (GET/PUT) не вызываются ни
фронтом, ни CLI; вместе с ними мертвы все их приватные помощники — больше
на них никто не ссылается.

| Место | Что |
|---|---|
| `api/strategies.py:508-514` | `api_categories_list` — роут GET |
| `api/strategies.py:516-566` | `api_categories_update` — роут PUT |
| `api/strategies.py:568-574` | `_get_categories_path` |
| `api/strategies.py:576-596` | `_load_categories` (+ дефолтный список из 6 категорий) |
| `api/strategies.py:598-605` | `_save_categories` |
| `api/strategies.py:27-29` | `_CATEGORIES_LOCK` — используется только в мёртвом `api_categories_update` |

Также перестаёт быть нужен `config/categories.json`, если он существует.

## C. Функции и классы с нулём ссылок (~279 строк)

Каждый пункт проверен grep'ом по всему репозиторию: имя встречается
ровно один раз — в собственном определении.

| Файл:строки | Строк | Символ |
|---|---|---|
| `core/awg_installer.py:322-382` | 61 | `AwgInstaller._resolve_release_tag` — поиск релиза с manifest.json |
| `core/blockcheck.py:1363-1406` | 44 | `BlockcheckRunner._build_summary_stats` |
| `core/ndms/commands.py:465-507` | 43 | `NdmsCommands.apply_domain_route` |
| `core/catalog_loader.py:588-624` | 37 | `CatalogManager.search_entries` — поиск по имени/автору/описанию |
| `core/awg_keenetic_setup.py:85-98` | 14 | `generate_install_instructions` |
| `core/ndms/commands.py:509-522` | 14 | `NdmsCommands.remove_domain_route` |
| `core/strategy_scanner.py:1503-1511` | 9 | `StrategyScanner._probe_tls` |
| `core/devices_discovery.py:614-621` | 8 | `get_device_by_ip` |
| `core/warp_generator.py:384-391` | 8 | `_extract_client_id_reserved` |
| `core/routing/domain_rule.py:1111-1117` | 7 | `reapply_all_domain_rules` |
| `core/catalog_merge.py:154-158` | 5 | `_merge_file` |
| `core/models.py:111-115` | 5 | `class ScanMode(Enum)` — сканер использует строки, не enum |
| `core/tunnel_monitor.py:328-332` | 5 | `TunnelMonitor.is_in_grace_period` |
| `core/models.py:118-121` | 4 | `class ScanProtocol(Enum)` — то же |
| `core/unified/failover.py:33-36` | 4 | `set_params` — «настраиваемые пороги», которые никто не настраивает |
| `core/awg_warp_in_warp.py:448-450` | 3 | `get_state` |
| `core/ext_binary_installer.py:279-281` | 3 | `github_latest_release` — шим «для совместимости со старыми тестами», которые его не зовут |
| `core/models.py:549-551` | 3 | `CatalogEntry.display_name` — property; в `to_dict()` не попадает, снаружи не читается |
| `core/unified/failover.py:39-40` | 2 | `get_params` |

Два уточнения:

- `apply_domain_route` / `remove_domain_route` (57 строк вместе) — парная
  NDMS-фича «FQDN-группа + dns-proxy route». Мертва как пара; отдельные
  примитивы `upsert_fqdn_group` / `delete_fqdn_group` живы, их зовут из
  других мест.
- `set_params` / `get_params` в `core/unified/failover.py` — комментарий над
  `_PARAMS` обещает «настраиваемые через `set_params`» пороги, но вызовов
  нет. Либо выкинуть обе функции, либо поправить комментарий.

## D. Роуты, зарегистрированные, но не вызываемые (5)

Не считая групп A и B. Проверено с учётом шаблонной интерполяции путей.

| Роут | Файл | Замечание |
|---|---|---|
| `POST /api/remediation/run` | `api/auto_remediation.py:23` | фронт зовёт только `/apply` (`help.js:1260`) |
| `GET /api/remediation/results` | `api/auto_remediation.py:56` | то же |
| `POST /api/monitor/start` | `api/tunnel_monitor.py:29` | `tunnel_monitor.js` зовёт только `/metrics` и `/status` |
| `POST /api/monitor/stop` | `api/tunnel_monitor.py:35` | то же |
| `GET /api/ping` | `api/status.py:291` | health-check; **предлагаю оставить** — 4 строки, типовая точка для внешнего мониторинга |

## E. Код, живой только ради тестов (18 функций)

Не мёртв формально, но продакшн-путей не имеет: единственный вызов — из
`tests/`. Каждый — кандидат либо на удаление вместе с тестом, либо на
осознанное решение «это публичный API модуля».

| Файл:строка | Символ | Тест |
|---|---|---|
| `core/awg_platform.py:140` | `AwgPlatform.uapi_path` | `test_awg_manager_lifecycle.py` |
| `core/blob_registry.py:192` | `reload_registry` | `test_blob_registry.py` |
| `core/blob_registry.py:200` | `get_blob_value` | `test_blob_registry.py` |
| `core/dns_providers.py:105` | `list_doh` | `test_dns_providers.py` (см. A) |
| `core/dns_providers.py:110` | `list_dot` | `test_dns_providers.py` (см. A) |
| `core/dns_providers.py:115` | `get_provider` | `test_dns_providers.py` (см. A) |
| `core/ext_binary_installer.py:749` | `get_install_status` | `test_ext_binary_installer.py` |
| `core/network_env.py:197` | `is_pc_profile` | `test_network_env.py` |
| `core/network_env.py:205` | `reset_cache` | `test_network_env.py` |
| `core/routing/alias_resolver.py:97` | `is_alias` | `test_alias_resolver.py` |
| `core/routing/ipset_backend.py:88` | `flush_set` | `test_ipset_backend.py` |
| `core/routing/nftset_backend.py:162` | `flush_set` | не зовётся даже тестом |
| `core/routing/storage.py:51` | `save_rules` | `test_routing_storage.py` |
| `core/singbox_transparent.py:621` | `reset_tproxy_cache` | `test_singbox_transparent.py` |
| `core/singbox_transparent_nft.py:211` | `build_ipv6_block_fragment` | `test_singbox_transparent_nft.py` |
| `core/unified/model.py:74` | `method_iface` | `test_unified_model.py` |
| `core/unified/model.py:83` | `is_tunnel_method` | `test_unified_model.py` |
| `core/unified/monitor.py:84` | `last_ok` | `test_unified_monitor_failover.py` |

`flush_set` есть в обоих backend'ах (`ipset_backend`, `nftset_backend`) —
парный API, из которого ни одну половину не использует продакшн-код, а
nft-версию не трогает и тест. Удалять только парой, иначе backend'ы
разъедутся по интерфейсу.

## F. Мусор внутри живых функций

### Неиспользуемые локальные переменные (`ruff F841`, 6)

| Место | Переменная | Замечание |
|---|---|---|
| `api/control.py:118` | `fw_ok` | `fw.remove_rules()` вызывается ради побочного эффекта, результат теряется — **проверьте, не потерянная ли это проверка ошибки** |
| `core/auto_remediation.py:256` | `cfg` | |
| `core/routing/dnsmasq_integration.py:1041` | `env` | |
| `core/strategy_scanner.py:818` | `good` | `f.get("good", [])` из `DPI_FILTERS` читается и выбрасывается |
| `core/strategy_scanner.py:824` | `args_list` | вычисляется в цикле для каждой стратегии — лишняя работа на каждой итерации |
| `core/testers/tcp_test.py:115` | `e` | `except ... as e` без использования |

`fw_ok` и `good` стоит посмотреть глазами: это может быть не мусор, а
недоделанная логика (у `DPI_FILTERS` есть ключ `good`, который нигде не
влияет на фильтрацию).

### Неиспользуемые импорты (`ruff F401`, 45)

Чинится автоматически: `ruff check --select F401 --fix app.py api/ core/ tools/`.
Типовой случай — `from core.log_buffer import log` в API-модулях, где
логирование потом убрали (`api/auto_remediation.py:17`, `api/geosite.py:15`
и др.), и `from bottle import request, response`, где нужен только один.

### Неиспользуемые аргументы (`ruff ARG`, ~20)

Большинство — обязательные сигнатуры фреймворка (`error404(error)`,
`options_handler(path)`, обработчик сигнала `(signum, frame)`), их трогать
нельзя. Реальные кандидаты:

| Место | Аргумент |
|---|---|
| `core/singbox_autostart.py:195-196` | `pids_dir`, `logs_dir` |
| `core/singbox_config.py:207-208` | `sniff`, `mark` |
| `core/singbox_transparent.py:216` | `dns_hijack` |
| `core/singbox_transparent.py:844` | `backend` |
| `core/strategy_scanner.py:849` | `index` |
| `core/strategy_scanner.py:1436` | `body_ok_count` |
| `core/awg_manager.py:1204` | `cfg` |

Это параметры, которые вызывающий код передаёт, а функция игнорирует —
то есть настройка молча не применяется. Стоит проверить каждый: у
`dns_hijack` и `sniff` цена ошибки — «опция в UI есть, эффекта нет».

## G. Фронтенд

### i18n: 11 мёртвых ключей из 23

`web/js/i18n/ru.js` и `en.js`, строки 14-25 в обоих файлах — весь блок с
точечными именами. Ни один не проходит через `i18n.t()` / `_t()`:

```
error.page_not_found   error.generic          common.loading
common.yes             common.no              common.save
common.cancel          common.delete          common.confirm_delete
page.not_found_title   page.not_found_message
```

Первые 12 ключей файла (`warp_masque`, `status_running`, `seconds_ago` …)
используются — их не трогать. Оба файла синхронны: расхождений ru/en нет.

### CSS: ~17 неиспользуемых классов

`web/css/style.css`. Проверено с учётом динамической сборки имён.

Группа «утилиты, которые не прижились» — ни одного вхождения в js/html:
`.flex-col`, `.items-center`, `.justify-between`, `.gap-8`, `.mt-8`,
`.mt-16`, `.mb-8`, `.mb-16`, `.text-mono`, `.text-warning`, `.btn-warning`,
`.table-wrap`.

Группа «остатки переделанных страниц»: `.tab-badge`, `.strat-filter`,
`.strategy-actions`, `.has-search-match`, `.list-loading`.

Остальные 44 «неиспользуемых» класса из первичной выборки — **ложные
срабатывания**, имена собираются конкатенацией, удалять нельзя:
`.log-level-*` (`logs.js:496`), `.logs-conn-*` (`logs.js:696`), `.mrh-*`
(`strategies.js:2361`), `.nfq-diag-*` (`strategies.js:1992`), а также
префиксные группы `.asn-*`, `.hl-*`.

### JS: чисто

Все 66 файлов из `web/js/` подключены в `index.html`, лишних и
отсутствующих нет. Из 1319 определений функций (`function name()` и
стрелочные в `const`/`let`/`var`) **не нашлось ни одной без ссылок** —
детектор проверен внедрением заведомо мёртвых проб, обе поймались.

---

## Проверено, НЕ удалять (ложные срабатывания)

Пункты, которые линтеры уверенно помечают как мёртвые, но которые вызывает
фреймворк через динамическую диспетчеризацию:

| Место | Почему живо |
|---|---|
| `app.py:88` `QuietHandler.log_request` | override `WSGIRequestHandler.log_request`, зовёт wsgiref |
| `core/download_transport.py:389` `http_open` | urllib зовёт по имени `<протокол>_open` из `OpenerDirector` |
| `core/download_transport.py:400` `https_open` | то же |
| `app.py:660` `options_handler` (`/api/<path:path>`) | CORS preflight от браузера |
| `app.py:673/677/681/686` `serve_css` / `serve_js` / `serve_img` / `favicon` | статика, запрашивает браузер |
| ~460 обработчиков роутов в `api/*.py` | регистрируются декоратором `@app.route`, вызываются bottle |
| `.log-level-*`, `.logs-conn-*`, `.mrh-*`, `.nfq-diag-*` | имена классов собираются конкатенацией |
| Модули без импорта | таких нет — все 199 модулей импортируются |

Отдельно: 32 срабатывания `ruff ERA001` («закомментированный код») —
почти все ложные, это заголовки файлов вида `# core/asset_importer.py` и
обычные комментарии. Отдельного разбора не требуют.

---

## Порядок работ, если удалять

1. **A + B** — самое крупное и безопасное: замкнутые подсистемы, внешних
   зависимостей нет. ~530 строк за один заход. Не забыть тесты,
   `api/__init__.py:45,84` и `CoderManual.md:448`.
2. **F, неиспользуемые импорты** — `ruff --fix`, механическая правка.
3. **C** — по одному символу, каждый с проверкой git-истории: часть могла
   быть добавлена «на будущее» под конкретную задачу.
4. **G** — i18n и CSS, изолированно от бэкенда.
5. **E** — только после решения, считаем ли мы это публичным API модулей.
6. **F, аргументы и переменные** — не механическая правка: сначала
   выяснить, мусор это или недоделанная логика (`fw_ok`, `good`,
   `dns_hijack`, `sniff`).

Скрипты анализа не коммитились — при необходимости перепроверить, весь
метод описан в разделе «Как проверялось».
