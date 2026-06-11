# Крупные задачи на следующую сессию (handoff)

Этот документ — план **крупных** задач, согласованных с владельцем проекта,
которые решено делать отдельной сессией. Написан так, чтобы новый чат (без
истории предыдущего) сразу понял контекст и мог приступить.

## Контекст проекта

`zapret-gui` — веб-GUI (бэкенд Python + микрофреймворк **Bottle**, фронтенд —
ванильный JS без сборки) для управления обходом блокировок на роутерах
**Keenetic (Entware)**, а также OpenWrt / Linux. Управляет: nfqws2/zapret2,
AmneziaWG (AWG), sing-box, mihomo, маршрутизацией (policy routing), firewall.

- Рабочая ветка: `claude/festive-pascal-o49x2x`.
- Язык интерфейса и комментариев — **русский**.
- Тесты — `unittest` (pytest не установлен). Прогон: `python3 -m unittest tests.test_<name>`.
  ВАЖНО: в dev-окружении нет модуля `bottle`, поэтому тесты, импортирующие
  `api/*`, локально падают на импорте — это ограничение окружения, не баг.
  Проверяй `core/*` тестами + `python3 -m py_compile` и `node --check` для JS.
- Каталог конфига (постоянный носитель) — где лежит `settings.json`
  (`get_config_manager().path`). На Entware обычно на USB.

### Карта кода (якоря)

- Установка/детект/версии: `core/{awg,singbox,mihomo}_installer.py`,
  `core/{awg,singbox,mihomo}_detector.py`; API `api/{awg,singbox,mihomo}.py`.
- Менеджеры жизненного цикла: `core/{awg,singbox,mihomo}_manager.py`.
- Прокси-таблица (эталон UI) — `web/js/pages/singbox_proxies.js`
  (таблица серверов, мультивыбор, сортировка, тест TCP+e2e, copy/paste
  share-ссылок, активация, трафик через clash_api, debug-флаги «битый ключ»).
- Установка как эталон отображения версий — `web/js/pages/awg_setup.js`
  (installed vs latest из manifest, нормализация версий).
- sing-box установка — `web/js/pages/singbox_setup.js`.
- mihomo — ОДНА страница `web/js/pages/mihomo.js` (нет отдельного раздела
  установки и нет прокси-таблицы).
- Маршрутизация: глобальная — `web/js/pages/routing_unified.js`
  (`/api/unified/*`, ядро `core/unified/`); AWG-правила —
  `web/js/pages/awg_routing.js` (`/api/routing/*`, ядро `core/routing/`).
  ФАКТ: `core/unified/applier.py` делегирует в `core/routing` — это слои, а
  не два конфликтующих движка.
- Прозрачное проксирование (для single-NIC): `core/singbox_transparent.py`,
  `core/singbox_transparent_nft.py`, `core/firewall.py`.
- Автообновлятели по таймеру: `core/list_updater.py` (`get_list_refresher`),
  `core/subscription_manager.py` (`get_refresher`), `core/server_pool.py`
  (`get_pool_refresher`) — стартуют на boot в `app.py` (~441-455).
- Навигация/разделы: `web/js/components/sidebar.js`.
- Декларативные настройки: `web/js/pages/settings.js` (массив `SECTIONS`).
- Подсказки: `web/js/components/help.js`.

### Уже сделано в предыдущих сессиях — НЕ переделывать

- `8d6e0bf` — mihomo `mihomo -t` теперь с `-d <config_dir>` (искал geo-базы не
  там); валидация проверяет содержимое редактора (несохранённое); polling-
  фолбэк для real-time логов (SSE часто режется KeenDNS/прокси); установка
  sing-box стала асинхронной (локальная часть сразу, проверка релиза — в фоне).
- `159b640` — персистентный лог критичных событий (WARNING+ рядом с
  `settings.json`, переживает ребут; галка в Настройки→Логирование, ВКЛ по
  умолчанию; `GET /api/logs/persistent`, ссылка «Сохранённый лог»); лимит
  памяти amneziawg-go GOGC/GOMEMLIMIT (карточка в AWG→Дашборд,
  `/api/awg/go-memory`, ВЫКЛ по умолчанию); подсказка на вкладке WARP-in-WARP;
  фикс гонки SSE-слушателей в `core/log_buffer.py`.
- Самодиагностика (`core/selfcheck.py`): проверка зависимостей (python-
  модули вкл. bottle, системные утилиты), движков (zapret2/AWG/sing-box/
  mihomo), конфигурации, сети + прогон юнит-тестов подпроцессом — прямо на
  устройстве, с записью в лог (source=selfcheck). GUI: Диагностика →
  «Самодиагностика» (`POST /api/diagnostics/selfcheck` + `/status`, фон).
  CLI без bottle: `python3 -m core.selfcheck [--no-tests|--pattern|--json]`
  — именно так проверять то, что dev-окружение прогнать не может.

---

## Крупные задачи (нумерованный план)

### 1. Раздел установки mihomo + унифицированное отображение версий (awg/sing-box/mihomo)
**Цель.** У mihomo нет отдельного раздела установки (всё свалено в
`mihomo.js`). Сделать его «как у sing-box»: отдельная страница установки с
окружением (платформа/TUN/firewall), текущей установленной версией и
актуальной версией из репозитория, прогрессом установки/обновления/удаления.
Заодно привести отображение версий sing-box и mihomo к виду AWG (installed vs
latest с нормализацией версии).
**Объём/требования.**
- Новая страница `web/js/pages/mihomo_setup.js` по образцу `singbox_setup.js`,
  пункт в `sidebar.js` (mihomo → Установка).
- Показ «установлено X / в релизе Y / доступно обновление», асинхронно, с
  индикатором «проверяю…» (как уже сделано для sing-box — НЕ блокировать
  открытие сетевым запросом к GitHub).
- Бэкенд у mihomo уже есть: `/api/mihomo/{environment,install,install/status,
  version,uninstall}` + `core/mihomo_installer.py`. Доп. бэкенд, скорее всего,
  не нужен — только фронт.
**Приёмка.** Раздел открывается мгновенно; видны обе версии; установка/
обновление/удаление работают с прогрессом; sing-box и mihomo показывают версии
единообразно.

### 2. Прокси-таблица и режим отладки для mihomo (паритет с sing-box)
**Цель.** Сейчас в mihomo прокси правятся только сырым YAML. Сделать таблицу
прокси как в `singbox_proxies.js` + режим отладки.
**Объём/требования.**
- `web/js/pages/mihomo_proxies.js`: таблица (имя/тип/адрес/задержка/трафик),
  мультивыбор, сортировка, тест прокси, copy/paste share-ссылок, активация
  выбранного, индикация «битых» прокси (debug).
- Бэкенд: парсер `proxies` из clash-YAML (есть `core/clash_yaml.py`),
  эндпоинты в `api/mihomo.py` (тест прокси, список/CRUD прокси, при наличии —
  трафик/переключение через external-controller mihomo, RESTful Clash API).
- Режим отладки mihomo (по аналогии с sing-box debug — см.
  `tests/test_singbox_debug.py`, `core/singbox_manager.py`).
**Приёмка.** Прокси mihomo видны и управляются таблицей без правки YAML; есть
тест и debug-режим.
**✅ Сделано (эта сессия).** Страница `web/js/pages/mihomo_proxies.js` (таблица
имя/тип/адрес/задержка/трафик, мультивыбор, сортировка, copy/paste ссылок,
активация выбранного), пункт «Прокси» в `sidebar.js`. Бэкенд: новые эндпоинты в
`api/mihomo.py` (`/configs/<n>/proxies`, `/activate`, `/enable-controller`,
`/proxies/delete-bulk`, `/import-links`, `/export-links`, `/test`+`/test/status`,
`/traffic`, `/debug`, `/configs/<n>/log`); `core/mihomo_proxies.py` (разбор
proxies, RESTful Clash API: список групп/активный/переключение, текстовые
правки), `core/mihomo_proxy_tester.py` (TCP-отсев + e2e через external-controller
запущенного инстанса или одноразовый mihomo, как у sing-box),
`core/proxy_traffic.py` обобщён под mihomo-трекер (`get_mihomo_traffic_tracker`),
YAML-эмиттер + clash↔URI-конвертеры в `core/clash_yaml.py`, режим отладки
(`log-level=debug` launch-конфиг) и хвост лога в `core/mihomo_manager.py`. Тесты:
`tests/test_mihomo_proxies.py`. NB: round-trip-удаление прокси из таблицы требует
PyYAML (без него — честный отказ, чтобы не повредить сложный конфиг); импорт/
экспорт/тест/трафик/переключение работают и без PyYAML.

### 3. Полная унификация интерфейса awg / mihomo / sing-box / маршрутизации
**Цель.** Единый стиль и логика разделов; общие компоненты вместо копипасты;
всё асинхронно и информативно без зависаний; «всё что можно — автоматизировать»,
расширенный режим — по галке «эксперт»; убрать дублирующийся функционал.
**Объём/требования.**
- Выделить переиспользуемые компоненты: блок «Установка» (версия/прогресс/
  кнопки), «Прокси-таблица», «Окружение». Сейчас паттерн install/version/
  manifest продублирован в singbox и mihomo фронтах — свести в один компонент.
- Единый «эксперт-режим» (галка), скрывающий продвинутые поля по умолчанию.
- Согласовать блоки/подразделы в `sidebar.js` и страницах.
**Приёмка.** Разделы выглядят и ведут себя единообразно; нет дубля кода; для
новичка всё понятно, эксперт включает расширенный режим галкой. Это зависит от
задач 1 и 2 (их компоненты переиспользуются здесь).
**✅ Сделано (эта сессия).** Новые компоненты:
`web/js/components/setup_ui.js` (общий блок «Окружение» + «Установка»:
версии с нормализацией, прогресс, кнопки; singbox/mihomo_setup.js стали
тонкими адаптерами, специфика sing-box — manifest/архитектура/clash_api —
через хуки), `web/js/components/proxy_table.js` (общая прокси-таблица:
выбор/сортировка/тест/copy-paste/активация/трафик/хоткеи;
singbox/mihomo_proxies.js — адаптеры с движко-специфичными баннерами и
методами), `web/js/components/expert.js` (единый режим «эксперт»: галка в
футере сайдбара, localStorage, чисто CSS — `.expert-only` видны только в
эксперт-режиме, `.expert-note` подсказки только в простом). Эксперт-режим
применён: выбор архитектуры (awg_setup + setup_ui), цель теста и debug в
прокси-таблицах, «Отладка» на sing-box-дашборде, fallback/probe и
«Классические инструменты» в routing_unified, поля `expert: true` в
settings.js (NFQUEUE/marks/user/pkt-лимиты/FlowOffload/PostNAT/debug).
Подключение — index.html (скрипты + галка в футере), Expert.init() в
app.js, CSS в style.css. Sidebar уже был согласован задачами 1-2
(Конфиги → Прокси → специфичное → Установка, одинаковые иконки).

### 4. Слияние «AWG-правил» с глобальной «Маршрутизацией» (без потери функций)
**Цель** (согласованная рекомендация по вопросу #5). Сейчас два UI и два
хранилища правил: глобальный (`/api/unified/*`) и AWG-специфичный
(`/api/routing/*`). Сделать ОДИН раздел маршрутизации, где «через что»
(AWG-iface / sing-box / mihomo / напрямую / nfqws2) — это свойство правила, а
«AWG-правила» — **отфильтрованный вид** того же единого движка, а не отдельная
система.
**Объём/требования.**
- Опереться на то, что `core/unified` уже делегирует в `core/routing`.
- Перенести возможности `awg_routing.js` (привязка к iface, dnsmasq/ndms-
  интеграция, устройства) в единый раздел как фильтр/пресет.
- Миграция существующих правил из обоих хранилищ.
**Приёмка.** Один раздel маршрутизации; **ничего из текущего функционала не
потеряно** (явное требование владельца); правила AWG доступны как
отфильтрованный вид; нет двух конфликтующих систем.
**✅ Сделано (эта сессия).** Модель `UnifiedRoute` расширена селекторами
«устройства» (`devices[]` — source IP/MAC/hostname) и «DSCP»
(`dscp`/`dscp_self`) — единый слой покрывает все 4 типа бывших AWG-правил.
`core/unified/applier.py` раскладывает их в производные
`DeviceRoutingRule` (по одному на устройство, id `uni-<route>-dev-<hash>`,
stale-очистка) и `DscpRoutingRule` (`uni-<route>-dscp`); для direct/nfqws2
честно помечает skipped. Новый `core/unified/migration.py`: legacy-правила
из `routing.rules` (не `uni-*`) 1:1 заворачиваются в маршруты
(`mig-<legacy_id>` — идемпотентно), метод `awg:<iface>`/`singbox:<iface>`
по принадлежности iface; авто на boot (app.py, до AWG-автостарта) +
`GET /api/unified/legacy` + `POST /api/unified/migrate`. UI:
`routing_unified.js` — единственный раздел (фильтр «Через» + поиск,
строка/баннер окружения dnsmasq+NDMS с автонастройкой/откатом, выбор
устройств из сети с автообновлением + ручной IP, DSCP с пресетами
(эксперт), баннер миграции legacy-правил); `awg_routing.js` — тонкий
адаптер: та же страница с пресетом «Через: AWG» (старые ссылки
#awg-routing работают). Тесты: `tests/test_unified_migration.py` (новый),
расширены test_unified_{model,applier}, test_api_unified.

### 5. Запуск на обычном ПК с одной сетевой картой (не только роутер)
**Цель.** Дать прогонять трафик через выбранное средство обхода по условной
маршрутизации на машине с 1 NIC (без LAN-форвардинга).
**Объём/требования.**
- Локальный режим: redirect/TPROXY для исходящего трафика самой машины (а не
  форвардинг из LAN). Опереться на `core/singbox_transparent*.py` и
  `core/firewall.py` (там уже есть TProxy/Redirect).
- Корректная работа без ролей WAN/LAN (детект «одна сетевуха»).
- Учесть исключения для локального трафика, чтобы не закольцевать.
**Приёмка.** На обычном Linux-ПК с одной NIC можно завернуть трафик через
awg/sing-box/mihomo по правилам маршрутизации; локальная связность не рвётся.
**✅ Сделано (эта сессия).** Детект окружения: новый `core/network_env.py`
(профиль `router`/`pc`: Keenetic/OpenWrt/Entware либо LAN-мост с физическим
членом → router; docker0/virbr0 из veth профиль не меняют; `single_nic`;
override `network.profile` в settings.json — действует без рестарта, скан
железа кэшируется) + `GET /api/network/environment` (api/status.py, есть
`?refresh=1`) + выбор профиля в Настройки→Интерфейсы. Локальный режим
перехвата: `scope='self'` в `core/singbox_transparent{,_nft}.py`
(apply/remove/reapply_saved + чистые builder'ы) — заворачивается ТОЛЬКО
OUTPUT самой машины: redirect → nat OUTPUT (PREROUTING не трогаем — на
машине с публичным IP он рвал бы входящие SSH/веб), tproxy → mangle OUTPUT
mark + возврат своих пакетов строго `-i lo` с match по метке; анти-петля и
связность: mark-RETURN движка (set_transparent_inbounds теперь выставляет
`route.default_mark`, валидно в 1.8–1.14), `addrtype --dst-type LOCAL`
(свои адреса; мягкая ошибка, если матча нет), `conntrack --ctdir REPLY`
(ответы на входящие соединения), bypass-сети/server_ips; DNS-hijack self
(redirect→NAT_OUT, dns-only+self с mark-RETURN — DNS движка не
зацикливается); IPv6-drop self → цепочка `SBT_V6_OUT` в filter OUTPUT
(nft: `out6`) с теми же исключениями. API: `scope` в
`/api/singbox/transparent/apply` (персистится — переживает ребут через
`--apply-singbox-transparent`), `network` в `/transparent/status`, `mark`
в `/transparent-inbounds`. UI: селектор «Область» (LAN-клиенты / Эта
машина) в singbox.js с авто-предложением self на профиле pc и баннером;
строка «Локальный режим» и подсказка в выборе устройств в
routing_unified.js (unified-правила домен/CIDR уже маркируют OUTPUT —
на ПК работают как есть; nfqws2 через POSTROUTING тоже). Тесты:
`tests/test_network_env.py` (новый), расширены
test_singbox_transparent{,_nft}.py (self-scope builders + apply-wiring +
default_mark + scope в reapply). Не сделано сознательно: mihomo/awg на ПК
идут через unified-маршруты (OUTPUT-mark ipset-бэкенда) и TUN — отдельный
transparent-режим им не нужен.

### 6. Адаптивная (мобильная) вёрстка
**Цель.** Поддержать отображение GUI на мобильных устройствах.
**Объём/требования.**
- Адаптив CSS (`web/css/style.css`), бургер-меню для `sidebar.js`, проверка
  таблиц/форм/прокси-таблицы на узких экранах.
**Приёмка.** GUI юзабелен на телефоне: меню сворачивается, таблицы и формы не
ломаются, основные сценарии доступны.

### 7. Автообновление списков прокси по таймеру + выбор транспорта скачивания
**Цель.** Периодически обновлять списки/подписки прокси из указанных
источников и дать выбрать, **через что** качать: напрямую / awg / mihomo /
sing-box.
**Объём/требования.**
- Развить существующие рефрешеры (`core/list_updater.py`,
  `core/subscription_manager.py`, `core/server_pool.py`) — они уже умеют
  таймер и стартуют на boot.
- Добавить параметр «транспорт скачивания» (привязка исходящего запроса к
  туннелю/прокси) и UI настройки таймера/источников/транспорта.
**Приёмка.** Списки обновляются по расписанию; пользователь выбирает источник,
интервал и транспорт; обновление переживает рестарт GUI.
**✅ Сделано (эта сессия).** Все три рефрешера переведены на общий слой
транспорта из задачи №8 (`urlopen_via` из `core/download_transport.py`,
спека `direct`/`awg[:iface]`/`singbox[:конфиг]`/`mihomo[:конфиг]`; в
download_transport добавлен `is_valid_spec()` для валидации сохраняемых
настроек). Хранение по подсистемам (всё в settings.json → переживает
рестарт; таймеры на boot уже были): списки — одна настройка
`lists.transport` (`list_updater.get_transport/set_transport`,
`refresh_one` качает через неё; `_fetch` заодно применяет зеркало
`install.mirror` к GitHub-URL); подписки — поле `transport` per-подписка
(`_norm_transport` приводит `direct`/мусор к '', `add/update_subscription`,
`refresh_one` передаёт в `_fetch`); пул — `singbox.pool.transport`
(`get_settings/update_settings`, `refresh_pool` передаёт в
`fetch_outbounds(transport=)`). Недоступный транспорт = честная
RuntimeError с человекочитаемым текстом → попадает в `last_error`
(существующие механизмы «не затирать при пустом/ошибке» сохранены). API:
`GET /api/lists/curated` отдаёт `transport`,
`POST /api/lists/curated/settings {transport}` (400 на неизвестную
спеку), `PUT /api/lists/<id>` принимает `interval_hours` (период
автообновления managed-списка), `transport` в subscriptions add/update и
pool settings. UI: новый общий `web/js/components/transport_select.js`
(кэш 60с одного запроса `/api/install/transports`, опции с пометкой
«сейчас недоступен», `labelFor`; InstallExtras из задачи 8 переведён на
него); «Списки» — селект «Качать через» + интервал в форме добавления
URL + интервал managed-списка в редакторе (и «каждые N ч» в таблице);
sing-box → Конфиги: вкладка «Подписки» — селект в форме и инлайн-селект
в каждой карточке, вкладка «Пул серверов» — «Качать источники через» в
настройках. Тесты: `tests/test_refresher_transport.py` (новый, 15 шт.),
расширены test_api_lists (transport get/set/reject) и test_api_singbox
(прокидка transport в subscriptions/pool).

### 8. Скачивание не только последней версии, но и старых + выбор транспорта/локально
**Цель.** Дать ставить произвольную (в т.ч. более старую) версию бинарей
(awg/sing-box/mihomo), при этом **последняя — по умолчанию**; выбрать, через
что качать: напрямую / awg / mihomo / sing-box / локально (из файла).
**Объём/требования.**
- Установщики уже принимают `tag` (см. `api/mihomo.py` install body `tag`,
  `core/*_installer.py` `_resolve_latest_tag`). Добавить выбор версии из списка
  релизов (последняя предвыбрана) и режим «локальный файл».
- Параметр «транспорт скачивания» (как в задаче 7).
**Приёмка.** В разделах установки можно выбрать версию (по умолчанию — latest),
указать транспорт или загрузить бинарь локально; установка проходит.
**✅ Сделано (эта сессия).** Транспорт скачивания: новый
`core/download_transport.py` (спека `direct` / `awg[:iface]` /
`singbox[:конфиг]` / `mihomo[:конфиг]`; awg — SO_BINDTODEVICE с фолбэком
на bind по IP интерфейса, sing-box/mihomo — их локальный mixed/http-порт
как HTTP-прокси, inbound'ы с авторизацией и socks-only пропускаются;
кандидаты/резолв/`build_opener`/`urlopen_via`; недоступный транспорт —
честная ошибка, не тихий direct) + `GET /api/install/transports`
(api/status.py). Транспорт пронизывает ВСЕ сетевые шаги установки
(releases/manifest/бинари): `download_file(transport=)` и
`fetch_verify_extract_install` в binary_installer, `_http_*` хелперы и
`install(...)` всех трёх установщиков, поле `transport` в
`POST /api/{awg,singbox,mihomo}/install` — слой готов для переиспользования
задачей 7. Выбор версии: `list_releases()` у трёх установщиков (кэш 5 мин;
awg — только `awg-bin-*` с manifest.json и парсингом версий go/tools из
тега, manual-* не предлагаем — манифест может быть чужим, issue #111;
sing-box — `singbox-bin-*`; mihomo — апстрим с пометкой prerelease) +
`GET /api/{awg,singbox,mihomo}/releases?transport=&force=1`. Локальный
файл: `prepare_local_binary()` в binary_installer (формат по magic:
tar.gz/одиночный .gz/голый ELF; итог обязан быть ELF) + `install_local()`
у трёх установщиков (state `tag="local"`, версия спрашивается у бинаря,
не отвечает → warning про архитектуру) + `POST .../install/local`
(multipart: singbox/mihomo — `file`, awg — `go` и/или `tools`; общий
помощник api/_install_upload.py). Заодно зеркало install.mirror теперь
применяется и к manifest-запросам sing-box. UI: под-компонент
`InstallExtras` (web/js/components/setup_ui.js — «Версия: последняя /
выбрать другую…», селект «Качать через» (виден только когда есть
варианты), блок «Установить из локального файла…»; выбранные файлы
переживают перерисовки) — встроен в SetupUI (sing-box/mihomo) и в
awg_setup.js (там кнопка установки разблокируется при выбранном
транспорте даже без manifest — он скачается через транспорт). Тесты:
`tests/test_download_transport.py`, `tests/test_installer_releases.py`
(новые), обновлены моки в test_awg_installer_arch /
test_singbox_installer_resolve (новый kwarg `transport`).

---

## Открытые мелкие follow-up (не «крупные», но не потерять)

- Watchdog AWG: владелец отметил, что «не помогает / срабатывает долго».
  Дефолты медленные (handshake 180с, cooldown 300с). После сбора данных из
  «Сохранённого лога» — решить, ускорять ли логику/дефолты (есть
  `tests/test_awg_watchdog.py` — не сломать) и лечит ли рестарт стал вообще.
- Лимит памяти amneziawg-go: если по логам подтвердится OOM на роутерах —
  сделать его ВКЛ по умолчанию на роутерных платформах (сейчас ВЫКЛ).

## Рекомендуемый порядок

Сначала **1 → 2** (дают переиспользуемые компоненты), затем **3** (общая
унификация на их основе) и **4** (маршрутизация). **5/6/7/8** независимы и
берутся по приоритету владельца.
