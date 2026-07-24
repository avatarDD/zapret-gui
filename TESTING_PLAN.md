# План тестирования Development → main

**Цель:** протестировать все изменения ветки `Development` относительно `main`,
исправить регрессии и подготовить ветку к безопасному мержу в `main`.

**Целевые платформы:** Keenetic 4.xx, Keenetic 5.xx, Entware, OpenWRT, Linux.
Код едет на роутере с **`python3-light`** — минимум зависимостей, HTTP через
`urllib` (не `requests`), логи в RAM.

## Топология веток

- `main` = merge-base (`d82711f`), «более-менее стабильная».
- `Development` = `main + 37 коммитов` (main полностью содержится в Development).
- Диф: **146 файлов, +18573 / −839**.
- Рабочая ветка фиксов: `claude/development-testing-merge-r2dauh` (базирована на Development).

## Что уже проверено (базовый фундамент — GREEN)

- [x] `python3 -m compileall` — весь Python компилируется.
- [x] `python3 -m unittest discover -s tests` — **2027 тестов, OK**.
- [x] `import app` + сборка Bottle-app + `register_routes` — **788 маршрутов**, без ошибок.
- [x] Все новые api/*-модули импортируются.
- [x] Все новые core/*-модули импортируются.
- [x] `node --check` на всех 63 JS-файлах — синтаксис валиден.
- [x] Все новые страницы зарегистрированы в `web/js/app.js` и объявляют корректный
      глобальный объект (`UsquePage`, `TgProxyPage`, …).
- [x] Все новые api-модули зарегистрированы в `api/__init__.py`.

> Вывод: краш-на-загрузке нет. Баги — **логические / runtime / регрессионные**,
> не покрытые юнит-тестами. Приоритет — **изменённые существующие файлы**
> (новые файлы аддитивны и не ломают то, что работало).

---

## Стратегия проверки

Проверяем по кластерам. Для каждого: (1) читаем дифф построчно; (2) проверяем
контракт API↔frontend; (3) проверяем платформенную абстракцию (пути, команды,
детект nft/ipset/iptables, RCI для Keenetic); (4) прогоняем/добавляем тесты;
(5) фиксим. Субагенты — для параллельного глубокого ревью новых модулей.

### Кластер 0 — Регрессии в изменённых существующих файлах (ВЫСШИЙ приоритет)

Файлы, которые существовали в main и заметно изменены (наиболее вероятная причина
«перестало работать»):

- [ ] `app.py` (+418) — boot-хуки, новые воркеры, CSP, флаги
- [ ] `core/strategy_scanner.py` (+311) — сканер стратегий
- [ ] `core/config_manager.py` (+127) — конфиг, save_config, миграции
- [ ] `core/awg_manager.py` (+118), `core/awg_watchdog.py` (+167)
- [ ] `core/routing/manager.py` (+133), `core/routing/ndms_backend.py` (+43)
- [ ] `core/mihomo_manager.py` (+89), `core/mihomo_watchdog.py` (+57)
- [ ] `core/singbox_manager.py` (+85), `core/singbox_transparent*.py`, `singbox_watchdog.py`
- [ ] `core/ndms/rci_client.py` (+89), `core/ndms/commands.py` (+66)
- [ ] `core/firewall.py` (+39), `core/nfqws_manager.py` (+15)
- [ ] `core/list_updater.py` (+114), `core/strategy_state.py` (+109)
- [ ] `core/log_buffer.py` (+74), `core/binary_installer.py` (+59)
- [ ] `core/blockcheck.py` (+59), `core/healthcheck.py` (+30)
- [ ] `core/platform_dirs.py` (+24), `core/proxy_tester.py`, `core/mihomo_proxy_tester.py`
- [ ] `core/unified/*`, `core/named_lists.py`, `core/server_pool.py`
- [ ] `api/config_api.py`, `api/lists.py`, `api/scan.py`

### Кластер 0f — Регрессии во фронтенде (изменённые страницы)

- [ ] `web/js/pages/dashboard.js` (+330) — дашборд
- [ ] `web/js/pages/strategies.js` (+193), `lists.js` (+171)
- [ ] `web/js/pages/settings.js` (+154), `routing_unified.js` (+114)
- [ ] `web/js/pages/blobs.js`, `awg_configs.js`, `autostart.js`, `control.js`
- [ ] `web/index.html` (+33), `web/css/style.css` (+78)
- [ ] `web/js/api.js`, `web/js/app.js`, `components/toast.js`, `setup_ui.js`
- [ ] CSP: проверить, что inline-обработчики не сломаны (был фикс 04ad3db)

### Кластер A — usque (Cloudflare WARP / MASQUE)
- [ ] `core/usque_manager.py`, `core/usque_watchdog.py`, `api/usque.py`,
      `web/js/pages/usque.js`, `usque_setup.js`

### Кластер B — Telegram proxy (MTProto + tgwsproxy)
- [ ] `core/tgproxy_manager.py` (1058!), `api/tgproxy.py`, `web/js/pages/tgproxy.js`

### Кластер C — WARP-in-WARP (MASQUE nested)
- [ ] `core/warp_in_warp.py` (849), `core/warp_in_warp_watchdog.py`,
      `api/warp_in_warp.py`, `web/js/pages/warp_in_warp.js`

### Кластер D — Opera proxy
- [ ] `core/opera_proxy_manager.py`, `core/opera_proxy_watchdog.py`,
      `api/opera_proxy.py`, `web/js/pages/opera_proxy.js`

### Кластер E — Tunnel monitor + optimizer
- [ ] `core/tunnel_monitor.py`, `core/tunnel_optimizer.py` (794),
      `api/*`, `web/js/pages/*`

### Кластер F — DNS routing / providers / GeoHide / geosite
- [ ] `core/dns_routing.py`, `core/dns_providers.py`, `core/geosite_importer.py`,
      `api/dns_routing.py`, `api/geosite.py`, `web/js/pages/dns_routing.js`

### Кластер G — Block detector (DPI filtering)
- [ ] `core/block_detector.py` (527), `api/block_detector.py`, `web/js/pages/block_detector.js`

### Кластер H — Update checker + auto-remediation
- [ ] `core/update_checker.py`, `core/auto_remediation.py`,
      `api/update_checker.py`, `api/auto_remediation.py`, `web/js/pages/update_checker.js`

### Кластер I — Ext binary installer + teardown
- [ ] `core/ext_binary_installer.py` (820), `core/teardown.py`

### Кластер L — CLI + сборка + CI
- [ ] `core/cli.py` (+195), `api/v1_compat.py`, `build_ipk.py`, `build_ipk.ps1`,
      `tools/bundle.py`, `.github/workflows/dev-release.yml`, `Makefile`, `install.sh`

---

## Журнал найденных дефектов и исправлений

| # | Тяжесть | Файл | Проблема | Статус |
|---|---------|------|----------|--------|
| 1 | HIGH | core/warp_in_warp_watchdog.py | `sendall(str)` вместо bytes → TypeError проглатывается → исправный WARP-in-WARP помечается «нездоровым» и watchdog его рестартит по кругу | ✅ fixed |
| 2 | HIGH | core/opera_proxy_manager.py | `Popen(stdout=PIPE)` не вычитывается → буфер пайпа переполняется → opera-proxy зависает под нагрузкой | ✅ fixed (drain-поток) |
| 3 | HIGH | core/mihomo_watchdog.py, core/singbox_watchdog.py | `concurrent.futures` без fallback → на Entware без python3-logging watchdog молча простаивает (регрессия: в main цикл был последовательным) | ✅ fixed (fallback) |
| 4 | HIGH | core/update_checker.py | `_check_tgproto` импортирует несуществующие `get_tgproxy_manager`/`_detect_mtproto` → проверка обновлений tg-mtproxy всегда в ошибке | ✅ fixed |
| 5 | HIGH | core/tunnel_monitor.py | тот же несуществующий `get_tgproxy_manager`/`_is_running` → tgproxy не виден в мониторе | ✅ fixed |
| 6 | HIGH | core/geosite_importer.py | неверная нумерация enum типов → отбрасывался Domain(2, ~99% записей), включался Regex(1) | ✅ fixed |
| 7 | HIGH | core/ext_binary_installer.py | usque-ассет `.ipk` ставился как сырой бинарник → битый | ✅ fixed (package/opkg) |
| 8 | HIGH | web/js/pages/update_checker.js | не поллит → «Проверить обновления» всегда «Нет данных» | ✅ fixed (poll + check_now) |
| 9 | HIGH | web/js/pages/warp_in_warp.js | форма перерисовывается каждые 3с → стирает ввод пользователя | ✅ fixed (сигнатура состояния) |
| 10 | HIGH | api/block_detector.py | ручной «Запустить мониторинг» — тихий no-op (гейт enabled), но фронт показывает успех | ✅ fixed (enabled+persist) |
| 11 | HIGH | core/tunnel_optimizer.py | overall-ok завязан на опциональный BBR → на Keenetic «Ошибка», хотя MTU/буферы применены | ✅ fixed |
| 12 | HIGH | core/auto_remediation.py + config | `opera` не метод unified → `ValueError: Неизвестный метод: opera:` | ✅ fixed (opera убран) |
| 13 | MED | core/teardown.py | dns-routing include в dnsmasq не снимался при удалении → dnsmasq падает после uninstall | ✅ fixed |
| 14 | MED | app.py | `_stops` фабрики opera/usque/warp watchdog неверны (`get_watchdog`) → graceful shutdown их пропускал | ✅ fixed |
| 15 | MED | app.py | usque autostart не аллоцировал iface (`start("")`) → autostart молча падал | ✅ fixed |
| 16 | MED | api/opera_proxy.py | «Автозапуск» opera не работал (enabled нигде не выставлялся) | ✅ fixed |
| 17 | MED | api/usque.py + usque_setup.js | контракт SetupUI (binary как объект, `/version` nested) не совпадал → страница установки всегда «не установлен» | ✅ fixed |
| 18 | MED | core/tunnel_monitor.py | `_read_nfqws_stats` читал константные колонки + хардкод queue 300 → скорость всегда ~0 | ✅ fixed (id_seq + queue_num из конфига) |
| 19 | MED | api/block_detector.py | per-IP rate-limit — мёртвый код (client_ip не пробрасывался) | ✅ fixed |
| 20 | MED | core/block_detector.py | `concurrent.futures` без fallback + возможный NameError `interval` в `_run_loop` | ✅ fixed |
| 21 | LOW | core/usque_watchdog.py | `interval_sec` игнорировался (хардкод 60) | ✅ fixed |
| 22 | LOW | core/geosite_importer.py | `list_categories` звал не тот парсер (`endswith("geosite")`) | ✅ fixed |
| 23 | MED | core/tunnel_optimizer.py | `probe_pmtu` использует `ping -M do` (нет в busybox) → на Keenetic ложное «dataplane не проходит» | ✅ fixed (детект DF + понятное сообщение) |
| 24 | HIGH | web/js/api.js | глобальный таймаут 15с рвал длинные синхронные запросы (traceroute до 45с, PMTU) → Deep Trace ломался | ✅ fixed (per-request timeout) |
| 25 | MED | web/js/api.js | `AbortSignal.timeout()` бросает `TimeoutError`, а не `AbortError` → сообщение о таймауте не показывалось на совр. браузерах | ✅ fixed |
| 26 | LOW | web/js/pages/usque.js | преждевременный toast «установлен» (opkg-установка в фоне) | ✅ fixed (поллинг статуса) |
| 27 | HIGH | web/js/app.js + pages | утечка делегированных click-слушателей на постоянном `#page-container` → двойные действия + межстраничные срабатывания (напр. удаление маршрута дёргало удаление списка) | ✅ fixed (роутер клонирует контейнер; routing сбрасывает guard; dashboard снимает слушатель) |
| 28 | CRIT | core/awg_manager.py | AWG не поднимался на Keenetic. `ca54746` (batch MR-sprint) заменил простой рабочий старт (`_run([bin_go,ifname],timeout=15)` + `sleep(0.2)`) на socket-polling по хардкод-пути `/var/run/wireguard/<if>.sock`, которого на Keenetic НЕТ → таймаут → код убивал уже поднятый демон. Проявлялось как «Protocol not supported» / «превышено время ожидания». Диагностика с 2 реальных роутеров | ✅ fixed (блок старта восстановлен ДОСЛОВНО как в main v0.22.34 — verified diff) |
| 29 | HIGH | core/config_manager.py | backup/restore: экспорт маскирует секреты `***`, импорт писал их дословно → пароль GUI = `***` (лок-аут) | ✅ fixed (import сохраняет текущие секреты вместо маски) |
| 30 | MED | core/blockcheck.py | DoH-сравнение давало ложный DNS_FAKE на CDN/geo-доменах | ✅ fixed (фейк только при непубличном IP среди системных) |
| 31 | MED | core/testers/dpi_classifier.py | `TIMEOUT`/`TCP_TIMEOUT` добавлены в IP_BLOCK вопреки комментарию → обходимый nfqws silent-drop классифицировался как «нужен туннель» | ✅ fixed (revert — timeout не IP_BLOCK) |
| 32 | LOW | core/awg_manager.py | окно ожидания сокета 3с → ложные фейлы старта на медленных MIPS | ✅ fixed (8с, ранний выход по сокету) |
| 33 | LOW | web/js/pages/settings.js | рекламировался нерабочий drag-n-drop приоритета туннелей | ✅ fixed (убран афорданс; работают ↑/↓) |

### Осознанно НЕ менялось (намеренное поведение, не баг)
- `core/ndms/commands.py` — исключение `HTTP 404`/`unknown` из not-found: намеренно (Keenetic отдаёт «no such» с HTTP 200; закреплено тестом). Уточнён комментарий.
- `core/list_updater.py is_safe_url` — блокировка LAN-URL: намеренная защита от SSRF (MR-63); откат вернул бы уязвимость.
- `core/awg_manager.py` PostUp/PostDown через `shlex.split`+`shell=False`: намеренное закрытие RCE (MR-20).
- `core/strategy_state.py` debounce авто-сброса: безвредно (интервал healthcheck ≥60с).

Регресс-тесты: `tests/test_dev_merge_regressions.py` (19 тестов).

---

## Финальные gate-проверки перед мержем

- [ ] `python3 -m compileall` — clean
- [ ] `python3 -m unittest discover -s tests` — все зелёные (+ новые тесты на фиксы)
- [ ] `import app` + `register_routes` — без ошибок
- [ ] `node --check` весь JS — clean
- [ ] Контракт API↔frontend согласован (каждый вызов `API.*` в JS имеет endpoint)
- [ ] python3-light: нет запрещённых зависимостей (`requests` и т.п. в рантайме)
- [ ] Платформы: пути и команды выбираются по детекту (Keenetic RCI / Entware / OpenWRT / Linux)
