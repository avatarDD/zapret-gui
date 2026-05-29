# TODO

Свободный реестр того, что хочется сделать. Не план релиза — заметки и
идеи, чтобы было с чего начинать в следующих чатах.

> Сделанные крупные вехи (NDMS-интеграция, sing-box, AWG, паритет с
> nfqws2-keenetic, оптимизация UI списков) перенесены в CHANGELOG.md.
> Здесь оставляем только открытые задачи и план на будущее.

## ★ Главный план: единый слой маршрутизации (nfqws2 + AWG + sing-box)

> **Статус: реализовано (backend + API + UI).** Все этапы ниже закрыты;
> остаётся полевое тестирование firewall/инъекций на железе.

Большая стратегическая цель. Раньше три подсистемы жили параллельно:
nfqws2 (обход DPI на месте), AmneziaWG и sing-box (туннели), у каждой —
свои списки доменов/IP и своя логика. Теперь есть **единый слой**, где для
каждого «назначения» (домен / CIDR / список / geosite / geoip) выбирается,
**через что** пустить трафик (`direct` / `nfqws2` / `awg:` / `singbox:` /
`mihomo:`), с резервной цепочкой; система **сама следит** за успешностью
и переключает метод при деградации (`core/unified/*`, страница
«Маршрутизация»).

Этапы (все выполнены):

- [x] **Объединение списков** — `core/named_lists.py` (хранилище
      доменов/CIDR, classify/parse, CRUD), страница «Списки (общие)»
      (`web/js/pages/lists.js`), API `/api/lists`. Destination единого
      слоя ссылается на список по id.
- [x] **Модель «назначение → метод»** — `core/unified/model.py`
      (Destination: domains/cidrs/list_ids/geosite/geoip + Method
      direct/nfqws2/awg:/singbox:/mihomo: + UnifiedRoute) и
      `core/unified/applier.py` (tunnel → Domain/CidrRoutingRule,
      nfqws2 → hostlist, direct → снятие). Хранилище + manager + API
      `/api/unified/*`.
- [x] **Автомониторинг успешности per-destination** —
      `core/unified/monitor.py`: история в RAM (deque), success_rate/
      stats, TLS-проба probe_route, фоновый цикл (опц., по умолч. OFF).
- [x] **Адаптивное переключение метода (failover)** —
      `core/unified/failover.py`: чистая decide() (порог/гистерезис/
      cooldown), состояние активного метода, step(). Per-route флаг,
      по умолчанию выключено.
- [x] **Единая страница «Маршрутизация»** —
      `web/js/pages/routing_unified.js`: таблица «назначение | метод |
      статус | успешность | действия», форма с fallback-цепочкой,
      тумблер мониторинга, «Применить все».
- [x] **Интеграция со strategy-scanner** —
      `core/unified/scanner_hint.py`: suggest_for_route, run_scan_for_route,
      apply_best_found; в UI — кнопка «Подобрать» у деградировавшего
      nfqws2-маршрута.

Открытые улучшения единого слоя (next):

- [x] **geosite/geoip через движок** — `core/unified/geo_engine.py`:
      для метода `singbox:<iface>` находит конфиг по interface_name и
      инжектирует route-правило {domain_suffix/geosite/geoip → proxy},
      идемпотентно через sidecar. mihomo/awg — понятный skip (нет
      YAML-эмиттера / iptables не умеет geo).
- [x] **Инъекция nfqws2-hostlist** — `core/unified/nfqws_hostlist.py`:
      агрегат доменов nfqws2-маршрутов → `--hostlist` перед профилями
      стратегии (opt-in `nfqws.unified_hostlist`, тумблер в Настройках).
- [~] **Слияние** старых страниц Стратегии / Routing(AWG) в единую
      «Маршрутизацию» — сделан безопасный шаг: «Маршрутизация» как
      основная точка входа + кросс-ссылки, старые помечены «расширенный
      режим». Полное удаление — после полевых тестов.

### Заимствования из rcd27/blockcheckw (MIT)

- [x] **IP-блок vs DPI-блок + `remediation`** — blockcheck теперь различает
      блок на уровне IP (TCP connect не проходит → нужен туннель) и DPI/SNI-
      блок (TCP ок, рвётся TLS → поможет zapret). Машиночитаемое поле
      `remediation` (`zapret`/`tunnel`/`dns`/`none`) на каждой цели —
      прямой вход для авто-выбора метода в «едином слое» выше.
- [x] **Ранжирование стратегий по простоте** —
      `strategy_scanner._select_strategies` использует `complexity_key`
      (action_count, max_repeats, is_multi_stage) из
      `core/strategy_generator.py`. Лёгкие/одноступенчатые тестируются
      раньше, рабочая стратегия находится быстрее.
- [x] **Новые методы из blockcheckw как именованные пресеты** —
      `catalogs/advanced/{tcp,http80}_blockcheckw.txt`: `tcpseg`
      (TCP-сегментация, `ip_id=rnd`, seqovl), `oob` (urgent pointer),
      `http_domcase`, `http_unixeol`. Курированный набор (не весь
      комбинаторный перебор оригинала).
- [x] **Генератор стратегий «на лету»** — `core/strategy_generator.py`:
      параметрические сетки (positions × seqovl × fooling × repeats для
      multisplit/multidisorder/fakedsplit/fakeddisorder/fake/tcpseg/oob),
      дедуп против каталога, ранжирование от простых к сложным. Сканер
      добавляет генерированные стратегии в режимах standard/full
      (флаг `scan.use_generated`). Альтернатива хранению 13K строк
      готовых вариантов как в blockcheckw. API:
      `GET /api/scan/generated?protocol=&level=` для предпросмотра.
- [x] **Сигнал «сервер получает fake-пакеты»** — HTTP 400 в body_tester
      классифицируется как `FAKE_LEAK` (десинк не сработал, fake-пакет
      дошёл до сервера). Высший приоритет в `_pick_best_error` сканера —
      такая стратегия точно не годится, маркируется однозначно.
- [x] **Generic off-domain redirect** — `isp_detector.is_off_domain_redirect`
      сравнивает регистрируемые домены источника и редирект-цели (последние
      две метки). Помечается как **мягкий** сигнал в `redirect_chain`
      («[off-domain] ...»), статус НЕ меняется на FAILED — чтобы не плодить
      ложные срабатывания на легитимных кросс-доменных редиректах
      (consent.youtube.com → google.com, шортлинки).
- [x] **Расширить окно DPI data-limit** — добавлены константы
      `TCP_BLOCK_RANGE_WIDE_{MIN,MAX}` = 10240..25600 (из blockcheckw).
      body_tester проверяет узкое окно (явный `tcp_16_20`), затем
      широкое (`dpi_marker=tcp_16_20_wide`). Тот же тип блока, но с
      другим размером DPI-буфера. Узкое окно по-прежнему приоритетно.

### Заимствования из XKeen (jameszeroX/XKeen)

- [x] **Прозрачное проксирование sing-box (TProxy/Redirect/Hybrid)** —
      `core/singbox_transparent.py`: firewall-обвязка (свои цепочки,
      идемпотентно) + `make_transparent_inbounds()` генерит inbound'ы.
      Включает заворот трафика самого роутера (`proxy_self`/OUTPUT),
      DNS-hijack и IPv6 anti-leak (drop форвард-v6, когда прокси v4-only).
- [x] **Движок mihomo (Clash.Meta)** — `core/mihomo_{platform,detector,
      manager,autostart}.py`, конфиги в clash-YAML (парсятся готовым
      `core/clash_yaml.py`). Альтернатива sing-box.
- [x] **fd-лимиты** — `RLIMIT_NOFILE=65536` при старте sing-box/mihomo
      (preexec_fn) + `ulimit`/`LimitNOFILE` в init-скриптах.
- [x] **CLI** — `core/cli.py`: `zapret-gui status|nfqws|strategy|
      singbox|mihomo`. Диспетчеризуется из `app.py`.
- [x] **DSCP/QoS-маршрутизация** — тип правила `dscp`
      (`core/routing/dscp_rule.py`): `-m dscp --dscp N -j MARK` +
      `ip rule fwmark`. Маршрутизируем уже промаркированный QoS-трафик.
- [x] **Зеркало/оффлайн-установка** — `binary_installer.resolve_url()`
      (env `ZAPRET_GUI_MIRROR` / `install.mirror`) + `file://`/локальные
      пути в `download_file()`.
- [x] **Совместимость с политиками Keenetic** — `commands.get_host_policy()`
      + сохранение/восстановление прежней политики хоста в
      `ndms_backend` (родительский контроль не затирается).
- [x] **Установщик mihomo** — `core/mihomo_installer.py` поверх
      `binary_installer` (апстрим MetaCubeX/mihomo, per-arch .gz через
      зеркало/оффлайн) + `api/mihomo.py` (environment/install/version/
      configs/autostart).
- [x] **UI для нового бэкенда** — страница mihomo
      (`web/js/pages/mihomo.js`: обзор/установка/инстансы/YAML-редактор),
      вкладка DSCP в routing, карточка прозрачного проксирования на
      странице sing-box, секция «Установка» с полем зеркала в Настройках.
- [x] **nftables-вариант** прозрачного проксирования и DSCP —
      `core/singbox_transparent_nft.py` (таблица `inet sbtproxy`,
      redirect/tproxy/hybrid) + nft-путь в `core/routing/dscp_rule.py`.
      `choose_backend()`: iptables приоритетнее (Keenetic), nft для
      OpenWrt 22+.
- [x] **Boot-персистентность transparent-firewall** — `app.py
      --apply/--remove-singbox-transparent`; init-скрипт sing-box
      (entware + systemd) на старте переприменяет firewall из
      сохранённых настроек, на остановке снимает.
- [ ] **Полевое тестирование** firewall-правил TProxy/Redirect/DSCP на
      железе (Keenetic/OpenWrt) — код не проверялся на устройствах.

## AWG / прочее (открытые)

- [ ] **QR-код** для конфигов на странице Configs (генерация
      без depency — нарисовать PNG/SVG руками или использовать
      встроенный awg, если он умеет).
- [ ] **Импорт `.conf` через QR с камеры** в браузере
      (`navigator.mediaDevices` + jsQR через CDN — опционально).
- [x] **UI-sparkline** для per-iface статистики —
      `web/js/components/sparkline.js` (inline-SVG) + дашборд AWG рисует
      rx/tx-серии из `/api/connectivity/traffic/<iface>`. Per-peer
      sparkline — по мере надобности (серии бэкенд отдаёт).
- [ ] **Полевое тестирование** на железе: OpenWrt 22.03+ (nftset
      backend) и KeenOS 4.x (детектор/инструкции) — код есть,
      не проверено на устройствах.

## Тех. долг

- [ ] **i18n** — UI русскоязычный. На будущее — выделить строки в
      словарь (`web/js/i18n/{ru,en}.js`).
- [x] **Рефакторинг `awg_installer.py` / `zapret_installer.py`** на
      общий `core/binary_installer.py` — загрузка делегирована
      download_file (зеркало + оффлайн + retry), GitHub API через
      resolve_url. Покрыто tests/test_installer_mirror.py.
- [~] **Расширить покрытие тестами** — добавлены log_buffer, scan_targets,
      catalog_loader, named_lists, unified/*, geo_engine, nfqws_hostlist,
      mihomo, transparent (iptables+nft), dscp, installer mirror.
      Осталось: strategy_scanner, blockcheck, diagnostics, warp_generator.
- [x] **Контекстные подсказки «?»** — `web/js/components/help.js`
      (модалка с примерами) на ключевых страницах.

## Идеи

- [ ] **Профили "режимов"** на главной — один клик переключает
      набор активных туннелей и routing-правил (например,
      "Дом" / "В дороге" / "Стриминг"). Пересекается с «единым слоем
      маршрутизации» выше — возможно, реализовать как пресеты поверх него.
- [ ] **Метрики** в Prometheus-формате на `/metrics` —
      AWG handshake age, нормированный RX/TX, число активных
      routing rules. Полезно тем, у кого Grafana.
