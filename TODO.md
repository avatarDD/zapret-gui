# TODO

Свободный реестр того, что хочется сделать после v0.19.0 (AmneziaWG
integration). Не план релиза — скорее заметки и идеи, чтобы было
с чего начинать в следующих чатах.

## Keenetic NDMS integration (заимствовано из awg-manager)

Главный приоритет. На Keenetic'е роутер уже занимает 53 порт своим
`ndnsproxy`, поэтому наш dnsmasq+ipset стек на нём не работает —
а у Keenetic'а ровно для этой задачи есть штатный механизм
`dns-proxy route` + `object-group fqdn`, который доступен через
встроенный Router Control Interface (RCI) на `http://localhost:79/rci/`.

Все пункты ниже **гейтятся явной проверкой**: «это Keenetic + RCI
отвечает» → используем NDMS. На OpenWrt, generic Linux и Entware-
не-Keenetic — продолжаем работать через dnsmasq+ipset/nftset, как
сейчас.

- [x] **RCI-клиент** — `core/ndms/rci_client.py`: тонкий HTTP-клиент
      к `localhost:79/rci`, методы `get(path)` и `post(payload)`,
      детектор доступности (`is_available()`), кэш версии прошивки.
- [x] **NDMS commands** — `core/ndms/commands.py`: высокоуровневые
      обёртки `upsert_fqdn_group()`, `set_dns_proxy_route()`,
      `add_static_route()`, `set_ip_policy()`, `save_config()`.
      Все payload'ы строятся как JSON-дерево NDMS-CLI.
- [x] **NDMS backend для domain-rules** —
      `core/routing/ndms_backend.py`: реализация `apply/remove` через
      `object-group fqdn <id>` + `dns-proxy route group <id> interface <iface>`.
      Никакого ipset/nftset/fwmark/ip rule — всё делает Keenetic сам.
- [x] **Выбор backend'а в `domain_rule._detect_backend()`** —
      приоритет: NDMS (если Keenetic + RCI) → nftset (dnsmasq + nft) →
      ipset (dnsmasq + ipset). NDMS-fast-path добавлен в начало
      `apply_domain_rule()`/`remove_domain_rule()` — при недоступности
      RCI падаем на dnsmasq-fallback. Дезактивация dnsmasq-проверок
      на Keenetic — отдельный пункт ниже.
- [x] **NDMS backend для CIDR-rules** — через `ip route <net> <mask>
      interface <iface>`. Включается в `manager._apply()`, когда
      target_iface — нативный NDMS-объект (Wireguard0/1, OpenVPN0,
      ISP*). Для AWG-userspace-туннелей остаёмся на стандартном
      `ip rule add to <cidr>`.
- [x] **NDMS backend для device-rules** — через `ip policy <ZGUI_id>
      permit <iface>` + `ip hotspot host <mac> policy <ZGUI_id>`.
      Активируется в `manager._apply()` через
      `ndms_backend.can_handle_device_rule()` — требует MAC и
      нативный NDMS-iface. Без MAC и на не-NDMS-интерфейсах
      остаёмся на стандартном `ip rule from <source_ip>`.
- [x] **Native Keenetic WG-интерфейсы как target** —
      `core/ndms/wg_discovery.py` запрашивает `show interface` и
      отдаёт список `Wireguard0..N`. `AwgManager.list_interfaces()`
      и эндпоинт `GET /api/routing/interfaces` отдают единый список
      (наши amneziawg-go + нативные NDMS-WG). В UI на странице
      Routing — выпадающий список включает оба типа.
- [x] **NDMS ping-check delegation** — для нативных Keenetic-WG
      туннелей мониторинг делегирован NDMS'у через `show interface`.
      `AwgManager.status()` для нативных WG идёт за состоянием
      в RCI вместо `wg show` (который их не видит).
- [x] **HydraRoute Neo support** — теги `geosite:youtube` / `geoip:ru`
      разворачиваются в полные списки в `core/routing/alias_resolver.py`.
      Источники: v2fly/domain-list-community и v2fly/geoip. Кэш в
      `data/aliases/`, TTL=24ч, при сетевой ошибке используется stale
      кэш. API: `GET /api/routing/aliases`,
      `POST /api/routing/aliases/refresh`,
      `POST /api/routing/aliases/preview`. Работает и через NDMS, и
      через dnsmasq-fallback. Frontend-autocomplete по `SUGGESTED_*` —
      отдельной задачей.
- [x] **«Доступен Keenetic NDMS-режим» индикатор** — на странице
      Routing вкладка «Домены» рендерит зелёный `alert-success`
      баннер «Активен Keenetic-native режим (NDMS)» с версией
      прошивки, когда `/api/routing/ndms/status` вернул
      `available: true`. Toggle auto/force-NDMS/force-dnsmasq —
      пока не реализован, по умолчанию auto (NDMS → fallback dnsmasq).
- [x] **Дезактивация dnsmasq-кода на Keenetic** — `apply_domain_rule()`
      первым делом пробует NDMS-fast-path; до dnsmasq-проверок
      `dn_status.get("running")` дело не доходит, когда RCI отвечает.
      В UI кнопка «Настроить dnsmasq автоматически» рендерится
      только в warning-баннере, который теперь скрыт при ndmsActive.
      Сам `dnsmasq_integration.py` (1213 строк) остаётся для
      OpenWrt/Linux/Entware-не-Keenetic.

## Дальнейшие заимствования из awg-manager

- [x] **Connectivity matrix (backend)** — `core/connectivity/matrix.py`:
      параллельный `ping -I <iface>` по списку таргетов и туннелей,
      результат кэшируется в RAM (без записи на flash), TTL=30с.
      Защита от двойного запуска, фолбэк на default route при отказе
      `-I`. API: `GET /api/connectivity/matrix`,
      `POST /api/connectivity/probe`,
      `GET|POST /api/connectivity/targets`. UI-виджет — отдельной
      подзадачей (нужен grid с цветовой шкалой good/ok/slow/failed).
- [x] **Traffic graphs (backend) по туннелям 1h/3h/24h** —
      `core/connectivity/traffic.py`: фоновой sampler раз в 30с
      пишет в кольцевой буфер per-iface (RAM, ~35КБ на интерфейс
      за 24ч), серии 1h/3h/24h ресемплятся в bps по 60 точек.
      Источники: NDMS (`rx_bytes`/`tx_bytes` из RCI),
      `awg show <iface> transfer`, `/proc/net/dev` как фолбэк.
      API: `GET /api/connectivity/traffic`,
      `GET /api/connectivity/traffic/<iface>`. UI-sparkline —
      отдельной подзадачей.
- [x] **Импорт подписок (WG-flavor)** — `core/subscription_importer.py`:
      fetch URL → base64-detect → парс URI/`.conf` блоков.
      WireGuard-URI и сырые `.conf` импортируются в `AwgManager`.
      VLESS/Trojan/SS/Hysteria2/TUIC URI распознаются, но
      пропускаются с пометкой `needs sing-box` (включится, когда
      будет готова Sing-box секция). API:
      `POST /api/awg/subscription/import`,
      `POST /api/awg/subscription/preview`.

## Sing-box / Karing replacement integration

Главный задел v0.19.0 — selective routing engine (`core/routing/*`) —
сделан независимым от AWG. Следующая интеграция должна
переиспользовать тот же движок, не плодя параллельные правила.

- [ ] **Бинарь sing-box** под наши целевые архитектуры
      (`mipsel-softfloat`, `mips-softfloat`, `aarch64`, `armv7`,
      `x86_64`). По возможности — отдельный workflow по аналогии с
      `.github/workflows/build-awg-binaries.yml`, со своим тегом
      релизов и `manifest.json`.
- [ ] **Платформенная абстракция** — переиспользовать
      `core/awg_platform.py` или вынести общие части в
      `core/platform.py`. Sing-box тоже использует TUN, поэтому
      OpkgTun-предчек уже готов.
- [ ] **Installer** — повторить паттерн `core/awg_installer.py`
      (скачать → sha256 → распаковать → +x). Стоит сразу обобщить
      в `core/binary_installer.py`, чтобы оба установщика жили
      поверх общей утилиты.
- [ ] **Менеджер конфигов** — sing-box принимает JSON, не `.conf`.
      Нужен отдельный менеджер по аналогии с `core/awg_manager.py`
      с импортом подписок Karing/Hiddify, шейпингом аутбаундов.
- [ ] **Routing** — `RoutingRule.target_iface` уже абстрактный;
      достаточно добавить sing-box-интерфейсы (`tun0` / `tun1`) в
      выпадающие списки на странице Routing. Правила CIDR/domain/
      device применяются как есть.
- [ ] **Selectors из sing-box** (`outbound_selector` / `urltest`) —
      ортогональны нашему routing engine: они выбирают аутбаунд
      внутри sing-box, мы выбираем интерфейс снаружи. Стоит
      решить, где какая ответственность.
- [ ] **Karing-совместимый импорт подписок** —
      base64/clash-yaml/sing-box JSON, авторефреш по таймеру.

## AWG: то, что не успели в v0.19.0

- [ ] **QR-код** для конфигов на странице Configs (генерация
      без depency — нарисовать PNG/SVG руками или использовать
      встроенный awg, если он умеет).
- [ ] **Импорт `.conf` через QR с камеры** в браузере
      (`navigator.mediaDevices` + jsQR через CDN — опционально).
- [x] **Per-peer статистика (backend) — sparkline RX/TX** за
      последние 5 минут. `core/connectivity/traffic.py` теперь
      ведёт два уровня буферов: `_buffers` (24ч per-iface) и
      `_peer_buffers` (5 минут per-iface-per-peer, дискретность 30с).
      Источник peer-метрик: `awg show <iface> dump`. API:
      `GET /api/connectivity/peers/<iface>`. Для нативных
      Keenetic-WG peers пуст (RCI per-peer формат — отдельная задача).
      UI-sparkline — подзадача фронтенда.
- [x] **DoH/DoT для роутинга по доменам** —
      `core/routing/doh_resolver.py`: опциональный DoH-резолвер для
      pre-population ipset/nftset. Использует JSON-формат (RFC 8484),
      без сторонних DNS-библиотек. По умолчанию выключен — поведение
      dnsmasq-пути не меняется. Включается через settings.json
      (`routing.doh.enabled`) или API: `GET|POST /api/routing/doh`,
      `POST /api/routing/doh/test`. Известные провайдеры: Cloudflare,
      Google, Quad9. На Keenetic с NDMS-backend неактуален —
      ndnsproxy сам резолвит через настроенные upstream'ы.
- [x] **Тесты selective routing на OpenWrt nftables (unit)** —
      `tests/test_nftset_backend.py`: 16 unit-тестов с моком `_run`
      покрывают `set_name_for`, `_output_chain_type_wrong`,
      `available`, `create_set`, `_rule_exists`,
      `ensure_iface_masquerade`. Запуск:
      `python3 -m unittest discover -s tests -v`.
      ПОЛЕВОЕ тестирование на реальном OpenWrt-устройстве —
      открытая задача (нужен железный роутер с OpenWrt 22.03+).
- [x] **Уменьшить размер `amneziawg-go`** — в
      `.github/workflows/build-awg-binaries.yml` добавлен UPX-step
      для mipsel/mips/armv7 (на aarch64/x86_64 не применяем —
      экономия не оправдывает риски). На armv7 — `upx --best --lzma`,
      на mips/mipsel — `upx --best` без LZMA (Go-runtime на MIPS
      имеет проблемы с LZMA in-place decompression).
      `-ldflags="-s -w" -trimpath` уже стоял ранее.
      Ожидаемый выигрыш на mipsel: 5-7МБ → ~2МБ.
- [ ] **Поддержка KeenOS 4.x** — детект есть, но тестирование на
      реальном устройстве не проводилось. KeenOS 4.x иначе работает
      с пользовательскими iptables-цепочками.
- [ ] **Watchdog для AWG** — рестарт `amneziawg-go` при отсутствии
      handshake'а более N минут (по аналогии с тем, как
      `nfqws_manager.py` следит за nfqws2).

## Тех. долг

- [ ] **Единый installer-фреймворк** для бинарных депенденси
      (nfqws2, amneziawg-go/tools, в будущем sing-box). Сейчас три
      разных установщика дублируют логику скачивания/sha256/
      распаковки.
- [ ] **Тесты** — пока полагаемся на ручную проверку. Минимально
      нужны unit-тесты на парсер `.conf` (`core/awg_config.py`) и
      на эвристики `is_warp_config()` / манифест-парсер
      `awg_installer.py`. Они проще всего поддаются изоляции.
      Сюда же — unit-тесты на новые `core/ndms/*` (моки RCI).
- [ ] **i18n** — UI русскоязычный. На будущее — выделить строки в
      словарь (`web/js/i18n/{ru,en}.js`).
- [ ] **Явный enum платформы** — `Platform.{KEENETIC_NDMS,
      OPENWRT_NFT, ENTWARE_GENERIC, LINUX}` вместо разрозненных
      isinstance-проверок. Сейчас Keenetic-специфика разбросана
      по `awg_detector`, `awg_platform`, `awg_keenetic_setup`,
      `system_info`. С приходом NDMS-backend'а это станет ещё
      больше — стоит вынести в один источник истины.

## Идеи

- [ ] **Профили "режимов"** на главной — один клик переключает
      набор активных туннелей и routing-правил (например,
      "Дом" / "В дороге" / "Стриминг").
- [ ] **Метрики** в Prometheus-формате на `/metrics` —
      AWG handshake age, нормированный RX/TX, число активных
      routing rules. Полезно тем, у кого Grafana.
- [ ] **Auto-pick рабочей стратегии для конкретного домена**
      (объединить selective routing + strategy scanner): если
      `youtube.com` плохо работает через WARP, а напрямую через
      nfqws2 тянет — переключать автоматически.
