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

- [ ] **RCI-клиент** — `core/ndms/rci_client.py`: тонкий HTTP-клиент
      к `localhost:79/rci`, методы `get(path)` и `post(payload)`,
      детектор доступности (`is_available()`), кэш версии прошивки.
- [ ] **NDMS commands** — `core/ndms/commands.py`: высокоуровневые
      обёртки `upsert_fqdn_group()`, `set_dns_proxy_route()`,
      `add_static_route()`, `set_ip_policy()`, `save_config()`.
      Все payload'ы строятся как JSON-дерево NDMS-CLI.
- [ ] **NDMS backend для domain-rules** —
      `core/routing/ndms_backend.py`: реализация `apply/remove` через
      `object-group fqdn <id>` + `dns-proxy route group <id> interface <iface>`.
      Никакого ipset/nftset/fwmark/ip rule — всё делает Keenetic сам.
- [ ] **Выбор backend'а в `domain_rule._detect_backend()`** —
      приоритет: NDMS (если Keenetic + RCI) → nftset (dnsmasq + nft) →
      ipset (dnsmasq + ipset). При Keenetic-режиме dnsmasq-проверки
      должны быть отключены (сейчас они валят `apply_domain_rule()`
      с сообщением «dnsmasq не установлен»).
- [ ] **NDMS backend для CIDR-rules** — через `ip route <net> <mask>
      interface <iface>`. Сейчас CIDR-маршрутизация на Keenetic
      работает только через `ip rule add to <cidr>`, а это не самый
      устойчивый путь (NDMS периодически перетирает kernel routes
      при reload-running-config). NDMS-static-route переживает reload.
- [ ] **NDMS backend для device-rules** — через `ip policy <name>` +
      `ip hotspot host <mac> policy <name>`. Опционально и
      менее приоритетно: текущая реализация через iptables MARK
      работает на Keenetic с OpkgTun.
- [ ] **Native Keenetic WG-интерфейсы как target** — `core/ndms/
      wg_discovery.py`: запрашивать `show interface` и отдавать
      список интерфейсов вида `Wireguard0..N` плюс наши
      amneziawg-go-туннели одним списком в `/api/routing/interfaces`.
      В UI на странице Routing — выпадающий список включает оба
      типа, и пользователь выбирает любой как `target_iface`.
- [ ] **NDMS ping-check delegation** — для нативных Keenetic-WG
      туннелей мониторинг здоровья нужно делегировать NDMS'у
      (`interface <name> ping-check profile <name>` +
      `show interface <name>` → live state). Наш собственный
      check-loop в `core/awg_detector.py` /диагностике должен
      детектить «это нативный WG» и брать состояние из RCI.
- [ ] **HydraRoute Neo support** — теги `geosite:youtube` / `geoip:ru`
      в правилах. На бэке — резолвер таких алиасов в полные
      списки доменов/IP с автообновлением. На фронте — autocomplete
      по популярным алиасам.
- [ ] **«Доступен Keenetic NDMS-режим» индикатор** на странице
      Routing — баннер сверху, что мы переключились (или можем
      переключиться) на нативный backend. Toggle: auto / force-NDMS /
      force-dnsmasq для тех, кто хочет старый путь.
- [ ] **Дезактивация dnsmasq-кода на Keenetic** — при детекте
      Keenetic+RCI скрывать в UI кнопку «Настроить dnsmasq
      автоматически» и не падать в `apply_domain_rule()` с
      проверкой `dn_status.get("running")`. Сам файл
      `dnsmasq_integration.py` (1213 строк) на Keenetic'е
      становится dead-code — оставляем для остальных платформ.

## Дальнейшие заимствования из awg-manager

- [ ] **Connectivity matrix** — строки = таргеты (`8.8.8.8`,
      `1.1.1.1`, ...), столбцы = туннели, ячейки = latency с
      цветовой шкалой (зелёный <100ms / оранжевый <250ms / красный).
      Виджет на Dashboard страницы AWG. У нас уже есть
      `core/testers/` и `core/diagnostics.py` — нужно собрать
      матрицу и нарисовать.
- [ ] **Traffic graphs по туннелям 1h/3h/24h** — sparkline и
      развёрнутый график RX/TX per-iface. Источник — `wg show
      <iface> transfer` раз в N секунд, хранилище — кольцевой
      буфер в RAM (на Keenetic не плодим запись на flash).
- [ ] **Импорт подписок Karing/Hiddify/VLESS** — base64 /
      clash-yaml / sing-box JSON / VLESS URI. Уже есть отдельный
      пункт в Sing-box секции — здесь дублируем как кросс-ссылку,
      т.к. в awg-manager это центральный feature.

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
- [ ] **Per-peer статистика** на Dashboard в виде графика
      (sparkline RX/TX за последние 5 минут) — частично перекрывается
      пунктом «Traffic graphs» из awg-manager-заимствований.
- [ ] **DoH/DoT для роутинга по доменам** — сейчас домены
      резолвятся dnsmasq'ом обычным апстримом, что может
      обходиться DPI. Опционально стоит давать на платформах с
      stubby/cloudflared отдельный апстрим.
      ВАЖНО: на Keenetic с NDMS-backend этот пункт неактуален —
      резолв делает встроенный ndnsproxy через настроенные upstream'ы.
- [ ] **Тесты selective routing на OpenWrt nftables** — на момент
      релиза проверено на Keenetic 5.x + Entware ipset. nftables
      ветка нуждается в полевом прогоне.
- [ ] **Уменьшить размер `amneziawg-go`** через `-ldflags="-s -w"`
      и `upx --best --lzma` — для mipsel/mips это критично.
      Сейчас бинарь весит ~5-7 МБ. У awg-manager в
      `.github/workflows/build-awg-binaries.yml` это уже сделано —
      посмотреть как референс.
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
