---
name: singbox
description: >-
  Полный справочник по sing-box в проекте zapret-gui (роутеры Keenetic на
  Entware / OpenWrt). Использовать при любых задачах о: конфигах sing-box
  (log/dns/inbounds/outbounds/endpoints/route/services/experimental), CLI
  (run/check/format/merge/tools/generate/rule-set), типах outbound
  (vless/vmess/trojan/shadowsocks/hysteria2/tuic/selector/urltest), TLS/Reality/
  uTLS/ECH, transport (ws/grpc/httpupgrade/h2/quic), multiplex, прозрачном
  проксировании (tproxy/redirect/tun), подписках и пуле серверов
  (server_pool, subscription_*), парсинге vless:// vmess:// ss:// trojan://
  hysteria2:// tuic://, миграциях версий 1.11/1.12/1.13 (удалённые block/dns
  outbounds, legacy inbound-поля, новый формат DNS), режиме отладки и
  диагностике «sing-box не запускается / конфиг не валиден / прокси не
  работает». Источник истины — sing-box.sagernet.org + sagernet/sing-box,
  привязка — наш код core/singbox_*.py, api/singbox.py, web/js/pages/singbox*.js.
---

# sing-box — справочник для zapret-gui

Единый источник истины о том, **как sing-box реально работает** и как с ним
обращаться в `zapret-gui`. Читать перед тем, как трогать генерацию конфигов,
менеджер процессов, прозрачное проксирование, подписки/пул или объяснять
пользователю «почему не работает».

Источники истины (в порядке убывания авторитета):
1. **sing-box.sagernet.org** — официальная документация конфигурации и CLI;
   `sagernet/sing-box` (Go-исходники) — окончательная истина по схемам.
2. **`sing-box check -c <file>`** — валидатор самого бинаря. Если он молчит —
   конфиг валиден для ЭТОЙ версии; если ругается — это и есть причина.
3. **Наш код** — `core/singbox_config.py` (генерация/валидация JSON),
   `core/singbox_manager.py` (run/check/up/down/debug/log),
   `core/singbox_platform.py` (пути), `core/singbox_transparent.py` +
   `core/singbox_transparent_nft.py` (firewall tproxy/redirect/tun),
   `core/singbox_subscription.py` + `core/subscription_importer.py` +
   `core/subscription_manager.py` (подписки), `core/server_pool.py` (пул),
   `core/singbox_autostart.py`, `core/singbox_installer.py`,
   `core/singbox_detector.py`, `api/singbox.py`, `web/js/pages/singbox*.js`.

> ⚠️ **Версии — главный источник «не работает».** sing-box ломает обратную
> совместимость по minor-версиям (см. §9). На роутере может стоять что угодно
> от 1.8 до 1.13+. Любая фича/поле, генерируемые нами, обязаны быть валидны на
> ЦЕЛЕВОЙ версии. При сомнении — `sing-box version` и `sing-box check`.

---

## 1. Как sing-box используется в zapret-gui

Модель: **один процесс = один конфиг-файл** (упрощение против AWG, где туннель =
интерфейс). Имя инстанса = имя файла без `.json`. Внутри одного инстанса —
сколько угодно outbound'ов и групп.

Поток:
- **Конфиги** лежат в `platform.config_dir` (Keenetic Entware:
  `/opt/etc/sing-box/`, Linux: `/etc/sing-box/`). CRUD — `SingboxManager`.
- **Запуск**: `sing-box run -c <config>` через `subprocess.Popen` с
  `start_new_session=True`, stdout/stderr → лог-файл (`platform.log_path`),
  PID → `platform.pid_path`. Перед стартом — обязательный pre-flight
  `sing-box check -c <config>` (если не прошёл — старт не делаем, отдаём
  stderr пользователю).
- **Подписки** (`subscription_manager`): каждая приватная подписка → свой
  конфиг. **Пул** (`server_pool`): много ПУБЛИЧНЫХ источников-«свалок» →
  дедуп → (опц.) health-тест → cap → один конфиг `server-pool` с
  urltest-группой.
- **Прозрачное проксирование** (`singbox_transparent`): tproxy / redirect /
  hybrid / tun — заворачивает трафик LAN в sing-box через iptables/nft.
- **Маршрутизация GUI** поверх: target_iface = `tun0`/`singbox-tun` для TUN.

### Базовый генерируемый конфиг (`make_minimal_config`)
`mixed`-inbound на 127.0.0.1:1080 → outbound с тегом `proxy-out` (юзер
заменяет на свой), `final: direct`. **Спец-outbound `block` НЕ добавляем** —
он удалён в 1.13 (см. §9).

---

## 2. CLI sing-box (что мы вызываем и что есть ещё)

**Глобальные (persistent) флаги** — работают со всеми командами:
| Флаг | Назначение |
|------|-----------|
| `-c, --config <file>` | путь к конфигу. **Повторяемый**: `-c a.json -c b.json` → файлы **объединяются** (объекты — deep-merge, массивы — конкатенация). |
| `-C, --config-directory <dir>` | взять все `*.json` из каталога (тоже merge). |
| `-D, --directory <dir>` | рабочий каталог процесса. |
| `--disable-color` | без ANSI-цвета (для логов в файл). |

**Команды:**
| Команда | Назначение |
|---------|-----------|
| `run` | запустить сервис (наш основной путь). |
| `check` | проверить конфиг(и) без запуска (наш pre-flight + `validate_via_binary`). |
| `format [-w]` | отформатировать конфиг (`-w` — переписать на месте). |
| `merge <output>` | склеить несколько `-c`/`-C` в один файл (доказывает, что merge поддержан). |
| `tools connect <addr>` | проверить досягаемость через конфиг (диагностика). |
| `tools fetch <url>` | HTTP-запрос через outbound (диагностика). |
| `tools synctime` | синхронизировать время (важно для TLS/Reality!). |
| `generate uuid` / `rand` / `reality-keypair` / `wireguard-keypair` / `tls-keypair` / `ech-keypair` / `vapid-keypair` | генерация ключей/идентификаторов. |
| `rule-set compile/decompile/convert/format/match/merge/upgrade` | работа с rule-set (бинарные `.srs`). |
| `geoip` / `geosite` | устаревшие (geoip/geosite удалены в пользу rule-set, §9). |
| `version` | версия (всегда снимай при диагностике). |

### 2.1 Режим отладки (наш `singbox.debug_log`)
`core/singbox_manager.py`: тумблер `singbox.debug_log` (API `GET/POST
/api/singbox/debug`, UI — «Режим отладки» в обзоре). Когда включён, при
запуске инстанса подмешивается **overlay вторым `-c`**:
```json
{"log": {"disabled": false, "level": "debug", "timestamp": true}}
```
(файл `<run_dir>/_zg-debug.json`). Тот же набор `-c` идёт и в pre-flight
`check`. **Graceful**: если билд не умеет merge (`check -c a -c b` != 0) —
overlay не применяется, инстанс стартует на обычном уровне (старт никогда не
ломаем). Overlay НЕ пишется в сам конфиг — выключил тумблер, перезапустил,
debug ушёл. Просмотр лога: `GET /api/singbox/configs/<name>/log?lines=N` →
`SingboxManager.read_log()` (хвост `platform.log_path`). UI — кнопка «Лог».

---

## 3. Верхнеуровневые ключи конфига

| Ключ | Назначение | Заметки по версиям |
|------|-----------|--------------------|
| `log` | логирование | см. §3.1 |
| `dns` | DNS-сервер и правила | **формат переписан в 1.12** (§7) |
| `ntp` | встроенный NTP-клиент | для TLS, если часы плывут |
| `certificate` / `certificate_providers` | TLS-сертификаты (ACME, Tailscale) | новое |
| `endpoints` | WireGuard / Tailscale как endpoint | добавлено в 1.11 |
| `inbounds` | входящие листенеры | legacy-поля sniff/domain_strategy удалены в 1.13 (§9) |
| `outbounds` | исходящие прокси | `block`/`dns` удалены в 1.13 (§9) |
| `route` | правила маршрутизации + rule-actions | §6 |
| `services` | доп. сервисы (DERP, resolved, ssm-api) | добавлено в 1.11+ |
| `experimental` | clash-api / cache-file / v2ray-api | §8 |

### 3.1 `log`
```json
{"log": {"disabled": false, "level": "info", "output": "box.log", "timestamp": true}}
```
- `level`: `trace | debug | info | warn | error | fatal | panic` (по умолч. `info`).
- `output`: путь к файлу. **ВАЖНО: если задан `output`, в консоль/stderr лог НЕ
  пишется.** Мы редиректим stderr в файл сами и `output` НЕ задаём — иначе наш
  захват лога опустеет. (Debug-overlay тоже без `output`.)
- `timestamp`: время в каждой строке (по умолч. true).

---

## 4. Inbounds (входящие)

Типы: `mixed` (http+socks одним портом — наш дефолт), `socks`, `http`,
`shadowsocks`, `vmess`, `vless`, `trojan`, `hysteria`, `hysteria2`, `tuic`,
`naive`, `shadowtls`, `tun`, `redirect`, `tproxy`, `direct`.

Общие поля listen-inbound: `type`, `tag`, `listen` (адрес, `::`/`0.0.0.0`/
`127.0.0.1`), `listen_port`.

> **1.11→1.13 (КРИТИЧНО):** legacy-поля inbound **`sniff`,
> `sniff_override_destination`, `sniff_timeout`, `domain_strategy`,
> `udp_disable_domain_unmapping`** объявлены deprecated в 1.11 и **удалены в
> 1.13**. Замена — route rule-actions `sniff` / `resolve` (§6). Наш код это уже
> делает: `make_sniff_rule()` ставит `{"action":"sniff"}`, inbound'ы «чистые».
> Issue #149 был ровно про это.

### TUN-inbound (`make_tun_inbound`)
`type:tun`, `interface_name` (`singbox-tun`), `address`
(`172.18.0.1/30`+v6), `mtu`, `stack` (`system`/`gvisor`/`mixed`),
`auto_route`, `strict_route`. Требует поддержку TUN в ядре
(`platform.tun_available()`). Не нужен TPROXY — забирает TCP+UDP.

---

## 5. Outbounds (исходящие) и endpoints

### 5.1 Прокси-типы (наши билдеры в `singbox_config.py`)
- **vless** (`make_vless_outbound`): `uuid`, опц. `flow:"xtls-rprx-vision"`,
  `tls`, `transport`, `multiplex`.
- **vmess** (`make_vmess_outbound`): `uuid`, `security`(`auto`), `alter_id`.
- **trojan** (`make_trojan_outbound`): `password`, обычно с `tls`.
- **shadowsocks** (`make_shadowsocks_outbound`): `method`, `password`.
- **hysteria2** (`make_hysteria2_outbound`): `password`, `up_mbps`/`down_mbps`,
  `obfs`(`salamander`), всегда TLS (часто `tls.insecure`).
- **tuic** (`make_tuic_outbound`): `uuid`, `password`,
  `congestion_control`(`bbr`), UDP-over-QUIC.
- **direct**, и группы ниже.

Общие поля: `type`, `tag`, `server`, `server_port`. `direct` — валидный тип
(прямой выход), НЕ deprecated.

### 5.2 Группы
- **selector** (`make_selector_outbound`): ручной выбор; `outbounds:[tags]`,
  `default`(тег), `interrupt_exist_connections`.
- **urltest** (`make_urltest_outbound`): авто по latency; `url`
  (`https://www.gstatic.com/generate_204` / cloudflare), `interval`,
  `tolerance`, `idle_timeout`. Наш пул заворачивает все ключи в urltest.

### 5.3 Endpoints (1.11+)
`endpoints` (отдельно от outbounds): `wireguard`, `tailscale`. WireGuard как
endpoint заменил старый `type:wireguard` outbound.

### 5.4 TLS / Transport / Multiplex (вложенные объекты)
- **tls**: `enabled`, `server_name`(SNI), `insecure`, `alpn`,
  `utls`(`{enabled, fingerprint:"chrome"}` — маскировка ClientHello),
  `reality`(`{enabled, public_key, short_id}`), `ech`.
- **transport**: `type` ∈ `ws` (`path`,`headers`), `grpc`(`service_name`),
  `httpupgrade`, `http`(h2), `quic`.
- **multiplex**: `{enabled, protocol:"smux|yamux|h2mux", max_streams,
  padding, brutal:{...}}`.

---

## 6. Route и rule-actions (1.11+ модель)

`route`: `rules:[...]`, `final`(тег по умолчанию), `auto_detect_interface`,
`default_mark`, `rule_set:[...]`.

Каждое правило = **матчеры + `action`**. Матчеры: `inbound`, `protocol`,
`domain`/`domain_suffix`/`domain_keyword`/`domain_regex`, `ip_cidr`,
`source_ip_cidr`, `port`/`port_range`, `network`(tcp/udp), `clash_mode`,
`rule_set`, и т.д.

**Actions (это и есть «новая модель» 1.11+):**
| action | смысл | ключевые параметры |
|--------|------|--------------------|
| `route` (default) | направить в outbound | `outbound` |
| `route-options` | оверрайды без финализации | override_address/port, TLS-fragment |
| `reject` | оборвать соединение | `method`: `default` (RST/ICMP-unreach) / `drop` (тихо) / `reply` (ICMP echo). **Заменяет удалённый `block`-outbound.** |
| `hijack-dns` | завернуть DNS в DNS-модуль sing-box | **Заменяет удалённый `dns`-outbound.** (`make_hijack_dns_rule`) |
| `sniff` | определить L7-протокол (для domain-правил) | `sniffer:[...]`, `timeout`(300ms). **Заменяет inbound `sniff`.** (`make_sniff_rule`) |
| `resolve` | резолв домена в IP до маршрутизации | `server`(тег), `strategy`(`prefer_ipv4`/`prefer_ipv6`/`ipv4_only`/`ipv6_only`), `disable_cache`, `rewrite_ttl`, `client_subnet` |
| `bypass` | обойти sing-box на уровне ядра (auto-redirect, только Linux) | — |

Типовой порядок правил при sniffing: сначала `{"action":"sniff"}`, затем
`{"protocol":"dns","action":"hijack-dns"}`, затем доменные/ip правила с
`outbound`, в конце `final`.

---

## 7. DNS (формат переписан в 1.12)

- **До 1.12 (legacy):** `dns.servers[].address` (`"tls://1.1.1.1"`,
  `"https://..."`, `"local"`, `"fakeip"`), `detour`, `address_resolver`,
  `strategy`.
- **С 1.12 (типизированный):** `dns.servers[].type` ∈ `udp | tcp | tls |
  https | quic | h3 | local | hosts | dhcp | fakeip | tailscale | resolved`,
  плюс `type:legacy` для старого address-формата (старое всё ещё принимается
  через `legacy`). Структура: `servers[]`, `rules[]`, `final`, `strategy`,
  `independent_cache`, `client_subnet`.

> При генерации DNS-секции учитывай целевую версию: на 1.12+ предпочитай
> типизированные серверы; legacy-`address` всё ещё валиден как `type:legacy`,
> но это путь к будущим поломкам. DNS-перехват у нас делается route-action
> `hijack-dns`, а не спец-outbound `dns` (тот удалён, §9).
>
> ⚠️ **Реальность нашего кода:** базовый unified/OS-routing путь **НЕ эмитит
> секцию `dns`** (`hijack-dns` — только в transparent-режиме с `dns_port>0`).
> НО есть отдельный **FakeIP-режим** (`build_fakeip_config` /
> `core/singbox_fakeip`), который генерирует полноценную `dns`-секцию с FakeIP
> + `hijack-dns` — см. §13.

---

## 8. experimental

- `clash_api` (`make_clash_api`): `{external_controller, secret,
  external_ui}` — даёт API для трафик-статистики/переключения (наш
  `/api/singbox/traffic`, enable-clash-api).
- `cache_file`: `{enabled, path, store_fakeip}` — кэш fakeip/urltest между
  рестартами.
- `v2ray_api`: устаревает в пользу clash_api.

---

## 9. Миграции версий — таблица «что удалено» (ГЛАВНОЕ при «не работает»)

| Версия | Удалено / изменено | Замена | Наш статус |
|--------|--------------------|--------|-----------|
| 1.8 | `geoip`, `geosite` (deprecated) | `rule_set` (бинарные `.srs`) | используем ipset/hostlist + rule-set при импорте |
| 1.11 | спец-outbounds **`block`**, **`dns`** (deprecated) | `reject` / `hijack-dns` rule-actions | `block` убран из `make_minimal_config`; dns-hijack через route |
| 1.11 | inbound-поля `sniff*`, `domain_strategy` (deprecated) | rule-actions `sniff` / `resolve` | `make_sniff_rule()` |
| 1.12 | формат `dns` (типизированные серверы) | `type:...`/`type:legacy` | см. §7 |
| **1.13** | **ФАКТИЧЕСКИ УДАЛЕНЫ** всё, что было deprecated в 1.11: `block`/`dns` outbounds и legacy inbound-поля | как выше | issue #149 — наш фикс; `validate()` оставляет block/dns в «известных типах» только для ЧТЕНИЯ чужих старых конфигов |

> Симптомы на 1.13: `FATAL ... legacy inbound fields ... removed in sing-box
> 1.13.0` (legacy sniff) или падение на `{"type":"block"|"dns"}`. Лечится
> переходом на rule-actions. Наш генератор уже чистый; импортированные/ручные
> конфиги пользователя — нет, поэтому существует pre-flight `check` и режим
> отладки.

---

## 10. Прозрачное проксирование (`singbox_transparent*`)

Режимы (`make_transparent_inbounds`, firewall в `singbox_transparent.py` /
`_nft.py`):
- **redirect** — `nat REDIRECT` (TCP). TPROXY НЕ нужен, работает почти везде.
  Минус: UDP/QUIC уходит напрямую.
- **tproxy** — `mangle TPROXY` (TCP+UDP). **Требует ядро/модуль
  `xt_TPROXY`/`nf_tproxy` + `iptables-mod-tproxy`.**
- **hybrid** — redirect для TCP + tproxy для UDP.
- **tun** — TUN-инбаунд, забирает TCP+UDP без TPROXY.

> **issue #149/#151 (Keenetic mips):** TPROXY часто ОТСУТСТВУЕТ (`modprobe not
> found`, `iptables-mod-* = Unknown package`). Тогда tproxy/hybrid не
> поднимутся в принципе. GUI зондирует цель TPROXY заранее, помечает
> tproxy/hybrid как недоступные, рекомендует **redirect** (TCP) или **TUN**
> (TCP+UDP). Правила обязаны строиться с явной таблицей (`-t mangle`/`-t nat`)
> — иначе уходят в `filter` и падают с «No chain/target/match by that name».

---

## 11. Подписки и парсинг ссылок

`subscription_importer` / `singbox_subscription` парсят форматы:
- **URI-ключи**: `vless://`, `vmess://` (base64-JSON), `ss://`
  (base64 method:pass), `trojan://`, `hysteria2://`/`hy2://`, `tuic://`.
- **base64-список** (строки URI в base64), **clash YAML**, **sing-box JSON**.
`format:"auto"` определяет тип сам. Дедуп по (type, server, port, cred) в
`server_pool.dedup_outbounds`, уникализация тегов.

**Пул источников** (`server_pool.BUILTIN_PRESETS`): публичные «свалки» ключей.
Инвариант «не затирать при пустом» — last-good кэш на источник. Битая ссылка
(404) → 0 ключей → берётся прошлый успешный набор. **Проверяй URL пресетов**:
файлы в публичных репо переименовываются/переезжают (igareck → `BLACK_*`;
kort0881 → `*_for_mirror.txt`), `configs.txt`/`vless.txt` в корне могут давать
404.

---

## 12. Диагностика «почему не работает» (чек-лист)

1. **`sing-box version`** — какая версия? (определяет, что валидно.)
2. **`sing-box check -c <config>`** — первый и главный шаг. Текст ошибки =
   причина (legacy-поля, удалённые типы, опечатки).
3. **Режим отладки** (§2.1) → `log.level=debug` → смотреть `read_log`/кнопку
   «Лог»: видно dial/handshake/TLS-ошибки, отказ сервера, неверный SNI/uuid.
4. **Часы**: TLS/Reality рушатся при расхождении времени → `tools synctime`.
5. **Транспорт/TLS совпадает с сервером?** ws-path, SNI, `flow`, `reality`
   public_key/short_id, `insecure` для self-signed/hysteria2.
6. **TPROXY** недоступен (§10) → redirect/TUN.
7. **DNS**: на 1.12+ legacy-формат — частая причина; hijack-dns через route.
8. **Лишний/удалённый ключ** (`block`/`dns` outbound, inbound `sniff`) на 1.13.

---

## 13. Наша selective-routing модель и DNS (и чем отличаемся от podkop)

**Как мы заворачиваем выбранные ресурсы в sing-box-TUN** (единый слой,
`core/unified`; см. `applier._apply_tunnel` + `geo_engine`):
- **домены / CIDR** правит **НЕ sing-box, а ОС-роутинг** (`core/routing`:
  dnsmasq + ipset/nftset + `ip rule`) — листовые домены резолвятся в ipset,
  их IP маршрутизируются в TUN-интерфейс; sing-box просто форвардит всё, что
  вошло в TUN, в прокси-outbound (`route.final`). DNS-leak частично закрывает
  `core/routing/doh_resolver.py` (преднаполнение set'а через DoH).
- **geosite / geoip** — нативные концепции движка, ОС их не выразит →
  `geo_engine._inject_singbox` добавляет их как sing-box route-правила
  (`domain_suffix/geosite/geoip → proxy`, `build_geo_route_rule`).
- `set_tun_inbound()` добавляет `{"action":"sniff"}` (доменные правила
  ВНУТРИ движка матчатся по SNI), но **`hijack_dns=False`** и **секцию `dns`
  не генерирует**. `auto_route=false` по умолчанию (трафик в TUN загоняет
  Selective routing через `ip rule`/ipset, а не сам sing-box).

**podkop устроен наоборот — DNS-центрично:** dnsmasq → sing-box DNS с
**FakeIP**; домены из списков получают fake-IP, диапазон fake-IP роутится в
TUN, sing-box по fake-IP восстанавливает домен и проксирует. Маршрутизация
управляется DNS/FakeIP внутри движка. podkop — **только OpenWrt 24.10+**
(fw4/nftset + переписываемый dnsmasq). Списки доменов у обоих из одного
источника — **itdoginfo/allow-domains** (наш `core/list_updater.py`).

**Почему у нас иначе:** мультиплатформенность (Keenetic/Entware с NDM-dnsmasq
и iptables, OpenWrt, Linux). На Keenetic нельзя свободно переписать резолвер
на sing-box-fakeip, поэтому базовый путь — ОС-роутинг по ipset.

**Известные ограничения нашего пути (которых нет у fakeip):**
- DNS клиента для проксируемого домена может уйти мимо и зарезолвиться в IP
  вне нашего ipset (geo-split CDN) → соединение не завернётся / лёгкий
  DNS-leak; `doh_resolver` смягчает, но best-effort.
- QUIC/ECH (шифрованный ClientHello) ломает SNI-sniff → доменные правила
  ВНУТРИ движка не сработают (fakeip сработал бы).
- Режим «весь трафик» (`auto_route=true`) без секции `dns` → системный
  резолвер может течь.

**FakeIP-режим (РЕАЛИЗОВАН)** — podkop-уровень надёжности доменного роутинга,
мультиплатформенно:
- `singbox_config.build_fakeip_config()` — собирает self-contained конфиг:
  TUN(`auto_route`+`strict_route`[+`auto_redirect` на nft]) + `dns` с FakeIP +
  `{action:sniff}` + `{protocol:dns,action:hijack-dns}` + domain/cidr-правила
  → `proxy-out`; `experimental.cache_file.store_fakeip`. `ip_is_private→direct`.
- `make_fakeip_dns()` — DNS-секция в **двух форматах**: legacy (`address:fakeip`
  + top-level `dns.fakeip`; валиден 1.8–1.13) и typed (`type:fakeip`; 1.12+).
- `core/singbox_fakeip.py` — оркестратор: резолвит прокси из ссылки
  (`uri_to_outbound`) или из конфига; домены берёт из hostlist'ов
  пользователя + формы; **подбирает формат DNS под версию и проверяет
  `sing-box check`-ом ДО сохранения** (`SingboxManager.check_text`), legacy↔typed
  fallback; `route_all` отключает FakeIP (весь трафик в прокси).
- API: `GET /api/singbox/fakeip/options`, `POST /api/singbox/fakeip/build`.
- UI: карточка «Умный доменный роутинг (FakeIP)» на дашборде sing-box
  (`web/js/pages/singbox.js`): ссылка/конфиг прокси, чекбоксы списков,
  доп. домены/подсети, прямой DNS, режим «весь трафик».

**DNS-перехват LAN-клиентов** (FakeIP работает, только если их DNS доходит до
движка):
- **nft** (OpenWrt): `auto_redirect` TUN сам забирает forwarded :53 → ничего
  не нужно.
- **iptables** (Keenetic): конфиг несёт `dns-in` direct-inbound на `dns_port`
  (1153), а `SingboxManager` на **старте** ставит REDIRECT udp/tcp `:53 →
  dns_port` и на **остановке** снимает (живёт ровно пока конфиг запущен —
  иначе LAN остался бы без DNS). Сделано через `singbox_transparent`
  **`mode="dns-only"`** (только DNS-hijack, без traffic-redirect; своя
  цепочка `SBT_REDIR_PRE` в nat PREROUTING — локальный DNS роутера/движка в
  OUTPUT не трогается → без петли). Состояние сохраняется как
  `singbox.transparent={mode:dns-only,...}`, поэтому переживает перезагрузку
  через штатный `--apply-singbox-transparent`. Сигнал «этому конфигу нужен
  перехват» — наличие inbound'а `tag=dns-in` (`_config_dns_in_port`).
  Конфликт-гард: если активно прозрачное проксирование (redirect/tproxy) —
  dns-only не ставится (общие цепочки).
- Управление — чекбокс «Перехватывать DNS LAN-клиентов» в карточке FakeIP
  (`capture_dns`, по умолчанию вкл); `build_and_save` возвращает `dns_capture`
  ∈ {auto_redirect, iptables-redirect, manual}.

---

## 14. Layout (где что)

- Бинарь: `singbox_detector.detect_binary()` (Entware: `/opt/sbin/sing-box`).
- Конфиги: `platform.config_dir` (`/opt/etc/sing-box/` | `/etc/sing-box/`).
- PID/лог/overlay: `platform.run_dir` (`/opt/var/run/sing-box/` | `/var/run/sing-box/`):
  `singbox-<name>.pid`, `<name>.log`, `_zg-debug.json`.
- last-good кэш пула: `.server_pool_cache.json` рядом с settings.json.
- Автозапуск: `singbox_autostart` (init-скрипт платформы).
