---
name: mihomo
description: >-
  Полный справочник по mihomo (MetaCubeX, ядро Clash.Meta) в проекте zapret-gui
  (роутеры Keenetic на Entware / OpenWrt / Linux). Использовать при любых задачах
  о: clash-YAML конфигах (general-ключи, proxies, proxy-groups, rules,
  rule-providers, proxy-providers, dns/fake-ip, tun, sniffer, listeners), типах
  прокси (ss/vmess/vless/trojan/hysteria2/tuic/wireguard/…), CLI (mihomo -d/-f/-t/-v),
  external-controller (RESTful API + metacubexd), запуске/валидации/диагностике
  инстансов (mihomo_manager), установке/детекте бинаря и архитектурах
  (mihomo_installer/detector), платформенных путях, автозапуске, geo-базах, а также
  о НАШЕМ конвертере clash-YAML → sing-box outbounds (core/clash_yaml.py) для
  импорта clash-подписок. Источник истины — MetaCubeX/mihomo + wiki.metacubex.one,
  привязка — наш код core/mihomo_*.py, core/clash_yaml.py, api/mihomo.py,
  web/js/pages/mihomo.js.
---

# mihomo (Clash.Meta) — справочник для zapret-gui

Единый источник истины о том, **как mihomo реально работает** и как с ним
обращаться в `zapret-gui`. Читать перед тем, как трогать менеджер mihomo,
конвертер clash-YAML, установку/детект или объяснять «почему mihomo не
стартует / конфиг не валиден».

Источники истины (в порядке убывания авторитета):
1. **wiki.metacubex.one** — официальная документация конфигурации и CLI;
   **MetaCubeX/mihomo** (Go-исходники, `docs/config.yaml`) — окончательная
   истина по схеме. mihomo — наследник Clash.Meta, форк-линия от Dreamacro/clash.
2. **`mihomo -t -f <config>`** — валидатор самого бинаря. Молчит → конфиг
   валиден для ЭТОЙ версии; ругается — это и есть причина.
3. **Наш код** — `core/mihomo_manager.py` (run/test/up/down/status),
   `core/mihomo_config.py` + `core/mihomo_routing.py` (генерация конфигов
   маршрутизации), `core/mihomo_proxies.py` (таблица прокси + Clash API),
   `core/mihomo_platform.py` (пути), `core/mihomo_installer.py` +
   `core/mihomo_detector.py` (бинарь/арх), `core/mihomo_autostart.py`,
   `core/mihomo_watchdog.py`, `core/clash_yaml.py` (конвертер clash→sing-box,
   §10), `api/mihomo.py`, `web/js/pages/mihomo{,_proxies,_setup}.js`.
   Полный список — §17.

> ⚠️ **Пользовательский YAML мы не переписываем.** `mihomo_manager` хранит
> конфиг как текст, проверяет минимально (валидный YAML + есть `proxies` или
> `proxy-providers`) и отдаёт всё на откуп `mihomo -t`. Свои конфиги мы
> **генерируем целиком** (`mihomo_config`, §11.1) — но и их валидирует
> бинарь. Поэтому **истина по ключам — официальная вики и исходники, а не наш
> парсер**: он покрывает подмножество YAML (см. §16.8) и «угадывать» поля по
> нему нельзя.

---

## 1. Две роли mihomo в zapret-gui (не путать)

1. **Standalone движок.** `mihomo_manager` запускает `mihomo -d <config_dir> -f
   <config.yaml>` как отдельный прокси-движок (clash-YAML конфиги, свой
   inbound/DNS/TUN/правила, RESTful API). Это самостоятельная альтернатива
   sing-box.
2. **Конвертер импорта.** `core/clash_yaml.py` — это **НЕ про запуск mihomo**, а
   про разбор clash-YAML подписки и **конвертацию proxies → sing-box
   outbounds** (§10). Используется, когда пользователь импортирует clash-ссылку,
   но гоняет трафик через sing-box.

Когда говорят «mihomo не работает» — сначала пойми, о какой роли речь: упавший
процесс mihomo (§11–16) или неконвертированный proxy при импорте в sing-box (§10).

---

## 2. CLI mihomo (что вызываем)

| Флаг/команда | Назначение | Используем? |
|--------------|-----------|-------------|
| `-d <dir>` | home/workdir: тут лежат `config.yaml`, кэш, **geo-базы** | **да** (`-d <config_dir>`) |
| `-f <file>` | путь к конфигу | **да** |
| `-t` | проверить конфиг и выйти (test) | **да** (pre-flight + `/validate`) |
| `-v` | версия | да (детект версии) |
| `-ext-ctl <addr>` | переопределить external-controller | нет (через YAML) |
| `-ext-ui`, `-secret`, `-m` | UI/секрет/geodata-режим | нет |

Таблица — только то, что вызываем мы; полный список шире. В v1.19.29 есть
ещё `-config` (конфиг base64-строкой), `-ext-ctl-tls`/`-ext-ctl-unix`/
`-ext-ctl-pipe`/`-ext-ctl-routing-mark`, `-post-up`/`-post-down` (скрипты),
`-age-secret-key`. Почти все дублируются переменными `CLASH_*` — сверено с
`main.go` mihomo v1.19.29.

Запуск у нас: `mihomo -d <config_dir> -f <config.yaml>` в новой сессии
(`start_new_session`), `stdin=DEVNULL`, stdout/stderr → лог-файл,
`RLIMIT_NOFILE=65536`, PID → `<run_dir>/mihomo-<name>.pid`.

---

## 3. Верхнеуровневые (general) ключи clash-YAML

Источник: wiki.metacubex.one/en/config/general.

| Ключ | Назначение |
|------|-----------|
| `port` / `socks-port` / `mixed-port` | HTTP / SOCKS / совмещённый порт |
| `redir-port` / `tproxy-port` | прозрачный proxy (REDIRECT / TPROXY) |
| `authentication` | логин:пароль для http/socks/mixed |
| `allow-lan` / `bind-address` | доступ из LAN / какие адреса слушать |
| `mode` | `rule` (по правилам, дефолт) / `global` / `direct` |
| `log-level` | `silent`/`error`/`warning`/`info`/`debug` |
| `ipv6` | принимать IPv6 (дефолт `true`) |
| `external-controller` | адрес RESTful API (для metacubexd / нашего мониторинга) |
| `external-ui` / `secret` | статика UI по `<api>/ui` / ключ доступа к API |
| `tcp-concurrent` | конкурентные TCP по всем resolved-адресам |
| `unified-delay` | двойной замер задержки (убрать вклад handshake) |
| `geodata-mode` | формат geoip: `mmdb` или `dat` |
| `geo-auto-update` / `geox-url` | автообновление / кастомные URL geo-баз |
| `find-process-mode` | `always`/`strict`(дефолт)/`off` — матчинг процессов |
| `global-client-fingerprint` | uTLS-отпечаток по умолчанию |
| `profile` | `store-selected` (запоминать выбор в группах), `store-fake-ip` |

Секции: `proxies` (§4), `proxy-groups` (§5), `rules`+`rule-providers` (§6),
`proxy-providers` (§9), `dns` (§7), `tun`+`listeners` (§8), `sniffer` (§8.1),
`hosts`, `ntp`, `experimental`.

> **geo-базы (`geoip.dat`/`geosite.dat`/`*.mmdb`) zapret-gui НЕ ставит** (в
> отличие от sing-box). Они лежат в `-d`-workdir (= `config_dir`); mihomo сам
> качает их при старте (`geox-url`) либо их кладёт пользователь. На роутере без
> исходящего доступа правила `GEOIP/GEOSITE` упадут, если баз нет — см. §16.

---

## 4. Proxies (типы и поля)

mihomo поддерживает: `ss` (shadowsocks), `ssr`, `snell`, `vmess`, `vless`,
`trojan`, `anytls`, `mieru`, `hysteria`, `hysteria2`, `tuic`, `wireguard`,
`tailscale`, `ssh`, `http`, `socks5`, плюс `direct`/`dns`. Общие поля:
`name` (уникальное), `type`, `server`, `port`, `udp`, `ip-version`,
`interface-name`, `routing-mark`, `tfo`, `mptcp`, `dialer-proxy`, `smux`.

Ключевые поля по типам (вики, config/proxies):
- **vless**: `uuid`, `flow` (`xtls-rprx-vision`), `network` (`tcp`/`ws`/`grpc`/`http`),
  `tls`, `servername`, `client-fingerprint`, `reality-opts`(`public-key`,`short-id`),
  `ws-opts`(`path`,`headers.Host`), `grpc-opts`(`grpc-service-name`).
- **vmess**: `uuid`, `alterId`, `cipher`(`auto`), `network`, `tls`, `servername`, `ws-opts`.
- **trojan**: `password`, `sni`, `skip-cert-verify`, `network`, `ws-opts`.
- **ss**: `cipher`, `password`, `udp`, опц. `plugin`/`plugin-opts`.
- **hysteria2**: `password`(или `auth`), `sni`, `skip-cert-verify`, `up`/`down`,
  `obfs`/`obfs-password`.
- **tuic**: `uuid`, `password`, `sni`, `alpn`, `congestion-controller`.
- **wireguard**: `private-key`, `peers`/`public-key`, `allowed-ips`, `reserved`,
  и — важно — **`amnezia-wg-option`** (mihomo умеет AmneziaWG-обфускацию прямо в
  wireguard-outbound; см. skill `awg` про сами параметры).

---

## 5. Proxy-groups

Типы: `select`, `url-test`, `fallback`, `load-balance`, `relay`. Поля:
`name`, `type`, `proxies`, `use` (имена proxy-providers), `url`, `interval`,
`tolerance`, `lazy`, `timeout`, `max-failed-times`, `filter`, `exclude-filter`,
`include-all` / `include-all-proxies` / `include-all-providers`, `disable-udp`,
`hidden`, `icon`. У `load-balance` — `strategy`
(`round-robin`/`consistent-hashing`/`sticky-sessions`).

---

## 6. Rules и rule-providers

Формат правила: `ТИП,аргумент,цель[,модификатор]`. Цель — имя proxy/группы,
`DIRECT`, `REJECT`, `PASS`.

Типы (вики, config/rules): `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`,
`DOMAIN-REGEX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-ASN`,
`GEOIP`, `SRC-GEOIP`, `SRC-IP-CIDR`, `SRC-PORT`, `DST-PORT`, `IN-PORT`,
`IN-TYPE`, `IN-USER`, `NETWORK` (`tcp`/`udp`), `DSCP`, `PROCESS-NAME`,
`PROCESS-PATH`, `RULE-SET`, `AND`/`OR`/`NOT`, `SUB-RULE`, `MATCH` (последнее,
ловит всё). Модификаторы: **`no-resolve`** (не резолвить для IP-правил),
**`src`** (матчить source IP). Примеры:
`DOMAIN-SUFFIX,google.com,PROXY` · `IP-CIDR,127.0.0.0/8,DIRECT,no-resolve` ·
`GEOIP,CN,DIRECT` · `MATCH,PROXY`.

**rule-providers** — внешние списки правил: `type` (`http`/`file`/`inline`),
`behavior` (`domain`/`ipcidr`/`classical`), `format` (`yaml`/`text`/`mrs`),
`url`, `path`, `interval`. Ссылаются из `rules` через `RULE-SET,<name>,<цель>`.

---

## 7. DNS (включая fake-ip)

Ключи (вики, config/dns): `enable`, `listen`, `ipv6`, `prefer-h3`,
`enhanced-mode` (`fake-ip` / `redir-host`), `fake-ip-range` (дефолт
`198.18.0.1/16`), `fake-ip-filter` + `fake-ip-filter-mode`
(`blacklist`/`whitelist`/`rule`), `default-nameserver` (только IP — ими
резолвятся хостнеймы других DNS), `nameserver`, `fallback`, `fallback-filter`
(`geoip`,`geoip-code`,`geosite`,`ipcidr`,`domain`), `nameserver-policy`,
`proxy-server-nameserver` (резолв доменов прокси-узлов), `direct-nameserver`,
`use-hosts`, `use-system-hosts`, `respect-rules`.

Схемы nameserver: `udp://`, `tcp://`, `tls://`(DoT), `https://`(DoH),
`quic://`(DoQ), `system`, `dhcp`, `rcode://`. Суффикс `#` задаёт параметры
сервера (например `#proxy` — гонять DNS-запрос по правилам/через прокси,
`&ecs=…` — EDNS Client Subnet).

> **fake-ip** — аналог singbox-fakeip: доменам выдаются адреса из
> `fake-ip-range`, маршрутизация идёт по ним, по правилам восстанавливается
> домен. На роутере это самый надёжный доменный роутинг, но требует, чтобы DNS
> LAN-клиентов доходил до mihomo (TUN `dns-hijack` или REDIRECT :53).

---

## 8. TUN / прозрачное проксирование / listeners

**tun** (вики, config/inbound): `enable`, `stack` (`system`/`gvisor`/`mixed`,
дефолт `gvisor`), `device`, `auto-route` (прописать маршруты, чтобы трафик шёл
в TUN), `auto-redirect` (nft-redirect для ПЕРЕсылаемого трафика LAN; только
Linux+nftables, вместе с `auto-route`), `auto-detect-interface`, `dns-hijack`
(например `["any:53"]`; без схемы подразумевается `udp://`), `mtu`,
`strict-route`, `route-address` / `route-address-set` /
`route-exclude-address-set` (последние два — только nftables при
`auto-route`+`auto-redirect`), `gso`/`gso-max-size` (дефолт 65536),
`disable-icmp-forwarding`, `endpoint-independent-nat`, `udp-timeout` (300 c),
`iproute2-table-index` (2022) / `iproute2-rule-index` (9000), устаревшие
`inet4-address`/`inet4-route-address`.

> **`device` по умолчанию — `Meta`, а не `utun`.** В
> `listener/sing_tun/server.go`: `var InterfaceName = "Meta"`, и
> `CalculateInterfaceName()` на не-darwin возвращает это имя как есть (префикс
> `utun` — исключительно macOS). Значит конфиг с `tun: {enable: true}` без
> `device` создаёт интерфейс **`Meta`**. Мы на это опираемся в
> `core/mihomo_config.tun_device_from_text()` — правило маршрутизации должно
> указывать на реальное имя, иначе оно молча ни во что не заворачивает.

**listeners** (доп. входящие): `http`, `socks`, `mixed`, `redir`, `tproxy`,
`tunnel`, `tun`, а также серверные `shadowsocks`/`vmess`/`vless`/`trojan`/`tuic`.

> Прозрачный режим через ОС (iptables/nft-правила) у нас завязан на sing-box
> (`core/singbox_transparent*`) и Selective routing (`core/routing`). Для
> mihomo мы TUN не настраиваем на уровне ОС — движок делает это сам
> (`auto-route`/`auto-redirect`), а секцию `tun` в конфиге **генерируем**
> (`core/mihomo_config.make_tun()`, флоу «Маршрутизация» на странице mihomo).
> Дополнительно детектим `/dev/net/tun` (`mihomo_detector`).

### 8.1 sniffer — как движок узнаёт домен

`sniffer` определяет домен по содержимому соединения (TLS SNI / HTTP Host),
когда его неоткуда взять иначе. Ключи и **дефолты сверены с
`config/config.go` v1.19.29** (`DefaultRawConfig`):

| Ключ | Дефолт | Смысл |
|------|--------|-------|
| `enable` | `false` | сниффер выключен, пока не включишь |
| `sniff` | `{}` | что и на каких портах: `TLS`/`QUIC` (без `ports` — 443), `HTTP` (без `ports` — 80). Каждый протокол может переопределить `override-destination` |
| `override-destination` | **`true`** | подменять адрес назначения сниффнутым доменом |
| `force-dns-mapping` | `true` | принудительно сниффить трафик, опознанный как redir-host |
| `parse-pure-ip` | `true` | сниффить всё, у чего домена нет вовсе |
| `force-domain` / `skip-domain` | `[]` | белый/чёрный список доменов |
| `skip-src-address` / `skip-dst-address` | `[]` | пропускать по адресам |
| `sniffing` / `port-whitelist` | — | **устаревшие**, игнорируются, если задан `sniff` |

> ⚠️ **Когда fake-ip не спасает.** Доменные правила (`DOMAIN-SUFFIX`,
> `GEOSITE`) матчатся, только если движок знает домен. При `enhanced-mode:
> fake-ip` он его знает — но лишь для клиентов, чей DNS идёт **через сам
> mihomo**. Приложение со своим DoH/DoT (браузер с DNS-over-HTTPS,
> `opera-proxy`, `usque`) резолвит мимо движка, и mihomo видит только IP —
> доменное правило не сработает. Единственное лекарство — `sniffer`.
> Именно поэтому `core/opera_proxy_chain._attach_mihomo()` при подключении
> opera-proxy в TUN-конфиг включает сниффер: без него защита от петли
> `DOMAIN-SUFFIX,sec-tunnel.com,DIRECT` мертва и трафик самого прокси
> уходит в туннель по кругу.
>
> **`override-destination` при fake-ip ставь в `false`.** Дефолт `true`
> подменяет назначение сниффнутым доменом и ломает уже корректную
> fake-ip-маршрутизацию; для матчинга правил подмена не нужна — домен
> попадает в метаданные соединения в любом случае.

---

## 9. proxy-providers (подписки)

Внешние источники прокси: `type` (`http`/`file`/`inline`), `url`, `path`,
`interval`, `proxy` (через какой прокси качать), `header`, `health-check`
(`enable`,`url`,`interval`,`lazy`,`expected-status`), `override`
(`additional-prefix`/`-suffix`, `skip-cert-verify`, `udp`, …), `filter`,
`exclude-filter`, `exclude-type`, `dialer-proxy`. Подключаются в группах через
`use: [<provider>]` или `include-all-providers`.

---

## 10. Наш конвертер clash-YAML → sing-box (`core/clash_yaml.py`)

Это **отдельная** функция (импорт clash-подписки в движок sing-box), не запуск
mihomo. Мини-парсер YAML + реестр конвертеров `_CLASH_CONVERTERS`.

**Конвертируются 6 типов** (clash-proxy → sing-box outbound):

| clash `type` | → sing-box | Заметки маппинга |
|--------------|-----------|------------------|
| `ss` | `shadowsocks` | `cipher`/`method` → `method` (через `normalize_ss_method`), `password` |
| `vless` | `vless` | `uuid`, `flow`; `network ws/grpc` → `transport`; `tls`/`security:reality` → `tls` c `reality`(`public-key`→`public_key`,`short-id`→`short_id`), `servername`/`sni`→`server_name`, `client-fingerprint`→`utls`. **Reality без fingerprint → utls `chrome`** автоматически |
| `vmess` | `vmess` | `uuid`, `cipher`(`auto`)→`security`, `alterId`→`alter_id`, ws-transport, tls |
| `trojan` | `trojan` | `password`, `sni`/`servername`→`server_name`, `skip-cert-verify`→`insecure`, ws |
| `hysteria2`/`hy2` | `hysteria2` | `password`/`auth`, sni, `skip-cert-verify`→`insecure` |
| `tuic` | `tuic` | `uuid`, `password`, sni |

**НЕ конвертируются** — узел попадает в `skipped` с причиной
«неподдерживаемый тип» (не теряется молча: список отдаётся вызывающему и
показывается в GUI). Но причины у разных типов **разные**, и это важно:

| Тип в clash | Почему не конвертируем |
|---|---|
| `anytls`, `hysteria` (v1), `ssh`, `socks5`→`socks`, `http` | **Аналог в sing-box ЕСТЬ** — просто конвертер не написан. Реальный пробел, а не ограничение |
| `wireguard` | В sing-box это не outbound, а **`endpoint`** (outbound удалён в 1.13) — нужен отдельный путь, см. скил `singbox` §5.3 |
| `tailscale` | Тоже не outbound: в sing-box это endpoint/service |
| `ssr`, `snell` | Аналога нет: ShadowsocksR из sing-box выпилен ещё в 1.6, snell там не реализован |
| `mieru`, `masque`, `shadowquic`, `trusttunnel`, `openvpn`, `sudoku`, `rematch` | Протоколы, которые есть только у mihomo |
| `direct`, `dns`, `reject` | Служебные, при импорте узлов не нужны |

Список типов сверен с `adapter/parser.go` mihomo v1.19.29 и каталогом
`docs/configuration/outbound/` sing-box v1.13.15. Апстрим mihomo добавляет
протоколы заметно быстрее — при следующей сверке проверить, не появился ли
аналог у обоих.

> Нюанс YAML: `short-id: 01` парсится как int `1` — конвертер обрабатывает это
> best-effort, чтобы не потерять ведущий ноль. `proxy-groups`/`rules` при таком
> импорте **не переносятся** — берутся только узлы. Тесты: `tests/test_clash_yaml.py`.

---

## 11. Менеджер: запуск / валидация / статус (`mihomo_manager`)

- **Имя конфига** — regex `^[A-Za-z0-9_.\-]{1,32}$`; файл `<config_dir>/<name>.yaml`.
- **Лёгкая проверка** (`validate_yaml`): валидный YAML-словарь + есть `proxies`
  ИЛИ `proxy-providers`. Ошибки: «пустой конфиг», «неправильный YAML», «нет
  секции proxies».
- **Глубокая проверка** (`validate_via_binary`): `mihomo -t -f <path>` (timeout
  15 c) → `{ok, stdout, stderr, returncode}`.
- **up**: pre-flight `mihomo -t`; если не прошёл — не стартуем, отдаём stderr.
  Старт (§2), через ~1 c проверяем, не упал ли процесс; если упал — хвост лога
  (до 80 строк) в ошибку («mihomo упал при старте (exit=…)»).
- **down**: SIGTERM → ждём 5 c → SIGKILL. **restart** = down → 0.5 c → up.
- CRUD: `list_configs`/`get_config`/`save_config` (атомарно через `.tmp`+rename)/
  `delete_config` (только если не запущен). `status(name)` → `{name, active, pid,
  log_path}`. `list_configs()` дополнительно отдаёт `tun_iface`/`tun_enabled` —
  через них mihomo попадает в цели маршрутизации (§16.9).

## 11.1 Наши генераторы конфигов маршрутизации

`core/mihomo_config.py` — **чистые** билдеры (без I/O), `core/mihomo_routing.py`
— оркестратор. Два режима, оба самодостаточные: OS-слой `ip rule` для них не
нужен, трафик забирает сам движок.

| Режим | Билдер | Кого проксируем | Стек по умолчанию |
|-------|--------|-----------------|-------------------|
| домены / списки | `build_domain_config()` | выбранные домены и подсети (`RULE-SET`/`DOMAIN-SUFFIX` + `IP-CIDR` → `PROXY`, остальное `MATCH,DIRECT`), либо весь трафик | `gvisor` |
| устройства / весь трафик | `build_source_config()` | `SRC-IP-CIDR` выбранных устройств, либо весь трафик | `system` (kernel, низкий CPU) |

Общий каркас: `mode: rule`, `unified-delay`, `tcp-concurrent`,
`external-controller` на свободном порту 127.0.0.1 + `secret`, `proxies`,
одна `proxy-group` (`PROXY`, `select` либо `url-test`), `tun` (§8), `dns` с
`enhanced-mode: fake-ip` и «приватное → DIRECT» первым правилом.

Осознанные решения (уроки sing-box, см. комментарии в модуле): `mtu: 1500`
(9000 с gvisor на MIPS → GC-молотьба и 100% CPU), `strict-route: false` (не
«лочим» роутер при мёртвом прокси), QUIC **не** глушим по умолчанию (ломает
DoH3 клиента), DoH задаём **по имени хоста** (`https://cloudflare-dns.com/…`,
не по IP-литералу — иначе не сходится TLS-сертификат), домены прокси-серверов
исключаются из fake-ip и резолвятся через `proxy-server-nameserver` (иначе
петля «резолв адреса прокси через сам прокси»).

`geosite:`/`geoip:` в этом флоу **разворачиваются нашим `alias_resolver`** в
домены и CIDR (тот же путь, что у OS-routing/sing-box/AWG) — geo-базы mihomo
для них не нужны, что важно на роутере без исходящего доступа (§3, §16.3).

`_validate_and_pick()` собирает несколько кандидатов (стек `gvisor`↔`system`,
inline `RULE-SET`↔развёрнутые `DOMAIN-SUFFIX`) и берёт **первый, который принял
`mihomo -t`**; без бинаря сохраняет самый совместимый с предупреждением.

---

## 12. Установка и детект (`mihomo_installer` / `mihomo_detector`)

- **Источник** — GitHub-релизы **MetaCubeX/mihomo**. Ассет:
  `mihomo-linux-<arch>-v?<ver>.gz` (gzip-распаковка в бинарь).
- **Маппинг арх** (от общего детектора): `x86_64→amd64`, `aarch64→arm64`,
  `armv7→armv7`, `mips-softfloat→mips-softfloat`, `mipsel-softfloat→mipsle-softfloat`.
  **`amd64` — точное совпадение**, не `amd64-compatible`/`amd64-v3` (это
  отдельные варианты под старые/новые CPU).
- **Детект бинаря**: `platform.binary_path()`, затем PATH в `/opt/usr/{sbin,bin}`,
  `/opt/{bin,sbin}`, `/usr/local/{sbin,bin}`, `/usr/{sbin,bin}`, `/{sbin,bin}`.
  Имена: `mihomo`, `clash.meta`, `clash-meta`, `clash` (исторические). Версия —
  `mihomo -v`, regex `v?(\d+\.\d+\.\d+)`.
- Состояние установки — `mihomo-installed.json` (`{tag, version, binary,
  installed_at}`).

---

## 13. Платформенные пути (`mihomo_platform`)

| | Keenetic/Entware | OpenWrt | Generic Linux |
|--|------------------|---------|---------------|
| bin | `/opt/usr/sbin/mihomo` | `/usr/sbin/mihomo` | `/usr/local/bin/mihomo` |
| config (= `-d` workdir) | `/opt/etc/mihomo` | `/etc/mihomo` | `/etc/mihomo` |
| run | `/opt/var/run/mihomo` | `/var/run/mihomo` | `/var/run/mihomo` |
| log | `/opt/var/log` | `/var/log` | `/var/log` |
| init | `/opt/etc/init.d` (`S53mihomo-gui`) | `/etc/init.d` (`mihomo-gui`) | systemd (`mihomo-gui.service`) |

Шаблоны: `config_path(name)=<config_dir>/<name>.yaml`,
`pid_path=<run_dir>/mihomo-<name>.pid`, `log_path=<log_dir>/mihomo-<name>.log`.
**`config_dir` = `-d`-workdir mihomo**, поэтому geo-базы и кэш fake-ip кладутся
туда же.

---

## 14. Автозапуск (`mihomo_autostart`)

Флаги в `settings.json` → `mihomo.autostart = {<name>: true}`. Init-скрипт:
- **Entware/OpenWrt**: sh со `start_one`/`stop_one`, `ulimit -n 65536`,
  `setsid <bin> -d <config_dir> -f <config> &` + ручной PID-файл; действия
  `start|stop|restart|status`.
- **systemd**: `.service` (`LimitNOFILE=65536`). ⚠️ текущая реализация systemd-юнита
  поднимает **только первый** включённый конфиг — для нескольких нужен отдельный
  юнит на конфиг.

`regenerate()` пишет/ставит скрипт, `apply_now()` поднимает включённые сразу,
`remove()` удаляет скрипт.

---

## 15. API (`api/mihomo.py`)

**Окружение и бинарь:** `GET /environment` (+`POST /environment/refresh`),
`GET /install/status`, `POST /install`, `POST /install/local` (multipart),
`GET /releases`, `POST /uninstall`, `GET /version`.

**Конфиги:** `GET /configs`, `POST /configs` (`{name,text}`),
`GET|PUT|DELETE /configs/<name>`, `POST /configs/<name>/up|down|restart`,
`GET /configs/<name>/status`, `POST /configs/<name>/validate` (`mihomo -t`,
принимает несохранённый `{text}`), `GET /configs/<name>/log?lines=N`.

**Прокси-таблица:** `GET /configs/<name>/proxies`,
`POST /configs/<name>/activate` (переключение узла вживую через
external-controller), `POST /configs/<name>/enable-controller`,
`POST /configs/<name>/proxies/delete-bulk`, `POST /configs/<name>/import-links`
(Ctrl+V), `POST /export-links` (Ctrl+C).

**Маршрутизация:** `GET /routing/options`, `POST /routing/domain/build`,
`POST /routing/source/build`.

**Прочее:** `GET|POST /watchdog`, `GET|POST /debug` (log-level=debug),
`POST /test` + `GET /test/status`, `GET /traffic?config=<name>`,
`GET /autostart`, `POST /autostart/<name>` (`{enabled}`),
`POST /autostart/{regenerate,remove,apply}`.

Ответ `GET /configs/<name>/proxies` (важен для §16.8): `proxies` (строки
таблицы), `providers`/`provider_live` (подписки), `live_nodes` (узлы,
которые реально загрузил движок), `groups`/`active`/`select_groups`,
`controller`/`controller_live`/`running`, а также `parse_error` и
`text_fallback` — признаки того, что YAML разобрался не полностью.

---

## 16. Диагностика «не работает» (чек-лист)

1. **`mihomo -t -f <config>`** (или `/validate`) — первый шаг. Текст ошибки =
   причина (неизвестный ключ/тип прокси, кривой YAML, опечатка в `rules`).
2. **Процесс упал сразу после старта?** — `mihomo_manager` отдаёт хвост лога;
   читать `log_path` (`<log_dir>/mihomo-<name>.log`). Частое: занятый порт
   (`mixed-port`), нет прав на TUN, битый бинарь.
3. **`GEOIP`/`GEOSITE`/`RULE-SET` не матчатся / ошибка загрузки** — **нет geo-баз**
   в workdir, а исходящего доступа на роутере нет (мы базы не ставим, §3). Решение:
   положить `geoip.dat`/`geosite.dat`/`*.mmdb` в `config_dir` вручную или задать
   доступный `geox-url`.
4. **Битый бинарь** (неверная арх, особенно `amd64` vs `amd64-compatible`,
   endianness MIPS) — переустановить под верную арх (§12).
5. **`external-controller` недоступен** — проверь адрес/`secret`; для роутера
   слушать на LAN-адресе, не только `127.0.0.1`.
6. **Прокси не ходит, хотя инстанс жив** — проверь сам узел (sni/uuid/cipher/
   reality), `unified-delay`/задержки в группе `url-test`, `mode` (в `direct`
   правила игнорируются), и доходит ли DNS до mihomo при fake-ip (§7).
7. **Импорт clash-подписки в sing-box** (НЕ запуск mihomo) — если узел
   пропал, его тип не из 6 поддерживаемых (§10): `wireguard`/`snell`/`ssr`/… не
   конвертируются.
8. **«В редакторе прокси есть, а в таблице пусто» / «mihomo нет в списке целей
   маршрутизации»** — это ОДИН симптом: конфиг не разобрался нашим YAML-парсером.
   Чаще всего виноваты **якоря и `<<:`-merge** (частый приём генераторов
   подписок), которые самописный fallback-парсер (окружение без PyYAML —
   типичная Entware-сборка) не понимает; секции `proxies` и `tun` при этом
   «исчезают» одновременно. Что сделано, чтобы это не выглядело как пустой
   конфиг:
   - ошибка разбора видна в ответе `/proxies` (`parse_error`) и в баннере
     страницы, а не глотается;
   - `mihomo_proxies.proxies_from_text()` снимает `name/type/server/port` прямо
     с текста блока `proxies:` (флаг `text_fallback`);
   - у запущенного инстанса список дополняется правдой рантайма — `live_nodes`
     из `GET /proxies` его external-controller;
   - `mihomo_config.tun_device_from_text()` так же имеет текстовый фолбэк для
     блока `tun:`, поэтому цель маршрутизации не пропадает.
   Если прокси не видно даже так — проверь, не подписка ли это
   (`proxy-providers`, §9): её узлов в файле нет by design.
9. **Тест говорит «мертво» на заведомо живых узлах.** Три частые причины,
   и все они не про сервер:
   - **узел только что добавлен, а инстанс не перезапущен** — замер идёт в
     запущенный движок через external-controller, а тот держит набор узлов
     на момент старта; `/proxies/<имя>/delay` отвечает 404. Мы это ловим
     (`controller_known_names()`) и меряем новые узлы одноразовым `mihomo`;
   - **ссылка потеряла `allowInsecure`** — у hysteria2 сертификат обычно
     self-signed, а `sni` часто просто IP; без `skip-cert-verify`
     рукопожатие падает (см. `_insecure_flag` в `singbox_subscription`);
   - **умерли ВСЕ и по одной причине** — смотри её текст в строке: «имя не
     резолвится (DNS)» / «нет маршрута» означает проблему у самого роутера
     (сломанный резолвер, трафик роутера завёрнут в нерабочий туннель), а
     не у ключей. Тест выводит это отдельной подсказкой.
10. **«Удаление прокси требует PyYAML»** — больше не требует: удаление идёт
   текстом (`remove_proxies_text`), вырезая элементы блока `proxies:` и
   ссылки на них в `proxy-groups[].proxies`. Round-trip через PyYAML
   остался фолбэком для нестандартных блоков (инлайн/якорь). Если после
   удаления группа осталась без узлов, конфиг не запустится — об этом
   предупреждает и API (`emptied_groups`), и UI.
11. **Конфиг запущен, но `mihomo:<iface>` не предлагается в правилах
   маршрутизации** — у конфига нет секции `tun`. Это не поломка: без TUN
   mihomo работает обычным прокси на порту, сетевого интерфейса нет и
   `ip rule` заворачивать некуда. `/api/routing/interfaces` объясняет это
   в поле `notes`.

---

## 17. Layout (где что)

- Менеджер (run/test/up/down/status, CRUD, debug/log): `core/mihomo_manager.py`.
- Генератор clash-YAML для маршрутизации (tun/dns-fakeip/rules):
  `core/mihomo_config.py`; оркестратор (резолв прокси → сборка → `mihomo -t` →
  сохранение): `core/mihomo_routing.py`.
- Прокси-таблица, Clash API запущенного инстанса, текстовые правки конфига:
  `core/mihomo_proxies.py`; тестер задержек: `core/mihomo_proxy_tester.py`.
- Watchdog: `core/mihomo_watchdog.py`. Учёт трафика: `core/proxy_traffic.py`.
- Пути/раскладка: `core/mihomo_platform.py`.
- Установка/детект/арх: `core/mihomo_installer.py`, `core/mihomo_detector.py`.
- Автозапуск: `core/mihomo_autostart.py`.
- Конвертер clash-YAML → sing-box (импорт): `core/clash_yaml.py`.
- opera-proxy как upstream внутрь конфига: `core/opera_proxy_chain.py` (§8.1).
- API: `api/mihomo.py`. UI: `web/js/pages/mihomo.js` (инстансы + маршрутизация),
  `mihomo_proxies.js` (таблица прокси), `mihomo_setup.js` (установка).
- Тесты: `tests/test_mihomo.py`, `tests/test_mihomo_proxies.py`,
  `tests/test_mihomo_providers.py`, `tests/test_api_mihomo_routing.py`,
  `tests/test_clash_yaml.py`, `tests/test_opera_proxy_chain.py`.
