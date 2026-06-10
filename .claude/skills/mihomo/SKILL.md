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
   `core/mihomo_platform.py` (пути), `core/mihomo_installer.py` +
   `core/mihomo_detector.py` (бинарь/арх), `core/mihomo_autostart.py`,
   `core/clash_yaml.py` (конвертер clash→sing-box, §10), `api/mihomo.py`,
   `web/js/pages/mihomo.js`.

> ⚠️ **Мы почти не трогаем содержимое YAML.** `mihomo_manager` хранит конфиг
> как текст, проверяет минимально (валидный YAML + есть `proxies` или
> `proxy-providers`) и отдаёт всё на откуп `mihomo -t`. Поэтому **истина по
> ключам — официальная вики, а не наш код.** Не «угадывай» поля по нашему
> парсеру — их там нет.

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
| `-ext-ui`, `-secret`, `-m` | UI/секрет/лимит памяти | нет |

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
`proxy-providers` (§9), `dns` (§7), `tun`+`listeners` (§8), `sniffer`, `hosts`,
`ntp`, `experimental`.

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

**tun** (вики, config/inbound): `enable`, `stack` (`system`/`gvisor`/`mixed`),
`device`, `auto-route` (прописать маршруты, чтобы трафик шёл в TUN),
`auto-redirect`, `auto-detect-interface` (авто-определение выходного интерфейса),
`dns-hijack` (например `["any:53"]`), `mtu`, `strict-route`, `inet4-address` /
`inet4-route-address`, `endpoint-independent-nat`.

**listeners** (доп. входящие): `http`, `socks`, `mixed`, `redir`, `tproxy`,
`tunnel`, `tun`, а также серверные `shadowsocks`/`vmess`/`vless`/`trojan`/`tuic`.

> zapret-gui **не генерирует и не настраивает** TUN/tproxy/redir для mihomo —
> это делает сам YAML пользователя. Мы лишь детектим `/dev/net/tun`
> (`mihomo_detector`) и сообщаем доступность TUN. Прозрачный режим через ОС у
> нас исторически завязан на sing-box (`core/singbox_transparent*`) и
> Selective routing (`core/routing`).

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

**НЕ конвертируются** (пропуск с причиной «неподдерживаемый тип»): `wireguard`,
`snell`, `ssr`, `ssh`, `http`, `socks5`, `direct`, и т.п. — для них в sing-box
другой путь или нет аналога.

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
  log_path}`.

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

`GET /api/mihomo/environment` (+`/refresh`), `GET /install/status`,
`POST /install`, `POST /uninstall`, `GET /version` (проверка обновлений),
`GET /configs`, `POST /configs` (`{name,text}`), `GET|PUT|DELETE /configs/<name>`,
`POST /configs/<name>/up|down|restart`, `GET /configs/<name>/status`,
`POST /configs/<name>/validate` (`mihomo -t`), `GET /autostart`,
`POST /autostart/<name>` (`{enabled}`), `POST /autostart/{regenerate,remove,apply}`.

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

---

## 17. Layout (где что)

- Менеджер (run/test/up/down/status, CRUD): `core/mihomo_manager.py`.
- Пути/раскладка: `core/mihomo_platform.py`.
- Установка/детект/арх: `core/mihomo_installer.py`, `core/mihomo_detector.py`.
- Автозапуск: `core/mihomo_autostart.py`.
- Конвертер clash-YAML → sing-box (импорт): `core/clash_yaml.py`.
- API: `api/mihomo.py`. UI: `web/js/pages/mihomo.js`.
- Тесты: `tests/test_mihomo.py`, `tests/test_clash_yaml.py`.
