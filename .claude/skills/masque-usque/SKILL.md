---
name: masque-usque
description: >-
  Полный справочник по MASQUE / usque (Cloudflare WARP поверх HTTP/3) в проекте
  zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux). Использовать при
  любых задачах о: протоколе MASQUE и CONNECT-IP (RFC 9484 / RFC 9298), CLI
  usque (register/enroll/nativetun/socks/http-proxy/l4-socks/l4-http-proxy/
  portfw/account/version) и его флагах (-c/--config, -n/--interface-name,
  -s/--sni-address, -k/--keepalive-period, -m/--mtu, -I/--no-iproute2,
  -P/--connect-port, -6/--ipv6, -F/--no-tunnel-ipv4, -S/--no-tunnel-ipv6,
  --http2, --insecure, --persist, --always-reconnect, -r/--reconnect-delay,
  -i/--initial-packet-size, --on-connect/--on-disconnect), формате
  config.json (private_key ECDSA P-256, access_token, id, endpoint_v4/v6,
  endpoint_h2_v4/v6, endpoint_pub_key, license, ipv4, ipv6), регистрации
  устройства в Cloudflare и ZeroTrust (--jwt), «ленивом» подключении туннеля
  и том, почему «Tunnel established» не значит «подключено», настройке
  TUN-интерфейса (кто назначает адреса и поднимает link), профилях транспорта
  performance/restricted/auto (H3/QUIC против H2/TCP), SNI-маскировке,
  установке пакета usque-keenetic (.ipk через opkg, sha256), автозапуске,
  watchdog'е, WARP-in-WARP, API /api/usque/*, CLI `zapret-gui usque` и
  диагностике «туннель не поднимается / интерфейс есть, а трафика нет /
  версия показывается мусором». Источники истины — Diniboy1123/usque и
  side-effect-tm/usque-keenetic, привязка — наш код core/usque_manager.py,
  core/usque_watchdog.py, api/usque.py, web/js/pages/usque.js,
  core/warp_in_warp.py, core/ext_binary_installer.py.
---

# MASQUE / usque — справочник для zapret-gui

Единый источник истины о том, **как работает usque** (клиент Cloudflare WARP
по протоколу MASQUE) и как с ним обращаться в `zapret-gui`. Читать перед тем,
как трогать менеджер, watchdog, установку бинарника, WARP-in-WARP или
объяснять «почему туннель не поднимается».

Источники истины (в порядке убывания авторитета):

1. **Сам бинарник.** `usque <cmd> --help` — единственный достоверный список
   флагов и дефолтов для КОНКРЕТНОЙ версии. **Всё в §3 сверено с реальным
   выводом `--help` бинарника usque v4.2.0, собранного из тега `v4.2.0`**
   (`go build`, linux/amd64), а не пересказано по README.
2. **[Diniboy1123/usque](https://github.com/Diniboy1123/usque)** — апстрим
   (неофициальный клиент WARP на MASQUE). README + `_docs/` + wiki.
   Последний релиз на момент написания — **v4.2.1**.
3. **[side-effect-tm/usque-keenetic](https://github.com/side-effect-tm/usque-keenetic)**
   — сборка usque под Keenetic/Entware в виде `.ipk`, откуда мы ставим
   бинарник. Последний релиз — **v0.3.0** (несёт usque **v4.2.0**, добавлена
   поддержка HTTP/2).
4. **Наш код** — `core/usque_manager.py` (жизненный цикл, детект, импорт
   конфигов, лог), `core/usque_watchdog.py` (проба и рестарт),
   `api/usque.py` (REST), `web/js/pages/usque.js` + `usque_setup.js`
   (страницы), `core/warp_in_warp.py` (двойной туннель),
   `core/ext_binary_installer.py` (`BINARIES["usque"]`), `core/cli.py`
   (`zapret-gui usque`), `core/config_manager.py` (секция `usque`),
   `app.py` (`_apply_usque_autostart_on_boot`), `core/tunnel_monitor.py`.

> ⚠️ **Две главные ловушки, на которых горит отладка** (обе проверены
> экспериментально, см. §6 и §5):
>
> 1. **`--no-iproute2` не поднимает интерфейс.** Флаг означает «не назначай
>    адреса **и не поднимай link**». TUN появляется, но остаётся
>    `operstate=down` и без единого IP-адреса. Кто-то должен сделать это
>    за usque — иначе интерфейс есть, а трафика нет.
> 2. **«Tunnel established» ≠ «подключено».** Эта строка печатается сразу
>    после создания TUN, ДО какого-либо сетевого обмена. Реальное
>    MASQUE-соединение устанавливается **лениво**, при первом исходящем
>    пакете. Поэтому неподнявшийся туннель выглядит в логе как успешный.

---

## 1. Что это такое и чем НЕ является

**MASQUE** (Multiplexed Application Substrate over QUIC Encryption) — набор
IETF-механизмов проксирования поверх HTTP/3:

* **RFC 9298** (`CONNECT-UDP`) — проксирование UDP-датаграмм;
* **RFC 9484** (`CONNECT-IP`) — проксирование **IP-пакетов целиком**; именно
  его использует usque, поэтому туннель может нести любой IP-трафик.

**usque** — неофициальный клиент Cloudflare WARP, говорящий с WARP по MASQUE
вместо WireGuard. Всё идёт внутри обычного **HTTPS/QUIC на 443/udp** (или
HTTP/2 поверх **TCP:443** — см. §4), поэтому трафик неотличим от обычного
веба на уровне протокола.

**Чем НЕ является:**

* **Это не WireGuard и не AmneziaWG.** Разные протоколы и разные ключи:
  у WireGuard/AWG — X25519, у usque — **ECDSA на кривой P-256**. Апстрим
  прямо пишет «no support for WireGuard». Практический вывод, который надо
  повторять пользователям: **сессию usque НЕЛЬЗЯ собрать из `.conf`
  AmneziaWG/WireGuard**, и наоборот. Единственные пути получить сессию —
  `usque register` или импорт готового `config.json` самого usque
  (`UsqueManager.import_config`).
* **Это не `MASQUERADE`.** В нашем коде есть `core/routing/masquerade.py` —
  это NAT-правило (SNAT) для selective-routing, к протоколу MASQUE отношения
  **не имеет**. Совпадение имён; не путать при grep.
* **Это не замена WireGuard по производительности.** usque — userspace на
  `quic-go`, congestion control только Reno (BBR нет). Апстрим измерял
  ~833 Mbit/s на десктопе; на MIPS-роутере ожидания должны быть куда скромнее.

**Зачем нужен:** WireGuard-транспорт WARP местами режется по протоколу/портам,
а MASQUE выглядит как HTTPS. Плюс работает там, где UDP/51820 закрыт.

---

## 2. Установка: пакет usque-keenetic

usque-keenetic распространяется **как Entware `.ipk`**, а не сырым бинарником.
Это важно: `install_kind: "package"` в `BINARIES["usque"]` — если поставить
файл копированием, в `/opt/usr/bin/usque` ляжет неисполняемый `ar`-архив.

| Что | Значение |
|---|---|
| Репозиторий | `side-effect-tm/usque-keenetic` |
| Закреплённый тег | `v0.3.0` (несёт usque v4.2.0) |
| Имя пакета | `usque-keenetic` |
| Путь бинарника | `/opt/usr/bin/usque` |
| Архитектуры | `aarch64-3.10`, `mipsel-3.4`, `mips-3.4`, `all_entware` (armv7) |
| Проверка | sha256 из `sha256_map`, fail-closed |

Требования апстрим-пакета: Keenetic OS ≥ 5.0, Entware (лучше на USB),
модуль TUN (`kmod-tun`, устройство `/dev/net/tun`).

> **Две разные системы версий.** Тег пакета (`v0.3.0`) и версия самого usque
> (`4.2.0`) — **разные пространства**. Сравнивать их между собой нельзя:
> «установлено 4.2.0, в релизе 0.3.0» всегда даст ложное «есть обновление».
> Для «есть ли апдейт» сравнивать надо `usque.installed_tag` (тег пакета,
> который мы поставили) с `BINARIES["usque"]["release_tag"]`.

Пакет апстрима также кладёт свой `/opt/etc/init.d/S51usque` и
`/opt/etc/usque/usque.conf`. **Мы ими не пользуемся**: GUI запускает `usque`
сам (см. §7) и хранит конфиги в `platform_dirs.config_dir()/usque`. Если
пользователь включил и штатный `S51usque`, и наш автозапуск — получится два
процесса и два TUN; это первое, что надо проверять при «интерфейсов больше,
чем я создавал».

Поиск бинарника (`UsqueManager._find_binary`, по порядку):
`/opt/usr/bin/usque` → `/opt/bin/usque` → `/usr/local/bin/usque` → `/usr/bin/usque`.

---

## 3. CLI usque — полная карта (сверено с v4.2.0)

### 3.1 Корневая команда

```
usque [command]

Available Commands:
  account       Manage account and license keys
  completion    Generate the autocompletion script for the specified shell
  enroll        Enrolls a MASQUE private key and switches mode
  help          Help about any command
  http-proxy    Expose Warp as an HTTP proxy with CONNECT support
  l4-http-proxy Expose Warp as an L4 TCP-only HTTP proxy with CONNECT support
  l4-socks      Expose Warp as an L4 TCP-only SOCKS5 proxy
  nativetun     Expose Warp as a native TUN device
  portfw        Forward ports through a MASQUE tunnel
  register      Register a new client and enroll a device key
  socks         Expose Warp as a SOCKS5 proxy
  version       Print the version number of usque

Flags:
  -c, --config string   config file (default is config.json) (default "config.json")
  -h, --help            help for usque
```

**Глобальный флаг ровно один — `-c/--config`.** `-s`, `--http2` и прочее
принадлежат подкомандам, а не корню.

> 🔴 **`usque --version` НЕ СУЩЕСТВУЕТ.** Cobra-команда не объявляет поле
> `Version`, поэтому вызов падает:
> ```
> $ usque --version
> Error: unknown flag: --version
> ... (usage) ...
> $ echo $?
> 1
> ```
> Версию печатает **подкоманда** `usque version`, в **stdout**, тремя
> строками:
> ```
> usque version: dev
> Commit: none
> Build Date: unknown
> ```
> Строка `dev` — это значение по умолчанию: если сборка сделана без
> `-ldflags "-X ...version=<x>"`, номера версии не будет вообще. Парсер
> обязан переживать и `4.2.0`, и `dev`.
>
> Ещё нюанс: `usque version` **всё равно пытается прочитать конфиг** и, не
> найдя его, пишет в **stderr** две строки
> («Config file not found…» / «You may only use the register command…»),
> но возвращает **rc=0**. Поэтому версию надо брать из **stdout**, а stderr
> при детекте игнорировать.

### 3.1.1 Регистрация через прокси: usque уважает `HTTPS_PROXY`

Практически важный факт, которого нет в README апстрима. Все запросы к
API Cloudflare идут через `http.DefaultClient` (`api/cloudflare.go`), а у
него `Proxy: http.ProxyFromEnvironment`. Значит **`usque register`
подчиняется переменным окружения** `HTTP_PROXY` / `HTTPS_PROXY` /
`NO_PROXY`, включая схему `socks5://`.

Проверено на живом бинарнике:

```
$ HTTPS_PROXY=http://127.0.0.1:1 usque register -a -c out.json
Failed to register: ... Post "https://api.cloudflareclient.com/v0a4471/reg":
  proxyconnect tcp: dial tcp 127.0.0.1:1: connect: connection refused

$ HTTPS_PROXY=socks5://127.0.0.1:11080 usque register -a -c out.json
Successful registration. Saving config...
   [прокси видит ровно один CONNECT api.cloudflareclient.com:443]
```

Это единственный вменяемый способ зарегистрироваться там, где провайдер
режет сам `api.cloudflareclient.com` (симптом —
`net/http: TLS handshake timeout`). На этом построена наша «Регистрация
через» (§8.1).

Отдельно: `--http2` тоже ходит через `ProxyFromEnvironment`
(`api/masque.go`), а **QUIC-режим — нет**. То есть прокси-переменные в
окружении процесса влияют на регистрацию и на H2-туннель, но не на H3.

### 3.2 `register` — создать сессию WARP

```
usque register [flags]
  -a, --accept-tos      accept Cloudflare TOS (not interactive setup)
      --jwt string      team token
  -l, --locale string   locale (default "en_US")
  -m, --model string    model (default "PC")
  -n, --name string     device name
```

Регистрирует новый аккаунт, энроллит ключ устройства, **переключает аккаунт в
режим MASQUE** и сохраняет config по пути `-c`. Без `-a` уходит в
интерактивный режим — в GUI это означало бы вечное ожидание, поэтому
`--accept-tos` обязателен.

* `-n` — имя устройства в аккаунте Cloudflare (иначе все туннели выглядят
  одинаково).
* `--jwt` — регистрация в **ZeroTrust** вместо обычного consumer-WARP.

⚠️ В `register` `-n` — это **имя устройства**, а в `nativetun` `-n` — **имя
интерфейса**. Один короткий флаг, два разных смысла.

### 3.3 `nativetun` — туннель как TUN-интерфейс

Основной режим для роутера. Требует root, `tun.ko` и (по умолчанию) iproute2.

```
usque nativetun [flags]
      --always-reconnect             Always reconnect after tunnel loss, even when idle
  -P, --connect-port int             Used port for MASQUE connection (default 443)
      --http2                        Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC
  -i, --initial-packet-size uint16   Custom initial packet size (default: auto with PMTU discovery)
      --insecure                     Disable endpoint certificate pinning and trust any certificate
  -n, --interface-name string        Custom interface name for the TUN interface
  -6, --ipv6                         Use IPv6 for MASQUE connection
  -k, --keepalive-period duration    Keepalive period for MASQUE connection (default 30s)
  -m, --mtu int                      MTU for MASQUE connection (default 1280)
  -I, --no-iproute2                  Linux only: Do not set up IP addresses and do not set the link up
  -F, --no-tunnel-ipv4               Disable IPv4 inside the MASQUE tunnel
  -S, --no-tunnel-ipv6               Disable IPv6 inside the MASQUE tunnel
      --on-connect string            Path to an executable to run after each successful tunnel connect
      --on-disconnect string         Path to an executable to run after each tunnel disconnect
      --persist                      Linux only: Keep the TUN interface after exit
  -r, --reconnect-delay duration     Delay between reconnect attempts (default 1s)
  -s, --sni-address string           SNI address for MASQUE connection (default "consumer-masque.cloudflareclient.com")
```

Чего **нет** и выдумывать нельзя: `--tcp-nodelay`, `--keepalive` (только
`--keepalive-period`), `--dns`/`--local-dns` (DNS есть только у прокси-режимов),
`--sni` (только `--sni-address` / `-s`).

`-6/--ipv6` относится к **транспорту наружу** (стучаться на `endpoint_v6`), а
`-F/-S` — к тому, какие семьи работают **внутри** туннеля. Это разные вещи.

### 3.4 Прокси-режимы

`socks`, `http-proxy` и их «лёгкие» TCP-only варианты `l4-socks`,
`l4-http-proxy` (без UDP/датаграмм и без userspace-стека — заметно дешевле по
CPU, что для MIPS-роутера существенно). Общие флаги:

* `-b <addr>` — bind (SOCKS5 по умолчанию `0.0.0.0`), `-p <port>` (SOCKS5 —
  `1080`);
* `-u/-w` — логин/пароль;
* `-d <dns>` — DNS-сервер, повторяемый (по умолчанию Quad9);
* `--on-connect` / `--on-disconnect`.

**Мы эти режимы не используем** — GUI работает только через `nativetun`.
Если понадобится «WARP как прокси без TUN» (роутер без `kmod-tun`), это
готовый путь, но кода под него сейчас нет.

### 3.5 Прочее

* `enroll` — переэнроллить существующий ключ / обновить данные серверов;
  полезно при миграции устройства или переключении с WireGuard на MASQUE.
* `account` — управление аккаунтом и лицензионными ключами (WARP+).
* `portfw` — проброс портов (`-L`, `-R`) для ZeroTrust WARP-to-WARP.

### 3.6 Хуки

Все туннельные режимы поддерживают `--on-connect` / `--on-disconnect`:
путь к исполняемому файлу, **без аргументов**, контекст передаётся через
переменные окружения `USQUE_EVENT`, `USQUE_MODE`, `USQUE_IFACE`,
`USQUE_IPV4`, `USQUE_IPV6`, `USQUE_ENDPOINT`.

Это правильное место, чтобы вешать маршруты/DNS «когда туннель реально
поднялся» — в отличие от факта запуска процесса, хук срабатывает по
**фактическому** соединению.

---

## 4. Транспорт: H3/QUIC против H2/TCP

| | `performance` (дефолт) | `restricted` (`--http2`) |
|---|---|---|
| Протокол | HTTP/3 поверх QUIC | HTTP/2 поверх TCP+TLS |
| Порт | 443/**udp** | 443/**tcp** |
| Endpoint из конфига | `endpoint_v4` / `endpoint_v6` | `endpoint_h2_v4` / `endpoint_h2_v6` |
| Когда нужен | нормальная сеть | UDP/443 зарезан или сильно деградирован |
| Цена | — | выше latency, TCP-over-TCP при вложенности |

Проверено на живом бинарнике: при `--http2` в лог уходит
`HTTP/2 mode enabled` и `Using HTTP/2 endpoint <ip>:443`.

⚠️ **`endpoint_h2_v6` у свежей бесплатной регистрации ПУСТОЙ.** Реальный
`config.json` от `usque register` (v4.2.0) содержит непустой `endpoint_h2_v4`
и **пустую строку** в `endpoint_h2_v6`. Значит связка `--http2 -6` на
consumer-аккаунте работать не будет; про это же предупреждает README
usque-keenetic («HTTP/2 требует настроенного IPv6-endpoint»).

⚠️ **HTTP/2-режим уважает `HTTP_PROXY`/`HTTPS_PROXY` из окружения** (это
обычный Go `http.Transport`), а QUIC-режим — нет. Если процесс GUI запущен
с прокси-переменными, H2-туннель молча пойдёт через прокси и упрётся в него.
На роутере это редкость, но при отладке в контейнере — постоянный источник
ложных выводов вида
`failed to dial connect-ip over HTTP/2: ... Connect "https://cloudflareaccess.com": connection reset by peer`.

**Профиль `auto` в нашем коде — не то, чем кажется.** Он делает ровно один
повтор с `--http2`, и только если **процесс упал или интерфейс не появился**
на старте. Но при заблокированном UDP процесс не падает и интерфейс
появляется (§5) — падает лишь ленивое соединение, уже после того как
`start()` вернул успех. Поэтому на «UDP зарезан» `auto` сам по себе не
переключится; вытягивает ситуацию только watchdog (§9), который после
неудачных проб перезапускает туннель и в режиме `auto` понижает транспорт до
`restricted`.

**SNI.** `-s` подменяет только SNI в TLS-хендшейке; сертификат при этом
по-прежнему пиннится по `endpoint_pub_key`. Наш дефолт —
`usque.default_sni = "ozon.ru"` (крупный российский домен), апстримовский —
`consumer-masque.cloudflareclient.com`. Пустая строка = «не подменять».

---

## 5. Жизненный цикл соединения (и почему лог врёт)

Порядок событий у `nativetun`, дословно из stderr живого бинарника:

```
Created TUN device: warp0
Tunnel established, you may now set up routing and DNS
Tunnel idle. Waiting for outbound activity before reconnecting...
```

…и только когда через интерфейс пойдёт первый пакет:

```
Detected outbound activity (60 bytes). Reconnecting...
Establishing MASQUE connection to 162.159.198.2:443
```

Дальше либо тишина (успех), либо:

```
Failed to connect tunnel: failed to dial connect-ip: timeout: no recent network activity
Tunnel idle. Waiting for outbound activity before reconnecting...
```

Выводы, критичные для кода и для поддержки:

1. **«Tunnel established» печатается ДО сети.** Это значит «TUN создан,
   можно настраивать маршруты», а не «WARP подключён». Считать его признаком
   успеха нельзя.
2. **Соединение ленивое.** Пока через интерфейс нет исходящего трафика,
   usque не подключается вообще (`--always-reconnect` меняет это поведение).
   Следствие: проверять «работает ли туннель» можно только **проведя через
   него трафик** — что и делает наш watchdog (`SO_BINDTODEVICE` + TCP-проба).
3. **Ретраи вечные,** с паузой `--reconnect-delay` (1s) плюс собственный
   таймаут дозвона (~5 с). Процесс при этом жив и rc не отдаёт — «процесс
   есть» ничего не доказывает.
4. **Сообщения об ошибках дозвона надо читать буквально:**
   * `failed to dial connect-ip: timeout: no recent network activity` —
     QUIC/UDP до endpoint не доходит → пробовать `--http2`;
   * `failed to dial connect-ip over HTTP/2: ... connection reset` —
     TCP/443 перехвачен или зарезан (часто — прокси из окружения);
   * `x509: cannot verify signature: algorithm unimplemented` /
     любые cert-ошибки — на пути TLS-MITM, пиннинг сработал как задумано;
   * `server responded with 403` — до Cloudflare достучались, но
     CONNECT-IP-запрос отвергнут (протухшая/чужая сессия, либо всё тот же
     MITM).

---

## 6. TUN-интерфейс: кто назначает адреса

Самая дорогая ловушка. Дословная справка флага:

```
-I, --no-iproute2   Linux only: Do not set up IP addresses and do not set the link up
```

То есть `--no-iproute2` отключает **и адреса, и подъём link'а**.
Экспериментально, `usque nativetun --no-iproute2 -n utest0`:

```
Skipping IP address and link setup. You should set the link up manually.
Config has the following IP addresses:
IPv4: 172.16.0.2
IPv6: 2606:4700:110:...
Created TUN device: utest0
```

и в системе:

```
/sys/class/net/utest0/operstate → down      ← НЕ "unknown", а именно down
адресов на интерфейсе нет
```

Для сравнения, **без** `--no-iproute2` usque настраивает всё сам (через
netlink, бинарник `ip` ему не нужен):

```
/sys/class/net/utest2/operstate → unknown
IPv4 на интерфейсе: 172.16.0.2
MTU: 1280
```

**Практические следствия:**

* Проверять готовность интерфейса по `operstate ∈ {up, unknown}` **валидно
  только для режима без `--no-iproute2`**. С `--no-iproute2` эта проверка
  не пройдёт никогда, и туннель будет убит как «не поднявшийся».
* Если мы передаём `--no-iproute2`, мы **обязаны** сами: назначить `ipv4`
  (и `ipv6`, если он есть) из `config.json`, выставить MTU и поднять link.
  Именно это делает `UsqueManager._configure_iface()` (§7).
* Обратная сторона: **на хосте без IPv6 обычный режим падает целиком** —
  `Failed to create TUN device: failed to add IPv6 address: operation not
  supported`. Спасают либо `-S/--no-tunnel-ipv6`, либо `--no-iproute2` с
  ручной настройкой. Мы выбрали второе: настраиваем сами и делаем IPv6
  best-effort, чтобы отсутствие v6 не роняло туннель.
* `--persist` мы **не** передаём: TUN должен исчезать вместе с процессом,
  иначе после падения остаётся мёртвый интерфейс, который занимает имя.

---

## 7. Наш менеджер: `core/usque_manager.py`

Синглтон `get_usque_manager()`. Реентрантный `RLock` (не `Lock`: `start()`
зовёт `_is_running()` уже под локом — с обычным `Lock` это гарантированный
самодедлок).

### Команда, которую мы строим

```
usque nativetun --config <path> --interface-name <iface> --no-iproute2
                [-s <sni>] [--http2] [--keepalive-period 10s]
```

* `--no-iproute2` — намеренно: адреса и link настраиваем сами (§6), иначе
  на хостах без IPv6 usque падает целиком.
* `--http2` — только для профиля `restricted`.
* `--keepalive-period 10s` — при `low_latency` (дефолт usque — 30s).

### Ключевые методы

| Метод | Что делает / на что смотреть |
|---|---|
| `detect()` | `{installed, binary, version, arch}`. Версия — через **`usque version`**, из stdout. |
| `register(path, device_name, team_token)` | `usque register --accept-tos -c <path> [-n] [--jwt]`, таймаут 30 с. |
| `import_config(name, text)` | Импорт готового `config.json`. Валидирует обязательные поля, режет path-traversal, `chmod 600`. |
| `list_configs()` | Файлы `.conf`/`.toml`/`.json` из конфиг-каталога + `iface`/`active`. |
| `allocate_iface(prefix)` | Свободное имя `opkgtun<N>` (≤15 символов), с оглядкой на `/sys/class/net` и pid-файлы. |
| `start(iface, path, …)` | См. ниже. |
| `stop(iface)` | SIGTERM всей группе (`start_new_session=True` → `killpg`), затем SIGKILL; чистит pid/`.run`. |
| `status(iface)` | `{running, iface_exists, pid, diagnostic}`. |
| `read_log(iface, lines)` | Хвост stderr из кольцевого буфера в ОЗУ. |

### Что делает `start()` по шагам

1. Валидация имени интерфейса (`^[a-zA-Z0-9_-]{1,15}$`) и профиля.
2. Под локом — проверка `_is_running()`.
3. `Popen` с `stderr=PIPE`, `start_new_session=True`; отдельный поток
   вычитывает stderr в `deque` (иначе pipe заполнится и usque встанет).
4. Ждём **появления** интерфейса в `/sys/class/net` (до 5 с, шаг 0.1 с),
   попутно проверяя, не умер ли процесс.
5. `_configure_iface()` — MTU, адреса из `config.json`, `ip link set up`.
6. Пишем pid-файл и `<config>.run` (`IFACE=`/`PID=`), применяем
   `tunnel_optimizer`.

Шаг 4 смотрит именно на **существование** интерфейса, а не на `operstate`:
с `--no-iproute2` состояние остаётся `down` до шага 5 (§6).

### Файлы состояния

* `<pid_dir>/usque-<iface>.pid` — PID (`_pid_dir = /opt/var/run`);
* `<config>.run` — `IFACE="…"` / `PID="…"`, по нему `list_configs()`
  восстанавливает привязку конфига к интерфейсу после рестарта GUI.

⚠️ `/opt/var/run` **переживает перезагрузку**, поэтому pid-файл после ребута
почти наверняка указывает на чужой процесс. Отсюда `_pid_is_usque(pid)`
(читает `/proc/<pid>/cmdline`): без неё `_is_running()` врал бы «уже
запущен», а `stop()` слал бы `killpg` посторонней группе от root.

### Формат `config.json`

Реальный конфиг от `usque register` v4.2.0 (значения сокращены):

```json
{
  "private_key":      "<base64 ECDSA P-256, ~164 симв.>",
  "endpoint_v4":      "162.159.198.2",
  "endpoint_v6":      "2606:4700:103::2",
  "endpoint_h2_v4":   "162.159.198.2",
  "endpoint_h2_v6":   "",
  "endpoint_pub_key": "<PEM, ~178 симв.>",
  "id":               "<uuid устройства>",
  "access_token":     "<uuid токена>",
  "ipv4":             "172.16.0.2",
  "ipv6":             "2606:4700:110:...."
}
```

* Обязательные для нашего импорта: `private_key`, `access_token`, `id`.
* `license` в бесплатной регистрации **отсутствует** — появляется только
  после привязки ключа WARP+ (`usque account`). Требовать его нельзя.
* `endpoint_h2_v4`/`endpoint_h2_v6` — полноправные поля; если их нет в
  списке известных, GUI будет ругаться «неизвестные поля» на совершенно
  нормальном конфиге.
* `ipv4`/`ipv6` — это адреса **внутри** туннеля, те самые, что мы вешаем на
  интерфейс при `--no-iproute2`.

Мы сохраняем конфиг с расширением `.conf` (`api/usque.py`, `register`),
хотя содержимое — JSON. Путь передаётся в usque явно через `-c`, так что
расширение роли не играет; `list_configs()` принимает `.conf`/`.toml`/`.json`.

---

## 8. API, настройки, CLI

### REST (`api/usque.py`)

| Метод | Endpoint |
|---|---|
| GET | `/api/usque/environment` (+ `POST .../refresh`) |
| GET | `/api/usque/version` |
| GET/POST | `/api/usque/settings` |
| GET/POST | `/api/usque/debug` |
| POST | `/api/usque/register` |
| POST | `/api/usque/configs/import` |
| GET | `/api/usque/configs` |
| POST | `/api/usque/configs/<name>/up` \| `/down` \| `/remove` |
| GET | `/api/usque/configs/<name>/status` \| `/log?lines=N` |
| GET | `/api/usque/watchdog/status` |
| GET | `/api/usque/releases` (`?transport=&force=`) |
| POST | `/api/usque/install` (`{tag?, transport?}`) \| `/install/local` (multipart `file`) \| `/uninstall`; GET `/install/status` |

`/environment` отдаёт `binary` **объектом**
`{installed, version, engine_version, path}` — этого ждёт `SetupUI`
(`usque_setup.js`); плоские `installed`/`version`/`arch` рядом читает
основная страница `usque.js`. Ломать любую из двух форм нельзя.

> ⚠️ **`binary.version` — это тег ПАКЕТА (`v0.3.0`), а не версия движка.**
> SetupUI сравнивает его с «В релизе» и по результату рисует «доступно
> обновление», а сравнение двух систем нумерации (§2) не совпадает
> никогда. Версия самого usque живёт рядом в `engine_version` и в плоском
> `version`.

### 8.1 «Регистрировать через» — когда режут Cloudflare

Симптом: `Failed to register: ... net/http: TLS handshake timeout`. До
`api.cloudflareclient.com` нет доступа, а сессию получить неоткуда —
собрать её из AWG-конфига нельзя (§1).

Решение: провести регистрацию через **уже работающий** обход. Спека
транспорта — общая с «Качать через» (`core/download_transport`):
`direct`, `awg:<iface>`, `singbox:<name>`, `mihomo:<name>`.

Механика (`UsqueManager._register_env`):

* **singbox/mihomo** дают локальный HTTP-прокси → его адрес просто
  уходит в `HTTPS_PROXY` дочернего процесса (§3.1.1);
* **awg** — это интерфейс, порта у него нет. На время регистрации
  поднимается эфемерный SOCKS5 на loopback, чьи исходящие соединения
  привязаны к интерфейсу через `SO_BINDTODEVICE`
  (`core/iface_socks.py`), и в `HTTPS_PROXY` уходит он;
* `direct` **вычищает** унаследованные прокси-переменные — «напрямую»
  должно означать напрямую;
* мост открыт только на `api.cloudflareclient.com` (белый список) и
  умирает вместе с операцией;
* привязка к интерфейсу **проверяется чтением** сокет-опции: молчаливый
  отказ `setsockopt` означал бы выход мимо туннеля, то есть ровно туда,
  откуда мы уходим. Не встала — ошибка, а не тихий `direct`.

Тот же приём применим к любому «интерфейсному» обходу, не только AWG.

Замечание про DNS: имя резолвит мост (системным резолвером, при неудаче —
DoH проекта), то есть **не** через туннель. Для случая «TLS режут, DNS
работает» этого достаточно; при отравленном DNS понадобится DoH.

### Секция конфига `usque`

```
enabled          false   — общий выключатель фонового управления
autostart        false   — поднимать туннели при старте GUI
default_sni      "ozon.ru"
transport_profile "performance" | "restricted" | "auto"
http2_enable     false   — принудительный H2 (перебивает transport_profile)
debug_log        false   — глубина буфера лога 40 → 500 строк
installed_tag/_arch/_at  — метаданные установленного ПАКЕТА
watchdog: { enabled, interval_sec (10..3600), probe_host, probe_port }
```

Автозапуск при буте (`app.py::_apply_usque_autostart_on_boot`) требует
**и** `enabled`, **и** `autostart`. Частая жалоба «включил автозапуск, ничего
не поднимается» — это выключенный `usque.enabled`.

### CLI

```
zapret-gui usque status
zapret-gui usque start <iface|name>
zapret-gui usque stop  <iface>
```

---

## 9. Watchdog (`core/usque_watchdog.py`)

По умолчанию **выключен**. Включается только при `usque.enabled` **и**
`usque.watchdog.enabled`.

Цикл: раз в `interval_sec` (дефолт 60) по каждому активному туннелю —
TCP-проба `probe_host:probe_port` (дефолт `1.1.1.1:443`) с
`SO_BINDTODEVICE` на интерфейс туннеля.

Тройственный результат пробы — важная деталь:

* `True` — прошла, счётчик сбрасывается;
* `False` — не прошла, счётчик растёт;
* `None` — **недостоверно** (нет прав на `SO_BINDTODEVICE`, привязка не
  подтвердилась) → тик пропускается. Без этого watchdog без root
  перезапускал бы исправные туннели по кругу.

Рестарт после 3 неудач подряд; cooldown 120 с на интерфейс; не более
6 рестартов в час.

**Понижение транспорта.** Если `transport_profile = "auto"`, то при рестарте
watchdog поднимает туннель уже в `restricted` (H2/TCP). Это и есть рабочий
путь автопереключения при зарезанном UDP — на старте оно сработать не может
(§4, §5). Каждая проба стоит трафика через туннель, что заодно «будит»
ленивое соединение.

---

## 10. WARP-in-WARP (`core/warp_in_warp.py`)

Режимы: `masque_masque`, `masque_awg`, `awg_masque` (чистый AWG+AWG живёт
отдельно в `core/awg_warp_in_warp.py`).

Что важно помнить:

* Статус внутренних туннелей спрашивается **только** через публичный
  `usque_mgr.status(iface)["running"]` — не через приватный `_processes`.
* Inner-туннель обязан ходить до своего endpoint **через outer**, иначе
  «двойной туннель» — фикция. Для AWG endpoint читается из `[Peer]/Endpoint`.
  Для MASQUE-стороны адрес из session-конфига мы не разбираем, поэтому
  `inner_endpoint_host` для режимов с inner=MASQUE **обязателен**, и без него
  запуск отклоняется (а не делает вид, что всё хорошо).
* `AwgManager.up(name)` принимает **имя зарегистрированного конфига**, а не
  путь и не текст.

---

## 11. Диагностика: симптом → причина

| Симптом | Что смотреть |
|---|---|
| «Установлен: Error: unknown flag…» | Версия читается через `usque --version` — такого флага нет (§3.1). Нужен `usque version`. |
| Всегда «доступно обновление» | Сравниваются версия usque (`4.2.0`) и тег пакета (`0.3.0`) — разные пространства (§2). |
| `usque не создал интерфейс X (rc=None)` | Ждали `operstate=up`, а с `--no-iproute2` он `down` (§6). Либо реально нет `/dev/net/tun`. |
| Интерфейс есть, трафика нет | Нет адресов/link down (§6) — либо нет `masquerade` на forwarded-трафик (`core/routing/masquerade.py`). |
| В логе «Tunnel established», но интернета нет | Это сообщение ничего не значит (§5). Смотреть дальше — `Establishing…` / `Failed to connect…`. |
| `failed to dial connect-ip: timeout: no recent network activity` | UDP/443 не проходит → `restricted` (H2/TCP). |
| `... over HTTP/2: ... connection reset` | TCP/443 перехвачен/зарезан; проверить `HTTP(S)_PROXY` в окружении процесса (§4). |
| `x509: ... algorithm unimplemented`, `server responded with 403` | TLS-MITM на пути либо протухшая сессия. Пиннинг отработал корректно. |
| `failed to add IPv6 address: operation not supported` | Хост без IPv6 и запуск **без** `--no-iproute2` (§6). |
| Туннель поднялся, но «отваливается через час» | Включить `usque.debug_log` (буфер 40 → 500 строк) и читать `/api/usque/configs/<name>/log`. |
| Появились лишние `opkgtun*` | Одновременно работают наш автозапуск и штатный `S51usque` из пакета (§2). |
| «Импортировал конфиг — пишет про неизвестные поля» | В списке известных нет `endpoint_h2_v4`/`endpoint_h2_v6` (§7). |
| Регистрация падает с `TLS handshake timeout` | Провайдер режет `api.cloudflareclient.com`. Регистрировать через уже работающий обход (§8.1). |
| «Список релизов недоступен: method not allowed» | Нет маршрута `GET /api/usque/releases` (§8). |
| Просят «сделать usque из моего AWG-конфига» | Невозможно в принципе: разные протоколы и ключи (§1). AWG может лишь ДОСТАВИТЬ регистрацию до Cloudflare (§8.1) — но сессию всё равно выдаёт Cloudflare. |

Полезные команды на роутере:

```sh
usque version                       # версия (stdout!), stderr про конфиг игнорировать
usque nativetun --help              # реальный список флагов ЭТОЙ сборки
cat /sys/class/net/opkgtun0/operstate
logread | grep -i usque
```

---

## 12. Что проверено экспериментально, а что нет

Проверено на живом бинарнике usque **v4.2.0** (собран из тега, linux/amd64,
root, `/dev/net/tun` есть):

* отсутствие `--version` и формат вывода `usque version`;
* полный список флагов `nativetun` и `register`;
* `usque register --accept-tos` против настоящего API Cloudflare —
  регистрация проходит, конфиг сохраняется;
* точный набор полей реального `config.json` (включая пустой
  `endpoint_h2_v6`);
* поведение `--no-iproute2` (`operstate=down`, адресов нет) против режима по
  умолчанию (`operstate=unknown`, адрес назначен, MTU 1280);
* падение обычного режима на хосте без IPv6;
* ленивое подключение и текст ошибок дозвона для H3 и H2.

**НЕ проверено:** передача полезного трафика через установленное
MASQUE-соединение — тестовое окружение режет UDP/443 и MITM-ит TCP/443, так
что данные до WARP не доходят (`403` при `--insecure`). Всё, что в этом
документе сказано про поведение **после** успешного дозвона, опирается на
апстрим-документацию, а не на собственный замер.
