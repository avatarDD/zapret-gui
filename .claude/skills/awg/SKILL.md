---
name: awg
description: >-
  Полный справочник по AmneziaWG (AWG) в проекте zapret-gui (роутеры Keenetic на
  Entware / OpenWrt / Linux). Использовать при любых задачах о: конфигах AWG
  (.conf — [Interface]/[Peer], wg-quick-расширения), параметрах обфускации
  (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5, J1-J3, Itime) и версиях протокола
  1.0/1.5/2.0, разборе/генерации конфигов (awg_config), жизненном цикле туннеля
  (amneziawg-go + awg setconf + ip link/addr/route, awg_manager), установке/детекте
  бинарей (amneziawg-go, awg/awg-quick), платформенных путях, Cloudflare WARP и
  WARP-in-WARP (warp_generator/warp_importer/awg_warp_in_warp), интеграции с
  нативным WireGuard Keenetic через NDMS (ndms/wg_discovery), watchdog/autostart,
  подписках, и диагностике «handshake есть, трафика нет / 92 B in, 20 KB out /
  туннель не поднимается». Источник истины — amnezia-vpn/amneziawg-go +
  amneziawg-tools + docs.amnezia.org, привязка — наш код core/awg_*.py,
  core/warp_*.py, core/ndms/wg_discovery.py, api/awg.py, web/js/pages/awg_*.js.
---

# AmneziaWG (AWG) — справочник для zapret-gui

Единый источник истины о том, **как AmneziaWG реально работает** и как с ним
обращаться в `zapret-gui`. Читать перед тем, как трогать разбор/генерацию
`.conf`, менеджер туннелей, параметры обфускации, WARP, интеграцию с Keenetic
или объяснять пользователю «почему handshake есть, а трафика нет».

Источники истины (в порядке убывания авторитета):
1. **amnezia-vpn/amneziawg-go** — userspace-реализация протокола на Go
   (`README.md` = спецификация параметров обфускации); **amnezia-vpn/amneziawg-tools**
   — форк `wireguard-tools` (`awg`/`awg-quick`); **docs.amnezia.org** —
   описание протокола и версий (1.0 / 1.5 / 2.0).
2. **`awg show <iface>` / `awg showconf <iface>`** — что демон реально принял.
   Если в `showconf` нет ваших `I1`/`S3`/`H*` — значит до `awg setconf` они не
   дошли (см. §3, §12). Это первичная диагностика.
3. **Наш код** — `core/awg_config.py` (парсер/генератор `.conf`, ключи),
   `core/awg_manager.py` (up/down/status/diagnostics), `core/awg_platform.py`
   (пути), `core/awg_installer.py` + `core/awg_detector.py` (бинари/арх),
   `core/warp_generator.py` + `core/warp_importer.py` + `core/awg_warp_in_warp.py`
   (WARP), `core/ndms/wg_discovery.py` (нативный WG Keenetic),
   `core/awg_watchdog.py`, `core/awg_autostart_manager.py` +
   `core/awg_init_script.py`, `api/awg.py`, `web/js/pages/awg_*.js`.

> ⚠️ **Версия протокола — главный источник «handshake есть, трафика нет».**
> AmneziaWG несовместим между мажорными версиями обфускации (§2.3). Если
> клиент шлёт data-пакеты в формате одной версии, а пир ждёт другую — handshake
> проходит (он на общих параметрах), а transport-пакеты дропаются. Классическая
> картина в `awg show`: **`transfer: 92 B received, 20 KB sent`** — мы
> отправляем, сервер молчит. См. §12.

---

## 1. Как AWG используется в zapret-gui

Модель: **один туннель = один сетевой интерфейс** (как у WireGuard; в отличие
от sing-box, где инстанс = файл). Имя инстанса = имя `.conf` без расширения и =
имя интерфейса (конфиг `awg0.conf` → интерфейс `awg0`).

**Мы НЕ используем `awg-quick`.** Логику wg-quick (Address/MTU/Table/DNS/
PreUp…PostDown, маршруты из `AllowedIPs`) мы реализуем сами в
`awg_manager._do_up`, а ядро поднимаем напрямую:

```
amneziawg-go <iface>                 # форкает userspace-демон + TUN-устройство
awg setconf <iface> <filtered.conf>  # заливает крипто + обфускацию в демон
ip link set dev <iface> mtu <MTU>
ip addr add <Address> dev <iface>
ip link set dev <iface> up
ip route add <AllowedIPs> dev <iface> table <id>   # если Table != off
```

Почему так, а не `awg-quick up`: на Keenetic/Entware нет полноценного bash и
ряда утилит, которые тянет `awg-quick`; нам нужен контроль над таблицами
маршрутизации (Selective routing GUI) и устойчивый teardown. Поэтому
`amneziawg-go` (userspace) + `awg setconf` + ручной `ip` — наш базовый путь.

**Поток:**
- **Конфиги** лежат в `platform.config_dir` (Keenetic: `/opt/etc/amneziawg/`).
  CRUD — через `api/awg.py` поверх `core/awg_config.py`.
- **`awg setconf`** получает НЕ весь `.conf`, а отфильтрованный (только
  `WG_INTERFACE_FIELDS` + `WG_PEER_FIELDS`, §3) — wg-quick-поля демон не
  понимает.
- **Маршрутизация GUI** поверх: `target_iface = <iface>`, правила навешивает
  `core/routing/applier` при подъёме интерфейса.

---

## 2. Параметры обфускации AmneziaWG (официальная истина)

AmneziaWG — форк WireGuard-Go, который убирает узнаваемые DPI-сигнатуры
WireGuard, **сохраняя его крипто и производительность**. Все «магия» —
дополнительные поля в секции **`[Interface]`** (одинаковые у клиента и сервера,
кроме случаев, где иначе сказано). **Если все параметры = 0 → ведёт себя как
обычный WireGuard** (для плавной миграции).

### 2.1 Таблица параметров (источник: amneziawg-go README + docs.amnezia.org)

| Параметр | Что делает | Диапазон/рекомендация | Версия |
|----------|-----------|------------------------|--------|
| **Jc** | **Кол-во** junk-пакетов перед handshake (после I1–I5) | рекоменд. 4–12 (docs: 0–10) | 1.0 |
| **Jmin** | Мин. **размер** junk-пакета | байты; `Jmin ≤ Jmax` | 1.0 |
| **Jmax** | Макс. **размер** junk-пакета | байты; **`Jmax < MTU`** (иначе фрагментация); docs: 64–1024 | 1.0 |
| **S1** | Префикс-padding handshake **init** | 0–64 байт | 1.0 |
| **S2** | Префикс-padding handshake **response** | 0–64 байт | 1.0 |
| **S3** | Префикс-padding handshake **cookie** | 0–64 байт | **2.0** |
| **S4** | Префикс-padding **transport** (data) | 0–32 байта | **2.0** |
| **H1** | Магический заголовок (тип) пакета **init** | 0…4294967295 | 1.0 |
| **H2** | Магический заголовок пакета **response** | 0…4294967295 | 1.0 |
| **H3** | Магический заголовок пакета **cookie** | 0…4294967295 | 1.0 |
| **H4** | Магический заголовок **transport** (data) | 0…4294967295 | 1.0 |
| **I1…I5** | Signature-пакеты перед handshake (мимикрия под реальный протокол), hex-blob в формате Custom Protocol Signature | произвольный hex | **1.5** |
| **J1…J3** | Доп. junk-параметры | — | 1.5, **удалены в 2.0** |
| **Itime** | Тайминг signature-пакетов | — | 1.5, **удалён в 2.0** |

> **Junk vs padding vs header — не путать.** `Jc/Jmin/Jmax` — отдельные
> мусорные пакеты ДО рукопожатия. `S1–S4` — случайный префикс ВНУТРИ реальных
> пакетов каждого типа. `H1–H4` — подменяют первый байт (тип сообщения), чтобы
> DPI не видел сигнатуру WireGuard.

### 2.2 H1–H4: ограничения

- Стандартный WireGuard использует типы сообщений **1, 2, 3, 4** (init/
  response/cookie/transport). `H1–H4` их заменяют → значения должны **отличаться
  от 1–4 и друг от друга**. Поэтому наш `warp_generator` берёт `H*` из диапазона
  **`5 … 0x7FFFFFFF`** (`core/warp_generator.py`).
- В **AmneziaWG 2.0** у `H1–H4` появилась **поддержка диапазонов** (range): значения
  выбираются случайно в заданном окне и **не должны перекрываться**. В `.conf`
  это строка вида `H1 = 123-456`. `parse_conf` хранит `H*` как строки, но
  ⚠️ `validate()` пока проверяет `H1–H4` как **строгий int** (они в
  `AWG_OBFUSCATION_FIELDS`) → диапазонный синтаксис 2.0 он зарубит ложной
  ошибкой «H1 должен быть числом». Известное ограничение валидатора (сам
  `awg setconf` диапазон принимает).

### 2.3 Версии протокола и совместимость (КРИТИЧНО)

| Версия | Что добавляет | Параметры |
|--------|---------------|-----------|
| **1.0** | базовая обфускация: junk + magic-headers + padding init/response | Jc, Jmin, Jmax, S1, S2, H1–H4 |
| **1.5** | мимикрия под обычные UDP-протоколы (QUIC, DNS…) через signature-пакеты | + I1–I5, J1–J3, Itime |
| **2.0** | «полная мимикрия»: меняющиеся заголовки и размеры пакетов и в data-фазе | + S3, S4; range для H1–H4; **− J1–J3, Itime** |

> **Версия должна совпадать на обоих концах.** Подключиться по 2.0 к
> старому пиру нельзя; в старом AmneziaVPN профиль 2.0 даже не покажется, хотя
> сервер его поддерживает (docs.amnezia.org). **Это и есть инженерная причина
> "92 B in / 20 KB out"**: handshake собирается на общих параметрах и проходит,
> а data-пакеты пир дропает, потому что ждёт другой набор обфускации (например,
> на сервере включены S3/S4/I1, а в нашем конфиге их нет — или наоборот, мы их
> потеряли при парсинге, см. §3).

---

## 3. Формат `.conf` и наш парсер (`core/awg_config.py`)

API модуля: `parse_conf(text) -> {"interface": {...}, "peers": [{...}]}`,
`render_conf(cfg) -> text`, `validate(cfg) -> [errors]`, `generate_keypair()`.

### 3.1 Какие поля куда идут

| Группа | Константа | Куда применяется |
|--------|-----------|------------------|
| Крипто + ListenPort + FwMark + **вся обфускация** | `WG_INTERFACE_FIELDS` | в демон через **`awg setconf`** |
| `Address, DNS, MTU, Table, PreUp, PostUp, PreDown, PostDown, SaveConfig` | `WGQUICK_INTERFACE_FIELDS` | **наша wg-quick-логика** в `_do_up` (демон их НЕ видит) |
| `PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive` | `WG_PEER_FIELDS` | в демон через `awg setconf` |

`WG_INTERFACE_FIELDS` содержит: `PrivateKey, ListenPort, FwMark`, обфускацию v1
(`Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4`) и расширенную (`S3, S4, I1–I5,
J1–J3, Itime`). Числовые валидируются как int (`AWG_OBFUSCATION_FIELDS`); hex-blob
`I1–I5, J1–J3` — отдельно (`AWG_V2_BLOB_FIELDS`).

> **Голого поля `I` в AmneziaWG нет** — signature-пакеты это `I1…I5`
> (подтверждено парсером amneziawg-tools `src/config.c`: `key_match` только
> `I1`..`I5`). Раньше `I` ошибочно числился в наших списках как «v1»-параметр;
> **убрано** (см. CHANGELOG), чтобы случайный `I=` не ушёл в `awg setconf` —
> иначе тулза отбросила бы весь конфиг. Расширенный набор у нас исторически
> назван «v2», хотя по docs.amnezia.org `J1–J3`/`Itime` относятся к 1.5 и
> **удалены в 2.0** — мы их просто пропускаем как есть, решение принимает движок.

### 3.2 Парсинг hex-blob `I1–I5` (многострочный `<b …>`) — частый баг

`I1…I5` в `.conf` приходят как бинарный blob в одной из форм:

```ini
# однострочная
I1 = <b 0xf6ab...>

# многострочная (закрывается '>' или новым 'Key=' или пустой строкой)
I1 = <b
0xf6ab34c1...
9d2e...
>
```

`parse_conf` накапливает hex-куски (`pending_*`/`flush_pending`) и склеивает их.
**Без этой обработки парсер брал только `<b`, и `I1` терялся при
`render_setconf`** → handshake проходил, а сервер дропал data → ровно «92 B in /
20 KB out». Если меняешь парсер — не сломай blob-склейку; тесты —
`tests/test_awg_config.py`.

### 3.3 Прочее

- Голым адресам без маски `parse_conf` добавляет `/32`/`/128`, чтобы `awg`/`ip`
  их приняли.
- `_is_base64_key` проверяет ключи: 44 символа, заканчивается `=`, декодится в
  32 байта. `validate()` ругается на кривые ключи/`Endpoint`/`AllowedIPs`.
- `render_conf` пишет полный `.conf` (для хранения/показа), а в `awg setconf`
  уходит **отфильтрованный** временный файл (только setconf-поля).

---

## 4. Инструменты AmneziaWG (CLI)

Форк wireguard-tools, CLI идентичен — просто `awg` вместо `wg`:

| Команда | Назначение | Используем мы? |
|---------|-----------|----------------|
| `awg show [<iface>] [dump]` | статус: handshake, transfer, endpoint, allowed-ips | **да** (status/diagnostics; `dump` — таб-разделённый машинный вид) |
| `awg showconf <iface>` | дамп активного конфига демона | да (диагностика — что реально принято) |
| `awg setconf <iface> <file>` | залить конфиг в демон (replace) | **да** (основной путь конфигурации) |
| `awg syncconf <iface> <file>` | применить дельту без сброса peers | нет (мы делаем setconf при up) |
| `awg genkey` / `pubkey` / `genpsk` | генерация ключей | через наш `generate_keypair` (Python) |
| `awg set <iface> …` | точечная правка | нет |
| `awg-quick up/down <conf>` | bash-обёртка (Address/MTU/Table/routes/DNS) | **НЕТ** — реализуем сами (§1) |
| `amneziawg-go <iface>` | запустить userspace-демон + TUN | **да** (это и есть «движок») |

Альтернативы userspace-демону: модуль ядра `amneziawg` (DKMS /
`amneziawg-linux-kernel-module`). Мы ставим/детектим **userspace `amneziawg-go`**
(§7) — он не требует сборки под ядро роутера.

---

## 5. Жизненный цикл туннеля (`awg_manager`)

### 5.1 Подъём — `_do_up`
1. `validate()` конфига; если ошибки — не стартуем.
2. `PreUp`-хуки.
3. `amneziawg-go <iface>` (subprocess) — форкает демон + TUN. PID находим через
   `pgrep`, пишем в `<run_dir>/awg-<iface>.pid`.
4. короткая пауза (UAPI-сокет `/var/run/wireguard/<iface>.sock` должен подняться).
5. `awg setconf <iface> <filtered.conf>` — крипто + обфускация.
6. `ip link set dev <iface> mtu <MTU>` (если задан).
7. `ip addr add <Address>` (каждый адрес).
8. `ip link set dev <iface> up`.
9. маршруты из `AllowedIPs` → `table <id>` (если `Table != off`). `id` —
   стабильный хэш имени интерфейса в диапазоне **100…999**.
10. снимок состояния `<run_dir>/awg-<iface>.last_up.json` + список добавленных
    маршрутов `<run_dir>/awg-<iface>.routes.json` (чтобы корректно снять при down).
11. `PostUp`-хуки → `core.routing.applier.apply_all_on_interface_up()`.

### 5.2 Снятие — `_do_down`
Обратный порядок: `PreDown` → снять правила роутинга → удалить добавленные
маршруты → `ip link down` → `ip link delete dev <iface>` → SIGTERM (затем
SIGKILL) демону по PID → удалить pid-файл и UAPI-сокет → `PostDown` →
откат auto-dnsmasq (если это был последний AWG-интерфейс).

`restart` = down → up. `status(name)` парсит `awg show <iface> dump`
(per-peer: `latest_handshake` unix-ts, `rx_bytes`, `tx_bytes`).

---

## 6. Платформенные пути (`awg_platform`)

| | Keenetic/Entware | OpenWrt | Generic Linux |
|--|------------------|---------|---------------|
| bin | `/opt/usr/sbin` | `/usr/sbin` | `/usr/local/bin` |
| config | `/opt/etc/amneziawg` | `/etc/amneziawg` | `/etc/amneziawg` |
| run | `/opt/var/run/awg` | `/var/run/awg` | `/var/run/awg` |
| init | `/opt/etc/init.d` | `/etc/init.d` | `/etc/systemd/system` |

Файлы в `run_dir`: `awg-<iface>.pid`, `awg-<iface>.routes.json`,
`awg-<iface>.last_up.json`. UAPI-сокет демона — `/var/run/wireguard/<iface>.sock`
(путь от wireguard-go, не от нашего run_dir).

`awg_detector.CONFIG_DIR_CANDIDATES` ищет чужие конфиги и в
`/opt/etc/amnezia/{amneziawg,awg}`, `/opt/etc/AmneziaWG`, `*/wireguard` и т.д. —
импорт из существующих установок Amnezia.

---

## 7. Установка и детект (`awg_installer` / `awg_detector`)

- **Что ставим:** `amneziawg-go` (userspace-демон) и утилиту `awg` (при отсутствии
  — fallback на `wg`). Источник — GitHub-релизы (манифест через `api/awg/manifest`).
- **Архитектура** (`detect_architecture()`): сначала `opkg print-architecture`
  (берём приоритетный не-`all`/не-`noarch`), fallback — `uname -m` + `/proc`.
  Артефактные архи: `mipsel-softfloat`, `mips-softfloat`, `aarch64`, `armv7`,
  `x86_64`. **Endianness MIPS** определяется по `sys.byteorder` (т.к. `uname -m`
  на mips неоднозначен).
- **Версия бинаря** — `<bin> --version`/`-v`, regex `v?(\d+(\.\d+){1,3}…)`; fallback
  `opkg status <pkg>` для Entware.
- **Битый бинарь** (`_probe_binary`): ловим `exec format error`, `cannot execute
  binary`, `syntax error` — типичная ситуация при неверной арх/endianness.

---

## 8. Cloudflare WARP и WARP-in-WARP

### 8.1 Генерация WARP (`warp_generator.py`)
- Регистрация: `POST https://api.cloudflareclient.com/v0a2483/reg` (генерим пару
  ключей, регистрируем публичный, получаем peer/endpoint).
- Дефолты: endpoint `engage.cloudflareclient.com:2408`, peer-pubkey
  `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`.
- **Диапазоны обфускации для WARP:** `Jc 4..12`, `Jmin=40`, `Jmax=70`,
  `S1,S2 15..100`, `H1–H4 5..0x7FFFFFFF`. **Запрещённые размеры пакетов** (это
  фиксированные размеры самого WireGuard, маскировку сломают): `32, 64, 92, 148`.

### 8.2 Импорт WARP (`warp_importer.py`)
Распознаёт готовый `.conf` как WARP по: endpoint в диапазонах Cloudflare
(`162.159.192.0/24`, `162.159.193.0/24`, …), `AllowedIPs` = `0.0.0.0/0`/`::/0`,
наличию AWG-обфускации.

### 8.3 WARP-in-WARP (двойной туннель, `awg_warp_in_warp.py`)
Состояние в `config["awg"]["warp_in_warp"]`. Подъём:
1. **Резолв endpoint внутреннего** туннеля ДО подъёма (пока маршрут «наружу» ещё
   прямой).
2. поднять **внешний** туннель (если не запущен).
3. добавить `/32` (или `/128`) маршрут к IP внутреннего endpoint **через внешний**
   интерфейс (чтобы внутренний handshake пошёл сквозь внешний).
4. поднять **внутренний** туннель.
5. сохранить флаги «кого подняли мы» (чтобы при teardown не уронить чужое).

Статус = оба туннеля живы + маршрут к inner-endpoint существует + handshake свежий.

---

## 9. Нативный WireGuard Keenetic (NDMS) — `core/ndms/wg_discovery.py`

На Keenetic есть **свой** WireGuard (`Wireguard0`, `Wireguard1`, …), которым
рулит прошивка через NDMS/RCI, а не наш `amneziawg-go`.

- `wg_discovery` перечисляет такие интерфейсы через RCI (имя, описание, state,
  address, `type: wireguard`, `source: ndms`), кэш **30 c**.
- `awg_manager.list_interfaces()` показывает их рядом с нашими userspace-AWG.
- Для NDMS-нативных интерфейсов `status()` **делегирует** чтение в NDMS
  (`should_delegate_monitoring()`), а не дёргает `awg show` — иначе получим
  пусто (демон-то не наш).

> Не пытайся поднимать/опускать `WireguardN` через `ip`/`awg` — это сломает
> состояние прошивки. Управление ими — через NDMS-команды (`core/ndms/`).

---

## 10. Watchdog и автозапуск

**Watchdog** (`awg_watchdog.py`) — перезапуск при «протухшем» handshake:
`handshake_timeout_sec=180`, `check_interval_sec=30`, `cooldown_sec=300`,
`max_restarts_per_hour=6`, опциональный TCP-`probe` (host:port сквозь туннель).
`decide_restart()`: рестарт, если возраст handshake ≥ timeout **или** probe
падает N раз; учитывает per-iface cooldown и rate-limit.

**Autostart** (`awg_autostart_manager` + `awg_init_script`): флаг на конфиг в
`config["awg"]["autostart"]`. Init-скрипт:
- **Entware:** `/opt/etc/init.d/S51amneziawg-gui` (`start|stop|restart`);
- **OpenWrt:** procd (`start_service`/`stop_service`);
- **systemd:** `awg-gui.service`.

Все вызывают `python3 app.py --apply-awg-autostart` / `--stop-awg-autostart`
(поднимает включённые конфиги + восстанавливает WARP-in-WARP).

---

## 11. API (`api/awg.py`)

| Метод | Путь | Назначение |
|-------|------|-----------|
| GET | `/api/awg/environment` | отчёт детектора (платформа, арх, TUN, бинари) |
| POST | `/api/awg/environment/refresh` | пере-сканировать |
| GET | `/api/awg/manifest` | манифест GitHub-релизов |
| POST | `/api/awg/install`, `/api/awg/uninstall` | бинари |
| GET | `/api/awg/configs` | список конфигов |
| GET/PUT/DELETE | `/api/awg/configs/<name>` | CRUD конфига |
| POST | `/api/awg/configs/<name>/up`\|`down`\|`restart` | жизненный цикл |
| GET | `/api/awg/configs/<name>/status` | статус интерфейса |
| POST | `/api/awg/warp/import`, `/api/awg/warp/generate` | WARP |
| GET/POST | `/api/awg/warp-in-warp` | двойной туннель |
| GET/POST | `/api/awg/watchdog` | настройки watchdog |
| GET/POST | `/api/awg/autostart` | автозапуск |
| POST | `/api/awg/subscription/import`\|`preview` | импорт подписки |

---

## 12. Диагностика «не работает» (чек-лист)

1. **`awg show <iface>`** — есть ли peer и свежий `latest handshake`?
   - **нет handshake вообще** → не туда `Endpoint`/`PublicKey`, фаервол/маршрут
     до endpoint (на Keenetic — проверь, что трафик к endpoint не заворачивается
     в сам туннель; для WARP-in-WARP нужен `/32`-маршрут, §8.3), не тот
     `ListenPort`, либо **H1–H4/обфускация не совпадает с пиром** (DPI/сервер
     дропают и сам handshake).
   - **handshake есть, но `transfer: ~92 B received, ~20 KB sent`** → классика
     **рассинхрона версии/параметров обфускации** (§2.3). Мы шлём data, сервер
     молчит. Проверь:
     a) совпадают ли `S1–S4`, `H1–H4`, `I1–I5`, `Jc/Jmin/Jmax` с серверным
        конфигом (версия 1.0/1.5/2.0 одинаковая!);
     b) **не потерялся ли `I1` при парсинге** (§3.2) — сравни `awg showconf
        <iface>` с исходным `.conf`; в `awg_manager` есть `_compute_i1_lengths()`,
        который сверяет длину blob из конфига с тем, что эхо-ит `awg show`
        (несовпадение = blob недопарсился или демон старый, не понимает 2.0).
2. **`awg showconf <iface>`** — реально ли в демоне ваши `S3/S4/I1/H*`? Если их
   там нет — они не дошли через `setconf` (фильтрация `WG_INTERFACE_FIELDS` или
   баг парсера) или **бинарь старый** и игнорирует новые поля.
3. **версия бинаря** `amneziawg-go --version` / `awg --version` — поддерживает ли
   он 2.0-поля (`S3/S4`, range-`H*`)? Старый демон молча работает в 1.x.
4. **MTU/фрагментация** — `Jmax`/`S*` не должны раздувать пакет за MTU; дефолт
   `MTU=1420`. Симптом: handshake ок, мелкое работает, крупное/TLS виснет.
5. **битый бинарь** (неверная арх/endianness MIPS) — `_probe_binary`,
   «exec format error». Переустановить под верную арх (§7).
6. **`awg_manager.diagnostics()`** даёт полный снимок: бинари, конфиг (privkey
   замаскирован), `awg show`, `ip rule`/`ip route`, маршрут до каждого endpoint,
   состояние фаервола/dnsmasq.
7. **Keenetic native WG** не управляется нами — статус берётся из NDMS (§9), не
   из `awg show`.

---

## 13. Layout (где что)

- Парсер/генератор `.conf`, ключи: `core/awg_config.py`.
- Жизненный цикл, статус, диагностика: `core/awg_manager.py`.
- Пути/раскладка: `core/awg_platform.py`.
- Установка/детект бинарей и арх: `core/awg_installer.py`, `core/awg_detector.py`.
- WARP: `core/warp_generator.py`, `core/warp_importer.py`,
  `core/awg_warp_in_warp.py`.
- Нативный WG Keenetic: `core/ndms/wg_discovery.py`.
- Watchdog/автозапуск: `core/awg_watchdog.py`, `core/awg_autostart_manager.py`,
  `core/awg_init_script.py`, `core/awg_keenetic_setup.py`.
- API: `api/awg.py`. UI: `web/js/pages/awg_{setup,dashboard,configs,routing,warp}.js`.
- Тесты: `tests/test_awg_*.py`, `tests/test_api_awg.py`.
