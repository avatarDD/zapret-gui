---
name: awg
description: >-
  Полный справочник по AmneziaWG (AWG) в проекте zapret-gui (роутеры Keenetic на
  Entware / OpenWrt / Linux). Использовать при любых задачах о: конфигах AWG
  (.conf — [Interface]/[Peer], wg-quick-расширения), параметрах обфускации
  (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5, J1-J3, Itime) и версиях протокола
  1.0/1.5/2.0/3.0/3.1 (AWG 3+: HeaderProtectionKey, ContentPaddingAddition,
  Rekey*/RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts;
  AWG 3.1: RandomTrailers, DisableCookies), разборе
  и генерации конфигов (awg_config), жизненном цикле туннеля
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
   (`README.md` = спецификация параметров обфускации; сверено с
   **v3.1.20260828**); **amnezia-vpn/amneziawg-tools** — форк
   `wireguard-tools` (`awg`/`awg-quick`), сверено с **v3.1.20260812**.
   README на ветке 3.1 не изменился: два новых параметра (§2.1.2) описаны
   только кодом — `device/uapi.go` и `src/config.c`.
   Окончательный список ключей, которые вообще
   можно писать в `.conf`, — это `key_match` в его `src/config.c`, а НЕ
   документация: docs.amnezia.org описывает параметры протокола, часть
   которых парсер не принимает (см. §2.1 про `J1..J3`/`Itime`).
   **docs.amnezia.org** — описание протокола и версий (1.0 / 1.5 / 2.0);
   поколение **AWG 3+** документировано только в README amneziawg-go (§2.1.1).
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
   Общая с sing-box/mihomo обвязка — `core/engine_common.py` +
   `api/engine_wrapper.py`: лимит памяти Go (`/api/awg/go-memory`), режим
   отладки (`/api/awg/debug` → `LOG_LEVEL=verbose` демона, лог в
   `<log_dir>/awg-<iface>.log`, `/api/awg/configs/<name>/log`), проверка
   связи через туннель (`POST /api/awg/configs/<name>/test`, та же проба,
   что у сторожа), блок `wrapper` в диагностике; MCP — `tunnel_log`,
   `tunnel_diagnostics`, `tunnel_settings`.

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
  `core/routing/applier` при подъёме интерфейса (из `AwgManager.up` и —
  для любого движка — из netlink-сторожа `core/routing/guardian`, который
  не повторяет применение, сделанное за последние 15 с). После перезаписи
  netfilter прошивкой Keenetic тот же сторож по хуку
  `101-zapret-gui-routing.sh` возвращает маркировку и masquerade. Метки
  доменных/DSCP-маршрутов — поле `0x0FFF0000` (`core/routing/marks.py`),
  чужие биты метки не затираются.

---

## 2. Параметры обфускации AmneziaWG (официальная истина)

AmneziaWG — форк WireGuard-Go, который убирает узнаваемые DPI-сигнатуры
WireGuard, **сохраняя его крипто и производительность**. Все «магия» —
дополнительные поля в секции **`[Interface]`** (в README апстрима эта секция
называется `[Device]`). Какие из них обязаны совпадать с пиром, а какие
задаются только на клиенте — см. таблицу «сторон» ниже: путать их дорого.
**Если все параметры = 0 → ведёт себя как обычный WireGuard** (для плавной
миграции), и «значение не задано» апстрим трактует именно как 0.

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
| **I1…I5** | Signature-пакеты перед handshake (мимикрия под реальный протокол); отправляются по порядку I1→I5, пропускаются, если значение не задано | последовательность тегов, §2.1.2 | **1.5** |
| **J1…J3** | Доп. junk-параметры | — | 1.5, **удалены в 2.0** |
| **Itime** | Тайминг signature-пакетов | — | 1.5, **удалён в 2.0** |

**Где параметр обязан совпадать с пиром.** README amneziawg-go вводит явное
деление: `server-side` — значение ОБЯЗАНО быть одинаковым на обоих концах,
`client-side` — можно задавать только у клиента.

| Параметр | Сторона | Практический вывод |
|---|---|---|
| `Jc/Jmin/Jmax` | **client-side** | «Junk-пакеты не несут данных, задавать на обеих сторонах не требуется; общая рекомендация — только на клиенте» (README). Поэтому junk и работает против ванильного WireGuard-пира (§8.1) |
| `I1…I5` | **client-side** | то же самое: signature-пакеты пир просто игнорирует |
| `S1–S4`, `H1–H4` | должны совпадать | это формат САМИХ пакетов, пир обязан уметь их разобрать |
| `HeaderProtectionKey` | **server-side** | ключ защиты заголовка (§2.1.1) |
| `ContentPaddingAddition`, тайминги, `PersistentKeepalive` | **client-side** | «важно задать паддинг с обеих сторон, но строго не обязательно» |

Тип **`range,x`** (AWG 3): значение может быть `"a-b"`, `"a"` или `"(off)"` —
например `PersistentKeepalive = 22-30`. **Значение не задано = 0** для любого
параметра.

### 2.1.2 Синтаксис I1…I5 — это НЕ просто hex

Значение `I1..I5` — последовательность тегов (README amneziawg-go, раздел
«Custom signature packets»):

| Тег | Что кладёт в пакет |
|---|---|
| `<b 0x[seq]>` | статические байты: `[seq]` — hex-строка чётной длины (2 знака на байт) |
| `<r [size]>` | `[size]` случайных байт |
| `<rd [size]>` | `[size]` случайных цифр `[0-9]` |
| `<rc [size]>` | `[size]` случайных букв `[a-zA-Z]` |
| `<t>` | 4 байта текущего времени в формате UNIX |

Теги можно комбинировать в одной строке. Наш парсер (§3.2) сводит в hex
ТОЛЬКО одиночный `<b 0xHEX>` (одно- или многострочный); любое сочетание
тегов (`<r 32><t>`, `<b 0x..><r 16>`) хранится дословно, а `_emit` отдаёт
значение, начинающееся с `<`, как есть, не заворачивая в `<b 0x…>`. Если
правишь `parse_conf`, не считай, что содержимое `I*` обязано быть hex.

> ⚠️ Раньше парсер выкидывал пробелы из всего хвоста (`<r 16>` → `<r16>`),
> а рендер заворачивал любое значение в `<b 0x…>` (`<b 0x<r 32><t>>`) —
> профиль с такими тегами не поднимался или давал «92 B in / 20 KB out».
> Сторож — `TestSignatureTags` в `tests/test_awg_routing_safety.py`.

> **`Jmax` и MTU.** README: «если `Jmax` ≥ системного MTU (не того, что задан в
> AWG), система нарежет пакет на фрагменты, что со стороны цензора выглядит
> подозрительно». То же про итоговый размер signature-пакета.

> ⚠️ **`J1..J3` и `Itime` нельзя отдавать в `awg setconf` — вообще никогда.**
> Их нет в `key_match` парсера amneziawg-tools (`src/config.c`) ни в одном
> релизе, включая свежий `v3.1.20260812`. На неизвестном ключе парсер делает
> `goto error`: печатает `Line unrecognized: '<строка>'` и **отбрасывает
> конфиг целиком**. То есть один лишний ключ из чужого `.conf` = интерфейс не
> поднимается вовсе, а наружу видно лишь невнятное «Unable to modify
> interface». Разбирать и сохранять их при round-trip мы обязаны (профиль из
> клиента Amnezia не должен терять поля), а в setconf — не отдаём:
> `AWG_FIELDS_UNSUPPORTED_BY_TOOLS` + `_setconf_skip_fields` в
> `core/awg_config.py`, сторож — `tests/test_awg_config.py`.

### 2.1.1 AWG 3+: защита заголовка, паддинг содержимого, тайминги

Ветка **amneziawg-go v3.x** (текущая; сверено с README **v3.1.20260828** —
на 3.1 он не менялся) добавила
поколение параметров, которое апстрим маркирует как **`[AWG 3+]`**. В `.conf`
они живут в секции устройства (`[Device]` в терминах README = `[Interface]` в
терминах wg-quick):

| Ключ | Тип / сторона | Назначение |
|---|---|---|
| `HeaderProtectionKey` | `key,string`, **server-side** | Ключ шифрования низкоэнтропийных полей заголовка — тех, что WireGuard использует для аутентификации и собственного шифрования. Нонсом служит crypto-паддинг `S1–S4`. Генерируется `awg genkey` |
| `ContentPaddingAddition` | `uint32,range`, client-side | Дополнительный паддинг содержимого |
| `RekeyAfterTime` | `uint32,range`, сек | Через сколько клиент пробует сделать handshake |
| `RekeyTimeout` | `uint32,range`, сек | Таймаут, после которого handshake повторяется |
| `RejectAfterTime` | `uint32,range`, сек | Когда клиент форсирует handshake и отвергает входящие данные |
| `KeepaliveTimeout` | `uint32,range`, сек | Через сколько после последней отправки данных шлётся keepalive |
| `MaxHandshakeAttempts` | `uint32,range` | Предел попыток handshake |

> ⚠️ **Защита заголовка требует `S1–S4` не меньше 12** (README, «Header
> protection»): паддинг служит нонсом шифра. `HeaderProtectionKey` при
> `S*` < 12 — нерабочая связка.

Все семь ключей **принимаются парсером tools** — они есть в `key_match`
(`src/config.c`, `v3.0.20260730` и новее), в отличие от `J1..J3`/`Itime`.
То есть в `awg setconf` их отдавать можно и нужно.

**Наш статус:** поддержаны — константа `AWG3_INTERFACE_FIELDS` в
`core/awg_config.py` входит в `WG_INTERFACE_FIELDS`, поэтому поля переживают
round-trip и доходят до демона. `validate()` проверяет их как тип `range`
(`"a-b"` / `"a"` / `"(off)"` — числом их валидировать нельзя),
`HeaderProtectionKey` — как base64-ключ на 32 байта, и отдельно ругается,
если при заданном ключе минимальный из `S1..S4` меньше
`AWG3_HEADER_PROTECTION_MIN_S` (12).

> ⚠️ Раньше этих полей в списке не было, и AWG3-профиль молча терял их при
> `render_setconf`: демон поднимался без защиты заголовка, а пир, который её
> ждёт, дропал data-пакеты — тот самый «92 B in / 20 KB out» (§12).
> Тесты-сторожа: `TestAwg3Fields` в `tests/test_awg_config.py`.

### 2.1.2 AWG 3.1: случайные хвосты и отказ от cookie-ответов

Пара **amneziawg-go `v3.1.20260814`** + **amneziawg-tools `v3.1.20260812`**
добавила ровно два ключа в секцию устройства (поведение обоих уточнено в
`v3.1.20260828`, см. врезку ниже). В README их нет — источник
истины здесь только код: `device/uapi.go` (UAPI-ключи) и `src/config.c`
(`key_match`).

| Ключ | UAPI-ключ | Тип | Назначение |
|---|---|---|---|
| `RandomTrailers` | `random_trailers` | bool | Дописывать служебным пакетам (init / response / cookie) хвост случайной длины — до размера UDP-окна пира. Размер пакета перестаёт быть константой, по которой его опознаёт DPI |
| `DisableCookies` | `disable_cookies` | bool | Не отвечать cookie-reply на отброшенный handshake. Cookie-ответ — заметная сигнатура WireGuard, но это же и штатная анти-DoS-защита |

> ⚠️ **Что изменилось в `v3.1.20260828` (важно для обоих ключей).**
> `DisableCookies` раньше лишь не ОТПРАВЛЯЛ cookie-reply
> (`SendHandshakeCookie` выходил сразу), а под нагрузкой всё равно
> ТРЕБОВАЛ корректный MAC2 во входящем handshake. Теперь флаг выключает
> под-нагрузкой-путь целиком: `RoutineHandshake` не проверяет MAC2, если
> `DisableCookies` включён (`device/receive.go`). То есть это уже не «молчим
> в ответ», а «анти-DoS cookie-механизм не работает вовсе» — именно так
> его и надо описывать пользователю.
>
> `ContentPaddingAddition` (§2.1.1) и `RandomTrailers` теперь ограничены не
> MTU, а **UDP-окном пира** (`peer.udpWindow`): стартовое значение
> `DefaultUdpWindow = 500` байт, дальше окно растёт до размера самого
> большого реально виденного пакета в обе стороны. Если пакет уже больше
> окна — добавка равна нулю. Практический вывод: на «тихом» туннеле
> паддинг/хвосты заметно меньше, чем можно было ожидать по MTU, и растут по
> мере трафика; это не баг конфигурации.

> ⚠️ **`RandomTrailers` симметричен — включать надо на ОБОИХ концах.**
> Приёмник опознаёт служебный пакет по точному размеру и допускает больший
> только при включённом флаге (`DeterminePacketTypeAndPadding` в
> `device/receive.go`). Включён у клиента и выключен у сервера — handshake не
> проходит вовсе: пакет просто не распознаётся как init.

> ⚠️ **Значение пишется как `on`/`off` или число, но НЕ `true`/`false`.**
> `parse_bool` в `src/config.c` знает только `on`/`off` (без учёта регистра) и
> десятичное число (`0` = выкл). На `true` он печатает «Boolean value is
> neither on/off nor 0/1» и, как на любой ошибке разбора, **отбрасывает
> конфиг целиком**. Наш `validate()` ловит это на импорте, пока ещё видно,
> какое поле виновато.

> ⚠️ **Это отдельная планка поколения, а не «ещё два поля AWG 3+».** Движок
> `v3.0.x` на этих UAPI-ключах отвечает `invalid UAPI device key` → EINVAL →
> знакомое «Unable to modify interface: Invalid argument». Поэтому
> `required_generation()` поднимает такой профиль до **3.1**, а не до 3.0:
> подсказка «нужен AWG 3.0» пользователю, у которого как раз 3.0, увела бы
> совсем не туда.

**Наш статус:** поддержаны — `AWG31_INTERFACE_FIELDS` в `core/awg_config.py`
входит в `WG_INTERFACE_FIELDS`, поэтому поля переживают round-trip и доходят
до `awg setconf`.

### 2.1.2а Поле `[Peer] AdvancedSecurity`

В `key_match` секции `[Peer]` у tools, кроме стандартных `PublicKey`,
`PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`, есть ещё
**`AdvancedSecurity`** (флаг «продвинутой безопасности» для конкретного пира).
Он есть и в нашем `WG_PEER_FIELDS`, так что импортированный профиль его не
теряет.

`PersistentKeepalive` в AWG 3+ — тоже тип `range`: валидны `25`, `22-30` и
`(off)`. `validate()` принимает все три формы и проверяет границы 0..65535
для числовых.

> **Junk vs padding vs header — не путать.** `Jc/Jmin/Jmax` — отдельные
> мусорные пакеты ДО рукопожатия. `S1–S4` — случайный префикс ВНУТРИ реальных
> пакетов каждого типа. `H1–H4` — подменяют первый байт (тип сообщения), чтобы
> DPI не видел сигнатуру WireGuard.

### 2.2 H1–H4: ограничения

- Стандартный WireGuard использует типы сообщений **1, 2, 3, 4** (init/
  response/cookie/transport). `H1–H4` их заменяют — но это работает, **только
  если AmneziaWG-обфускацию понимает и пир**. Cloudflare WARP — это ВАНИЛЬНЫЙ
  WireGuard, он `H1–H4 ≠ 1,2,3,4` не понимает и дропает handshake. Поэтому для
  WARP `warp_generator` оставляет **`H1=1, H2=2, H3=3, H4=4`** (и `S1=S2=0`),
  а обфускацию даёт только junk-пакетами (`Jc/Jmin/Jmax`) — их ванильный
  WireGuard просто игнорирует. Нестандартные `H*` (`5 … 0x7FFFFFFF`) уместны
  лишь для AmneziaWG-aware сервера, не для чистого WARP (`core/warp_generator.py`).
  Проверено локально: против ванильного WG-пира handshake проходит ТОЛЬКО при
  `S1=S2=0` и `H1..H4=1,2,3,4`; рандомные `H*` или `S>0` → handshake не идёт.
- В **AmneziaWG 2.0** у `H1–H4` появилась **поддержка диапазонов** (range): значения
  выбираются случайно в заданном окне и **не должны перекрываться**. В `.conf`
  это строка вида `H1 = 123-456`. `parse_conf` хранит `H*` как строки, а
  `validate()` принимает для `H1–H4` либо одиночный uint, либо диапазон `N-M`
  (`N<=M`); прочие числовые поля обфускации остаются строгими int.
  amneziawg-tools (`src/config.c`) хранит `H*` как opaque-строки
  (`parse_awg_string`) — так что это лишь GUI-санити-чек формата.

### 2.3 Версии протокола и совместимость (КРИТИЧНО)

| Версия | Что добавляет | Параметры |
|--------|---------------|-----------|
| **1.0** | базовая обфускация: junk + magic-headers + padding init/response | Jc, Jmin, Jmax, S1, S2, H1–H4 |
| **1.5** | мимикрия под обычные UDP-протоколы (QUIC, DNS…) через signature-пакеты | + I1–I5, J1–J3, Itime |
| **2.0** | «полная мимикрия»: меняющиеся заголовки и размеры пакетов и в data-фазе | + S3, S4; range для H1–H4; **− J1–J3, Itime** |
| **3.0** (`AWG 3+`) | шифрование полей заголовка, кастомный паддинг содержимого, настраиваемые тайминги WireGuard | + HeaderProtectionKey, ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts; тип `range` у таймингов и `PersistentKeepalive` (§2.1.1) |
| **3.1** | случайная длина служебных пакетов, отказ от cookie-ответов | + RandomTrailers, DisableCookies (bool, `on`/`off`; §2.1.2) |

> **Нумерация версий ≠ нумерация релизов, но с 3.0 они совпали.** `amneziawg-go`
> прыгнул с `v0.2.19` сразу на `v3.0.0`, и `[AWG 3+]` в README — это ровно
> поколение параметров этой ветки. Пользователь со старым бинарём (`v0.2.x`)
> AWG3-полей не понимает: демон их не применит, а `awg` из старого
> `amneziawg-tools` (`v1.0.2026*`) на них ещё и **отбросит весь конфиг**
> (`Line unrecognized`). То есть «профиль AWG3 + старая пара бинарей» = туннель
> не поднимется вовсе, а не деградирует.

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
J1–J3, Itime`). Числовые валидируются как int (`AWG_OBFUSCATION_FIELDS`), а
`H1–H4` — как int ИЛИ диапазон `N-M` (§2.2); hex-blob `I1–I5, J1–J3` — отдельно
(`AWG_V2_BLOB_FIELDS`).

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
3. `amneziawg-go <iface>` (subprocess) — форкает демон + TUN. PID находим
   обходом `/proc` с ПОТОКЕННОЙ сверкой argv (`_argv_has_seq`), пишем в
   `<run_dir>/awg-<iface>.pid`. Подстрокой искать нельзя: «amneziawg-go
   warp» входит в «amneziawg-go warp2», и `down warp` убивал бы соседа;
   `_pid_is_our_daemon(pid, iface)` тоже требует имя интерфейса в argv.
4. короткая пауза (UAPI-сокет `/var/run/wireguard/<iface>.sock` должен подняться).
5. резолв Endpoint'ов в IP и **исключение для собственного Endpoint**:
   `ip rule add to <ep>/32 iif lo lookup main priority 9990`
   (`ENDPOINT_BYPASS_PRIORITY`, раньше всех правил маршрутизации). Без него
   CIDR/домен/geoip, накрывший Endpoint, заворачивал UDP демона в этот же
   туннель — петля. `iif lo` — только трафик роутера; `main` — потому что
   WARP-in-WARP кладёт маршрут к Endpoint inner'а именно туда. Ставится ДО
   setconf, пишется в `routes.json` (`{"bypass": …}`), снимается при down.
   Выключатель — `awg.endpoint_bypass` (по умолчанию вкл.).
6. `awg setconf <iface> <filtered.conf>` — крипто + обфускация.
7. `ip link set dev <iface> mtu <MTU>` (если задан).
8. `ip addr add <Address>` (каждый адрес; ошибка — предупреждение: v6 на
   роутере без IPv6 не встаёт, а v4 работает).
9. `ip link set dev <iface> up` — ошибка здесь фатальна: откат и `ok=False`.
10. маршруты из `AllowedIPs` → `table <id>` (если `Table != off`). `id` —
   стабильный хэш имени интерфейса в диапазоне **100…999**, кроме системных
   253/254/255 (`default`/`main`/`local`, `RESERVED_TABLE_IDS` в
   `core/routing/manager.py`): таблицу туннеля `down` целиком флашит, и
   совпадение с `main`/`local` отрезало бы роутер от сети. Сохранённый в
   `routing.table_map` системный id выдаётся заново.
11. снимок состояния `<run_dir>/awg-<iface>.last_up.json` + список добавленных
    маршрутов `<run_dir>/awg-<iface>.routes.json` (чтобы корректно снять при down).
12. `PostUp`-хуки → `core.routing.applier.apply_all_on_interface_up()`.

> **`DNS =` из `[Interface]` не применяется — намеренно.** wg-quick
> переписал бы `resolv.conf` роутера и увёл бы в туннель весь DNS, а у нас
> туннель только *доступен* через свою таблицу (селективная модель, п.10).
> DNS роутера остаётся за dnsmasq/NDMS; DNS через туннель — это
> `dns_routing` («Маршрутизация» → DNS) или DoH в правиле. Поле
> сохраняется в конфиге, чтобы экспорт/импорт не терял его.

### 5.2 Снятие — `_do_down`
Обратный порядок: `PreDown` → снять правила роутинга → удалить добавленные
маршруты → `ip link down` → `ip link delete dev <iface>` → SIGTERM (затем
SIGKILL) демону по PID → удалить pid-файл и UAPI-сокет → `PostDown` →
откат auto-dnsmasq (если это был последний AWG-интерфейс).

`restart` = `_do_down(keep_routing=killswitch.enabled())` → up. С
включённым kill-switch'ем (`routing.killswitch`) правила маршрутизации на
рестарте НЕ снимаются (ip rule, доменные set'ы с IP от dnsmasq), а blackhole
возвращается в таблицу сразу после `flush` — иначе на время рестарта (а при
неудачном `up` — навсегда) трафик правил уходил бы мимо туннеля. Без
kill-switch'а (по умолчанию) рестарт — полный down + up, как до 13.10.2026:
таблица между ними всё равно пуста, а после того изменения на Keenetic
начались зависания роутера при рестартах watchdog'а. Явный `down` снимает
всё и сообщает watchdog'у (`awg_watchdog.forget_took_down`), что туннель
остановлен пользователем. `restart` интерфейса без нашего `.conf`
отказывает, ничего не трогая (watchdog такие и вовсе пропускает:
`has_config_for`).

`status(name)` парсит `awg show <iface> dump`
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
`awg-<iface>.last_up.json`.

**UAPI-сокет демона лежит НЕ в нашем `run_dir`** — путь задаёт сам движок:

| Бинарь | Каталог сокета |
|---|---|
| `amneziawg-go` **v3.x** | `/var/run/amneziawg/<iface>.sock` (`ipc/uapi_unix.go`: `var socketDirectory = "/var/run/amneziawg"`) |
| `awg` (tools v3.1.20260812) | тот же: `SOCK_PATH RUNSTATEDIR "/amneziawg/"` (`src/ipc-uapi-unix.h`) |
| унаследованный от wireguard-go (старые сборки `v0.2.x`) | `/var/run/wireguard/<iface>.sock` |

Единый список каталогов — `awg_platform.UAPI_SOCKET_DIRS` (v3-путь первым);
`platform.uapi_paths(iface)` отдаёт все кандидаты, `uapi_path(iface)` —
существующий, иначе путь текущей ветки. Подчистка в
`awg_manager._cleanup_iface()` и поиск интерфейсов в `awg_detector` обходят
**оба** каталога: на роутере вполне может стоять и старый `amneziawg-go`.

> Раньше оба места были захардкожены на `/var/run/wireguard/`, и с бинарями
> v3 сокет после SIGKILL оставался лежать, а обнаружение интерфейсов по
> сокетам не находило ничего. На путь ЗАПУСКА это не влияло и не влияет —
> `_do_up` сокет намеренно НЕ ждёт (был регресс, ронявший AWG на Keenetic,
> см. комментарий в `_do_up`). Сторож — `TestUapiSocketDirs` в
> `tests/test_awg_manager_lifecycle.py`.

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
- **Версия бинаря** — ТОЛЬКО `<bin> --version`, regex `v?(\d+(\.\d+){1,3}…)`;
  источник №1 — `opkg status <pkg>` для Entware. 🔴 **Никаких `-v`**: у
  amneziawg-go (как у wireguard-go) версию печатает лишь `--version`, а любой
  другой единственный аргумент — ИМЯ ИНТЕРФЕЙСА. `amneziawg-go -v` поднимает
  userspace-туннель «-v» (демон в фоне, PPID=1, `/var/run/amneziawg/-v.sock`,
  ~15 МБ RSS навсегда). Старый fallback на `-v` при медленном `--version` так
  и плодил демонов; уже рождённых убирает `awg_manager.reap_stray_daemons()`
  на старте GUI, а `_valid_iface_name` не пускает имена с «-» в начале.
  Версия внешней установки кешируется (`_ext_version_cache`, ключ — путь,
  отпечаток — mtime+размер; неудача — на 10 мин), иначе каждый опрос статуса
  запускал `opkg status` + `--version`.
- **Автозапуск** — общего выключателя нет: решают только
  `awg.autostart.interfaces.<имя>`. Поле `awg.autostart.enabled` — мёртвое
  наследие (старый `_section` дописывал его как `false`), `_section` стирает
  его из settings.json при первом чтении. Учитывать его как выключатель
  нельзя: оно `false` у всех, кто трогал автозапуск. Выключить автоподъём
  туннеля — снять его галку «автозапуск» на странице AWG.
  `autostart.enabled` в корне — про nfqws2, не про AWG.
- **Битый бинарь** (`_probe_binary`): ловим `exec format error`, `cannot execute
  binary`, `syntax error` — типичная ситуация при неверной арх/endianness.

---

## 8. Cloudflare WARP и WARP-in-WARP

### 8.1 Генерация WARP (`warp_generator.py`)
- Регистрация: `POST https://api.cloudflareclient.com/v0a2483/reg` (генерим пару
  ключей, регистрируем публичный, получаем peer/endpoint).
- Дефолты: endpoint `engage.cloudflareclient.com:2408`, peer-pubkey
  `bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=`.
- **Обфускация для WARP (vanilla-WG-совместимая):** `Jc 4..12`, `Jmin=40`,
  `Jmax=70`, **`S1=S2=0`**, **`H1=1, H2=2, H3=3, H4=4`**. Cloudflare-сервер —
  обычный WireGuard, поэтому единственная допустимая обфускация — junk-пакеты
  (отдельные UDP-датаграммы перед handshake, которые пир игнорирует). Паддинг
  `S1..S4>0` и нестандартные `H1..H4` ломают разбор пакета у Cloudflare → туннель
  не поднимается (это была реальная регрессия: генератор ставил рандомные `H*` и
  `S1/S2 15..100`, и «чистый WARP» не работал — теперь только junk). Готовые
  amnezia-wg-WARP конфиги «в дикой природе» используют ровно этот профиль
  (`H=1,2,3,4`, `S=0`, `Jc>0`, опц. signature-`I1`).

> **Новый путь — генератор `core/vpngen`** (скил `vpngen`): WARP и Proton
> для AWG/usque/sing-box/mihomo, маски I1 (QUIC/DNS/SIP), регистрация через
> обход. `warp_generator.py` остался за старым `/api/awg/warp/generate`
> (вкладка «Генерация» на странице WARP ссылается на новый генератор).
> Ограничения обфускации для ванильного WG-сервера там те же, что здесь.

### 8.2 Импорт WARP (`warp_importer.py`)
Распознаёт готовый `.conf` как WARP по: endpoint в диапазонах Cloudflare
(`162.159.192.0/24`, `162.159.193.0/24`, …), `AllowedIPs` = `0.0.0.0/0`/`::/0`,
наличию AWG-обфускации.

### 8.3 WARP-in-WARP (двойной туннель, `awg_warp_in_warp.py`)
Состояние в `config["awg"]["warp_in_warp"]`. Подъём:
1. **Резолв endpoint внутреннего** туннеля ДО подъёма (пока маршрут «наружу» ещё
   прямой) и проверка, что он **не совпадает** с endpoint'ом outer
   (`_endpoint_ips_of`): иначе `/32` из шага 3 завернул бы в outer его же UDP.
   Два WARP-профиля часто смотрят на один `162.159.192.x` — такая пара
   отклоняется с подсказкой взять другой адрес Cloudflare.
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

**Watchdog** (`awg_watchdog.py`) — перезапуск при «протухшем» handshake
(только интерфейсов с нашим `.conf` — чужие пропускаются):
`handshake_timeout_sec=180`, `check_interval_sec=30`, `cooldown_sec=300`,
`max_restarts_per_hour=6`, опциональный TCP-`probe` (host:port сквозь туннель).
`decide_restart()`: рестарт, если возраст handshake ≥ timeout **или** probe
падает N раз **или** сработал пассивный детектор. Cooldown и лимит в час —
один бюджет на **имя конфига** (`_config_name`), общий у рестартов и у
воскрешения (`_resurrect_down_autostart`); раньше рестарты считались по
интерфейсу, и при `awg0-opkgtun0`/`opkgtun0` бюджет удваивался.

Возраст handshake — по системным часам, а роутер без RTC грузится с часами
из прошлого: handshake до синхронизации NTP получает старую метку, и после
неё выходит «handshake 1032687с назад». `effective_handshake_age()`: возраст
больше аптайма (или отрицательный) недостоверен — считается по монотонным
часам с первого взгляда на эту метку.

Пассивных детекторов два, оба по счётчикам `awg show` (у неактивного
интерфейса их состояние сбрасывается):
- **rx-stall** (`eval_rx_stall`, `rx_stall_*`, 120 с): tx вырос на ≥4 КБ, а
  rx — не больше чем на 1 КБ (keepalive-шум) → «шлёт, но не принимает»;
- **zero-rx** (`eval_zero_rx`, `zero_rx_enabled`/`zero_rx_timeout_sec`, 60 с):
  с подъёма rx == 0 при tx > 0 → «трафик стоит, 0 байт», сервер не ответил
  даже на handshake. Handshake-триггер тут слеп (handshake'а не было, возраст
  None). В простое (tx == 0) не срабатывает.

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
3. **версия бинаря** `amneziawg-go --version` / `awg --version` — поддерживает
   ли он поля своего поколения? `S3/S4` и range-`H*` — это 2.0; AWG3-поля
   (`HeaderProtectionKey`, `ContentPaddingAddition`, тайминги, §2.1.1) — только
   ветка `v3.x`, а `RandomTrailers`/`DisableCookies` (§2.1.2) — только
   `v3.1.20260814` и новее (их поведение уточнено в `v3.1.20260828`).
   Старый **демон** молча работает в 1.x, а старые **tools** на
   незнакомом ключе печатают `Line unrecognized` и отбрасывают весь конфиг —
   разные симптомы, не перепутай. Наш `render_setconf` AWG3-поля пропускает
   (§2.1.1), так что их отсутствие в `awg showconf` на свежем бинаре — это
   про сам бинарь, а не про фильтрацию у нас.
4. **MTU/фрагментация** — `Jmax`/`S*` не должны раздувать пакет за MTU; дефолт
   `MTU=1420`. Симптом: handshake ок, мелкое работает, крупное/TLS виснет.
5. **битый бинарь** (неверная арх/endianness MIPS) — `_probe_binary`,
   «exec format error». Переустановить под верную арх (§7).
6. **`awg_manager.diagnostics()`** даёт полный снимок: бинари, конфиг (privkey
   замаскирован), `awg show`, `ip rule`/`ip route`, маршрут до каждого endpoint,
   состояние фаервола/dnsmasq.
7. **Keenetic native WG** не управляется нами — статус берётся из NDMS (§9), не
   из `awg show`.
8. **Туннель поднят не нами.** `amneziawg-go <iface>`, которого нет в наших
   pid-файлах (`run_dir/awg-<iface>.pid`), — это Entware `S99amneziawg`,
   `S52awg-opkgtun0` и т.п. `is_running()` по `awg show interfaces` считает его
   «поднятым», но `down`/автозапуск им не управляют, а после перезагрузки его
   поднимет свой скрипт. `core/foreign_services` показывает такие процессы и
   скрипты (страница «Сторонние туннели»), находит **конфликт имён** (`S51usque`
   и `S52awg-opkgtun0` оба на `opkgtun0`) и по кнопке передаёт туннель GUI:
   конфиг из каталогов GUI или из самого скрипта → `stop` + снять бит
   исполнения скрипта → убрать UAPI-сокет → `up` силами GUI → автозапуск GUI.

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
