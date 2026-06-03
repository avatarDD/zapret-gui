---
name: nfqws2-strategies
description: >-
  Полный справочник по nfqws2 / zapret2 в проекте zapret-gui (роутеры Keenetic
  на Entware). Использовать при любых запросах о: стратегиях nfqws2/zapret2,
  каталогах catalogs/*, сканере стратегий (strategy_scanner), сборке аргументов
  (nfqws_manager, strategy_builder, blob_registry, lua_manager), firewall /
  NFQUEUE-правилах (core/firewall.py), lua-desync функциях, blob'ах,
  hostlist'ах, оркестраторах (circular), blockcheck2-интеграции и диагностике
  «стратегия не работает / 0% успешности». Источник истины — bol-van/zapret2
  (docs/manual.md, lua/zapret-antidpi.lua), привязка — наш код в core/.
---

# nfqws2 / zapret2 — справочник для zapret-gui

Этот файл — единый источник истины о том, **как nfqws2 (zapret2) реально
работает** и как с ним правильно обращаться в проекте `zapret-gui`. Читать
перед тем, как трогать сборку аргументов, сканер стратегий, firewall,
каталоги или объяснять пользователю «почему не работает».

Источники истины (в порядке убывания авторитета):
1. **bol-van/zapret2** — движок nfqws2: `docs/manual.md`, `lua/zapret-antidpi.lua`
   (комментарий перед каждой функцией = спецификация её аргументов),
   `lua/zapret-auto.lua`, `lua/zapret-lib.lua`, `lua/zapret-obfs.lua`,
   `init.d/custom.d.examples.linux/`, `config.default`.
2. **`nfqws2 -?`** (v0.9.5.2) — дамп опций CLI, §3 ниже.
3. **nfqws2-keenetic** — поведенческий эталон под Keenetic (НЕ путать пути —
   у них своя раскладка `S51nfqws2` / `/opt/etc/nfqws2/…`; у нас её НЕТ).
4. **Наш код в `core/`** — `nfqws_manager.py`, `strategy_scanner.py`,
   `strategy_builder.py`, `blob_registry.py`, `firewall.py`, `diagnostics.py`,
   `blockcheck2.py`, `autostart_manager.py`, `lua_manager.py`,
   `hostlist_manager.py`, `catalog_loader.py`, `config_manager.py`.

---

## 1. nfqws2 vs nfqws1 — ключевые отличия

nfqws2 **не имеет хардкод-стратегий**. Параметров `--dpi-desync=fake,split2`,
`--dpi-desync-split-pos=`, `--dpi-desync-fooling=` **больше нет** — это
синтаксис старого nfqws1 / winws. Всё дурение живёт в **Lua-скриптах**, а CLI
лишь загружает их и вызывает функции.

Что изменилось:

- **Ядро nfqws2** (dvtws2 на BSD, winws2 на Windows) — только перехват и
  диссекция; «дурение» вынесено в Lua. Это даёт радикально большую гибкость.
- Параметры `--dpi-desync-*` заменены на:
  - **`--lua-desync=<function>[:arg1[=val1]:argN[=valN]]`** — вызов
    Lua-инстанса (десинк-функции из `zapret-antidpi.lua` или своей);
  - **`--lua-init=@file.lua | <lua_code>`** — однократная инициализация
    (можно несколько раз, порядок сохраняется, поддержан `.gz`);
  - **`--blob=<name>:[+ofs]@file | 0xHEX`** — загрузка двоичных данных в
    Lua-переменную.
- Понятие **payload type** (`tls_client_hello`, `http_req`, `quic_initial`, …)
  пришло на смену «протоколу соединения» в фильтрах.
- Десинхронизации больше не «фаза 1 / фаза 2». Каждый `--lua-desync` —
  отдельный инстанс, выполняются последовательно, можно вызывать одну функцию
  много раз с разными параметрами.
- Старые `start/cutoff` стали **диапазонами**: `--in-range` и `--out-range`.
- **Профили** (мультистратегия) и **хостлисты** сохранены, разделитель —
  `--new`. Логика автохостлиста изменена: профиль с автолистом захватывает
  только соединения с известным `hostname`; до его получения — мимо.
- `--server` инвертирует трактовку направлений и фильтрации.
- Автоматическая TCP-сегментация в `zapret-lib.lua`: размер blob не важен,
  всё нарезается по MSS.
- Поддержка **многопакетных пейлоадов** (kyber в `tls_client_hello`,
  многопакетный `quic_initial`) с авто-reasm и replay.

### Состав стандартной Lua-библиотеки (`/opt/zapret2/lua/`)

| Файл | Содержимое |
|---|---|
| `zapret-lib.lua` | Базовые примитивы. **ПЕРВЫМ среди `--lua-init`**: `rawsend`, `tcpseg`, `send`, `drop`, диссекторы TLS/QUIC, маркеры, утилиты. |
| `zapret-antidpi.lua` | Готовые desync-аналоги nfqws1: `fake`, `multisplit`, `multidisorder`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `tcpseg`, `oob`, `wsize`, `wssize`, `syndata`, `rst`, `synack`, `synack_split`, `udplen`, `dht_dn`, `http_*`, `pktmod`, `pass`, `luaexec`. **Без неё `--lua-desync=fake:...` — вызов несуществующей функции: тихий 0%**. |
| `zapret-auto.lua` | Оркестраторы (`circular`, `repeater`, `condition`, `per_instance_condition`, `stopif`) и iff-функции (`cond_random`, `cond_payload_str`, `cond_lua`, …). |
| `zapret-obfs.lua` | Обфускаторы: `wgobfs`, `ippxor`, `udp2icmp`, `synhide`. **Надмножество** `zapret-wgobfs.lua` — если грузим `obfs`, то `wgobfs.lua` грузить НЕ надо (двойное определение). |
| `zapret-pcap.lua` | Запись pcap. Требует `--writeable`. |
| `zapret-tests.lua` | Тесты C-функций. |

### Наши расширения (`import/lua/`, разворачиваются на `lua_path` через `core/asset_importer.py`)

| Файл | Экспорт |
|---|---|
| `zapret-multishake.lua` | `hostfakesplit_stealth/chaos/multi/gradual/decoy/blend/soft`, `snifakesplit` |
| `fakemultisplit.lua` | `fakemultisplit` |
| `fakemultidisorder.lua` | `fakemultidisorder` |
| `zapret-16kb.lua` | `flood_white`, `ttl_ladder`, `white_sandwich`, `seqovl_white` |
| `zapret-rst-flood.lua` | `rst_flood` |
| `zapret-auto.lua` | `circular`/`condition`/`repeater`/`stopif`/`per_instance_condition` + детекторы/хосткеи (`standard_*_detector`, `cond_*`, `automate_*`). Триггер-загрузка по этим функциям; companion-bundle зависит от его `standard_*_detector`, поэтому `zapret-auto` до-грузится и в orchestrator-блоке (для `circular_with_preload`, которого нет в его экспорте) |
| `custom_funcs.lua` | расширенный каталог приёмов проекта (`http_*`/`tls_*`/`discord_*`/`multisplit_tls`/`tlsrec`/`rst_desync`/…); зависит только от core |
| `custom_diag.lua` | `diag_once`, `diag_always` (диагностические no-op) |
| **Companion'ы оркестратора `circular`** (грузятся **bundle'ом**, см. §10): `combined-detector.lua`, `domain-grouping.lua`, `strategy-stats.lua`, `strategy-lock-manager.lua`, `silent-drop-detector.lua` |

**Core = только `zapret-lib.lua` + `zapret-antidpi.lua`** (как эталонный
`blockcheck2 pktws_start`): грузятся при наличии любого `--lua-desync`. Всё
остальное — включая `zapret-auto`/`custom_funcs`/`custom_diag`/`init_vars` —
условно (раньше эти четыре были в core «всегда»).

**`init_vars.lua` — value-триггер (НЕ в `_EXTENSION_LUA_FILES`):** объявляет
именованные паттерн-переменные (`tls_google`, `tls_rnd*`, `bin_max`,
`fake_inverted_tls`, …), используемые как `blob=`/`pattern=`/`seqovl_pattern=<NAME>`.
Грузится сразу после core ТОЛЬКО если стратегия ссылается на такое имя
(см. `_INIT_VARS_NAMES`/`_NAMED_PATTERN_RE` в `nfqws_manager.py`). Встроенные
блобы (`fake_default_*`) его не требуют. Сторож — `TestInitVarsTrigger`.

**Инвариант:** набор-триггер каждого файла (карта `_EXTENSION_LUA_FILES` в
`nfqws_manager.py:56`) обязан совпадать с его глобальными функциями
(`grep '^function ' import/lua/<file>.lua`) — иначе вызов «выпавшей» функции
= тихий 0%. Сторож — `tests/test_nfqws_lua_map.py`.

---

## 2. Архитектура обработки пакета

```
ядро ОС
  └── iptables/nftables → NFQUEUE №X (= --qnum)
        └── nfqws2
              ├── dissect (ip/ip6/tcp/udp/icmp + payload)
              ├── conntrack (счётчики, направления, MSS, scale, hostname)
              ├── распознавание payload type
              ├── reasm / decrypt (для tls_client_hello, quic_initial)
              ├── выбор профиля по фильтрам (1..N → default 0)
              ├── последовательно: Lua-инстансы (--lua-desync)
              │     каждый возвращает вердикт PASS / MODIFY / DROP
              │     (агрегация: DROP > MODIFY > PASS)
              └── возврат пакета в ядро
```

Цикл выбора профиля повторяется при изменении L7-протокола и при получении
hostname (макс. 2 «перескока»). Если все инстансы профиля вошли в cutoff или
вышли за `range` — соединение помечается **lua cutoff** по направлению и
больше не дёргает Lua.

### Обязательные инварианты (нарушение = тихий 0%)

1. **`zapret-lib.lua` грузится `--lua-init` ПЕРВЫМ** — он определяет базовые
   примитивы, на которые опирается `zapret-antidpi.lua` и наши расширения.
2. **`zapret-antidpi.lua` подключён**, если стратегия вызывает `fake`,
   `multisplit`, `multidisorder`, … (см. список выше).
3. **Extension-скрипты грузятся ТОЛЬКО** при упоминании их функций — карта
   `_EXTENSION_LUA_FILES` в `nfqws_manager.py`. Дедуп `--lua-init`
   выполняется в `_build_lua_init_args`.
4. **`circular`-оркестратор тащит весь bundle** (`_ORCHESTRATOR_LUA_FILES`).
   Companion'ы (`combined-detector`, `domain-grouping`, `strategy-stats`,
   `strategy-lock-manager`, `silent-drop-detector`) — НЕ desync-действия,
   это аргументы `detector=`/`success=`/`hostkey=`/`preload=` у `circular`.
   Грузятся идемпотентно, без `require()`, существующие — guard'ом.
5. **`--qnum N` == firewall `queue num N`**. Оба значения берутся из
   `nfqws.queue_num` (дефолт **300**). Расходящиеся — пакеты идут в очередь,
   которую никто не слушает → тихий 0%.
6. **Все `--blob=NAME:@file` декларируются ДО первого `--new`** (декларации
   глобальные). Иначе fake уходит пустым.

### Встроенные блобы (НЕ требуют `--blob`)

- `fake_default_tls` — TLS ClientHello от Firefox без kyber, SNI =
  `www.microsoft.com`.
- `fake_default_http` — HTTP-запрос на `www.iana.org`.
- `fake_default_quic` — `0x40 + 619 × 0x00`.

Любые другие имена (`tls_google`, `stun_pat`, `quic_vk`, …) обязаны иметь
`--blob=NAME:@bin/file.bin`. Дозаявка по имени в проекте автоматизирована —
`core/blob_registry.build_blob_declarations()`.

---

## 3. Полный CLI nfqws2 (`nfqws2 -?`, v0.9.5.2)

Дамп v0.9.5.2 движка `bol-van/zapret2`. Версия печатается:
`github version v0.9.5.2 (<git-hash>) lua_compat_ver 5`. Опции с `[0|1]`/
`[=val]` имеют необязательный аргумент (без него — дефолт, обычно `=1`).

### 3.1 Общие / служебные

| Опция | Назначение |
|---|---|
| `@<config_file>` / `$<config_file>` | Читать опции из файла. **Должен быть единственным аргументом** — остальные игнорируются. Используется `nfqws2@.service` (systemd). У нас НЕ используется (всё inline через `compose_command`). |
| `--debug=0\|1\|syslog\|@<file>` | Уровень/назначение отладочного лога. Бэйр `--debug` ≡ `=1`. Файл `--debug=@file` можно удалить — продолжит писать с нуля. |
| `--version` | Печать версии и `lua_compat_ver`, выход. |
| `--dry-run` | Проверить параметры и выйти с кодом 0 при успехе. Lua-синтаксис НЕ проверяется (только наличие файлов и парсинг опций). **У нас: `NFQWSManager.dry_run()`, API `POST /api/strategies/<sid>/validate`.** |
| `--comment=<text>` | No-op, для читабельности конфига. |
| `--intercept=0\|1` | 0 = выполнить только `lua-init` и выйти. |
| `--qnum=<n>` | Номер NFQUEUE (== firewall `queue num`). |
| `--daemon` | Демонизироваться. **GUI запускает БЕЗ него** (foreground-child + Popen). С ним работает только автозапуск `S99zapret` (свой `--pidfile`). |
| `--chdir[=path]` | Без аргумента — `EXEDIR`. |
| `--pidfile=<file>` | PID-файл. У `S99zapret` — `/var/run/zapret-nfqws.pid`. |
| `--user=<name>` / `--uid=uid[:gid,…]` | Сброс root-привилегий. На Entware `--user nobody` работает (есть в read-only `/etc/passwd`); кастомных юзеров там нет. |
| `--bind-fix4` / `--bind-fix6` | Фикс выбора исходящего интерфейса для генерируемых пакетов (PBR / multi-WAN). Добавляются в `_build_base_args` при нескольких WAN. |
| `--fwmark=<int\|0xHEX>` | fwmark anti-loop. **Дефолт `0x40000000`** (1073741824) — совпадает с нашим `nfqws.desync_mark`. Не путать с firewall MARK_PROCESSED / MARK_EXCLUDE. |
| `--ctrack-timeouts=S:E:F[:U]` | Внутр. conntrack: TCP SYN, ESTABLISHED, FIN, UDP. Дефолт `60:300:60:60`. |
| `--ctrack-disable[=0\|1]` | Отключить внутренний conntrack. |
| `--payload-disable[=t1,…]` | Не детектировать типы payload (без аргумента — все). |
| `--reasm-disable[=t1,…]` | Отключить reasm для `tls_client_hello`, `quic_initial`. |
| `--server[=0\|1]` | Серверный режим (инверсия направлений и фильтров). |
| `--ipcache-lifetime=<sec>` | TTL hop-count / hostname-кэша (дефолт 7200, 0 = вечно). |
| `--ipcache-hostname[=0\|1]` | Кэшировать ip→hostname (нужно стратегиям нулевой фазы). |
| `--filter-ssid=ssid1[,…]` | Wi-Fi SSID-фильтр (Linux). |

### 3.2 DESYNC ENGINE INIT

| Опция | Назначение |
|---|---|
| `--writeable[=dir]` | Создать каталог для Lua (env `WRITEABLE`). |
| `--blob=<name>:[+ofs]@<file>\|0xHEX` | Глобальная декларация именованного блоба. Поддержан offset `+ofs`. **До первого `--new`**. |
| `--lua-init=@<file>\|<lua_text>` | Загрузить Lua. Порядок сохраняется. Поддержаны gzip-файлы. |
| `--lua-gc=<sec>` | Интервал GC Lua (дефолт 60). |

### 3.3 MULTI-STRATEGY (профили)

| Опция | Назначение |
|---|---|
| `--new[=<name>]` | Разделитель профилей. |
| `--skip` | Не использовать профиль. |
| `--name=<name>` | Имя профиля. |
| `--template[=<name>]` | Сделать профиль шаблоном (для `--import`). |
| `--cookie[=<str>]` | Значение `desync.cookie` для всех инстансов профиля. |
| `--import=<name>` | Импорт настроек из шаблона. Простые параметры замещаются, списочные (`--hostlist=`, `--filter-tcp=`, `--lua-desync=`) добавляются в конец. |
| `--filter-l3=ipv4\|ipv6` | Фильтр версии IP. |
| `--filter-tcp=[~]p1[-p2]\|*` | Фильтр TCP-портов; `~` = инверсия. Список через запятую. |
| `--filter-udp=[~]p1[-p2]\|*` | Аналогично UDP. |
| `--filter-icmp=type[:code]\|*` | Автоматически включает ICMPv6 (типы/коды разные). |
| `--filter-ipp=proto\|*` | Raw IP-протоколы (НЕ относится к tcp/udp/icmp — для них нужен свой `filter`). |
| `--filter-l7=p1[,p2…]` | L7-протокол потока. Полный список — §3.6. |
| `--ipset=<file>` / `--ipset-ip=<list>` | Include по IP/CIDR (ipv4+ipv6, gzip, несколько файлов). |
| `--ipset-exclude=<file>` / `--ipset-exclude-ip=<list>` | Exclude по IP. |
| `--hostlist=<file>` / `--hostlist-domains=<list>` | Десинк только для перечисленных хостов. Поддомены автоматически, `^` в начале — отключает учёт поддоменов, `#` — комментарий, gzip, несколько. |
| `--hostlist-exclude=<file>` / `--hostlist-exclude-domains=<list>` | Исключения. |
| `--hostlist-auto=<file>` | Автохостлист. |
| `--hostlist-auto-fail-threshold=<n>` | Фейлов для добавления (дефолт 3). |
| `--hostlist-auto-fail-time=<sec>` | В пределах N сек (дефолт 60). |
| `--hostlist-auto-retrans-threshold=<n>` | Ретрансмиссий = провал (дефолт 3). |
| `--hostlist-auto-retrans-reset=0\|1` | RST ретрансмиттеру (дефолт 1). |
| `--hostlist-auto-retrans-maxseq=<n>` | Дефолт 32768. |
| `--hostlist-auto-incoming-maxseq=<n>` | Успех если входящий rel-seq > N (дефолт 4096). |
| `--hostlist-auto-udp-out=<n>` | UDP-провал (дефолт 4). |
| `--hostlist-auto-udp-in=<n>` | UDP-провал (дефолт 1). |
| `--hostlist-auto-debug=<file>` | Лог срабатываний (глобальный). |

### 3.4 LUA PACKET PASS MODE (внутрипрофильные фильтры)

Действуют **до следующего переопределения того же типа или до конца профиля**.
В новом профиле сбрасываются на default.

| Опция | Default | Назначение |
|---|---|---|
| `--payload=t1[,t2]` | `all` | Какие payload-типы обрабатывают **следующие** Lua-функции. |
| `--out-range=<spec>` | `a` (всегда) | Диапазон по исходящему направлению. |
| `--in-range=<spec>` | `x` (никогда) | Диапазон по входящему направлению. |

### 3.5 LUA DESYNC ACTION

| Опция | Назначение |
|---|---|
| `--lua-desync=<fn>[:p1[=v1]:p2[=v2]…]` | Вызов Lua-инстанса. Несколько подряд — последовательно. |

### 3.6 Справочные списки значений

**`--filter-l7`:** `all unknown known http tls dtls quic wireguard dht discord
stun xmpp dns mtproto bt utp_bt`.

**`--payload` (типы):** `all unknown empty known ipv4 ipv6 icmp http_req
http_reply tls_client_hello tls_server_hello dtls_client_hello dtls_server_hello
quic_initial wireguard_initiation wireguard_response wireguard_cookie
wireguard_keepalive wireguard_data dht discord_ip_discovery stun xmpp_stream
xmpp_starttls xmpp_proceed xmpp_features dns_query dns_response mtproto_initial
bt_handshake utp_bt_handshake`.

**`--reasm-disable`:** `tls_client_hello`, `quic_initial`.

### 3.7 Правила построения фильтров профиля

- Профили проверяются строго **слева направо**, побеждает первый подошедший.
- Профиль 0 (default) — пустой, никаких действий.
- Группы фильтров `tcp / udp / icmp / ipp` объединяются **OR** между собой.
  Указание любого блокирует остальные группы — нужно явно прописать
  `--filter-tcp=*` если хочешь TCP + что-то ещё.
- `filter-ipp` НЕ относится к tcp/udp/icmp.
- Без автохостлиста профиль с хостлистами **не выбирается до получения
  hostname**. Если хост в exclude — стратегия не применяется. С автохостлистом —
  работает всегда при наличии hostname (счётчики через `--hostlist-auto-*`).
- ipset-ы могут смешивать ipv4+ipv6.

---

## 4. Диапазоны (`--in-range` / `--out-range`)

Формат: `[mode<int>](-|<)[mode<int>]`.

- `-` — верхняя граница **включительная**, `<` — исключительная.
- `mode`:
  - `a` — always (без числа)
  - `x` — never (без числа)
  - `n` — номер пакета
  - `d` — номер пакета с данными (рекомендуется на Windows из-за
    `--wf-tcp-empty=0`)
  - `b` — байт-позиция переданных данных
  - `s` — relative sequence (TCP) от начала пакета
  - `p` — relative sequence верхней границы пакета (s+payload)

Примеры: `--out-range=-d10` (первые 10 пакетов с данными), `--in-range=-s5556`,
`--out-range=s100-s1000`, `--in-range=s1<d1` (только до первого с данными).

---

## 5. Распознаваемые пейлоады (payload types)

| L7-протокол | L4 | Payload-типы |
|---|---|---|
| http | tcp | `http_req`, `http_reply` |
| tls | tcp | `tls_client_hello`, `tls_server_hello` |
| xmpp | tcp | `xmpp_stream`, `xmpp_starttls`, `xmpp_proceed`, `xmpp_features` |
| mtproto | tcp | `mtproto_initial` |
| bt | tcp | `bt_handshake` |
| quic | udp | `quic_initial` |
| wireguard | udp | `wireguard_initiation`, `_response`, `_cookie`, `_keepalive`, `_data` |
| dht | udp | `dht` |
| utp_bt | udp | `utp_bt_handshake` |
| discord | udp | `discord_ip_discovery` |
| stun | udp | `stun` |
| dns | udp | `dns_query`, `dns_response` |
| dtls | udp | `dtls_client_hello`, `dtls_server_hello` |
| icmp | * | `ipv4`, `ipv6`, `icmp` |

Спец-типы: `empty` (пустой), `unknown`. В фильтрах поддерживаются `all` и
`known` (не empty/unknown).

---

## 6. Маркеры позиции (для `pos=` в split/disorder/tcpseg)

- Абсолютный положительный — число с начала пейлоада: `100`.
- Абсолютный отрицательный — от конца: `-1` (последний байт), `-10`.
- Относительный — относительно логических позиций в известных пейлоадах:
  - `method` — начало HTTP-метода
  - `host`, `endhost` — начало/конец имени хоста
  - `sld`, `endsld`, `midsld` — second-level domain
  - `sniext` — поле данных SNI extension в TLS
  - `extlen` — поле длины TLS extensions
- Арифметика: `method+2`, `endhost-2`, `sniext+1`.
- Список через запятую: `1,midsld,endhost-2,-10`.

---

## 7. Передача параметров в Lua-инстансы и блобы

```
--lua-desync=fn[:arg[=value]:arg=value:…]
```

- Каждый `arg` — строка. Если `value` не задано — пустая строка.
- Подстановки C-кода в значениях:
  - `%var` → значение `desync.var` (или global `var`).
  - `#var` → длина `desync.var` или global `var`.
  - Эскейп: `\:` `\%` `\#`.

Блобы:
```
--blob=mytls:@/etc/myfake.bin            # из файла
--blob=mytls_ofs:+12@/etc/myfake.bin     # с offset
--blob=mytls_hex:0xDEADBEEF              # inline hex
```

Подставляются в аргументы:
```
--lua-desync=fake:blob=mytls
--lua-desync=tcpseg:seqovl=#mytls:seqovl_pattern=mytls
```

`#mytls` → длина, `%mytls` → содержимое (применяется в C-коде до Lua).

---

## 8. Библиотека стратегий `zapret-antidpi.lua`

Вызов: `--lua-desync=fnname:arg=val:…`. **Главный источник правды по
параметрам** — комментарии перед каждой функцией в lua-файле.

### 8.1 Базовые

| Функция | Поведение |
|---|---|
| `drop` | `VERDICT_DROP`. args: `dir` (in/out/any), `payload`. |
| `send` | Отправить текущий диссект (без дропа оригинала). args: `dir`, `fooling`, `ipid`, `ipfrag`, `reconstruct`, `rawsend`, `delay=ms`. |
| `pktmod` | Применить fooling/ipid к диссекту (без отсылки и вердикта). |
| `pass` | No-op (для оркестраторов). |
| `luaexec` | Выполнить Lua-выражение из `code=…` (доступ к `desync`). |

### 8.2 HTTP-дурение

| Функция | Поведение |
|---|---|
| `http_hostcase` | Менять регистр заголовка `Host:` (arg: `spell="host"`). |
| `http_domcase` | Менять регистр имени домена в `Host:`. |
| `http_methodeol` | `\r\n` перед методом (only nginx). |
| `http_unixeol` | `0D0A` → `0A`. |

### 8.3 Window size (legacy)

| Функция | Поведение |
|---|---|
| `wsize` | Менять `tcp.th_win` и scale в SYN/ACK (только уменьшение). args: `wsize`, `scale`. |
| `wssize` | То же по всем пакетам потока до cutoff. args: `dir`, `wsize`, `scale`, `forced_cutoff=<payloads>`. **Снижает скорость.** Стратегия нулевой фазы (с хостлистами — только при `--ipcache-hostname`). |

### 8.4 Фейки

| Функция | Поведение |
|---|---|
| `fake` | Прямой фейк (отдельный пакет). args: `dir`, `payload` (default `known`), `fooling`, `ipid`, `ipfrag`, `reconstruct`, `rawsend`, **`blob=<name>`**, `optional`, `tls_mod=<mods>`. Сегментация автоматическая (для blob > MSS). |
| `syndata` | Добавить пейлоад в SYN. arg: `blob` (must fit MTU), `tls_mod`. После не-SYN пакета — instance_cutoff. **Стратегия нулевой фазы.** |
| `rst` | Отослать пустой RST (или RST+ACK при `rstack`). args: `dir`, `payload`, `fooling`, `ipid`, `ipfrag`, `reconstruct`, `rawsend`. |
| `tls_client_hello_clone` | Подготовить blob с модифицированным TLS ClientHello. args: `blob`, `fallback`, `sni_del_ext`, `sni_del`, `sni_snt`, `sni_snt_new`, `sni_first`, `sni_last`. |

### 8.5 TCP-сегментация

| Функция | Поведение |
|---|---|
| `multisplit` | Нарезать пейлоад по списку маркеров. args: `pos=m1,m2,…` (default `2`), `seqovl=<int>`, `seqovl_pattern=<blob>`, `blob=<replace_payload>`, `optional`, `nodrop`. Поддерживает reasm. |
| `multidisorder` | То же, но в обратном порядке отправки. `seqovl` может быть маркером. **Не работает с Windows-серверами.** Подходит для `tls_client_hello` с kyber и без. |
| `multidisorder_legacy` | Поведение из nfqws1 — для backward-compat (использует `blockcheck2.d/standard`). |
| `fakedsplit` | Split с замешиванием фейков. args: `pos`, `seqovl`, `seqovl_pattern`, `blob`, `optional`, `nodrop`, `nofake1..nofake4`, `pattern=<blob>`. **Требует fooling.** |
| `fakeddisorder` | Disorder с замешиванием фейков. Аналогично. |
| `hostfakesplit` | Спец-резатель для `http_req`/`tls_client_hello` вокруг имени хоста. args: `host=<random.template>`, `midhost=<marker>`, `disorder_after=<marker>`, `nofake`, `nofake2`, `blob`, `optional`, `nodrop`. |
| `tcpseg` | Отослать произвольную часть пейлоада/reasm/blob, ограниченную двумя маркерами. args: `pos=m1,m2`, `seqovl`, `seqovl_pattern`, `blob`, `optional`. Вердикт не выносит. Удобно с `drop:payload=known` для замещения. |
| `oob` | Вставить 1 OOB-байт в TCP handshake. args: `char` или `byte`, `urp=b\|e`. Требует разрешения первых входящих (`--in-range=-s1`). Не сочетается с multi-split/disorder. |

### 8.6 UDP

| Функция | Поведение |
|---|---|
| `udplen` | Раздуть/обрезать UDP-payload. args: `dir`, `payload`, `min`, `max`, `increment`, `pattern`, `pattern_offset`. |
| `dht_dn` | Заменить `d1`/`d2` в DHT на `dN`. arg: `dn`. |

### 8.7 Прочее (требует POSTNAT)

| Функция | Поведение |
|---|---|
| `synack` | Отослать SYN/ACK до SYN (TCB turnaround). **Ломает NAT, требует nftables-POSTNAT.** |
| `synack_split` | Вариация. |

### 8.8 Стандартные блоки опций (передаются как ключи `--lua-desync=fn:opt=val`)

**`fooling`:** `ip_ttl=N`, `ip6_ttl=N`, `ip_autottl=<delta>,<min>-<max>`,
`ip6_autottl=…`, `ip6_hopbyhop[=hex]`, `ip6_hopbyhop2`, `ip6_destopt`,
`ip6_destopt2`, `ip6_routing`, `ip6_ah`, `tcp_seq=<±int>`, `tcp_ack=<±int>`,
`tcp_ts=<±int>`, `tcp_md5[=16byte_hex]`, `tcp_flags_set=FIN,SYN,…`,
`tcp_flags_unset=ack`, `tcp_ts_up`, `tcp_nop_del`, `fool=<custom_lua_fn>`,
`badsum`, `badseq`.

**`ipid`:** `ip_id=seq|rnd|zero|none` (default `seq` для send-функций, `none`
для send), `ip_id_conn=1`.

**`ipfrag`:** `ipfrag` (без значения = вкл. ipfrag2 default), `ipfrag_disorder`,
`ipfrag_pos_udp=<mul8>` (default 8), `ipfrag_pos_tcp=<mul8>` (default 32),
`ipfrag_next=<proto>`.

**`reconstruct`:** `keepsum`, `badsum`, `ip6_preserve_next`, `ip6_last_proto`.

**`rawsend`:** `repeats=N`, `fwmark=<int>`, `ifout=<name>`.

**`tls_mod`:** `rnd`, `dupsid`, `rndsni`, `sni=<domain>`, `padencap`. Список:
`tls_mod=rnd,rndsni,dupsid`.

---

## 9. Оркестраторы (`zapret-auto.lua`) и наш bundle

### 9.1 Из `zapret-auto.lua`

- **`circular`** — крутит стратегии по кругу при неудачах. Аргументы:
  - `fails`, `retrans`, `maxseq` и др. (см. `automate_failure_check`).
  - Все последующие инстансы помечают `strategy=N` (с 1 непрерывно). `final` —
    финальная стратегия.
  - Требует входящих пакетов: `--in-range=-s5556` или больше (детектор успеха
    срабатывает на `s4096`).
- **`repeater`** — повторяет N последующих инстансов R раз. args:
  `instances=N`, `repeats=R`, `stop`, `clear`, `iff=<name>`, `neg`.
- **`condition`** — выполняет следующие инстансы только если `iff xor neg`.
  args: `iff`, `neg`, `instances=N`.
- **`per_instance_condition`** — каждый из следующих инстансов несёт `cond=…`,
  `cond_neg`.
- **`stopif`** — очистить план при условии.
- **iff-функции:** `cond_true`, `cond_false`, `cond_random:percent=N`,
  `cond_payload_str:pattern=str`, `cond_tcp_has_ts`, `cond_lua:cond_code=…`.

### 9.2 Наш bundle для `circular` (companion'ы)

`circular_with_preload` и `circular` принимают аргументы `detector=`,
`success=`, `hostkey=`, `preload=`. Имена резолвятся в функции из:

| Файл | Что даёт |
|---|---|
| `combined-detector.lua` | Композитные детекторы успеха/провала (TCP+TLS+timing). |
| `silent-drop-detector.lua` | Детект «соединение установилось, но молчит». |
| `domain-grouping.lua` | `hostkey=` — группировка хостов в один stateful-ключ. |
| `strategy-stats.lua` | Метрики (для дебага). |
| `strategy-lock-manager.lua` | Защёлка стратегии после успеха (антифлап). |

Эти файлы — **НЕ desync-действия**. Они грузятся bundle'ом
(`_ORCHESTRATOR_LUA_FILES`, `_ORCHESTRATOR_TRIGGERS` в `nfqws_manager.py:108`),
когда стратегия использует `--lua-desync=circular[…]` или
`circular_with_preload`. Порядок между companion'ами не важен (только
определения + идемпотентная инициализация таблиц, без `require()`). На
обычные circular-стратегии без ссылок на эти функции лишние определения не
влияют.

Пример:
```
--filter-tcp=80,443 --filter-l7=http,tls --out-range=-s34228 --in-range=-s5556
--lua-desync=circular
--in-range=x --payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:badsum:strategy=1
--lua-desync=multidisorder:strategy=2
--payload=http_req
--lua-desync=fake:blob=fake_default_http:badsum:strategy=1
--lua-desync=multisplit:strategy=2
```

---

## 10. Firewall: NFQUEUE-перехват

В проекте — `core/firewall.FirewallManager`. Автоопределяет тип:
- На Keenetic / Entware / старом OpenWrt — **iptables** (по умолчанию).
- На OpenWrt 22+ — **nftables**.
- Если есть оба — предпочитает **iptables** (совместимость с Entware).

### 10.1 Sysctl, обязательные на роутере

`FirewallManager._apply_sysctls` ставит:
- `net.netfilter.nf_conntrack_tcp_be_liberal=1` — НЕ дропать пакеты вне TCP
  window (десинк намеренно их шлёт).
- `net.netfilter.nf_conntrack_checksum=0` — не считать checksum дважды.

Без них iptables/conntrack дропает out-of-window сегменты десинка → тихий 0%.

Hardware offload **обязательно выключен** на роутере (`fw3` / netifd). Иначе
iptables не видит трафик. Это поведенческий эталон nfqws2-keenetic, не «наша
выдумка».

### 10.2 Ключевые правила построения

1. **fwmark anti-loop**: пакеты, сгенерированные nfqws2, помечены
   `nfqws.desync_mark` (default `0x40000000`). Все NFQUEUE-захваты должны
   исключать пакеты с этой меткой (`mark & 0x40000000 == 0`). Иначе бесконечная
   рекурсия / залипание.
2. **conntrack ограничитель**: первые N пакетов через `--connbytes 1:N
   --connbytes-mode=packets` (iptables) или `ct original packets 1-N` (nft) —
   экономия CPU. Параметры читаются из секции `nfqws.*`, дефолты захардкожены
   в `firewall.py`:
   - TCP: `nfqws.tcp_pkt_out` (20) / `nfqws.tcp_pkt_in` (10).
   - UDP: `nfqws.udp_pkt_out` (5) / `nfqws.udp_pkt_in` (3).
3. **Перехват SYN+ACK, FIN, RST** на входе нужен для корректной работы
   conntrack и autohostlist (детект RST-блока).
4. **notrack для пакетов с DESYNC_MARK** в output/predefrag — чтобы NAT не
   ломал нестандартные пакеты (только nftables-POSTNAT).
5. **Не указывать в фильтрах** исключающий ipset (`nozapret`/`nozapret6`) —
   это делает основной код, и проверку `DESYNC_FWMARK`.
6. **iptables PRENAT vs nftables POSTNAT**: iptables НЕ умеет POSTNAT-перехват
   для проходящего трафика, поэтому **некоторые техники (`synack`,
   манипуляции с IP/портами) не работают** на iptables в forwarded-сценарии.
   На современном Linux/OpenWrt — выбирай **nftables**. На Keenetic — iptables
   с поправкой ниже.

### 10.3 Keenetic UDP fix (специально для нашего пути)

Из-за проприетарного `ndmmark` родная NAT-логика Keenetic не masquerade'ит
UDP-пакеты от nfqws → они уходят с LAN-IP и дропаются провайдером. Без этого
UDP-стратегии (QUIC, DTLS, WireGuard) рассыпаются.

Решение — правило (выставляется при `firewall.apply()`):
```
iptables -t nat -A POSTROUTING -o $wanif -p udp \
  -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j MASQUERADE
```

В апстриме это `init.d/custom.d.examples.linux/10-keenetic-udp-fix`. У нас
повторный MASQUERADE для UDP-пакетов с DESYNC_MARK добавляется в `firewall.py`
на **iptables-пути** (`do_nat = (ipt_cmd == "iptables")`, только IPv4) — как
паритет с nfqws2-keenetic, а не по отдельному детекту Keenetic. На
nftables-пути есть свой `nat postrouting … masquerade` для переписанных
nfqws2-пакетов.

### 10.4 Порты по умолчанию

`config_manager.DEFAULT_CONFIG` (намеренно шире эталона keenetic, который
ограничивается 443/QUIC):
- `nfqws.ports_tcp = "80,443,2053,2083,2087,2096,5222,8443"` — HTTP/HTTPS +
  alt-порты Cloudflare + Telegram MTProto 5222.
- `nfqws.ports_udp = "443,3478:3481,5349,19294:19344,49152:65535"` — QUIC +
  STUN/TURN + WireGuard-диапазоны + Discord voice.

Должны согласовываться с `--filter-tcp=` / `--filter-udp=` в стратегии. Если
стратегия `--filter-tcp=443`, а в `nfqws.ports_tcp` нет 443 — в очередь не
придёт ничего.

### 10.5 Сигналы nfqws2

- `SIGHUP` — принудительно перечитать хостлисты и ipset-ы. У нас:
  `kill -HUP $(cat /var/run/zapret-nfqws.pid)` — после правки `lists/`.
- `SIGUSR1` — дамп пула conntrack.
- `SIGUSR2` — дамп autohostlist-счётчиков и ipcache.

---

## 11. Layout проекта (где что лежит)

Наш проект следует раскладке **bol-van/zapret2** (`ZAPRET_BASE = /opt/zapret2`).
Имена файлов/каталогов — как в апстриме. Дефолты — `config_manager.DEFAULT_CONFIG`.

### 11.1 Ассеты движка zapret2 (`/opt/zapret2/`)

| Путь | Конфиг | Назначение |
|---|---|---|
| `nfq2/nfqws2` | `zapret.nfqws_binary` | Бинарник nfqws2 (статический). |
| `lua/*.lua` | `zapret.lua_path` | `zapret-lib.lua`, `zapret-antidpi.lua`, … + наши `import/lua/*.lua`, развёрнутые `core/asset_importer.py` (`import_all` / `_sync_dir`). `core/lua_manager.py` управляет ими в рантайме (list/get/save/reset_to_bundled), bundled-исходники — `import/lua/`. |
| `lists/` | `zapret.lists_path` | Hostlist'ы (`*.txt`). |
| `ipset/` | `zapret.ipset_path` | IP-списки + ipban + auto-листы. |
| `files/fake/*.bin` | `zapret.bin_path` | Blob-файлы для `--blob=NAME:@…`. |
| `blockcheck2.sh` / `blockcheck.sh` | `zapret.blockcheck2_path` (иначе автопоиск в `base_path`) | Штатный blockcheck. |

⚠️ **Миграция:** до 0.16.3 дефолт `bin_path = /opt/zapret2/bin` был неверным
(апстрим — `files/fake`), и не было `ipset_path`. `config_manager` лечит
старые конфиги автоматически.

### 11.2 Состояние GUI (`/opt/etc/zapret-gui/`)

- `settings.json` — конфигурация (`core/config_manager.DEFAULT_CONFIG_DIR`);
  секции `zapret.*`, `nfqws.*`, `firewall.*`, `scan.*` и т.д.;
- Runtime firewall-конфиг и хуки персистентности
  (`core/firewall_persistence.GUI_RUNTIME_DIR`);
- State-файлы установщиков (singbox/mihomo и пр.).

### 11.3 Автозапуск (`/opt/etc/init.d/`, Entware)

- **`S99zapret`** — автозапуск nfqws2 с применённой стратегией + firewall.
  Генерируется `core/autostart_manager.py` (`INIT_DIR` / `SCRIPT_NAME`,
  шаблон `_S99ZAPRET_TEMPLATE`). PID-файл — `/var/run/zapret-nfqws.pid`.
- **`S99zapret-gui`** — сам сервис Web-GUI (создаётся `install.sh`).

⚠️ Путей вида `/opt/etc/nfqws2/nfqws2.conf` или `/opt/etc/init.d/S51nfqws2`
у нас **НЕТ** — это раскладка стороннего упаковщика **nfqws2-keenetic**, не
bol-van/zapret2. Из nfqws2-keenetic берём только **идеи поведения** (НЕ
пути): режимы выбора доменов **list** / **auto** (домен добавляется после 3
фейлов за 60с) / **all**, отключение hardware offload, рекомендация DoT/DoH.

### 11.4 Каталоги стратегий (`catalogs/`)

| Каталог | Тип содержимого |
|---|---|
| `builtin/winws2_presets.txt`, `zapret_gui_defaults.txt` | **Полные пресеты** — содержат свои `--filter-*`/`--hostlist=`/`--blob=`/`--new`. Берутся как есть, только резолвятся пути. |
| `basic/`, `advanced/`, `direct/` | **«Приёмы» (tricks)** — один-два `--lua-desync=`. Сканер сам оборачивает в шаблон цели (добавляет `--filter-*`, `--filter-l7`, `--payload`, `--hostlist=<tmp с доменами цели>`). См. `StrategyScanner._wrap_trick_args`. |

Эвристика «полный пресет vs приём» — `_is_full_preset_args()` в
`strategy_scanner.py`: наличие `--filter-*`/`--new`/`--hostlist`/`--ipset`/
`--blob` ⇒ полный пресет.

---

## 12. Сборка argv: `NFQWSManager.compose_command()`

Единый источник argv (и для live-запуска, и для автозапуска):

```
[binary]
  + base       (--user / --fwmark / --qnum [/--debug] [/--bind-fix4/6])
  + lua-init   (core + extension + orchestrator bundle, dedup)
  + unified    (--hostlist подмешан из активных профилей)
  + strategy_args
```

- `_build_base_args` (`nfqws_manager.py:~512`) — `--user`, `--fwmark`,
  `--qnum` из конфига; `--debug` при `nfqws.debug=true`; `--bind-fix4/6` при
  нескольких WAN.
- `_build_lua_init_args` (`:556`) — добавляет core-lua **только если** в
  стратегии есть `--lua-desync` **И файл существует** на `lua_path`.
  Extension-lua — по используемым функциям из `_EXTENSION_LUA_FILES`.
  Orchestrator-bundle — если функция входит в `_ORCHESTRATOR_TRIGGERS`.
  Дедуп `--lua-init`.
- `queue_num` — из `nfqws.queue_num` (дефолт **300**); то же значение
  использует `firewall.py` для `queue num`. **Не разводить эти числа.**
- **Превью команды** (`build_preview_command`, `POST /api/strategies/preview`)
  собирается ЧЕРЕЗ тот же `compose_command` — превью = реальная команда.
  Поэтому если в превью видны `--lua-init …/combined-detector.lua` и т.п. —
  это **корректно** для circular-стратегий, не «мусор».
- Блобы по имени дозаявляются автоматически — `core/blob_registry.py`
  (`build_blob_declarations`), маппинг имя → `@bin/*.bin`.

### 12.1 dry-run валидация (без поднятия NFQUEUE)

- `NFQWSManager.dry_run(strategy_args)` собирает argv тем же
  `compose_command`, **убирает `--user=`** (чтобы не было setuid вне рантайма),
  добавляет `--dry-run`, запускает и проверяет `returncode==0`.
- Ловит: вызовы несуществующих lua-функций (через сам факт парсинга), битые
  `--blob`/`--lua-init`, плохой синтаксис `--lua-desync`. **Lua-синтаксис не
  проверяется** — только наличие файлов и парсинг CLI.
- API:
  - `POST /api/strategies/<sid>/validate` → `{ok, returncode, output, command}`.
  - `POST /api/strategies/preview` с `{"validate": true}` → поле
    `validation: {ok, available, returncode, output, command}`.
    `available=false` — бинарника нет (dev-машина без zapret2).

---

## 13. Сканер стратегий: `strategy_scanner.py`

### 13.1 Обёртка приёмов (`_wrap_trick_args`)

Стратегия из `basic/`/`advanced/`/`direct/` — это «приём» (1-2
`--lua-desync=`). Сканер оборачивает её в полный профиль:

1. Берёт `target` (домен/порт/L7/payload из `scan_targets.py`).
2. Достаёт hostlist цели → tmp-файл → `--hostlist=<tmp>`.
3. Добавляет `--filter-tcp/--filter-udp`, `--filter-l7`, `--payload` под цель.
4. Дозаявляет блобы (`blob_registry.build_blob_declarations`).
5. Передаёт в `compose_command`.

Полный пресет (из `builtin/`) — НЕ оборачивается, идёт как есть.

### 13.2 Baseline-aware: «сайт открыт без обхода → всегда 0%»

В `strategy_scanner.py:~1220` — `baseline_open_all`. Если до запуска
стратегии цель открывается успешно **по всем AF** (`_baseline_by_af`), то
любая стратегия получает принудительное `success=False` с ошибкой
**`BASELINE_OPEN`**. Логика: стратегия не может «починить» то, что не сломано.

**Следствие:** подбор надо запускать на **заблокированном** ресурсе. На
заведомо доступном — 0% это **не баг**, это охрана от ложных «успехов».

### 13.3 Body-проба (≥ 64 KB)

`BODY_PROBE_MIN_BYTES = 65_536` (`strategy_scanner.py:61`). DPI часто пускает
первые 16-20 KB ответа и потом рвёт соединение — body-проба ловит это.
TLS-only без body считается псевдо-успехом (отсев «формально открылось»).

Аналог в `blockcheck2.sh` — env `CURL_HTTPS_GET=1` (GUI-галка «Качать полное
тело»): HTTPS-проба делает GET всего тела вместо HEAD (`-I`).

### 13.4 Предварительная проверка предпосылок

`StrategyScanner._check_prerequisites()` (`:550`) вызывает
`core.diagnostics.check_strategy_prerequisites()` на старте сканирования и
громко логирует блокеры. **Первое, что смотреть при «0% на всём».**

API: `GET /api/diagnostics/prerequisites`. Проверяет:
- наличие бинарника `nfqws2`;
- обязательные lua (`zapret-lib.lua`, `zapret-antidpi.lua`);
- наличие blob-файлов в `bin_path`;
- каталоги списков;
- доступность NFQUEUE-модуля;
- `nf_conntrack_tcp_be_liberal = 1`.

Возвращает `issues` со `severity=error|warning` и `hint`.

### 13.5 Дедуп

`strategy_generator._norm_args()` (`:262`) — нормализованный ключ для дедупа.
Используется и при генерации стратегий «на лету», и в сканере. Не
дублировать стратегии с одинаковыми нормализованными args.

---

## 14. Blockcheck2-интеграция

`core/blockcheck2.Blockcheck2Runner`, API
`/api/blockcheck2/{script,start,status,output,stop}`. Запускает **оригинальный**
`blockcheck2.sh` (или `blockcheck.sh`) из репозитория zapret2 как подпроцесс
неинтерактивно (`BATCH=1`), стримит вывод в лог-буфер (`source=blockcheck2`) и
в кольцевой буфер для инкрементального polling (`output?offset=N`).

Путь — `zapret.blockcheck2_path` или автопоиск в `base_path`. Это **НЕ путать**
с `core/blockcheck.py` — наша Python-реализация проб для GUI-тестера.

### 14.1 Ключевые env (из шапки `blockcheck2.sh`)

```
DOMAINS=bbc.com           # домены через пробел, поддерживается "rutracker.org/forum"
TEST=standard|custom|<dir># имя теста (subdir в blockcheck2.d)
IPVS=4|6|46               # версии IP
ENABLE_HTTP=1, ENABLE_HTTPS_TLS12=1, ENABLE_HTTPS_TLS13=1, ENABLE_HTTP3=1
REPEATS=N                 # попыток на стратегию
PARALLEL=0|1              # внимание: rate-limit
SCANLEVEL=quick|standard|force
BATCH=1                   # без интерактива
HTTP_PORT, HTTPS_PORT, QUIC_PORT
SKIP_DNSCHECK=1, SKIP_IPBLOCK=1, SKIP_PKTWS=1
CURL=<path>               # заменить системный curl (для kyber/quic)
CURL_MAX_TIME[_QUIC|_DOH]
CURL_CMD=1                # печатать команды curl
CURL_HTTPS_GET=1          # GET вместо HEAD — для теста ~16K-блока
PKTWS_EXTRA_PRE[_N], PKTWS_EXTRA_POST[_N]  # доп.параметры nfqws/winws
SECURE_DNS=0|1, DOH_SERVER, DOH_SERVERS
DNSCHECK_DNS, DNSCHECK_DOM, UNBLOCKED_DOM
MIN_TTL, MAX_TTL
SIMULATE=1, SIM_SUCCESS_RATE=N    # debug сам blockcheck2
```

### 14.2 Примороженные итоги (`highlights`)

`_HIGHLIGHT_RE` в `blockcheck2.py` ловит **ТОЛЬКО** найденные рабочие
стратегии (`working strategy found …`) и заголовки `* SUMMARY` / `* COMMON`, с
дедупом и чисткой `!!!!!`.

**НЕ примораживать** `AVAILABLE`/`UNAVAILABLE` (вдобавок `AVAILABLE` —
подстрока `UNAVAILABLE`, на этом горел старый фильтр).

**Структурные находки (`found`) → бейджи в GUI.** Помимо `highlights`,
`blockcheck2.py` парсит строки `working strategy found` в структуру
(`parse_found_strategy`/`_classify_test`): `{ipv, test, domain, engine,
strategy, proto, port, l7, payload, label}` и отдаёт её в `get_status()`
полем `found`. Тип теста (`curl_test_http`/`https_tls12`/`tls13`/`http3`) →
proto/port/l7/payload как в `scan_targets`. Фронтенд (`blockcheck2.js`)
рисует кликабельные бейджи; клик открывает редактор создания стратегии,
предзаполненный фильтром из типа теста + **дословным** `--lua-desync`
(реконструкция по той же конвенции, что `_wrap_trick_args`, см. §13.1). Сторож —
`tests/test_blockcheck2_found.py`.

Документация GUI-помощи — `web/js/components/help.js`, топик `blockcheck2`.

### 14.3 Тест `custom`

Простой пробивщик по спискам стратегий из:
- `blockcheck2.d/custom/list_http.txt`
- `blockcheck2.d/custom/list_https_tls12.txt`
- `blockcheck2.d/custom/list_https_tls13.txt`
- `blockcheck2.d/custom/list_quic.sh`

Каждая стратегия — одна строка, поддержаны `#` комментарии. Параметры
интерпретируются shell — нужно экранирование `<`, `>`, `(`, `)`, кавычек.

**Важно:** blockcheck2 проверяет один домен/URI/протокол. Браузер делает
гораздо больше (DNS, ipv4/6, TLS1.2/1.3, QUIC, kyber, ECH, fingerprint).
Поэтому `Summary OK ≠ автоматически рабочий сайт`.

---

## 15. Типовые шаблоны стратегий

Каждый профиль строится по схеме: **фильтр профиля** → **внутрипрофильные
фильтры (range/payload)** → **последовательность инстансов**.

### 15.1 HTTP-only (порт 80)

```
--filter-tcp=80 --filter-l7=http
  --out-range=-d10 --payload=http_req
    --lua-desync=fake:blob=fake_default_http:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5
    --lua-desync=fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5
```

### 15.2 TLS 1.2/1.3 (порт 443) — фейк + multidisorder

```
--filter-tcp=443 --filter-l7=tls --hostlist=youtube.txt
  --out-range=-d10 --payload=tls_client_hello
    --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com
    --lua-desync=multidisorder:pos=1,midsld
```

### 15.3 TLS с seqovl (скрытый фейк, без фулинга)

```
--payload=tls_client_hello
  --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000
```

### 15.4 QUIC (UDP 443)

```
--blob=quic_google:@/opt/zapret2/files/fake/quic_initial_www_google_com.bin
--filter-udp=443 --filter-l7=quic --hostlist=youtube.txt
  --payload=quic_initial
    --lua-desync=fake:blob=quic_google:repeats=11
```

### 15.5 WireGuard / STUN / Discord (UDP)

```
--filter-l7=wireguard,stun,discord
  --payload=wireguard_initiation,wireguard_cookie,stun,discord_ip_discovery
    --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2
```

### 15.6 Циклическая смена стратегий с детектором неудач

```
--filter-tcp=80,443 --filter-l7=http,tls
  --out-range=-s34228 --in-range=-s5556
  --lua-desync=circular
  --in-range=x
  --payload=tls_client_hello
    --lua-desync=fake:blob=fake_default_tls:badsum:strategy=1
    --lua-desync=multidisorder:strategy=2
  --payload=http_req
    --lua-desync=fake:blob=fake_default_http:badsum:strategy=1
    --lua-desync=multisplit:strategy=2
```

### 15.7 Кастомный фейк случайного размера

```
--lua-desync=luaexec:code='desync.rnd=brandom_az(math.random(5,10))'
--lua-desync=tcpseg:pos=0,-1:seqovl=#rnd:seqovl_pattern=rnd
--lua-desync=drop:payload=known
```

---

## 16. Чеклист «не находит ни одной рабочей стратегии»

Проверять В ЭТОМ ПОРЯДКЕ:

1. **Сайт доступен без обхода → всегда 0% (это НЕ баг).** См. §13.2
   (`baseline_open_all` / `BASELINE_OPEN`). **Подбор — на заблокированном
   ресурсе.**
2. **Нет lua-скриптов на `lua_path`** (`/opt/zapret2/lua`). `_build_lua_init_args`
   не добавит то, чего нет, → `--lua-desync=fake/multisplit` = вызов
   несуществующей функции. Проверка: `ls /opt/zapret2/lua/` →
   `zapret-lib.lua`, `zapret-antidpi.lua`. На dev-машине без zapret2 —
   тотальный 0%.
3. **Нет blob-файлов** в `bin_path` (`/opt/zapret2/files/fake/*.bin`) — fake
   уходит пустым. В логе `blobs`: «blob '…' не найден в реестре».
4. **`--qnum` ≠ firewall `queue num`** — трафик в очередь, которую не
   слушают. Оба берутся из `nfqws.queue_num`, но если правила накатаны
   вручную / из другого источника — расходятся.
5. **Hostlist не матчит SNI цели.** Приёмы оборачиваются tmp-hostlist'ом с
   доменами цели; если домен не совпал с реальным SNI — десинк не применился.
   Лечится «выключить hostlist для теста» (`MODE_FILTER=none`).
6. **Hardware offload включён** / **conntrack не настроен.** iptables не
   видит трафик, либо ядро дропает out-of-window сегменты десинка. Наш
   firewall ставит `nf_conntrack_tcp_be_liberal=1` и `nf_conntrack_checksum=0`
   — проверить, что применилось (`sysctl -a | grep be_liberal`) **на роутере,
   не в контейнере**.
7. **Body-проба требует ≥ 64 KB** (`BODY_PROBE_MIN_BYTES`). TLS-only без
   body — считается псевдо-успехом.
8. **NAT ломает технику** (`synack`, TCB-turnaround): нужно nftables-POSTNAT.
   На iptables — не работает.
9. **Keenetic-UDP не уходит**: см. §10.3 (MASQUERADE с проверкой mark).
10. **`--user nobody` падает на Entware**: указать пользователя из
    `/etc/passwd` (он там обычно есть).
11. **Стратегия работает один раз, потом перестаёт**: DPI «наказывает» —
    рассмотри `circular` (§9) или включи `--ipcache-hostname` если работаешь
    нулевой фазой.
12. **`multidisorder` не работает на Windows-сервере**: Windows не
    переписывает буфер сокета по seqovl. Используй `multisplit`.
13. **`wssize` режет скорость**: применяй только в крайних случаях,
    дублируй в отдельный профиль до получения hostname.
14. **autohostlist не наполняется**: нужно перехватывать достаточно
    входящих пакетов для детектора (`--in-range` пошире) и/или достаточно
    исходящих ретрансмиссий.
15. **VM не работает**: гипервизорный NAT (VMware, VirtualBox) ломает
    большинство техник; используй bridge.
16. **Профиль не выбирается до hostname**: если в нём есть `--hostlist=` без
    autolist — это норма. Дублируй стратегию в профиль без хостлиста, если
    нужно действовать с первого пакета.

---

## 17. Отладка

Главный диагностический приём — поднять пер-пакетный лог nfqws2:

- Конфиг: `nfqws.debug = true` → `nfqws_manager` добавляет `--debug` в argv,
  stderr nfqws2 логируется на уровне INFO, чтобы быть видимым.
- В логе смотреть: грузятся ли lua-скрипты, объявлены ли блобы, **матчится
  ли пакет цели по filter/hostlist**, какие desync реально применяются.

Ручной прогон (эталон из zapret2, для сверки на роутере):

```
nfqws2 --qnum 300 --debug \
  --lua-init=@/opt/zapret2/lua/zapret-lib.lua \
  --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua \
  --filter-tcp=80,443 --filter-l7=tls,http \
  --payload=tls_client_hello \
    --lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid \
  --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5 \
  --payload=tls_client_hello,http_req \
    --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000
```

Запускать с **уже накатанными firewall-правилами** на тот же `--qnum`, иначе
в очередь ничего не придёт и debug будет пустым.

Lua-отладчики (из `zapret-lib.lua`): `pktdebug`, `argdebug`, `posdebug`,
`var_debug(t)` — рекурсивная печать `desync`-таблицы.

---

## 18. Правила при написании / правке стратегий

- **НЕ** использовать синтаксис nfqws1 (`--dpi-desync=`, `--dpi-desync-split-pos=`)
  — другой движок. Только `--lua-desync=`.
- **Blob-декларации** (`--blob=`) — один раз в начало, до первого `--new`.
- **`zapret-lib.lua` первым** среди `--lua-init`.
- **Не дублировать `--qnum`**; синхронизировать с firewall.
- Для мультипрофиля — `--new` между профилями; фильтры/payload — внутри своего
  профиля.
- При генерации стратегий «на лету» (`strategy_generator`) — дедуп по
  нормализованным args (`_norm_args`).
- Тестировать **всегда на заблокированном ресурсе** — иначе baseline-aware
  даст 0%.
- Перед сохранением — `dry-run` через API (`POST /api/strategies/<sid>/validate`).
- Кастомные `.lua` / `.bin` / `.conf` — **не** в `/opt/zapret2` (снесёт
  инсталлятор при обновлении), а в отдельный каталог (например
  `/opt/etc/zapret-gui/custom/`) и подключай полными путями.

---

## 19. Lua-программирование (для расширений)

### 19.1 Где исполняется Lua

1. `--lua-init` — при старте, один раз. Можно строкой или `@file`. Поддержан `.gz`.
2. `--lua-desync` — на каждый пакет, проходящий профиль (после фильтров C-кода).
3. Таймеры (`timer_set`).

### 19.2 Прототип desync-функции

```lua
function fnname(ctx, desync)
  -- ctx — для вызова C-функций (rawsend, instance_cutoff, ...)
  -- desync — таблица с:
  --   desync.dis        — диссект (.ip / .ip6 / .tcp / .udp / .icmp / .payload / .l4proto / ...)
  --   desync.arg        — аргументы инстанса (после подстановок %, #)
  --   desync.outgoing   — направление
  --   desync.l7payload  — payload type
  --   desync.l7proto    — protocol type
  --   desync.track      — conntrack (может отсутствовать!)
  --   desync.track.lua_state — для хранения состояния на поток
  --   desync.reasm_data — собранный многопакетный пейлоад
  --   desync.replay, desync.replay_piece, ...
  --   desync.tcp_mss    — есть всегда для TCP
  return VERDICT_PASS  -- или VERDICT_MODIFY / VERDICT_DROP (+ VERDICT_PRESERVE_NEXT)
end
```

### 19.3 Полезные C-функции (из Lua)

- Лог: `DLOG(s)`, `DLOG_ERR(s)`, `DLOG_CONDUP(s)`.
- IP: `ntop(raw)`, `pton(str)`.
- Битовые: `bitand`, `bitor`, `bitxor`, `bitnot`, `bitlshift`, `bitrshift`,
  `bitget`, `bitset`.
- Беззнаковые числа: `u8/u16/u24/u32`, `bu8/bu16/…`, `swap16/swap32/…`,
  `u32add`, …
- Случайные: `brandom(n)`, `bcryptorandom(n)`, `brandom_az(n)`.
- Парсинг: `parse_hex(s)`.
- Крипта: `aes`, `aes_gcm`, `aes_ctr`, `hkdf`, `hash`.
- Сжатие: `gzip(b)`, `gunzip(b)`.
- Системные: `uname()`, `clock_gettime()`, `getpid()`, `stat(path)`, `time()`.
- Диссекция: `dissect(raw)`, `reconstruct_dissect(dis, opts)`,
  `reconstruct_tcphdr` / `…iphdr` / `…ip6hdr`, `csum_*_fix`.
- conntrack: `conntrack_feed(dis_or_raw, opts)`.
- IP/iface: `get_source_ip(target)`, `get_ifaddrs()`.
- Отсылка: `rawsend(raw, opts)`, `rawsend_dissect(dis, opts, recopts)`.
- Управление: `instance_cutoff(ctx[, outgoing])`,
  `lua_cutoff(ctx[, outgoing])`, `execution_plan(ctx)`,
  `execution_plan_cancel(ctx)`.
- Таймеры: `timer_set(name, ms, fn, data)`, `timer_del(name)`,
  `timer_info(name)`, `timer_enum()`.
- Пейлоады: `resolve_pos(blob, payload_type, marker)`, `resolve_multi_pos`,
  `resolve_range`, `tls_mod(blob, modlist, payload)`.
- Файлы: `--writeable` создаст каталог, путь в `os.getenv("WRITEABLE")`.

**Песочница:** `os.execute`, `io.popen`, `package.loadlib`, модуль `debug` —
удалены.

### 19.4 Минимальный пример

```lua
function my_repeated_fake(ctx, desync)
  if not desync.dis.tcp then
    instance_cutoff_shim(ctx, desync)  -- хелпер из zapret-lib
    return
  end
  local rep = tonumber(desync.arg.repeats or "3")
  local dis = deepcopy(desync.dis)
  dis.payload = blob(desync, desync.arg.blob)
  apply_fooling(desync, dis)
  for i = 1, rep do
    rawsend_dissect_segmented(desync, dis, desync.tcp_mss, desync.arg)
  end
  -- VERDICT_PASS — оригинал пройдёт следом
end
```

Подключение:
```
--lua-init=@/opt/zapret2/lua/zapret-lib.lua
--lua-init=@/opt/etc/zapret-gui/custom/my-strategy.lua
--lua-desync=my_repeated_fake:blob=fake_default_tls:repeats=5:ip_autottl=-1,3-20
```

---

## 20. Шпаргалка по командам

| Действие | Команда |
|---|---|
| Версия nfqws2 | `/opt/zapret2/nfq2/nfqws2 --version` |
| Валидация опций | `nfqws2 --dry-run <opts>` |
| Старт GUI (Entware) | `/opt/etc/init.d/S99zapret-gui start` |
| Старт автозапуска | `/opt/etc/init.d/S99zapret start` |
| Стоп/рестарт | `… stop` / `… restart` |
| Перечитать листы (без рестарта) | `kill -HUP $(cat /var/run/zapret-nfqws.pid)` |
| Дамп conntrack | `kill -USR1 $(cat /var/run/zapret-nfqws.pid)` |
| Дамп autohostlist + ipcache | `kill -USR2 $(cat /var/run/zapret-nfqws.pid)` |
| Запуск blockcheck (через API) | `POST /api/blockcheck2/start` |
| Проверка предпосылок | `GET /api/diagnostics/prerequisites` |
| dry-run стратегии | `POST /api/strategies/<sid>/validate` |
| Превью команды | `POST /api/strategies/preview` |

### Ссылки на исходные документы (`bol-van/zapret2`)

- `docs/manual.md` — полный мануал (RU, ~5800 строк).
- `docs/manual.en.md` — английская версия.
- `docs/readme.md` — короткое введение / портирование стратегий nfqws1 → nfqws2.
- `docs/changes.txt`, `docs/changes_compat.txt` — история изменений.
- `lua/zapret-antidpi.lua` — **главный источник правды по стратегиям**
  (комментарии перед каждой функцией).
- `lua/zapret-lib.lua` — хелперы (для написания своих desync).
- `lua/zapret-auto.lua` — оркестраторы.
- `init.d/custom.d.examples.linux/` — рабочие custom-скрипты.
- `blockcheck2.d/standard/` — модули стандартного теста;
  `blockcheck2.d/custom/list_*.txt` — пресет-стратегии.
- `config.default` — дефолтный config с подробными комментариями.

---

**Главное правило при работе со стратегией**: пиши `--debug=1`, дёргай
curl-ом нужный домен, читай лог. Без debug — слепая работа.
