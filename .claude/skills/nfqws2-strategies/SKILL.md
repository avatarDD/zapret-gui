---
name: nfqws2-strategies
description: >-
  Справочник по написанию и отладке стратегий обхода DPI на nfqws2 (zapret2)
  для роутеров Keenetic в проекте zapret-gui. Использовать при любых запросах,
  касающихся: стратегий nfqws2/zapret2, каталогов catalogs/*, сканера стратегий
  (strategy_scanner), сборки аргументов nfqws2 (nfqws_manager, strategy_builder),
  firewall/NFQUEUE правил, lua-desync, blob'ов, hostlist'ов, или диагностики
  «стратегия не работает / 0% успешности». Основано на bol-van/zapret2 и
  nfqws/nfqws2-keenetic.
---

# nfqws2 / zapret2 strategies on Keenetic — reference

Этот скилл — единый источник истины о том, **как nfqws2 (zapret2) реально
работает** и как с ним правильно обращаться в проекте `zapret-gui`. Читать
перед тем, как трогать сканер стратегий, сборку аргументов, firewall или
каталоги, и перед тем, как объяснять пользователю «почему не работает».

Референсы:
- **bol-van/zapret2** — сам движок nfqws2 (lua-десинк).
- **nfqws/nfqws2-keenetic** — эталонная упаковка/конфиг под Keenetic, у которого
  «всё работает». Когда наш проект ведёт себя иначе — сверяемся с ним.

---

## 1. Как устроен nfqws2 (главное отличие от nfqws1/winws)

nfqws2 **не имеет хардкод-стратегий** (`--dpi-desync=fake,split2` — это старый
nfqws1!). Вся логика десинхронизации живёт в **Lua-скриптах**, а CLI лишь
загружает их и вызывает функции.

Поток пакета: ядро → NFQUEUE → nfqws2 (применяет lua-desync) → ядро.

### Обязательный костяк команды

```
nfqws2 --qnum 300 \
  --lua-init=@/opt/zapret2/lua/zapret-lib.lua \      # ПЕРВЫМ — базовые примитивы
  --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua \  # определяет fake/multisplit/...
  --filter-tcp=80,443 --filter-l7=tls,http \
  --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tls_mod=rnd \
  --lua-desync=multisplit:pos=1
```

**Критические инварианты (нарушение = тихий 0%):**

1. `zapret-lib.lua` **обязан** грузиться `--lua-init` ПЕРВЫМ — он определяет
   базовые примитивы (rawsend, tcpseg, send, drop, дисекторы TLS/QUIC, маркеры).
2. `zapret-antidpi.lua` определяет сами desync-функции: `fake`, `multisplit`,
   `multidisorder`, `fakedsplit`, `pktmod`, `wssize`, `syndata`, `luaexec` и т.д.
   **Без него `--lua-desync=fake:...` — это вызов несуществующей функции:
   nfqws2 либо падает на старте, либо десинк просто не применяется.**
3. Extension-скрипты подключаются `--lua-init` ТОЛЬКО если стратегия реально
   вызывает их функции (`--lua-desync=FN`), см. `_EXTENSION_LUA_FILES` в
   `nfqws_manager.py`. Карта (файл → его экспортируемые функции-триггеры):
   - `zapret-multishake.lua` — `hostfakesplit_stealth/chaos/multi/gradual/decoy/blend/soft`, `snifakesplit`;
   - `fakemultisplit.lua` — `fakemultisplit`; `fakemultidisorder.lua` — `fakemultidisorder`;
   - `zapret-obfs.lua` — `wgobfs`, `ippxor`, `udp2icmp`, `synhide` (надмножество `zapret-wgobfs.lua`, последний поэтому НЕ грузим — иначе `wgobfs` определится дважды);
   - `zapret-16kb.lua` — `flood_white`, `ttl_ladder`, `white_sandwich`, `seqovl_white`;
   - `zapret-rst-flood.lua` — `rst_flood`; `zapret-pcap.lua` — `pcap` (требует `--writeable`).
   **Инвариант:** набор-триггер каждого файла обязан совпадать с его
   глобальными функциями (`grep '^function ' import/lua/<file>.lua`) — иначе
   вызов «выпавшей» функции = тихий 0%. Сторожит `tests/test_nfqws_lua_map.py`.
   Скрипты-оркестраторы/детекторы (`combined-detector`, `domain-grouping`,
   `strategy-stats`, `strategy-lock-manager`, `silent-drop-detector`) — это
   companion'ы роутерного auto-оркестратора, а НЕ desync-действия; в GUI-потоке
   детекцию делает Python-сканер, поэтому в desync-путь они не подключаются.
4. `--qnum N` **обязан** совпадать с номером очереди в правиле firewall
   (`queue num N`). Иначе пакеты уходят в очередь, которую никто не слушает.

### Ключевые опции CLI

| Опция | Назначение |
|---|---|
| `--qnum N` | Номер NFQUEUE (должен == firewall `queue num`) |
| `--lua-init=@file` / `--lua-init="code"` | Загрузка lua один раз при старте |
| `--blob=NAME:@file` / `--blob=NAME:0xHEX` | Глобальная декларация именованного блоба |
| `--filter-tcp=PORTS` / `--filter-udp=PORTS` | Фильтр по портам |
| `--filter-l7=tls,http,quic` | Фильтр по L7-протоколу |
| `--payload=tls_client_hello,http_req,quic_initial` | Фильтр по типу payload |
| `--hostlist=FILE` / `--hostlist-exclude=FILE` | Матч по SNI/Host (поддомены автоматически) |
| `--ipset=FILE` / `--ipset-exclude=FILE` | Матч по IP |
| `--new` | Разделитель ПРОФИЛЕЙ (мультистратегия) |
| `--lua-desync=FN:p1=v1:p2=v2` | Вызов desync-функции (несколько — выполняются последовательно) |
| `--debug[=0\|1\|syslog\|@file]` | Пер-пакетный лог. Бэйр `--debug` ≡ `--debug=1`. **Главный инструмент отладки.** Полный справочник опций — §8. |

### Desync-функции и частые параметры

- Функции: `fake`, `multisplit`, `multidisorder`, `fakedsplit`, `split`/`disorder`,
  `syndata`, `pktmod`, `wssize`, `hostfakesplit_*`, `pass` (no-op).
- Параметры: `blob=NAME`, `pos=MARKER` (`1`, `method+2`, `midsld`, `-1`),
  `repeats=N`, `tcp_md5`, `ip_ttl=`, `ip6_ttl=`, `ip_autottl=`, `ip6_autottl=`,
  `tcp_seq=`, `tcp_ack=`, `seqovl=`, `seqovl_pattern=0xHEX|NAME`,
  `tls_mod=rnd,rndsni,dupsid`, `badsum`, `badseq`, `payload=all`.
- Маркеры позиции: `0` начало, `-1` конец, `method` (HTTP), `midsld`, `sld`,
  арифметика `method+2`, `endhost-1`.
- Цепочка: каждый следующий `--lua-desync` видит уже изменённый предыдущим
  пакет (verdict PASS/MODIFY/DROP комбинируются).

### Встроенные блобы (НЕ требуют `--blob`)

`fake_default_tls`, `fake_default_http`, `fake_default_quic` — генерируются
самим nfqws2. Любые другие имена (`tls_google`, `stun_pat`, `quic_vk`, …)
**обязаны** иметь декларацию `--blob=NAME:@bin/file.bin` ОДИН раз в начале
команды (до первого `--new`, т.к. декларации глобальны). Иначе fake уходит
пустым и обход не срабатывает (внешне — тихий 0%).

---

## 2. Пути и layout — как в оригинальном bol-van/zapret2

Наш проект следует раскладке **bol-van/zapret2** (ZAPRET_BASE = `/opt/zapret2`),
имена файлов и каталогов — как в апстриме. Корни:

- **`/opt/zapret2/`** — ассеты движка zapret2 (дефолты в `core/config_manager`):
  - `nfq2/nfqws2` — бинарник (`zapret.nfqws_binary`);
  - `lua/` — Lua-скрипты `zapret-lib.lua`, `zapret-antidpi.lua`, … (`zapret.lua_path`);
  - `lists/` — hostlist'ы (`zapret.lists_path`);
  - `ipset/` — IP-списки (`zapret.ipset_path`);
  - `files/fake/` — blob-файлы `*.bin` (`zapret.bin_path`);
  - `blockcheck2.sh` / `blockcheck.sh` — штатный blockcheck
    (`zapret.blockcheck2_path`, иначе автопоиск в `base_path`).
- **`/opt/etc/zapret-gui/`** — конфиг и состояние самого GUI (НЕ движка):
  - `settings.json` — конфигурация (`core/config_manager.DEFAULT_CONFIG_DIR`);
    секции `zapret.*`, `nfqws.*`, `firewall.*`, `scan.*` и т.д.;
  - runtime firewall-конфиг и хуки персистентности
    (`core/firewall_persistence.GUI_RUNTIME_DIR`);
  - state-файлы установщиков (singbox/mihomo и пр.).
- **`/opt/etc/init.d/`** (Entware) — init-скрипты автозапуска:
  - `S99zapret` — автозапуск nfqws2 с применённой стратегией + firewall;
    генерируется `core/autostart_manager.py` (`INIT_DIR`/`SCRIPT_NAME`,
    шаблон `_S99ZAPRET_TEMPLATE`; PID-файл `/var/run/zapret-nfqws.pid`);
  - `S99zapret-gui` — сам сервис Web-GUI (создаётся `install.sh`).

⚠️ Путей вида `/opt/etc/nfqws2/nfqws2.conf` или `/opt/etc/init.d/S51nfqws2` у нас
**НЕТ** — это раскладка стороннего упаковщика nfqws2-keenetic, не bol-van/zapret2.
Наш автозапуск — `S99zapret` (см. выше). Не путать.

### nfqws2-keenetic — только поведенческий эталон

Из nfqws2-keenetic берём идеи поведения (НЕ пути):
- режимы выбора доменов: **list** / **auto** (домен добавляется после 3 фейлов
  за 60с) / **all**;
- **обязательно** отключить hardware offload (иначе iptables не видит трафик),
  выставить `nf_conntrack_tcp_be_liberal=1`, рекомендован DoT/DoH.

**Порты — любые, зависят от целевого сервиса**, который «дурим». Задаются в
`nfqws.ports_tcp` / `nfqws.ports_udp` (их использует `firewall.py` для NFQUEUE)
и должны согласовываться с `--filter-tcp` / `--filter-udp` в стратегии. Дефолты
в проекте намеренно шире, чем «443/QUIC» у keenetic:
- `ports_tcp = "80,443,2053,2083,2087,2096,5222,8443"` (HTTP/HTTPS + alt-порты
  Cloudflare, Telegram MTProto 5222);
- `ports_udp = "443,3478:3481,5349,19294:19344,49152:65535"` (QUIC + STUN/TURN +
  WireGuard-диапазоны + Discord voice).

---

## 3. Как это отображается в zapret-gui

| zapret2 (эталон) | zapret-gui |
|---|---|
| опции nfqws2 в `config` ZAPRET_BASE | стратегия (JSON user / каталог) → `strategy_builder` / `catalog_loader` |
| init.d + iptables (`init.d/`) | `core/firewall.py` (`FirewallManager`) + `core/nfqws_manager.py`; автозапуск — `core/autostart_manager.py` → `/opt/etc/init.d/S99zapret` |
| hostlist'ы в `ipset/` (`zapret-hosts-*.txt`) | `core/hostlist_manager.py`, `core/named_lists.py`, профили `scan_targets` |
| ручной подбор | `core/strategy_scanner.py` (автоперебор) |

### Сборка argv: `NFQWSManager.compose_command()`

Единый источник argv (и для live-запуска, и для автозапуска):

```
[binary] + base(--user/--fwmark/--qnum[/--debug][/--bind-fix4/6]) + lua-init(core+ext)
        + unified(--hostlist) + strategy_args
```

- `_build_base_args` — `--user`, `--fwmark`, `--qnum` из конфига; `--debug` при
  `nfqws.debug=true`; `--bind-fix4/6` при нескольких WAN.
- `_build_lua_init_args` — добавляет core-lua **только если** в стратегии есть
  `--lua-desync` **И файл существует** на `lua_path`. Extension-lua — по
  используемым функциям. Дедуп `--lua-init`.
- `queue_num` берётся из `nfqws.queue_num` (по умолчанию **300**) — то же
  значение использует `firewall.py` для `queue num`. **Не разводить эти числа.**
- **Превью команды** (`build_preview_command`, `POST /api/strategies/preview`)
  собирается ЧЕРЕЗ тот же `compose_command` — превью = реальная команда.

### Каталоги `catalogs/`

- `builtin/` — **полные пресеты**: содержат свои `--filter-*`/`--hostlist=`/
  `--blob=`/`--new`. Берутся как есть, только резолвятся пути.
- `basic/`, `advanced/`, `direct/` — **«приёмы» (tricks)**: один-два
  `--lua-desync=`. Сканер сам оборачивает их в шаблон цели (добавляет
  `--filter-*`, `--filter-l7`, `--payload`, `--hostlist=<tmp с доменами цели>`).
  См. `StrategyScanner._wrap_trick_args`.
- Эвристика «полный пресет vs приём» — `_is_full_preset_args()`
  (наличие `--filter-*`/`--new`/`--hostlist`/`--ipset`/`--blob`).
- Блобы по имени дозаявляются автоматически — `core/blob_registry.py`
  (`build_blob_declarations`), маппинг имя→`@bin/*.bin`.

---

## 4. Почему «не находит ни одной рабочей стратегии» — чеклист причин

Проверять В ЭТОМ ПОРЯДКЕ:

1. **Сайт доступен без обхода → всегда 0% (это НЕ баг).**
   `strategy_scanner._deep_probe` при `baseline_open_all` принудительно ставит
   `success=False` (error `BASELINE_OPEN`): стратегия не может «починить» то,
   что не сломано. **Подбор надо запускать на ЗАБЛОКИРОВАННОМ ресурсе.** На
   заведомо доступном 0% — ожидаемо.

2. **Нет lua-скриптов на `lua_path`** (`/opt/zapret2/lua`). Тогда
   `_build_lua_init_args` ничего не добавит, а `--lua-desync=fake/multisplit`
   станет вызовом несуществующих функций → десинк не применяется.
   Проверка: `ls /opt/zapret2/lua/` → должны быть `zapret-lib.lua`,
   `zapret-antidpi.lua`. На dev-машине без zapret2 это даёт тотальный 0%.

3. **Нет blob-файлов** (`bin_path`, `/opt/zapret2/files/fake/*.bin`) — fake
   уходит пустым. В логе `blobs`: «blob '…' не найден в реестре».

4. **`--qnum` ≠ firewall `queue num`** — трафик в очередь, которую не слушают.
   Оба берутся из `nfqws.queue_num`, но если правила накатаны вручную/из
   другого источника — расходятся.

5. **Hostlist не матчит SNI цели.** Приёмы оборачиваются tmp-hostlist'ом с
   доменами цели; если домен не совпал с реальным SNI — десинк не применился.

6. **Hardware offload включён / conntrack не настроен.** iptables не видит
   трафик, либо ядро дропает out-of-window сегменты десинка. Наш firewall ставит
   `nf_conntrack_tcp_be_liberal=1` и `nf_conntrack_checksum=0` — проверить, что
   применилось (на роутере, не в контейнере).

7. **Body-проба требует ≥64 КБ** (`BODY_PROBE_MIN_BYTES`). TLS-only без body —
   считается псевдо-успехом (отсев «пускает первые 16-20 КБ и рвёт»).

---

## 5. Отладка: включить `--debug` nfqws2

Главный диагностический приём — поднять пер-пакетный лог nfqws2.

- Конфиг: `nfqws.debug = true` → `nfqws_manager` добавляет `--debug` в argv, а
  stderr nfqws2 (уже захватывается в лог-буфер) логируется на уровне INFO,
  чтобы быть видимым.
- В логе смотреть: грузятся ли lua-скрипты, объявлены ли блобы, **матчится ли
  пакет цели по filter/hostlist**, какие desync реально применяются.

Ручной прогон (эталон из zapret2, для сверки на роутере):

```
nfqws2 --qnum 200 --debug \
  --lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua \
  --filter-tcp=80,443 --filter-l7=tls,http \
  --payload=tls_client_hello \
    --lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid \
  --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5 \
  --payload=tls_client_hello,http_req \
    --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000
```

(Запускать с уже накатанными firewall-правилами на тот же `--qnum`, иначе в
очередь ничего не придёт и debug будет пустым.)

---

## 6. Готовые инструменты диагностики в проекте

- **Предпосылки стратегий** — `core/diagnostics.check_strategy_prerequisites()`,
  API `GET /api/diagnostics/prerequisites`. Проверяет бинарник nfqws2,
  обязательные lua (`zapret-lib.lua`, `zapret-antidpi.lua`), наличие blob-файлов,
  каталоги списков, доступность NFQUEUE и `nf_conntrack_tcp_be_liberal`. Возвращает
  `issues` с `severity` error|warning и `hint`. Сканер вызывает её на старте и
  громко логирует блокеры (`_check_prerequisites`). **Первое, что смотреть при
  «0% на всём».**
- **Штатный blockcheck zapret2** — `core/blockcheck2.Blockcheck2Runner`, API
  `/api/blockcheck2/{script,start,status,output,stop}`. Запускает оригинальный
  `blockcheck2.sh`/`blockcheck.sh` как подпроцесс неинтерактивно (`BATCH=1`,
  env `DOMAINS`/`IPVS`/`SCANLEVEL`/`ENABLE_*`/`REPEATS`/`PARALLEL`/…), стримит
  вывод в лог-буфер (`source=blockcheck2`) и в кольцевой буфер для
  инкрементального polling (`output?offset=N`). Путь — `zapret.blockcheck2_path`
  или автопоиск в `base_path`. Это НЕ путать с `core/blockcheck.py` (наша
  Python-реализация проб для GUI-тестера).
- **nfqws2 `--debug`** — конфиг `nfqws.debug=true` добавляет `--debug` и
  поднимает stderr nfqws2 до INFO (см. §5).

## 7. Правила при написании/правке стратегий

- НЕ использовать синтаксис nfqws1 (`--dpi-desync=`, `--dpi-desync-split-pos=`) —
  это другой движок. Только `--lua-desync=`.
- Блоб-декларации (`--blob=`) — ОДИН раз в начало, до первого `--new`.
- `zapret-lib.lua` первым среди `--lua-init`.
- Не дублировать `--qnum`; синхронизировать с firewall.
- Для мультипрофиля разделять `--new`; фильтры/payload — внутри своего профиля.
- При генерации стратегий «на лету» (`strategy_generator`) дедуп по
  нормализованным args (`_norm_args`).
- Тестировать всегда на ЗАБЛОКИРОВАННОМ ресурсе, иначе baseline-aware даст 0%.

---

## 8. Полный справочник CLI nfqws2 (`nfqws2 -?`, v0.9.5.2)

Дамп `./nfqws2 -?` движка `bol-van/zapret2`. Версия движка печатается так:
`github version v0.9.5.2 (<git-hash>) lua_compat_ver 5`. Это **источник истины**
по опциям — сверяться с ним, а не угадывать. Опции с `[0|1]`/`[=val]` имеют
необязательный аргумент (без него включаются дефолтом, обычно `=1`).

### 8.1 Глобальные / общие

| Опция | Назначение |
|---|---|
| `@<config_file>` / `$<config_file>` | Читать опции из файла. **Должен быть единственным аргументом** — остальные игнорируются. |
| `--debug=0\|1\|syslog\|@<filename>` | Уровень/назначение отладочного лога. Бэйр `--debug` ≡ `=1`. |
| `--version` | Печать версии и выход. |
| `--dry-run` | Проверить параметры и выйти с кодом 0 при успехе. **Использовать для валидации стратегии без запуска** (preview/lint). |
| `--comment=<text>` | Комментарий (no-op, для читабельности конфига). |
| `--intercept=0\|1` | Включить перехват. Если выключить — выполнить только lua-init и выйти. |
| `--qnum=<n>` | Номер NFQUEUE (== firewall `queue num`). |
| `--daemon` | Демонизироваться. **GUI запускает БЕЗ него** (foreground-child + Popen). С ним работает только автозапуск `S99zapret` (свой `--pidfile`). |
| `--chdir[=path]` | Сменить рабочий каталог (без аргумента — EXEDIR). |
| `--pidfile=<file>` | Записать PID в файл. |
| `--user=<username>` | Сбросить root-привилегии на пользователя. |
| `--uid=uid[:gid1,gid2,...]` | Сбросить привилегии по uid/gid. |
| `--bind-fix4` / `--bind-fix6` | Фикс выбора исходящего интерфейса для генерируемых IPv4/IPv6 пакетов (multi-WAN). |
| `--fwmark=<int\|0xHEX>` | fwmark генерируемых пакетов. **Дефолт `0x40000000` (1073741824)**. |
| `--ctrack-timeouts=S:E:F[:U]` | Таймауты внутреннего conntrack: TCP SYN, ESTABLISHED, FIN, UDP. Дефолт `60:300:60:60`. |
| `--ctrack-disable[=0\|1]` | Отключить внутренний conntrack. |
| `--payload-disable[=type[,type]]` | Не детектировать эти типы payload (без аргумента — все). |
| `--server[=0\|1]` | Менять обработку src/dst ip/port для входящих соединений (серверный режим). |
| `--ipcache-lifetime=<int>` | TTL кэша hop-count/имени домена, сек (дефолт 7200, 0 = вечно). |
| `--ipcache-hostname[=0\|1]` | Кэшировать ip→hostname. |
| `--reasm-disable[=type[,type]]` | Отключить reasm для L7 payload: `tls_client_hello`, `quic_initial` (без аргумента — все). |

### 8.2 DESYNC ENGINE INIT

| Опция | Назначение |
|---|---|
| `--writeable[=<dir>]` | Создать writeable-каталог для LUA-скриптов, путь → env `WRITEABLE` (только один). |
| `--blob=<name>:[+ofs]@<file>\|0xHEX` | Загрузить blob в LUA-переменную `<name>`. Поддержан offset `+ofs`. |
| `--lua-init=@<file>\|<lua_text>` | Загрузить LUA из файла или строки. **Порядок нескольких сохраняется.** Поддержаны gzip-файлы. |
| `--lua-gc=<int>` | Принудительный GC каждые N сек (дефолт 60, триггерится при приходе пакета, 0 = выкл). |

### 8.3 MULTI-STRATEGY (профили)

| Опция | Назначение |
|---|---|
| `--new[=<name>]` | Начать новый профиль (опционально имя). |
| `--skip` | Не использовать этот профиль. |
| `--name=<name>` | Задать имя профиля. |
| `--template[=<name>]` | Использовать профиль как шаблон (должен быть именованным). |
| `--cookie[=<str>]` | Передать в LUA строку, привязанную к профилю. |
| `--import=<name>` | Заполнить текущий профиль данными шаблона. |
| `--filter-l3=ipv4\|ipv6` | Фильтр L3 (через запятую). |
| `--filter-tcp=[~]port1[-port2]\|*` | Фильтр TCP-портов. `~` — отрицание. Список через запятую. Задание tcp-фильтра без прочих запрещает прочие. |
| `--filter-udp=[~]port1[-port2]\|*` | Фильтр UDP-портов (аналогично). |
| `--filter-icmp=type[:code]\|*` | Фильтр ICMP type+code. |
| `--filter-ipp=proto` | Фильтр IP-протокола. |
| `--filter-l7=proto[,proto]` | L6-L7 фильтр. Полный список ниже (§8.6). |
| `--filter-ssid=ssid1[,...]` | Пер-профильный Wi-Fi SSID-фильтр. |
| `--ipset=<file>` | Include по IP/CIDR (ipv4+ipv6, gzip, несколько). |
| `--ipset-ip=<list>` | Фиксированный список подсетей через запятую. |
| `--ipset-exclude=<file>` / `--ipset-exclude-ip=<list>` | Exclude по IP. |
| `--hostlist=<file>` | Десинк только для перечисленных хостов (поддомены автоматически, gzip, несколько). |
| `--hostlist-domains=<list>` | Фиксированный список доменов через запятую. |
| `--hostlist-exclude=<file>` / `--hostlist-exclude-domains=<list>` | Исключения по хостам. |
| `--hostlist-auto=<file>` | Автодетект DPI-блокировок и построение hostlist. |
| `--hostlist-auto-fail-threshold=<int>` | Сколько фейлов добавляют хост в auto-hostlist (дефолт 3). |
| `--hostlist-auto-fail-time=<int>` | Все фейлы в пределах N сек (дефолт 60). |
| `--hostlist-auto-retrans-threshold=<int>` | Сколько ретрансмиссий запроса = провал попытки (дефолт 3). |
| `--hostlist-auto-retrans-maxseq=<int>` | Считать ретрансмиссии только в пределах rel-seq (дефолт 32768). |
| `--hostlist-auto-retrans-reset=[0\|1]` | Слать RST ретрансмиттеру (дефолт 1). |
| `--hostlist-auto-incoming-maxseq=<int>` | Считать соединение успешным, если входящий rel-seq превысил порог (дефолт 4096). |
| `--hostlist-auto-udp-out=<int>` | UDP-провал: отправлено ≥ udp_out пакетов (дефолт 4). |
| `--hostlist-auto-udp-in=<int>` | UDP-провал: получено ≤ udp_in пакетов (дефолт 1). |
| `--hostlist-auto-debug=<logfile>` | Лог срабатываний auto-hostlist (глобальный параметр). |

### 8.4 LUA PACKET PASS MODE

| Опция | Назначение |
|---|---|
| `--payload=type[,type]` | Какие типы payload обрабатывают следующие LUA-функции. Полный список — §8.6. |
| `--out-range=[(n\|a\|d\|s\|p)<int>](-\|<)[...]` | Диапазон исходящих пакетов для следующих LUA-функций. |
| `--in-range=[(n\|a\|d\|s\|p)<int>](-\|<)[...]` | Диапазон входящих пакетов. |

Префиксы диапазона: `n` — номер пакета, `d` — номер data-пакета, `s` — rel-seq,
`p` — позиция данных в rel-seq, `b` — счётчик байт, `x` — никогда, `a` — всегда.
`-` включает конечную позицию, `<` — не включает.

### 8.5 LUA DESYNC ACTION

| Опция | Назначение |
|---|---|
| `--lua-desync=<function>[:p1=v1[:p2=v2]]` | Вызвать LUA-функцию при приходе пакета. |

### 8.6 Справочные списки значений

**`--filter-l7`:** `all unknown known http tls dtls quic wireguard dht discord
stun xmpp dns mtproto bt utp_bt`.

**`--payload` (типы):** `all unknown empty known ipv4 ipv6 icmp http_req
http_reply tls_client_hello tls_server_hello dtls_client_hello
dtls_server_hello quic_initial wireguard_initiation wireguard_response
wireguard_cookie wireguard_keepalive wireguard_data dht discord_ip_discovery
stun xmpp_stream xmpp_starttls xmpp_proceed xmpp_features dns_query dns_response
mtproto_initial bt_handshake utp_bt_handshake`.

**`--reasm-disable` (типы):** `tls_client_hello quic_initial`.

### 8.7 Важные следствия для zapret-gui

- **`--dry-run`** — штатная валидация собранной стратегии без поднятия
  NFQUEUE. **Реализовано:** `NFQWSManager.dry_run(strategy_args)` собирает argv
  тем же `compose_command`, убирает `--user=` (чтобы не было setuid вне
  рантайма), добавляет `--dry-run`, запускает и проверяет `returncode==0`.
  Ловит вызовы несуществующих lua-функций, битые `--blob`/`--lua-init`, плохой
  синтаксис `--lua-desync`. API: `POST /api/strategies/<sid>/validate` и
  `POST /api/strategies/preview` с `{"validate": true}` → поле `validation:
  {ok, available, returncode, output, command}`. `available=false` — бинарника
  нет (dev-машина без zapret2).
- **`--version`** даёт `lua_compat_ver` — полезно при диагностике
  несовместимости lua-скриптов с версией движка.
- **`--fwmark` дефолт `0x40000000`** совпадает с нашим `nfqws.desync_mark` —
  не путать с firewall MARK_PROCESSED/MARK_EXCLUDE (другой слой).
- `@<config_file>` обязан быть **единственным** аргументом — нельзя
  смешивать файл-конфиг с inline-опциями. Мы собираем всё inline через
  `compose_command`, файл-конфиг не используем.
- `--daemon` использует только автозапуск `S99zapret`; GUI ведёт процесс
  как foreground-child. Один nfqws2 на NFQUEUE — дубли зачищает
  `NFQWSManager._sweep_stray_processes` (issue #123).
