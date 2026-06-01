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
3. Extension-скрипты (`zapret-multishake.lua`, `fakemultisplit.lua`,
   `fakemultidisorder.lua`) нужны только если стратегия использует функции
   `hostfakesplit_*`, `fakemultisplit`, `fakemultidisorder`.
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
| `--debug` | Подробный пер-пакетный лог. **Главный инструмент отладки.** |

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

## 2. Конвенции nfqws2-keenetic (эталон)

- Конфиг: `/opt/etc/nfqws2/nfqws2.conf` с переменными `NFQWS_ARGS` (HTTPS/TCP),
  `NFQWS_ARGS_QUIC`, `NFQWS_ARGS_UDP`, `NFQWS_ARGS_CUSTOM`.
- Списки: `user.list`, `auto.list`, `exclude.list`, `ipset.list`,
  `ipset_exclude.list`.
- Режимы выбора доменов: **list** (только user.list), **auto** (домен
  добавляется после 3 фейлов за 60с), **all** (всё, кроме exclude.list).
- init-скрипт `/opt/etc/init.d/S51nfqws2`, цепочка iptables `nfqws_post`,
  очередь 300, проверка fwmark чтобы не обрабатывать уже промаркированное.
- Порты: TCP 443 (+опц. 80), UDP 443 (QUIC).
- **Обязательно**: отключить hardware offload (иначе iptables не видит трафик),
  настроить conntrack (`nf_conntrack_tcp_be_liberal=1`), рекомендован DoT/DoH.

---

## 3. Как это отображается в zapret-gui

| nfqws2-keenetic | zapret-gui |
|---|---|
| `nfqws2.conf` NFQWS_ARGS | стратегия (JSON user / каталог) → `strategy_builder` / `catalog_loader` |
| init.d + iptables | `core/firewall.py` (`FirewallManager`) + `core/nfqws_manager.py` |
| user/auto/exclude.list | `core/hostlist_manager.py`, `core/named_lists.py`, профили `scan_targets` |
| ручной подбор | `core/strategy_scanner.py` (автоперебор) |

### Сборка argv: `NFQWSManager.compose_command()`

Единый источник argv (и для live-запуска, и для автозапуска):

```
[binary] + base(--user/--fwmark/--qnum[/--bind-fix4/6]) + lua-init(core+ext)
        + unified(--hostlist) + strategy_args
```

- `_build_base_args` — `--user`, `--fwmark`, `--qnum` из конфига; `--bind-fix4/6`
  при нескольких WAN.
- `_build_lua_init_args` — добавляет core-lua **только если** в стратегии есть
  `--lua-desync` **И файл существует** на `lua_path`. Extension-lua — по
  используемым функциям. Дедуп `--lua-init`.
- `queue_num` берётся из `nfqws.queue_num` (по умолчанию **300**) — то же
  значение использует `firewall.py` для `queue num`. **Не разводить эти числа.**

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

## 6. Правила при написании/правке стратегий

- НЕ использовать синтаксис nfqws1 (`--dpi-desync=`, `--dpi-desync-split-pos=`) —
  это другой движок. Только `--lua-desync=`.
- Блоб-декларации (`--blob=`) — ОДИН раз в начало, до первого `--new`.
- `zapret-lib.lua` первым среди `--lua-init`.
- Не дублировать `--qnum`; синхронизировать с firewall.
- Для мультипрофиля разделять `--new`; фильтры/payload — внутри своего профиля.
- При генерации стратегий «на лету» (`strategy_generator`) дедуп по
  нормализованным args (`_norm_args`).
- Тестировать всегда на ЗАБЛОКИРОВАННОМ ресурсе, иначе baseline-aware даст 0%.
</content>
</invoke>
