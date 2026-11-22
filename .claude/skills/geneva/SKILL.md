---
name: geneva
description: >-
  Справочник по geneva_c в проекте zapret-gui: C-порт Geneva (Genetic
  Evasion, avatarDD/geneva_c) как второй движок обхода DPI рядом с nfqws2.
  Использовать при любых задачах о: выборе движка nfqws2 / geneva_c
  (core/bypass_engine.py, настройка bypass.engine, /api/bypass/engine,
  снимки state/engines.json), запуске `geneva run` (NFQUEUE 310, метка
  0x20000000, сокет управления unix, события JSONL, set_strategy на лету,
  pause/resume, fw down), генетическом подборе `geneva evolve` (checkpoint,
  --resume, база оценок db.jsonl, пробы tls/http/https, пауза обхода на
  время подбора, продолжение с прерванного места), проверке стратегий `eval`,
  библиотеке Geneva (`library --json`), языке стратегий Geneva, телеметрии
  в разделе «Обход DPI» (web/js/pages/geneva.js, вкладки движков в
  web/js/components/engine_tabs.js), строке geneva на странице «Обновления»,
  установке бинарника
  из релиза с sha256 (BINARIES["geneva"]), MCP-инструментах geneva_* и
  bypass_engine_*, а также диагностике «geneva запущен, а обхода нет /
  правила пропали / подбор не стартует / exit 4, 5, 7», а также о режиме
  «Авто» (сам находит заблокированные сервисы любых протоколов по
  conntrack, подтверждает пробой без обхода, подбирает стратегию eval/evolve
  параллельными воркерами и применяет её отдельным geneva run на очереди
  340+ только к адресам сервиса; core/geneva_auto*.py, состояние
  state/geneva/auto.json, geneva.auto.*, /api/geneva/auto*, geneva_auto_*).
  Источник истины — сам бинарник и docs/ в avatarDD/geneva_c, привязка —
  core/geneva_manager.py, core/bypass_engine.py, core/geneva_auto*.py,
  api/geneva.py, core/mcp/tools/geneva.py.
---

# geneva_c — справочник для zapret-gui

geneva_c — порт на C11 движка и генетического поиска из Geneva (Kansas
University / UMD, «Genetic Evasion»). В zapret-gui он второй движок обхода
DPI: пользователь выбирает, через что идёт обход на роутере, **nfqws2 или
geneva_c**, и в каждый момент работает ровно один.

Источники истины (по убыванию авторитета):

1. **Сам бинарник** нужной версии: `geneva version --json` (поле `proto`
   должно быть `1`), `geneva <команда> --help`.
2. **[avatarDD/geneva_c](https://github.com/avatarDD/geneva_c)**, релиз
   **v2.0.1**: `docs/STRATEGY.md` (язык), `docs/PROTOCOL.md` (события и
   сокет), `docs/EVAL.md` (пробы и fitness), `docs/INTEGRATION.md`
   (встраивание), `.claude/skills/geneva/SKILL.md` (карта репозитория).
3. **Наш код**:
   - `core/geneva_manager.py`: процессы, события, подбор, телеметрия;
   - `core/bypass_engine.py`: выбор движка и снимки;
   - `api/geneva.py`: REST;
   - `core/mcp/tools/geneva.py`: MCP;
   - `web/js/pages/geneva.js`: части интерфейса geneva (`sections`);
   - `web/js/components/engine_tabs.js`: раздел «Обход DPI» по задачам;
   - `core/update_checker.py`: `_check_geneva`, `geneva_release_info`;
   - `core/ext_binary_installer.py`: `BINARIES["geneva"]`;
   - `core/config_manager.py`: секции `bypass` и `geneva`;
   - `core/nfqws_control.py`: `_engine_refusal`;
   - `app.py`: поток `geneva-boot`.

> ⚠️ **Стратегии Geneva — не стратегии nfqws2.** Это деревья действий над
> пакетами (`[TCP:flags:PA]-duplicate(...)-|`), а не аргументы `--lua-desync`.
> Их никогда не переводят в конфиг zapret2 и не смешивают со списком
> стратегий nfqws2: у каждого движка свой список и свой прогресс подбора.

---

## 1. Выбор движка (core/bypass_engine.py)

| Что | Где |
|---|---|
| активный движок | `settings.json → bypass.engine` (`nfqws2` по умолчанию) |
| снимки движков и история 30 переключений | `<config>/state/engines.json` |
| сводка обоих движков | `overview()`, `GET /api/bypass/engine`, MCP `bypass_engine_status` |
| переключение | `switch(engine, start)`, `POST /api/bypass/engine`, MCP `bypass_engine_set` |

`switch()` отказывает (`error_code: busy`), если nfqws2 занят сканером или
blockcheck, или если идёт подбор geneva.

Переход **на geneva** (`_to_geneva`):

1. Проверяет, что geneva установлен и `proto` совпадает. Если `start=True`,
   нужна ещё рабочая стратегия, иначе ответ `error_code: no_strategy`;
   страница тогда предлагает выбрать geneva без запуска.
2. Записывает снимок nfqws2: стратегию, автозапуск и то, был ли он запущен.
3. Останавливает nfqws2 с `source="engine_switch"` и выключает его
   автозапуск. Флаг автозапуска переносится в `geneva.autostart`.
4. Ставит `bypass.engine=geneva` и запускает geneva. Если запуск не
   удался, всё откатывается: прежний движок, автозапуск и запуск nfqws2.

Переход **на nfqws2** (`_to_nfqws`):

1. Останавливает geneva и ставит `bypass.engine=nfqws2`.
2. Включает автозапуск nfqws2, если он был включён в снимке.
3. Запускает nfqws2, если у него выбрана стратегия.

Исключительность движков держится в трёх местах:

- `nfqws_control.start/restart/apply_strategy` → `_engine_refusal` →
  `bypass_engine.nfqws_refusal()` → `error_code: engine_geneva`. Проверку
  обходит только `source="engine_switch"`.
- `GenevaManager.start()` отказывает с `error_code: engine_nfqws2`, пока
  активен nfqws2.
- Загрузка: `_apply_saved_strategy_on_boot` в `app.py` молчит при активном
  geneva, а `boot_apply()` поднимает geneva, если стоит автозапуск.

API отвечает HTTP 409 на `busy`, `engine_nfqws2` и `engine_geneva`.

## 2. Команды geneva, которые мы вызываем

| Наш вызов | Команда | Права |
|---|---|---|
| `start()` | `geneva run -f strategy.txt -p PORTS --proto P -q 310 --mark 0x20000000 --firewall auto\|nft\|iptables -c unix:SOCK -e EVENTS --stats-interval 30 -l LVL --log-file LOG --quiet [-i IF] [--first N]` | root |
| `stop()` (крайний случай) | `geneva fw down` с теми же `-p/--proto/-q/--firewall/-i/--mark` из `run.args.json` | root |
| `start_search()` | `geneva evolve [--ext --ext-blob z2_*:@файл…] --probe tls\|http\|exec --host H ... --population N --generations M -q 311 --checkpoint search.ckpt --db db.jsonl --target T -e job-events.jsonl [--resume]` | root |
| `start_eval()` | `geneva eval -f candidates.txt --host H ... -q 311` | root |
| `auto_apply({q: стратегия})` (группы «Авто») | `geneva run -f <rt>/auto/qQ.strategy -q Q --firewall none -p 1-65535 --proto tcp,udp --mark 0x20000000 -c unix:<rt>/auto/qQ.sock -e <rt>/auto/qQ.jsonl --stats-interval 5 …`, Q = 340..347; правила — `core/geneva_auto_fw` (таблица `inet zapret_geneva_auto` или цепочки `ZGGA_POST/ZGGA_PRE` + ipset `geneva_auto_Q_n_v4/v6`) | root |
| `start_auto_job("eval")` («Авто», быстрые кандидаты) | `geneva eval --probe external -f state/geneva/auto/candidates.txt --workers N -q 311 -e job-events.jsonl` (stdin — ответы `ExternalAnswerer`); без фичи `external_workers` — `--probe exec --cmd "python3 core/geneva_auto_probe_cli.py … --lports {lports}" --injected-contains INJECTED` | root |
| `start_auto_job("evolve")` («Авто», сервис) | `geneva evolve [--ext --ext-blob …] --probe external\|exec … --protos TCP\|UDP,IP\|UDP,IP,DNS,DNSQR --population 20 --generations 10 --workers N -q 311 --checkpoint state/geneva/auto/<sha1>.ckpt --db db.jsonl --target https:<host>\|replay:<ip>:<port> [--resume]` | root |
| `check_strategy()` | `geneva check --json -f -` | нет |
| `library()` | `geneva library --json --ext` (при фиче `ext`; старая сборка без ключа — повтор без него) | нет |
| `db_top()` | `geneva db --db db.jsonl top --json` (печатает JSONL) | нет |
| `detect()` | `geneva version --json` | нет |

`--ext` и фейки zapret2 у `evolve` — `geneva_ext.evolve_argv`: только при
фиче `ext_xgen` (geneva_c 2.0.1), тогда подбор сам делает x-действия
zapret2 и мутирует их параметры. Ключа `--ext` нет в параметрах checkpoint,
поэтому `--resume` подбора, начатого без него, geneva принимает.

Точные аргументы собирают чистые функции `build_run_args`,
`build_evolve_args`, `build_eval_args`, `build_auto_eval_args`,
`build_auto_evolve_args`, `fw_down_args` и `_probe_args`. Они
покрыты тестами, и аргументы правят только в них.

- **Очереди NFQUEUE.** nfqws2 держит 300–303, `run` 310, оценщик 311. Две
  очереди нужны, чтобы оценка могла идти рядом с `run`, хотя по умолчанию
  мы всё равно ставим обход на паузу (§4).
- **Метка 0x20000000** у пакетов, которые geneva отправляет сам. Правила
  geneva их пропускают, иначе получилась бы петля.
- **Менеджер «Авто»** (`core/geneva_auto_manager.py`,
  `get_geneva_auto_manager()`): поток `geneva-auto`, `tick()` — срез,
  захват протокола, подтверждение, подбор, применение, `stats`,
  сохранение `state/geneva/auto.json`. Пока режим включён, `start()`,
  `start_search()`, `start_eval()` отвечают `error_code: geneva_auto`;
  `bypass_engine.switch("nfqws2")` выключает режим, `hold_geneva_for`
  ставит его на паузу (`suspend`/`resume`), `boot_apply` зовёт `boot()`.
- **Группы «Авто»** — по процессу на стратегию, очереди 340–347
  (`geneva.auto.max_groups`, по умолчанию 4). Трафик выбирают правила
  zapret-gui: адреса сервисов группы (наборы на «очередь + порты»), DHT —
  по исходному кортежу conntrack, первые 12 исходящих и 6 входящих
  пакетов, пропуск метки `0x20000000`, портов оценщика 30000–30511 и
  портов пробы «Авто» без обхода 30512–30543.
  Без адресов правила нет: «все порты» процесса безопасны только поэтому.
- **Профили «Авто» (geneva_c 2.0, фича `ext_profile`)** — вместо групп
  один процесс: `geneva run --ext --ext-profile <rt>/auto/engine/profiles.ini
  --ext-workers N -q 340 --firewall none -p 1-65535 --proto tcp,udp`.
  Стратегий сколько угодно (предел `MAX_PROFILES 200`, у движка
  `XPROF_MAX 255`), профиль отбирает пакеты своим `ipset`-файлом и
  `filter-tcp/udp`. Схему выбирает `Applier` по `features(binary)`
  (`ga.PROFILE_FEATURE`), без фичи — прежние группы.
  Потоков не больше, чем умеет сам движок: `ENGINE_WORKERS_MAX = 64`
  (`--ext-workers` 1–64, docs/EXT.md «Многоочередной движок»). Очереди
  «по имени» (`HOST_QUEUE = 404`) и детектора (`OBSERVE_QUEUE = 405`)
  стоят СРАЗУ ЗА диапазоном профилей (`340..403`), поэтому своего
  предела сверх движка наш код не вводит.
  **Ловушки формата профиля:** «все порты» можно назвать только для
  одного протокола (`filter-tcp = 1-65535` без `filter-udp`) — второй
  протокол без фильтра означает «все порты» и при `-p` даёт ошибку
  `takes every port: give -p (and --proto)`; стратегия команды (`-f`) не
  передаётся вовсе, иначе geneva делает из неё профиль 1 и он ловит всё
  раньше файла; у цели по локальному порту (`by_local_port`, пиры/DHT)
  порт в фильтр профиля НЕ попадает — geneva сравнивает порт сервера
  (`src/ext/ext.c:290`), а там записан порт клиента, поэтому такие цели
  идут отдельным профилем `…-peer-…` «все порты сервера» и последним.

  Нет `ipset` или `xt_connbytes` (iptables) — ошибка с подсказкой.
- **Задания «Авто»** занимают тот же слот задачи, что ручной подбор
  (`job.pid`), но пишут своё состояние (`state/geneva/auto/search.json`,
  `owner: "auto"`) и свои checkpoint'ы на сервис: «Продолжить» ручного
  поиска их не подхватит. Обход на паузу не ставится.
- **Проба заданий «Авто».** Если в `geneva version --json` есть фича
  `external_workers` (geneva_c 1.2+) — `--probe external`: geneva пишет
  `eval_request` (`id`, `lports`) в файл событий задания,
  `ExternalAnswerer` в процессе GUI пробует сервис с блока портов воркера
  (`geneva_auto_probe_cli.measure`, в своём потоке на запрос, до N
  разом) и пишет в stdin `{"id":N,"fitness":F,"detail":"…"}` — по `id`, в
  любом порядке. Фитнес точный (−360/−400/−480 по шкале geneva), python на
  каждую оценку не запускается. Процесс с пайпом в stdin перезапуск GUI не
  переживает: stdin закрывается, geneva останавливает поиск (checkpoint
  остаётся). Без фичи — `--probe exec` со скриптом
  `geneva_auto_probe_cli.py`: шкала только ok (+400), `reset`/`INJECTED`
  (−360) и прочее (−400).
- **Проба `https`** у нас означает `--probe exec` с `curl -sf --local-port {lports}`
  (блок портов воркера), полная загрузка страницы. TLS-проба geneva не
  завершает рукопожатие, а `curl` без `-f` засчитывает HTTP-ошибку как
  успех (Pitfalls апстрима).

Коды возврата (`EXIT_CODES`):

| Код | Значение |
|---|---|
| 0 | ok |
| 1 | ни одна стратегия не прошла |
| 2 | неверные аргументы |
| 3 | стратегия не разбирается |
| 4 | нет прав или модулей ядра (NFQUEUE, raw-сокеты) |
| 5 | правила firewall не применились |
| 6 | ошибка ввода-вывода |
| 7 | ресурс доступен и без обхода, подбирать нечего |

## 3. Язык стратегий (кратко, полностью в docs/STRATEGY.md апстрима)

```
strategy := out-forest "\/" in-forest
tree     := "[" PROTO:field:value[:gas] "]-" action "-|"
action   := name["{" params "}"]["(" left "," right ")"]
```

- Действия: `duplicate`, `fragment{tcp:N:inorder}`,
  `tamper{TCP:field:replace|corrupt:V}`, `drop`, `send`. Во входящем лесу
  допустимы только `tamper` и `drop`.
- В стратегиях из библиотеки Geneva часто нет `\/`. Поэтому
  `check_strategy_text` требует только, чтобы строка начиналась с `[` или
  с `\/`, а полную проверку делает `geneva check`.
- Длина не больше 4096 символов (`MAX_STRATEGY_LEN`), одна строка.

### x-стратегии geneva_c 2.0 и фейки zapret2 (`core/geneva_ext.py`)

Договор с Zapret2_AutoTuner (там `GenevaStrategyText.NeedsExt`,
`GenevaBlobs`, `GenevaShare`), менять в обоих проектах сразу:

- **x-стратегия** — строка с x-действием (`xfake`, `xsplit`, `xwhen`…:
  функции zapret2, `docs/EXT.md` geneva_c) или триггером `[L7:`, `[FLOW:`,
  `[META:` (`needs_ext`). Ей нужна geneva_c 2.0 (фича `ext_xact`) и ключ
  `--ext` сразу после команды: `check --ext`, `run --ext`, `eval --ext`.
  Обычные стратегии запускаются без ключа, как с geneva_c 1.x.
- **Фейки zapret2** — `files/fake/*.bin` установленного zapret2
  (`zapret.base_path`). Каждый geneva с `--ext` получает все:
  `--ext-blob z2_<имя>:@<файл>`. Имя: `z2_` + имя файла без `.bin`,
  A–Z → a–z, прочее вне `[a-z0-9_]` → `_`, не длиннее 63; файл 1 байт–1 МБ,
  не ссылка; при совпадении имён — первый по пути. Префикс `z2_` — только
  для них.
- `GenevaManager.ext_problem` — почему x-стратегию не запустить (нет
  geneva_c 2.0, нет названного фейка); `runnable` отсеивает такие из
  `eval` и кандидатов «Авто», `check_strategy` возвращает причину,
  `auto_apply` даёт ошибку очереди и останавливает прежний процесс.
  `set_strategy` x-стратегии на движке без `--ext` перезапускает его.
- **Файл обмена** `zapret-gui/geneva-strategies` (`core/geneva_share.py`)
  — версия 2: у x-стратегии в строке `"ext": true` и `"blobs":
  ["z2_…"]`. Поля только для человека и старых программ: импорт
  вычисляет их заново. Файлы версии 1 и простой текст импортируются как
  раньше; x-стратегия, которую этой geneva не запустить, сохраняется с
  пояснением в `errors` и пробуется, когда появятся geneva_c 2.0 или
  нужный фейк.

## 4. Подбор (evolve) и продолжение с прерванного места

1. `validate_search()` проверяет параметры по `SEARCH_LIMITS` и по
   умолчанию берёт `SEARCH_DEFAULTS`: tls, 30×15, 1 воркер, 5 с.
   На странице размер задают пресеты: быстрый 20×8, обычный 30×15,
   глубокий 60×30 или свой.
2. `_launch_job()` ставит обход на паузу через
   `bypass_engine.pause_for_search()`, если не снят флаг `pause_bypass`.
   Пробы идут на 443/80, и живой обход исказил бы оценку. Если nfqws2
   держит сканер или blockcheck, ответ `busy`. Что именно остановили,
   пишется в `search.json → paused_engine`.
3. Пока подбор идёт, `_pump_job()` читает `job-events.jsonl`. Он пишет
   `search.json` раз в поколение с полями generation, best, baseline,
   results и последние оценки, а в ленту кладёт строки по-русски
   (`describe_event`).
4. Итог `_finish_job()` пишет в `status`:

   | status | когда |
   |---|---|
   | `done` | подбор завершился штатно |
   | `stopped` | остановил пользователь, checkpoint сохранён |
   | `not_blocked` | exit 7 |
   | `interrupted` | процесс умер вместе с GUI |
   | `error` | любая другая ошибка |

   Затем он возвращает приостановленный движок, но только если тот
   по-прежнему активный (`resume_after_search`).
5. **Продолжение.** `start_search(resume=True)` берёт параметры из
   `search.json` и запускает `evolve --resume search.ckpt`.
   `more_generations=N` добавляет N поколений, в том числе к законченному
   поиску (`can_extend`: статус `done` и checkpoint на месте). Число
   поколений не входит в хэш параметров checkpoint'а, и geneva разрешает
   его увеличивать (docs/EVOLVE.md). Кнопка «Ещё поколений» на странице
   добавляет 8.
   `paused_engine` перед продолжением всегда обнуляется, чтобы не вернуть
   устаревший движок.
6. `db.jsonl` — общая база оценок для подборов и `eval`. Повторная оценка
   той же стратегии на той же цели берётся из базы.
   `db_top(target)` показывает лучшие стратегии.

Остановка `stop_search()`: SIGTERM, затем до 30 с ожидания. geneva сам
дописывает checkpoint и снимает свои правила.

## 5. Сохранение состояния

| Что | Путь | Переживает перезагрузку |
|---|---|---|
| рабочая стратегия | `<config>/state/geneva/strategy.txt` + `settings.json → geneva.strategy` | да |
| checkpoint поиска | `<config>/state/geneva/search.ckpt` | да |
| база оценок | `<config>/state/geneva/db.jsonl` | да |
| состояние поиска (для UI и resume) | `<config>/state/geneva/search.json` | да |
| снимки движков | `<config>/state/engines.json` | да |
| прогресс подбора nfqws2 | `<config>/state/scan/resume.json` (с `working`: до 20 лучших) | да |
| сокет, pid, события, лог | `/tmp/zapret-gui/geneva/` (`ZAPRET_GUI_GENEVA_RUNTIME`) | нет, ОЗУ |

`<config>` — каталог `settings.json`, обычно `/opt/etc/zapret-gui`. События
и лог в ОЗУ урезаются (`MAX_EVENTS_BYTES`, `MAX_LOG_BYTES`). geneva
открывает их с `O_APPEND`, поэтому обрезка безопасна, а `EventReader`
замечает её и читает файл с начала.

Прогресс nfqws2 раньше лежал в `/tmp` и терялся при перезагрузке. Теперь
он в каталоге конфига вместе с найденными стратегиями, а на странице
«Подбор стратегий» появляется кнопка «Продолжить прерванный подбор».

## 6. Интерфейс и телеметрия

Раздел «Обход DPI» устроен по задачам, движок — вкладка внутри задачи
(`engine_tabs.js`; без `?engine=` открывается активный движок).
`GenevaPage.render(container, {sections})` рисует нужные части:

| Пункт меню | Хеш | Части geneva |
|---|---|---|
| Движок обхода | `#bypass` (старый `#geneva` — алиас) | `engines` |
| Управление → geneva_c | `#control?engine=geneva` | `engine`, `settings` |
| Стратегии → geneva_c | `#strategies?engine=geneva` | `library` (своё поле сайта для eval и итог проверки) |
| Подбор стратегий → geneva_c | `#scan?tab=geneva` | `search` |

«Обновления»: строка `geneva`. «Последняя» — закреплённый релиз
(`latest_source: pinned`, апстримный тег рядом). Сборка не из релиза
(версия — хэш коммита) обновлением не считается. Кнопка ведёт в
`#control?engine=geneva`, там же «Обновить до …»
(`detect.release.has_update` в `/api/geneva/status`).


`GET /api/geneva/status` одним ответом отдаёт `detect`, `engine` и
`search`. Страница опрашивает его и `/api/bypass/engine` раз в 3 с.

- **`engine`**: running, pid, стратегия, `stats` из сокета (`status` +
  `stats`), разбивка по деревьям и лента последних 200 событий.
- **Вердикт** (`summarize_stats`):

  | verdict | что значит |
  |---|---|
  | `working` | деревья срабатывают |
  | `not_firing` | трафик есть, а триггеры не совпали: стратегия не про этот трафик |
  | `no_traffic` | пакеты не доходят до очереди |

- **`search`**: статус, поколение N из M, baseline (проходит ли цель без
  обхода), лучшая стратегия, результаты, последние 30 оценок и лента.

Монитор `_monitor_loop` работает раз в 2 с, пока жив `run` или задание.
Раз в 30 с он проверяет, что правила на месте (`rules_present`: таблица
`inet geneva_310` или переход в `GENEVA_310_OUT`). Keenetic и fw3/fw4 при
пересборке сносят чужие правила, и тогда движок перезапускается.

## 7. REST и MCP

REST: см. docstring `api/geneva.py`, все пути под `/api/geneva/*`, плюс
`/api/bypass/engine`. Режим «Авто»: `GET /api/geneva/auto[?all=1]`,
`POST /api/geneva/auto/enable {confirm}` (без `confirm: true` при нужном
переключении движка — 409 `need_confirm`), `POST …/disable`,
`POST …/reset {key}`, `POST …/check-now|priority|pin|try|no-search
{key, …}`, `GET/POST …/lists`. Карточка «Авто» — секция `auto` страницы
`web/js/pages/geneva.js` (раздел «Обход DPI» и вкладка «Управление →
geneva_c»), тексты — `geneva.auto.*` в `web/js/i18n/*`.

MCP (`core/mcp/tools/geneva.py`):

| Инструмент | Scope | Меняет |
|---|---|---|
| `bypass_engine_status` | read | нет |
| `geneva_auto_status` | read | нет |
| `geneva_status` | read | нет |
| `geneva_library` | read | нет |
| `geneva_check` | read | нет |
| `geneva_db_top` | read | нет |
| `geneva_search_status` | read | нет |
| `bypass_engine_set` | control | да, undo `bypass_engine` |
| `geneva_set_strategy` | control | да, undo `geneva_strategy` |
| `geneva_start` | control | да |
| `geneva_stop` | control | да |
| `geneva_search_start` | probes | да |
| `geneva_search_stop` | probes | да |
| `geneva_eval_start` | probes | да |
| `geneva_auto_enable` | control | да, в два шага: токен, затем тот же инструмент с `confirm_token` (или `shell_confirm`, или кнопка на странице MCP) |
| `geneva_auto_disable` | control | да |
| `geneva_auto_reset` | control | да |
| `geneva_auto_check_now` | control | да |
| `geneva_auto_priority` | control | да |
| `geneva_auto_pin` | control | да, обратное — `pinned=false` |
| `geneva_auto_lists` | control | без аргументов — чтение; со списками — запись |

Подбор отнесён к `probes`, потому что он шлёт пробы в сеть и на время
останавливает обход.

`geneva_auto_status` отдаёт состояние **окном** (`_paging.page`): сводка
всегда, `items` — сервисы по `offset`/`limit`, `total` — сколько подошло
под `all`, `services_known` — сколько знает книга, `groups` — группы
(адреса только при `groups=true`, иначе `peers`), `journal` — последние
30 строк. Ключ сервиса приходит полем **`service`**, а не `key`:
`core/mcp/redact.py` маскирует любое поле с именем `key`, и по `***`
нельзя было вызвать `geneva_auto_pin`/`_reset`/`_set_priority`. Группы и
журнал передаются в `page()` как `extra`, а не дописываются после —
`_fit` ужимает окно по РАЗМЕРУ ответа и «лишнего» не видит.

## 8. Установка

`BINARIES["geneva"]` в `core/ext_binary_installer.py`:

- репозиторий `avatarDD/geneva_c`, `pinned_tag` v2.0.1 (из
  `GENEVA_VERSION`);
- ассеты `geneva-<GENEVA_VERSION>-linux-<arch>.tar.gz` для aarch64, armv7,
  mips, mipsel и x86_64 — имена строятся из версии, вручную меняются
  только хэши;
- sha256 сверены с `SHA256SUMS` релиза.

Страница «Обновления» и `updates_check`: «последняя» — пин; апстримный
релиз новее пина — `upstream_newer` (жёлтая строка на странице, строка в
`updates_only` и в `hint` MCP), `has_update` он не зажигает: кнопка ставит
только пин.

Первый файл архива — LICENSE, поэтому установщик достаёт член `geneva`
(`archive_member`). Бинарник ставится в `/opt/usr/bin/geneva`. Новая
версия означает новый `pinned_tag` и новые sha256, а также обновлённые
`docs/upstream.json` и этот скил. Ставить только из официального релиза.

**Раскладка тарбола меняется между релизами — член выбирается по
содержимому, а не по порядку.** В 1.x порядок был `LICENSE`, `geneva`,
README; в 2.0.1 первыми идут `packaging/s6/geneva/run`,
`packaging/openwrt/*`, `packaging/entware/*`, `packaging/systemd/*` и —
главное — `packaging/sysv/geneva` и `packaging/openrc/geneva`: это
`/bin/sh` init-скрипты с тем же базовым именем, что у бинарника, и лежат
они ПЕРЕД ним. Установщик долго брал первый член по имени и в 2.0.1
положил init-скрипт на `/opt/usr/bin/geneva`; `geneva version --json`
отвечал ему справкой с кодом 2, `version_info()` получал `{}`, и
страница писала «бинарник не отвечает на «geneva version --json»».
Теперь `_pick_archive_member` (`core/ext_binary_installer.py`) среди
одноимённых членов выбирает исполняемый: `_archive_member_rank`
даёт `2` для ELF, `1` — для не-текста без `#`/`<` в начале, `0` — для
скрипта и текста; при равенстве побеждает самый верхний по дереву. Плюс
`verify_installed_binary` считает скрипт (`#!`) ошибкой с флагом
`not_a_binary` — установка движка скриптом не считается, а уход на
`legacy_source` в этом случае не делается (это не «не та
архитектура»). Проверять установку после смены `pinned_tag` на живом
тарболе: `_unpack_if_needed(<tar>, "geneva")` должен вернуть
`.../geneva` размером ~787 КБ, а не файл из `packaging/`.

## 9. Подводные камни

- **exit 4** обычно значит, что нет `kmod-nfnetlink-queue` / `xt_NFQUEUE`
  или нет root. На Keenetic нужен компонент «Пакеты сетевых фильтров
  (netfilter)».
- **exit 5** — firewall отказал. Посмотреть «Лог» и попробовать
  `firewall: nft` или `iptables` явно.
- **exit 7** на подборе — цель открывается и без обхода, например из-за
  VPN или маршрута мимо DPI. Это не ошибка, подбирать нечего.
- Подбор с выключенной галкой «Остановить обход» даёт ложные победы:
  проба проходит через nfqws2.
- SIGKILL оставляет правила, поэтому `stop()` после неудачного SIGTERM
  обязательно вызывает `geneva fw down` (правило 5 AGENTS.md geneva_c).
- Перед `start()` всегда выполняется `fw down`: после краха остаются
  старые правила, а второй `run` на ту же очередь не встанет.
- `pid_alive` сверяет подкоманду в `/proc/<pid>/cmdline`, чтобы чужой
  процесс с переиспользованным pid не приняли за geneva.
- Порты, протокол, интерфейс и firewall — аргументы процесса. После
  `PUT /api/geneva/config` живой движок подхватит их только перезапуском
  (`restart_needed` в ответе). Стратегия меняется на лету через сокет
  (`set_strategy`).

## 10. Режим «Авто»

Пользователь включает один переключатель (карточка «Авто» в «Обход DPI»,
`POST /api/geneva/auto/enable`, MCP `geneva_auto_enable`), дальше всё
решает zapret-gui. Перенос режима из Zapret2_AutoTuner (§9 его скила):
алгоритм, пороги и состояния — оттуда, наблюдение, пробы и firewall —
свои, под роутер. Отличия от эталона помечены в коде словом «отличие».

| Модуль | Что делает |
|---|---|
| `core/geneva_auto.py` | чистое ядро: `Service`/`Sample`, пороги одним блоком, книга `Book` (переходы AutoBook), `plan_groups`/`target`, шаблоны `AUTO_CANDIDATES_*`, `candidates_for`, `protos_for`, `search_target` |
| `core/geneva_auto_observer.py` | срез conntrack → `Sample`: разбор строк, фильтр «свой/чужой», оценка `judge`, ключи `classify`, протокол и replay из захвата `analyze_capture` |
| `core/geneva_auto_probes.py` | пробы без обхода и с обходом, fitness для geneva |
| `core/geneva_auto_probe_cli.py` | проба «Авто» с блока портов воркера: `measure()` — для `--probe external` (в процессе GUI), скрипт — для `--probe exec` без фичи `external_workers` |
| `core/geneva_auto_search.py` | подбор одного сервиса в своём потоке |
| `core/geneva_auto_fw.py` | правила групп: `build_auto_rules`, `ipt_commands`, `teardown_commands` |
| `core/geneva_auto_apply.py` | очереди групп, процессы + правила, пробная группа, `stats` |
| `core/geneva_auto_manager.py` | цикл `geneva-auto`, состояние, включение/выключение, пауза |

1. **Наблюдение — conntrack, не pcap.** Срез раз в 15 с из
   `/proc/net/nf_conntrack` (иначе `conntrack -L -o extended`, IPv4 и
   `-f ipv6`). На время режима `nf_conntrack_acct=1` и
   `nf_conntrack_timestamp=1`, прежние значения возвращаются. Есть ли
   учёт, решает срез (`last_stats.counted`), а не sysctl: в Keenetic
   NDMS 14.x этих файлов нет, а `packets=` в таблице есть всегда. Нет ни
   таблицы, ни утилиты — `conntrack_tool_missing` («поставьте
   conntrack»), ядро без conntrack — `conntrack_unsupported`.
   Пропускается: не интернет (RFC1918, CGNAT, loopback, multicast),
   входящие (клиент не локальный), ct mark `0x30000000` (исключение и
   пробы), порты 30000–30575 (оценщик geneva и пробы «Авто»), ответ не от
   сервера (REDIRECT/DNAT в локальный прокси), ответ на адрес туннельного
   интерфейса (awg, wg, nwg, tun…) — это трафик ВНУТРИ туннеля — и
   `geneva.auto.exclude`. Внешние соединения туннелей и прокси (роутер →
   сервер AWG/WG/sing-box/mihomo/usque) наблюдаются, как обычные
   (`geneva.auto.help_tunnels`, по умолчанию да): заблокированное
   подключение к VPN получает свою стратегию. Серверы из `awg/wg show all
   endpoints` попадают в `Local.servers` — только для подписи «Туннель:
   …»; при `help_tunnels: false` они исключаются. TPROXY в conntrack не
   виден — такие серверы только через `exclude`.
   **Имена** (отличие: AutoTuner видит SNI каждого соединения захватом ПК)
   — `core/name_sniffer.py` всё время режима: один `AF_PACKET`/`SOCK_DGRAM`
   с BPF-фильтром в ядре (DNS-ответы с порта 53, первые байты запросов к
   443/80: TLS ClientHello → SNI, HTTP → Host, IPv4 и IPv6, любой тип
   интерфейса) пишет в `block_detector.remember_names`. Без него на
   OpenWrt (dnsmasq пишет в syslog, секундный сниффер детектора, DoH в
   браузерах) почти всё было `ep:tcp:<ip>:443`. Нет прав на AF_PACKET —
   одна строка в журнале, имена только из журналов DNS. QUIC Initial не
   разбирается (AES нет в stdlib).
   **Ускорение NAT** (OpenWrt `flow_offloading`/`_hw`, потоки `[OFFLOAD]`
   в срезе) уводит установленные соединения клиентов мимо netfilter:
   geneva не видит их ClientHello, а проба с роутера проходит. Режим
   ничего не меняет сам, а показывает предупреждение (`status().offload`,
   журнал, карточка). Переключатель внизу карточки «Авто» —
   `core/nat_offload.py`, `GET/POST /api/geneva/nat-offload {enabled,
   confirm}` (без `confirm: true` — 409 `need_confirm`): OpenWrt — `uci`
   `flow_offloading`/`_hw` + `uci commit firewall` + reload firewall,
   Keenetic — `ndmc` `[no] ppe software|hardware` + `system configuration
   save`. Включение возвращает то, что было до выключения
   (`geneva.nat_offload_saved`).
2. **Оценка соединения по счётчикам** (данные — `bytes − packets ×
   заголовок`, у TCP с запасом на опции): SYN без ответа ≥ 3 с и ≥ 2 SYN →
   нет соединения; ESTABLISHED, ответ ≤ 3 пакетов и ≤ 100 Б данных, ≥ 5 с,
   клиент слал данные (и повторял или порт 80/443) → «данных нет»;
   CLOSE (RST) при ответе < 200 Б → сброс; данные ответа 8–32 КБ и
   «зависли» между срезами → обрыв на 16 КБ; ответ ≥ 2 КБ → успех;
   `[OFFLOAD]` — малые счётчики ничего не значат. UDP: ответ — успех,
   `[UNREPLIED]` ≥ 5 с при ≥ 2 запросах (DNS — 1) — провал; долгий поток
   после первого вердикта судится приростом за срез. Одно TCP-соединение
   — один провал (потом только «успех»-поправка).
3. **Ключи** — как в ядре: `web:<домен>`, `quic:<домен>` (UDP 443 с
   именем), `dns:<ip>`, `ep:<app>:<tcp|udp>:<ip>:<port>`,
   `port:<tcp|udp>:<клиент>:<порт>`. Имя — карта «IP → имя» детектора
   блокировок (`block_detector.ip_names`/`refresh_names`: dnsmasq
   `reply`/`cached`, AdGuard, AF_PACKET) и SNI из захвата. DHT без
   захвата — «веер» (с одного UDP-порта к ≥ 8 адресам) → `p2p`. Ключ `ep:`
   липкий: узнанный позже протокол его не меняет.
4. **Протокол и replay** подозрительного endpoint/P2P — фоном короткий
   захват (`traffic_capture.capture_first`: фиксированный argv tcpdump,
   `-i any`, адрес + порт, 16 пакетов, снапшот 1500, файл удаляется,
   payload'ы из прогона стираются). Разбор: DHT, OpenVPN (опкод 7/10),
   TLS (+SNI), HTTP, QUIC Initial, Discord, STUN/ICE, DNS, DTLS,
   WireGuard; MTProto — нет (нужен AES). Replay — только
   `REPLAYABLE_APPS`, у TCP — ровно первое сообщение.
5. **Подтверждение** (`AutoProbes.check`). «Блокировка по IP» только
   без рукопожатий в окне (`ga.handshake_seen`: успехи или TCP-провалы
   после рукопожатия); иначе таймаут connect пробы роутера — это
   блокировка по содержимому (отличие от эталона). Ослабление
   (`applied → degraded`) — по провалам после последнего успеха.
   Если проба с обходом вернула сервис в `applied`, а он снова ослаб за
   30 мин, стратегия помогает только роутеру: она в `rejected`, сервис —
   в `blocked` на новый подбор.
    сайт — загрузка страницы с
   увиденного IP с SNI/Host (≥ 64 КБ или весь ответ, без зависания,
   сертификат проверяется, без CA-бандла — без проверки), таймаут
   соединения → `ip_blocked`; прочее — повтор replay (две попытки),
   STUN — свежий Binding Request, DNS без replay — свежий запрос (отличие).
   Без обхода: `SO_MARK` (метка проб nfqws2 | `0x20000000`), мимо очередей;
   с обходом — без метки, через группу. Пробы без обхода — с портов
   30512–30543 (правила групп пропускают их по порту: метка есть только у
   исходящих пакетов, ответы иначе прошли бы через стратегию), с обходом —
   30544–30575.
   Ошибка самой пробы → `unknown`.
6. **Подбор** (по одному, приоритет web → dns → endpoint → quic → DHT):
   круги `ga.candidate_rounds` (отличие: в эталоне один круг до 12 без
   библиотеки) — **проверенные в этой сети** (стратегии групп, `db_top`
   цели с успехами, работающие у других сервисов по числу сервисов,
   `db_top` всех целей по успехам, импортированные), добранные до
   кратного числа воркеров, затем **все остальные** (`AUTO_PRESETS_*`,
   шаблоны, вся `geneva library` для транспорта; всего до 192),
   прошедшие `geneva check` (неразбираемый кандидат уронил бы весь
   `eval -f` кодом 3); каждый круг — один `geneva eval --workers N`
   **параллельно** (`geneva.auto.workers`, 4, от 1 до 32 — предел
   geneva_c, у ручного подбора тот же; поле внизу карточки «Авто»,
   `POST /api/geneva/auto/settings` — там же `max_groups`,
   `help_tunnels` и `exclude` (IP-адреса, список или текст; неверный —
   400 `bad_value`), всё сразу передаётся наблюдателю, подбору и
   применению; карточка показывает
   «проверено X из N, параллельно: W»). Отвергнутые для сервиса
   (`Service.rejected`) не предлагаются. Без пробы — проверенные и 12
   остальных. Новая рабочая стратегия сразу будит «не найдено» того же
   транспорта (`Book.wake_not_found`); никто не прошёл — `evolve` (20 × 10, `--protos` по транспорту,
   свой checkpoint `state/geneva/auto/<sha1>.ckpt`, следующий раз
   `--resume` +5 поколений); до 3 прошедших — пробной группой на трафике
   сервиса и пробой с обходом. Без пробы — кандидат за кандидатом, успех —
   поток клиента за 50 с. Проба — `external` с N воркерами (geneva_c 1.2,
   `external_workers`, точный фитнес), без фичи — `exec` (ok/reset+INJECTED/
   прочее, +400/−360/−400). Слот задачи
   общий с ручным подбором; ручной «Стоп» даёт `busy`, не `not_found`.
7. **Применение.** Группа = стратегия = свой `geneva run --firewall none`
   на очереди 340..340+N−1 (`geneva.auto.max_groups`, 4, до 8). У движка с
   `ext_profile` (geneva_c 2.0) — наоборот: **все** стратегии живут в одном
   процессе профилями (`plan_profiles` → `auto_profiles_ini` →
   `auto_engine_apply`), очередь у них одна (`QUEUE_BASE`), а правила
   различают профили своими наборами адресов и порт-фильтрами; «потоков»
   процесса — `ENGINE_WORKERS_MAX` (64, предел `--ext-workers`); очередь
   «по имени» и детектор стоят за диапазоном профилей (404/405).
   Подпись живого процесса — воркеры, имена и стратегии: новые адреса
   CDN файлы переписываются, а процесс их перечитывает (`reload_lists`),
   без перезапуска. Стратегия
   сохраняет очередь и процесс; смена — `set_strategy`; упавший
   поднимается при следующем применении (при изменении плана и раз в
   2 мин). Правила — `core/geneva_auto_fw`: nft-таблица
   `inet zapret_geneva_auto` (атомарная замена) или mangle
   `ZGGA_POST/ZGGA_PRE` + ipset `geneva_auto_<Q>_<n>_v4/v6`; наборы на
   «очередь + порты» (у профилей — на «профиль + порты»);
   `ct original packets 1-12` / `ct reply packets 1-6`;
   DHT — по `ct original saddr/proto-src` и направлению; пропуск метки
   `0x20000000` и портов оценщика. Без адресов правил нет. Нет ipset или
   xt_connbytes — режим выключается с причиной. Пробная стратегия
   применена, только если её процесс жив и правила встали (`trial_ok`).
   iptables зовётся с `-w`; обязательная команда упала (NDMS пересобрал
   mangle посреди применения) — один повтор всего списка, и только потом
   снятие. Иной сбой — повтор на следующем срезе, дальше раз в 2 мин.
   **Самолечение:** каждый срез `fw.present()` (`iptables -t mangle -S`
   + `ipset list -n` или `nft list table`) — нет перехода, правил или
   набора → применение сразу и `Book.rules_restored()`: провалы за время
   без правил не в счёт, `degraded` → `applied` без пробы (иначе проба
   «с обходом» в окне без правил отвергала рабочую стратегию как
   «помогает роутеру, но не устройствам»). Хук netfilter.d сторожа
   маршрутизации (`core/routing/guardian.py`) зовёт `reassert_rules()`
   сразу. Счётчик — `status().rules_lost`, журнал — не чаще раза в 30 мин.
   На время режима `nf_conntrack_tcp_be_liberal=1` (как у nfqws2), при
   выключении — прежнее значение.
8. **Цикл и состояние.** `tick()`: срез → захват протокола →
   подтверждение одного → подбор → применение → `stats` → сохранение
   (`state/geneva/auto.json`: переход — сразу, иначе ≤ раза в минуту,
   пустой срез не пишет). Ошибка среза — повтор через 15→30→…→300 с.
   Сохранённый «в подборе» при загрузке — `blocked` (исправление
   эталона). Журнал — 300 строк в ОЗУ + `log_buffer`.
9. **Взаимоисключения.** Включение: geneva установлен, nfqws2 свободен,
   conntrack есть; переключение движка и остановка одиночного run — после
   подтверждения (REST 409 `need_confirm`, MCP — `confirm_token`). При
   «Авто» `start()`, `start_search()`, `start_eval()` →
   `error_code: geneva_auto`; `switch("nfqws2")` выключает режим;
   `hold_geneva_for` (сканер, blockcheck) — `suspend`, после — `resume`.
   Правила и группы снимаются при выключении, выходе GUI (`shutdown`) и
   при загрузке с выключенным режимом (`boot`).

Вкладка «Стратегии → geneva_c» — секция `found`:
`GET /api/geneva/found` → `GenevaAutoManager.found()` →
`geneva_auto.found_strategies(services, db_items, working)`: только
проверенное в этой сети (сервисы «Авто» `applied`/`degraded` и записи
`db top` с `ok > 0`), сгруппировано по стратегии, с сервисами и целями.
Библиотека исследований — секция `library` в свёрнутом `<details>`,
`geneva library` зовётся при раскрытии.

Подводные камни:

- Прокси на 443 с Reality: проба страницы по имени сервера из DNS может
  счесть его заблокированным, хотя подключение работает (Reality отвечает
  чужим сертификатом); такой сервер — в `geneva.auto.exclude`.
- В таблице нет `packets=` (учёт выключен, запись `nf_conntrack_acct`
  не прошла) — видно только «нет соединения»; проблема в
  `status().problems` ставится по срезу и снимается, когда счётчики
  появились. Нет файла sysctl при счётчиках в таблице (Keenetic NDMS
  14.x) — не проблема.
- Аппаратный offload (Keenetic hwnat, OpenWrt flow offloading) замораживает
  счётчики: зависания такого потока не видны, успех — только по
  большому ответу.
- Порты 30000–30543 не должны попадать в правила групп (оценщик и проба
  без обхода), 30544–30575 (проба с обходом) — обязаны; 30512–30575 не
  попадают в срез.
- Проверка с обходом идёт с самого роутера: правила групп обязаны
  ловить и локальный трафик (postrouting/prerouting, а не только forward).

### 10.1. Перенос Zapret2_AutoTuner 1.1 → 1.4

ТЗ: `/mnt/project-files/analysis/autotuner-1.1-1.4-sync.md` (проектные
файлы). Что пришло и где:

- **Важность** (`core/geneva_auto_lists.py`, AutoPriorities):
  important / normal / low / background; метка пользователя, списки
  `geneva.auto.lists.{important,unimportant,no_search}` (домен, `*.ru`,
  `.ru`, маска `*google*`/`?`, адрес, подсеть, `AS12389`), семейства
  (`FAMILIES`) при `known_important`. Фоновый, ждущий ≥ 30 мин, — low.
  Очереди подтверждения и подбора — важность → degraded → сайт, DNS,
  QUIC, сервер, пир → свежесть → трафик. Пиры не занимают последние 60
  мест книги. Сети AS — RIPEstat `announced-prefixes` (уходит только
  номер), `state/geneva/auto/asn.json`, раз в 7 дней, ≤ 5000 на AS.
- **«Не подбирать»** — сервис не попадает в книгу; **«Не трогать»**
  (`geneva.auto.exclude`, только домены/адреса/подсети) — вне режима и
  ручному `geneva run` через `--ipset-exclude-ip`/`--hostlist-exclude-domains`
  (фича `ext_lists`; без неё — предупреждение, run идёт; отличие: в
  эталоне run не стартует).
- **Действия над сервисом**: проверить сейчас, важность, закрепить
  (провалы не ведут к подбору), своя стратегия (`try` — пробная группа и
  проба с обходом, успех — применить и закрепить), «Не подбирать».
- **Ложные блокировки** (`AutoProbes._check_page`): без обхода сайт
  «заблокирован» только после второй неудачи через 2 с; сертификат с
  верным именем от «Russian Trusted» (узнаётся по издателю листа:
  цепочки на роутере нет — отличие) проходит, хост запоминается
  (`_national_hosts`) и для оценки. Подбор позже 5 мин после последнего
  «заблокирован» сначала перепроверяет без обхода.
- **Шейпер и обрыв 16 КБ** (`core/geneva_rate.py` = RateShelf +
  LinkCapacity, `PageCheck`): у подозреваемого без обхода страница
  читается до 1 МБ, окна по 500 мс; полка — критерий `min_rate`
  (3 полки, ≤ ½ канала, ≥ 1,5 полки); маленькая страница — ещё раз с
  добивкой 24 КБ, обрыв внутри ответа дважды — `min_bytes=128K, pad`.
  Находка считается, только если её видели обе пробы.
  `Service.criteria` получают проба с обходом, `judge` и внешняя проба
  (`probe_spec["criteria"]`, `--min-rate/--pad/--min-bytes`).
- **Несколько подборов** (`split_workers`): мест `min(потоки, 4)`, не
  больше свободных групп; слот 0 — очередь 311 (общий с ручным), слоты
  1–3 — 312–314, свои процессы (`AutoJobSlot`); порты блоками по 128
  (`--local-ports 30000+128·k`, ≤ 2 воркера; отличие: в эталоне 331–334
  и 512). Своя база оценок у цели (`auto/db/<hash>.jsonl`). Сервисы с
  общим адресом/сайтом рядом не подбираются; важный прерывает менее
  важный.
- **x-кандидаты** (`ga.x_for`, `X_TCP`…`X_TCP_ANY`, `blob_candidates`,
  фейки zapret2 по 8 за круг по `Service.attempts`) — при `ext_xact`,
  во втором круге перед библиотекой. Все 73 строки проходят
  `geneva check --ext` (тест с `GENEVA_BIN`). `_fits`: триггеры
  `[FLOW:`/`[L7:`/`[META:` решаются по действиям под ними. Стратегия
  семейства — первой; пробная засчитывается после 2 проверок подряд.
- **Ручной подбор**: `geneva.search.zapret2` — `X_TCP` (для `http`/80 —
  `X_HTTP`) в `--load-from state/geneva/seeds.txt`; «Библиотека»
  (`library(zapret2=True)`) — TCP-методы с `country: zapret2`.
- **По имени** (`by_name`, по умолчанию да; фичи `ext`, `ext_profile`,
  `ext_lists`, `ext_l7`): `ga.host_profiles` (≤ 24, домены семейства без
  своей жизни в книге, пробная — нет) → `GenevaManager.auto_host_apply`:
  `run --ext --ext-profile profiles.ini -q 404 --firewall none
  --ext-ipcache-hostname` (`-q` = `ga.HOST_QUEUE`; номер зависит от
  предела потоков, а подпись процесса от него — нет, поэтому живой
  процесс сверяется с фактической `-q` через `_queue_matches` и при
  несовпадении перезапускается), hostlist на профиль, `ipset-exclude` = адреса
  живых групп + «Не трогать». Те же стратегии — `reload_lists`, иначе
  перезапуск. Правило — `fw.HostRule` после групп: TCP 80/443 (+UDP 443
  при `ext_crypto`) первые пакеты. `Book.by_name` — покрытые сайты.
- **Детектор** (`ext_auto`): `run --ext --ext-auto observe -s '\/' -p 9
  -q 405` (`ga.OBSERVE_QUEUE`; NFLOG-правила ставит сама geneva), раз в
  срез `ext_status`:
  `THROTTLE`/`FREEZE_N` у `host`/`ip` → `Book.detect` (подозрение, раз в
  минуту), `capacity` → `geneva_rate.SHARED`, `DNS_POISON` → совет DoH
  раз в час на имя.

  Детектору нужна подсистема ядра **NFLOG** (`nfnetlink_log`), а это НЕ
  то же, что NFQUEUE: `nfnetlink_queue` и `nfnetlink_log` — разные
  модули, и на OpenWrt второй в образ по умолчанию не входит (пакет
  `kmod-nfnetlink-log`, фича ядра `nfnetlink-log`). Без подсистемы
  ядро отвечает на `NFULNL_CFG_CMD_BIND` через `EINVAL` — в логе geneva
  это `error engine: cannot bind NFLOG group 405: Invalid argument`, и
  процесс умирает с `EXIT_FAIL` («ни одна стратегия не прошла»). Признак
  загруженной подсистемы — `/proc/net/netfilter/nfnetlink_log`
  (`proc_create_net` в `nfnetlink_log.c`, файл живёт, пока модуль
  загружен) и `nfnetlink_log` в `/proc/modules`
  (`core.diagnostics._check_nflog_available`).
  - `GenevaManager.auto_observer_ensure` различает отказ по тексту
    (`geneva_manager.nflog_refused`): `EBUSY` апстрима
    (`(another program reads this group)`) — НЕ наш случай, группу
    читает другая программа. После `EINVAL` ставится
    `_obs_disabled = "no_nflog"`, и детектор не перезапускается до
    `auto_observer_reset()` (вызывается при включении режима): модуль
    ядра сам не появится, а попытка каждые 15 с — только мусор.
  - Перед первым запуском детектора — одна попытка подгрузить модуль:
    `GenevaManager._ensure_nflog_module` (флаг `_nflog_load_tried`, сброс
    в `auto_observer_reset`) → `core.kmod_manager.nflog_ensure_module`
    (`modprobe nfnetlink_log`, если `/proc/net/netfilter/nfnetlink_log`
    нет). Это дорога для Linux и Keenetic, где модуль есть, но не
    загружен: автозагрузка по алиасу `nfnetlink-subsys-4` срабатывает не
    всегда (нужен `modules.dep`). На OpenWrt модуля нет вовсе — modprobe
    ничего не находит, и дальше решает только установка пакета.
  - `GenevaAutoManager._detector_off`: `no_nflog` → одна строка в
    `problems` и один `note` за сеанс; прочие падения — `note` при смене
    вида отказа (ключ дедупликации `_detector_reason_text` вырезает метки
    времени из хвоста лога — иначе каждая попытка выглядит новой) и
    повтор не чаще `DETECTOR_RETRY = 300` с.
  - Починка из GUI: `core/kmod_manager` знает два «вкуса» установки
    (`_FLAVORS`: `nfqueue`/`nflog`, общий `_state_lock` — пакетный
    менеджер один). `nflog_deps_status()` / `nflog_fix_hint()` →
    `GET /api/diagnostics/nflog-deps`, `POST .../install`,
    `GET .../install/status`; кнопка «Установить модуль NFLOG» на
    карточке «Авто» (`nflog_fix` в `/api/geneva/auto/status`). На
    Keenetic/Entware модуль приходит из прошивки — `can_auto_install:
    False`, `install_command: ""` (пакета `kmod-nfnetlink-log` в opkg-фиде
    нет, и показывать команду было бы ложью) и инструкция; режим «Авто»
    работает без детектора.
- **UI**: фильтр и стабильный порядок строк, колонка «Важность», меню
  «⋯», блок «Важные сервисы и исключения» (`/auto/lists`), строка
  «подборов сразу», «по имени», «детектор»; ручной подбор — галочка
  «добавить методы zapret2» (видна при `detect.ext`).
- **«Важно» — два разных механизма, и страница показывает оба.** Список
  `geneva.auto.lists.important` — маски/домены/AS в настройках; отметка
  из меню «⋯» — `user_priority` одного сервиса в книге
  (`Book.set_user_priority`) и в `auto.json`. В текстовых полях формы
  отметок поэтому не видно: `lists_view()` отдаёт их отдельным полем
  `marked: {important: [{service, name}], unimportant: [...]}` (через
  `services_snapshot()`, чтобы читались и при выключенном режиме), а
  страница рисует их строкой `#gv-list-marked`. Не превращать `marked`
  в списки: порядок важности — `user_priority` → `lists.important` →
  `lists.unimportant` → `known_important` (семейства) → по типу.
- **Почему подборов идёт меньше выбранного.** `_search_slots()` =
  `max(1, min(workers, MAX_SEARCHES, max_groups - <число живых рабочих
  стратегий>))`. У группы-очереди ровно одна пробная стратегия
  (`plan_groups`/`assign_queues`: пара «адрес + транспорт» достаётся
  только одной группе), поэтому при всех занятых группах остаётся один
  слот — это не сбой, а нехватка очередей группового пути (у профилей,
  которые работают на geneva_c 2.0, `_search_slots` отвязывается на
  следующем этапе). `HOST_QUEUE`/`OBSERVE_QUEUE` уже вынесены за предел
  потоков (404/405); страница честно
  пишет причину (`geneva.auto.split_now` под фазой), а не поднимает
  лимит. Замеры на живом роутере и варианты расширения —
  `docs/geneva-auto-queues.md`.

### 10.2. Перенос Zapret2_AutoTuner 1.5

Итоговая проверка в AutoTuner — встроенный браузер; на роутере его нет,
отличия ниже. Настройка общая: `geneva.final_check` (по умолчанию да;
`/auto/lists` и `search/start` с `final_check`).

- **Связанные ресурсы в «Авто»** (`core/geneva_related.py`): после
  `TRIAL_PASSES` проверок сайта на 443 `AutoSearch._check_related` зовёт
  `related(s, strat)` менеджера: `_related` + `_hosts` добавляют профиль
  «по имени» `grel.trial_families` (другие имена сайта и семейство, без
  членов со своей жизнью и уже названного применёнными профилями, после
  них; не влезает в 24 — нет), затем `SETTLE` 2 с и
  `AutoProbes.check_related`: TLS + ответ HTTP на 443 через обход, имена —
  увиденные устройствами (`seen_hosts`), иначе `PROBE_HOSTS`, не больше
  4, «Не трогать» (имя, подсеть) — мимо. Вердикт `grel.judge`: ответ —
  `ok`; нет соединения или корень Минцифры — без вердикта (журнал);
  соединение без ответа или чужой сертификат — `failed` → следующий
  кандидат. pid процесса «по имени» до снятия другой — перезапуск, провал
  не в счёт. Без процесса «по имени» проверяется только сам сайт.
- **Семейство по хосту**: `gal.service_family` берёт `s.host`
  (`youtubei.googleapis.com` — YouTube), у адреса семейства нет, без хоста —
  по сайту.
- **Итоговая проверка ручного подбора** (`core/geneva_final_check.py`):
  `_finish_job` законченного `evolve` (не «Авто») → `_start_final`: до 3
  лучших с фитнесом > 0, фича `external_workers`; `FinalCheck` в своём
  потоке разрешает сайт, берёт связанные ресурсы и запускает
  `start_final_job` — `geneva eval --probe external` в `AutoJobSlot(1)`
  (очередь 312, порты 30128+), ответы `ExternalAnswerer(with_strategy=True)`
  → `gfc.measure` (страница уровня «тело» + связанные ресурсы с того же
  блока портов). Отличие от эталона: стратегия действует только на
  соединения проверки, а не на весь порт сайта. Пауза обхода держится до
  конца (`_final_done` → `_restore_paused`). Итог — `search.final`
  (`status`, `items` {стратегия: {ok, detail}}) и
  `state/geneva/final.json` → «Найденные» (`found()[i].final`). Пока идёт
  — новый подбор и проверка отказывают (`geneva_final`); перезапуск GUI —
  `final.status = interrupted`.
- **Сколько проверяется**: `ExternalAnswerer.counters()` → `probing`
  (≤ воркеров, 0 после выхода), `workers`, `checked` в
  `auto_job_status` слотов; прогресс подбора — `probing`, `threads`,
  `checked`, `generations`; строка сервиса «подбор geneva: поколение … ·
  проверяется сейчас N из M потоков · проверено K»; `search_slots_wanted`
  — подсказка под «Делить потоки», если идёт меньше; на карточке ручного
  подбора — идущие подборы «Авто».
- **Библиотека geneva_c** (с 2.1): стратегии geneva_c против блокировок в
  России (`country` `russia`, `test` `tls`/`quic`/`udp`, `rate` = фитнес −
  300); стратегии Китая, Индии, Казахстана убраны; x-стратегии — только с
  `--ext` (`"ext": true`, значок `ext` в «Библиотеке»).
