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
  правила пропали / подбор не стартует / exit 4, 5, 7». Источник истины —
  сам бинарник и docs/ в avatarDD/geneva_c, привязка — core/geneva_manager.py,
  core/bypass_engine.py, api/geneva.py, core/mcp/tools/geneva.py.
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
   **v1.0.0**: `docs/STRATEGY.md` (язык), `docs/PROTOCOL.md` (события и
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
| `start_search()` | `geneva evolve --probe tls\|http\|exec --host H ... --population N --generations M -q 311 --checkpoint search.ckpt --db db.jsonl --target T -e job-events.jsonl [--resume]` | root |
| `start_eval()` | `geneva eval -f candidates.txt --host H ... -q 311` | root |
| `check_strategy()` | `geneva check --json -f -` | нет |
| `library()` | `geneva library --json` | нет |
| `db_top()` | `geneva db --db db.jsonl top --json` (печатает JSONL) | нет |
| `detect()` | `geneva version --json` | нет |

Точные аргументы собирают чистые функции `build_run_args`,
`build_evolve_args`, `build_eval_args`, `fw_down_args` и `_probe_args`. Они
покрыты тестами, и аргументы правят только в них.

- **Очереди NFQUEUE.** nfqws2 держит 300–303, `run` 310, оценщик 311. Две
  очереди нужны, чтобы оценка могла идти рядом с `run`, хотя по умолчанию
  мы всё равно ставим обход на паузу (§4).
- **Метка 0x20000000** у пакетов, которые geneva отправляет сам. Правила
  geneva их пропускают, иначе получилась бы петля.
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
`/api/bypass/engine`.

MCP (`core/mcp/tools/geneva.py`):

| Инструмент | Scope | Меняет |
|---|---|---|
| `bypass_engine_status` | read | нет |
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

Подбор отнесён к `probes`, потому что он шлёт пробы в сеть и на время
останавливает обход.

## 8. Установка

`BINARIES["geneva"]` в `core/ext_binary_installer.py`:

- репозиторий `avatarDD/geneva_c`, `pinned_tag` v1.0.0;
- ассеты `geneva-1.0.0-linux-<arch>.tar.gz` для aarch64, armv7, mips,
  mipsel и x86_64;
- sha256 сверены с `SHA256SUMS` релиза.

Первый файл архива — LICENSE, поэтому установщик достаёт член `geneva`
(`archive_member`). Бинарник ставится в `/opt/usr/bin/geneva`. Новая
версия означает новый `pinned_tag` и новые sha256, а также обновлённые
`docs/upstream.json` и этот скил. Ставить только из официального релиза.

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
